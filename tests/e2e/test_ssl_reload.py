from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import ssl

import pytest
import trio

import hypercorn.asyncio
import hypercorn.trio
from hypercorn.config import Config
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope

ASSETS = os.path.join(os.path.dirname(__file__), "..", "assets")
CERT1 = os.path.join(ASSETS, "cert1.pem")
KEY1 = os.path.join(ASSETS, "key1.pem")
CERT2 = os.path.join(ASSETS, "cert2.pem")
KEY2 = os.path.join(ASSETS, "key2.pem")
CA = os.path.join(ASSETS, "ca.pem")
CLIENT_CERT = os.path.join(ASSETS, "client.pem")
CLIENT_KEY = os.path.join(ASSETS, "client_key.pem")

REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    body = b"Hello, world!"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain"), (b"content-length", b"13")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _config(port: int) -> Config:
    config = Config()
    config.bind = [f"127.0.0.1:{port}"]
    config.certfile = CERT1
    config.keyfile = KEY1
    config.accesslog = "-"
    config.errorlog = "-"
    return config


def _client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


@pytest.mark.asyncio
async def test_asyncio_ssl_reload() -> None:
    port = _free_port()
    config = _config(port)
    sni_names: list[str | None] = []
    ssl_context = config.ssl_context
    assert ssl_context is not None
    ssl_context.set_servername_callback(lambda sslobj, name, context: sni_names.append(name))

    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(
        hypercorn.asyncio.serve(app, config, shutdown_trigger=shutdown.wait)
    )
    try:
        reader, writer = await _asyncio_connect(port, _client_context())
        ssl_object = writer.get_extra_info("ssl_object")
        assert ssl_object.selected_alpn_protocol() == "http/1.1"
        fingerprint1 = _fingerprint(ssl_object.getpeercert(binary_form=True))
        assert await _asyncio_request(reader, writer) == b"Hello, world!"

        # A mismatched certificate and key cannot be reloaded, the
        # previous certificate keeps being served.
        config.certfile = CERT2
        config.keyfile = KEY1
        assert ssl_context.reload() is False
        reader2, writer2 = await _asyncio_connect(port, _client_context())
        assert (
            _fingerprint(writer2.get_extra_info("ssl_object").getpeercert(binary_form=True))
            == fingerprint1
        )
        writer2.close()

        # Rotating to the new certificate succeeds
        config.keyfile = KEY2
        assert ssl_context.reload() is True

        # The established connection is not interrupted by the reload
        assert await _asyncio_request(reader, writer) == b"Hello, world!"

        # New connections complete a full handshake with the new certificate
        reader3, writer3 = await _asyncio_connect(port, _client_context())
        ssl_object3 = writer3.get_extra_info("ssl_object")
        assert _fingerprint(ssl_object3.getpeercert(binary_form=True)) != fingerprint1
        assert ssl_object3.selected_alpn_protocol() == "http/1.1"
        assert await _asyncio_request(reader3, writer3) == b"Hello, world!"

        # The SNI configuration is not lost on reload
        assert sni_names == ["localhost"] * 3

        writer.close()
        writer3.close()
    finally:
        shutdown.set()
        await serve_task


async def _asyncio_connect(
    port: int, context: ssl.SSLContext
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    for _ in range(100):
        try:
            return await asyncio.open_connection(
                "localhost", port, ssl=context, server_hostname="localhost"
            )
        except ConnectionRefusedError:
            await asyncio.sleep(0.05)
    raise ConnectionRefusedError(f"Cannot connect to port {port}")


async def _asyncio_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    writer.write(REQUEST)
    await writer.drain()
    data = b""
    while b"\r\n\r\n" not in data:
        data += await asyncio.wait_for(reader.read(2**16), 5)
    headers, body = data.split(b"\r\n\r\n", 1)
    length = _content_length(headers)
    while len(body) < length:
        body += await asyncio.wait_for(reader.read(2**16), 5)
    return body[:length]


def _content_length(headers: bytes) -> int:
    return int(
        [line for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length")][
            0
        ].split(b":")[1]
    )


@pytest.mark.asyncio
async def test_asyncio_ssl_reload_client_cert_verification() -> None:
    port = _free_port()
    config = _config(port)
    config.ca_certs = CA
    config.verify_mode = ssl.CERT_REQUIRED

    shutdown = asyncio.Event()
    serve_task = asyncio.ensure_future(
        hypercorn.asyncio.serve(app, config, shutdown_trigger=shutdown.wait)
    )
    try:
        client_context = _client_context()
        client_context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
        reader, writer = await _asyncio_connect(port, client_context)
        assert await _asyncio_request(reader, writer) == b"Hello, world!"
        writer.close()

        config.certfile = CERT2
        config.keyfile = KEY2
        ssl_context = config.ssl_context
        assert ssl_context is not None
        assert ssl_context.reload() is True

        # Verified clients still work after the reload
        client_context = _client_context()
        client_context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
        reader, writer = await _asyncio_connect(port, client_context)
        assert await _asyncio_request(reader, writer) == b"Hello, world!"
        writer.close()

        # Clients without a certificate are still rejected after the reload
        data = b""
        try:
            reader, writer = await _asyncio_connect(port, _client_context())
            writer.write(REQUEST)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2**16), 5)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        assert b"200" not in data
    finally:
        shutdown.set()
        await serve_task


@pytest.mark.trio
async def test_trio_ssl_reload() -> None:
    port = _free_port()
    config = _config(port)
    sni_names: list[str | None] = []
    ssl_context = config.ssl_context
    assert ssl_context is not None
    ssl_context.set_servername_callback(lambda sslobj, name, context: sni_names.append(name))

    async with trio.open_nursery() as nursery:
        shutdown = trio.Event()

        async def serve() -> None:
            await hypercorn.trio.serve(app, config, shutdown_trigger=shutdown.wait)

        nursery.start_soon(serve)
        await trio.testing.wait_all_tasks_blocked()

        with trio.fail_after(30):
            stream = await _trio_connect(port)
            assert stream.selected_alpn_protocol() == "http/1.1"
            fingerprint1 = _fingerprint(stream.getpeercert(binary_form=True))
            assert await _trio_request(stream) == b"Hello, world!"

            # A missing certificate cannot be reloaded, the previous
            # certificate keeps being served.
            config.certfile = os.path.join(ASSETS, "missing.pem")
            assert ssl_context.reload() is False
            stream2 = await _trio_connect(port)
            assert _fingerprint(stream2.getpeercert(binary_form=True)) == fingerprint1
            await stream2.aclose()

            # Rotating to the new certificate succeeds
            config.certfile = CERT2
            config.keyfile = KEY2
            assert ssl_context.reload() is True

            # The established connection is not interrupted by the reload
            assert await _trio_request(stream) == b"Hello, world!"

            # New connections complete a full handshake with the new certificate
            stream3 = await _trio_connect(port)
            assert _fingerprint(stream3.getpeercert(binary_form=True)) != fingerprint1
            assert stream3.selected_alpn_protocol() == "http/1.1"
            assert await _trio_request(stream3) == b"Hello, world!"

            # The SNI configuration is not lost on reload
            assert sni_names == ["localhost"] * 3

            await stream.aclose()
            await stream3.aclose()
        shutdown.set()


async def _trio_connect(port: int) -> trio.SSLStream:
    for _ in range(100):
        try:
            stream = await trio.open_ssl_over_tcp_stream(
                "localhost", port, ssl_context=_client_context(), https_compatible=True
            )
        except ConnectionRefusedError:
            await trio.sleep(0.05)
        else:
            await stream.do_handshake()
            return stream
    raise ConnectionRefusedError(f"Cannot connect to port {port}")


async def _trio_request(stream: trio.SSLStream) -> bytes:
    await stream.send_all(REQUEST)
    data = b""
    while b"\r\n\r\n" not in data:
        data += await stream.receive_some(2**16)
    headers, body = data.split(b"\r\n\r\n", 1)
    length = _content_length(headers)
    while len(body) < length:
        body += await stream.receive_some(2**16)
    return body[:length]
