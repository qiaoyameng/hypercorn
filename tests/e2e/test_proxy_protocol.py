from __future__ import annotations

import asyncio
import json
import socket
import ssl
from functools import partial

import pytest
import trio

import hypercorn.trio.run
from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.run import worker_serve as asyncio_worker_serve
from hypercorn.config import Config, Sockets
from hypercorn.proxy_protocol import SIGNATURE
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope

PREAMBLE = (
    SIGNATURE
    + b"\x21\x11"
    + (19).to_bytes(2, "big")
    + b"\xc0\x00\x02\x01"  # 192.0.2.1
    + b"\xc6\x33\x64\x02"  # 198.51.100.2
    + (54321).to_bytes(2, "big")
    + (443).to_bytes(2, "big")
    + b"\x03\x00\x04\x01\x02\x03\x04"  # A TLV to preserve
)

REQUEST = b"GET / HTTP/1.1\r\nHost: hypercorn\r\nConnection: close\r\n\r\n"


async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    proxy = scope["state"].get("proxy_protocol")  # type: ignore[attr-defined]
    body = json.dumps(
        {
            "client": scope["client"],  # type: ignore[attr-defined]
            "server": scope["server"],  # type: ignore[attr-defined]
            "proxy": None
            if proxy is None
            else {
                "command": proxy["command"],
                "transport_client": proxy["transport_client"],
                "transport_server": proxy["transport_server"],
                "tlvs": [[type_, value.hex()] for type_, value in proxy["tlvs"]],
            },
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _read_response(sock: socket.socket) -> dict:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(2**16)
        assert chunk, "Connection closed before a response was received"
        data += chunk
    headers, _, body = data.partition(b"\r\n\r\n")
    content_length = 0
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":")[1].strip())
    while len(body) < content_length:
        chunk = sock.recv(2**16)
        assert chunk, "Connection closed before the response body was received"
        body += chunk
    return json.loads(body.decode())


def _http_client(port: int, preamble: bytes) -> dict:
    with socket.create_connection(("127.0.0.1", port)) as sock:
        sock.sendall(preamble + REQUEST)
        return _read_response(sock)


def _https_client(port: int, preamble: bytes) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port))
    raw.sendall(preamble)
    with context.wrap_socket(raw, server_hostname="localhost") as sock:
        sock.sendall(REQUEST)
        return _read_response(sock)


def _check_response(response: dict, port: int) -> None:
    assert response["client"] == ["192.0.2.1", 54321]
    assert response["server"] == ["198.51.100.2", 443]
    proxy = response["proxy"]
    assert proxy["command"] == "proxy"
    # The original transport addresses remain traceable
    assert proxy["transport_client"][0] == "127.0.0.1"
    assert proxy["transport_server"] == ["127.0.0.1", port]
    assert proxy["tlvs"] == [[3, "01020304"]]


def _config(**kwargs: object) -> Config:
    config = Config()
    config.bind = ["127.0.0.1:0"]
    config.proxy_protocol = True
    config.proxy_protocol_allowed_networks = ["127.0.0.0/8"]
    config.proxy_protocol_timeout = 0.2
    for key, value in kwargs.items():
        setattr(config, key, value)
    return config


def _sockets(config: Config) -> tuple[Sockets, int]:
    sockets = config.create_sockets()
    if sockets.secure_sockets:
        return sockets, sockets.secure_sockets[0].getsockname()[1]
    return sockets, sockets.insecure_sockets[0].getsockname()[1]


@pytest.mark.asyncio
async def test_asyncio_proxy_protocol_http() -> None:
    config = _config()
    sockets, port = _sockets(config)
    shutdown = asyncio.Event()
    task = asyncio.get_running_loop().create_task(
        asyncio_worker_serve(
            ASGIWrapper(app), config, sockets=sockets, shutdown_trigger=shutdown.wait
        )
    )
    try:
        response = await asyncio.to_thread(_http_client, port, PREAMBLE)
        _check_response(response, port)
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_asyncio_proxy_protocol_https() -> None:
    config = _config(certfile="tests/assets/cert.pem", keyfile="tests/assets/key.pem")
    sockets, port = _sockets(config)
    shutdown = asyncio.Event()
    task = asyncio.get_running_loop().create_task(
        asyncio_worker_serve(
            ASGIWrapper(app), config, sockets=sockets, shutdown_trigger=shutdown.wait
        )
    )
    try:
        response = await asyncio.to_thread(_https_client, port, PREAMBLE)
        _check_response(response, port)
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_asyncio_proxy_protocol_untrusted_peer() -> None:
    config = _config(proxy_protocol_allowed_networks=["10.0.0.0/8"])
    sockets, port = _sockets(config)
    shutdown = asyncio.Event()
    task = asyncio.get_running_loop().create_task(
        asyncio_worker_serve(
            ASGIWrapper(app), config, sockets=sockets, shutdown_trigger=shutdown.wait
        )
    )
    try:
        def client() -> bytes:
            with socket.create_connection(("127.0.0.1", port)) as sock:
                sock.sendall(PREAMBLE + REQUEST)
                return sock.recv(2**16)

        assert await asyncio.to_thread(client) == b""
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_asyncio_proxy_protocol_half_preamble_does_not_block() -> None:
    config = _config()
    sockets, port = _sockets(config)
    shutdown = asyncio.Event()
    task = asyncio.get_running_loop().create_task(
        asyncio_worker_serve(
            ASGIWrapper(app), config, sockets=sockets, shutdown_trigger=shutdown.wait
        )
    )
    try:
        def half_client() -> bytes:
            with socket.create_connection(("127.0.0.1", port)) as sock:
                sock.sendall(PREAMBLE[:8])  # Never completed
                sock.settimeout(5)
                return sock.recv(2**16)  # b"" once the preamble read times out

        assert await asyncio.to_thread(half_client) == b""
        # The worker is still able to serve other connections
        response = await asyncio.to_thread(_http_client, port, PREAMBLE)
        _check_response(response, port)
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.trio
async def test_trio_proxy_protocol_http() -> None:
    config = _config()
    sockets, port = _sockets(config)
    for sock in sockets.insecure_sockets:
        sock.listen(config.backlog)
    shutdown = trio.Event()
    async with trio.open_nursery() as nursery:
        nursery.start_soon(
            partial(
                hypercorn.trio.run.worker_serve,
                ASGIWrapper(app),
                config,
                sockets=sockets,
                shutdown_trigger=shutdown.wait,
            )
        )
        response = await trio.to_thread.run_sync(_http_client, port, PREAMBLE)
        _check_response(response, port)
        shutdown.set()


@pytest.mark.trio
async def test_trio_proxy_protocol_https() -> None:
    config = _config(certfile="tests/assets/cert.pem", keyfile="tests/assets/key.pem")
    sockets, port = _sockets(config)
    for sock in sockets.secure_sockets:
        sock.listen(config.backlog)
    shutdown = trio.Event()
    async with trio.open_nursery() as nursery:
        nursery.start_soon(
            partial(
                hypercorn.trio.run.worker_serve,
                ASGIWrapper(app),
                config,
                sockets=sockets,
                shutdown_trigger=shutdown.wait,
            )
        )
        response = await trio.to_thread.run_sync(_https_client, port, PREAMBLE)
        _check_response(response, port)
        shutdown.set()
