from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from collections.abc import Callable, Generator
from typing import Any

import pytest

import hypercorn.asyncio
from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from .helpers import MemoryReader, MemoryWriter
from ..helpers import (
    MockSocket,
    PROXY_LOCAL_PREAMBLE,
    PROXY_V4_PREAMBLE,
    PROXY_V6_PREAMBLE,
    scope_framework,
)

REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"


class MockSSLContext:
    pass


class MockSSLObject:
    def selected_alpn_protocol(self) -> str:
        return "http/1.1"


class TLSMemoryWriter(MemoryWriter):
    def __init__(self) -> None:
        super().__init__()
        self.ssl_context: MockSSLContext | None = None

    async def start_tls(
        self, ssl_context: MockSSLContext, ssl_handshake_timeout: float | None = None
    ) -> None:
        self.ssl_context = ssl_context

    def get_extra_info(self, name: str) -> MockSocket | MockSSLObject | None:
        if name == "ssl_object" and self.ssl_context is not None:
            return MockSSLObject()
        return super().get_extra_info(name)


def proxy_config(**overrides: Any) -> Config:
    config = Config()
    config.proxy_protocol = True
    config.proxy_protocol_allowed_networks = ["127.0.0.0/8", "::1/128"]
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


async def run_server(
    config: Config, writer: MemoryWriter | None = None
) -> tuple[TCPServer, asyncio.Task]:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = TCPServer(
        ASGIWrapper(scope_framework),
        event_loop,
        config,
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        writer if writer is not None else MemoryWriter(),  # type: ignore
        MockSSLContext() if config.ssl_enabled else None,  # type: ignore
    )
    return server, event_loop.create_task(server.run())


async def receive_response(server: TCPServer) -> bytes:
    response = b""
    while True:
        data = await server.writer.receive()  # type: ignore
        if data == b"":
            return response
        response += data


def response_json(response: bytes) -> dict:
    assert response.startswith(b"HTTP/1.1 200")
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


@pytest.mark.asyncio
async def test_proxy_protocol_ipv4() -> None:
    server, task = await run_server(proxy_config())
    await server.reader.send(PROXY_V4_PREAMBLE + REQUEST)  # type: ignore
    server.reader.close()  # type: ignore
    data = response_json(await receive_response(server))
    assert data["client"] == ["203.0.113.7", 45678]
    assert data["server"] == ["192.0.2.1", 443]
    assert data["scheme"] == "http"
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_ipv6() -> None:
    server, task = await run_server(proxy_config())
    await server.reader.send(PROXY_V6_PREAMBLE + REQUEST)  # type: ignore
    server.reader.close()  # type: ignore
    data = response_json(await receive_response(server))
    assert data["client"] == ["2001:db8::7", 45678]
    assert data["server"] == ["2001:db8::1", 443]
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_local_command_keeps_transport_addresses() -> None:
    server, task = await run_server(proxy_config())
    await server.reader.send(PROXY_LOCAL_PREAMBLE + REQUEST)  # type: ignore
    server.reader.close()  # type: ignore
    data = response_json(await receive_response(server))
    assert data["client"] == ["127.0.0.1", 80]
    assert data["server"] == ["162.1.1.1", 80]
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_logs_transport_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    server, task = await run_server(proxy_config())
    with caplog.at_level(logging.INFO, logger="hypercorn.error"):
        await server.reader.send(PROXY_V4_PREAMBLE + REQUEST)  # type: ignore
        server.reader.close()  # type: ignore
        await receive_response(server)
    assert "203.0.113.7" in caplog.text
    assert "127.0.0.1" in caplog.text
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_tls_upgrade() -> None:
    config = proxy_config(certfile="tests/assets/cert.pem", keyfile="tests/assets/key.pem")
    writer = TLSMemoryWriter()
    server, task = await run_server(config, writer)
    await server.reader.send(PROXY_V4_PREAMBLE + REQUEST)  # type: ignore
    server.reader.close()  # type: ignore
    data = response_json(await receive_response(server))
    assert writer.ssl_context is not None
    assert data["client"] == ["203.0.113.7", 45678]
    assert data["scheme"] == "https"
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_untrusted_peer_rejected(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = proxy_config(proxy_protocol_allowed_networks=["10.0.0.0/8"])
    server, task = await run_server(config)
    with caplog.at_level(logging.WARNING, logger="hypercorn.error"):
        await server.reader.send(PROXY_V4_PREAMBLE + REQUEST)  # type: ignore
        server.reader.close()  # type: ignore
        assert await receive_response(server) == b""
    assert "untrusted" in caplog.text
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_oversized_preamble_rejected() -> None:
    server, task = await run_server(proxy_config())
    fixed_header = b"\r\n\r\n\x00\r\nQUIT\n" + b"\x21\x11" + (2000).to_bytes(2, "big")
    await server.reader.send(fixed_header)  # type: ignore
    server.reader.close()  # type: ignore
    assert await receive_response(server) == b""
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_truncated_preamble_rejected() -> None:
    server, task = await run_server(proxy_config())
    await server.reader.send(PROXY_V4_PREAMBLE[:8])  # type: ignore
    server.reader.close()  # type: ignore
    assert await receive_response(server) == b""
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_partial_preamble_times_out() -> None:
    server, task = await run_server(proxy_config(proxy_protocol_timeout=0.1))
    await server.reader.send(PROXY_V4_PREAMBLE[:8])  # type: ignore
    assert await receive_response(server) == b""
    server.reader.close()  # type: ignore
    await task


@pytest.mark.asyncio
async def test_proxy_protocol_invalid_preamble_rejected() -> None:
    server, task = await run_server(proxy_config())
    await server.reader.send(REQUEST)  # type: ignore
    server.reader.close()  # type: ignore
    assert await receive_response(server) == b""
    await task


@pytest.fixture(name="proxy_port")
def _proxy_port() -> Generator[int, None, None]:
    try:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
    except PermissionError:
        pytest.skip("TCP sockets are not permitted in this environment")
    port = sock.getsockname()[1]
    yield port
    sock.close()


async def serve_proxy(
    port: int, configure: Callable[[Config], None] | None = None
) -> tuple[asyncio.Task, asyncio.Event]:
    config = proxy_config()
    config.bind = [f"127.0.0.1:{port}"]
    if configure is not None:
        configure(config)
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        hypercorn.asyncio.serve(scope_framework, config, shutdown_trigger=shutdown.wait)
    )
    for _ in range(100):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.01)
        else:
            writer.close()
            return task, shutdown
    raise AssertionError("Server did not start")


async def roundtrip(port: int, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    return await asyncio.wait_for(reader.read(), 5)


@pytest.mark.asyncio
async def test_socket_proxy_protocol_http(proxy_port: int) -> None:
    task, shutdown = await serve_proxy(proxy_port)
    try:
        data = response_json(await roundtrip(proxy_port, PROXY_V4_PREAMBLE + REQUEST))
        assert data["client"] == ["203.0.113.7", 45678]
        assert data["server"] == ["192.0.2.1", 443]
        assert data["scheme"] == "http"
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_socket_proxy_protocol_tls(proxy_port: int) -> None:
    def configure(config: Config) -> None:
        config.certfile = "tests/assets/cert.pem"
        config.keyfile = "tests/assets/key.pem"

    task, shutdown = await serve_proxy(proxy_port, configure)
    try:

        def tls_roundtrip() -> bytes:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", proxy_port)) as sock:
                sock.sendall(PROXY_V4_PREAMBLE)
                with context.wrap_socket(sock, server_hostname="example.com") as tls_sock:
                    tls_sock.sendall(REQUEST)
                    response = b""
                    while True:
                        chunk = tls_sock.recv(4096)
                        if chunk == b"":
                            return response
                        response += chunk
            return response

        data = response_json(await asyncio.to_thread(tls_roundtrip))
        assert data["client"] == ["203.0.113.7", 45678]
        assert data["server"] == ["192.0.2.1", 443]
        assert data["scheme"] == "https"
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_socket_proxy_protocol_untrusted_peer_rejected(proxy_port: int) -> None:
    def configure(config: Config) -> None:
        config.proxy_protocol_allowed_networks = ["10.0.0.0/8"]

    task, shutdown = await serve_proxy(proxy_port, configure)
    try:
        assert await roundtrip(proxy_port, PROXY_V4_PREAMBLE + REQUEST) == b""
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_socket_proxy_protocol_partial_preamble_does_not_block(
    proxy_port: int,
) -> None:
    def configure(config: Config) -> None:
        config.proxy_protocol_timeout = 0.2

    task, shutdown = await serve_proxy(proxy_port, configure)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(PROXY_V4_PREAMBLE[:8])
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()
        data = response_json(await roundtrip(proxy_port, PROXY_V4_PREAMBLE + REQUEST))
        assert data["client"] == ["203.0.113.7", 45678]
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 5)
