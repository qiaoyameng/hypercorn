from __future__ import annotations

import json
import socket
import ssl
from collections.abc import Callable, Generator
from functools import partial
from typing import Any, cast

import pytest
import trio

import hypercorn.trio
from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.config import Config
from hypercorn.trio.tcp_server import TCPServer
from hypercorn.trio.worker_context import WorkerContext
from ..helpers import (
    MockSocket,
    PROXY_LOCAL_PREAMBLE,
    PROXY_V4_PREAMBLE,
    PROXY_V6_PREAMBLE,
    scope_framework,
)

REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"


def proxy_config(**overrides: Any) -> Config:
    config = Config()
    config.proxy_protocol = True
    config.proxy_protocol_allowed_networks = ["127.0.0.0/8", "::1/128"]
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def make_server(config: Config, nursery: trio.Nursery) -> trio.StapledStream:
    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream = cast("trio.SSLStream[trio.SocketStream]", server_stream)
    server_stream.socket = MockSocket()
    server = TCPServer(
        ASGIWrapper(scope_framework),
        config,
        WorkerContext(None),
        {},
        server_stream,
        config.create_ssl_context() if config.ssl_enabled else None,
    )
    nursery.start_soon(server.run)
    return client_stream


async def receive_all(stream: trio.abc.Stream) -> bytes:
    response = b""
    while True:
        try:
            chunk = bytes(await stream.receive_some(4096))
        except (trio.BrokenResourceError, trio.ClosedResourceError):
            return response
        if chunk == b"":
            return response
        response += chunk


def response_json(response: bytes) -> dict:
    assert response.startswith(b"HTTP/1.1 200")
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


@pytest.mark.trio
async def test_proxy_protocol_ipv4(nursery: trio.Nursery) -> None:
    client_stream = make_server(proxy_config(), nursery)
    await client_stream.send_all(PROXY_V4_PREAMBLE + REQUEST)
    data = response_json(await receive_all(client_stream))
    assert data["client"] == ["203.0.113.7", 45678]
    assert data["server"] == ["192.0.2.1", 443]
    assert data["scheme"] == "http"


@pytest.mark.trio
async def test_proxy_protocol_ipv6(nursery: trio.Nursery) -> None:
    client_stream = make_server(proxy_config(), nursery)
    await client_stream.send_all(PROXY_V6_PREAMBLE + REQUEST)
    data = response_json(await receive_all(client_stream))
    assert data["client"] == ["2001:db8::7", 45678]
    assert data["server"] == ["2001:db8::1", 443]


@pytest.mark.trio
async def test_proxy_protocol_local_command_keeps_transport_addresses(
    nursery: trio.Nursery,
) -> None:
    client_stream = make_server(proxy_config(), nursery)
    await client_stream.send_all(PROXY_LOCAL_PREAMBLE + REQUEST)
    data = response_json(await receive_all(client_stream))
    assert data["client"] == ["127.0.0.1", 80]
    assert data["server"] == ["162.1.1.1", 80]


@pytest.mark.trio
async def test_proxy_protocol_tls(nursery: trio.Nursery) -> None:
    config = proxy_config(certfile="tests/assets/cert.pem", keyfile="tests/assets/key.pem")
    client_stream = make_server(config, nursery)
    client_context = ssl.create_default_context()
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    tls_stream = trio.SSLStream(client_stream, client_context, server_hostname="example.com")
    await client_stream.send_all(PROXY_V4_PREAMBLE)
    await tls_stream.do_handshake()
    await tls_stream.send_all(REQUEST)
    data = response_json(await receive_all(tls_stream))
    assert data["client"] == ["203.0.113.7", 45678]
    assert data["server"] == ["192.0.2.1", 443]
    assert data["scheme"] == "https"


@pytest.mark.trio
async def test_proxy_protocol_untrusted_peer_rejected(nursery: trio.Nursery) -> None:
    config = proxy_config(proxy_protocol_allowed_networks=["10.0.0.0/8"])
    client_stream = make_server(config, nursery)
    await client_stream.send_all(PROXY_V4_PREAMBLE + REQUEST)
    assert await receive_all(client_stream) == b""


@pytest.mark.trio
async def test_proxy_protocol_oversized_preamble_rejected(nursery: trio.Nursery) -> None:
    client_stream = make_server(proxy_config(), nursery)
    fixed_header = b"\r\n\r\n\x00\r\nQUIT\n" + b"\x21\x11" + (2000).to_bytes(2, "big")
    await client_stream.send_all(fixed_header)
    assert await receive_all(client_stream) == b""


@pytest.mark.trio
async def test_proxy_protocol_truncated_preamble_rejected(nursery: trio.Nursery) -> None:
    client_stream = make_server(proxy_config(), nursery)
    await client_stream.send_all(PROXY_V4_PREAMBLE[:8])
    await client_stream.send_eof()
    assert await receive_all(client_stream) == b""


@pytest.mark.trio
async def test_proxy_protocol_partial_preamble_times_out(nursery: trio.Nursery) -> None:
    client_stream = make_server(proxy_config(proxy_protocol_timeout=0.1), nursery)
    await client_stream.send_all(PROXY_V4_PREAMBLE[:8])
    with trio.move_on_after(5):
        assert await receive_all(client_stream) == b""


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
    nursery: trio.Nursery, port: int, configure: Callable[[Config], None] | None = None
) -> trio.Event:
    config = proxy_config()
    config.bind = [f"127.0.0.1:{port}"]
    if configure is not None:
        configure(config)
    shutdown = trio.Event()
    nursery.start_soon(
        partial(hypercorn.trio.serve, scope_framework, config, shutdown_trigger=shutdown.wait)
    )
    await trio.testing.wait_all_tasks_blocked()
    return shutdown


async def roundtrip(port: int, data: bytes) -> bytes:
    stream = await trio.open_tcp_stream("127.0.0.1", port)
    await stream.send_all(data)
    with trio.move_on_after(5):
        return await receive_all(stream)
    raise AssertionError("Timed out waiting for response")


@pytest.mark.trio
async def test_socket_proxy_protocol_http(nursery: trio.Nursery, proxy_port: int) -> None:
    shutdown = await serve_proxy(nursery, proxy_port)
    try:
        data = response_json(await roundtrip(proxy_port, PROXY_V4_PREAMBLE + REQUEST))
        assert data["client"] == ["203.0.113.7", 45678]
        assert data["server"] == ["192.0.2.1", 443]
        assert data["scheme"] == "http"
    finally:
        shutdown.set()


@pytest.mark.trio
async def test_socket_proxy_protocol_tls(nursery: trio.Nursery, proxy_port: int) -> None:
    def configure(config: Config) -> None:
        config.certfile = "tests/assets/cert.pem"
        config.keyfile = "tests/assets/key.pem"

    shutdown = await serve_proxy(nursery, proxy_port, configure)
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

        data = response_json(await trio.to_thread.run_sync(tls_roundtrip))
        assert data["client"] == ["203.0.113.7", 45678]
        assert data["server"] == ["192.0.2.1", 443]
        assert data["scheme"] == "https"
    finally:
        shutdown.set()


@pytest.mark.trio
async def test_socket_proxy_protocol_untrusted_peer_rejected(
    nursery: trio.Nursery, proxy_port: int
) -> None:
    def configure(config: Config) -> None:
        config.proxy_protocol_allowed_networks = ["10.0.0.0/8"]

    shutdown = await serve_proxy(nursery, proxy_port, configure)
    try:
        assert await roundtrip(proxy_port, PROXY_V4_PREAMBLE + REQUEST) == b""
    finally:
        shutdown.set()
