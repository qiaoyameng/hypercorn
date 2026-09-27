from __future__ import annotations

import asyncio

import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope
from .helpers import MemoryWriter

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

REQUEST = b"GET / HTTP/1.1\r\nHost: hypercorn\r\n\r\n"


class ProxyReader:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.eof = False
        self._event = asyncio.Event()

    async def send(self, data: bytes) -> None:
        self.buffer.extend(data)
        self._event.set()

    def close(self) -> None:
        self.eof = True
        self._event.set()

    async def readexactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            if self.eof:
                partial = bytes(self.buffer)
                self.buffer.clear()
                raise asyncio.IncompleteReadError(partial, n)
            self._event.clear()
            await self._event.wait()
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    async def read(self, n: int) -> bytes:
        while not self.buffer:
            if self.eof:
                return b""
            self._event.clear()
            await self._event.wait()
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def at_eof(self) -> bool:
        return self.eof and not self.buffer


class ScopeRecorder:
    def __init__(self) -> None:
        self.scope: Scope | None = None
        self._event = asyncio.Event()

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        self.scope = scope
        self._event.set()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK"})

    async def wait(self) -> None:
        await asyncio.wait_for(self._event.wait(), 1)


def _config(**kwargs: object) -> Config:
    config = Config()
    config.proxy_protocol = True
    config.proxy_protocol_allowed_networks = ["127.0.0.0/8"]
    for key, value in kwargs.items():
        setattr(config, key, value)
    return config


@pytest.mark.asyncio
async def test_proxy_protocol_scope() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(PREAMBLE + REQUEST)
    await app.wait()
    reader.close()
    await task

    assert app.scope is not None
    assert app.scope["client"] == ("192.0.2.1", 54321)
    assert app.scope["server"] == ("198.51.100.2", 443)
    proxy_state = app.scope["state"]["proxy_protocol"]
    assert proxy_state["command"] == "proxy"
    # The original transport addresses remain traceable
    assert proxy_state["transport_client"] == ("127.0.0.1", 80)
    assert proxy_state["transport_server"] == ("162.1.1.1", 80)
    assert proxy_state["tlvs"] == [(0x03, b"\x01\x02\x03\x04")]


@pytest.mark.asyncio
async def test_proxy_protocol_local_command_keeps_addresses() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    preamble = SIGNATURE + b"\x20\x11" + (12).to_bytes(2, "big") + b"\x00" * 12
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(preamble + REQUEST)
    await app.wait()
    reader.close()
    await task

    assert app.scope is not None
    assert app.scope["client"] == ("127.0.0.1", 80)
    assert app.scope["server"] == ("162.1.1.1", 80)
    assert app.scope["state"]["proxy_protocol"]["command"] == "local"


@pytest.mark.asyncio
async def test_proxy_protocol_untrusted_peer_rejected() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(proxy_protocol_allowed_networks=["10.0.0.0/8"]),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(PREAMBLE + REQUEST)
    await asyncio.wait_for(task, 1)

    assert app.scope is None
    assert writer.is_closed


@pytest.mark.asyncio
async def test_proxy_protocol_invalid_preamble_rejected() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(REQUEST)  # A plain HTTP request is not a valid preamble
    await asyncio.wait_for(task, 1)

    assert app.scope is None
    assert writer.is_closed


@pytest.mark.asyncio
async def test_proxy_protocol_truncated_preamble_rejected() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(PREAMBLE[:10])
    reader.close()
    await asyncio.wait_for(task, 1)

    assert app.scope is None
    assert writer.is_closed


@pytest.mark.asyncio
async def test_proxy_protocol_half_preamble_times_out() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(proxy_protocol_timeout=0.05),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(PREAMBLE[:8])  # Never completed
    await asyncio.wait_for(task, 1)

    assert app.scope is None
    assert writer.is_closed


@pytest.mark.asyncio
async def test_proxy_protocol_oversized_preamble_rejected() -> None:
    app = ScopeRecorder()
    reader, writer = ProxyReader(), MemoryWriter()
    server = TCPServer(
        ASGIWrapper(app),
        asyncio.get_running_loop(),
        _config(proxy_protocol_max_size=16),
        WorkerContext(None),
        {},
        reader,  # type: ignore
        writer,  # type: ignore
    )
    task = asyncio.get_running_loop().create_task(server.run())
    await reader.send(PREAMBLE + REQUEST)
    await asyncio.wait_for(task, 1)

    assert app.scope is None
    assert writer.is_closed
