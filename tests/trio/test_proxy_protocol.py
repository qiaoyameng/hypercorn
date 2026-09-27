from __future__ import annotations

import ipaddress

import pytest
import trio

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.config import Config
from hypercorn.proxy_protocol import SIGNATURE
from hypercorn.trio.tcp_server import PrebufferedStream, TCPServer
from hypercorn.trio.worker_context import WorkerContext
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope
from ..helpers import MockSocket

PREAMBLE = (
    SIGNATURE
    + b"\x21\x21"
    + (36).to_bytes(2, "big")
    + ipaddress.IPv6Address("2001:db8::1").packed
    + ipaddress.IPv6Address("2001:db8::2").packed
    + (54321).to_bytes(2, "big")
    + (443).to_bytes(2, "big")
)

REQUEST = b"GET / HTTP/1.1\r\nHost: hypercorn\r\n\r\n"


class FakeStream:
    def __init__(self) -> None:
        self.socket = MockSocket()
        self.buffer = bytearray()
        self.sent = bytearray()
        self.closed = False
        self.eof = False
        self._event = trio.Event()

    async def send(self, data: bytes) -> None:
        self.buffer.extend(data)
        self._event = trio.Event()
        self._event.set()

    def close(self) -> None:
        self.eof = True
        self._event = trio.Event()
        self._event.set()

    async def receive_some(self, max_bytes: int | None = None) -> bytes:
        while not self.buffer:
            if self.eof:
                return b""
            event = self._event
            await event.wait()
        max_bytes = max_bytes or len(self.buffer)
        data = bytes(self.buffer[:max_bytes])
        del self.buffer[:max_bytes]
        return data

    async def send_all(self, data: bytes) -> None:
        self.sent.extend(data)

    async def wait_send_all_might_not_block(self) -> None:
        pass

    async def send_eof(self) -> None:
        self.eof = True

    async def aclose(self) -> None:
        self.closed = True


class ScopeRecorder:
    def __init__(self) -> None:
        self.scope: Scope | None = None
        self._event = trio.Event()

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        self.scope = scope
        self._event.set()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK"})

    async def wait(self) -> None:
        with trio.fail_after(1):
            await self._event.wait()


def _config(**kwargs: object) -> Config:
    config = Config()
    config.proxy_protocol = True
    config.proxy_protocol_allowed_networks = ["127.0.0.0/8"]
    for key, value in kwargs.items():
        setattr(config, key, value)
    return config


@pytest.mark.trio
async def test_prebuffered_stream() -> None:
    stream = FakeStream()
    buffered = PrebufferedStream(stream)  # type: ignore[arg-type]
    await stream.send(b"hello")
    assert await buffered.receive_some(2) == b"he"
    buffered.prepend(b"llo")
    assert await buffered.receive_some(5) == b"llo"
    await stream.send(b" world")
    assert await buffered.receive_some(6) == b" world"


@pytest.mark.trio
async def test_proxy_protocol_scope() -> None:
    app = ScopeRecorder()
    stream = FakeStream()
    server = TCPServer(
        ASGIWrapper(app), _config(), WorkerContext(None), {}, stream  # type: ignore
    )
    async with trio.open_nursery() as nursery:
        nursery.start_soon(server.run)
        await stream.send(PREAMBLE + REQUEST)
        await app.wait()
        stream.close()
        with trio.fail_after(1):
            while not stream.closed:
                await trio.sleep(0.01)
        nursery.cancel_scope.cancel()

    assert app.scope is not None
    assert app.scope["client"] == ("2001:db8::1", 54321)
    assert app.scope["server"] == ("2001:db8::2", 443)
    proxy_state = app.scope["state"]["proxy_protocol"]
    assert proxy_state["transport_client"] == ("127.0.0.1", 80)
    assert proxy_state["transport_server"] == ("162.1.1.1", 80)


@pytest.mark.trio
async def test_proxy_protocol_untrusted_peer_rejected() -> None:
    app = ScopeRecorder()
    stream = FakeStream()
    server = TCPServer(
        ASGIWrapper(app),
        _config(proxy_protocol_allowed_networks=["10.0.0.0/8"]),
        WorkerContext(None),
        {},
        stream,  # type: ignore
    )
    async with trio.open_nursery() as nursery:
        nursery.start_soon(server.run)
        await stream.send(PREAMBLE + REQUEST)
        with trio.fail_after(1):
            while not stream.closed:
                await trio.sleep(0.01)
        nursery.cancel_scope.cancel()

    assert app.scope is None
    assert stream.closed


@pytest.mark.trio
async def test_proxy_protocol_half_preamble_times_out() -> None:
    app = ScopeRecorder()
    stream = FakeStream()
    server = TCPServer(
        ASGIWrapper(app),
        _config(proxy_protocol_timeout=0.05),
        WorkerContext(None),
        {},
        stream,  # type: ignore
    )
    async with trio.open_nursery() as nursery:
        nursery.start_soon(server.run)
        await stream.send(PREAMBLE[:8])  # Never completed
        with trio.fail_after(1):
            while not stream.closed:
                await trio.sleep(0.01)
        nursery.cancel_scope.cancel()

    assert app.scope is None
    assert stream.closed
