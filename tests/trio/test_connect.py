from __future__ import annotations

from typing import cast

import h11
import pytest
import trio

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.config import Config
from hypercorn.trio.tcp_server import TCPServer
from hypercorn.trio.worker_context import WorkerContext
from ..helpers import ConnectEchoFramework, MockSocket


@pytest.mark.trio
async def test_http1_connect_echo(nursery: trio.Nursery) -> None:
    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream = cast("trio.SSLStream[trio.SocketStream]", server_stream)
    server_stream.socket = MockSocket()
    server = TCPServer(
        ASGIWrapper(ConnectEchoFramework()), Config(), WorkerContext(None), {}, server_stream
    )
    nursery.start_soon(server.run)
    client = h11.Connection(h11.CLIENT)
    await client_stream.send_all(
        client.send(
            h11.Request(
                method="CONNECT",
                target="hypercorn:443",
                headers=[(b"host", b"hypercorn:443")],
            )
        )
    )
    client.receive_data(await client_stream.receive_some())
    event = client.next_event()
    assert isinstance(event, h11.Response)
    assert event.status_code == 200
    # The connection has switched to a raw tunnel
    await client_stream.send_all(b"hello")
    assert await client_stream.receive_some() == b"hello"
    # Half-close, the server can still send its pending data
    await client_stream.send_all(b"pending")
    await client_stream.send_eof()
    assert await client_stream.receive_some() == b"pending"
    assert await client_stream.receive_some() == b""
    await client_stream.aclose()


@pytest.mark.trio
async def test_http1_connect_rejection(nursery: trio.Nursery) -> None:
    client_stream, server_stream = trio.testing.memory_stream_pair()
    server_stream = cast("trio.SSLStream[trio.SocketStream]", server_stream)
    server_stream.socket = MockSocket()
    server = TCPServer(
        ASGIWrapper(ConnectEchoFramework()), Config(), WorkerContext(None), {}, server_stream
    )
    nursery.start_soon(server.run)
    client = h11.Connection(h11.CLIENT)
    await client_stream.send_all(
        client.send(
            h11.Request(method="CONNECT", target="reject:443", headers=[(b"host", b"reject:443")])
        )
    )
    events = []
    while not events or not isinstance(events[-1], h11.EndOfMessage):
        client.receive_data(await client_stream.receive_some())
        while True:
            event = client.next_event()
            if event is h11.NEED_DATA:
                break
            events.append(event)
    assert isinstance(events[0], h11.Response)
    assert events[0].status_code == 403
    assert isinstance(events[1], h11.Data)
    assert events[1].data == b"denied!"
    await client_stream.aclose()
