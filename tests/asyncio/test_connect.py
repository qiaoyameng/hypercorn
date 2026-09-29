from __future__ import annotations

import asyncio
from typing import Any

import h2.connection
import h2.events
import h11
import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope
from .helpers import MemoryReader, MemoryWriter
from ..helpers import ConnectEchoFramework


class ResettableMemoryReader(MemoryReader):
    def reset(self) -> None:
        self.data.put_nowait(ConnectionResetError())  # type: ignore

    async def read(self, length: int) -> bytes:
        item = await self.data.get()
        if isinstance(item, Exception):
            raise item
        return item


class SlowEchoFramework:
    # A CONNECT echo endpoint that is slow to read the tunnelled data
    def __init__(self, delay: float) -> None:
        self.delay = delay

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        await send({"type": "http.connect.accept", "status": 200, "headers": []})
        while True:
            event = await receive()
            if event["type"] == "http.connect.receive":
                await asyncio.sleep(self.delay)
                await send(
                    {
                        "type": "http.connect.send",
                        "body": event["body"],
                        "more_body": event.get("more_body", False),
                    }
                )
                if not event.get("more_body", False):
                    break
            elif event["type"] == "http.disconnect":
                break


def _server(app: Any, http2: bool = False) -> TCPServer:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    return TCPServer(
        ASGIWrapper(app),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(http2=http2),  # type: ignore
    )


async def _send_connect_request(server: TCPServer, client: h11.Connection, host: bytes) -> None:
    await server.reader.send(  # type: ignore
        client.send(
            h11.Request(method="CONNECT", target=host, headers=[(b"host", host)]),
        )
    )


async def _receive_response(server: TCPServer, client: h11.Connection) -> list:
    events = []
    while True:
        event = client.next_event()
        if event == h11.NEED_DATA:
            client.receive_data(await server.writer.receive())  # type: ignore
        else:
            events.append(event)
            return events


@pytest.mark.asyncio
async def test_http1_connect_echo() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework())
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await _send_connect_request(server, client, b"hypercorn:443")
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    assert events[0].status_code == 200
    # The connection has switched to a raw tunnel
    await server.reader.send(b"hello")  # type: ignore
    assert await server.writer.receive() == b"hello"  # type: ignore
    await server.reader.send(b"world")  # type: ignore
    assert await server.writer.receive() == b"world"  # type: ignore
    server.reader.close()  # type: ignore
    await task
    assert server.writer.is_closed  # type: ignore


@pytest.mark.asyncio
async def test_http1_connect_rejection() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework())
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await _send_connect_request(server, client, b"reject:443")
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    assert events[0].status_code == 403
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Data)
    assert events[0].data == b"denied!"
    server.reader.close()  # type: ignore
    await task


@pytest.mark.asyncio
async def test_http1_connect_optimistic_data() -> None:
    # Data sent by the client before the tunnel is accepted must be
    # delivered after acceptance.
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework())
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    request = client.send(
        h11.Request(
            method="CONNECT",
            target="hypercorn:443",
            headers=[(b"host", b"hypercorn:443")],
        )
    )
    await server.reader.send(request + b"early")  # type: ignore
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    assert events[0].status_code == 200
    assert await server.writer.receive() == b"early"  # type: ignore
    server.reader.close()  # type: ignore
    await task


@pytest.mark.asyncio
async def test_http1_connect_client_half_close() -> None:
    # A client half-close must not discard data the server is yet to
    # send in the other direction.
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework())
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await _send_connect_request(server, client, b"hypercorn:443")
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    # Send data and half-close before the echo is received
    await server.reader.send(b"pending")  # type: ignore
    server.reader.close()  # type: ignore
    assert await server.writer.receive() == b"pending"  # type: ignore
    await task
    assert server.writer.is_closed  # type: ignore


@pytest.mark.asyncio
async def test_http1_connect_early_disconnect() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    app = ConnectEchoFramework()
    server = TCPServer(
        ASGIWrapper(app),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        ResettableMemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await _send_connect_request(server, client, b"hypercorn:443")
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    server.reader.reset()  # type: ignore
    await task
    assert app.disconnected


@pytest.mark.asyncio
async def test_http1_connect_slow_reader() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(SlowEchoFramework(0.05))
    task = event_loop.create_task(server.run())
    client = h11.Connection(h11.CLIENT)
    await _send_connect_request(server, client, b"hypercorn:443")
    events = await _receive_response(server, client)
    assert isinstance(events[0], h11.Response)
    chunks = [b"one", b"two", b"three"]
    for chunk in chunks:
        await server.reader.send(chunk)  # type: ignore
    echoed = b""
    while len(echoed) < len(b"".join(chunks)):
        echoed += await server.writer.receive()  # type: ignore
    assert echoed == b"".join(chunks)
    server.reader.close()  # type: ignore
    await task


async def _receive_h2_events(
    server: TCPServer, client: h2.connection.H2Connection
) -> list[h2.events.Event]:
    data = await server.writer.receive()  # type: ignore
    events = client.receive_data(data)
    for event in events:
        if isinstance(event, h2.events.DataReceived):
            client.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
    await server.reader.send(client.data_to_send())  # type: ignore
    return events


@pytest.mark.asyncio
async def test_http2_connect_echo_with_parallel_request() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework(), http2=True)
    task = event_loop.create_task(server.run())
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    connect_stream_id = client.get_next_available_stream_id()
    client.send_headers(
        connect_stream_id,
        [
            (":method", "CONNECT"),
            (":authority", "hypercorn:443"),
        ],
    )
    request_stream_id = client.get_next_available_stream_id()
    client.send_headers(
        request_stream_id,
        [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "hypercorn"),
            (":scheme", "https"),
        ],
        end_stream=True,
    )
    await server.reader.send(client.data_to_send())  # type: ignore
    # Both the tunnel and the normal request are answered
    responses: dict[int, list[h2.events.Event]] = {connect_stream_id: [], request_stream_id: []}
    while not all(
        any(isinstance(event, h2.events.ResponseReceived) for event in events)
        for events in responses.values()
    ):
        for event in await _receive_h2_events(server, client):
            if getattr(event, "stream_id", None) in responses:
                responses[event.stream_id].append(event)  # type: ignore[attr-defined]
    assert responses[connect_stream_id][0].headers[0] == (b":status", b"200")
    assert responses[request_stream_id][0].headers[0] == (b":status", b"200")
    # The tunnel echoes whilst the normal request completes
    client.send_data(connect_stream_id, b"echo")
    await server.reader.send(client.data_to_send())  # type: ignore
    received: dict[int, list[h2.events.Event]] = {connect_stream_id: [], request_stream_id: []}
    while not any(
        isinstance(event, h2.events.DataReceived) for event in received[connect_stream_id]
    ):
        for event in await _receive_h2_events(server, client):
            if getattr(event, "stream_id", None) in received:
                received[event.stream_id].append(event)  # type: ignore[attr-defined]
    data_events = [
        event for event in received[connect_stream_id] if isinstance(event, h2.events.DataReceived)
    ]
    assert data_events[0].data == b"echo"
    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await task


@pytest.mark.asyncio
async def test_http2_connect_client_half_close() -> None:
    # END_STREAM from the client must not discard data the server is
    # yet to send on the stream.
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = _server(ConnectEchoFramework(), http2=True)
    task = event_loop.create_task(server.run())
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    stream_id = client.get_next_available_stream_id()
    client.send_headers(
        stream_id,
        [
            (":method", "CONNECT"),
            (":authority", "hypercorn:443"),
        ],
    )
    await server.reader.send(client.data_to_send())  # type: ignore
    while True:
        events = await _receive_h2_events(server, client)
        if any(isinstance(event, h2.events.ResponseReceived) for event in events):
            break
    # Send data and half-close the stream before the echo is received
    client.send_data(stream_id, b"pending")
    client.end_stream(stream_id)
    await server.reader.send(client.data_to_send())  # type: ignore
    received = []
    while not any(isinstance(event, h2.events.StreamEnded) for event in received):
        received.extend(await _receive_h2_events(server, client))
    data_events = [event for event in received if isinstance(event, h2.events.DataReceived)]
    assert data_events[0].data == b"pending"
    # The data was received before the stream ended
    assert received.index(data_events[0]) < next(
        index
        for index, event in enumerate(received)
        if isinstance(event, h2.events.StreamEnded)
    )
    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await task
