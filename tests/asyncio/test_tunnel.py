from __future__ import annotations

import asyncio

import h2.connection
import h2.events
import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope
from .helpers import MemoryReader, MemoryWriter
from ..helpers import tunnel_framework

TIMEOUT = 2


async def _receive(server: TCPServer, timeout: float = TIMEOUT) -> bytes:
    return await asyncio.wait_for(server.writer.receive(), timeout)  # type: ignore


async def _wait_for_h2_event(
    server: TCPServer,
    client: h2.connection.H2Connection,
    event_type: type,
    stream_id: int,
) -> h2.events.Event:
    async def _poll() -> h2.events.Event:
        while True:
            data = await server.writer.receive()  # type: ignore
            for event in client.receive_data(data):
                if isinstance(event, event_type) and event.stream_id == stream_id:
                    return event

    return await asyncio.wait_for(_poll(), TIMEOUT)


def _serve(http2: bool = True) -> tuple[TCPServer, asyncio.Task]:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = TCPServer(
        ASGIWrapper(tunnel_framework),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(http2=http2),  # type: ignore
    )
    return server, event_loop.create_task(server.run())


@pytest.mark.asyncio
async def test_http1_tunnel_echo_and_half_close() -> None:
    server, task = _serve(http2=False)
    await server.reader.send(  # type: ignore
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    assert (await _receive(server)).startswith(b"HTTP/1.1 200")
    await server.reader.send(b"ping")  # type: ignore
    assert await _receive(server) == b"ping"
    # The client half-closes (sends EOF), this must only close the
    # client to server direction.
    server.reader.close()  # type: ignore
    # Data the app still had to send must not be lost
    assert await _receive(server) == b"Goodbye"
    await asyncio.wait_for(task, TIMEOUT)
    assert server.writer.is_closed  # type: ignore


@pytest.mark.asyncio
async def test_http1_tunnel_rejection() -> None:
    server, task = _serve(http2=False)
    await server.reader.send(  # type: ignore
        b"CONNECT reject.example.com:443 HTTP/1.1\r\nHost: reject.example.com:443\r\n\r\n"
    )
    assert (await _receive(server)).startswith(b"HTTP/1.1 403")
    assert await _receive(server) == b"Forbidden"
    server.reader.close()  # type: ignore
    await asyncio.wait_for(task, TIMEOUT)
    assert server.writer.is_closed  # type: ignore


@pytest.mark.asyncio
async def test_http2_tunnel_echo_parallel_request_and_half_close() -> None:
    server, task = _serve()
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    client.receive_data(await _receive(server))  # Server settings

    client.send_headers(1, [(":method", "CONNECT"), (":authority", "example.com:443")])
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.ResponseReceived, 1)
    assert (b":status", b"200") in event.headers  # type: ignore

    client.send_data(1, b"ping")
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.DataReceived, 1)
    assert event.data == b"ping"  # type: ignore
    client.acknowledge_received_data(event.flow_controlled_length, 1)  # type: ignore

    # A normal request on a parallel stream is unaffected by the tunnel
    client.send_headers(
        3,
        [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "hypercorn"),
            (":scheme", "https"),
        ],
        end_stream=True,
    )
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.ResponseReceived, 3)
    assert (b":status", b"200") in event.headers  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.DataReceived, 3)
    assert event.data == b"Hello"  # type: ignore
    client.acknowledge_received_data(event.flow_controlled_length, 3)  # type: ignore
    await _wait_for_h2_event(server, client, h2.events.StreamEnded, 3)

    # The tunnel still works after the parallel request completed
    client.send_data(1, b"ping2")
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.DataReceived, 1)
    assert event.data == b"ping2"  # type: ignore
    client.acknowledge_received_data(event.flow_controlled_length, 1)  # type: ignore

    # Half-close the tunnel stream, the pending server data must arrive
    # before the stream ends.
    client.end_stream(1)
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.DataReceived, 1)
    assert event.data == b"Goodbye"  # type: ignore
    client.acknowledge_received_data(event.flow_controlled_length, 1)  # type: ignore
    await _wait_for_h2_event(server, client, h2.events.StreamEnded, 1)

    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await asyncio.wait_for(task, TIMEOUT)


@pytest.mark.asyncio
async def test_http2_tunnel_rejection() -> None:
    server, task = _serve()
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    client.receive_data(await _receive(server))  # Server settings

    client.send_headers(1, [(":method", "CONNECT"), (":authority", "reject.example.com:443")])
    await server.reader.send(client.data_to_send())  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.ResponseReceived, 1)
    assert (b":status", b"403") in event.headers  # type: ignore
    event = await _wait_for_h2_event(server, client, h2.events.DataReceived, 1)
    assert event.data == b"Forbidden"  # type: ignore
    await _wait_for_h2_event(server, client, h2.events.StreamEnded, 1)

    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await asyncio.wait_for(task, TIMEOUT)


@pytest.mark.asyncio
async def test_http2_tunnel_slow_reader() -> None:
    # The app echoes a large amount of data whilst the client is slow
    # to read (doesn't acknowledge), the server must apply
    # backpressure rather than drop data.
    total = 100_000
    server, task = _serve()
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    client.receive_data(await _receive(server))  # Server settings

    client.send_headers(1, [(":method", "CONNECT"), (":authority", "example.com:443")])
    await server.reader.send(client.data_to_send())  # type: ignore
    await _wait_for_h2_event(server, client, h2.events.ResponseReceived, 1)

    sent = 0
    received = 0
    while received < 65535:  # The default flow control window
        while sent < total and client.local_flow_control_window(1) > 0:
            chunk = min(2**14, client.local_flow_control_window(1), total - sent)
            client.send_data(1, b"x" * chunk)
            sent += chunk
        await server.reader.send(client.data_to_send())  # type: ignore
        data = await _receive(server)
        for event in client.receive_data(data):
            if isinstance(event, h2.events.DataReceived):
                # Purposely don't acknowledge, a slow reader
                received += len(event.data)
    assert received == 65535  # Stalled, the window is exhausted
    with pytest.raises(asyncio.TimeoutError):
        await _receive(server, timeout=0.2)

    # Acknowledge (read) the data, the rest must now flow
    client.acknowledge_received_data(received, 1)
    await server.reader.send(client.data_to_send())  # type: ignore
    while received < total:
        while sent < total and client.local_flow_control_window(1) > 0:
            chunk = min(2**14, client.local_flow_control_window(1), total - sent)
            client.send_data(1, b"x" * chunk)
            sent += chunk
        await server.reader.send(client.data_to_send())  # type: ignore
        data = await _receive(server)
        for event in client.receive_data(data):
            if isinstance(event, h2.events.DataReceived):
                client.acknowledge_received_data(event.flow_controlled_length, 1)
                received += len(event.data)
        await server.reader.send(client.data_to_send())  # type: ignore
    assert received == total

    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await asyncio.wait_for(task, TIMEOUT)


@pytest.mark.asyncio
async def test_http2_tunnel_early_disconnect() -> None:
    disconnected = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "tunnel":
            await send({"type": "tunnel.accept", "headers": []})  # type: ignore
            while True:
                event = await receive()
                if event["type"] == "tunnel.disconnect":
                    disconnected.set()
                    return

    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = TCPServer(
        ASGIWrapper(app),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(http2=True),  # type: ignore
    )
    task = event_loop.create_task(server.run())
    client = h2.connection.H2Connection()
    client.initiate_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    client.receive_data(await _receive(server))  # Server settings

    client.send_headers(1, [(":method", "CONNECT"), (":authority", "example.com:443")])
    await server.reader.send(client.data_to_send())  # type: ignore
    await _wait_for_h2_event(server, client, h2.events.ResponseReceived, 1)

    # The client abruptly resets the stream
    client.reset_stream(1)
    await server.reader.send(client.data_to_send())  # type: ignore
    await asyncio.wait_for(disconnected.wait(), TIMEOUT)

    client.close_connection()
    await server.reader.send(client.data_to_send())  # type: ignore
    server.reader.close()  # type: ignore
    await asyncio.wait_for(task, TIMEOUT)
