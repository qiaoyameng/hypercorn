from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, call, Mock

import pytest
from _pytest.monkeypatch import MonkeyPatch

import hypercorn.protocol.http_stream
from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.events import Closed
from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope
from .helpers import MemoryReader, MemoryWriter
from ..helpers import BoundedReadFile, bounded_open_factory, echo_framework


@pytest.mark.asyncio
async def test_completes_on_closed() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    server = TCPServer(
        ASGIWrapper(echo_framework),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    server.reader.close()  # type: ignore
    await server.run()
    # Key is that this line is reached, rather than the above line
    # hanging.


@pytest.mark.asyncio
async def test_complets_on_half_close() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    server = TCPServer(
        ASGIWrapper(echo_framework),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    task = event_loop.create_task(server.run())
    await server.reader.send(b"GET / HTTP/1.1\r\nHost: hypercorn\r\n\r\n")  # type: ignore
    server.reader.close()  # type: ignore
    await task
    data = await server.writer.receive()  # type: ignore
    assert (
        data
        == b"HTTP/1.1 200 \r\ncontent-length: 376\r\ndate: Thu, 01 Jan 1970 01:23:20 GMT\r\nserver: hypercorn-h11\r\n\r\n"  # noqa: E501
    )


@pytest.mark.asyncio
async def test_pathsend(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    body = b"x" * (3 * 2**16 + 5)
    file_path = tmp_path / "asset.bin"
    file_path.write_bytes(body)
    opened: list[BoundedReadFile] = []
    monkeypatch.setattr(
        hypercorn.protocol.http_stream,
        "open",
        bounded_open_factory(str(file_path), opened),
        raising=False,
    )

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert "http.response.pathsend" in scope["extensions"]  # type: ignore
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.pathsend", "path": str(file_path)})

    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = TCPServer(
        ASGIWrapper(app),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    task = event_loop.create_task(server.run())
    await server.reader.send(b"GET / HTTP/1.1\r\nHost: hypercorn\r\n\r\n")  # type: ignore
    received = b""
    while True:
        received += await server.writer.receive()  # type: ignore
        head, separator, response_body = received.partition(b"\r\n\r\n")
        if separator and len(response_body) >= len(body):
            break
    server.reader.close()  # type: ignore
    await task
    assert head.startswith(b"HTTP/1.1 200")
    assert b"content-length: %d" % len(body) in head
    assert response_body == body
    # The fallback path must read the file in bounded chunks, never whole
    assert len(opened) == 1
    assert len(opened[0].read_sizes) > 1
    assert max(opened[0].read_sizes) <= 2**16


def _send_file_server() -> TCPServer:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    server = TCPServer(
        ASGIWrapper(echo_framework),
        event_loop,
        Config(),
        WorkerContext(None),
        {},
        MemoryReader(),  # type: ignore
        MemoryWriter(),  # type: ignore
    )
    server.protocol = AsyncMock()
    return server


@pytest.mark.asyncio
async def test_send_file_uses_sendfile(tmp_path: Path) -> None:
    file_path = tmp_path / "asset.bin"
    file_path.write_bytes(b"data")
    server = _send_file_server()
    transport = Mock()
    server.writer = Mock()
    server.writer.transport = transport
    server.writer.get_extra_info.return_value = None  # Not SSL
    server.loop = Mock()
    server.loop.sendfile = AsyncMock()
    with open(file_path, "rb") as file:
        await server._send_file(file)
    server.loop.sendfile.assert_called_once()
    assert server.loop.sendfile.call_args_list == [
        call(transport, file, fallback=False)
    ]


@pytest.mark.asyncio
async def test_send_file_sendfile_unsupported_falls_back(tmp_path: Path) -> None:
    body = b"x" * (2**16 + 5)
    file_path = tmp_path / "asset.bin"
    file_path.write_bytes(body)
    server = _send_file_server()
    server.writer = Mock()
    server.writer.transport = Mock()
    server.writer.get_extra_info.return_value = None  # Not SSL
    server.writer.drain = AsyncMock()
    server.loop = Mock()
    server.loop.sendfile = AsyncMock(side_effect=RuntimeError("unsupported"))
    with open(file_path, "rb") as file:
        await server._send_file(file)
    written = b"".join(call[0][0] for call in server.writer.write.call_args_list)
    assert written == body


@pytest.mark.asyncio
async def test_send_file_ssl_reads_chunks(tmp_path: Path) -> None:
    body = b"x" * (2**16 + 5)
    file_path = tmp_path / "asset.bin"
    file_path.write_bytes(body)
    server = _send_file_server()
    server.writer = Mock()
    server.writer.transport = Mock()
    server.writer.get_extra_info.return_value = Mock()  # SSL connection
    server.writer.drain = AsyncMock()
    server.loop = Mock()
    server.loop.sendfile = AsyncMock()
    with open(file_path, "rb") as file:
        await server._send_file(file)
    server.loop.sendfile.assert_not_called()
    written = b"".join(call[0][0] for call in server.writer.write.call_args_list)
    assert written == body


@pytest.mark.asyncio
async def test_send_file_client_disconnect(tmp_path: Path) -> None:
    file_path = tmp_path / "asset.bin"
    file_path.write_bytes(b"data")
    server = _send_file_server()
    server.writer = Mock()
    server.writer.transport = None  # Force the chunked fallback
    server.writer.get_extra_info.return_value = None
    server.writer.write.side_effect = ConnectionError()
    server.writer.drain = AsyncMock()
    with open(file_path, "rb") as file:
        await server._send_file(file)
    assert server.protocol.handle.call_args_list == [call(Closed())]
