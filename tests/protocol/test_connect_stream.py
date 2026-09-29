from __future__ import annotations

from unittest.mock import AsyncMock, call

import pytest
import pytest_asyncio

from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.logging import Logger
from hypercorn.protocol.connect_stream import ASGIConnectState, ConnectStream
from hypercorn.protocol.events import (
    Body,
    Data,
    EndBody,
    EndData,
    Request,
    Response,
    StreamClosed,
)
from hypercorn.typing import ConnectionState
from hypercorn.utils import UnexpectedMessageError


@pytest_asyncio.fixture(name="stream")  # type: ignore[misc]
async def _stream() -> ConnectStream:
    stream = ConnectStream(
        AsyncMock(), Config(), WorkerContext(None), AsyncMock(), False, None, None, AsyncMock(), 1
    )
    stream.app_put = AsyncMock()
    stream.config._log = AsyncMock(spec=Logger)
    return stream


@pytest_asyncio.fixture(name="requested_stream")  # type: ignore[misc]
async def _requested_stream(stream: ConnectStream) -> ConnectStream:
    await stream.handle(
        Request(
            stream_id=1,
            http_version="1.1",
            headers=[(b"host", b"hypercorn")],
            raw_path=b"hypercorn:443",
            method="CONNECT",
            state=ConnectionState({}),
        )
    )
    return stream


@pytest.mark.asyncio
async def test_handle_request_scope(stream: ConnectStream) -> None:
    await stream.handle(
        Request(
            stream_id=1,
            http_version="2",
            headers=[(b"host", b"hypercorn")],
            raw_path=b"hypercorn:443",
            method="CONNECT",
            state=ConnectionState({}),
        )
    )
    stream.task_group.spawn_app.assert_called()  # type: ignore
    scope = stream.task_group.spawn_app.call_args[0][2]  # type: ignore
    assert scope == {
        "type": "http",
        "http_version": "2",
        "asgi": {"spec_version": "2.1", "version": "3.0"},
        "method": "CONNECT",
        "scheme": "http",
        "path": "hypercorn:443",
        "raw_path": b"hypercorn:443",
        "query_string": b"",
        "root_path": stream.config.root_path,
        "headers": [(b"host", b"hypercorn")],
        "client": None,
        "server": None,
        "extensions": {"http.connect": {}},
        "state": ConnectionState({}),
    }


@pytest.mark.asyncio
async def test_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept", "status": 200, "headers": []})
    assert stream.state == ASGIConnectState.CONNECTED
    stream.send.assert_called_once_with(  # type: ignore
        Response(stream_id=1, headers=[], status_code=200)
    )


@pytest.mark.asyncio
async def test_accept_defaults(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    stream.send.assert_called_once_with(  # type: ignore
        Response(stream_id=1, headers=[], status_code=200)
    )


@pytest.mark.asyncio
async def test_accept_non_2xx(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    with pytest.raises(ValueError):
        await stream.app_send({"type": "http.connect.accept", "status": 404, "headers": []})


@pytest.mark.asyncio
async def test_response_start_2xx_requires_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    with pytest.raises(ValueError):
        await stream.app_send({"type": "http.response.start", "status": 200, "headers": []})


@pytest.mark.asyncio
async def test_rejection(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send(
        {"type": "http.response.start", "status": 403, "headers": [(b"content-length", b"7")]}
    )
    await stream.app_send({"type": "http.response.body", "body": b"denied!", "more_body": False})
    assert stream.state == ASGIConnectState.CLOSED
    assert stream.send.call_args_list == [  # type: ignore
        call(Response(stream_id=1, headers=[(b"content-length", b"7")], status_code=403)),
        call(Body(stream_id=1, data=b"denied!")),
        call(EndBody(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_send_and_receive(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    await stream.handle(Data(stream_id=1, data=b"hello"))
    stream.app_put.assert_called_with(  # type: ignore
        {"type": "http.connect.receive", "body": b"hello", "more_body": True}
    )
    await stream.app_send({"type": "http.connect.send", "body": b"world", "more_body": True})
    stream.send.assert_called_with(Data(stream_id=1, data=b"world"))  # type: ignore


@pytest.mark.asyncio
async def test_client_half_close(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    await stream.handle(EndData(stream_id=1))
    stream.app_put.assert_called_with(  # type: ignore
        {"type": "http.connect.receive", "body": b"", "more_body": False}
    )
    # The server can still send data in the other direction
    await stream.app_send({"type": "http.connect.send", "body": b"data", "more_body": True})
    stream.send.assert_called_with(Data(stream_id=1, data=b"data"))  # type: ignore


@pytest.mark.asyncio
async def test_server_half_close(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    await stream.app_send({"type": "http.connect.send", "body": b"data", "more_body": False})
    assert stream.send.call_args_list[-2:] == [  # type: ignore
        call(Data(stream_id=1, data=b"data")),
        call(EndData(stream_id=1)),
    ]
    with pytest.raises(UnexpectedMessageError):
        await stream.app_send({"type": "http.connect.send", "body": b"more", "more_body": True})


@pytest.mark.asyncio
async def test_data_buffered_before_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.handle(Data(stream_id=1, data=b"early "))
    await stream.handle(Data(stream_id=1, data=b"data"))
    stream.app_put.assert_not_called()  # type: ignore
    await stream.app_send({"type": "http.connect.accept"})
    stream.app_put.assert_called_once_with(  # type: ignore
        {"type": "http.connect.receive", "body": b"early data", "more_body": True}
    )


@pytest.mark.asyncio
async def test_client_end_buffered_before_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.handle(Data(stream_id=1, data=b"early"))
    await stream.handle(EndData(stream_id=1))
    await stream.app_send({"type": "http.connect.accept"})
    stream.app_put.assert_called_once_with(  # type: ignore
        {"type": "http.connect.receive", "body": b"early", "more_body": False}
    )


@pytest.mark.asyncio
async def test_http_body_framing_forbidden_after_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    with pytest.raises(UnexpectedMessageError):
        await stream.app_send({"type": "http.response.body", "body": b"nope", "more_body": False})
    with pytest.raises(UnexpectedMessageError):
        await stream.app_send({"type": "http.response.start", "status": 200, "headers": []})


@pytest.mark.asyncio
async def test_app_finish_without_response(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send(None)
    assert stream.send.call_args_list == [  # type: ignore
        call(
            Response(
                stream_id=1,
                headers=[(b"content-length", b"0"), (b"connection", b"close")],
                status_code=500,
            )
        ),
        call(EndBody(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_app_finish_after_accept(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    await stream.app_send(None)
    assert stream.send.call_args_list[-2:] == [  # type: ignore
        call(EndData(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_stream_closed_sends_disconnect(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    await stream.app_send({"type": "http.connect.accept"})
    await stream.handle(StreamClosed(stream_id=1))
    stream.app_put.assert_called_once_with({"type": "http.disconnect"})  # type: ignore


@pytest.mark.asyncio
async def test_unexpected_message(requested_stream: ConnectStream) -> None:
    stream = requested_stream
    with pytest.raises(UnexpectedMessageError):
        await stream.app_send({"type": "http.connect.send", "body": b"a", "more_body": True})
