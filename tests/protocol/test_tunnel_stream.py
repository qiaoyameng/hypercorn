from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, call

import pytest
import pytest_asyncio

from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.logging import Logger
from hypercorn.protocol.events import Body, Data, EndBody, EndData, Request, Response, StreamClosed
from hypercorn.protocol.tunnel_stream import ASGITunnelState, TunnelStream
from hypercorn.typing import ConnectionState, TunnelAcceptEvent
from hypercorn.utils import UnexpectedMessageError


@pytest_asyncio.fixture(name="stream")  # type: ignore[misc]
async def _stream() -> TunnelStream:
    stream = TunnelStream(
        AsyncMock(), Config(), WorkerContext(None), AsyncMock(), False, None, None, AsyncMock(), 1
    )
    stream.task_group.spawn_app.return_value = AsyncMock()  # type: ignore
    stream.app_put = AsyncMock()
    stream.config._log = AsyncMock(spec=Logger)
    return stream


async def _connect(stream: TunnelStream) -> None:
    await stream.handle(
        Request(
            stream_id=1,
            http_version="2",
            headers=[],
            raw_path=b"example.com:443",
            method="CONNECT",
            state=ConnectionState({}),
        )
    )


async def _accept(stream: TunnelStream) -> None:
    await _connect(stream)
    await stream.app_send(cast(TunnelAcceptEvent, {"type": "tunnel.accept", "headers": []}))
    stream.send.reset_mock()  # type: ignore


@pytest.mark.asyncio
async def test_handle_request(stream: TunnelStream) -> None:
    await _connect(stream)
    stream.task_group.spawn_app.assert_called()  # type: ignore
    scope = stream.task_group.spawn_app.call_args[0][2]  # type: ignore
    assert scope == {
        "type": "tunnel",
        "asgi": {"spec_version": "2.5", "version": "3.0"},
        "http_version": "2",
        "method": "CONNECT",
        "scheme": "http",
        "path": "example.com:443",
        "raw_path": b"example.com:443",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": None,
        "server": None,
        "state": ConnectionState({}),
        "extensions": {"tunnel.http.response": {}},
    }
    assert stream.app_put.call_args_list == [call({"type": "tunnel.connect"})]  # type: ignore


@pytest.mark.asyncio
async def test_accept(stream: TunnelStream) -> None:
    await _connect(stream)
    await stream.app_send(
        {"type": "tunnel.accept", "headers": [(b"x-foo", b"bar")]}  # type: ignore
    )
    assert stream.state == ASGITunnelState.CONNECTED
    assert stream.send.call_args_list == [  # type: ignore
        call(Response(stream_id=1, status_code=200, headers=[(b"x-foo", b"bar")]))
    ]


@pytest.mark.asyncio
async def test_send_and_receive(stream: TunnelStream) -> None:
    await _accept(stream)
    await stream.handle(Body(stream_id=1, data=b"ping"))
    assert stream.app_put.call_args_list[-1] == call(  # type: ignore
        {"type": "tunnel.receive", "bytes": b"ping", "more": True}
    )
    await stream.app_send({"type": "tunnel.send", "bytes": b"pong"})  # type: ignore
    assert stream.send.call_args_list == [call(Data(stream_id=1, data=b"pong"))]  # type: ignore


@pytest.mark.asyncio
async def test_half_close_only_closes_client_direction(stream: TunnelStream) -> None:
    await _accept(stream)
    await stream.handle(EndBody(stream_id=1))
    assert stream.app_put.call_args_list[-1] == call(  # type: ignore
        {"type": "tunnel.receive", "bytes": b"", "more": False}
    )
    # The server to client direction must still be usable
    await stream.app_send({"type": "tunnel.send", "bytes": b"pending"})  # type: ignore
    await stream.app_send({"type": "tunnel.close"})  # type: ignore
    assert stream.send.call_args_list == [  # type: ignore
        call(Data(stream_id=1, data=b"pending")),
        call(EndData(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_rejection(stream: TunnelStream) -> None:
    await _connect(stream)
    await stream.app_send(
        {"type": "tunnel.http.response.start", "status": 403, "headers": []}  # type: ignore
    )
    await stream.app_send(
        {  # type: ignore
            "type": "tunnel.http.response.body",
            "body": b"Forbidden",
            "more_body": False,
        }
    )
    assert stream.state == ASGITunnelState.HTTPCLOSED
    assert stream.send.call_args_list == [  # type: ignore
        call(Response(stream_id=1, status_code=403, headers=[])),
        call(Body(stream_id=1, data=b"Forbidden")),
        call(EndBody(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_data_before_acceptance(stream: TunnelStream) -> None:
    await _connect(stream)
    await stream.handle(Data(stream_id=1, data=b"early"))
    assert stream.send.call_args_list == [  # type: ignore
        call(
            Response(
                stream_id=1,
                status_code=400,
                headers=[(b"content-length", b"0"), (b"connection", b"close")],
            )
        ),
        call(EndBody(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_http_body_framing_forbidden_after_accept(stream: TunnelStream) -> None:
    await _accept(stream)
    with pytest.raises(UnexpectedMessageError):
        await stream.app_send(
            {  # type: ignore
                "type": "tunnel.http.response.body",
                "body": b"nope",
                "more_body": False,
            }
        )


@pytest.mark.asyncio
async def test_early_disconnect(stream: TunnelStream) -> None:
    await _accept(stream)
    await stream.handle(StreamClosed(stream_id=1))
    assert stream.app_put.call_args_list[-1] == call({"type": "tunnel.disconnect"})  # type: ignore


@pytest.mark.asyncio
async def test_app_return_when_connected(stream: TunnelStream) -> None:
    await _accept(stream)
    await stream.app_send(None)
    assert stream.send.call_args_list == [  # type: ignore
        call(EndData(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]


@pytest.mark.asyncio
async def test_app_return_before_accept(stream: TunnelStream) -> None:
    await _connect(stream)
    await stream.app_send(None)
    assert stream.send.call_args_list == [  # type: ignore
        call(
            Response(
                stream_id=1,
                status_code=500,
                headers=[(b"content-length", b"0"), (b"connection", b"close")],
            )
        ),
        call(EndBody(stream_id=1)),
        call(StreamClosed(stream_id=1)),
    ]
