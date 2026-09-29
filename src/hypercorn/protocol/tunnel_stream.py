from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import auto, Enum
from time import time
from urllib.parse import unquote

from .events import Body, Data, EndBody, EndData, Event, Request, Response, StreamClosed
from ..config import Config
from ..typing import (
    AppWrapper,
    ASGISendEvent,
    TaskGroup,
    TunnelAcceptEvent,
    TunnelResponseBodyEvent,
    TunnelResponseStartEvent,
    TunnelScope,
    WorkerContext,
)
from ..utils import (
    build_and_validate_headers,
    suppress_body,
    UnexpectedMessageError,
    valid_server_name,
)


class ASGITunnelState(Enum):
    # Before acceptance the tunnel behaves like a normal HTTP
    # request/response, after acceptance only raw byte messages are
    # allowed.
    REQUEST = auto()
    CONNECTED = auto()
    RESPONSE = auto()
    CLOSED = auto()
    HTTPCLOSED = auto()


class TunnelStream:
    # This is a ASGI tunnel (CONNECT) stream, the app decides whether
    # to accept the tunnel (and hence where to connect to) or to
    # reject it with a normal HTTP response.
    def __init__(
        self,
        app: AppWrapper,
        config: Config,
        context: WorkerContext,
        task_group: TaskGroup,
        ssl: bool,
        client: tuple[str, int] | None,
        server: tuple[str, int] | None,
        send: Callable[[Event], Awaitable[None]],
        stream_id: int,
    ) -> None:
        self.app = app
        self.app_put: Callable | None = None
        self.client = client
        self.closed = False
        self.config = config
        self.context = context
        self.task_group = task_group
        self.response: TunnelResponseStartEvent
        self.scope: TunnelScope
        self.send = send
        self.scheme = "https" if ssl else "http"
        self.server = server
        self.start_time: float
        self.state = ASGITunnelState.REQUEST
        self.stream_id = stream_id

    @property
    def idle(self) -> bool:
        return self.state in {ASGITunnelState.CLOSED, ASGITunnelState.HTTPCLOSED}

    @property
    def connected(self) -> bool:
        return self.state == ASGITunnelState.CONNECTED

    async def handle(self, event: Event) -> None:
        if self.closed:
            return
        elif isinstance(event, Request):
            self.start_time = time()
            path, _, query_string = event.raw_path.partition(b"?")
            self.scope = {
                "type": "tunnel",
                "asgi": {"spec_version": "2.5", "version": "3.0"},
                "http_version": event.http_version,
                "method": event.method,
                "scheme": self.scheme,
                "path": unquote(path.decode("ascii", "surrogateescape")),
                "raw_path": path,
                "query_string": query_string,
                "root_path": self.config.root_path,
                "headers": event.headers,
                "client": self.client,
                "server": self.server,
                "state": event.state.copy(),  # type: ignore[typeddict-item]
                "extensions": {"tunnel.http.response": {}},
            }

            if not valid_server_name(self.config, event):
                await self._send_error_response(404)
                self.closed = True
            else:
                self.app_put = await self.task_group.spawn_app(
                    self.app, self.config, self.scope, self.app_send
                )
                await self.app_put({"type": "tunnel.connect"})
        elif isinstance(event, (Body, Data)):
            if self.state == ASGITunnelState.CONNECTED:
                await self.app_put(
                    {"type": "tunnel.receive", "bytes": bytes(event.data), "more": True}
                )
            else:
                # Data received before the tunnel was accepted is a
                # protocol error.
                await self._send_error_response(400)
                self.closed = True
        elif isinstance(event, EndBody):
            # The client has half-closed the tunnel, only the client
            # to server direction is affected, the app may continue to
            # send data.
            if self.state == ASGITunnelState.CONNECTED:
                await self.app_put({"type": "tunnel.receive", "bytes": b"", "more": False})
        elif isinstance(event, StreamClosed):
            self.closed = True
            if self.app_put is not None:
                await self.app_put({"type": "tunnel.disconnect"})

    async def app_send(self, message: ASGISendEvent | None) -> None:
        if self.closed:
            # Allow app to finish after close
            return

        if message is None:  # ASGI App has finished sending messages
            # Cleanup if required
            if self.state == ASGITunnelState.REQUEST:
                await self._send_error_response(500)
            elif self.state == ASGITunnelState.CONNECTED:
                await self.send(EndData(stream_id=self.stream_id))
            await self.send(StreamClosed(stream_id=self.stream_id))
        else:
            if message["type"] == "tunnel.accept" and self.state == ASGITunnelState.REQUEST:
                await self._accept(message)
            elif (
                message["type"] == "tunnel.http.response.start"
                and self.state == ASGITunnelState.REQUEST
            ):
                self.response = message
            elif message["type"] == "tunnel.http.response.body" and self.state in {
                ASGITunnelState.REQUEST,
                ASGITunnelState.RESPONSE,
            }:
                await self._send_rejection(message)
            elif message["type"] == "tunnel.send" and self.state == ASGITunnelState.CONNECTED:
                await self.send(
                    Data(stream_id=self.stream_id, data=bytes(message.get("bytes", b"")))
                )
            elif message["type"] == "tunnel.close" and self.state == ASGITunnelState.CONNECTED:
                self.state = ASGITunnelState.CLOSED
                # EndData ensures any unsent data is flushed before
                # the stream is ended (half-closing our direction).
                await self.send(EndData(stream_id=self.stream_id))
                self.closed = True
                await self.send(StreamClosed(stream_id=self.stream_id))
            else:
                raise UnexpectedMessageError(self.state, message["type"])

    async def _accept(self, message: TunnelAcceptEvent) -> None:
        self.state = ASGITunnelState.CONNECTED
        headers = build_and_validate_headers(message.get("headers", []))
        await self.send(Response(stream_id=self.stream_id, status_code=200, headers=headers))
        await self.config.log.access(
            self.scope, {"status": 200, "headers": headers}, time() - self.start_time
        )

    async def _send_rejection(self, message: TunnelResponseBodyEvent) -> None:
        body_suppressed = suppress_body("CONNECT", self.response["status"])
        if self.state == ASGITunnelState.REQUEST:
            headers = build_and_validate_headers(self.response["headers"])
            await self.send(
                Response(
                    stream_id=self.stream_id,
                    status_code=int(self.response["status"]),
                    headers=headers,
                )
            )
            self.state = ASGITunnelState.RESPONSE
        if not body_suppressed:
            await self.send(Body(stream_id=self.stream_id, data=bytes(message.get("body", b""))))
        if not message.get("more_body", False):
            self.state = ASGITunnelState.HTTPCLOSED
            await self.send(EndBody(stream_id=self.stream_id))
            await self.config.log.access(self.scope, self.response, time() - self.start_time)

    async def _send_error_response(self, status_code: int) -> None:
        await self.send(
            Response(
                stream_id=self.stream_id,
                status_code=status_code,
                headers=[(b"content-length", b"0"), (b"connection", b"close")],
            )
        )
        await self.send(EndBody(stream_id=self.stream_id))
        await self.config.log.access(
            self.scope, {"status": status_code, "headers": []}, time() - self.start_time
        )
