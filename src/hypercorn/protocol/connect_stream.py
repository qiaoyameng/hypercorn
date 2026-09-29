from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import auto, Enum
from time import time
from urllib.parse import unquote

from .events import Body, Data, EndBody, EndData, Event, Request, Response, StreamClosed
from ..config import Config
from ..typing import (
    AppWrapper,
    ASGIReceiveEvent,
    ASGISendEvent,
    HTTPConnectAcceptEvent,
    HTTPResponseStartEvent,
    HTTPScope,
    TaskGroup,
    WorkerContext,
)
from ..utils import (
    build_and_validate_headers,
    suppress_body,
    UnexpectedMessageError,
    valid_server_name,
)


class ASGIConnectState(Enum):
    # The CONNECT tunnel extension allows the app to either accept the
    # tunnel (http.connect.accept) after which raw bytes flow in both
    # directions, or to respond with a plain HTTP response before
    # acceptance (a rejection).
    REQUEST = auto()
    CONNECTED = auto()
    RESPONSE = auto()
    CLOSED = auto()


class ConnectStream:
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
        self.app_put: Callable[[ASGIReceiveEvent], Awaitable[None]] | None = None
        self.client = client
        self.closed = False
        self.config = config
        self.context = context
        self.response: HTTPResponseStartEvent
        self.scope: HTTPScope
        self.send = send
        self.scheme = "https" if ssl else "http"
        self.server = server
        self.start_time: float
        self.state = ASGIConnectState.REQUEST
        self.stream_id = stream_id
        self.task_group = task_group
        # Data received from the client before the tunnel is accepted
        # is buffered and delivered to the app upon acceptance.
        self._buffer = bytearray()
        self._client_closed = False
        self._server_closed = False

    @property
    def idle(self) -> bool:
        return self.state == ASGIConnectState.CLOSED

    @property
    def accepted(self) -> bool:
        return self.state == ASGIConnectState.CONNECTED

    async def handle(self, event: Event) -> None:
        if self.closed:
            return
        elif isinstance(event, Request):
            self.start_time = time()
            path, _, query_string = event.raw_path.partition(b"?")
            self.scope = {
                "type": "http",
                "http_version": event.http_version,
                "asgi": {"spec_version": "2.1", "version": "3.0"},
                "method": event.method,
                "scheme": self.scheme,
                "path": unquote(path.decode("ascii")),
                "raw_path": path,
                "query_string": query_string,
                "root_path": self.config.root_path,
                "headers": event.headers,
                "client": self.client,
                "server": self.server,
                "state": event.state.copy(),  # type: ignore[typeddict-item]
                "extensions": {"http.connect": {}},
            }

            if valid_server_name(self.config, event):
                self.app_put = await self.task_group.spawn_app(
                    self.app, self.config, self.scope, self.app_send
                )
            else:
                await self._send_error_response(404)
                self.closed = True
        elif isinstance(event, (Body, Data)):
            if self.state == ASGIConnectState.CONNECTED and self.app_put is not None:
                await self.app_put(
                    {"type": "http.connect.receive", "body": bytes(event.data), "more_body": True}
                )
            elif self.state == ASGIConnectState.REQUEST:
                self._buffer.extend(event.data)
        elif isinstance(event, EndBody):
            # CONNECT requests have no body, so this is a HTTP/1
            # framing artifact rather than a client half-close.
            pass
        elif isinstance(event, EndData):
            # The client has half-closed its side of the tunnel, the
            # server can still send data in the other direction.
            self._client_closed = True
            if self.state == ASGIConnectState.CONNECTED and self.app_put is not None:
                await self.app_put(
                    {"type": "http.connect.receive", "body": b"", "more_body": False}
                )
        elif isinstance(event, StreamClosed):
            self.closed = True
            if self.state == ASGIConnectState.REQUEST:
                await self.config.log.access(self.scope, None, time() - self.start_time)
            if self.app_put is not None:
                await self.app_put({"type": "http.disconnect"})

    async def app_send(self, message: ASGISendEvent | None) -> None:
        if message is None:  # ASGI App has finished sending messages
            if not self.closed:
                # Cleanup if required
                if self.state == ASGIConnectState.REQUEST:
                    await self._send_error_response(500)
                elif self.state == ASGIConnectState.CONNECTED and not self._server_closed:
                    await self.send(EndData(stream_id=self.stream_id))
                await self.send(StreamClosed(stream_id=self.stream_id))
        elif message["type"] == "http.connect.accept" and self.state == ASGIConnectState.REQUEST:
            await self._accept(message)
        elif message["type"] == "http.response.start" and self.state == ASGIConnectState.REQUEST:
            status_code = int(message["status"])
            if 200 <= status_code < 300:
                raise ValueError(
                    "A 2XX response establishes a CONNECT tunnel, "
                    "use the http.connect.accept message instead"
                )
            self.response = message
            headers = build_and_validate_headers(self.response.get("headers", []))
            await self.send(
                Response(
                    stream_id=self.stream_id,
                    headers=headers,
                    status_code=status_code,
                )
            )
            self.state = ASGIConnectState.RESPONSE
        elif message["type"] == "http.response.body" and self.state == ASGIConnectState.RESPONSE:
            if (
                not suppress_body(self.scope["method"], int(self.response["status"]))
                and message.get("body", b"") != b""
            ):
                await self.send(Body(stream_id=self.stream_id, data=bytes(message["body"])))

            if not message.get("more_body", False):
                await self._send_closed()
        elif message["type"] == "http.connect.send" and self.state == ASGIConnectState.CONNECTED:
            if self._server_closed:
                raise UnexpectedMessageError(self.state, message["type"])
            body = bytes(message.get("body", b""))
            if body != b"":
                await self.send(Data(stream_id=self.stream_id, data=body))
            if not message.get("more_body", False):
                # Half-close the server to client direction only
                self._server_closed = True
                await self.send(EndData(stream_id=self.stream_id))
        else:
            raise UnexpectedMessageError(self.state, message["type"])

    async def _accept(self, message: HTTPConnectAcceptEvent) -> None:
        status_code = int(message.get("status", 200))
        if not 200 <= status_code < 300:
            raise ValueError("A CONNECT tunnel must be accepted with a 2XX status code")
        headers = build_and_validate_headers(message.get("headers", []))
        await self.send(
            Response(stream_id=self.stream_id, headers=headers, status_code=status_code)
        )
        self.state = ASGIConnectState.CONNECTED
        await self.config.log.access(
            self.scope, {"status": status_code, "headers": headers}, time() - self.start_time
        )
        if (len(self._buffer) > 0 or self._client_closed) and self.app_put is not None:
            await self.app_put(
                {
                    "type": "http.connect.receive",
                    "body": bytes(self._buffer),
                    "more_body": not self._client_closed,
                }
            )
            self._buffer = bytearray()

    async def _send_closed(self) -> None:
        await self.send(EndBody(stream_id=self.stream_id))
        self.state = ASGIConnectState.CLOSED
        await self.config.log.access(self.scope, self.response, time() - self.start_time)
        await self.send(StreamClosed(stream_id=self.stream_id))

    async def _send_error_response(self, status_code: int) -> None:
        await self.send(
            Response(
                stream_id=self.stream_id,
                headers=[(b"content-length", b"0"), (b"connection", b"close")],
                status_code=status_code,
            )
        )
        await self.send(EndBody(stream_id=self.stream_id))
        self.state = ASGIConnectState.CLOSED
        await self.config.log.access(
            self.scope, {"status": status_code, "headers": []}, time() - self.start_time
        )
