from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from json import dumps
from socket import AF_INET
from typing import cast

from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, Scope, WWWScope

SANITY_BODY = b"Hello Hypercorn"


class MockSocket:
    family = AF_INET

    def getsockname(self) -> tuple[str, int]:
        return ("162.1.1.1", 80)

    def getpeername(self) -> tuple[str, int]:
        return ("127.0.0.1", 80)


async def empty_framework(scope: Scope, receive: Callable, send: Callable) -> None:
    pass


class SlowLifespanFramework:
    def __init__(self, delay: float, sleep: Callable) -> None:
        self.delay = delay
        self.sleep = sleep

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        await self.sleep(self.delay)


async def echo_framework(
    input_scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
) -> None:
    input_scope = cast(WWWScope, input_scope)
    scope = deepcopy(input_scope)
    scope["query_string"] = scope["query_string"].decode()  # type: ignore
    scope["raw_path"] = scope["raw_path"].decode()  # type: ignore
    scope["headers"] = [
        (name.decode(), value.decode()) for name, value in scope["headers"]  # type: ignore
    ]

    body = bytearray()
    while True:
        event = await receive()
        if event["type"] in {"http.disconnect", "websocket.disconnect"}:
            break
        elif event["type"] == "http.request":
            body.extend(event.get("body", b""))
            if not event.get("more_body", False):
                response = dumps({"scope": scope, "request_body": body.decode()}).encode()
                content_length = len(response)
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [(b"content-length", str(content_length).encode())],
                    }
                )
                await send({"type": "http.response.body", "body": response, "more_body": False})
                break
        elif event["type"] == "websocket.connect":
            await send({"type": "websocket.accept"})  # type: ignore
        elif event["type"] == "websocket.receive":
            await send({"type": "websocket.send", "text": event["text"], "bytes": event["bytes"]})


async def sanity_framework(
    scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
) -> None:
    body = b""
    if scope["type"] == "websocket":
        await send({"type": "websocket.accept"})  # type: ignore

    while True:
        event = await receive()
        if event["type"] in {"http.disconnect", "websocket.disconnect"}:
            break
        elif event["type"] == "lifespan.startup":
            assert "state" in scope
            await send({"type": "lifspan.startup.complete"})  # type: ignore
        elif event["type"] == "lifespan.shutdown":
            await send({"type": "lifspan.shutdown.complete"})  # type: ignore
        elif event["type"] == "http.request" and event.get("more_body", False):
            body += event["body"]
        elif event["type"] == "http.request" and not event.get("more_body", False):
            body += event["body"]
            assert body == SANITY_BODY
            response = b"Hello & Goodbye"
            content_length = len(response)
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-length", str(content_length).encode())],
                }
            )
            await send({"type": "http.response.body", "body": response, "more_body": False})
            break
        elif event["type"] == "websocket.receive":
            assert event["bytes"] == SANITY_BODY
            await send({"type": "websocket.send", "text": "Hello & Goodbye"})  # type: ignore


class ConnectEchoFramework:
    # An in-app echo endpoint for the http.connect extension. It
    # rejects requests whose host starts with "reject" with a plain
    # HTTP response, accepts any other CONNECT request and echoes the
    # tunnelled bytes back. Plain HTTP requests are answered normally.
    def __init__(self) -> None:
        self.disconnected = False

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        if scope["type"] != "http":
            return
        if "http.connect" not in scope["extensions"]:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-length", b"2")],
                }
            )
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})
            return

        headers = dict(scope["headers"])
        if headers.get(b"host", b"").startswith(b"reject"):
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-length", b"7")],
                }
            )
            await send({"type": "http.response.body", "body": b"denied!", "more_body": False})
            return

        await send({"type": "http.connect.accept", "status": 200, "headers": []})
        while True:
            event = await receive()
            if event["type"] == "http.connect.receive":
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
                self.disconnected = True
                break
