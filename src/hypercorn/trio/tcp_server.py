from __future__ import annotations

from collections.abc import Generator
from math import inf
from ssl import SSLContext
from typing import Any

import trio

from .task_group import TaskGroup
from .worker_context import TrioSingleTask, WorkerContext
from ..config import Config
from ..events import Closed, Event, RawData, Updated
from ..protocol import ProtocolWrapper
from ..proxy_protocol import (
    COMMAND_PROXY,
    FIXED_HEADER_LENGTH,
    parse_proxy_v2_preamble,
    preamble_length,
    ProxyProtocolError,
    ProxyProtocolInfo,
)
from ..typing import AppWrapper, ConnectionState, LifespanState
from ..utils import parse_socket_addr

MAX_RECV = 2**16


class TCPServer:
    def __init__(
        self,
        app: AppWrapper,
        config: Config,
        context: WorkerContext,
        state: LifespanState,
        stream: trio.SSLStream[trio.SocketStream] | trio.SocketStream,
        ssl_context: SSLContext | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.context = context
        self.protocol: ProtocolWrapper
        self.send_lock = trio.Lock()
        self.idle_task = TrioSingleTask()
        self.ssl_context = ssl_context
        self.stream = stream
        self.state = state

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        proxy_info: ProxyProtocolInfo | None = None
        if self.config.proxy_protocol:
            proxy_info = await self._read_proxy_protocol()
            if proxy_info is None:
                await self.stream.aclose()
                return
            if self.ssl_context is not None:
                self.stream = trio.SSLStream(
                    self.stream, self.ssl_context, server_side=True, https_compatible=True
                )
        try:
            try:
                with trio.fail_after(self.config.ssl_handshake_timeout):
                    await self.stream.do_handshake()
            except (trio.BrokenResourceError, trio.TooSlowError):
                return  # Handshake failed
            alpn_protocol = self.stream.selected_alpn_protocol()
            socket = self.stream.transport_stream.socket
            ssl = True
        except AttributeError:  # Not SSL
            alpn_protocol = "http/1.1"
            socket = self.stream.socket
            ssl = False

        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
            server = parse_socket_addr(socket.family, socket.getsockname())
            if proxy_info is not None and proxy_info.command == COMMAND_PROXY:
                await self.config.log.info(
                    "PROXY protocol: trusted proxy %s forwarded client %s (server %s)",
                    client,
                    proxy_info.client,
                    proxy_info.server,
                )
                client, server = proxy_info.client, proxy_info.server

            async with TaskGroup() as task_group:
                self._task_group = task_group
                self.protocol = ProtocolWrapper(
                    self.app,
                    self.config,
                    self.context,
                    task_group,
                    ConnectionState(self.state),
                    ssl,
                    client,
                    server,
                    self.protocol_send,
                    alpn_protocol,
                )
                await self.protocol.initiate()
                await self.idle_task.restart(self._task_group, self._idle_timeout)
                await self._read_data()
        except OSError:
            pass
        finally:
            await self._close()

    async def protocol_send(self, event: Event) -> None:
        if isinstance(event, RawData):
            async with self.send_lock:
                try:
                    with trio.CancelScope() as cancel_scope:
                        cancel_scope.shield = True
                        await self.stream.send_all(event.data)
                except (trio.BrokenResourceError, trio.ClosedResourceError):
                    await self.protocol.handle(Closed())
        elif isinstance(event, Closed):
            await self._close()
            await self.protocol.handle(Closed())
        elif isinstance(event, Updated):
            if event.idle:
                await self.idle_task.restart(self._task_group, self._idle_timeout)
            else:
                await self.idle_task.stop()

    async def _read_proxy_protocol(self) -> ProxyProtocolInfo | None:
        socket = self.stream.socket
        client = parse_socket_addr(socket.family, socket.getpeername())
        if not self.config.is_proxy_protocol_allowed(client):
            await self.config.log.warning("PROXY protocol: rejected untrusted peer %s", client)
            return None

        try:
            with trio.fail_after(self.config.proxy_protocol_timeout or inf):
                fixed_header = await self._receive_exactly(FIXED_HEADER_LENGTH)
                total_length = preamble_length(fixed_header)
                if total_length > self.config.proxy_protocol_max_header_size:
                    raise ProxyProtocolError("PROXY protocol preamble is too large")
                rest = await self._receive_exactly(total_length - FIXED_HEADER_LENGTH)
            return parse_proxy_v2_preamble(fixed_header + rest)
        except (
            ProxyProtocolError,
            trio.BrokenResourceError,
            trio.ClosedResourceError,
            trio.TooSlowError,
        ) as error:
            await self.config.log.warning("PROXY protocol: rejected %s, %s", client, error)
            return None

    async def _receive_exactly(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = await self.stream.receive_some(length - len(data))
            if chunk == b"":
                raise ProxyProtocolError("Truncated PROXY protocol v2 preamble")
            data.extend(chunk)
        return bytes(data)

    async def _read_data(self) -> None:
        while True:
            try:
                with trio.fail_after(self.config.read_timeout or inf):
                    data = await self.stream.receive_some(MAX_RECV)
            except (
                trio.ClosedResourceError,
                trio.BrokenResourceError,
                trio.TooSlowError,
            ):
                break
            else:
                await self.protocol.handle(RawData(bytes(data)))
                if data == b"":
                    break
        await self.protocol.handle(Closed())

    async def _close(self) -> None:
        try:
            await self.stream.send_eof()
        except (
            trio.BrokenResourceError,
            AttributeError,
            trio.BusyResourceError,
            trio.ClosedResourceError,
        ):
            # They're already gone, nothing to do
            # Or it is a SSL stream
            pass
        await self.stream.aclose()

    async def _idle_timeout(self) -> None:
        with trio.move_on_after(self.config.keep_alive_timeout):
            await self.context.terminated.wait()

        with trio.CancelScope(shield=True):
            await self._initiate_server_close()

    async def _initiate_server_close(self) -> None:
        await self.protocol.handle(Closed())
        await self.stream.aclose()
