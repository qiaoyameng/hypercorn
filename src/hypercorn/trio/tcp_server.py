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
from ..proxy_protocol import peer_allowed, ProxyPreamble, ProxyProtocolError, ProxyV2Parser
from ..typing import AppWrapper, ConnectionState, LifespanState
from ..utils import parse_socket_addr

MAX_RECV = 2**16


class PrebufferedStream(trio.abc.HalfCloseableStream):
    """A stream wrapper that serves buffered (already read) data first.

    This allows the PROXY protocol preamble to be parsed without
    losing any bytes that belong to the wrapped protocol (e.g. TLS or
    HTTP).
    """

    def __init__(self, stream: trio.SocketStream) -> None:
        self._stream = stream
        self._buffer = bytearray()

    @property
    def socket(self) -> trio.socket.SocketType:
        return self._stream.socket

    def prepend(self, data: bytes) -> None:
        self._buffer[:0] = data

    async def receive_some(self, max_bytes: int | None = None) -> bytes:
        if self._buffer:
            if max_bytes is None:
                max_bytes = len(self._buffer)
            data = bytes(self._buffer[:max_bytes])
            del self._buffer[:max_bytes]
            return data
        return await self._stream.receive_some(max_bytes)

    async def send_all(self, data: bytes) -> None:
        await self._stream.send_all(data)

    async def wait_send_all_might_not_block(self) -> None:
        await self._stream.wait_send_all_might_not_block()

    async def send_eof(self) -> None:
        await self._stream.send_eof()

    async def aclose(self) -> None:
        await self._stream.aclose()


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
        self.stream: trio.SSLStream[Any] | trio.abc.HalfCloseableStream = stream
        self.state = state
        self.ssl_context = ssl_context

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        if self.config.proxy_protocol:
            preamble = await self._read_proxy_preamble()
            if preamble is None:
                await self._close()
                return
        else:
            preamble = None

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

            if preamble is not None:
                connection_state = ConnectionState(
                    {
                        **self.state,
                        "proxy_protocol": {
                            "version": 2,
                            "command": preamble.command,
                            "transport_client": client,
                            "transport_server": server,
                            "tlvs": preamble.tlvs,
                        },
                    }
                )
                if preamble.client is not None:
                    client, server = preamble.client, preamble.server
            else:
                connection_state = ConnectionState(self.state)

            async with TaskGroup() as task_group:
                self._task_group = task_group
                self.protocol = ProtocolWrapper(
                    self.app,
                    self.config,
                    self.context,
                    task_group,
                    connection_state,
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

    async def _read_proxy_preamble(self) -> ProxyPreamble | None:
        socket = self.stream.socket
        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
        except OSError:
            client = None
        if not peer_allowed(client, self.config.proxy_protocol_networks):
            await self.config.log.warning(
                "PROXY protocol: rejecting connection from disallowed peer %s", client
            )
            return None
        parser = ProxyV2Parser(self.config.proxy_protocol_max_size)
        buffered = PrebufferedStream(self.stream)  # type: ignore[arg-type]
        try:
            while True:
                with trio.fail_after(self.config.proxy_protocol_timeout or inf):
                    data = await buffered.receive_some(MAX_RECV)
                if data == b"":
                    raise ProxyProtocolError("Truncated PROXY protocol preamble")
                preamble, leftover = parser.feed(data)
                if preamble is not None:
                    buffered.prepend(leftover)
                    self.stream = buffered
                    return preamble
        except (
            trio.TooSlowError,
            trio.BrokenResourceError,
            trio.ClosedResourceError,
            ProxyProtocolError,
        ) as error:
            await self.config.log.warning(
                "PROXY protocol: rejecting invalid preamble from %s: %s", client, error
            )
            return None

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
