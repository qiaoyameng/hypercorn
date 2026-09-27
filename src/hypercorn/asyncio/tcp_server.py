from __future__ import annotations

import asyncio
from collections.abc import Generator
from ssl import SSLContext, SSLError
from typing import Any

from .task_group import TaskGroup
from .worker_context import AsyncioSingleTask, WorkerContext
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
        loop: asyncio.AbstractEventLoop,
        config: Config,
        context: WorkerContext,
        state: LifespanState,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ssl_context: SSLContext | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.context = context
        self.loop = loop
        self.protocol: ProtocolWrapper
        self.reader = reader
        self.writer = writer
        self.send_lock = asyncio.Lock()
        self.ssl_context = ssl_context
        self.state = state
        self.idle_task = AsyncioSingleTask()

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        socket = self.writer.get_extra_info("socket")
        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
            server = parse_socket_addr(socket.family, socket.getsockname())
            if self.config.proxy_protocol:
                info = await self._read_proxy_protocol(client)
                if info is None:
                    return
                if info.command == COMMAND_PROXY:
                    await self.config.log.info(
                        "PROXY protocol: trusted proxy %s forwarded client %s (server %s)",
                        client,
                        info.client,
                        info.server,
                    )
                    client, server = info.client, info.server
                if self.ssl_context is not None:
                    try:
                        await self.writer.start_tls(
                            self.ssl_context,
                            ssl_handshake_timeout=self.config.ssl_handshake_timeout,
                        )
                    except (OSError, asyncio.TimeoutError, TimeoutError):
                        return  # Handshake failed
            ssl_object = self.writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                ssl = True
                alpn_protocol = ssl_object.selected_alpn_protocol()
            else:
                ssl = False
                alpn_protocol = "http/1.1"

            async with TaskGroup(self.loop) as task_group:
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
                await self.idle_task.restart(task_group, self._idle_timeout)
                await self._read_data()
        except OSError:
            pass
        finally:
            await self._close()

    async def _read_proxy_protocol(
        self, client: tuple[str, int] | None
    ) -> ProxyProtocolInfo | None:
        if not self.config.is_proxy_protocol_allowed(client):
            await self.config.log.warning("PROXY protocol: rejected untrusted peer %s", client)
            return None

        async def read_preamble() -> bytes:
            fixed_header = await self.reader.readexactly(FIXED_HEADER_LENGTH)
            total_length = preamble_length(fixed_header)
            if total_length > self.config.proxy_protocol_max_header_size:
                raise ProxyProtocolError("PROXY protocol preamble is too large")
            return fixed_header + await self.reader.readexactly(total_length - FIXED_HEADER_LENGTH)

        try:
            preamble = await asyncio.wait_for(read_preamble(), self.config.proxy_protocol_timeout)
            return parse_proxy_v2_preamble(preamble)
        except (
            ProxyProtocolError,
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            TimeoutError,
            ConnectionError,
            OSError,
        ) as error:
            await self.config.log.warning("PROXY protocol: rejected %s, %s", client, error)
            return None

    async def protocol_send(self, event: Event) -> None:
        if isinstance(event, RawData):
            async with self.send_lock:
                try:
                    self.writer.write(event.data)
                    await self.writer.drain()
                except (ConnectionError, RuntimeError):
                    await self.protocol.handle(Closed())
        elif isinstance(event, Closed):
            await self._close()
        elif isinstance(event, Updated):
            if event.idle:
                await self.idle_task.restart(self._task_group, self._idle_timeout)
            else:
                await self.idle_task.stop()

    async def _read_data(self) -> None:
        while not self.reader.at_eof():
            try:
                data = await asyncio.wait_for(self.reader.read(MAX_RECV), self.config.read_timeout)
            except (
                ConnectionError,
                OSError,
                asyncio.TimeoutError,
                TimeoutError,
                SSLError,
            ):
                break
            else:
                await self.protocol.handle(RawData(data))

        await self.protocol.handle(Closed())

    async def _close(self) -> None:
        try:
            self.writer.write_eof()
        except (NotImplementedError, OSError, RuntimeError):
            pass  # Likely SSL connection

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            RuntimeError,
            asyncio.CancelledError,
        ):
            pass  # Already closed
        finally:
            await self.idle_task.stop()

    async def _initiate_server_close(self) -> None:
        await self.protocol.handle(Closed())
        self.writer.close()

    async def _idle_timeout(self) -> None:
        try:
            await asyncio.wait_for(self.context.terminated.wait(), self.config.keep_alive_timeout)
        except asyncio.TimeoutError:
            pass
        await asyncio.shield(self._initiate_server_close())
