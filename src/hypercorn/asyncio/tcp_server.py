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
from ..proxy_protocol import peer_allowed, ProxyPreamble, ProxyProtocolError, ProxyV2Parser
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
        self.state = state
        self.idle_task = AsyncioSingleTask()
        self.ssl_context = ssl_context

    def __await__(self) -> Generator[Any]:
        return self.run().__await__()

    async def run(self) -> None:
        socket = self.writer.get_extra_info("socket")
        try:
            client = parse_socket_addr(socket.family, socket.getpeername())
            server = parse_socket_addr(socket.family, socket.getsockname())

            if self.config.proxy_protocol:
                preamble = await self._read_proxy_preamble(client)
                if preamble is None:
                    return
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

            if self.ssl_context is not None:
                try:
                    await self._upgrade_to_tls()
                except (OSError, asyncio.TimeoutError):
                    return  # The TLS handshake failed

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
                    connection_state,
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

    async def _read_proxy_preamble(self, client: tuple[str, int] | None) -> ProxyPreamble | None:
        if not peer_allowed(client, self.config.proxy_protocol_networks):
            await self.config.log.warning(
                "PROXY protocol: rejecting connection from disallowed peer %s", client
            )
            return None
        parser = ProxyV2Parser(self.config.proxy_protocol_max_size)
        try:
            while True:
                data = await asyncio.wait_for(
                    self.reader.readexactly(parser.expected - parser.received),
                    self.config.proxy_protocol_timeout,
                )
                preamble, _ = parser.feed(data)
                if preamble is not None:
                    return preamble
        except (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            TimeoutError,
            ConnectionError,
            OSError,
            ProxyProtocolError,
        ) as error:
            await self.config.log.warning(
                "PROXY protocol: rejecting invalid preamble from %s: %s", client, error
            )
            return None

    async def _upgrade_to_tls(self) -> None:
        ssl_context = self.ssl_context
        assert ssl_context is not None
        if hasattr(self.writer, "start_tls"):  # Python >= 3.11
            await self.writer.start_tls(
                ssl_context,
                ssl_handshake_timeout=self.config.ssl_handshake_timeout,
            )
        else:  # Python 3.10
            transport = self.writer.transport
            protocol = transport.get_protocol()
            new_transport = await self.loop.start_tls(
                transport,
                protocol,
                ssl_context,
                server_side=True,
                ssl_handshake_timeout=self.config.ssl_handshake_timeout,
            )
            self.writer._transport = new_transport  # type: ignore[attr-defined]
            protocol._transport = new_transport  # type: ignore[attr-defined]

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
