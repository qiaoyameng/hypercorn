from __future__ import annotations

import asyncio

from ..helpers import MockSocket


class MockSSLObject:
    def selected_alpn_protocol(self) -> str:
        return "h2"


class MemoryReader:
    def __init__(self) -> None:
        self.data: asyncio.Queue = asyncio.Queue()
        self.eof = False
        self.buffer = bytearray()

    async def send(self, data: bytes) -> None:
        if data != b"":
            await self.data.put(data)

    async def read(self, length: int) -> bytes:
        if len(self.buffer) > 0:
            data = bytes(self.buffer[:length])
            del self.buffer[:length]
            return data
        return await self.data.get()

    async def readexactly(self, length: int) -> bytes:
        while len(self.buffer) < length:
            chunk = await self.data.get()
            if chunk == b"":
                raise asyncio.IncompleteReadError(bytes(self.buffer), length)
            self.buffer.extend(chunk)
        data = bytes(self.buffer[:length])
        del self.buffer[:length]
        return data

    def close(self) -> None:
        self.data.put_nowait(b"")
        self.eof = True

    def at_eof(self) -> bool:
        return self.eof and self.data.empty()


class MemoryWriter:
    def __init__(self, http2: bool = False) -> None:
        self.is_closed = False
        self.data: asyncio.Queue = asyncio.Queue()
        self.http2 = http2

    def get_extra_info(self, name: str) -> MockSocket | MockSSLObject | None:
        if name == "socket":
            return MockSocket()
        elif self.http2 and name == "ssl_object":
            return MockSSLObject()
        else:
            return None

    def write_eof(self) -> None:
        self.data.put_nowait(b"")

    def write(self, data: bytes) -> None:
        if self.is_closed:
            raise ConnectionError()
        self.data.put_nowait(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.is_closed = True
        self.data.put_nowait(b"")

    async def wait_closed(self) -> None:
        pass

    async def receive(self) -> bytes:
        return await self.data.get()
