from __future__ import annotations

from abc import ABC
from dataclasses import dataclass


class Event(ABC):
    pass


@dataclass(frozen=True)
class RawData(Event):
    data: bytes
    address: tuple[str, int] | None = None


@dataclass(frozen=True)
class Closed(Event):
    pass


@dataclass(frozen=True)
class ReadClosed(Event):
    # The client has half-closed the connection (clean EOF), no more
    # data can be received but data can still be sent.
    pass


@dataclass(frozen=True)
class WriteClosed(Event):
    # Half-close the sending direction of the connection, whilst
    # continuing to read any incoming data.
    pass


@dataclass(frozen=True)
class Updated(Event):
    idle: bool
