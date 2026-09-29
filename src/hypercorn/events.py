from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import BinaryIO


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
class Updated(Event):
    idle: bool


@dataclass(frozen=True)
class SendFile(Event):
    file: BinaryIO
