from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
HEADER_LENGTH = 16

COMMAND_LOCAL = 0x00
COMMAND_PROXY = 0x01

FAMILY_INET = 0x10
FAMILY_INET6 = 0x20

TRANSPORT_STREAM = 0x01

IPV4_ADDRESS_LENGTH = 12
IPV6_ADDRESS_LENGTH = 36


class ProxyProtocolError(Exception):
    """Raised when a PROXY protocol preamble is invalid or unsupported."""


@dataclass
class ProxyPreamble:
    command: str  # "proxy" or "local"
    client: tuple[str, int] | None  # None for the LOCAL command
    server: tuple[str, int] | None
    tlvs: list[tuple[int, bytes]] = field(default_factory=list)


class ProxyV2Parser:
    """An incremental parser for PROXY protocol version 2 preambles.

    Feed data as it arrives; once a full preamble has been consumed
    the parsed preamble and any leftover bytes (belonging to the
    wrapped protocol, e.g. TLS or HTTP) are returned. Raises
    ProxyProtocolError as soon as the preamble is known to be
    invalid, unsupported, or larger than max_size.
    """

    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self._buffer = bytearray()
        self._expected = HEADER_LENGTH

    @property
    def expected(self) -> int:
        """The total preamble size expected based on the data so far."""
        return self._expected

    @property
    def received(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> tuple[ProxyPreamble | None, bytes]:
        self._buffer.extend(data)
        if len(self._buffer) > self.max_size:
            raise ProxyProtocolError("PROXY protocol preamble exceeds the maximum size")

        prefix = bytes(self._buffer[:12])
        if prefix != SIGNATURE[: len(prefix)]:
            raise ProxyProtocolError("Invalid PROXY protocol signature")

        if len(self._buffer) >= 13:
            version = self._buffer[12] >> 4
            if version != 0x02:
                raise ProxyProtocolError(f"Unsupported PROXY protocol version {version:#x}")
            command = self._buffer[12] & 0x0F
            if command not in (COMMAND_LOCAL, COMMAND_PROXY):
                raise ProxyProtocolError(f"Unsupported PROXY protocol command {command:#x}")

        if len(self._buffer) >= 14:
            family = self._buffer[13] & 0xF0
            transport = self._buffer[13] & 0x0F
            if command == COMMAND_PROXY and (family, transport) not in {
                (FAMILY_INET, TRANSPORT_STREAM),
                (FAMILY_INET6, TRANSPORT_STREAM),
            }:
                raise ProxyProtocolError(
                    f"Unsupported PROXY protocol address family {family:#x} or "
                    f"transport {transport:#x}"
                )

        if len(self._buffer) < HEADER_LENGTH:
            return None, b""

        header = bytes(self._buffer[:HEADER_LENGTH])

        body_length = int.from_bytes(header[14:16], "big")
        total = HEADER_LENGTH + body_length
        if total > self.max_size:
            raise ProxyProtocolError("PROXY protocol preamble exceeds the maximum size")
        self._expected = total
        if len(self._buffer) < total:
            return None, b""

        body = bytes(self._buffer[HEADER_LENGTH:total])
        leftover = bytes(self._buffer[total:])
        self._buffer.clear()

        if command == COMMAND_LOCAL:
            # The address block must be ignored for LOCAL commands, the
            # real connection addresses continue to apply.
            return ProxyPreamble("local", None, None), leftover

        if family == FAMILY_INET:
            if body_length < IPV4_ADDRESS_LENGTH:
                raise ProxyProtocolError("Truncated PROXY protocol IPv4 address block")
            client = (
                str(ipaddress.IPv4Address(body[0:4])),
                int.from_bytes(body[8:10], "big"),
            )
            server = (
                str(ipaddress.IPv4Address(body[4:8])),
                int.from_bytes(body[10:12], "big"),
            )
            tlvs = _parse_tlvs(body[IPV4_ADDRESS_LENGTH:])
        else:
            if body_length < IPV6_ADDRESS_LENGTH:
                raise ProxyProtocolError("Truncated PROXY protocol IPv6 address block")
            client = (
                str(ipaddress.IPv6Address(body[0:16])),
                int.from_bytes(body[32:34], "big"),
            )
            server = (
                str(ipaddress.IPv6Address(body[16:32])),
                int.from_bytes(body[34:36], "big"),
            )
            tlvs = _parse_tlvs(body[IPV6_ADDRESS_LENGTH:])

        return ProxyPreamble("proxy", client, server, tlvs), leftover


def _parse_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    tlvs: list[tuple[int, bytes]] = []
    while data:
        if len(data) < 3:
            raise ProxyProtocolError("Truncated PROXY protocol TLV")
        type_ = data[0]
        length = int.from_bytes(data[1:3], "big")
        if len(data) < 3 + length:
            raise ProxyProtocolError("Truncated PROXY protocol TLV value")
        tlvs.append((type_, data[3 : 3 + length]))
        data = data[3 + length :]
    return tlvs


def peer_allowed(
    peer: tuple[str, int] | None,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if the peer's address is within an allowed network."""
    if peer is None:
        return False
    try:
        address = ipaddress.ip_address(peer[0])
    except ValueError:
        return False
    return any(address in network for network in networks)
