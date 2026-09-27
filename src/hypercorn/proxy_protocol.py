from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
FIXED_HEADER_LENGTH = 16

VERSION = 0x2

COMMAND_LOCAL = 0x0
COMMAND_PROXY = 0x1

FAMILY_INET = 0x1
FAMILY_INET6 = 0x2

TRANSPORT_STREAM = 0x1

IPV4_ADDRESS_LENGTH = 12
IPV6_ADDRESS_LENGTH = 36


class ProxyProtocolError(Exception):
    pass


@dataclass
class ProxyTLV:
    type: int
    value: bytes


@dataclass
class ProxyProtocolInfo:
    command: int
    client: tuple[str, int] | None
    server: tuple[str, int] | None
    tlvs: list[ProxyTLV] = field(default_factory=list)


def preamble_length(fixed_header: bytes) -> int:
    """Return the total preamble length implied by the fixed header.

    This validates the parts of the preamble that are known before the
    variable length address block has been received, so that invalid
    preambles are rejected as early as possible.
    """
    if len(fixed_header) != FIXED_HEADER_LENGTH or not fixed_header.startswith(SIGNATURE):
        raise ProxyProtocolError("Invalid PROXY protocol v2 signature")
    if fixed_header[12] >> 4 != VERSION:
        raise ProxyProtocolError("Unsupported PROXY protocol version")
    return FIXED_HEADER_LENGTH + int.from_bytes(fixed_header[14:16], "big")


def parse_proxy_v2_preamble(preamble: bytes) -> ProxyProtocolInfo:
    length = preamble_length(preamble[:FIXED_HEADER_LENGTH])
    if len(preamble) != length:
        raise ProxyProtocolError("Truncated PROXY protocol v2 preamble")

    command = preamble[12] & 0x0F
    if command == COMMAND_LOCAL:
        return ProxyProtocolInfo(command, None, None)
    elif command != COMMAND_PROXY:
        raise ProxyProtocolError(f"Unsupported PROXY protocol command {command:#x}")

    family = preamble[13] >> 4
    transport = preamble[13] & 0x0F
    if transport != TRANSPORT_STREAM:
        raise ProxyProtocolError(f"Unsupported PROXY protocol transport {transport:#x}")

    payload = preamble[FIXED_HEADER_LENGTH:]
    if family == FAMILY_INET:
        if len(payload) < IPV4_ADDRESS_LENGTH:
            raise ProxyProtocolError("Truncated PROXY protocol IPv4 addresses")
        client = (str(ipaddress.IPv4Address(payload[0:4])), int.from_bytes(payload[8:10], "big"))
        server = (str(ipaddress.IPv4Address(payload[4:8])), int.from_bytes(payload[10:12], "big"))
        tlvs = _parse_tlvs(payload[IPV4_ADDRESS_LENGTH:])
    elif family == FAMILY_INET6:
        if len(payload) < IPV6_ADDRESS_LENGTH:
            raise ProxyProtocolError("Truncated PROXY protocol IPv6 addresses")
        client = (
            str(ipaddress.IPv6Address(payload[0:16])),
            int.from_bytes(payload[32:34], "big"),
        )
        server = (
            str(ipaddress.IPv6Address(payload[16:32])),
            int.from_bytes(payload[34:36], "big"),
        )
        tlvs = _parse_tlvs(payload[IPV6_ADDRESS_LENGTH:])
    else:
        raise ProxyProtocolError(f"Unsupported PROXY protocol address family {family:#x}")

    return ProxyProtocolInfo(command, client, server, tlvs)


def _parse_tlvs(data: bytes) -> list[ProxyTLV]:
    tlvs = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            raise ProxyProtocolError("Truncated PROXY protocol TLV")
        tlv_type = data[offset]
        tlv_length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        if len(data) - offset - 3 < tlv_length:
            raise ProxyProtocolError("Truncated PROXY protocol TLV value")
        tlvs.append(ProxyTLV(tlv_type, data[offset + 3 : offset + 3 + tlv_length]))
        offset += 3 + tlv_length
    return tlvs
