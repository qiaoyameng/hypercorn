from __future__ import annotations

import pytest

from hypercorn.config import Config
from hypercorn.proxy_protocol import (
    COMMAND_LOCAL,
    COMMAND_PROXY,
    FIXED_HEADER_LENGTH,
    parse_proxy_v2_preamble,
    preamble_length,
    ProxyProtocolError,
    ProxyTLV,
    SIGNATURE,
)

IPV4_ADDRESSES = (
    bytes([203, 0, 113, 7])
    + bytes([192, 0, 2, 1])
    + (45678).to_bytes(2, "big")
    + (443).to_bytes(2, "big")
)
IPV6_ADDRESSES = (
    bytes.fromhex("20010db8000000000000000000000007")
    + bytes.fromhex("20010db8000000000000000000000001")
    + (45678).to_bytes(2, "big")
    + (443).to_bytes(2, "big")
)


def build_preamble(
    family_protocol: int, payload: bytes, command: int = COMMAND_PROXY
) -> bytes:
    return (
        SIGNATURE
        + bytes([0x20 | command, family_protocol])
        + len(payload).to_bytes(2, "big")
        + payload
    )


def test_parse_ipv4() -> None:
    info = parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES))
    assert info.command == COMMAND_PROXY
    assert info.client == ("203.0.113.7", 45678)
    assert info.server == ("192.0.2.1", 443)
    assert info.tlvs == []


def test_parse_ipv6() -> None:
    info = parse_proxy_v2_preamble(build_preamble(0x21, IPV6_ADDRESSES))
    assert info.client == ("2001:db8::7", 45678)
    assert info.server == ("2001:db8::1", 443)


def test_parse_tlvs_preserved() -> None:
    tlvs = b"\x02\x00\x05hello" + b"\x20\x00\x04\x00\x00\x00\x2a"
    info = parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES + tlvs))
    assert info.client == ("203.0.113.7", 45678)
    assert info.tlvs == [
        ProxyTLV(type=0x02, value=b"hello"),
        ProxyTLV(type=0x20, value=b"\x00\x00\x00\x2a"),
    ]


def test_local_command_ignores_addresses() -> None:
    info = parse_proxy_v2_preamble(
        build_preamble(0x00, b"\x00" * 12, command=COMMAND_LOCAL)
    )
    assert info.command == COMMAND_LOCAL
    assert info.client is None
    assert info.server is None


def test_preamble_length() -> None:
    preamble = build_preamble(0x11, IPV4_ADDRESSES)
    assert preamble_length(preamble[:FIXED_HEADER_LENGTH]) == len(preamble)


def test_preamble_length_invalid_signature() -> None:
    preamble = build_preamble(0x11, IPV4_ADDRESSES)
    with pytest.raises(ProxyProtocolError):
        preamble_length(b"GET / HTTP/1.1\r" + preamble[15:16])


def test_invalid_signature() -> None:
    preamble = b"\r\n\r\n\x00\r\nQUIT\x00" + build_preamble(0x11, IPV4_ADDRESSES)[12:]
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(preamble)


def test_invalid_version() -> None:
    preamble = build_preamble(0x11, IPV4_ADDRESSES)
    preamble = preamble[:12] + bytes([0x11]) + preamble[13:]
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(preamble)


def test_unsupported_command() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES, command=0x5))


def test_unsupported_family() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x31, b"\x00" * 20))


def test_unsupported_transport() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x12, IPV4_ADDRESSES))


def test_truncated_preamble() -> None:
    preamble = build_preamble(0x11, IPV4_ADDRESSES)
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(preamble[:-2])


def test_truncated_addresses() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES[:8]))


def test_truncated_tlv() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES + b"\x02\x00"))


def test_truncated_tlv_value() -> None:
    with pytest.raises(ProxyProtocolError):
        parse_proxy_v2_preamble(build_preamble(0x11, IPV4_ADDRESSES + b"\x02\x00\x05he"))


def test_is_proxy_protocol_allowed() -> None:
    config = Config()
    config.proxy_protocol_allowed_networks = ["10.0.0.0/8", "2001:db8::/32"]
    assert config.is_proxy_protocol_allowed(("10.1.2.3", 5000))
    assert config.is_proxy_protocol_allowed(("2001:db8::1", 5000))
    assert not config.is_proxy_protocol_allowed(("192.168.1.1", 5000))
    assert not config.is_proxy_protocol_allowed(("2001:db9::1", 5000))
    assert not config.is_proxy_protocol_allowed(None)


def test_is_proxy_protocol_allowed_defaults_closed() -> None:
    config = Config()
    assert not config.is_proxy_protocol_allowed(("127.0.0.1", 5000))
