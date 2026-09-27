from __future__ import annotations

import ipaddress

import pytest

from hypercorn.config import Config
from hypercorn.proxy_protocol import (
    peer_allowed,
    ProxyProtocolError,
    ProxyV2Parser,
    SIGNATURE,
)


def _v4_preamble(
    src: bytes = b"\x7f\x00\x00\x01",
    dst: bytes = b"\x0a\x00\x00\x02",
    src_port: int = 12345,
    dst_port: int = 443,
    tlvs: bytes = b"",
) -> bytes:
    body = src + dst + src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big") + tlvs
    return SIGNATURE + b"\x21\x11" + len(body).to_bytes(2, "big") + body


def _v6_preamble() -> bytes:
    src = ipaddress.IPv6Address("2001:db8::1").packed
    dst = ipaddress.IPv6Address("2001:db8::2").packed
    body = src + dst + (4321).to_bytes(2, "big") + (8080).to_bytes(2, "big")
    return SIGNATURE + b"\x21\x21" + len(body).to_bytes(2, "big") + body


def test_parse_ipv4_preamble() -> None:
    parser = ProxyV2Parser(512)
    preamble, leftover = parser.feed(_v4_preamble())
    assert preamble is not None
    assert preamble.command == "proxy"
    assert preamble.client == ("127.0.0.1", 12345)
    assert preamble.server == ("10.0.0.2", 443)
    assert preamble.tlvs == []
    assert leftover == b""


def test_parse_ipv4_preamble_with_tlvs() -> None:
    tlvs = b"\x03\x00\x04\x01\x02\x03\x04" + b"\x20\x00\x02ab"
    parser = ProxyV2Parser(512)
    preamble, leftover = parser.feed(_v4_preamble(tlvs=tlvs))
    assert preamble is not None
    assert preamble.tlvs == [(0x03, b"\x01\x02\x03\x04"), (0x20, b"ab")]


def test_parse_ipv6_preamble() -> None:
    parser = ProxyV2Parser(512)
    preamble, leftover = parser.feed(_v6_preamble())
    assert preamble is not None
    assert preamble.client == ("2001:db8::1", 4321)
    assert preamble.server == ("2001:db8::2", 8080)
    assert leftover == b""


def test_parse_local_command_ignores_addresses() -> None:
    body = b"\x00" * 12
    data = SIGNATURE + b"\x20\x11" + len(body).to_bytes(2, "big") + body
    parser = ProxyV2Parser(512)
    preamble, leftover = parser.feed(data)
    assert preamble is not None
    assert preamble.command == "local"
    assert preamble.client is None
    assert preamble.server is None
    assert leftover == b""


def test_parse_incremental_feed() -> None:
    parser = ProxyV2Parser(512)
    preamble = None
    for byte in _v4_preamble():
        preamble, leftover = parser.feed(bytes([byte]))
    assert preamble is not None
    assert preamble.client == ("127.0.0.1", 12345)


def test_parse_returns_leftover_bytes() -> None:
    parser = ProxyV2Parser(512)
    preamble, leftover = parser.feed(_v4_preamble() + b"\x16\x03\x01TLS")
    assert preamble is not None
    assert leftover == b"\x16\x03\x01TLS"


def test_parse_expected_length() -> None:
    parser = ProxyV2Parser(512)
    assert parser.expected == 16
    preamble, _ = parser.feed(_v4_preamble()[:16])
    assert preamble is None
    assert parser.expected == 16 + 12
    assert parser.received == 16


def test_parse_invalid_signature() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError):
        parser.feed(b"GET / HTTP/1.1\r\n\r\n")


def test_parse_invalid_signature_incremental() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError):
        parser.feed(b"GET ")


def test_parse_unsupported_version() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError, match="version"):
        parser.feed(SIGNATURE + b"\x11\x11" + b"\x00\x0c" + b"\x00" * 12)


def test_parse_unsupported_command() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError, match="command"):
        parser.feed(SIGNATURE + b"\x25\x11" + b"\x00\x0c" + b"\x00" * 12)


@pytest.mark.parametrize("family", [b"\x12", b"\x31", b"\x32", b"\x00"])
def test_parse_unsupported_family_or_transport(family: bytes) -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError, match="family"):
        parser.feed(SIGNATURE + b"\x21" + family + b"\x00\x0c" + b"\x00" * 12)


def test_parse_unsupported_family_rejected_on_header() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError):
        parser.feed(SIGNATURE + b"\x21\x31")  # Only the header is required


def test_parse_truncated_address_block() -> None:
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError, match="Truncated"):
        parser.feed(SIGNATURE + b"\x21\x11" + b"\x00\x04" + b"\x00" * 4)


def test_parse_truncated_tlv() -> None:
    tlvs = b"\x03\x00\x04\x01"  # Declares 4 bytes, provides 1
    parser = ProxyV2Parser(512)
    with pytest.raises(ProxyProtocolError, match="TLV"):
        parser.feed(_v4_preamble(tlvs=tlvs))


def test_parse_exceeds_max_size_via_length() -> None:
    parser = ProxyV2Parser(20)
    with pytest.raises(ProxyProtocolError, match="maximum size"):
        parser.feed(_v4_preamble()[:16])


def test_parse_exceeds_max_size_via_data() -> None:
    parser = ProxyV2Parser(8)
    with pytest.raises(ProxyProtocolError, match="maximum size"):
        parser.feed(SIGNATURE + b"\x21")


def test_peer_allowed() -> None:
    networks = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("2001:db8::/32")]
    assert peer_allowed(("10.1.2.3", 80), networks)
    assert peer_allowed(("2001:db8::1", 80), networks)
    assert not peer_allowed(("192.168.0.1", 80), networks)
    assert not peer_allowed(None, networks)
    assert not peer_allowed(("not-an-ip", 80), networks)
    assert not peer_allowed(("10.1.2.3", 80), [])


def test_config_proxy_protocol_defaults() -> None:
    config = Config()
    assert config.proxy_protocol is False
    assert config.proxy_protocol_allowed_networks == []
    assert config.proxy_protocol_networks == []
    assert config.proxy_protocol_max_size > 0
    assert config.proxy_protocol_timeout > 0


def test_config_proxy_protocol_allowed_networks() -> None:
    config = Config()
    config.proxy_protocol_allowed_networks = "127.0.0.0/8"
    assert config.proxy_protocol_allowed_networks == ["127.0.0.0/8"]
    config.proxy_protocol_allowed_networks = ["10.0.0.0/8", "2001:db8::/32"]
    assert config.proxy_protocol_networks == [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("2001:db8::/32"),
    ]


def test_config_proxy_protocol_invalid_network() -> None:
    config = Config()
    config.proxy_protocol_allowed_networks = ["not-a-network"]
    with pytest.raises(ValueError):
        config.proxy_protocol_networks
