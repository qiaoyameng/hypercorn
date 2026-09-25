from __future__ import annotations

import hashlib
import os
import ssl

import pytest

from hypercorn.config import Config, ReloadableSSLContext

ASSETS = os.path.join(os.path.dirname(__file__), "assets")
CERT1 = os.path.join(ASSETS, "cert1.pem")
KEY1 = os.path.join(ASSETS, "key1.pem")
CERT2 = os.path.join(ASSETS, "cert2.pem")
KEY2 = os.path.join(ASSETS, "key2.pem")
CA = os.path.join(ASSETS, "ca.pem")
CLIENT_CERT = os.path.join(ASSETS, "client.pem")
CLIENT_KEY = os.path.join(ASSETS, "client_key.pem")


def _config() -> Config:
    config = Config()
    config.certfile = CERT1
    config.keyfile = KEY1
    return config


def _client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    return context


def _handshake(
    server_context: ssl.SSLContext,
    client_context: ssl.SSLContext,
    server_hostname: str | None = "localhost",
) -> tuple[ssl.SSLObject, ssl.SSLObject]:
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname=server_hostname
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(100):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        data = client_out.read()
        if data:
            server_in.write(data)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        data = server_out.read()
        if data:
            client_in.write(data)
        if client_done and server_done:
            return client, server
    raise AssertionError("Handshake did not complete")


def _fingerprint(ssl_object: ssl.SSLObject) -> str:
    der = ssl_object.getpeercert(binary_form=True)
    assert isinstance(der, bytes)
    return hashlib.sha256(der).hexdigest()


def test_ssl_context_control_entry() -> None:
    config = _config()
    assert isinstance(config.ssl_context, ReloadableSSLContext)
    assert config.ssl_context is config.ssl_context  # Cached, shared with the workers
    assert Config().ssl_context is None  # SSL is not enabled


def test_reload_swaps_served_certificate() -> None:
    config = _config()
    context = config.ssl_context
    assert context is not None
    client, _ = _handshake(context, _client_context())
    fingerprint1 = _fingerprint(client)

    config.certfile = CERT2
    config.keyfile = KEY2
    assert context.reload() is True

    client, server = _handshake(context, _client_context())
    assert _fingerprint(client) != fingerprint1
    # The ALPN configuration is not lost on reload
    assert server.selected_alpn_protocol() == "http/1.1"


def test_reload_missing_files_keeps_previous_context() -> None:
    config = _config()
    context = config.ssl_context
    assert context is not None
    client, _ = _handshake(context, _client_context())
    fingerprint1 = _fingerprint(client)

    config.certfile = os.path.join(ASSETS, "missing.pem")
    assert context.reload() is False

    client, _ = _handshake(context, _client_context())
    assert _fingerprint(client) == fingerprint1


def test_reload_mismatched_cert_key_keeps_previous_context() -> None:
    config = _config()
    context = config.ssl_context
    assert context is not None
    client, _ = _handshake(context, _client_context())
    fingerprint1 = _fingerprint(client)

    config.certfile = CERT2
    config.keyfile = KEY1  # Does not match cert2.pem
    assert context.reload() is False

    client, _ = _handshake(context, _client_context())
    assert _fingerprint(client) == fingerprint1


def test_reload_ssl_disabled_returns_false() -> None:
    config = _config()
    context = config.ssl_context
    assert context is not None
    config.certfile = None
    assert context.reload() is False


def test_reload_preserves_servername_callback() -> None:
    config = _config()
    context = config.ssl_context
    assert context is not None
    names: list[str | None] = []
    context.set_servername_callback(lambda sslobj, name, ctx: names.append(name))

    _handshake(context, _client_context())
    config.certfile = CERT2
    config.keyfile = KEY2
    assert context.reload() is True
    _handshake(context, _client_context())

    assert names == ["localhost", "localhost"]


def test_reload_preserves_client_cert_verification() -> None:
    config = _config()
    config.ca_certs = CA
    config.verify_mode = ssl.CERT_REQUIRED
    context = config.ssl_context
    assert context is not None

    client_context = _client_context()
    client_context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    _handshake(context, client_context)

    config.certfile = CERT2
    config.keyfile = KEY2
    assert context.reload() is True

    # Clients with a valid certificate are still verified after the reload
    client_context = _client_context()
    client_context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    _handshake(context, client_context)
    # Clients without a certificate are still rejected after the reload
    with pytest.raises(ssl.SSLError):
        _handshake(context, _client_context())
