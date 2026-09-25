from __future__ import annotations

import asyncio
import shutil
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from hypercorn.app_wrappers import ASGIWrapper
from hypercorn.asyncio.run import worker_serve
from hypercorn.config import Config
from ..tls_helpers import (
    CERT_A_PATH,
    CERT_B_PATH,
    CA_PATH,
    KEY_A_PATH,
    KEY_B_PATH,
    RESPONSE_BODY,
    connect,
    fingerprint,
    http1_get,
    tls_app,
)


@asynccontextmanager
async def serve(config: Config) -> AsyncIterator[int]:
    sockets = config.create_sockets()
    port = sockets.secure_sockets[0].getsockname()[1]
    shutdown = asyncio.Event()
    task = asyncio.ensure_future(
        worker_serve(
            ASGIWrapper(tls_app), config, sockets=sockets, shutdown_trigger=shutdown.wait
        )
    )
    try:
        yield port
    finally:
        shutdown.set()
        await asyncio.wait_for(task, 10)


def _tls_config(tmp_path: Path) -> Config:
    # Copy the first certificate into place, a certificate update is
    # then a replacement of these files (as with real rotation)
    shutil.copy(CERT_A_PATH, tmp_path / "cert.pem")
    shutil.copy(KEY_A_PATH, tmp_path / "key.pem")
    config = Config()
    config.bind = ["127.0.0.1:0"]
    config.certfile = str(tmp_path / "cert.pem")
    config.keyfile = str(tmp_path / "key.pem")
    config.errorlog = None
    return config


def _update_certificate(config: Config, tmp_path: Path) -> None:
    shutil.copy(CERT_B_PATH, tmp_path / "cert.pem")
    shutil.copy(KEY_B_PATH, tmp_path / "key.pem")


@pytest.mark.asyncio
async def test_reload_tls_changes_certificate(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    async with serve(config) as port:
        before = await asyncio.to_thread(lambda: fingerprint(connect(port)))
        _update_certificate(config, tmp_path)
        result = config.reload_tls()
        assert result.success
        assert result.error is None
        assert result.reloaded_at is not None
        after = await asyncio.to_thread(lambda: fingerprint(connect(port)))
        assert before != after
        assert after == await asyncio.to_thread(
            lambda: fingerprint(connect(port, server_hostname=None))
        )


@pytest.mark.asyncio
async def test_reload_tls_missing_files_keeps_previous_certificate(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    async with serve(config) as port:
        before = await asyncio.to_thread(lambda: fingerprint(connect(port)))
        (tmp_path / "cert.pem").unlink()
        result = config.reload_tls()
        assert not result.success
        assert result.error is not None
        assert config.tls_reloader.last_result is result
        assert before == await asyncio.to_thread(lambda: fingerprint(connect(port)))


@pytest.mark.asyncio
async def test_reload_tls_mismatched_key_keeps_previous_certificate(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    async with serve(config) as port:
        before = await asyncio.to_thread(lambda: fingerprint(connect(port)))
        shutil.copy(KEY_B_PATH, tmp_path / "key.pem")  # Does not match cert A
        result = config.reload_tls()
        assert not result.success
        assert result.error is not None
        assert before == await asyncio.to_thread(lambda: fingerprint(connect(port)))
        # Restoring a matching pair allows a reload to succeed
        _update_certificate(config, tmp_path)
        assert config.reload_tls().success
        assert before != await asyncio.to_thread(lambda: fingerprint(connect(port)))


@pytest.mark.asyncio
async def test_reload_tls_preserves_alpn(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    async with serve(config) as port:
        sock = await asyncio.to_thread(lambda: connect(port, alpn=["h2"]))
        assert sock.selected_alpn_protocol() == "h2"
        sock.close()
        _update_certificate(config, tmp_path)
        assert config.reload_tls().success
        sock = await asyncio.to_thread(lambda: connect(port, alpn=["h2"]))
        assert sock.selected_alpn_protocol() == "h2"
        sock.close()
        sock = await asyncio.to_thread(lambda: connect(port, alpn=["http/1.1"]))
        assert sock.selected_alpn_protocol() == "http/1.1"
        sock.close()


@pytest.mark.asyncio
async def test_reload_tls_preserves_client_cert_verification(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    config.ca_certs = str(CA_PATH)
    config.verify_mode = ssl.CERT_REQUIRED
    async with serve(config) as port:
        sock = await asyncio.to_thread(lambda: connect(port, with_client_cert=True))
        sock.close()
        _update_certificate(config, tmp_path)
        assert config.reload_tls().success
        sock = await asyncio.to_thread(lambda: connect(port, with_client_cert=True))
        assert fingerprint(sock) == await asyncio.to_thread(
            lambda: fingerprint(connect(port, with_client_cert=True))
        )
        sock.close()
        with pytest.raises((ssl.SSLError, OSError)):
            sock = await asyncio.to_thread(lambda: connect(port))
            await asyncio.to_thread(lambda: http1_get(sock))


@pytest.mark.asyncio
async def test_reload_tls_keeps_established_connections(tmp_path: Path) -> None:
    config = _tls_config(tmp_path)
    async with serve(config) as port:
        sock = await asyncio.to_thread(lambda: connect(port))
        before = fingerprint(sock)
        assert await asyncio.to_thread(lambda: http1_get(sock)) == RESPONSE_BODY
        _update_certificate(config, tmp_path)
        assert config.reload_tls().success
        # The established connection continues to work ...
        assert await asyncio.to_thread(lambda: http1_get(sock)) == RESPONSE_BODY
        # ... whilst new connections complete a full handshake with
        # the new certificate
        after = await asyncio.to_thread(lambda: fingerprint(connect(port)))
        assert before != after
        sock.close()
