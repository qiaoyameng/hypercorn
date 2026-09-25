from __future__ import annotations

import shutil
from pathlib import Path

from hypercorn.config import Config
from .tls_helpers import CERT_A_PATH, CERT_B_PATH, KEY_A_PATH, KEY_B_PATH


def _config(tmp_path: Path) -> Config:
    shutil.copy(CERT_A_PATH, tmp_path / "cert.pem")
    shutil.copy(KEY_A_PATH, tmp_path / "key.pem")
    config = Config()
    config.certfile = str(tmp_path / "cert.pem")
    config.keyfile = str(tmp_path / "key.pem")
    config.errorlog = None
    return config


def test_reload_tls_disabled() -> None:
    config = Config()
    result = config.reload_tls()
    assert not result
    assert result.error is not None
    assert config.tls_reloader.last_result is result


def test_reload_tls_success(tmp_path: Path) -> None:
    config = _config(tmp_path)
    context = config.tls_reloader.context
    result = config.reload_tls()
    assert result.success
    assert result.error is None
    assert result.reloaded_at is not None
    assert config.tls_reloader.context is not context
    assert config.tls_reloader.last_result is result


def test_reload_tls_missing_files(tmp_path: Path) -> None:
    config = _config(tmp_path)
    context = config.tls_reloader.context
    (tmp_path / "cert.pem").unlink()
    result = config.reload_tls()
    assert not result.success
    assert result.error is not None
    assert config.tls_reloader.context is context


def test_reload_tls_mismatched_key(tmp_path: Path) -> None:
    config = _config(tmp_path)
    context = config.tls_reloader.context
    shutil.copy(KEY_B_PATH, tmp_path / "key.pem")  # Does not match cert A
    result = config.reload_tls()
    assert not result.success
    assert result.error is not None
    assert config.tls_reloader.context is context
    # A matching pair reloads successfully
    shutil.copy(CERT_B_PATH, tmp_path / "cert.pem")
    assert config.reload_tls().success
    assert config.tls_reloader.context is not context
