"""Tests for env:/file: secret resolution used by credential flags."""
import pytest

from explotica.core.secret_input import resolve_secret, SecretResolutionError
from explotica import cli


def test_literal_passthrough():
    assert resolve_secret("root:hunter2") == "root:hunter2"


def test_none_passthrough():
    assert resolve_secret(None) is None


def test_env_reference(monkeypatch):
    monkeypatch.setenv("EXPLOTICA_TEST_SECRET", "admin:s3cret")
    assert resolve_secret("env:EXPLOTICA_TEST_SECRET") == "admin:s3cret"


def test_env_missing_raises(monkeypatch):
    monkeypatch.delenv("EXPLOTICA_TEST_MISSING", raising=False)
    with pytest.raises(SecretResolutionError):
        resolve_secret("env:EXPLOTICA_TEST_MISSING")


def test_file_reference(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_text("svc:p@ss\n", encoding="utf-8")
    assert resolve_secret(f"file:{p}") == "svc:p@ss"


def test_file_missing_raises(tmp_path):
    with pytest.raises(SecretResolutionError):
        resolve_secret(f"file:{tmp_path / 'nope.txt'}")


def test_ssh_parser_resolves_env(monkeypatch):
    monkeypatch.setenv("EXPLOTICA_SSH", "root:toor")
    creds = cli._parse_ssh_creds("env:EXPLOTICA_SSH")
    assert creds["username"] == "root"
    assert creds["password"] == "toor"


def test_winrm_parser_resolves_file(tmp_path):
    p = tmp_path / "w.txt"
    p.write_text("admin:Passw0rd", encoding="utf-8")
    creds = cli._parse_winrm_creds(f"file:{p}")
    assert creds["username"] == "admin"
    assert creds["password"] == "Passw0rd"
