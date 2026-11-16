"""Tests for AF-10: bind to 127.0.0.1 by default; NETPI_HOST opts in to LAN access."""
import app


def test_default_is_localhost(monkeypatch):
    monkeypatch.delenv("NETPI_HOST", raising=False)
    assert app._resolve_bind_host() == "127.0.0.1"


def test_env_override(monkeypatch):
    monkeypatch.setenv("NETPI_HOST", " 0.0.0.0 ")
    assert app._resolve_bind_host() == "0.0.0.0"


def test_blank_env_falls_back(monkeypatch):
    monkeypatch.setenv("NETPI_HOST", "")
    assert app._resolve_bind_host() == "127.0.0.1"
