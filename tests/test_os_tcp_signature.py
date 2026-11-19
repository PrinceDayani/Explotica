"""Tests for the TCP/IP-stack OS signature classifier (pure)."""
from explotica.fingerprint.os_fingerprint import (
    classify_tcp_signature, guess_os_from_ttl,
)


def test_linux_ttl_window():
    r = classify_tcp_signature(ttl=64, window=29200)
    assert r["match"] == "ttl+window"
    assert "Linux" in r["os_label"]
    assert r["initial_ttl"] == 64


def test_windows_modern_ttl_window():
    r = classify_tcp_signature(ttl=128, window=65535)
    assert r["match"] == "ttl+window"
    assert "Windows" in r["os_label"]


def test_cisco_ttl_window():
    r = classify_tcp_signature(ttl=255, window=4128)
    assert "Cisco" in r["os_label"] or "network" in r["os_label"]


def test_ttl_hops_still_classifies():
    # TTL 58 = Linux 6 hops away; window unknown -> ttl-only family.
    r = classify_tcp_signature(ttl=58, window=None)
    assert r["match"] == "ttl-only"
    assert r["initial_ttl"] == 64
    assert "Linux" in r["os_label"]


def test_unknown_window_on_known_ttl_falls_back():
    r = classify_tcp_signature(ttl=128, window=12345)  # odd window
    assert r["match"] == "ttl-only"
    assert r["os_label"] == "Windows"


def test_zero_ttl_returns_none():
    assert classify_tcp_signature(ttl=0, window=5840) is None
    assert classify_tcp_signature(ttl=None, window=5840) is None


def test_ttl_guess_unchanged():
    # Ensure the existing TTL-only helper still works.
    g = guess_os_from_ttl(124)
    assert g["initial_ttl"] == 128
    assert g["hops_estimate"] == 4
