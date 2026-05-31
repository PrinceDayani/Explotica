"""Tests for the raw-ICMP UDP turbo tier (Phase 71).

scapy/Npcap aren't required to run these: the ICMP classifier is pure logic, and
the availability gate + transparent fallback are exercised without raw sockets.
"""

from __future__ import annotations

from explotica.discovery import udp_scan_raw as R
from explotica.discovery import udp_scan as S


# ── ICMP (type, code) → state classifier (the accuracy core) ──────────────────
def test_port_unreachable_is_closed():
    state, reason = R.icmp_unreachable_state(3, 3)
    assert state == "closed"
    assert "3/3" in reason


def test_admin_prohibited_is_filtered_not_closed():
    # This is the exact case Windows' WSAECONNRESET collapse gets WRONG.
    for code in (1, 2, 9, 10, 13):
        state, reason = R.icmp_unreachable_state(3, code)
        assert state == "filtered", f"code {code} should be filtered"
        assert f"3/{code}" in reason


def test_non_type3_icmp_is_filtered():
    state, _ = R.icmp_unreachable_state(11, 0)   # time-exceeded
    assert state == "filtered"


def test_unknown_code_defaults_filtered():
    state, _ = R.icmp_unreachable_state(3, 7)
    assert state == "filtered"


# ── Availability gate + fallback ──────────────────────────────────────────────
def test_raw_available_returns_bool():
    assert isinstance(R.raw_udp_available(), bool)


def test_raw_scan_returns_empty_when_unavailable(monkeypatch):
    monkeypatch.setattr(R, "raw_udp_available", lambda: False)
    assert R.raw_udp_scan(["10.0.0.1"], [161]) == {}


def test_prefer_raw_falls_back_transparently(monkeypatch):
    # With raw forced unavailable, scan_udp(prefer_raw=True) must still return
    # results via the connected-socket engine — never crash, never empty-by-raw.
    monkeypatch.setattr(R, "raw_udp_available", lambda: False)
    res = S.scan_udp("127.0.0.1", [40301, 40302], prefer_raw=True,
                     timeout=0.5, retries=0, deep=False)
    assert len(res) == 2
    for p in res:
        assert p.protocol == "udp"
        assert p.state in ("closed", "open|filtered", "filtered")


def test_maybe_raw_returns_none_when_not_preferred():
    # prefer_raw=False must never touch the raw path.
    assert S._maybe_raw(["10.0.0.1"], [161], prefer_raw=False, timeout=1.0,
                        retries=1, max_rate=0.0, progress=None) is None
