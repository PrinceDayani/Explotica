"""Tests for UDP scan evasion (Phase 75).

source_port + data_length work in the privilege-free connected-socket engine;
decoys + fragment require raw sockets and must fall back transparently when
those aren't available.
"""

from __future__ import annotations

from explotica.discovery import udp_scan as S
from explotica.discovery.udp_scan import Evasion


# ── Evasion config semantics ──────────────────────────────────────────────────
def test_pad_appends_random_bytes():
    e = Evasion(data_length=16)
    out = e.pad(b"abc")
    assert len(out) == 3 + 16
    assert out.startswith(b"abc")


def test_pad_noop_when_zero():
    assert Evasion().pad(b"xyz") == b"xyz"
    assert Evasion(data_length=0).pad(b"") == b""


def test_pad_randomness_differs():
    e = Evasion(data_length=32)
    # Two pads of the same payload should differ in the random tail.
    assert e.pad(b"q")[1:] != e.pad(b"q")[1:]


def test_needs_raw_only_for_decoys_or_fragment():
    assert Evasion().needs_raw is False
    assert Evasion(source_port=53).needs_raw is False
    assert Evasion(data_length=64).needs_raw is False
    assert Evasion(decoys=("10.0.0.1",)).needs_raw is True
    assert Evasion(fragment=True).needs_raw is True


# ── Connected-socket engine honours source_port + data_length ─────────────────
def test_scan_with_source_port_and_padding_still_classifies():
    ev = Evasion(source_port=53, data_length=24)
    res = S.scan_udp("127.0.0.1", [40811, 40812], timeout=0.8, retries=0,
                     deep=False, evasion=ev)
    assert len(res) == 2
    for p in res:
        # The probe must still reach the target and get a verdict — the bind +
        # padding are evasion dressing, not a functional change.
        assert p.state in ("closed", "open|filtered")


def test_probe_once_accepts_evasion_directly():
    ev = Evasion(source_port=0, data_length=8)   # src port 0 = ephemeral (no-op)
    # _probe_once returns the RAW outcome, not the classified Port state.
    outcome, _extra, _rtt = S._probe_once("127.0.0.1", 40813, b"x", 0.6,
                                          evasion=ev)
    assert outcome in ("data", "refused", "timeout", "error")


# ── Raw-only evasion falls back transparently when raw is unavailable ─────────
def test_decoy_fragment_falls_back_without_raw(monkeypatch):
    from explotica.discovery import udp_scan_raw as R
    monkeypatch.setattr(R, "raw_udp_available", lambda: False)
    ev = Evasion(decoys=("192.0.2.9",), fragment=True)
    # Must NOT crash and must NOT return empty-by-raw — connected engine answers.
    res = S.scan_udp("127.0.0.1", [40814], timeout=0.6, retries=0, deep=False,
                     evasion=ev)
    assert len(res) == 1
    assert res[0].state in ("closed", "open|filtered")


def test_maybe_raw_triggers_on_evasion_needs_raw(monkeypatch):
    # Even without prefer_raw, decoy/fragment evasion should attempt the raw
    # path (and here, with raw forced available + a stub scan, route to it).
    from explotica.discovery import udp_scan_raw as R
    monkeypatch.setattr(R, "raw_udp_available", lambda: True)
    monkeypatch.setattr(R, "raw_udp_scan",
                        lambda ips, ports, **k: {ips[0]: ["SENTINEL"]})
    out = S._maybe_raw(["10.0.0.1"], [161], prefer_raw=False, timeout=1.0,
                       retries=1, max_rate=0.0, progress=None,
                       evasion=Evasion(fragment=True))
    assert out == {"10.0.0.1": ["SENTINEL"]}


def test_maybe_raw_skips_when_no_raw_need_and_no_prefer():
    assert S._maybe_raw(["10.0.0.1"], [161], prefer_raw=False, timeout=1.0,
                        retries=1, max_rate=0.0, progress=None,
                        evasion=Evasion(source_port=53)) is None
