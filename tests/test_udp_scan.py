"""Tests for the adaptive UDP scan engine (Phase 69)."""

from __future__ import annotations

import struct

from explotica.discovery import udp_payloads as P
from explotica.discovery import udp_parsers as PR
from explotica.discovery import udp_scan as S
from explotica.core.models import Port


# ── Payload registry ──────────────────────────────────────────────────────────
def test_every_payload_is_bytes():
    for port, (proto, payload) in P.PAYLOADS.items():
        assert isinstance(port, int) and 1 <= port <= 65535
        assert isinstance(proto, str) and proto
        assert isinstance(payload, (bytes, bytearray))


def test_payload_for_known_and_unknown():
    proto, payload = P.payload_for(161)
    assert proto == "snmp" and payload
    proto, payload = P.payload_for(40000)
    assert proto == "unknown" and payload == b""


def test_high_value_ports_unique_and_sorted_set():
    assert len(P.HIGH_VALUE_UDP_PORTS) == len(set(P.HIGH_VALUE_UDP_PORTS))
    # All crafted-payload ports are included in the curated triage set.
    assert set(P.PAYLOADS).issubset(set(P.HIGH_VALUE_UDP_PORTS))


def test_dns_payload_is_chaos_txt_version_bind():
    _, payload = P.payload_for(53)
    assert b"\x07version\x04bind\x00" in payload
    # qtype TXT (16), qclass CHAOS (3) tail
    assert payload.endswith(struct.pack(">HH", 0x0010, 0x0003))


# ── Classifier contract (the honesty core) ────────────────────────────────────
def test_classify_outcomes():
    assert S.classify_outcome("data")[0] == "open"
    assert S.classify_outcome("refused")[0] == "closed"
    assert S.classify_outcome("error", errno=13)[0] == "filtered"
    # timeout: retry while not final, terminal open|filtered when final
    state, _, retry = S.classify_outcome("timeout", final=False)
    assert state == "open|filtered" and retry is True
    state, _, retry = S.classify_outcome("timeout", final=True)
    assert state == "open|filtered" and retry is False


# ── Parsers: never raise on garbage, dispatch correctly ───────────────────────
def test_parsers_tolerate_garbage():
    for proto in list(PR._DISPATCH) + ["unknown", "ntp-monlist"]:
        out = PR.parse_udp_response(proto, b"\x00" * 64)
        assert isinstance(out, dict)
        assert out.get("responded") is True


def test_empty_response_handled():
    assert PR.parse_udp_response("snmp", b"")["raw_bytes"] == 0


# ── DNS parser: regression for the version.bind false-positive ────────────────
def test_dns_no_false_leak_when_question_only_echoed():
    # A response that echoes the question (qd=1, an=0) must NOT report a leak.
    header = struct.pack(">HHHHHH", 0x1337, 0x8180, 1, 0, 0, 0)
    question = b"\x07version\x04bind\x00" + struct.pack(">HH", 0x10, 0x03)
    out = PR.parse_dns_version(header + question)
    assert out["responded"] is True
    assert "version_bind" not in out
    assert "finding" not in out


def test_dns_reports_real_txt_answer():
    header = struct.pack(">HHHHHH", 0x1337, 0x8180, 1, 1, 0, 0)
    question = b"\x07version\x04bind\x00" + struct.pack(">HH", 0x10, 0x03)
    # Answer: name pointer 0xC00C, TYPE TXT, CLASS CH, TTL, RDLEN, TXT rdata
    txt = b"9.11.3-RedHat"
    rdata = bytes([len(txt)]) + txt
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 0x10, 0x03, 0, len(rdata))
              + rdata)
    out = PR.parse_dns_version(header + question + answer)
    assert out["version_bind"] == "9.11.3-RedHat"
    assert "finding" in out


# ── Security-finding parsers ──────────────────────────────────────────────────
def test_ntp_monlist_flags_amplification():
    out = PR.parse_ntp_monlist(b"\x00" * 500)
    assert out["monlist_enabled"] is True
    assert out["severity"] == "high"
    assert "amplification" in out["finding"].lower()


def test_chargen_flags_finding():
    out = PR.parse_chargen(b"A" * 200)
    assert "finding" in out and out["severity"] == "medium"


# ── summarize_udp: legacy-key back-compat ─────────────────────────────────────
def test_summarize_maps_netbios_legacy_key():
    p = Port(number=137, protocol="udp", state="open",
             service="netbios-ns",
             service_intel={"netbios-ns": {"responded": True, "names": []}})
    summary = S.summarize_udp([p])
    assert "netbios" in summary           # legacy key the CLI/dashboard expect
    assert "netbios-ns" not in summary


def test_summarize_skips_closed_ports():
    closed = Port(number=53, protocol="udp", state="closed")
    assert S.summarize_udp([closed]) == {}


# ── End-to-end: closed-port detection on loopback (the no-admin ICMP trick) ───
def test_loopback_closed_ports_detected():
    # A high random UDP port on loopback is closed; the connected-socket trick
    # should surface it as 'closed' via ICMP port-unreachable — no admin needed.
    res = S.scan_udp("127.0.0.1", [40123, 40124], timeout=0.8, retries=0,
                     deep=False)
    states = {p.number: p.state for p in res}
    assert len(res) == 2
    # On platforms that deliver the ICMP we get 'closed'; some CI sandboxes
    # blackhole loopback ICMP → 'open|filtered'. Accept either, reject 'open'.
    for st in states.values():
        assert st in ("closed", "open|filtered")
