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


# ── Phase 70: RTT estimator (RFC 6298) ────────────────────────────────────────
def test_hoststate_rtt_first_sample_seeds_estimator():
    hs = S.HostState("1.2.3.4", min_rto=0.25, max_rto=3.0, default_timeout=1.2)
    # Before any sample, timeout is the conservative default.
    assert hs.current_timeout() == 1.2
    hs.observe_rtt(0.10)
    assert hs.srtt == 0.10 and hs.rttvar == 0.05
    # RTO = srtt + 4*rttvar = 0.10 + 0.20 = 0.30, within clamp.
    assert abs(hs.rto - 0.30) < 1e-9
    assert hs.current_timeout() == hs.rto


def test_hoststate_rto_is_clamped():
    hs = S.HostState("1.2.3.4", min_rto=0.25, max_rto=3.0, default_timeout=1.2)
    hs.observe_rtt(0.001)             # tiny RTT → RTO would be < min, clamps up
    assert hs.rto == 0.25
    hs2 = S.HostState("1.2.3.4", min_rto=0.25, max_rto=3.0, default_timeout=1.2)
    hs2.observe_rtt(5.0)              # huge RTT → RTO clamps down to max
    assert hs2.rto == 3.0


def test_hoststate_rtt_converges_with_jitter():
    hs = S.HostState("1.2.3.4", min_rto=0.05, max_rto=3.0, default_timeout=1.2)
    for sample in [0.20, 0.21, 0.19, 0.20, 0.20]:
        hs.observe_rtt(sample)
    # SRTT should track ~0.20s; RTO comfortably above it.
    assert 0.15 < hs.srtt < 0.25
    assert hs.rto > hs.srtt


# ── Phase 70: token bucket pacing ─────────────────────────────────────────────
def test_token_bucket_unlimited_when_rate_zero():
    b = S._TokenBucket(0)
    assert all(b.try_acquire() for _ in range(1000))


def test_token_bucket_throttles():
    b = S._TokenBucket(2.0)           # 2 tokens/sec, starts with 2
    grants = sum(1 for _ in range(10) if b.try_acquire())
    # Should hand out roughly the initial burst (2), then refuse the rest.
    assert 1 <= grants <= 3


# ── Phase 70: multi-host scheduler API ────────────────────────────────────────
def test_scan_udp_multi_returns_dict_per_host():
    res = S.scan_udp_multi(["127.0.0.1", "127.0.0.2"], [40201, 40202],
                           timeout=0.6, retries=0, deep=False)
    assert set(res) == {"127.0.0.1", "127.0.0.2"}
    for plist in res.values():
        assert len(plist) == 2
        for p in plist:
            assert p.protocol == "udp"


def test_scan_udp_multi_dedupes_hosts():
    res = S.scan_udp_multi(["127.0.0.1", "127.0.0.1"], [40203],
                           timeout=0.5, retries=0, deep=False)
    assert list(res) == ["127.0.0.1"]


# ── Phase 73: IPv6 support ────────────────────────────────────────────────────
def test_connect_target_ipv4_is_plain_tuple():
    assert S._connect_target("192.0.2.1", 161) == ("192.0.2.1", 161)
    assert S._is_ipv6("192.0.2.1") is False


def test_connect_target_ipv6_detected():
    assert S._is_ipv6("2001:db8::1") is True
    # Non-scoped v6 also uses a plain (ip, port) tuple.
    assert S._connect_target("2001:db8::1", 53) == ("2001:db8::1", 53)


def test_scan_ipv6_loopback_closed():
    # ::1 closed UDP ports must classify like 127.0.0.1 — ICMPv6 surfaces the
    # same connected-socket error. Accept open|filtered on sandboxes that drop it.
    import socket as _sock
    if not _sock.has_ipv6:
        return
    try:
        res = S.scan_udp("::1", [40911, 40912], timeout=0.8, retries=0,
                         deep=False)
    except OSError:
        return                                # no IPv6 stack on this runner
    assert len(res) == 2
    for p in res:
        assert p.protocol == "udp"
        assert p.state in ("closed", "open|filtered")


def test_scan_udp_is_single_host_wrapper_over_core():
    # scan_udp must return the same Port list scan_udp_multi gives for that host.
    one = S.scan_udp("127.0.0.1", [40204, 40205], timeout=0.5, retries=0,
                     deep=False)
    many = S.scan_udp_multi(["127.0.0.1"], [40204, 40205], timeout=0.5,
                            retries=0, deep=False)["127.0.0.1"]
    assert [p.number for p in one] == [p.number for p in many]
    assert [p.state for p in one] == [p.state for p in many]
