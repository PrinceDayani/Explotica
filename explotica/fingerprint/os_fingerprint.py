"""Passive OS fingerprinting from TTL values.

When you send a packet to a host, the host's initial TTL is set by its OS:
  - Linux / BSD: 64
  - Windows: 128
  - Cisco / network gear: 255
  - macOS modern: 64

The received TTL is initial − (router hops). So if you see TTL=58, the host
is probably Linux 6 hops away. If you see 124, probably Windows 4 hops away.

This isn't a perfect identification, but it's a cheap and useful hint
collected for free from any ICMP echo / ARP reply.
"""

from __future__ import annotations

from typing import Optional


def guess_os_from_ttl(ttl: int) -> Optional[dict]:
    """Return {os_family, hops_estimate, initial_ttl} based on observed TTL."""
    if ttl is None or ttl <= 0:
        return None
    # Common initial TTLs in descending order. Bound the hop count so a
    # mid-range TTL (e.g. 124) matches the nearest initial above it (128,
    # 4 hops) rather than the largest (255, 131 hops).
    candidates = [255, 128, 64, 32]
    for initial in candidates:
        if ttl <= initial and (initial - ttl) <= 40:
            hops = initial - ttl
            family = {
                255: "network device (Cisco/router/printer)",
                128: "Windows",
                64:  "Linux/BSD/macOS",
                32:  "older Windows/embedded",
            }.get(initial, "unknown")
            return {
                "os_family": family,
                "hops_estimate": hops,
                "initial_ttl": initial,
                "observed_ttl": ttl,
            }
    return None


# ── TCP/IP stack signature (initial-TTL + TCP window) ─────────────────────
# A p0f-style passive fingerprint: the pair of (initial TTL, advertised TCP
# window on the SYN-ACK) is characteristic of the OS/stack. Both values come
# for free from a single SYN-ACK; this classifier is pure (no raw sockets).
#
# Each entry: (initial_ttl, set_of_typical_windows, os_label, confidence).
_TCP_SIGNATURES = [
    (64, {5840, 5792, 29200, 28960, 14600}, "Linux (2.6–5.x)", 0.8),
    (64, {64240, 64240, 65535}, "Linux (recent) / *BSD / macOS", 0.6),
    (128, {8192, 8190}, "Windows (7/Server 2008)", 0.8),
    (128, {64240, 65535, 65520}, "Windows (10/11/Server 2016+)", 0.75),
    (255, {4128, 4096, 16384}, "Cisco IOS / network device", 0.7),
    (64, {16384}, "macOS / FreeBSD", 0.6),
]


def _initial_ttl(ttl: int) -> Optional[int]:
    for initial in (255, 128, 64, 32):
        if 0 < ttl <= initial and (initial - ttl) <= 40:
            return initial
    return None


def classify_tcp_signature(ttl: Optional[int],
                           window: Optional[int]) -> Optional[dict]:
    """Classify an OS from the (initial TTL, TCP window) pair on a SYN-ACK.

    Returns {os_label, confidence, initial_ttl, window, match} or None when
    there isn't enough signal. An exact window match on the right TTL gives a
    confident label; a TTL-only match falls back to the family with lower
    confidence (match="ttl-only").
    """
    if not ttl or ttl <= 0:
        return None
    initial = _initial_ttl(ttl)
    if initial is None:
        return None
    if window and window > 0:
        for sig_ttl, windows, label, conf in _TCP_SIGNATURES:
            if sig_ttl == initial and window in windows:
                return {
                    "os_label": label,
                    "confidence": conf,
                    "initial_ttl": initial,
                    "window": window,
                    "match": "ttl+window",
                }
    # Fall back to the TTL-only family (lower confidence).
    family = {255: "network device (Cisco/router/printer)",
              128: "Windows", 64: "Linux/BSD/macOS",
              32: "older Windows/embedded"}.get(initial, "unknown")
    return {
        "os_label": family,
        "confidence": 0.4,
        "initial_ttl": initial,
        "window": window,
        "match": "ttl-only",
    }
