"""Multi-signal OS fingerprint database — beyond TTL.

Combines five signals into an OS guess:
  1. TTL (initial = 64/128/255 → Linux/Windows/network gear)
  2. MAC OUI vendor (already collected)
  3. Open port profile (specific OS = specific service mix)
  4. Banner-derived OS strings (SSH/HTTP/SMB headers leak OS)
  5. TCP window size / MSS (advanced, optional via scapy)

Output: best-guess (os_family, os_version, confidence_0_to_1, reasons).
"""

from __future__ import annotations

import re
from typing import Optional


# ── Port-profile fingerprints ─────────────────────────────────────────────
# Each entry: characteristic open-port set + OS guess
PORT_PROFILES: list[dict] = [
    {
        "name": "Windows Server",
        "required": [135, 445],
        "preferred": [139, 3389, 5985, 49152, 49153],
        "denied": [],
        "confidence": 0.85,
    },
    {
        "name": "Windows Desktop",
        "required": [135, 139],
        "preferred": [445, 3389],
        "denied": [80, 443],
        "confidence": 0.70,
    },
    {
        "name": "Linux Server",
        "required": [22],
        "preferred": [80, 443, 25, 587, 8080],
        "denied": [135, 139, 445],
        "confidence": 0.75,
    },
    {
        "name": "Domain Controller (AD)",
        "required": [88, 389, 636, 445],
        "preferred": [3268, 3269, 5985],
        "denied": [],
        "confidence": 0.95,
    },
    {
        "name": "VMware ESXi host",
        "required": [443, 902],
        "preferred": [80, 8000, 8100],
        "denied": [],
        "confidence": 0.90,
    },
    {
        "name": "Network printer",
        "required": [9100],
        "preferred": [515, 631, 80],
        "denied": [22],
        "confidence": 0.90,
    },
    {
        "name": "IP Camera (Hikvision/Dahua family)",
        "required": [554],
        "preferred": [80, 8000, 8554, 443, 37777],
        "denied": [22],
        "confidence": 0.80,
    },
    {
        "name": "Synology NAS (DSM)",
        "required": [5000, 5001],
        "preferred": [22, 80, 443, 139, 445, 873],
        "denied": [],
        "confidence": 0.90,
    },
    {
        "name": "QNAP NAS",
        "required": [8080],
        "preferred": [22, 80, 443, 139, 445, 873, 8443],
        "denied": [],
        "confidence": 0.75,
    },
    {
        "name": "Mikrotik RouterOS",
        "required": [8291],
        "preferred": [22, 80, 443, 8728, 8729, 53],
        "denied": [],
        "confidence": 0.95,
    },
    {
        "name": "Cisco IOS / network gear",
        "required": [],
        "preferred": [22, 23, 80, 443, 161, 830],
        "denied": [445, 3389],
        "confidence": 0.55,
    },
    {
        "name": "macOS",
        "required": [],
        "preferred": [22, 88, 445, 548, 5900, 7000],
        "denied": [135, 3389],
        "confidence": 0.65,
    },
    {
        "name": "Kubernetes node",
        "required": [10250],
        "preferred": [2379, 2380, 6443, 10257, 10259],
        "denied": [],
        "confidence": 0.90,
    },
    {
        "name": "Docker host",
        "required": [],
        "preferred": [2375, 2376, 5000],
        "denied": [],
        "confidence": 0.65,
    },
    {
        "name": "Raspberry Pi (OS-default)",
        "required": [22],
        "preferred": [80, 5353],
        "denied": [135, 445],
        "confidence": 0.50,
    },
]


# ── Banner→OS regex map ──────────────────────────────────────────────────
BANNER_OS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"SSH-2\.0-OpenSSH_\d.+Ubuntu", re.I), "Ubuntu Linux", "ssh"),
    (re.compile(r"SSH-2\.0-OpenSSH_\d.+Debian", re.I), "Debian Linux", "ssh"),
    (re.compile(r"SSH-2\.0-OpenSSH_\d.+CentOS", re.I), "CentOS Linux", "ssh"),
    (re.compile(r"SSH-2\.0-OpenSSH_\d.+RHEL", re.I), "RHEL Linux", "ssh"),
    (re.compile(r"SSH-2\.0-OpenSSH_for_Windows", re.I), "Windows", "ssh"),
    (re.compile(r"Server:\s*Microsoft-IIS", re.I), "Windows Server", "http"),
    (re.compile(r"Server:\s*Apache/\d+\.\d+\.\d+\s*\(Win32\)", re.I), "Windows", "http"),
    (re.compile(r"Server:\s*Apache/\d+\.\d+\.\d+\s*\(Ubuntu\)", re.I), "Ubuntu Linux", "http"),
    (re.compile(r"Server:\s*Apache/\d+\.\d+\.\d+\s*\(Debian\)", re.I), "Debian Linux", "http"),
    (re.compile(r"Server:\s*Apache/\d+\.\d+\.\d+\s*\(CentOS\)", re.I), "CentOS Linux", "http"),
    (re.compile(r"Server:\s*nginx/\d+\.\d+\.\d+\s*\(Ubuntu\)", re.I), "Ubuntu Linux", "http"),
    (re.compile(r"NASFTPD Turbo Station", re.I), "Synology DSM", "ftp"),
    (re.compile(r"DSM/\d+\.\d+", re.I), "Synology DSM", "http"),
    (re.compile(r"MikroTik\s+RouterOS", re.I), "Mikrotik RouterOS", "any"),
    (re.compile(r"Cisco IOS", re.I), "Cisco IOS", "any"),
    (re.compile(r"FortiOS", re.I), "Fortinet FortiOS", "any"),
    (re.compile(r"OpenWrt", re.I), "OpenWrt Linux", "any"),
    (re.compile(r"DD-WRT", re.I), "DD-WRT", "any"),
    (re.compile(r"VMware ESXi", re.I), "VMware ESXi", "any"),
    (re.compile(r"Mac OS X", re.I), "macOS", "any"),
    (re.compile(r"Darwin", re.I), "macOS / Darwin", "any"),
    (re.compile(r"FreeBSD", re.I), "FreeBSD", "any"),
    (re.compile(r"NetBSD", re.I), "NetBSD", "any"),
    (re.compile(r"OpenBSD", re.I), "OpenBSD", "any"),
]


def _score_port_profile(open_ports: set[int], profile: dict) -> float:
    """Return a 0-1 confidence score for how well open_ports matches profile."""
    req = set(profile.get("required", []))
    pref = set(profile.get("preferred", []))
    denied = set(profile.get("denied", []))

    if req and not req.issubset(open_ports):
        return 0.0
    if denied & open_ports:
        return 0.0

    # Score: how many preferred ports are present?
    if not pref:
        pref_score = 1.0 if req else 0.5
    else:
        pref_score = len(pref & open_ports) / len(pref)

    base = profile.get("confidence", 0.5)
    # Bonus for hitting ALL required ports
    return base * (0.4 + 0.6 * pref_score)


def _banner_signals(banners: list[str]) -> list[tuple[str, str]]:
    """Extract OS signals from a host's banner strings."""
    out: list[tuple[str, str]] = []
    for banner in banners:
        if not banner:
            continue
        for pattern, os_name, service in BANNER_OS_PATTERNS:
            if pattern.search(banner):
                out.append((os_name, service))
    return out


def fingerprint(host: dict) -> dict:
    """Multi-signal OS fingerprint for a host dict (port list + banners + TTL).

    Returns dict with:
      best_guess: str ("Ubuntu Linux", "Windows Server", etc.)
      confidence: 0-1
      signals: list of (signal_type, value) pairs that contributed
      port_profile_matches: ranked list of (profile_name, score)
    """
    signals: list[tuple[str, str]] = []
    port_profile_scores: list[tuple[str, float]] = []

    open_ports = {p["number"] for p in host.get("ports", [])}
    banners = [p.get("banner") or "" for p in host.get("ports", [])]

    # TTL signal
    ttl = host.get("ttl")
    os_hint = host.get("os_hint") or {}
    if os_hint.get("os_family"):
        signals.append(("ttl", os_hint["os_family"]))

    # MAC vendor signal
    vendor = host.get("vendor")
    if vendor:
        signals.append(("mac_vendor", vendor))

    # Banner signals
    banner_hits = _banner_signals(banners)
    for os_name, service in banner_hits:
        signals.append((f"banner_{service}", os_name))

    # Port-profile signals
    for profile in PORT_PROFILES:
        score = _score_port_profile(open_ports, profile)
        if score > 0:
            port_profile_scores.append((profile["name"], score))
    port_profile_scores.sort(key=lambda x: -x[1])

    # Combine all signals into a single best guess
    # Priority: banner hits (high confidence) > port profile > TTL/vendor
    if banner_hits:
        # Take the most-specific banner hit
        os_name = banner_hits[0][0]
        confidence = 0.85
    elif port_profile_scores:
        os_name = port_profile_scores[0][0]
        confidence = port_profile_scores[0][1]
    elif os_hint.get("os_family"):
        os_name = os_hint["os_family"]
        confidence = 0.4
    elif vendor:
        os_name = f"{vendor} device"
        confidence = 0.3
    else:
        os_name = "unknown"
        confidence = 0.0

    return {
        "best_guess": os_name,
        "confidence": round(confidence, 2),
        "signals": signals,
        "port_profile_matches": [
            {"name": n, "score": round(s, 2)} for n, s in port_profile_scores[:5]
        ],
    }


def fingerprint_scan(scan_dict: dict) -> dict[str, dict]:
    """Run OS fingerprint for every host in a scan result."""
    out: dict[str, dict] = {}
    for h in scan_dict.get("hosts", []):
        out[h["ip"]] = fingerprint(h)
    return out
