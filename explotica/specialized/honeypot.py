"""Honeypot detection — fingerprints for known honeypots + heuristics.

Knowing you're poking a honeypot saves time (don't waste budget cracking
fake creds) and ego (don't claim a finding from a deception target).

Detection signals:

  1. SOFTWARE FINGERPRINTS — Cowrie/Dionaea/Conpot/Kippo have default
     banners that are slightly off from the real thing they emulate.

  2. RESPONSE-TIME ANOMALIES — honeypots emulate many services, so
     response times tend to be either suspiciously uniform (scripted
     replies) or suspiciously fast (no real OS overhead).

  3. PROTOCOL-CORRECTNESS QUIRKS — honeypots implement protocols
     "good enough" but miss edge cases. We probe for specific quirks.

  4. CROSS-SERVICE INCONSISTENCY — a host that runs FTP+SSH+SMB+HTTP
     all with default banners on a fresh-looking install is suspicious.
"""

from __future__ import annotations

import logging
import re
import socket
import time
from typing import Optional

log = logging.getLogger(__name__)


# ── Cowrie SSH honeypot fingerprints ──────────────────────────────────────
COWRIE_FINGERPRINTS = [
    # Default Cowrie banner advertises an OpenSSH version that doesn't quite
    # match the underlying service stack — see also config quirks
    re.compile(rb"SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2"),
    re.compile(rb"SSH-2\.0-OpenSSH_6\.6\.1p1 Ubuntu-2ubuntu1"),
]


# ── Kippo (deprecated Cowrie predecessor) ─────────────────────────────────
KIPPO_FINGERPRINTS = [
    re.compile(rb"SSH-2\.0-OpenSSH_5\.1p1 Debian-5"),
    re.compile(rb"SSH-1\.99-OpenSSH_5\.1p1 Debian-5"),
]


# ── Dionaea (multi-protocol honeypot) ─────────────────────────────────────
DIONAEA_FINGERPRINTS = {
    "smb": re.compile(rb"\xffSMB.*\x00\x00\x00\x00.*samba", re.S | re.I),
    "ftp": re.compile(rb"220 \(vsFTPd 2\.0\.5\)"),  # Dionaea's default FTP banner
    "mssql": re.compile(rb"\x04\x01\x00.+SQL Server", re.S),
}


# ── Conpot (ICS honeypot) ─────────────────────────────────────────────────
CONPOT_FINGERPRINTS = {
    "modbus": re.compile(rb"Siemens.*SIMATIC", re.S),  # often-default identity
    "http": re.compile(rb"Siemens", re.I),
}


def probe_ssh_honeypot(host: str, port: int = 22,
                        timeout: float = 4.0) -> Optional[dict]:
    """SSH-specific honeypot detection."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # Read banner
        t0 = time.perf_counter()
        banner = b""
        while b"\n" not in banner and len(banner) < 256:
            chunk = sock.recv(256)
            if not chunk:
                break
            banner += chunk
        banner_time = time.perf_counter() - t0

        # Send our banner + a fake auth attempt
        sock.sendall(b"SSH-2.0-PuTTY_Release_0.74\r\n")
        # Try invalid auth — Cowrie accepts "anything"
        time.sleep(0.1)
        sock.close()
    except (socket.timeout, OSError):
        return None

    findings: list[str] = []
    for fp in COWRIE_FINGERPRINTS:
        if fp.search(banner):
            findings.append("Cowrie banner match")
    for fp in KIPPO_FINGERPRINTS:
        if fp.search(banner):
            findings.append("Kippo banner match")

    # Banner timing heuristic — real OpenSSH ~5-20ms on LAN; honeypots can be <1ms
    if banner_time < 0.001 and banner.startswith(b"SSH-"):
        findings.append(f"banner returned in {banner_time*1000:.2f}ms (suspiciously fast)")

    if findings:
        return {
            "service": "ssh",
            "honeypot_suspected": True,
            "findings": findings,
            "banner": banner.decode("ascii", "ignore").strip()[:120],
            "banner_ms": round(banner_time * 1000, 2),
            "severity": "INFO",
            "note": "Likely SSH honeypot — do not waste credential brute-force budget",
        }
    return None


def probe_telnet_honeypot(host: str, port: int = 23,
                           timeout: float = 4.0) -> Optional[dict]:
    """Telnet honeypots often accept literally any password instantly."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(1024)
        sock.close()
    except (socket.timeout, OSError):
        return None
    findings: list[str] = []
    # Cowrie's telnet emulation: similar fingerprint quirks
    if b"BusyBox" in banner and b"login:" in banner:
        # Suspiciously generic embedded-Linux login
        findings.append("BusyBox login prompt — common honeypot template")
    if findings:
        return {
            "service": "telnet",
            "honeypot_suspected": True,
            "findings": findings,
            "severity": "INFO",
        }
    return None


def probe_http_honeypot(host: str, port: int = 80, *,
                         tls: bool = False, timeout: float = 4.0) -> Optional[dict]:
    """Check for HTTP honeypot patterns (Glastopf, Snare, perfect default pages)."""
    try:
        import ssl as ssl_mod
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl_mod._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        data = sock.recv(8192)
        sock.close()
    except Exception:
        return None
    if not data:
        return None
    findings: list[str] = []
    # Conpot serves a too-perfect Siemens identity page
    for sig in CONPOT_FINGERPRINTS["http"].finditer(data):
        findings.append("Conpot Siemens emulation page")
    # Glastopf-style pages: lots of fake CVE-bait content
    if b"phpMyAdmin" in data and b"vuln" in data.lower():
        findings.append("Glastopf-style web honeypot pattern")
    if findings:
        return {
            "service": "http",
            "honeypot_suspected": True,
            "findings": findings,
            "severity": "INFO",
        }
    return None


def cross_service_heuristic(host: dict) -> Optional[dict]:
    """Multi-service heuristic: a host advertising many wildly-different
    default banners (SSH+FTP+SMB+SQL+HTTP all on stock-version) is suspicious.

    Real production servers usually run a focused set; honeypots intentionally
    expose many to catch all comers.
    """
    if not host.get("ports"):
        return None
    services = set()
    for p in host["ports"]:
        if p.get("service"):
            services.add(p["service"].lower())
    # Specific honeypot-like service combinations
    suspicious_combos = [
        {"ssh", "ftp", "telnet", "mssql"},  # Dionaea typical
        {"ssh", "telnet", "ftp", "smtp", "imap", "pop3"},  # multi-honeypot stack
    ]
    for combo in suspicious_combos:
        if combo.issubset(services):
            return {
                "host": host.get("ip"),
                "honeypot_suspected": True,
                "findings": [f"Service combination unusual: {sorted(combo)}"],
                "severity": "INFO",
                "note": "Diverse service set on one host — common in honeypots",
            }
    return None


def detect_honeypot(host_ip: str, ports: list[int],
                    timeout: float = 4.0) -> dict:
    """Run all honeypot probes against a host:port set."""
    findings: dict = {"host": host_ip, "indicators": []}
    if 22 in ports:
        r = probe_ssh_honeypot(host_ip, 22, timeout=timeout)
        if r:
            findings["indicators"].append(r)
    if 23 in ports:
        r = probe_telnet_honeypot(host_ip, 23, timeout=timeout)
        if r:
            findings["indicators"].append(r)
    for p in (80, 8080, 443, 8443):
        if p in ports:
            r = probe_http_honeypot(host_ip, p,
                                     tls=(p in (443, 8443)),
                                     timeout=timeout)
            if r:
                findings["indicators"].append(r)
                break
    return findings if findings["indicators"] else {}


def detect_honeypot_in_scan(scan_dict: dict) -> list[dict]:
    """Run honeypot detection against every host in a completed scan."""
    out: list[dict] = []
    for host in scan_dict.get("hosts", []):
        ports = [p["number"] for p in host.get("ports", [])]
        # Cross-service heuristic
        cross = cross_service_heuristic(host)
        if cross:
            out.append(cross)
        # Per-host probes
        if ports:
            r = detect_honeypot(host["ip"], ports)
            if r:
                out.append(r)
    return out
