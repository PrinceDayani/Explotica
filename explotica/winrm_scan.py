"""WinRM credentialed scanning — Windows fleet inspection.

Same idea as creds_scan.py but for Windows. Uses pywinrm to authenticate
via NTLM or Kerberos to the Windows Remote Management service (port 5985
HTTP, 5986 HTTPS). Once connected, runs WMI/PowerShell queries to get:

  - Installed products (Get-WmiObject Win32_Product)
  - Installed updates / hotfixes (Get-HotFix)
  - Installed Windows features (Get-WindowsFeature)
  - Running services (Get-Service)
  - OS version + edition (Get-CimInstance Win32_OperatingSystem)

Each result feeds into NVD CPE lookup for CVE matching.

Requires `pywinrm` (pip install pywinrm).
"""

from __future__ import annotations

import logging
import re
from typing import Optional

log = logging.getLogger(__name__)


def winrm_available() -> bool:
    try:
        import winrm  # noqa: F401
        return True
    except ImportError:
        return False


# ── WinRM session ─────────────────────────────────────────────────────────
def _winrm_session(host: str, *,
                    port: int = 5985,
                    username: str,
                    password: str,
                    use_ssl: bool = False,
                    transport: str = "ntlm",
                    timeout: float = 15.0):
    """Establish a WinRM session. transport: ntlm / kerberos / basic / ssl."""
    import winrm
    scheme = "https" if use_ssl or port == 5986 else "http"
    if port not in (5985, 5986):
        # Custom port — explicit
        endpoint = f"{scheme}://{host}:{port}/wsman"
    else:
        endpoint = f"{scheme}://{host}:{port}/wsman"
    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport=transport,
        server_cert_validation="ignore",
        read_timeout_sec=int(timeout),
        operation_timeout_sec=int(timeout - 2),
    )
    return session


def _run_ps(session, script: str) -> Optional[str]:
    """Run a PowerShell script through the session. Returns stdout or None."""
    try:
        r = session.run_ps(script)
        if r.status_code == 0:
            return r.std_out.decode("utf-8", errors="replace")
        log.debug("PS failed (%d): %s", r.status_code,
                  r.std_err.decode("utf-8", errors="replace")[:300])
        return None
    except Exception as e:
        log.debug("PS exec crashed: %s", e)
        return None


# ── Inventory queries ─────────────────────────────────────────────────────
PS_INVENTORY_QUERIES = {
    "installed_products": (
        "Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue "
        "| Select-Object Name, Version, Vendor "
        "| ConvertTo-Csv -NoTypeInformation"
    ),
    "hotfixes": (
        "Get-HotFix -ErrorAction SilentlyContinue "
        "| Select-Object HotFixID, Description, InstalledOn "
        "| ConvertTo-Csv -NoTypeInformation"
    ),
    "os_info": (
        "Get-CimInstance Win32_OperatingSystem "
        "| Select-Object Caption, Version, BuildNumber, OSArchitecture, "
        "InstallDate, LastBootUpTime "
        "| ConvertTo-Csv -NoTypeInformation"
    ),
    "windows_features": (
        # Only works on Server SKUs
        "Get-WindowsFeature -ErrorAction SilentlyContinue "
        "| Where-Object Installed -eq $true "
        "| Select-Object Name, DisplayName "
        "| ConvertTo-Csv -NoTypeInformation"
    ),
    "services": (
        "Get-Service "
        "| Where-Object Status -eq Running "
        "| Select-Object Name, DisplayName, Status "
        "| ConvertTo-Csv -NoTypeInformation"
    ),
}


def _parse_csv(csv_text: str) -> list[dict]:
    """Parse PowerShell ConvertTo-Csv output into list of dicts."""
    if not csv_text:
        return []
    import csv
    from io import StringIO
    rows: list[dict] = []
    try:
        reader = csv.DictReader(StringIO(csv_text))
        for row in reader:
            # Strip quotes / whitespace from values
            cleaned = {k: (v or "").strip() for k, v in row.items() if k}
            if any(cleaned.values()):
                rows.append(cleaned)
    except csv.Error as e:
        log.debug("CSV parse failed: %s", e)
    return rows


# ── Vendor mapping (Windows-specific) ────────────────────────────────────
_WIN_VENDOR_MAP = {
    "microsoft visual c++": ("microsoft", "visual_c++"),
    "microsoft .net": ("microsoft", ".net_framework"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "google chrome": ("google", "chrome"),
    "mozilla firefox": ("mozilla", "firefox"),
    "adobe acrobat": ("adobe", "acrobat_reader_dc"),
    "adobe reader": ("adobe", "acrobat_reader"),
    "java": ("oracle", "jre"),
    "openjdk": ("oracle", "openjdk"),
    "vmware tools": ("vmware", "tools"),
    "virtualbox": ("oracle", "virtualbox"),
    "7-zip": ("7-zip", "7-zip"),
    "winrar": ("rarlab", "winrar"),
    "putty": ("simon_tatham", "putty"),
    "filezilla": ("filezilla-project", "filezilla"),
    "notepad++": ("notepad-plus-plus", "notepad++"),
    "wireshark": ("wireshark", "wireshark"),
    "git": ("git", "git"),
    "python": ("python", "python"),
    "nodejs": ("nodejs", "nodejs"),
    "node.js": ("nodejs", "nodejs"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openbsd", "openssh"),
    "apache http server": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "mysql server": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "mariadb server": ("mariadb", "mariadb"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "docker desktop": ("docker", "desktop"),
    "kubernetes": ("kubernetes", "kubernetes"),
}


def _name_to_cpe(name: str) -> Optional[tuple[str, str]]:
    """Map a Win32_Product Name field to NVD (vendor, product) slugs."""
    if not name:
        return None
    lower = name.lower()
    for key, (vendor, product) in _WIN_VENDOR_MAP.items():
        if key in lower:
            return (vendor, product)
    # Heuristic: vendor=product, lowercase, alphanumeric only
    clean = re.sub(r"[^a-z0-9_]+", "_", lower).strip("_")
    if clean and len(clean) >= 3 and len(clean) <= 40:
        return (clean, clean)
    return None


def _clean_version(version: str) -> str:
    """Strip build numbers / suffixes for cleaner CPE matching."""
    # Win versions look like "10.0.19041" or "1.2.3.4567"
    m = re.match(r"(\d+\.\d+(?:\.\d+)?)", version or "")
    return m.group(1) if m else (version or "")


# ── CVE lookup ────────────────────────────────────────────────────────────
def lookup_cves_for_windows_products(products: list[dict],
                                       max_lookups: int = 50) -> list[dict]:
    """For each Win32_Product entry, attempt NVD CVE lookup."""
    from .nvd import lookup_cves
    out: list[dict] = []
    for prod in products[:max_lookups]:
        name = prod.get("Name", "")
        version = _clean_version(prod.get("Version", ""))
        mapping = _name_to_cpe(name)
        if not mapping or not version:
            continue
        vendor, product = mapping
        try:
            cves = lookup_cves(vendor, product, version)
            if cves:
                out.append({
                    "product_name": name,
                    "version": version,
                    "vendor_raw": prod.get("Vendor", ""),
                    "cpe_vendor": vendor,
                    "cpe_product": product,
                    "cve_count": len(cves),
                    "cves": [c.to_dict() for c in cves[:10]],
                })
        except Exception as e:
            log.debug("NVD lookup failed for %s: %s", name, e)
    return out


# ── Patch / hotfix correlation ────────────────────────────────────────────
def correlate_hotfixes_with_cves(hotfixes: list[dict],
                                   os_info: list[dict]) -> dict:
    """Coarse correlation — show what hotfixes are installed; let user
    cross-reference against known KB→CVE mappings (we don't ship the full
    map here)."""
    kb_ids = [h.get("HotFixID", "") for h in hotfixes if h.get("HotFixID")]
    return {
        "installed_kbs": sorted(set(kb_ids)),
        "kb_count": len(set(kb_ids)),
        "os_caption": os_info[0].get("Caption") if os_info else None,
        "os_build": os_info[0].get("BuildNumber") if os_info else None,
        "note": ("KB→CVE correlation requires the Microsoft Security Update "
                 "Guide JSON feed; cross-reference manually for now."),
    }


# ── Main entry ────────────────────────────────────────────────────────────
def winrm_credentialed_scan(host: str, *,
                             port: int = 5985,
                             username: str,
                             password: str,
                             use_ssl: bool = False,
                             transport: str = "ntlm",
                             timeout: float = 20.0,
                             max_cve_lookups: int = 50) -> Optional[dict]:
    """Full credentialed scan of a Windows host over WinRM."""
    if not winrm_available():
        log.warning("pywinrm not installed. Install: pip install pywinrm")
        return None

    try:
        sess = _winrm_session(host, port=port, username=username,
                               password=password, use_ssl=use_ssl,
                               transport=transport, timeout=timeout)
    except Exception as e:
        log.warning("WinRM connect %s failed: %s", host, e)
        return None

    inv: dict = {"host": host, "transport": transport, "queries": {}}
    for name, script in PS_INVENTORY_QUERIES.items():
        out = _run_ps(sess, script)
        if out:
            inv["queries"][name] = _parse_csv(out)

    products = inv["queries"].get("installed_products", [])
    hotfixes = inv["queries"].get("hotfixes", [])
    os_info = inv["queries"].get("os_info", [])

    inv["product_count"] = len(products)
    inv["hotfix_count"] = len(hotfixes)

    if products:
        log.info("WinRM scan %s: %d products, looking up CVEs…",
                 host, len(products))
        inv["cve_findings"] = lookup_cves_for_windows_products(
            products, max_lookups=max_cve_lookups
        )
        inv["total_cves"] = sum(f["cve_count"] for f in inv["cve_findings"])

    if hotfixes:
        inv["hotfix_summary"] = correlate_hotfixes_with_cves(hotfixes, os_info)

    return inv


def winrm_scan_hosts(hosts: list, creds: dict,
                      workers: int = 4) -> dict[str, dict]:
    """Run WinRM scan against multiple hosts in parallel.

    Only scans hosts that have port 5985 or 5986 open.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, dict] = {}

    def scan(h):
        # Phase 57: check state==open, not just "port number is present in list"
        # (which would include closed/filtered ports now that Phase 56 emits all)
        port = None
        if any(p.number == 5985 and p.state == "open" for p in h.ports):
            port = 5985
        elif any(p.number == 5986 and p.state == "open" for p in h.ports):
            port = 5986
        if not port:
            return (h.ip, None)
        return (h.ip, winrm_credentialed_scan(
            h.ip, port=port,
            username=creds.get("username", "Administrator"),
            password=creds.get("password", ""),
            use_ssl=(port == 5986),
            transport=creds.get("transport", "ntlm"),
        ))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for f in as_completed([pool.submit(scan, h) for h in hosts]):
            try:
                ip, data = f.result()
                if data:
                    out[ip] = data
            except Exception as e:
                log.debug("winrm worker error: %s", e)
    return out
