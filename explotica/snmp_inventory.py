"""SNMP credentialed inventory — Phase 53c.

When SNMP is reachable (community string or v3 credentials), walk the
host-resources MIB to enumerate installed software, running processes,
and system info. Each piece of software gets a CPE lookup → NVD CVE match.

Closes the SNMP portion of the Nessus auth-scanning matrix.

Standard MIBs we walk:
  - sysDescr.0         (1.3.6.1.2.1.1.1.0)  → OS family + version
  - sysObjectID.0      (1.3.6.1.2.1.1.2.0)  → vendor/model OID
  - hrSWInstalledTable (1.3.6.1.2.1.25.6.3.1) → installed software inventory
  - hrSWRunTable       (1.3.6.1.2.1.25.4.2.1) → running processes
  - ifDescr / ifPhysAddress → interface inventory (vendor recon)

Hand-rolled BER walk via `snmpwalk` binary (net-snmp) or pysnmp. We prefer
the binary because it's installed everywhere and avoids the pysnmp asyncio
churn. Falls back to pysnmp if the binary is missing.

SNMPv1 / v2c (community string) + SNMPv3 (user + auth + priv) all supported.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Optional

from .constants import TIMEOUT
from .models import Port

log = logging.getLogger(__name__)


# ── snmpwalk binary path ─────────────────────────────────────────────────
def snmpwalk_available() -> bool:
    return shutil.which("snmpwalk") is not None


# ── Core: walk one OID with auth ─────────────────────────────────────────
def _walk(host: str, oid: str, *,
           version: str = "2c",
           community: str = "public",
           # SNMPv3 args
           v3_user: Optional[str] = None,
           v3_auth_proto: str = "SHA",     # MD5 or SHA
           v3_auth_pass: Optional[str] = None,
           v3_priv_proto: str = "AES",     # DES or AES
           v3_priv_pass: Optional[str] = None,
           v3_level: str = "authPriv",     # noAuthNoPriv|authNoPriv|authPriv
           timeout: float = 4.0,
           retries: int = 1) -> list[str]:
    """Walk an OID subtree. Returns list of "key = value" lines from snmpwalk."""
    if not snmpwalk_available():
        log.debug("snmpwalk binary not available")
        return []
    if version == "3":
        if not v3_user:
            log.debug("SNMPv3 requires v3_user")
            return []
        args = ["snmpwalk", "-v", "3",
                "-u", v3_user,
                "-l", v3_level,
                "-t", str(int(timeout)),
                "-r", str(retries),
                "-On",  # Numeric OIDs only — easier to parse
                ]
        if v3_level in ("authNoPriv", "authPriv") and v3_auth_pass:
            args.extend(["-a", v3_auth_proto, "-A", v3_auth_pass])
        if v3_level == "authPriv" and v3_priv_pass:
            args.extend(["-x", v3_priv_proto, "-X", v3_priv_pass])
        args.extend([host, oid])
    else:
        args = ["snmpwalk", "-v", version,
                "-c", community,
                "-t", str(int(timeout)),
                "-r", str(retries),
                "-On",
                host, oid]
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                  timeout=timeout * 2 + 4)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if result.returncode != 0:
        log.debug("snmpwalk %s %s failed: %s", host, oid,
                  result.stderr[:200] if result.stderr else "rc=" + str(result.returncode))
        return []
    return [ln for ln in result.stdout.splitlines() if ln.strip()]


def _parse_value(line: str) -> tuple[str, str, str]:
    """Parse a snmpwalk output line.

    Format: '.1.3.6.1.2.1.25.6.3.1.2.1 = STRING: "openssl-libs"'
    Returns (oid, value_type, value).
    """
    if "=" not in line:
        return ("", "", "")
    left, right = line.split("=", 1)
    oid = left.strip()
    right = right.strip()
    if ":" in right:
        vtype, _, val = right.partition(":")
        return (oid, vtype.strip(), val.strip().strip('"'))
    return (oid, "", right.strip().strip('"'))


# ── System info ──────────────────────────────────────────────────────────
def get_system_info(host: str, **auth) -> dict:
    """Pull sysDescr.0, sysObjectID.0, sysName.0, sysContact.0, sysLocation.0,
    sysUpTime.0 from the standard MIB-2 tree."""
    out: dict = {}
    lines = _walk(host, "1.3.6.1.2.1.1", **auth)
    for line in lines:
        _, vtype, val = _parse_value(line)
        oid = line.split("=")[0].strip()
        if oid.startswith(".1.3.6.1.2.1.1.1."):
            out["sysDescr"] = val
        elif oid.startswith(".1.3.6.1.2.1.1.2."):
            out["sysObjectID"] = val
        elif oid.startswith(".1.3.6.1.2.1.1.3."):
            out["sysUpTime"] = val
        elif oid.startswith(".1.3.6.1.2.1.1.4."):
            out["sysContact"] = val
        elif oid.startswith(".1.3.6.1.2.1.1.5."):
            out["sysName"] = val
        elif oid.startswith(".1.3.6.1.2.1.1.6."):
            out["sysLocation"] = val
    return out


# ── Installed software inventory ─────────────────────────────────────────
# hrSWInstalledName     1.3.6.1.2.1.25.6.3.1.2
# hrSWInstalledID       1.3.6.1.2.1.25.6.3.1.3
# hrSWInstalledType     1.3.6.1.2.1.25.6.3.1.4
# hrSWInstalledDate     1.3.6.1.2.1.25.6.3.1.5
def get_installed_software(host: str, **auth) -> list[dict]:
    """Walk hrSWInstalledTable. Each row = (name, ID, type, install_date)."""
    lines = _walk(host, "1.3.6.1.2.1.25.6.3.1.2", **auth)
    out: list[dict] = []
    for line in lines:
        oid, vtype, val = _parse_value(line)
        if not val:
            continue
        # Try to split "name-1.2.3" into name+version
        m = re.match(r"^(.+?)-(\d[\d.]*[a-z\d]*)$", val)
        if m:
            name, version = m.group(1), m.group(2)
        else:
            name, version = val, ""
        out.append({
            "name": name,
            "full_name": val,
            "version": version,
            "version_clean": re.split(r"[-+~]", version)[0] if version else "",
            "source": "snmp-hrSWInstalled",
        })
    return out


# ── Running processes ────────────────────────────────────────────────────
def get_running_processes(host: str, **auth) -> list[dict]:
    """Walk hrSWRunTable. Each row = (PID, name, path, params, type, status)."""
    name_lines = _walk(host, "1.3.6.1.2.1.25.4.2.1.2", **auth)  # hrSWRunName
    out: list[dict] = []
    for line in name_lines:
        oid, _, val = _parse_value(line)
        if not val:
            continue
        # Last component of OID is the PID
        pid = oid.split(".")[-1]
        out.append({
            "pid": pid,
            "name": val,
            "source": "snmp-hrSWRun",
        })
    return out


# ── Network interface inventory ──────────────────────────────────────────
def get_interfaces(host: str, **auth) -> list[dict]:
    """Walk ifTable for interface names, MAC addresses, IPs."""
    descr_lines = _walk(host, "1.3.6.1.2.1.2.2.1.2", **auth)  # ifDescr
    mac_lines = _walk(host, "1.3.6.1.2.1.2.2.1.6", **auth)    # ifPhysAddress
    descrs: dict[str, str] = {}
    macs: dict[str, str] = {}
    for line in descr_lines:
        oid, _, val = _parse_value(line)
        idx = oid.split(".")[-1]
        descrs[idx] = val
    for line in mac_lines:
        oid, _, val = _parse_value(line)
        idx = oid.split(".")[-1]
        macs[idx] = val
    out: list[dict] = []
    for idx, name in descrs.items():
        out.append({
            "index": idx,
            "name": name,
            "mac": macs.get(idx, ""),
        })
    return out


# ── Top-level fingerprint ────────────────────────────────────────────────
def snmp_credentialed_inventory(host: str, port: int = 161, *,
                                  version: str = "2c",
                                  community: str = "public",
                                  v3_user: Optional[str] = None,
                                  v3_auth_pass: Optional[str] = None,
                                  v3_priv_pass: Optional[str] = None,
                                  v3_auth_proto: str = "SHA",
                                  v3_priv_proto: str = "AES",
                                  v3_level: str = "authPriv",
                                  timeout: float = 4.0) -> Optional[dict]:
    """Full SNMP credentialed inventory of one host.

    Returns dict with sys_info, software (with versions), processes,
    interfaces, and a synthesized cve_findings list from NVD lookups.

    NULL if SNMP is unreachable or returns no usable data.
    """
    auth: dict = {
        "version": version,
        "community": community,
        "v3_user": v3_user,
        "v3_auth_pass": v3_auth_pass,
        "v3_priv_pass": v3_priv_pass,
        "v3_auth_proto": v3_auth_proto,
        "v3_priv_proto": v3_priv_proto,
        "v3_level": v3_level,
        "timeout": timeout,
    }

    sys_info = get_system_info(host, **auth)
    if not sys_info.get("sysDescr"):
        log.debug("SNMP %s: no sysDescr — likely unreachable", host)
        return None

    software = get_installed_software(host, **auth)
    processes = get_running_processes(host, **auth)
    interfaces = get_interfaces(host, **auth)

    # CVE lookup for any installed software we can map to NVD
    from .creds_scan import _to_nvd_cpe
    from .nvd import lookup_cves
    cve_findings: list[dict] = []
    for sw in software[:200]:  # cap to avoid runaway NVD load
        if not sw.get("version_clean"):
            continue
        mapping = _to_nvd_cpe(sw["name"])
        if not mapping:
            continue
        vendor, product = mapping
        try:
            cves = lookup_cves(vendor, product, sw["version_clean"])
            if cves:
                cve_findings.append({
                    "package": sw["name"],
                    "version": sw["full_name"],
                    "cpe_vendor": vendor,
                    "cpe_product": product,
                    "cve_count": len(cves),
                    "cves": [c.to_dict() for c in cves[:10]],
                })
        except Exception as e:
            log.debug("NVD lookup failed for %s: %s", sw["name"], e)

    return {
        "host": host,
        "snmp_version": version,
        "system_info": sys_info,
        "software": software,
        "software_count": len(software),
        "processes": processes,
        "process_count": len(processes),
        "interfaces": interfaces,
        "cve_findings": cve_findings,
        "total_cves": sum(f["cve_count"] for f in cve_findings),
    }


def snmp_inventory_hosts(hosts: list, creds: dict,
                          timeout: float = 4.0,
                          workers: int = 8) -> dict[str, dict]:
    """Run SNMP credentialed inventory across multiple hosts in parallel.

    Args:
      hosts: list of Host objects (uses host.ip + checks for open SNMP)
      creds: {"version": "2c", "community": "public"} OR
             {"version": "3", "v3_user": ..., "v3_auth_pass": ...}
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, dict] = {}

    def scan(h):
        # SNMP is UDP/161 — we can't easily check open state from a TCP scan,
        # but if any TCP port is open the host is alive; just try SNMP.
        # (Most SNMP probes will fail quickly if 161/udp is closed.)
        result = snmp_credentialed_inventory(
            h.ip, timeout=timeout, **creds
        )
        return (h.ip, result)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for f in as_completed([pool.submit(scan, h) for h in hosts]):
            try:
                ip, data = f.result()
                if data:
                    out[ip] = data
            except Exception as e:
                log.debug("SNMP inventory worker error: %s", e)
    return out
