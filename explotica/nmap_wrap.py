"""Thin wrapper around the `nmap` binary for service/vuln detection.

We invoke nmap with `-sV --script vuln -oX -` and parse the XML output to
pull out:
  - service product/version (more reliable than our regex banners)
  - vulnerabilities reported by NSE vuln scripts (vulners, vuln-*)

Why shell-out and not python-nmap or python-libnmap:
  - those packages haven't kept up with nmap >= 7.9x in some distros,
  - shelling out keeps our dependency surface tiny,
  - the XML schema is stable.

Requirements:
  - nmap must be installed and on PATH.
  - Some NSE vuln scripts need raw sockets (root) just like our ARP scan.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from .models import CVE, Port

log = logging.getLogger(__name__)


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _parse_xml(xml_str: str) -> dict[int, dict]:
    """Parse nmap XML output into {port_number: {service, cves}}."""
    out: dict[int, dict] = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log.warning("nmap XML parse error: %s", e)
        return out

    for host_el in root.findall("host"):
        for port_el in host_el.findall("./ports/port"):
            portid = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            entry: dict = {"cves": [], "service": None, "version": None,
                           "product": None}
            svc = port_el.find("service")
            if svc is not None:
                entry["service"] = svc.get("name")
                entry["product"] = svc.get("product")
                entry["version"] = svc.get("version")

            # NSE script output — each <script id="..." output="..."> child
            for script in port_el.findall("script"):
                sid = script.get("id", "")
                soutput = script.get("output", "") or ""
                # The 'vulners' script emits a table with CVE IDs and CVSS.
                # Format: '\tCVE-2020-1234\t9.8\thttps://...'
                if sid in ("vulners",) or sid.startswith("vuln"):
                    for line in soutput.splitlines():
                        # Find CVE-YYYY-NNNN tokens; parse trailing float if present.
                        for token in line.split():
                            if token.startswith("CVE-") and token.count("-") >= 2:
                                cve_id = token.rstrip(",")
                                # Look for a CVSS in the same line.
                                cvss = None
                                for tok in line.replace("\t", " ").split():
                                    try:
                                        v = float(tok)
                                        if 0.0 <= v <= 10.0:
                                            cvss = v
                                            break
                                    except ValueError:
                                        continue
                                entry["cves"].append({
                                    "id": cve_id,
                                    "cvss": cvss,
                                    "summary": f"reported by nmap {sid}",
                                    "severity": (_severity_from_score(cvss)
                                                 if cvss is not None else "UNKNOWN"),
                                })
            out[portid] = entry
    return out


def run_nmap(ip: str, ports: list[int], timeout: int = 180) -> dict[int, dict]:
    """Run nmap -sV --script vuln against the given ports, return per-port info."""
    if not ports:
        return {}
    if not nmap_available():
        log.warning("nmap not installed — skipping --use-nmap")
        return {}
    port_arg = ",".join(str(p) for p in sorted(set(ports)))
    cmd = [
        "nmap",
        "-Pn",                  # we already know it's up
        "-n",                   # no DNS
        "-sV",                  # service/version detection
        "--script", "vuln",     # NSE vuln category
        "--version-intensity", "5",
        "-p", port_arg,
        "-oX", "-",             # XML to stdout
        ip,
    ]
    log.info("running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        log.warning("nmap timed out after %ds for %s", timeout, ip)
        return {}
    except FileNotFoundError:
        log.warning("nmap binary not found in PATH")
        return {}
    if proc.returncode != 0 and not proc.stdout:
        log.warning("nmap failed for %s: %s", ip, proc.stderr[:200])
        return {}
    return _parse_xml(proc.stdout)


def enrich_host_with_nmap(host_ip: str, ports: list[Port], timeout: int = 180) -> None:
    """Run nmap against host, merge product/version and CVEs into Port objects."""
    if not ports:
        return
    port_nums = [p.number for p in ports]
    findings = run_nmap(host_ip, port_nums, timeout=timeout)
    by_number = {p.number: p for p in ports}
    for portnum, info in findings.items():
        p = by_number.get(portnum)
        if p is None:
            continue
        if info.get("product") and not p.product_name:
            p.product_name = info["product"].lower()
            p.product_vendor = p.product_name  # best guess
        if info.get("version") and not p.product_version:
            p.product_version = info["version"]
        # Merge CVEs (deduped by id)
        existing = {c.id for c in p.cves}
        for c in info.get("cves", []):
            if c["id"] in existing:
                continue
            p.cves.append(CVE(
                id=c["id"],
                severity=c.get("severity", "UNKNOWN"),
                cvss=c.get("cvss"),
                summary=c.get("summary"),
                source="nmap",
            ))
        # Re-sort by severity
        p.cves.sort(key=lambda x: -(x.cvss or 0))
