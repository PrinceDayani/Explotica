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
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from .models import CVE, Host, Port

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


def _parse_xml_multi(xml_str: str) -> dict[str, dict[int, dict]]:
    """Parse nmap XML into {ip: {port_number: {service, version, cves}}}.

    Handles multi-host nmap output from one-shot invocations.
    """
    out: dict[str, dict[int, dict]] = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log.warning("nmap XML parse error: %s", e)
        return out

    for host_el in root.findall("host"):
        # Pull the IP for this host
        addr_el = host_el.find("./address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("./address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        if not ip:
            continue

        host_ports = _parse_host_ports(host_el)
        if host_ports:
            out[ip] = host_ports
    return out


def _parse_host_ports(host_el) -> dict[int, dict]:
    """Extract port info from one <host> element."""
    out: dict[int, dict] = {}
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
            if sid in ("vulners",) or sid.startswith("vuln"):
                for line in soutput.splitlines():
                    for token in line.split():
                        if token.startswith("CVE-") and token.count("-") >= 2:
                            cve_id = token.rstrip(",")
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
    """Single-host nmap. Kept for backward compat / fallback paths."""
    if not ports:
        return {}
    findings = run_nmap_multi([ip], ports, timeout=timeout)
    return findings.get(ip, {})


def run_nmap_multi(ips: list[str], ports: list[int],
                   timeout: int = 240) -> dict[str, dict[int, dict]]:
    """ONE-SHOT nmap against many hosts.

    Massively faster than spawning N nmap processes — nmap reuses its
    raw socket and NSE script engine across all hosts in one run.
    Typical /24 with --auto-fallback: 4-6 min → 60-90 sec.
    """
    if not ips or not ports:
        return {}
    if not nmap_available():
        log.warning("nmap not installed — skipping nmap step")
        return {}
    port_arg = ",".join(str(p) for p in sorted(set(ports)))

    # Write host list to a temp file (-iL); nmap parses it the same as
    # positional args but handles large lists more cleanly.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                      delete=False) as f:
        for ip in ips:
            f.write(f"{ip}\n")
        hostfile = f.name

    cmd = [
        "nmap",
        "-Pn",                  # skip ping — we already verified up
        "-n",                   # no DNS
        "-sV",                  # service/version
        "--script", "vuln",     # NSE vuln category
        "--version-intensity", "5",
        "-T4",                  # aggressive timing template
        "--min-parallelism", "32",
        "-p", port_arg,
        "-iL", hostfile,
        "-oX", "-",
    ]
    log.info("nmap one-shot: %d host(s), %d port(s)", len(ips), len(ports.__class__(ports) if not isinstance(ports, set) else ports))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        log.warning("nmap timed out after %ds (one-shot, %d hosts)",
                    timeout, len(ips))
        return {}
    except FileNotFoundError:
        log.warning("nmap binary not found in PATH")
        return {}
    finally:
        try:
            Path(hostfile).unlink(missing_ok=True)
        except Exception:
            pass

    if proc.returncode != 0 and not proc.stdout:
        log.warning("nmap one-shot failed: %s", proc.stderr[:300])
        return {}
    return _parse_xml_multi(proc.stdout)


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


def enrich_hosts_with_nmap(hosts: list[Host],
                            ports_per_host: Optional[dict[str, list[int]]] = None,
                            timeout: int = 240) -> None:
    """Plural — run nmap ONCE for all hosts, merge findings into each host.

    Args:
      hosts: Host objects whose ports will be enriched.
      ports_per_host: optional override mapping ip → [port nums]. If None,
        uses every open port on every host (union).
      timeout: nmap subprocess timeout for the entire one-shot.
    """
    if not hosts:
        return
    # Build the host list and the union of ports.
    ips = [h.ip for h in hosts if h.ports]
    if not ips:
        return
    if ports_per_host:
        all_ports = sorted({p for plist in ports_per_host.values() for p in plist})
    else:
        all_ports = sorted({p.number for h in hosts for p in h.ports})

    findings = run_nmap_multi(ips, all_ports, timeout=timeout)
    if not findings:
        return

    host_by_ip = {h.ip: h for h in hosts}
    for ip, port_findings in findings.items():
        host = host_by_ip.get(ip)
        if host is None:
            continue
        by_number = {p.number: p for p in host.ports}
        for portnum, info in port_findings.items():
            p = by_number.get(portnum)
            if p is None:
                continue
            if info.get("product") and not p.product_name:
                p.product_name = info["product"].lower()
                p.product_vendor = p.product_name
            if info.get("version") and not p.product_version:
                p.product_version = info["version"]
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
            p.cves.sort(key=lambda x: -(x.cvss or 0))
