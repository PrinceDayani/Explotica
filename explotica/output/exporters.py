"""Machine-readable exporters for CI/security-pipeline ingestion.

Two formats:
  - CSV: one row per (host, port, CVE); ports without CVEs still emit a row so
    the open-port inventory is complete.
  - SARIF 2.1.0: each CVE is a result, each unique CVE id a rule. Consumable by
    GitHub code scanning and other SARIF viewers.

Both take a ScanResult and write to a path, returning the Path.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..core.models import ScanResult

__all__ = ["write_csv", "write_sarif", "build_sarif"]

_CSV_COLUMNS = [
    "ip", "hostname", "port", "protocol", "state", "service",
    "product", "version", "cve_id", "severity", "cvss",
    "epss_score", "in_kev", "summary",
]

# SARIF severity → level. CVSS/KEV do not map 1:1 to SARIF levels, so we key
# off the textual severity the scanner already assigns.
_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}


def write_csv(scan: ScanResult, path: str | Path) -> Path:
    """Write a flat CSV of ports and CVEs. Returns the written Path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for host in scan.hosts:
            base = {
                "ip": host.ip,
                "hostname": host.hostname or "",
            }
            if not host.ports:
                writer.writerow({**{c: "" for c in _CSV_COLUMNS}, **base})
                continue
            for port in host.ports:
                prow = {
                    **{c: "" for c in _CSV_COLUMNS},
                    **base,
                    "port": port.number,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service or "",
                    "product": port.product_name or "",
                    "version": port.product_version or "",
                }
                if not port.cves:
                    writer.writerow(prow)
                    continue
                for cve in port.cves:
                    writer.writerow({
                        **prow,
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "cvss": "" if cve.cvss is None else cve.cvss,
                        "epss_score": "" if cve.epss_score is None
                                      else cve.epss_score,
                        "in_kev": "true" if cve.in_kev else "false",
                        "summary": (cve.summary or "").replace("\n", " "),
                    })
    return out


def build_sarif(scan: ScanResult) -> dict:
    """Build a SARIF 2.1.0 log dict from a ScanResult (no I/O)."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for host in scan.hosts:
        for port in host.ports:
            for cve in port.cves:
                if cve.id not in rules:
                    rule: dict = {
                        "id": cve.id,
                        "name": cve.id,
                        "shortDescription": {"text": cve.id},
                        "properties": {
                            "security-severity": (
                                str(cve.cvss) if cve.cvss is not None else "0.0"
                            ),
                            "tags": ["security", "cve"]
                                    + (["kev"] if cve.in_kev else []),
                        },
                    }
                    if cve.summary:
                        rule["fullDescription"] = {"text": cve.summary}
                    rules[cve.id] = rule

                loc = f"{host.ip}:{port.number}/{port.protocol}"
                svc = port.product_name or port.service or "service"
                results.append({
                    "ruleId": cve.id,
                    "level": _SEVERITY_TO_LEVEL.get(
                        (cve.severity or "UNKNOWN").upper(), "none"),
                    "message": {
                        "text": f"{cve.id} ({cve.severity}) affects {svc} on "
                                f"{loc}" + (f": {cve.summary}" if cve.summary
                                            else ""),
                    },
                    "locations": [{
                        "logicalLocations": [{
                            "fullyQualifiedName": loc,
                            "kind": "resource",
                        }],
                    }],
                    "partialFingerprints": {
                        "exploticaCveLocation": f"{cve.id}@{loc}",
                    },
                })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Explotica",
                    "informationUri": "https://github.com/PrinceDayani/Explotica",
                    "version": scan.scanner_version or "0+unknown",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }


def write_sarif(scan: ScanResult, path: str | Path) -> Path:
    """Write a SARIF 2.1.0 log. Returns the written Path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build_sarif(scan), indent=2), encoding="utf-8")
    return out
