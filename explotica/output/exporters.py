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
import os
from pathlib import Path

from ..core.models import ScanResult

__all__ = ["write_csv", "write_sarif", "build_sarif"]

# Spreadsheet formula-injection prefixes. A cell beginning with one of these is
# evaluated as a formula by Excel/Sheets, so untrusted scan text (hostnames,
# banners, CVE summaries) must be neutralised before it reaches a CSV cell.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise spreadsheet formula injection in a CSV cell value.

    Non-strings (ints, floats) are returned unchanged. A string starting with
    a formula marker is prefixed with a single quote so spreadsheet software
    treats it as text.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text to a temp file in the same dir, then atomically replace.

    A crash mid-write leaves the previous report intact instead of truncating
    it to a partial/empty file.
    """
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)

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
    """Write a flat CSV of ports and CVEs. Returns the written Path.

    Untrusted text is neutralised against spreadsheet formula injection, and
    the file is written atomically.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    import io
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()

    def _emit(row: dict) -> None:
        writer.writerow({k: _csv_safe(v) for k, v in row.items()})

    for host in scan.hosts:
        base = {"ip": host.ip, "hostname": host.hostname or ""}
        if not host.ports:
            _emit({**{c: "" for c in _CSV_COLUMNS}, **base})
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
                _emit(prow)
                continue
            for cve in port.cves:
                _emit({
                    **prow,
                    "cve_id": cve.id,
                    "severity": cve.severity,
                    "cvss": "" if cve.cvss is None else cve.cvss,
                    "epss_score": "" if cve.epss_score is None
                                  else cve.epss_score,
                    "in_kev": "true" if cve.in_kev else "false",
                    "summary": (cve.summary or "").replace("\n", " "),
                })

    _atomic_write_text(out, buf.getvalue())
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
    """Write a SARIF 2.1.0 log atomically. Returns the written Path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(out, json.dumps(build_sarif(scan), indent=2))
    return out
