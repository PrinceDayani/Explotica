"""Smart vulnerability prioritization scorer.

Combines multiple signals into a single 0-100 RiskScore that's actually
useful for triage. Inspired by SSVC + FIRST EPSS guidance, but kept simple
and explainable (no opaque ML).

Inputs per CVE finding:
  - CVSS base score (0-10)
  - EPSS probability (0-1)
  - KEV-listed (boolean)
  - Has known exploit (from searchsploit / nmap vulners — implied bool)
  - Asset exposure (port + service signals: open to LAN vs internet,
                    auth required, common-creds, public service)

Output: 0-100 with categorical bucket + plain-English reason string.
"""

from __future__ import annotations

from typing import Optional


# Weight constants — tunable. Sum of weights determines max score.
_W_CVSS = 25.0
_W_EPSS = 30.0
_W_KEV = 25.0
_W_EXPLOIT = 15.0
_W_EXPOSURE = 5.0

# Service exposure signals — these ports are typically directly exploitable
_HIGH_EXPOSURE_SERVICES = frozenset({
    "ssh", "ftp", "telnet", "rdp", "smb", "vnc",
    "mysql", "postgres", "mongodb", "redis", "memcached",
    "elasticsearch", "kibana", "jenkins", "docker-registry",
    "ftp-data",
})


def _bucket(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def score_cve(cvss: Optional[float] = None,
              epss: Optional[float] = None,
              in_kev: bool = False,
              has_exploit: bool = False,
              service: Optional[str] = None,
              port: Optional[int] = None,
              exposure_factor: float = 1.0) -> dict:
    """Return {score, bucket, reasons} for one CVE finding.

    exposure_factor: 1.0 = internal LAN; 1.5+ if internet-facing.
    """
    reasons: list[str] = []
    parts: list[tuple[str, float]] = []

    # CVSS (normalize 0-10 → 0-25)
    if cvss is not None:
        c = min(max(cvss, 0), 10) / 10.0 * _W_CVSS
        parts.append(("CVSS", c))
        if cvss >= 9.0:
            reasons.append(f"CVSS {cvss:.1f} (critical)")

    # EPSS (already 0-1)
    if epss is not None:
        e = min(max(epss, 0), 1) * _W_EPSS
        parts.append(("EPSS", e))
        if epss >= 0.5:
            reasons.append(f"EPSS {epss:.2f} (likely exploited)")

    # KEV — binary boost
    if in_kev:
        parts.append(("KEV", _W_KEV))
        reasons.append("CISA KEV (actively exploited)")

    # Has exploit (PoC or weaponized)
    if has_exploit:
        parts.append(("ExploitAvail", _W_EXPLOIT))
        reasons.append("Public exploit available")

    # Service exposure
    if service and service.lower() in _HIGH_EXPOSURE_SERVICES:
        parts.append(("HighExpService", _W_EXPOSURE * exposure_factor))
        reasons.append(f"High-exposure service: {service}")

    raw = sum(s for _, s in parts)
    max_possible = (_W_CVSS + _W_EPSS + _W_KEV + _W_EXPLOIT
                    + (_W_EXPOSURE * exposure_factor))
    score = round((raw / max_possible) * 100, 1) if max_possible > 0 else 0
    return {
        "score": score,
        "bucket": _bucket(score),
        "reasons": reasons,
        "components": dict(parts),
    }


def score_port(port_dict: dict, exposure_factor: float = 1.0) -> list[dict]:
    """Score every CVE on one Port dict; returns sorted list (highest first)."""
    out: list[dict] = []
    service = port_dict.get("service")
    port_num = port_dict.get("number")
    has_exploit = bool(port_dict.get("exploits"))

    for cve in port_dict.get("cves", []):
        result = score_cve(
            cvss=cve.get("cvss"),
            epss=cve.get("epss_score"),
            in_kev=cve.get("in_kev", False),
            has_exploit=has_exploit,
            service=service,
            port=port_num,
            exposure_factor=exposure_factor,
        )
        out.append({
            "cve_id": cve.get("id"),
            "host_port": f"{port_num}",
            **result,
        })
    out.sort(key=lambda x: -x["score"])
    return out


def score_host(host_dict: dict, exposure_factor: float = 1.0) -> dict:
    """Score every CVE on every port of a host; return summary."""
    all_scored = []
    for p in host_dict.get("ports", []):
        all_scored.extend(score_port(p, exposure_factor=exposure_factor))
    all_scored.sort(key=lambda x: -x["score"])

    # Bucket counts
    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for s in all_scored:
        buckets[s["bucket"]] = buckets.get(s["bucket"], 0) + 1

    # Top 5 for surface display
    top = all_scored[:5]

    return {
        "ip": host_dict.get("ip"),
        "total_cves_scored": len(all_scored),
        "buckets": buckets,
        "top_findings": top,
        "max_score": all_scored[0]["score"] if all_scored else 0,
    }


def score_scan_result(scan_result: dict,
                       exposure_factor: float = 1.0) -> dict:
    """Score every host in a scan result; return aggregated triage report."""
    host_scores = []
    for h in scan_result.get("hosts", []):
        host_scores.append(score_host(h, exposure_factor=exposure_factor))

    # Sort hosts by max score
    host_scores.sort(key=lambda h: -h["max_score"])

    # Network-wide buckets
    net_buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for hs in host_scores:
        for b, n in hs["buckets"].items():
            net_buckets[b] = net_buckets.get(b, 0) + n

    # Top 10 findings across the whole scan
    all_findings: list[dict] = []
    for hs in host_scores:
        for f in hs["top_findings"]:
            all_findings.append({**f, "host_ip": hs["ip"]})
    all_findings.sort(key=lambda x: -x["score"])

    return {
        "host_scores": host_scores,
        "network_buckets": net_buckets,
        "top_priorities": all_findings[:10],
        "scoring_weights": {
            "cvss": _W_CVSS, "epss": _W_EPSS, "kev": _W_KEV,
            "exploit_available": _W_EXPLOIT,
            "exposure": _W_EXPOSURE * exposure_factor,
        },
    }
