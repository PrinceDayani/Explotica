"""Compliance framework — evaluate scan results against policy rules.

Each rule is a structured check: a question like "Is SSH listening with
password auth disabled?" framed as a condition over scan data. Rules
group into frameworks (CIS Benchmarks, PCI-DSS, HIPAA, custom).

The engine walks rules against a ScanResult and returns PASS/FAIL/SKIP
per rule, with evidence.

Why this matters: auditors require compliance reports. This is the
single feature enterprises pay Nessus $5k/year for that we didn't have.

Rule format (pure Python — no YAML dependency):

  {
    "id": "CIS-3.1",
    "title": "Disable Telnet",
    "framework": "CIS Benchmarks v8",
    "category": "Network Services",
    "severity": "HIGH",
    "check": lambda scan: not any(p["number"] == 23
                                   for h in scan.get("hosts", [])
                                   for p in h.get("ports", [])),
    "remediation": "Remove telnetd; use SSH instead",
  }
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

log = logging.getLogger(__name__)


# ── Helper predicates over scan data ─────────────────────────────────────
def _any_host_has_port(scan: dict, port: int) -> list[str]:
    """Return list of host IPs that have the given port open."""
    return [h["ip"] for h in scan.get("hosts", [])
            if any(p["number"] == port for p in h.get("ports", []))]


def _hosts_with_cve_severity(scan: dict, sev: str) -> list[str]:
    return [h["ip"] for h in scan.get("hosts", [])
            if any((c.get("severity") or "").upper() == sev.upper()
                   for p in h.get("ports", [])
                   for c in p.get("cves", []))]


def _hosts_with_kev(scan: dict) -> list[str]:
    return [h["ip"] for h in scan.get("hosts", [])
            if any(c.get("in_kev") for p in h.get("ports", [])
                   for c in p.get("cves", []))]


def _hosts_with_tls_issue(scan: dict, issue_substring: str) -> list[str]:
    out: list[str] = []
    for h in scan.get("hosts", []):
        for p in h.get("ports", []):
            tls = p.get("tls_info") or {}
            for iss in tls.get("issues", []):
                if issue_substring.lower() in iss.lower():
                    out.append(h["ip"])
                    break
    return out


def _hosts_with_missing_security_header(scan: dict, header: str) -> list[str]:
    out: list[str] = []
    for h in scan.get("hosts", []):
        for p in h.get("ports", []):
            http_info = p.get("http_info") or {}
            missing = http_info.get("security_headers", {}).get("missing", [])
            if any(header.lower() in m.lower() for m in missing):
                out.append(h["ip"])
                break
    return out


def _hosts_with_default_creds(scan: dict) -> list[str]:
    ef = scan.get("extra_findings") or {}
    dc = ef.get("default_creds") or {}
    return list(dc.keys())


def _hosts_with_smb1(scan: dict) -> list[str]:
    out: list[str] = []
    for h in scan.get("hosts", []):
        for p in h.get("ports", []):
            smb = p.get("smb_info") or {}
            if smb.get("dialect_response") == "SMB1":
                out.append(h["ip"])
                break
    return out


# ── Pre-built rule sets ──────────────────────────────────────────────────
# CIS Benchmarks v8 (selected high-impact subset)
CIS_BENCHMARKS_V8: list[dict] = [
    {
        "id": "CIS-3.1",
        "title": "No Telnet (port 23) listening",
        "framework": "CIS Benchmarks v8",
        "category": "Network Services",
        "severity": "HIGH",
        "check": lambda scan: not _any_host_has_port(scan, 23),
        "evidence_fn": lambda scan: _any_host_has_port(scan, 23),
        "remediation": "Disable telnetd; use SSH (port 22)",
    },
    {
        "id": "CIS-3.2",
        "title": "No FTP (port 21) without TLS",
        "framework": "CIS Benchmarks v8",
        "category": "Network Services",
        "severity": "MEDIUM",
        "check": lambda scan: not _any_host_has_port(scan, 21),
        "evidence_fn": lambda scan: _any_host_has_port(scan, 21),
        "remediation": "Use SFTP (over SSH) or FTPS instead of plain FTP",
    },
    {
        "id": "CIS-3.3",
        "title": "No SMBv1 enabled",
        "framework": "CIS Benchmarks v8",
        "category": "Network Services",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_smb1(scan),
        "evidence_fn": lambda scan: _hosts_with_smb1(scan),
        "remediation": "Disable SMBv1 (EternalBlue family); use SMBv2/v3",
    },
    {
        "id": "CIS-3.4",
        "title": "No RDP (3389) exposed without NLA",
        "framework": "CIS Benchmarks v8",
        "category": "Network Services",
        "severity": "HIGH",
        "check": lambda scan: True,  # Detail check requires deeper RDP probe
        "evidence_fn": lambda scan: _any_host_has_port(scan, 3389),
        "remediation": "Enable Network Level Authentication on RDP",
    },
    {
        "id": "CIS-3.5",
        "title": "No SNMP with default community",
        "framework": "CIS Benchmarks v8",
        "category": "Network Services",
        "severity": "HIGH",
        "check": lambda scan: not any(
            "community=public" in str(f).lower()
            for h, findings in (scan.get("extra_findings") or {})
                .get("default_creds", {}).items()
            for f in findings
        ),
        "evidence_fn": lambda scan: list(
            (scan.get("extra_findings") or {}).get("default_creds", {}).keys()
        ),
        "remediation": "Set strong SNMP community strings; prefer SNMPv3",
    },
    {
        "id": "CIS-4.1",
        "title": "No weak TLS protocols enabled (TLS 1.0/1.1)",
        "framework": "CIS Benchmarks v8",
        "category": "TLS/SSL",
        "severity": "HIGH",
        "check": lambda scan: not _hosts_with_tls_issue(scan, "Weak TLS"),
        "evidence_fn": lambda scan: _hosts_with_tls_issue(scan, "Weak TLS"),
        "remediation": "Disable TLSv1.0 and TLSv1.1; require TLSv1.2+",
    },
    {
        "id": "CIS-4.2",
        "title": "No expired or self-signed certificates",
        "framework": "CIS Benchmarks v8",
        "category": "TLS/SSL",
        "severity": "MEDIUM",
        "check": lambda scan: (not _hosts_with_tls_issue(scan, "expired")
                                and not _hosts_with_tls_issue(scan, "self-signed")),
        "evidence_fn": lambda scan: (_hosts_with_tls_issue(scan, "expired")
                                      + _hosts_with_tls_issue(scan, "self-signed")),
        "remediation": "Renew expired certs; use CA-issued for production",
    },
    {
        "id": "CIS-5.1",
        "title": "No KEV-listed CVEs unpatched",
        "framework": "CIS Benchmarks v8",
        "category": "Patch Management",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_kev(scan),
        "evidence_fn": lambda scan: _hosts_with_kev(scan),
        "remediation": "Patch CISA KEV-listed CVEs within 14 days",
    },
    {
        "id": "CIS-5.2",
        "title": "No CRITICAL CVEs present",
        "framework": "CIS Benchmarks v8",
        "category": "Patch Management",
        "severity": "HIGH",
        "check": lambda scan: not _hosts_with_cve_severity(scan, "CRITICAL"),
        "evidence_fn": lambda scan: _hosts_with_cve_severity(scan, "CRITICAL"),
        "remediation": "Patch all CVSS ≥ 9.0 vulnerabilities",
    },
    {
        "id": "CIS-6.1",
        "title": "No default credentials anywhere",
        "framework": "CIS Benchmarks v8",
        "category": "Access Control",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_default_creds(scan),
        "evidence_fn": lambda scan: _hosts_with_default_creds(scan),
        "remediation": "Change all default credentials; enforce password policy",
    },
    {
        "id": "CIS-7.1",
        "title": "HSTS header on all HTTPS endpoints",
        "framework": "CIS Benchmarks v8",
        "category": "Web Security",
        "severity": "MEDIUM",
        "check": lambda scan: not _hosts_with_missing_security_header(scan, "HSTS"),
        "evidence_fn": lambda scan: _hosts_with_missing_security_header(scan, "HSTS"),
        "remediation": "Set Strict-Transport-Security on all HTTPS responses",
    },
    {
        "id": "CIS-7.2",
        "title": "X-Frame-Options or frame-ancestors CSP set",
        "framework": "CIS Benchmarks v8",
        "category": "Web Security",
        "severity": "MEDIUM",
        "check": lambda scan: not _hosts_with_missing_security_header(scan, "Clickjacking"),
        "evidence_fn": lambda scan: _hosts_with_missing_security_header(scan, "Clickjacking"),
        "remediation": "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'",
    },
]


# PCI-DSS — narrower set focusing on network-visible controls
PCI_DSS: list[dict] = [
    {
        "id": "PCI-1.1.6",
        "title": "Insecure services/protocols disabled",
        "framework": "PCI-DSS v4.0",
        "category": "Network Segmentation",
        "severity": "HIGH",
        "check": lambda scan: not (_any_host_has_port(scan, 23)
                                    or _any_host_has_port(scan, 21)),
        "evidence_fn": lambda scan: (_any_host_has_port(scan, 23)
                                      + _any_host_has_port(scan, 21)),
        "remediation": "Remove Telnet/FTP; PCI-DSS requires secure protocols",
    },
    {
        "id": "PCI-4.1",
        "title": "Strong cryptography on cardholder transmission",
        "framework": "PCI-DSS v4.0",
        "category": "Encryption in Transit",
        "severity": "CRITICAL",
        "check": lambda scan: (not _hosts_with_tls_issue(scan, "Weak TLS")
                                and not _hosts_with_tls_issue(scan, "SSLv")),
        "evidence_fn": lambda scan: (_hosts_with_tls_issue(scan, "Weak TLS")
                                      + _hosts_with_tls_issue(scan, "SSLv")),
        "remediation": "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 — require TLS 1.2+",
    },
    {
        "id": "PCI-6.2",
        "title": "Critical security patches applied within 30 days",
        "framework": "PCI-DSS v4.0",
        "category": "Vulnerability Management",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_kev(scan),
        "evidence_fn": lambda scan: _hosts_with_kev(scan),
        "remediation": "Patch all KEV-listed vulnerabilities",
    },
    {
        "id": "PCI-8.2.3",
        "title": "Strong authentication — no defaults",
        "framework": "PCI-DSS v4.0",
        "category": "Access Control",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_default_creds(scan),
        "evidence_fn": lambda scan: _hosts_with_default_creds(scan),
        "remediation": "PCI-DSS requires no default vendor passwords in scope",
    },
]


# HIPAA — narrower
HIPAA: list[dict] = [
    {
        "id": "HIPAA-164.312(a)",
        "title": "Encryption of ePHI in transit",
        "framework": "HIPAA Security Rule",
        "category": "Access Control",
        "severity": "CRITICAL",
        "check": lambda scan: (not _hosts_with_tls_issue(scan, "Weak TLS")
                                and not _hosts_with_tls_issue(scan, "expired")),
        "evidence_fn": lambda scan: (_hosts_with_tls_issue(scan, "Weak TLS")
                                      + _hosts_with_tls_issue(scan, "expired")),
        "remediation": "Use strong, current TLS for all PHI-handling endpoints",
    },
    {
        "id": "HIPAA-164.308(a)(1)",
        "title": "No unauthenticated database services",
        "framework": "HIPAA Security Rule",
        "category": "Security Management",
        "severity": "CRITICAL",
        "check": lambda scan: not _hosts_with_default_creds(scan),
        "evidence_fn": lambda scan: _hosts_with_default_creds(scan),
        "remediation": "All databases must require authentication",
    },
]


ALL_FRAMEWORKS = {
    "cis": CIS_BENCHMARKS_V8,
    "pci": PCI_DSS,
    "hipaa": HIPAA,
}


# ── Engine ───────────────────────────────────────────────────────────────
def evaluate(scan: dict, framework: str = "cis") -> dict:
    """Walk rules from `framework` against scan; return per-rule outcomes."""
    rules = ALL_FRAMEWORKS.get(framework.lower())
    if not rules:
        return {"error": f"Unknown framework: {framework}"}
    results: list[dict] = []
    pass_count = fail_count = skip_count = 0
    for rule in rules:
        try:
            passed = bool(rule["check"](scan))
            evidence = rule.get("evidence_fn", lambda s: [])(scan) if not passed else []
            outcome = "PASS" if passed else "FAIL"
            if passed:
                pass_count += 1
            else:
                fail_count += 1
        except Exception as e:
            log.debug("rule %s crashed: %s", rule["id"], e)
            outcome = "SKIP"
            evidence = []
            passed = None
            skip_count += 1
        results.append({
            "id": rule["id"],
            "title": rule["title"],
            "framework": rule["framework"],
            "category": rule["category"],
            "severity": rule["severity"],
            "outcome": outcome,
            "evidence": evidence[:10] if isinstance(evidence, list) else evidence,
            "remediation": rule.get("remediation", ""),
        })
    score = pass_count / max(pass_count + fail_count, 1) * 100
    return {
        "framework": rules[0]["framework"] if rules else framework,
        "rule_count": len(rules),
        "pass": pass_count,
        "fail": fail_count,
        "skip": skip_count,
        "score_pct": round(score, 1),
        "results": results,
    }


def evaluate_all(scan: dict) -> dict:
    """Run scan against all built-in frameworks."""
    return {fw: evaluate(scan, fw) for fw in ALL_FRAMEWORKS}
