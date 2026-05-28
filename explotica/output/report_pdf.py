"""PDF + Markdown report writers.

PDF: reuses the existing HTML report and converts via weasyprint.
Markdown: GitHub-flavored markdown suitable for pasting into issues / PRs.

Both produce sortable, prioritized findings — by default sorted by the
Phase 30 prioritization scorer.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except ImportError:
        return False


# ── PDF (HTML → PDF via weasyprint) ───────────────────────────────────────
def write_pdf_report(scan_result, output_path: str | Path,
                      html_string: Optional[str] = None) -> Optional[Path]:
    """Render the scan as a PDF.

    If `html_string` is not provided, we build one via report.render_report.
    """
    if not weasyprint_available():
        log.warning("weasyprint not installed — skipping PDF.")
        log.warning("Install: pip install weasyprint")
        return None

    if html_string is None:
        from .report import render_report
        html_string = render_report(scan_result)

    from weasyprint import HTML, CSS
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Light tweak: force a print stylesheet for better PDF readability
        pdf_css = CSS(string="""
            @page { size: A4; margin: 1cm; }
            body { font-size: 10pt; }
            section.host { page-break-inside: avoid; }
            #graph { display: none !important; }
        """)
        HTML(string=html_string).write_pdf(str(out_path), stylesheets=[pdf_css])
        log.info("PDF written: %s", out_path)
        return out_path
    except Exception as e:
        log.warning("PDF generation failed: %s", e)
        return None


# ── Markdown (GitHub-flavored) ────────────────────────────────────────────
def render_markdown_report(scan_result) -> str:
    """Build a GFM markdown report suitable for GitHub issues / PRs / wikis."""
    sd = scan_result.to_dict() if hasattr(scan_result, "to_dict") else scan_result
    hosts = sd.get("hosts", [])

    out: list[str] = []
    out.append(f"# Explotica scan report — `{sd.get('target')}`")
    out.append("")
    out.append(f"- **Started:** {sd.get('started_at')}")
    out.append(f"- **Duration:** {sd.get('duration_s')}s")
    out.append(f"- **Hosts:** {len(hosts)}")
    out.append(f"- **Scanner:** explotica v{sd.get('scanner_version')}")

    # Aggregate severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    kev_count = 0
    open_ports = 0
    for h in hosts:
        for p in h.get("ports", []):
            open_ports += 1
            for c in p.get("cves", []):
                s = (c.get("severity") or "").upper()
                if s in sev_counts:
                    sev_counts[s] += 1
                if c.get("in_kev"):
                    kev_count += 1
    out.append(f"- **Open ports:** {open_ports}")
    out.append(f"- **CVE summary:** "
               + ", ".join(f"{n} {s.lower()}" for s, n in sev_counts.items() if n))
    if kev_count:
        out.append(f"- ⚠️ **{kev_count} CVE(s) on CISA KEV (actively exploited)**")
    out.append("")

    # Prioritized findings
    try:
        from ..vulns.prioritize import score_scan_result
        prio = score_scan_result(sd)
        if prio["top_priorities"]:
            out.append("## 🔴 Top priorities")
            out.append("")
            out.append("| Score | Host | CVE | Bucket | Reasons |")
            out.append("|------:|------|-----|--------|---------|")
            for tp in prio["top_priorities"]:
                reasons = "; ".join(tp.get("reasons", []))
                out.append(f"| {tp['score']:.0f} | `{tp.get('host_ip','?')}` "
                           f"| `{tp.get('cve_id','?')}` | {tp.get('bucket')} | "
                           f"{reasons[:120]} |")
            out.append("")
    except Exception as e:
        log.debug("prioritize for markdown report failed: %s", e)

    # Per-host details
    out.append("## Hosts")
    out.append("")
    for h in sorted(hosts, key=lambda x: tuple(int(o) for o in x["ip"].split("."))):
        if not h.get("ports"):
            continue
        out.append(f"### `{h['ip']}` " + (f"({h['hostname']})" if h.get("hostname") else ""))
        if h.get("mac"):
            out.append(f"- **MAC:** `{h['mac']}` vendor: {h.get('vendor') or '-'}")
        if h.get("os_hint"):
            oh = h["os_hint"]
            out.append(f"- **OS:** {oh.get('os_family')} (TTL={h.get('ttl')})")
        out.append("")

        for p in h["ports"]:
            line = f"#### `{p['number']}/{p.get('protocol','tcp')}`"
            if p.get("service"):
                line += f" {p['service']}"
            if p.get("product_name") and p.get("product_version"):
                line += f" — `{p['product_name']} {p['product_version']}`"
            out.append(line)
            if p.get("banner"):
                banner_safe = p["banner"][:160].replace("`", "")
                out.append(f"  - banner: `{banner_safe}`")
            cves = sorted(
                p.get("cves", []),
                key=lambda c: (
                    not c.get("in_kev"),
                    -(c.get("epss_score") or 0),
                    -(c.get("cvss") or 0),
                ),
            )
            if cves:
                out.append("  - CVEs:")
                for c in cves[:5]:
                    marker = " 🔥KEV" if c.get("in_kev") else ""
                    score = (f"{c.get('cvss'):.1f}"
                              if c.get("cvss") is not None else "?")
                    out.append(
                        f"    - `{c.get('id')}` "
                        f"({c.get('severity')}/{score}){marker}"
                    )
                if len(cves) > 5:
                    out.append(f"    - … and {len(cves) - 5} more")
            if p.get("exploits"):
                out.append("  - 💥 exploits:")
                for ex in p["exploits"][:3]:
                    label = f"EDB-{ex.get('edb_id', '?')}"
                    title = ex.get("title", "")[:80]
                    if ex.get("url"):
                        out.append(f"    - [{label}]({ex['url']}) — {title}")
                    else:
                        out.append(f"    - {label} — {title}")
        out.append("")

    out.append("---")
    out.append("*Generated by [Explotica](https://github.com/PrinceDayani/Explotica) "
               "— do what is right, scan what you own.*")
    return "\n".join(out)


def write_markdown_report(scan_result, output_path: str | Path) -> Path:
    """Write a Markdown report to disk and return the path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown_report(scan_result), encoding="utf-8")
    log.info("Markdown written: %s", out)
    return out
