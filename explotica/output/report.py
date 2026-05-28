"""Standalone HTML report generation from a ScanResult.

Self-contained (no Jinja, no external CSS) so the report can be opened on
any machine without network access. Style is a minimal dark theme.
"""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

from ..core.models import CVE, Host, Port, ScanResult


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"]
_SEVERITY_COLORS = {
    "CRITICAL": "#ff3b30",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34c759",
    "UNKNOWN":  "#8e8e93",
    "NONE":     "#3a3a3c",
}


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _sev_pill(sev: str, score: float | None) -> str:
    color = _SEVERITY_COLORS.get(sev, "#8e8e93")
    score_str = f"{score:.1f}" if score is not None else "?"
    return (f'<span class="pill" style="background:{color}">'
            f'{_esc(sev)} {score_str}</span>')


def _ip_sort_key(host: Host) -> tuple:
    try:
        return tuple(int(o) for o in host.ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def _summarize(scan: ScanResult) -> dict:
    sev_counts: Counter[str] = Counter()
    hosts_with_findings = 0
    total_open_ports = 0
    for h in scan.hosts:
        host_has_cve = False
        for p in h.ports:
            total_open_ports += 1
            for c in p.cves:
                sev_counts[c.severity] += 1
                host_has_cve = True
        if host_has_cve:
            hosts_with_findings += 1
    return {
        "sev_counts": sev_counts,
        "hosts_with_findings": hosts_with_findings,
        "total_open_ports": total_open_ports,
    }


def render_report(scan: ScanResult) -> str:
    """Return a self-contained HTML document as a string."""
    summary = _summarize(scan)
    sev_counts = summary["sev_counts"]

    # Stat cards
    pill_row = "".join(
        f'<div class="stat" style="border-color:{_SEVERITY_COLORS.get(s, "#444")}">'
        f'<div class="stat-num">{sev_counts.get(s, 0)}</div>'
        f'<div class="stat-label">{_esc(s)}</div></div>'
        for s in _SEVERITY_ORDER if sev_counts.get(s, 0) or s in ("CRITICAL", "HIGH", "MEDIUM")
    )

    # Host rows
    host_rows = []
    for h in sorted(scan.hosts, key=_ip_sort_key):
        if not h.ports:
            continue
        port_rows = []
        for p in sorted(h.ports, key=lambda x: x.number):
            cve_html = ""
            if p.cves:
                cve_items = "".join(
                    f'<li>{_sev_pill(c.severity, c.cvss)} '
                    f'<code>{_esc(c.id)}</code> '
                    f'<span class="cve-summary">{_esc((c.summary or "")[:200])}</span></li>'
                    for c in p.cves[:10]
                )
                more = (f'<li class="more">+{len(p.cves) - 10} more</li>'
                        if len(p.cves) > 10 else "")
                cve_html = f'<ul class="cves">{cve_items}{more}</ul>'
            else:
                cve_html = '<span class="dim">—</span>'

            # Exploits section — rendered below CVEs
            exploit_html = ""
            if p.exploits:
                exp_items: list[str] = []
                for ex in p.exploits[:10]:
                    label = f"EDB-{_esc(ex.edb_id)}" if ex.edb_id else "exploit"
                    link = (f'<a href="{_esc(ex.url)}" target="_blank">{label}</a>'
                            if ex.url else label)
                    meta = " · ".join(filter(None, [
                        _esc(ex.type) if ex.type else "",
                        _esc(ex.platform) if ex.platform else "",
                    ]))
                    exp_items.append(
                        f'<li class="exploit">💥 {link} '
                        f'<span class="exploit-title">{_esc(ex.title[:120])}</span>'
                        + (f' <span class="dim">({meta})</span>' if meta else '')
                        + '</li>'
                    )
                more_exp = (f'<li class="more">+{len(p.exploits) - 10} more</li>'
                            if len(p.exploits) > 10 else "")
                exploit_html = (f'<ul class="exploits">{"".join(exp_items)}'
                                f'{more_exp}</ul>')

            product_str = ""
            if p.product_name and p.product_version:
                product_str = (f' <span class="product">'
                               f'{_esc(p.product_name)} {_esc(p.product_version)}'
                               f'</span>')

            banner_str = (f'<div class="banner">{_esc(p.banner)}</div>'
                          if p.banner else "")

            port_rows.append(
                f'<tr>'
                f'<td class="port-num">{p.number}/{_esc(p.protocol)}</td>'
                f'<td>{_esc(p.service or "-")}{product_str}{banner_str}</td>'
                f'<td>{cve_html}{exploit_html}</td>'
                f'</tr>'
            )

        port_table = "".join(port_rows) or '<tr><td colspan="3" class="dim">no open ports</td></tr>'

        host_rows.append(
            f'<section class="host">'
            f'<header>'
            f'<h2>{_esc(h.ip)}</h2>'
            f'<div class="meta">'
            f'<span>{_esc(h.hostname or "(no hostname)")}</span>'
            f'<span>MAC: {_esc(h.mac or "-")}</span>'
            f'<span>Vendor: {_esc(h.vendor or "-")}</span>'
            f'</div>'
            f'</header>'
            f'<table class="ports">'
            f'<thead><tr><th>Port</th><th>Service / banner</th><th>Vulnerabilities</th></tr></thead>'
            f'<tbody>{port_table}</tbody>'
            f'</table>'
            f'</section>'
        )

    style = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", "Helvetica Neue", sans-serif;
       background:#0d1117; color:#e6edf3; margin:0; padding:24px; }
header.global { display:flex; justify-content:space-between; align-items:end;
       border-bottom:1px solid #30363d; padding-bottom:16px; margin-bottom:24px; }
header.global h1 { margin:0; font-size:28px; }
header.global .meta { color:#8b949e; font-size:13px; }
.stats { display:flex; gap:12px; margin:24px 0; flex-wrap:wrap; }
.stat { border:2px solid #30363d; border-radius:12px; padding:14px 22px;
        min-width:110px; text-align:center; background:#161b22; }
.stat-num { font-size:32px; font-weight:700; }
.stat-label { font-size:11px; letter-spacing:1px; color:#8b949e; }
section.host { background:#161b22; border:1px solid #30363d; border-radius:10px;
               margin-bottom:18px; overflow:hidden; }
section.host header { padding:14px 18px; border-bottom:1px solid #30363d;
                      background:#0d1117; }
section.host h2 { margin:0 0 4px 0; font-family:"SF Mono", Consolas, monospace; }
section.host .meta { display:flex; gap:18px; font-size:12px; color:#8b949e; flex-wrap:wrap; }
table.ports { width:100%; border-collapse:collapse; }
table.ports th, table.ports td { padding:8px 14px; vertical-align:top;
                                 border-bottom:1px solid #21262d; text-align:left;
                                 font-size:13px; }
table.ports th { background:#0d1117; color:#8b949e; font-weight:600;
                 text-transform:uppercase; font-size:11px; letter-spacing:1px; }
.port-num { font-family:"SF Mono", Consolas, monospace; color:#58a6ff; white-space:nowrap; }
.product { font-family:"SF Mono", Consolas, monospace; color:#d29922;
           font-size:12px; margin-left:6px; }
.banner { font-family:"SF Mono", Consolas, monospace; color:#7d8590; font-size:11px;
          margin-top:4px; word-break:break-all; }
ul.cves { list-style:none; padding:0; margin:0; }
ul.cves li { padding:3px 0; font-size:12px; }
ul.cves code { background:#0d1117; padding:1px 6px; border-radius:3px;
               color:#79c0ff; font-family:"SF Mono", Consolas, monospace; }
.cve-summary { color:#8b949e; font-size:11px; margin-left:6px; }
ul.exploits { list-style:none; padding:0; margin:8px 0 0 0;
              border-top:1px solid #21262d; padding-top:6px; }
ul.exploits li.exploit { padding:2px 0; font-size:12px; }
ul.exploits a { color:#d29922; text-decoration:none; font-weight:600;
                font-family:"SF Mono", Consolas, monospace; }
ul.exploits a:hover { text-decoration:underline; }
.exploit-title { color:#e6edf3; margin-left:6px; }
.more { color:#8b949e; font-style:italic; }
.pill { display:inline-block; padding:1px 8px; border-radius:10px; font-size:10px;
        font-weight:700; color:#000; min-width:64px; text-align:center; }
.dim { color:#6e7681; }
footer { color:#6e7681; font-size:11px; margin-top:32px; text-align:center; }
"""

    body = (
        f'<header class="global">'
        f'<div><h1>Explotica scan report</h1>'
        f'<div class="meta">target: <code>{_esc(scan.target)}</code> · '
        f'started: {_esc(scan.started_at)} · '
        f'duration: {scan.duration_s:.2f}s · '
        f'hosts: {len(scan.hosts)} · '
        f'open ports: {summary["total_open_ports"]} · '
        f'hosts w/ findings: {summary["hosts_with_findings"]}</div>'
        f'</div>'
        f'<div class="meta">explotica v{_esc(scan.scanner_version)}</div>'
        f'</header>'
        f'<div class="stats">{pill_row}</div>'
        + "\n".join(host_rows) +
        '<footer>generated by explotica · '
        'do what is right, scan what you own</footer>'
    )

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<title>Explotica · {_esc(scan.target)}</title>'
        f'<style>{style}</style></head><body>{body}</body></html>'
    )


def write_report(scan: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_report(scan), encoding="utf-8")
    return p
