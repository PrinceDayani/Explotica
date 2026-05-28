"""Live web dashboard — FastAPI + Cytoscape.js network graph.

Serves a single-page dashboard showing hosts as nodes, ports as labeled
sub-nodes, with severity-colored hosts and a clickable detail drawer.

Security note: scan data is treated as UNTRUSTED in the frontend. All
dynamic content is escaped before insertion. Targets we scan could
return malicious banners/hostnames; the dashboard must not be XSSable
by them.

Run:
  python -m explotica.dashboard scans/full.json
  # then open http://localhost:8765
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def fastapi_available() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


# ── HTML template (single page, inline CSS/JS, Cytoscape from CDN) ────────
# IMPORTANT: every dynamic value from scan data is passed through esc()
# in the JS to prevent XSS via malicious hostnames/banners/CVE descriptions.
DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data:;">
<title>Explotica Dashboard</title>
<script src="https://unpkg.com/cytoscape@3.28/dist/cytoscape.min.js"></script>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", "Helvetica Neue", sans-serif;
  background: #0d1117; color: #e6edf3; margin: 0; padding: 0;
  height: 100vh; display: grid;
  grid-template-rows: 60px 1fr; grid-template-columns: 1fr 360px;
  grid-template-areas: "header header" "graph sidebar";
}
header {
  grid-area: header;
  background: #161b22; border-bottom: 1px solid #30363d;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px;
}
header h1 { margin: 0; font-size: 18px; }
header .meta { font-size: 12px; color: #8b949e; font-family: "SF Mono", Consolas, monospace; }
#graph { grid-area: graph; background: #0d1117; }
aside {
  grid-area: sidebar;
  background: #161b22; border-left: 1px solid #30363d;
  overflow-y: auto; padding: 16px;
}
.stat-row {
  display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px;
  margin-bottom: 16px;
}
.stat {
  background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
  padding: 8px 12px; text-align: center;
}
.stat-num { font-size: 22px; font-weight: 700; }
.stat-label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
.crit { color: #ff3b30; } .high { color: #ff9500; }
.med  { color: #ffcc00; } .low  { color: #34c759; }
.kev  { color: #ff3b30; font-weight: 700; }
.detail { margin-top: 12px; }
.detail h3 { font-size: 13px; margin: 8px 0 4px; color: #58a6ff; font-family: "SF Mono", Consolas, monospace; }
.detail .row { font-size: 12px; padding: 4px 0; border-bottom: 1px solid #21262d; word-break: break-all; }
.pill {
  display: inline-block; padding: 1px 6px; border-radius: 8px;
  font-size: 9px; font-weight: 700; color: #000;
}
.pill.critical { background: #ff3b30; }
.pill.high { background: #ff9500; }
.pill.medium { background: #ffcc00; }
.pill.low { background: #34c759; }
.cve-list { max-height: 200px; overflow-y: auto; }
.cve { font-size: 11px; padding: 3px 0; }
.cve code { background: #0d1117; padding: 1px 5px; border-radius: 3px; color: #79c0ff; }
.search { width: 100%; padding: 6px 10px; background: #0d1117; color: #e6edf3;
          border: 1px solid #30363d; border-radius: 6px; margin-bottom: 12px; }
.legend { font-size: 10px; color: #8b949e; padding: 6px 0; }
.legend .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
.banner { font-family: monospace; color: #7d8590; font-size: 10px; }
</style>
</head>
<body>
<header>
  <h1>🛰️ Explotica Dashboard</h1>
  <div class="meta" id="header-meta">loading…</div>
</header>
<div id="graph"></div>
<aside>
  <input class="search" placeholder="Filter host or CVE…" id="search">
  <div class="stat-row" id="stats"></div>
  <div class="legend">
    <span class="dot" style="background:#ff3b30"></span> Critical &nbsp;
    <span class="dot" style="background:#ff9500"></span> High &nbsp;
    <span class="dot" style="background:#ffcc00"></span> Medium &nbsp;
    <span class="dot" style="background:#34c759"></span> Low &nbsp;
    <span class="dot" style="background:#8b949e"></span> No CVEs
  </div>
  <div id="detail" class="detail"><em>Click a host to see details</em></div>
</aside>
<script>
// XSS protection: ALL scan data is treated as untrusted.
// Use esc() before inserting into innerHTML, or use el/text helpers.
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c]));
}
// Safe URL — only allow http/https; block javascript: data: etc.
function safeUrl(u) {
  if (!u) return '';
  try {
    const url = new URL(u);
    if (url.protocol === 'http:' || url.protocol === 'https:') return u;
  } catch(e) {}
  return '';
}
// Helper to build elements safely
function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'className') e.className = v;
    else if (k === 'href') { const u = safeUrl(v); if (u) e.href = u; }
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return e;
}

async function load() {
  const r = await fetch('/api/scan');
  if (!r.ok) {
    document.getElementById('detail').textContent = 'No scan loaded';
    return null;
  }
  return await r.json();
}

function severityOfHost(h) {
  let worst = 'none';
  const order = {critical:4, high:3, medium:2, low:1, none:0};
  for (const p of h.ports || []) {
    for (const c of p.cves || []) {
      const s = (c.severity || 'none').toLowerCase();
      if ((order[s]||0) > (order[worst]||0)) worst = s;
    }
  }
  return worst;
}

function color(sev) {
  return ({critical:'#ff3b30', high:'#ff9500', medium:'#ffcc00', low:'#34c759'}[sev]) || '#8b949e';
}

function renderStats(scan) {
  const counts = {critical:0, high:0, medium:0, low:0, kev:0};
  let openPorts = 0, exploits = 0;
  for (const h of scan.hosts || []) {
    for (const p of h.ports || []) {
      openPorts++;
      exploits += (p.exploits || []).length;
      for (const c of p.cves || []) {
        const s = (c.severity || '').toLowerCase();
        if (counts[s] !== undefined) counts[s]++;
        if (c.in_kev) counts.kev++;
      }
    }
  }
  const stats = [
    [scan.hosts.length, 'Hosts', ''],
    [openPorts, 'Open Ports', ''],
    [counts.critical, 'Critical', 'crit'],
    [counts.high, 'High', 'high'],
    [counts.medium, 'Medium', 'med'],
    [counts.kev, 'KEV', 'kev'],
    [exploits, 'Exploits', ''],
    [scan.duration_s != null ? scan.duration_s.toFixed(1) + 's' : '?', 'Duration', ''],
  ];
  const el2 = document.getElementById('stats');
  el2.replaceChildren();
  for (const [n, label, cls] of stats) {
    el2.appendChild(el('div', {className: 'stat'},
      el('div', {className: 'stat-num' + (cls ? ' ' + cls : '')}, String(n)),
      el('div', {className: 'stat-label'}, label)
    ));
  }
  document.getElementById('header-meta').textContent =
    `target: ${scan.target || '?'} · started ${scan.started_at || '?'} · ${scan.scanner_version || '?'}`;
}

function showHost(h) {
  const detail = document.getElementById('detail');
  detail.replaceChildren();
  detail.appendChild(el('h3', {}, h.ip || ''));
  if (h.hostname)
    detail.appendChild(el('div', {className: 'row'}, 'hostname: ', el('code', {}, h.hostname)));
  if (h.mac)
    detail.appendChild(el('div', {className: 'row'}, 'MAC: ', el('code', {}, h.mac)));
  if (h.vendor)
    detail.appendChild(el('div', {className: 'row'}, 'vendor: ' + h.vendor));
  if (h.os_hint)
    detail.appendChild(el('div', {className: 'row'},
      `OS: ${h.os_hint.os_family || '?'} (${h.os_hint.hops_estimate || '?'}h, TTL=${h.ttl || '?'})`));

  // Shodan
  if (h.udp_services && h.udp_services.shodan) {
    const sh = h.udp_services.shodan;
    detail.appendChild(el('div', {className: 'row'},
      `Shodan: ${(sh.ports||[]).length} ports, ${(sh.vulns||[]).length} CVEs, tags: ${(sh.tags||[]).join(', ')}`));
  }

  // Ports
  for (const p of h.ports || []) {
    const h3 = el('h3', {}, `port ${p.number}/${p.protocol || 'tcp'}`);
    if (p.service) {
      h3.appendChild(document.createTextNode(' '));
      h3.appendChild(el('span', {className: 'pill', style: 'background:#58a6ff;color:#000'},
                        p.service));
    }
    if (p.product_name && p.product_version) {
      h3.appendChild(document.createTextNode(' '));
      h3.appendChild(el('code', {}, `${p.product_name} ${p.product_version}`));
    }
    detail.appendChild(h3);
    if (p.banner) {
      detail.appendChild(el('div', {className: 'row banner'},
        String(p.banner).substring(0, 180)));
    }
    // CVEs (sorted KEV first, then EPSS, then CVSS)
    if (p.cves && p.cves.length) {
      const list = el('div', {className: 'cve-list'});
      const sorted = [...p.cves].sort((a,b) =>
        (b.in_kev?1:0) - (a.in_kev?1:0)
        || (b.epss_score||0) - (a.epss_score||0)
        || (b.cvss||0) - (a.cvss||0)
      );
      for (const c of sorted.slice(0, 15)) {
        const sev = String(c.severity || 'unknown').toLowerCase();
        const row = el('div', {className: 'cve'});
        row.appendChild(el('span', {className: 'pill ' + sev},
          `${sev.toUpperCase()} ${c.cvss != null ? c.cvss.toFixed(1) : '?'}`));
        row.appendChild(document.createTextNode(' '));
        row.appendChild(el('code', {}, c.id || ''));
        if (c.in_kev) {
          row.appendChild(document.createTextNode(' '));
          row.appendChild(el('span', {className: 'kev'}, 'KEV'));
        }
        if (c.epss_score) {
          row.appendChild(document.createTextNode(' '));
          row.appendChild(el('small', {}, `EPSS=${c.epss_score.toFixed(2)}`));
        }
        list.appendChild(row);
      }
      detail.appendChild(list);
    }
    // Exploits
    if (p.exploits && p.exploits.length) {
      const row = el('div', {className: 'row'}, '💥 ' + p.exploits.length + ' exploit(s): ');
      for (const ex of p.exploits.slice(0, 5)) {
        const label = 'EDB-' + (ex.edb_id || '?');
        if (ex.url) {
          row.appendChild(el('a', {href: ex.url, target: '_blank',
                                    style: 'color:#d29922'}, label));
        } else {
          row.appendChild(el('span', {}, label));
        }
        row.appendChild(document.createTextNode(' '));
      }
      detail.appendChild(row);
    }
  }
}

function buildGraph(scan) {
  const nodes = [];
  const edges = [];
  for (const h of scan.hosts || []) {
    const sev = severityOfHost(h);
    nodes.push({
      data: { id: h.ip, severity: sev, host: h, ports: (h.ports||[]).length },
      classes: 'host'
    });
    for (const p of h.ports || []) {
      const portId = h.ip + ':' + p.number;
      nodes.push({
        data: { id: portId,
                label: String(p.number) + (p.service ? '/' + p.service : ''),
                kind: 'port', cves: (p.cves||[]).length },
        classes: 'port'
      });
      edges.push({ data: { source: h.ip, target: portId } });
    }
  }
  return { nodes, edges };
}

(async () => {
  const scan = await load();
  if (!scan) return;
  renderStats(scan);
  const { nodes, edges } = buildGraph(scan);
  const cy = cytoscape({
    container: document.getElementById('graph'),
    elements: { nodes, edges },
    style: [
      { selector: 'node.host', style: {
          'background-color': ele => color(ele.data('severity')),
          'label': ele => ele.data('host').ip,
          'text-valign': 'bottom', 'text-margin-y': 6,
          'color': '#e6edf3', 'font-size': 11,
          'width': ele => 18 + Math.sqrt(ele.data('ports') || 1) * 4,
          'height': ele => 18 + Math.sqrt(ele.data('ports') || 1) * 4,
          'border-width': 2, 'border-color': '#0d1117',
      }},
      { selector: 'node.port', style: {
          'background-color': '#30363d',
          'shape': 'rectangle', 'width': 28, 'height': 16,
          'label': 'data(label)', 'font-size': 8,
          'color': '#e6edf3', 'text-valign': 'center',
      }},
      { selector: 'edge', style: {
          'line-color': '#30363d', 'width': 1, 'opacity': 0.4,
          'curve-style': 'bezier',
      }},
      { selector: 'node:selected', style: { 'border-color': '#58a6ff', 'border-width': 4 }},
    ],
    layout: { name: 'cose', animate: false, idealEdgeLength: 80, nodeRepulsion: 5000 },
  });
  cy.on('tap', 'node.host', evt => showHost(evt.target.data('host')));
  cy.fit();

  document.getElementById('search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    if (!q) {
      cy.elements().style('opacity', 1);
      return;
    }
    cy.nodes('.host').forEach(n => {
      const h = n.data('host');
      const matchIP = String(h.ip||'').toLowerCase().includes(q);
      const matchName = String(h.hostname||'').toLowerCase().includes(q);
      const matchCVE = (h.ports||[]).some(p =>
        (p.cves||[]).some(c => String(c.id||'').toLowerCase().includes(q))
      );
      const show = matchIP || matchName || matchCVE;
      n.style('opacity', show ? 1 : 0.15);
      n.connectedEdges().style('opacity', show ? 0.6 : 0.05);
      n.connectedEdges().targets().style('opacity', show ? 1 : 0.15);
    });
  });
})();
</script>
</body>
</html>
"""


def serve(json_path: str, *, host: str = "127.0.0.1",
          port: int = 8765) -> None:
    """Launch the dashboard server."""
    if not fastapi_available():
        print("[!] fastapi + uvicorn required for dashboard.")
        print("    Install: pip install fastapi uvicorn[standard]")
        sys.exit(1)

    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn

    app = FastAPI(title="Explotica Dashboard", version="0.1.0")
    json_path_p = Path(json_path)

    @app.get("/", response_class=HTMLResponse)
    def root():
        return DASHBOARD_HTML

    @app.get("/api/scan")
    def get_scan():
        if not json_path_p.exists():
            raise HTTPException(404, f"Scan file not found: {json_path}")
        try:
            data = json.loads(json_path_p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise HTTPException(500, f"Failed to load scan: {e}")
        return JSONResponse(data)

    @app.get("/api/health")
    def health():
        return {"ok": True, "scan_file": str(json_path_p),
                "exists": json_path_p.exists()}

    print(f"[*] Serving Explotica dashboard at http://{host}:{port}")
    print(f"[*] Loading scan from: {json_path}")
    print(f"[*] Press Ctrl+C to stop")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="explotica-dashboard",
        description="Live web dashboard for Explotica scan results.",
    )
    p.add_argument("scan_json", help="Path to a scan JSON file (from --json)")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind interface (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8765,
                   help="Listen port (default 8765)")
    args = p.parse_args(argv)
    serve(args.scan_json, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
