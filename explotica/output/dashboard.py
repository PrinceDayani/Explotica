"""Live web dashboard — FastAPI + Cytoscape.js network graph + scan launcher.

Serves a single-page dashboard showing hosts as nodes, ports as labeled
sub-nodes, with severity-colored hosts and a clickable detail drawer.

It is also a *control panel*: from the browser you can pick a target and a
scan profile and launch a scan. Scans run as `python -m explotica` subprocesses
managed by an in-process job manager; when a job finishes the graph reloads
from its JSON automatically.

Security model:
  - Scan data is treated as UNTRUSTED in the frontend. All dynamic content is
    escaped before insertion (malicious banners/hostnames must not be XSSable).
  - The launcher does NOT accept raw CLI flags from the browser. The frontend
    sends only {target, profile, aggressive}; argv is built server-side from a
    fixed PROFILES allowlist, and the target is validated against a strict
    regex (no leading dash, no whitespace/shell metacharacters). Subprocesses
    are spawned with a list argv (no shell), so there is no shell injection.
  - Binds 127.0.0.1 by default. Because the control panel can launch active
    scans, binding to a non-loopback address is gated behind --allow-remote.

Run:
  python -m explotica.output.dashboard               # empty, launch from UI
  python -m explotica.output.dashboard scans/full.json
  # then open http://localhost:8765
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


def fastapi_available() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


# ── Scan launcher: profiles + job manager ────────────────────────────────
# IMPORTANT: the browser may ONLY pick a profile name from this dict. It can
# never inject arbitrary flags. Profiles intentionally stop at --full-coverage
# and never enable the opt-in destructive checks (--all-the-things, default
# creds, takeover, smtp audit) — those stay CLI-only.
PROFILES: dict[str, dict[str, Any]] = {
    "discovery": {
        "label": "Discovery",
        "desc": "Host discovery + top 100 ports, no active probes.",
        "flags": ["-p", "top100", "--no-banners"],
    },
    "quick": {
        "label": "Quick",
        "desc": "Top 100 ports + banner grab + CVE match.",
        "flags": ["-p", "top100", "--vuln-scan"],
    },
    "standard": {
        "label": "Standard",
        "desc": "Top 1000 ports + deep version probes + CVE match.",
        "flags": ["-p", "top1000", "--vuln-scan", "--deep"],
    },
    "web": {
        "label": "Web",
        "desc": "Top 1000 ports + web crawl + HTTP audit + CVE match.",
        "flags": ["-p", "top1000", "--vuln-scan", "--web-crawl", "--http-audit"],
    },
    "full": {
        "label": "Full coverage",
        "desc": "Everything in --full-coverage (vuln, deep, nmap, searchsploit, aggressive).",
        "flags": ["--full-coverage"],
    },
}

# Target must start alphanumeric (blocks argparse flag injection via leading
# '-') and contain only host/CIDR-safe characters. Covers IPv4, IPv4/CIDR,
# IPv6, and hostnames.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-/]{0,253}$")

# Cap concurrent browser-launched scans so the box can't be DoS'd from the UI.
_MAX_ACTIVE_JOBS = 4
# Hard ceiling on subprocess wall-clock (seconds).
_JOB_TIMEOUT = 3600


def validate_target(target: str) -> Optional[str]:
    """Return an error string if the target is unsafe/invalid, else None."""
    if not target:
        return "target is required"
    if len(target) > 253:
        return "target too long"
    if not _TARGET_RE.match(target):
        return ("invalid target — use an IP, CIDR, or hostname "
                "(no leading dash, spaces, or shell characters)")
    return None


class ScanJobManager:
    """Runs `python -m explotica` scans as tracked background subprocesses.

    Thread-based (one daemon thread per job). Thread-safe via a single lock.
    On successful completion the produced JSON path is published via
    ``on_complete`` so the server can swap it in as the live scan.
    """

    def __init__(self, out_dir: Path, on_complete=None) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seq = 0
        self._out_dir = out_dir
        self._out_dir.mkdir(parents=True, exist_ok=True)
        self._on_complete = on_complete

    def _public(self, job: dict[str, Any]) -> dict[str, Any]:
        """A browser-safe view of a job (no absolute filesystem paths)."""
        return {
            "id": job["id"],
            "target": job["target"],
            "profile": job["profile"],
            "aggressive": job["aggressive"],
            "state": job["state"],
            "returncode": job["returncode"],
            "started_at": job["started_at"],
            "ended_at": job["ended_at"],
            "error": job["error"],
            "tail": job["tail"],
            "has_result": bool(job["out"]) and Path(job["out"]).exists(),
        }

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values()
                       if j["state"] in ("queued", "running"))

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(),
                          key=lambda j: j["seq"], reverse=True)
            return [self._public(j) for j in jobs]

    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return self._public(job) if job else None

    def start(self, target: str, profile: str, aggressive: bool) -> dict[str, Any]:
        err = validate_target(target)
        if err:
            raise ValueError(err)
        if profile not in PROFILES:
            raise ValueError(f"unknown profile '{profile}'")
        if self.active_count() >= _MAX_ACTIVE_JOBS:
            raise RuntimeError(
                f"too many scans running (max {_MAX_ACTIVE_JOBS}); wait for one to finish")

        with self._lock:
            self._seq += 1
            seq = self._seq
            job_id = f"job-{seq}"
            out_path = self._out_dir / f"{job_id}.json"
            job = {
                "id": job_id, "seq": seq, "target": target, "profile": profile,
                "aggressive": aggressive, "state": "queued", "returncode": None,
                "started_at": time.time(), "ended_at": None,
                "error": None, "tail": "", "out": str(out_path),
            }
            self._jobs[job_id] = job

        t = threading.Thread(target=self._run, args=(job_id,), daemon=True)
        t.start()
        return self._public(job)

    def _build_cmd(self, job: dict[str, Any]) -> list[str]:
        flags = list(PROFILES[job["profile"]]["flags"])
        if job["aggressive"] and "--full-coverage" not in flags \
                and "--aggressive" not in flags:
            flags.append("--aggressive")
        # --yes: no TTY to confirm the active-scan authorization prompt.
        # --strict-scope is the CLI default (we never pass --no-strict-scope).
        return ([sys.executable, "-m", "explotica", job["target"], *flags,
                 "--json", job["out"], "--yes", "--log-level", "WARNING"])

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job["state"] = "running"
            cmd = self._build_cmd(job)
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=_JOB_TIMEOUT,
                                  check=False)
            out = (proc.stdout or b"").decode("utf-8", "replace")
            errtxt = (proc.stderr or b"").decode("utf-8", "replace")
            tail = (out + ("\n" + errtxt if errtxt else ""))[-4000:]
            ok = proc.returncode == 0 and Path(job["out"]).exists()
            with self._lock:
                job["returncode"] = proc.returncode
                job["tail"] = tail
                job["ended_at"] = time.time()
                if ok:
                    job["state"] = "done"
                else:
                    job["state"] = "failed"
                    job["error"] = (errtxt.strip().splitlines() or
                                    ["scan failed (no output)"])[-1][:300]
            if ok and self._on_complete:
                self._on_complete(Path(job["out"]))
        except subprocess.TimeoutExpired:
            with self._lock:
                job["state"] = "failed"
                job["ended_at"] = time.time()
                job["error"] = f"scan exceeded {_JOB_TIMEOUT}s timeout"
        except Exception as e:  # pragma: no cover - defensive
            log.exception("scan job %s crashed", job_id)
            with self._lock:
                job["state"] = "failed"
                job["ended_at"] = time.time()
                job["error"] = str(e)[:300]


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
header .hgroup { display: flex; align-items: center; gap: 16px; }
.btn {
  background: #238636; color: #fff; border: 1px solid #2ea043;
  border-radius: 6px; padding: 7px 14px; font-size: 13px; font-weight: 600;
  cursor: pointer;
}
.btn:hover { background: #2ea043; }
.btn.secondary { background: #21262d; border-color: #30363d; color: #e6edf3; }
.btn.secondary:hover { background: #30363d; }
.btn:disabled { opacity: .5; cursor: not-allowed; }
#graph { grid-area: graph; background: #0d1117; position: relative; }
#empty {
  position: absolute; inset: 0; display: none;
  align-items: center; justify-content: center; flex-direction: column;
  color: #8b949e; gap: 14px; text-align: center;
}
#empty.show { display: flex; }
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
/* Jobs panel in sidebar */
#jobs { margin-bottom: 14px; }
#jobs:empty { display: none; }
.job {
  background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
  padding: 8px 10px; margin-bottom: 6px; font-size: 11px;
}
.job .jhead { display: flex; justify-content: space-between; align-items: center; }
.job code { color: #79c0ff; }
.job .jstate { font-size: 9px; font-weight: 700; padding: 1px 6px; border-radius: 8px; }
.jstate.running { background: #1f6feb; color: #fff; }
.jstate.queued  { background: #6e7681; color: #fff; }
.jstate.done    { background: #238636; color: #fff; }
.jstate.failed  { background: #da3633; color: #fff; }
.job .jerr { color: #ff7b72; margin-top: 4px; font-family: monospace; font-size: 10px; word-break: break-all; }
/* Modal launcher */
.modal-bg {
  position: fixed; inset: 0; background: rgba(1,4,9,.7);
  display: none; align-items: center; justify-content: center; z-index: 50;
}
.modal-bg.show { display: flex; }
.modal {
  background: #161b22; border: 1px solid #30363d; border-radius: 12px;
  width: 460px; max-width: 92vw; padding: 22px;
}
.modal h2 { margin: 0 0 4px; font-size: 17px; }
.modal p.sub { margin: 0 0 16px; color: #8b949e; font-size: 12px; }
.field { margin-bottom: 14px; }
.field label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 5px; }
.field input[type=text] {
  width: 100%; padding: 9px 11px; background: #0d1117; color: #e6edf3;
  border: 1px solid #30363d; border-radius: 6px; font-size: 14px;
}
.profiles { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.profile {
  border: 1px solid #30363d; border-radius: 8px; padding: 9px 11px;
  cursor: pointer; background: #0d1117;
}
.profile.sel { border-color: #58a6ff; background: #15233b; }
.profile .pname { font-weight: 700; font-size: 13px; }
.profile .pdesc { font-size: 10px; color: #8b949e; margin-top: 3px; }
.modal .checkrow { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #c9d1d9; margin-bottom: 16px; }
.modal .actions { display: flex; justify-content: flex-end; gap: 10px; }
.modal .err { color: #ff7b72; font-size: 12px; min-height: 16px; margin-bottom: 8px; }
</style>
</head>
<body>
<header>
  <h1>🛰️ Explotica Dashboard</h1>
  <div class="hgroup">
    <div class="meta" id="header-meta">loading…</div>
    <button class="btn" id="new-scan">＋ New scan</button>
  </div>
</header>
<div id="graph">
  <div id="empty">
    <div style="font-size:42px">🛰️</div>
    <div>No scan loaded yet.</div>
    <button class="btn" id="empty-launch">Launch a scan</button>
  </div>
</div>
<aside>
  <div id="jobs"></div>
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

<!-- Launch modal -->
<div class="modal-bg" id="modal-bg">
  <div class="modal">
    <h2>Launch a scan</h2>
    <p class="sub">Runs <code>explotica</code> against the target with the chosen profile.</p>
    <div class="err" id="modal-err"></div>
    <div class="field">
      <label for="target">Target (IP, CIDR, or hostname)</label>
      <input type="text" id="target" placeholder="192.168.1.0/24" autocomplete="off">
    </div>
    <div class="field">
      <label>Profile</label>
      <div class="profiles" id="profiles"></div>
    </div>
    <label class="checkrow"><input type="checkbox" id="aggressive"> Aggressive (more workers, lower timeouts)</label>
    <div class="actions">
      <button class="btn secondary" id="cancel-scan">Cancel</button>
      <button class="btn" id="launch-scan">Launch</button>
    </div>
  </div>
</div>

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

let CY = null;          // current cytoscape instance
let PROFILES = {};      // {key: {label, desc}}
let SEL_PROFILE = 'quick';

async function load() {
  const r = await fetch('/api/scan');
  if (!r.ok) return null;
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

function renderGraph(scan) {
  const { nodes, edges } = buildGraph(scan);
  if (CY) { CY.destroy(); CY = null; }
  CY = cytoscape({
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
  CY.on('tap', 'node.host', evt => showHost(evt.target.data('host')));
  CY.fit();
}

function wireSearch() {
  document.getElementById('search').addEventListener('input', e => {
    if (!CY) return;
    const q = e.target.value.toLowerCase();
    if (!q) { CY.elements().style('opacity', 1); return; }
    CY.nodes('.host').forEach(n => {
      const h = n.data('host');
      const matchIP = String(h.ip||'').toLowerCase().includes(q);
      const matchName = String(h.hostname||'').toLowerCase().includes(q);
      const matchCVE = (h.ports||[]).some(p =>
        (p.cves||[]).some(c => String(c.id||'').toLowerCase().includes(q)));
      const show = matchIP || matchName || matchCVE;
      n.style('opacity', show ? 1 : 0.15);
      n.connectedEdges().style('opacity', show ? 0.6 : 0.05);
      n.connectedEdges().targets().style('opacity', show ? 1 : 0.15);
    });
  });
}

async function reload() {
  const scan = await load();
  const empty = document.getElementById('empty');
  if (!scan || !(scan.hosts || []).length) {
    empty.classList.add('show');
    document.getElementById('header-meta').textContent = 'no scan loaded';
    return;
  }
  empty.classList.remove('show');
  renderStats(scan);
  renderGraph(scan);
}

// ── Launch modal + job polling ──────────────────────────────────────────
function openModal() {
  document.getElementById('modal-err').textContent = '';
  document.getElementById('modal-bg').classList.add('show');
  document.getElementById('target').focus();
}
function closeModal() {
  document.getElementById('modal-bg').classList.remove('show');
}

function renderProfiles() {
  const box = document.getElementById('profiles');
  box.replaceChildren();
  for (const [key, meta] of Object.entries(PROFILES)) {
    const card = el('div', {className: 'profile' + (key === SEL_PROFILE ? ' sel' : ''),
                            onclick: () => { SEL_PROFILE = key; renderProfiles(); }},
      el('div', {className: 'pname'}, meta.label || key),
      el('div', {className: 'pdesc'}, meta.desc || ''));
    box.appendChild(card);
  }
}

async function launch() {
  const target = document.getElementById('target').value.trim();
  const aggressive = document.getElementById('aggressive').checked;
  const errBox = document.getElementById('modal-err');
  errBox.textContent = '';
  const btn = document.getElementById('launch-scan');
  btn.disabled = true;
  try {
    const r = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target, profile: SEL_PROFILE, aggressive}),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { errBox.textContent = data.detail || ('error ' + r.status); return; }
    closeModal();
    pollJobs();
  } catch (e) {
    errBox.textContent = String(e);
  } finally {
    btn.disabled = false;
  }
}

function fmtElapsed(j) {
  const end = j.ended_at || (Date.now() / 1000);
  const s = Math.max(0, Math.round(end - j.started_at));
  return s + 's';
}

let JOBS_TIMER = null;
let LAST_DONE = new Set();

async function pollJobs() {
  let jobs = [];
  try { jobs = await (await fetch('/api/jobs')).json(); } catch (e) { return; }
  const box = document.getElementById('jobs');
  box.replaceChildren();
  let anyActive = false;
  let newlyDone = false;
  for (const j of jobs) {
    if (j.state === 'running' || j.state === 'queued') anyActive = true;
    if (j.state === 'done' && !LAST_DONE.has(j.id)) { LAST_DONE.add(j.id); newlyDone = true; }
    const card = el('div', {className: 'job'},
      el('div', {className: 'jhead'},
        el('code', {}, j.target),
        el('span', {className: 'jstate ' + j.state}, j.state)),
      el('div', {style: 'color:#8b949e;margin-top:3px'},
        `${(PROFILES[j.profile] && PROFILES[j.profile].label) || j.profile} · ${fmtElapsed(j)}`));
    if (j.error) card.appendChild(el('div', {className: 'jerr'}, j.error));
    box.appendChild(card);
  }
  if (newlyDone) reload();
  // Keep polling while anything is active; otherwise stop.
  if (anyActive) {
    if (!JOBS_TIMER) JOBS_TIMER = setInterval(pollJobs, 2000);
  } else if (JOBS_TIMER) {
    clearInterval(JOBS_TIMER); JOBS_TIMER = null;
  }
}

(async () => {
  // Pull profile metadata for the modal.
  try { PROFILES = await (await fetch('/api/profiles')).json(); }
  catch (e) { PROFILES = {quick: {label: 'Quick', desc: ''}}; }
  if (!PROFILES[SEL_PROFILE]) SEL_PROFILE = Object.keys(PROFILES)[0];
  renderProfiles();
  wireSearch();
  document.getElementById('new-scan').addEventListener('click', openModal);
  document.getElementById('empty-launch').addEventListener('click', openModal);
  document.getElementById('cancel-scan').addEventListener('click', closeModal);
  document.getElementById('launch-scan').addEventListener('click', launch);
  document.getElementById('target').addEventListener('keydown',
    e => { if (e.key === 'Enter') launch(); });
  await reload();
  await pollJobs();
})();
</script>
</body>
</html>
"""


# ── server ───────────────────────────────────────────────────────────────
def serve(json_path: Optional[str] = None, *, host: str = "127.0.0.1",
          port: int = 8765, allow_launch: bool = True) -> None:
    """Launch the dashboard server.

    json_path: optional initial scan to display. If None, the dashboard
               starts empty and you launch scans from the UI.
    allow_launch: if False, the scan-launch endpoints are disabled (viewer
                  only).
    """
    if not fastapi_available():
        print("[!] fastapi + uvicorn required for dashboard.")
        print("    Install: pip install fastapi uvicorn[standard]")
        sys.exit(1)

    from fastapi import FastAPI, HTTPException, Body
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn

    app = FastAPI(title="Explotica Dashboard", version="0.2.0")

    # Mutable holder for the "current" scan path the graph view reads.
    state: dict[str, Optional[Path]] = {
        "scan_path": Path(json_path) if json_path else None
    }

    out_dir = Path(tempfile.gettempdir()) / "explotica_dashboard"
    mgr = ScanJobManager(
        out_dir,
        on_complete=(lambda p: state.__setitem__("scan_path", p))
                    if allow_launch else None,
    )

    @app.get("/", response_class=HTMLResponse)
    def root():
        return DASHBOARD_HTML

    @app.get("/api/scan")
    def get_scan():
        p = state["scan_path"]
        if not p or not p.exists():
            raise HTTPException(404, "No scan loaded yet")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise HTTPException(500, f"Failed to load scan: {e}")
        return JSONResponse(data)

    @app.get("/api/profiles")
    def get_profiles():
        return {k: {"label": v["label"], "desc": v["desc"]}
                for k, v in PROFILES.items()}

    @app.get("/api/jobs")
    def get_jobs():
        return mgr.list_jobs()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str):
        job = mgr.get(job_id)
        if not job:
            raise HTTPException(404, "Unknown job")
        return job

    if allow_launch:
        @app.post("/api/scan")
        def start_scan(req: dict = Body(...)):
            target = str(req.get("target") or "").strip()
            profile = str(req.get("profile") or "quick").strip()
            aggressive = bool(req.get("aggressive"))
            try:
                job = mgr.start(target, profile, aggressive)
            except ValueError as e:
                raise HTTPException(400, str(e))
            except RuntimeError as e:
                raise HTTPException(429, str(e))
            return {"job_id": job["id"], "job": job}
    else:
        @app.post("/api/scan")
        def start_scan_disabled():
            raise HTTPException(403, "Scan launching is disabled (viewer mode)")

    @app.get("/api/health")
    def health():
        p = state["scan_path"]
        return {"ok": True, "scan_file": str(p) if p else None,
                "exists": bool(p and p.exists()),
                "launch_enabled": allow_launch,
                "active_jobs": mgr.active_count()}

    print(f"[*] Serving Explotica dashboard at http://{host}:{port}")
    if json_path:
        print(f"[*] Loading scan from: {json_path}")
    if allow_launch:
        print(f"[*] Scan launching ENABLED — open the page and click '＋ New scan'")
    if host not in ("127.0.0.1", "localhost", "::1") and allow_launch:
        print("[!] WARNING: bound to a non-loopback address with scan launching")
        print("[!]          enabled. Anyone who can reach this port can start")
        print("[!]          active scans. Use --no-launch for a read-only viewer.")
    print(f"[*] Press Ctrl+C to stop")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="explotica-dashboard",
        description="Live web dashboard + scan launcher for Explotica.",
    )
    p.add_argument("scan_json", nargs="?", default=None,
                   help="Optional scan JSON to display on start (from --json). "
                        "Omit to start empty and launch scans from the UI.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind interface (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8765,
                   help="Listen port (default 8765)")
    p.add_argument("--allow-remote", action="store_true",
                   help="Permit binding to a non-loopback --host (required "
                        "to expose the dashboard off-box; understand the risk).")
    p.add_argument("--no-launch", action="store_true",
                   help="Read-only viewer: disable the scan-launch endpoints.")
    args = p.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        print(f"[!] Refusing to bind to non-loopback host '{args.host}' without "
              f"--allow-remote.")
        print("[!] The dashboard can launch active scans; exposing it off-box is")
        print("[!] dangerous. Re-run with --allow-remote (and ideally --no-launch).")
        return 2

    serve(args.scan_json, host=args.host, port=args.port,
          allow_launch=not args.no_launch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
