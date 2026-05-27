"""Continuous monitoring daemon — scheduled scans + diff alerts.

Architecture:
  - SQLite DB at ~/.cache/explotica/monitor.db
  - Schema: scans (id, target, started_at, json_path), findings (per-scan)
  - On each tick: run the scan, store result, diff against previous scan
                  for the same target, emit alerts for new findings

Alerts via:
  - Slack incoming webhook
  - Generic webhook (POST JSON)
  - Console (always)

Run:
  python -m explotica.daemon \
    --target 192.168.1.0/24 \
    --interval 3600 \
    --scan-args "--ports top1000 --vuln-scan --deep --epss-kev --use-nmap"
    --slack-webhook https://hooks.slack.com/...
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_DB = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica")
) / "monitor.db"


# ── SQLite schema ─────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_s REAL,
  json_path TEXT,
  host_count INTEGER,
  open_port_count INTEGER,
  cve_count INTEGER,
  kev_count INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id),
  host_ip TEXT,
  port INTEGER,
  service TEXT,
  product TEXT,
  cve_id TEXT,
  severity TEXT,
  cvss REAL,
  epss REAL,
  in_kev BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_ip);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
"""


def _conn(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(db_path))
    c.executescript(SCHEMA)
    c.row_factory = sqlite3.Row
    return c


def _persist_scan(db: sqlite3.Connection, scan: dict, json_path: str) -> int:
    """Insert a scan + its findings; return scan_id."""
    hosts = scan.get("hosts", [])
    open_ports = sum(len(h.get("ports", [])) for h in hosts)
    cves = []
    for h in hosts:
        for p in h.get("ports", []):
            for c in p.get("cves", []):
                cves.append((h["ip"], p["number"], p.get("service"),
                              p.get("product_name"), c.get("id"),
                              c.get("severity"), c.get("cvss"),
                              c.get("epss_score"), c.get("in_kev", False)))
    kev_count = sum(1 for c in cves if c[8])

    cur = db.execute(
        "INSERT INTO scans (target, started_at, finished_at, duration_s, "
        "json_path, host_count, open_port_count, cve_count, kev_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan.get("target"), scan.get("started_at"),
         scan.get("finished_at"), scan.get("duration_s"),
         json_path, len(hosts), open_ports, len(cves), kev_count)
    )
    scan_id = cur.lastrowid

    for f in cves:
        db.execute(
            "INSERT INTO findings (scan_id, host_ip, port, service, product, "
            "cve_id, severity, cvss, epss, in_kev) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, *f)
        )
    # Also record open-port findings without CVEs for diff tracking
    for h in hosts:
        for p in h.get("ports", []):
            if not p.get("cves"):
                db.execute(
                    "INSERT INTO findings (scan_id, host_ip, port, service, "
                    "product, cve_id, severity, cvss, epss, in_kev) "
                    "VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, 0)",
                    (scan_id, h["ip"], p["number"], p.get("service"),
                     p.get("product_name"))
                )
    db.commit()
    return scan_id


def _diff_scans(db: sqlite3.Connection, target: str,
                 current_scan_id: int) -> dict:
    """Compare current scan to most recent prior scan of the same target."""
    prev = db.execute(
        "SELECT id FROM scans WHERE target = ? AND id < ? "
        "ORDER BY id DESC LIMIT 1",
        (target, current_scan_id)
    ).fetchone()
    if prev is None:
        return {"prev_scan_id": None, "first_scan": True,
                 "new_ports": [], "new_cves": [], "gone_ports": []}

    prev_id = prev[0]
    # New ports: in current but not in prev
    new_ports = db.execute(
        "SELECT DISTINCT host_ip, port, service FROM findings "
        "WHERE scan_id = ? AND (host_ip, port) NOT IN ("
        "  SELECT host_ip, port FROM findings WHERE scan_id = ?"
        ")",
        (current_scan_id, prev_id)
    ).fetchall()
    gone_ports = db.execute(
        "SELECT DISTINCT host_ip, port, service FROM findings "
        "WHERE scan_id = ? AND (host_ip, port) NOT IN ("
        "  SELECT host_ip, port FROM findings WHERE scan_id = ?"
        ")",
        (prev_id, current_scan_id)
    ).fetchall()
    # New CVEs
    new_cves = db.execute(
        "SELECT host_ip, port, cve_id, severity, cvss, epss, in_kev "
        "FROM findings WHERE scan_id = ? AND cve_id IS NOT NULL "
        "AND cve_id NOT IN ("
        "  SELECT cve_id FROM findings WHERE scan_id = ? AND cve_id IS NOT NULL"
        ")",
        (current_scan_id, prev_id)
    ).fetchall()

    return {
        "prev_scan_id": prev_id,
        "first_scan": False,
        "new_ports": [dict(r) for r in new_ports],
        "new_cves": [dict(r) for r in new_cves],
        "gone_ports": [dict(r) for r in gone_ports],
    }


# ── Alerters ──────────────────────────────────────────────────────────────
def _alert_slack(webhook: str, target: str, diff: dict) -> bool:
    nps, ncves = diff.get("new_ports", []), diff.get("new_cves", [])
    if not (nps or ncves):
        return False
    parts = []
    if ncves:
        kev = sum(1 for c in ncves if c.get("in_kev"))
        parts.append(f"*{len(ncves)} new CVE(s)* ({kev} KEV) on {target}")
        # Top 5
        sorted_cves = sorted(ncves, key=lambda c: (
            not c.get("in_kev"), -(c.get("epss") or 0), -(c.get("cvss") or 0)
        ))
        for c in sorted_cves[:5]:
            marker = "🔴 KEV" if c.get("in_kev") else ""
            parts.append(
                f"  `{c.get('cve_id')}` "
                f"({c.get('severity') or '?'} {c.get('cvss') or '?'}) "
                f"on `{c.get('host_ip')}:{c.get('port')}` {marker}"
            )
    if nps:
        parts.append(f"*{len(nps)} new open port(s)*:")
        for p in nps[:5]:
            parts.append(f"  `{p.get('host_ip')}:{p.get('port')}` "
                          f"({p.get('service') or '?'})")
    payload = {"text": "\n".join(parts)}
    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        log.warning("Slack alert failed: %s", e)
        return False


def _alert_webhook(url: str, target: str, diff: dict, scan_id: int) -> bool:
    payload = {
        "tool": "explotica",
        "event": "scan_diff",
        "target": target,
        "scan_id": scan_id,
        "diff": diff,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 400
    except Exception as e:
        log.warning("Webhook %s failed: %s", url, e)
        return False


def _alert_console(target: str, diff: dict) -> None:
    nps, ncves = diff.get("new_ports", []), diff.get("new_cves", [])
    if not (nps or ncves or diff.get("gone_ports")):
        print(f"[{datetime.now(timezone.utc).isoformat()}] {target}: "
              "no change since last scan")
        return
    print(f"[{datetime.now(timezone.utc).isoformat()}] {target}:")
    if ncves:
        kev = sum(1 for c in ncves if c.get("in_kev"))
        print(f"  ⚠ {len(ncves)} new CVE(s), {kev} KEV")
        for c in ncves[:10]:
            marker = " KEV" if c.get("in_kev") else ""
            print(f"     {c['cve_id']} ({c.get('severity')}/"
                   f"{c.get('cvss')}) on {c['host_ip']}:{c['port']}{marker}")
    if nps:
        print(f"  ➕ {len(nps)} new open port(s)")
        for p in nps[:10]:
            print(f"     {p['host_ip']}:{p['port']} ({p.get('service') or '?'})")
    if diff.get("gone_ports"):
        print(f"  ➖ {len(diff['gone_ports'])} port(s) no longer responding")


# ── Scan runner ───────────────────────────────────────────────────────────
def run_one_scan(target: str, scan_args: list[str],
                  out_dir: Path) -> Optional[tuple[dict, str]]:
    """Run a one-shot explotica scan via subprocess. Returns (scan_dict, json_path)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"{target.replace('/', '_')}_{ts}.json"

    cmd = [sys.executable, "-m", "explotica", target,
           "--json", str(json_path)] + scan_args
    log.info("daemon: running scan: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        log.warning("daemon: scan timed out")
        return None
    if proc.returncode != 0:
        log.warning("daemon: scan returned %d, stderr=%s",
                    proc.returncode, proc.stderr[:300])
    if not json_path.exists():
        log.warning("daemon: scan finished but JSON not written: %s", json_path)
        return None
    try:
        scan = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        log.warning("daemon: bad JSON in %s: %s", json_path, e)
        return None
    return (scan, str(json_path))


# ── Daemon loop ───────────────────────────────────────────────────────────
class MonitorDaemon:
    def __init__(self, target: str, interval_s: int, scan_args: list[str],
                  out_dir: Path, db_path: Path,
                  slack_webhook: Optional[str] = None,
                  webhook: Optional[str] = None):
        self.target = target
        self.interval_s = interval_s
        self.scan_args = scan_args
        self.out_dir = out_dir
        self.db_path = db_path
        self.slack_webhook = slack_webhook
        self.webhook = webhook
        self.running = True

    def stop(self, *_):
        log.info("daemon: stop signal received")
        self.running = False

    def run(self):
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log.info("daemon: starting target=%s interval=%ds out=%s db=%s",
                 self.target, self.interval_s, self.out_dir, self.db_path)
        while self.running:
            cycle_start = time.time()
            try:
                self._cycle()
            except Exception as e:
                log.warning("daemon: cycle failed: %s", e)
            elapsed = time.time() - cycle_start
            wait_s = max(0, self.interval_s - elapsed)
            log.info("daemon: cycle done in %.1fs, sleeping %.1fs",
                     elapsed, wait_s)
            # Sleep in 1s chunks so signals are responsive
            for _ in range(int(wait_s)):
                if not self.running:
                    break
                time.sleep(1)

    def _cycle(self):
        result = run_one_scan(self.target, self.scan_args, self.out_dir)
        if result is None:
            return
        scan, json_path = result
        db = _conn(self.db_path)
        try:
            scan_id = _persist_scan(db, scan, json_path)
            diff = _diff_scans(db, self.target, scan_id)

            _alert_console(self.target, diff)
            if (diff.get("new_ports") or diff.get("new_cves")):
                if self.slack_webhook:
                    _alert_slack(self.slack_webhook, self.target, diff)
                if self.webhook:
                    _alert_webhook(self.webhook, self.target, diff, scan_id)
        finally:
            db.close()


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="explotica-daemon",
        description="Continuous monitoring daemon — scheduled scans + diff alerts."
    )
    p.add_argument("--target", required=True,
                   help="Target CIDR/IP/hostname (same as explotica positional)")
    p.add_argument("--interval", type=int, default=3600,
                   help="Seconds between scan cycles (default 3600 = 1h)")
    p.add_argument("--scan-args", default="--ports top100 --vuln-scan --epss-kev",
                   help="Extra args passed to explotica per scan")
    p.add_argument("--out-dir", default="./scans",
                   help="Directory for JSON output of each scan")
    p.add_argument("--db", default=str(DEFAULT_DB),
                   help="SQLite DB path for history")
    p.add_argument("--slack-webhook", help="Slack incoming-webhook URL")
    p.add_argument("--webhook", help="Generic JSON webhook URL")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    daemon = MonitorDaemon(
        target=args.target,
        interval_s=args.interval,
        scan_args=args.scan_args.split(),
        out_dir=Path(args.out_dir),
        db_path=Path(args.db),
        slack_webhook=args.slack_webhook,
        webhook=args.webhook,
    )
    daemon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
