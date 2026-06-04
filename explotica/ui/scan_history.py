"""Shared scan-history index — powers both the shell `scans` command and the
TUI history modal from one data layer.

Both front-ends persist results as ``scans/*.json`` (ScanResult.to_dict). This
module globs those, pulls a lightweight summary out of each (without fully
rehydrating ScanResult objects), and ranks them. The shell renders the result
as a Rich table; the TUI renders it as a selectable DataTable — same data,
two views.

Parsing is defensive: a corrupt or half-written JSON becomes a ``ScanMeta`` with
``ok=False`` rather than raising, so one bad file never breaks the listing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ScanMeta:
    """One past scan's summary, cheap to compute from its JSON."""
    path: Path
    name: str
    target: str
    started_at: Optional[str]
    duration_s: float
    host_count: int
    up_count: int
    open_ports: int
    cve_count: int
    kev_count: int
    scanner_version: str
    mtime: float
    size_kb: float
    ok: bool = True
    error: Optional[str] = None

    @property
    def age(self) -> str:
        return _fmt_age(self.mtime)

    @property
    def duration(self) -> str:
        return _fmt_duration(self.duration_s)

    def row(self) -> tuple[str, ...]:
        """Columns for a (target, hosts, ports, cves, age, file) table."""
        if not self.ok:
            return (f"[corrupt] {self.name}", "-", "-", "-",
                    _fmt_age(self.mtime), self.name)
        cve = str(self.cve_count) + (f" ({self.kev_count} KEV)"
                                     if self.kev_count else "")
        return (self.target or "?",
                f"{self.up_count}/{self.host_count}",
                str(self.open_ports),
                cve,
                self.age,
                self.name)


# ── Formatting helpers ────────────────────────────────────────────────────────
def _fmt_age(mtime: float) -> str:
    secs = max(0, time.time() - mtime)
    if secs < 60:
        return f"{int(secs)}s ago"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def _fmt_duration(secs: float) -> str:
    secs = float(secs or 0)
    if secs < 60:
        return f"{secs:.0f}s"
    if secs < 3600:
        return f"{secs / 60:.0f}m"
    return f"{secs / 3600:.1f}h"


# ── Core ──────────────────────────────────────────────────────────────────────
def _summarize(path: Path) -> ScanMeta:
    st = path.stat()
    base = dict(path=path, name=path.name, mtime=st.st_mtime,
                size_kb=round(st.st_size / 1024, 1))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — a bad file is a row, not a crash
        return ScanMeta(target="", started_at=None, duration_s=0.0,
                        host_count=0, up_count=0, open_ports=0, cve_count=0,
                        kev_count=0, scanner_version="", ok=False,
                        error=str(e), **base)
    hosts = data.get("hosts", []) or []
    up = sum(1 for h in hosts if h.get("is_up", True))
    open_ports = cve = kev = 0
    for h in hosts:
        for p in h.get("ports", []) or []:
            if p.get("state") == "open":
                open_ports += 1
            for c in p.get("cves", []) or []:
                cve += 1
                if c.get("in_kev"):
                    kev += 1
    return ScanMeta(
        target=data.get("target", ""),
        started_at=data.get("started_at"),
        duration_s=float(data.get("duration_s", 0) or 0),
        host_count=len(hosts), up_count=up, open_ports=open_ports,
        cve_count=cve, kev_count=kev,
        scanner_version=data.get("scanner_version", ""),
        **base,
    )


# ════════════════════════════════════════════════════════════════════════════
#  RANKING — what makes a past scan worth surfacing first?
# ════════════════════════════════════════════════════════════════════════════
# Default is recency (most recent first) — that's what people usually want when
# resuming work. But "most relevant" is a real product decision: you could rank
# by risk (most KEV CVEs), by blast radius (most live hosts), or recency. The
# sort modes below are the knob; tweak the keys or add your own.
_SORT_KEYS = {
    "recent": lambda m: -m.mtime,
    "risk": lambda m: (-m.kev_count, -m.cve_count, -m.mtime),
    "size": lambda m: (-m.host_count, -m.mtime),
}


def list_scans(scans_dir: str | Path = "scans", *, sort: str = "recent",
               limit: Optional[int] = None) -> list[ScanMeta]:
    """Return summaries of every scans/*.json, ranked.

    sort: 'recent' (default), 'risk' (most KEV/CVEs first), or 'size'
          (most hosts first). Unknown values fall back to 'recent'.
    """
    d = Path(scans_dir)
    if not d.exists():
        return []
    metas = []
    for p in d.glob("*.json"):
        try:
            metas.append(_summarize(p))
        except OSError:
            continue
    key = _SORT_KEYS.get(sort, _SORT_KEYS["recent"])
    metas.sort(key=key)
    return metas[:limit] if limit else metas


def resolve_scan(ref: str, scans_dir: str | Path = "scans") -> Optional[Path]:
    """Resolve a scan reference to a path: a 1-based index into the recent
    listing, a bare filename in scans/, or a direct path. None if not found.
    """
    ref = ref.strip().strip('"').strip("'")
    if not ref:
        return None
    # Direct path / relative path that exists
    p = Path(ref)
    if p.exists():
        return p
    # 1-based index into the recent listing
    if ref.isdigit():
        metas = list_scans(scans_dir, sort="recent")
        i = int(ref) - 1
        if 0 <= i < len(metas):
            return metas[i].path
        return None
    # Bare name inside scans/
    candidate = Path(scans_dir) / ref
    if candidate.exists():
        return candidate
    if not ref.endswith(".json"):
        candidate = Path(scans_dir) / f"{ref}.json"
        if candidate.exists():
            return candidate
    return None


def iso_to_local(iso: Optional[str]) -> str:
    if not iso:
        return "?"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return iso[:16]
