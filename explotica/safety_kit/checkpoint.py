"""Scan checkpointing — flush partial results so crashes don't lose work.

Phase 63 — production hardening.

Long scans (e.g. /16 with --ports all) take hours. A power blip, OOM-killer,
or accidental kill -9 mid-scan currently wipes everything. This module
provides:

  - Checkpoint.update(scan_data) — writes scan to disk atomically
    (tmp file + rename) every N hosts or every M seconds
  - Checkpoint.load(path) — resume from a prior checkpoint
  - Automatic registration with the ShutdownToken — graceful Ctrl+C
    triggers a final flush

Usage in scanner.run_scan:
    chk = Checkpoint(out_path)
    for host in hosts:
        scan_one(host)
        chk.update(scan_data)   # cheap; only writes if N or M crossed
    chk.finalize(scan_data)     # always writes
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class Checkpoint:
    """Atomic checkpoint writer for in-progress scan data."""

    def __init__(self, path: str | os.PathLike, *,
                  every_n_hosts: int = 10,
                  every_secs: float = 30.0,
                  enabled: bool = True):
        self.path = Path(path) if path else None
        self.every_n = max(1, every_n_hosts)
        self.every_secs = max(1.0, every_secs)
        self.enabled = enabled and self.path is not None
        self._lock = threading.Lock()
        self._last_write = 0.0
        self._update_count = 0
        # Register with shutdown — final flush on Ctrl+C
        if self.enabled:
            try:
                from .shutdown import get_token
                token = get_token()
                token.on_shutdown(self._on_shutdown_flush)
                self._last_data: Optional[dict] = None
            except ImportError:
                self._last_data = None
        else:
            self._last_data = None

    def _atomic_write(self, data: dict) -> None:
        """Write to .partial then rename — never leaves a half-written file."""
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".partial")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.path)
            self._last_write = time.monotonic()
        except OSError as e:
            log.warning("checkpoint write failed: %s", e)

    def update(self, scan_data: dict) -> None:
        """Maybe flush — only if cooldown or every_n threshold crossed.

        Cheap: O(1) for the no-write case. Safe to call inside the per-host
        hot loop.
        """
        if not self.enabled:
            return
        with self._lock:
            self._update_count += 1
            self._last_data = scan_data
            elapsed = time.monotonic() - self._last_write
            if (self._update_count % self.every_n == 0
                    or elapsed >= self.every_secs):
                self._atomic_write(scan_data)

    def finalize(self, scan_data: dict) -> None:
        """Force a final write — used at end of scan."""
        if not self.enabled:
            return
        with self._lock:
            self._last_data = scan_data
            self._atomic_write(scan_data)

    def _on_shutdown_flush(self) -> None:
        """Called by ShutdownToken on Ctrl+C — writes whatever we have."""
        if self._last_data is None:
            return
        log.warning("shutdown — flushing checkpoint to %s", self.path)
        self._atomic_write(self._last_data)

    @staticmethod
    def load(path: str | os.PathLike) -> Optional[dict]:
        """Load a previous checkpoint. Returns None if missing or invalid."""
        try:
            p = Path(path)
            if not p.exists():
                return None
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("checkpoint load %s failed: %s", path, e)
            return None
