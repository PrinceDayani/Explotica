"""Graceful shutdown handling — Phase 62.

Ctrl+C in the middle of a scan should:
  1. Stop sending new probes
  2. Wait for in-flight probes to finish (with a timeout)
  3. Write whatever data we have to the configured --json path
  4. Exit cleanly with code 130

This module exposes a singleton ShutdownToken that scanner workers consult.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


class ShutdownToken:
    """Thread-safe shutdown flag.

    Workers call `is_set()` periodically — if True, finish current work
    and return. `request()` triggers an orderly shutdown.
    """

    def __init__(self):
        self._event = threading.Event()
        self._requested_at: Optional[float] = None
        self._on_shutdown: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    def is_set(self) -> bool:
        return self._event.is_set()

    def request(self, reason: str = "user-requested") -> None:
        """Trigger shutdown. Idempotent."""
        with self._lock:
            if self._event.is_set():
                return
            self._event.set()
            self._requested_at = time.monotonic()
        log.warning("shutdown requested: %s — finishing in-flight work…",
                    reason)
        for cb in list(self._on_shutdown):
            try:
                cb()
            except Exception as e:
                log.error("shutdown callback raised: %s", e)

    def on_shutdown(self, callback: Callable[[], None]) -> None:
        """Register a function to run when shutdown is requested.

        Use this to flush in-memory scan data to disk before exit.
        """
        with self._lock:
            self._on_shutdown.append(callback)

    def time_since_request(self) -> float:
        """Seconds since shutdown was requested (or 0 if not yet)."""
        if self._requested_at is None:
            return 0.0
        return time.monotonic() - self._requested_at

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout)


# Module-singleton
_token = ShutdownToken()


def get_token() -> ShutdownToken:
    return _token


def reset() -> None:
    """For tests — reset the singleton."""
    global _token
    _token = ShutdownToken()


# ── Signal installation ─────────────────────────────────────────────────
_signals_installed = False


def install_signal_handlers(emergency_dump_path: Optional[str] = None,
                              data_provider: Optional[Callable[[], dict]] = None
                              ) -> None:
    """Install SIGINT + SIGTERM handlers.

    Args:
      emergency_dump_path: if set, write the current scan data here on shutdown
      data_provider: callable returning the dict to dump
    """
    global _signals_installed
    if _signals_installed:
        return

    def emergency_dump():
        if not emergency_dump_path or not data_provider:
            return
        try:
            data = data_provider()
            if not data:
                return
            path = Path(emergency_dump_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".partial")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(path)
            sys.stderr.write("explotica: partial scan written to "
                              + str(path) + "\n")
        except Exception as e:
            log.error("emergency dump failed: %s", e)

    def handler(signum: int, frame: Any) -> None:
        signame = signal.Signals(signum).name
        # If already shutting down, a second signal forces immediate exit
        if _token.is_set():
            sys.stderr.write("\nexplotica: second " + signame
                              + " received — forced exit\n")
            sys.exit(130)
        sys.stderr.write("\nexplotica: " + signame
                          + " received — graceful shutdown (Ctrl+C again for force)\n")
        _token.request(reason=signame)
        emergency_dump()

    try:
        signal.signal(signal.SIGINT, handler)
    except ValueError:
        # Not on main thread; skip
        log.debug("could not install SIGINT handler (not main thread)")
        return
    try:
        signal.signal(signal.SIGTERM, handler)
    except (ValueError, AttributeError):
        pass

    _signals_installed = True
    log.debug("signal handlers installed (graceful shutdown)")
