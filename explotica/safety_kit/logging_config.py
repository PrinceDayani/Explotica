"""Production logging configuration — env-var driven, structured output.

Phase 62 hardening.

Default: WARNING to stderr.
Configurable via env vars:
  EXPLOTICA_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR|CRITICAL   (default: WARNING)
  EXPLOTICA_LOG_FILE=/path/to/log                          (also log to file)
  EXPLOTICA_LOG_FORMAT=plain|json                          (default: plain)

Modules should always use:
    log = logging.getLogger(__name__)
    log.info(...) / log.debug(...) / log.warning(...) / log.error(...)

Never `print()` for diagnostic info — only for final user-facing output.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Optional


class _JsonFormatter(logging.Formatter):
    """One-line JSON per log record. Useful for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Extra structured fields
        for key in ("host", "port", "target", "phase", "scan_id"):
            if key in record.__dict__:
                payload[key] = record.__dict__[key]
        return json.dumps(payload, separators=(",", ":"))


_PLAIN_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_PLAIN_DATEFMT = "%H:%M:%S"


def configure(level: Optional[str] = None,
                logfile: Optional[str] = None,
                format_kind: Optional[str] = None,
                force: bool = False) -> None:
    """Install handlers on the root logger.

    Idempotent — calling twice without `force` is a no-op. Use `force=True`
    to reconfigure (useful in tests).
    """
    root = logging.getLogger()
    if root.handlers and not force:
        return

    if force:
        for h in list(root.handlers):
            root.removeHandler(h)

    level_name = (level
                  or os.environ.get("EXPLOTICA_LOG_LEVEL")
                  or "WARNING").upper()
    level_value = getattr(logging, level_name, logging.WARNING)
    root.setLevel(level_value)

    kind = (format_kind
            or os.environ.get("EXPLOTICA_LOG_FORMAT")
            or "plain").lower()

    if kind == "json":
        formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(_PLAIN_FORMAT, _PLAIN_DATEFMT)

    # Console handler (stderr)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level_value)
    console.setFormatter(formatter)
    root.addHandler(console)

    # Optional file handler
    logfile_path = logfile or os.environ.get("EXPLOTICA_LOG_FILE")
    if logfile_path:
        try:
            fh = logging.FileHandler(logfile_path, encoding="utf-8")
            fh.setLevel(level_value)
            fh.setFormatter(formatter)
            root.addHandler(fh)
        except OSError as e:
            sys.stderr.write("explotica: could not open log file "
                              + str(logfile_path) + ": " + str(e) + "\n")

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "asyncio", "scapy.runtime", "playwright"):
        logging.getLogger(noisy).setLevel(max(level_value, logging.WARNING))


def set_level(level: str) -> None:
    """Bump or lower the log level after initial configure()."""
    level_value = getattr(logging, level.upper(), logging.WARNING)
    logging.getLogger().setLevel(level_value)
    for h in logging.getLogger().handlers:
        h.setLevel(level_value)
