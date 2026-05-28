"""Retry + circuit-breaker primitives — Phase 63.

Network calls in security tools fail constantly. NVD rate-limits, EPSS
has occasional 502s, Shodan returns 429s, DNS queries time out, target
hosts go offline mid-scan. Without retry logic, every single transient
failure becomes a permanent gap in the scan results.

This module provides:
  - @retry decorator with exponential backoff + jitter
  - CircuitBreaker — opens after N consecutive failures, half-opens after
    a cooldown. Prevents hammering broken services.
  - retry_call() one-shot helper for inline call sites

Design constraints:
  - Pure stdlib (no `tenacity` dep)
  - Thread-safe (used from worker pools)
  - Honors the global ShutdownToken — stops retrying on Ctrl+C
"""

from __future__ import annotations

import functools
import logging
import random
import threading
import time
from typing import Callable, Optional, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


# ── Default retryable exception classes ─────────────────────────────────
# Modules can override via @retry(retry_on=...).
import socket
import ssl
import urllib.error

DEFAULT_RETRY_EXCEPTIONS = (
    socket.timeout,
    ConnectionError,
    ConnectionResetError,
    ConnectionRefusedError,
    TimeoutError,
    ssl.SSLError,
    urllib.error.URLError,
    OSError,
)


# ── Backoff strategies ─────────────────────────────────────────────────
def exponential_backoff(attempt: int, *, base: float = 0.5,
                          cap: float = 30.0,
                          jitter: float = 0.2) -> float:
    """Compute delay for attempt N (0-indexed).

    base=0.5 → delays: 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 30 (cap)
    Adds ±jitter*delay random offset to avoid thundering herd.
    """
    delay = min(cap, base * (2 ** attempt))
    if jitter:
        delay *= 1 + random.uniform(-jitter, jitter)
    return max(0.0, delay)


# ── @retry decorator ────────────────────────────────────────────────────
def retry(*, max_attempts: int = 3,
            retry_on: tuple = DEFAULT_RETRY_EXCEPTIONS,
            base_delay: float = 0.5,
            cap_delay: float = 30.0,
            jitter: float = 0.2,
            log_level: int = logging.DEBUG):
    """Decorator: retry the wrapped call up to `max_attempts` times.

    Example:
        @retry(max_attempts=5, base_delay=1.0)
        def fetch_cve(cve_id):
            return urllib.request.urlopen(f"https://nvd.../{cve_id}")
    """
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> T:
            last_exc: Optional[BaseException] = None
            for attempt in range(max_attempts):
                # Honor graceful shutdown — stop retrying on Ctrl+C
                try:
                    from .shutdown import get_token
                    if get_token().is_set():
                        log.debug("retry %s: shutdown requested, aborting",
                                  fn.__name__)
                        break
                except ImportError:
                    pass

                try:
                    return fn(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if attempt == max_attempts - 1:
                        break  # last attempt; surface the exception
                    delay = exponential_backoff(
                        attempt, base=base_delay,
                        cap=cap_delay, jitter=jitter,
                    )
                    log.log(log_level,
                            "retry %s: attempt %d/%d failed (%s), "
                            "sleeping %.2fs",
                            fn.__name__, attempt + 1, max_attempts,
                            type(e).__name__, delay)
                    time.sleep(delay)
            if last_exc is not None:
                raise last_exc
            return None  # type: ignore[return-value]
        return wrapper
    return decorator


def retry_call(fn: Callable[..., T], *args,
                 max_attempts: int = 3,
                 retry_on: tuple = DEFAULT_RETRY_EXCEPTIONS,
                 base_delay: float = 0.5,
                 cap_delay: float = 30.0,
                 jitter: float = 0.2,
                 **kwargs) -> T:
    """One-shot retry wrapper. Equivalent to @retry but inline."""
    wrapped = retry(max_attempts=max_attempts, retry_on=retry_on,
                     base_delay=base_delay, cap_delay=cap_delay,
                     jitter=jitter)(fn)
    return wrapped(*args, **kwargs)


# ── Circuit breaker ─────────────────────────────────────────────────────
class CircuitBreaker:
    """Trip after N consecutive failures, then refuse calls for `cooldown`
    seconds. After cooldown, allow ONE probe — if it succeeds, close.

    States:
      CLOSED   — normal; calls go through
      OPEN     — blocked; raises BreakerOpen immediately
      HALF_OPEN — single probe in flight; outcome decides next state
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, *, threshold: int = 5,
                  cooldown: float = 60.0,
                  name: str = ""):
        self.threshold = threshold
        self.cooldown = cooldown
        self.name = name or "circuit"
        self.state = self.CLOSED
        self._fail_count = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Should the next call proceed?"""
        with self._lock:
            now = time.monotonic()
            if self.state == self.OPEN:
                if now - self._opened_at >= self.cooldown:
                    self.state = self.HALF_OPEN
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._fail_count = 0
            if self.state in (self.OPEN, self.HALF_OPEN):
                log.info("circuit '%s' closed (success after %s)",
                          self.name, self.state)
            self.state = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._fail_count += 1
            if self.state == self.HALF_OPEN:
                self.state = self.OPEN
                self._opened_at = time.monotonic()
                log.warning("circuit '%s' re-opened (half-open probe failed)",
                            self.name)
            elif self._fail_count >= self.threshold:
                self.state = self.OPEN
                self._opened_at = time.monotonic()
                log.warning("circuit '%s' OPEN after %d failures; "
                            "cooling down %.0fs",
                            self.name, self._fail_count, self.cooldown)

    def call(self, fn: Callable[..., T], *args, **kwargs) -> T:
        """Wrap a call with the breaker."""
        if not self.allow():
            raise BreakerOpen(self.name + " is open (cooldown until "
                              + str(round(self.cooldown - (time.monotonic()
                                                              - self._opened_at), 1))
                              + "s)")
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise


class BreakerOpen(RuntimeError):
    """Raised when a CircuitBreaker rejects a call."""


# ── Module-level breakers for shared services ───────────────────────────
# Modules can use these directly: NVD_BREAKER.call(fetch, cve_id)
_breakers: dict[str, CircuitBreaker] = {}
_breakers_lock = threading.Lock()


def get_breaker(name: str, *, threshold: int = 5,
                  cooldown: float = 60.0) -> CircuitBreaker:
    """Get or create a named breaker. Threadsafe."""
    with _breakers_lock:
        if name not in _breakers:
            _breakers[name] = CircuitBreaker(
                threshold=threshold, cooldown=cooldown, name=name
            )
        return _breakers[name]
