"""Retry + circuit breaker — Phase 63."""

import time

import pytest

from explotica.safety_kit.retry import (
    BreakerOpen, CircuitBreaker, exponential_backoff, get_breaker,
    retry, retry_call,
)


class TestExponentialBackoff:
    def test_attempt_zero_is_base(self):
        # 0.5 * 2^0 = 0.5 — with jitter ±20% → [0.4, 0.6]
        delay = exponential_backoff(0, base=0.5, jitter=0.0)
        assert delay == 0.5

    def test_doubles_each_attempt(self):
        a0 = exponential_backoff(0, base=1.0, jitter=0.0)
        a1 = exponential_backoff(1, base=1.0, jitter=0.0)
        a2 = exponential_backoff(2, base=1.0, jitter=0.0)
        assert a1 == 2 * a0
        assert a2 == 4 * a0

    def test_caps_at_max(self):
        delay = exponential_backoff(20, base=1.0, cap=10.0, jitter=0.0)
        assert delay == 10.0

    def test_jitter_within_bounds(self):
        delays = [exponential_backoff(0, base=1.0, jitter=0.2)
                   for _ in range(50)]
        # All within ±20% of 1.0
        assert all(0.8 <= d <= 1.2 for d in delays)


class TestRetryDecorator:
    def test_succeeds_on_first_attempt(self):
        calls = []
        @retry(max_attempts=3, base_delay=0.01)
        def f():
            calls.append(1)
            return "ok"
        assert f() == "ok"
        assert len(calls) == 1

    def test_retries_then_succeeds(self):
        attempts = []
        @retry(max_attempts=3, base_delay=0.01, retry_on=(ValueError,))
        def f():
            attempts.append(1)
            if len(attempts) < 3:
                raise ValueError("transient")
            return "ok"
        assert f() == "ok"
        assert len(attempts) == 3

    def test_gives_up_after_max_attempts(self):
        attempts = []
        @retry(max_attempts=3, base_delay=0.01, retry_on=(ValueError,))
        def f():
            attempts.append(1)
            raise ValueError("always fails")
        with pytest.raises(ValueError):
            f()
        assert len(attempts) == 3

    def test_non_retry_exception_propagates_immediately(self):
        attempts = []
        @retry(max_attempts=3, base_delay=0.01, retry_on=(ValueError,))
        def f():
            attempts.append(1)
            raise TypeError("not retryable")
        with pytest.raises(TypeError):
            f()
        assert len(attempts) == 1


class TestRetryCall:
    def test_inline_retry(self):
        attempts = []
        def f(x):
            attempts.append(x)
            if len(attempts) < 2:
                raise ConnectionError("flaky")
            return x * 2
        result = retry_call(f, 5, max_attempts=3, base_delay=0.01,
                              retry_on=(ConnectionError,))
        assert result == 10
        assert len(attempts) == 2


class TestCircuitBreaker:
    def test_closed_by_default(self):
        cb = CircuitBreaker(threshold=3, cooldown=1.0)
        assert cb.allow()
        assert cb.state == cb.CLOSED

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(threshold=3, cooldown=10.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == cb.OPEN
        assert not cb.allow()

    def test_success_resets(self):
        cb = CircuitBreaker(threshold=3, cooldown=10.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.state == cb.CLOSED
        for _ in range(3):
            cb.record_failure()
        assert cb.state == cb.OPEN

    def test_half_open_after_cooldown(self):
        cb = CircuitBreaker(threshold=2, cooldown=0.05)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == cb.OPEN
        time.sleep(0.06)
        assert cb.allow()
        assert cb.state == cb.HALF_OPEN

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(threshold=2, cooldown=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow()
        cb.record_success()
        assert cb.state == cb.CLOSED

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(threshold=2, cooldown=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.06)
        cb.allow()
        cb.record_failure()
        assert cb.state == cb.OPEN

    def test_call_raises_when_open(self):
        cb = CircuitBreaker(threshold=1, cooldown=10.0)
        cb.record_failure()
        with pytest.raises(BreakerOpen):
            cb.call(lambda: "should-not-run")


class TestNamedBreakers:
    def test_singleton_per_name(self):
        b1 = get_breaker("test-shared")
        b2 = get_breaker("test-shared")
        assert b1 is b2
