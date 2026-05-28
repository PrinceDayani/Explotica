"""Safety module — scope enforcement + safe-mode + rate-limiter tests."""

import pytest
import time

from explotica.safety_kit.safety import (
    Scope, ScopeViolation, SafeMode, RateLimiter,
    set_active_scope, get_active_scope, in_scope, require_in_scope,
    set_safe_mode, get_safe_mode, safe_to_run,
    classify_args_risk,
)


# ── Scope ────────────────────────────────────────────────────────────────
class TestScope:
    def test_empty_scope_permits_everything(self):
        s = Scope(strict=True)
        assert s.permits("1.2.3.4")
        assert s.permits("example.com")

    def test_single_host_scope(self):
        s = Scope.from_target("192.168.1.5")
        assert s.permits("192.168.1.5")
        assert not s.permits("192.168.1.6")
        assert not s.permits("8.8.8.8")

    def test_cidr_scope(self):
        s = Scope.from_target("192.168.1.0/24")
        assert s.permits("192.168.1.1")
        assert s.permits("192.168.1.254")
        assert not s.permits("192.168.2.1")
        assert not s.permits("10.0.0.1")

    def test_multi_network_scope(self):
        s = Scope.from_target("192.168.1.0/24,10.0.0.0/8")
        assert s.permits("192.168.1.50")
        assert s.permits("10.5.5.5")
        assert not s.permits("172.16.0.1")

    def test_domain_scope_exact(self):
        s = Scope.from_target("example.com")
        assert s.permits("example.com")
        assert s.permits("api.example.com")  # subdomain
        assert not s.permits("evil.com")
        assert not s.permits("notexample.com")  # not a subdomain

    def test_strict_records_violation(self):
        s = Scope(networks=["192.168.1.0/24"], strict=True)
        s.permits("8.8.8.8")
        assert len(s.violations) == 1
        assert s.violations[0]["target"] == "8.8.8.8"

    def test_non_strict_warns_but_allows(self):
        s = Scope(networks=["192.168.1.0/24"], strict=False)
        assert s.permits("8.8.8.8") is True
        assert len(s.violations) == 1

    def test_require_raises_on_violation(self):
        s = Scope(networks=["192.168.1.0/24"], strict=True)
        with pytest.raises(ScopeViolation):
            s.require("8.8.8.8")

    def test_active_scope_singleton(self):
        scope = Scope.from_target("10.0.0.0/24")
        set_active_scope(scope)
        assert get_active_scope() is scope
        assert in_scope("10.0.0.5")
        assert not in_scope("8.8.8.8")
        # Cleanup
        set_active_scope(None)

    def test_auto_target_skips(self):
        s = Scope.from_target("auto")
        assert s.permits("anything-when-empty.example")


# ── SafeMode ─────────────────────────────────────────────────────────────
class TestSafeMode:
    def test_default_blocks_nothing(self):
        sm = SafeMode.disabled()
        assert sm.gate("default_creds")
        assert sm.gate("syn_scan")

    def test_safe_all_blocks_everything(self):
        sm = SafeMode.safe_all()
        assert not sm.gate("default_creds")
        assert not sm.gate("syn_scan")
        assert not sm.gate("web_fuzz")
        assert not sm.gate("asrep_roast")

    def test_unknown_check_passes(self):
        """Categories not in BLOCKABLE_CHECKS should not be silently blocked."""
        sm = SafeMode.safe_all()
        # Anything not in blocked set is allowed — including unknown
        assert sm.gate("unknown_category_xyz")

    def test_partial_block(self):
        sm = SafeMode({"syn_scan", "web_fuzz"})
        assert not sm.gate("syn_scan")
        assert not sm.gate("web_fuzz")
        assert sm.gate("default_creds")

    def test_singleton_install(self):
        original = get_safe_mode()
        sm = SafeMode.safe_all()
        set_safe_mode(sm)
        assert not safe_to_run("syn_scan")
        set_safe_mode(original)
        assert safe_to_run("syn_scan")


# ── RateLimiter ──────────────────────────────────────────────────────────
class TestRateLimiter:
    def test_first_call_immediate(self):
        rl = RateLimiter(pps=10)
        t0 = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.05  # nearly instant

    def test_throttles_subsequent_calls(self):
        rl = RateLimiter(pps=20)  # 50ms between calls
        rl.acquire()
        t0 = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - t0
        # Should sleep ~50ms
        assert 0.04 < elapsed < 0.10

    def test_high_rate_minimal_throttle(self):
        rl = RateLimiter(pps=1000)
        t0 = time.monotonic()
        for _ in range(10):
            rl.acquire()
        elapsed = time.monotonic() - t0
        # 10 acquires at 1000 pps = ~10ms minimum, allow generous slack
        assert elapsed < 0.5

    def test_clamps_negative_pps(self):
        rl = RateLimiter(pps=0)
        assert rl.pps >= 0.1


# ── classify_args_risk ───────────────────────────────────────────────────
class TestClassify:
    def test_passive_only(self):
        class A:
            vuln_scan = True
            epss_kev = True
        low, active = classify_args_risk(A())
        assert len(low) == 2
        assert active == []

    def test_active_flagged(self):
        class A:
            web_fuzz = True
            check_default_creds = True
        low, active = classify_args_risk(A())
        assert any("DANGEROUS" in c for c in active)
        assert len(active) == 2

    def test_all_the_things_flagged(self):
        class A:
            all_the_things = True
        low, active = classify_args_risk(A())
        assert any("all-the-things" in c for c in active)
