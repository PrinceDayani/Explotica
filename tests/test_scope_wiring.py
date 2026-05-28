"""Phase 64 — verify scope enforcement is wired into leaky modules.

These tests inspect the modules to confirm scope checks are present at
the entry points. They DON'T run real network traffic — they just verify
the safety primitive is consulted.
"""

import inspect

import pytest

from explotica.safety_kit.safety import Scope, set_active_scope


@pytest.fixture(autouse=True)
def cleanup_scope():
    """Reset active scope after each test."""
    yield
    set_active_scope(None)


class TestOSINTScopeEnforcement:
    def test_crtsh_consults_scope(self):
        from explotica import osint
        src = inspect.getsource(osint.crtsh_subdomains)
        assert "get_active_scope" in src, \
            "crtsh_subdomains should consult active scope"

    def test_crtsh_blocks_out_of_scope(self):
        """When scope is set to example.com, crt.sh of evil.com must skip."""
        from explotica.enrich.osint import crtsh_subdomains
        set_active_scope(Scope.from_target("example.com"))
        result = crtsh_subdomains("evil.com")
        assert result is None


class TestTakeoverScopeEnforcement:
    def test_takeover_consults_scope(self):
        from explotica import takeover
        src = inspect.getsource(takeover.check_subdomain)
        assert "get_active_scope" in src

    def test_takeover_skips_out_of_scope(self):
        from explotica.active.takeover import check_subdomain
        set_active_scope(Scope.from_target("example.com"))
        result = check_subdomain("evil.com")
        assert result is None


class TestSubdomainEnumScopeEnforcement:
    def test_enum_consults_scope(self):
        from explotica import subdomain_extended
        src = inspect.getsource(subdomain_extended.enumerate_subdomains)
        assert "get_active_scope" in src

    def test_enum_returns_skipped_for_out_of_scope(self):
        from explotica.active.subdomain_extended import enumerate_subdomains
        set_active_scope(Scope.from_target("example.com"))
        result = enumerate_subdomains("evil.com")
        assert result.get("skipped_reason") == "outside-scope"


class TestADEnumScopeEnforcement:
    def test_ad_enum_consults_scope(self):
        from explotica import ad_enum
        src = inspect.getsource(ad_enum.run_ad_enum)
        assert "get_active_scope" in src

    def test_ad_enum_skips_out_of_scope(self):
        from explotica.ad.ad_enum import run_ad_enum
        set_active_scope(Scope.from_target("corp.local"))
        result = run_ad_enum("evil.local")
        assert result.get("skipped_reason") == "outside-scope"


class TestScopeWithMultipleDomains:
    def test_subdomain_of_in_scope_domain_allowed(self):
        from explotica.active.subdomain_extended import enumerate_subdomains
        set_active_scope(Scope.from_target("example.com"))
        # api.example.com is a subdomain — must be allowed
        # We can't run the full enum without network, so just verify the
        # scope check passes by not getting skipped immediately.
        # (The function will hit DNS and likely return wildcard results,
        # but it shouldn't be blocked at the scope gate.)
        # Run it briefly with a tiny timeout and check the skipped_reason
        result = enumerate_subdomains("api.example.com", timeout=0.1,
                                         max_candidates=1)
        assert result.get("skipped_reason") != "outside-scope"
