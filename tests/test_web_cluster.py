"""Offline verification of the web-cluster orchestrator's pure glue logic.

Network paths need a live target; here we pin the non-network parts: passive
IDOR reference aggregation (de-dup across URLs) and the empty-result pruning
that keeps reports compact.
"""

from explotica.active import web_cluster as W


class TestIdorRefAggregation:
    def test_detects_and_dedupes(self):
        urls = [
            "https://app/api?user_id=42",
            "https://app/api?user_id=42",          # duplicate -> collapsed
            "https://app/users/7/profile",
            "https://app/doc/550e8400-e29b-41d4-a716-446655440000",
        ]
        refs = W.detect_idor_refs(urls)
        values = {(r["param"], r["value"]) for r in refs}
        assert ("user_id", "42") in values
        # de-dup: user_id=42 appears once despite two URLs
        assert sum(1 for r in refs if r["value"] == "42") == 1
        assert any(r["type"] == "uuid" for r in refs)

    def test_empty_urls(self):
        assert W.detect_idor_refs([]) == []


class TestRunWebClusterPruning:
    def test_all_disabled_returns_empty(self):
        # No audits enabled -> nothing run -> empty dict (pruned).
        out = W.run_web_cluster("10.0.0.1", [(80, False)],
                                jwt_crack=False, graphql_audit=False,
                                dom_xss=False, idor_passive=False)
        assert out == {}

    def test_idor_passive_only_no_network(self):
        # idor_passive uses only the provided URLs — no socket needed.
        out = W.run_web_cluster(
            "10.0.0.1", [(80, False)],
            discovered_urls=["https://app/api?order_id=1001"],
            idor_passive=True)
        assert "idor_refs" in out
        assert any(r["param"] == "order_id" for r in out["idor_refs"])
