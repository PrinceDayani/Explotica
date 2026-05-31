"""Offline verification of IDOR detection + the two-context confirmation logic.

The point of the module is to confirm IDOR *correctly* — so the tests focus on
the classifier distinguishing real data exposure from generic denied pages and
the attacker's own object.
"""

from explotica.active import idor_audit as I


class TestReferenceTyping:
    def test_numeric(self):
        r = I.classify_reference("12345")
        assert r["type"] == "numeric" and r["predictability"] == 1.0

    def test_uuid(self):
        r = I.classify_reference("550e8400-e29b-41d4-a716-446655440000")
        assert r["type"] == "uuid" and r["predictability"] < 0.1

    def test_objectid(self):
        r = I.classify_reference("507f1f77bcf86cd799439011")
        assert r["type"] == "mongo_objectid"


class TestRefDetection:
    def test_query_param(self):
        refs = I.detect_object_refs("https://app/api?user_id=42&q=x")
        assert any(r["param"] == "user_id" and r["value"] == "42" for r in refs)

    def test_path_segment(self):
        refs = I.detect_object_refs("https://app/users/123/profile")
        assert any(r["location"] == "path" and r["value"] == "123" for r in refs)

    def test_uuid_in_path(self):
        refs = I.detect_object_refs(
            "https://app/doc/550e8400-e29b-41d4-a716-446655440000")
        assert any(r["type"] == "uuid" for r in refs)


class TestCandidateGen:
    def test_numeric_neighbors(self):
        ref = {"value": "100", "type": "numeric"}
        cands = I.generate_candidates(ref)
        assert "101" in cands and "99" in cands

    def test_uuid_not_guessable(self):
        ref = {"value": "550e8400-e29b-41d4-a716-446655440000", "type": "uuid"}
        assert I.generate_candidates(ref) == []

    def test_objectid_counter_decrement(self):
        ref = {"value": "507f1f77bcf86cd799439011", "type": "mongo_objectid"}
        cands = I.generate_candidates(ref)
        assert cands and all(c[:18] == "507f1f77bcf86cd799" for c in cands)


class TestSimilarity:
    def test_identical(self):
        assert I.response_similarity("hello world foo bar", "hello world foo bar") == 1.0

    def test_disjoint(self):
        s = I.response_similarity("alpha beta gamma delta",
                                  "one two three four five six")
        assert s < 0.3

    def test_empty_vs_content(self):
        assert I.response_similarity("", "content here") == 0.0


VICTIM_DATA = ("<html><body>Account: Alice Smith, Balance: $14,203.55, "
               "SSN: 555-01-2031, Email: alice@corp.test</body></html>")
DENIED_PAGE = "<html><body><h1>403 Forbidden</h1>Access denied.</body></html>"
ATTACKER_OWN = ("<html><body>Account: Bob Jones, Balance: $12.00, "
                "SSN: 555-99-0000, Email: bob@corp.test</body></html>")


class TestClassifier:
    def test_confirmed_idor(self):
        # Attacker fetches victim's id and gets the victim's data verbatim.
        out = I.classify_idor(
            {"status": 200, "body": VICTIM_DATA},
            {"status": 200, "body": VICTIM_DATA},
            denied_baseline={"status": 403, "body": DENIED_PAGE})
        assert out["verdict"] == "confirmed"
        assert out["severity"] == "HIGH"

    def test_proper_denial_by_status(self):
        out = I.classify_idor(
            {"status": 200, "body": VICTIM_DATA},
            {"status": 403, "body": DENIED_PAGE})
        assert out["verdict"] == "denied"

    def test_soft_denial_matches_baseline(self):
        # App returns 200 but with the generic denied page (soft 403).
        out = I.classify_idor(
            {"status": 200, "body": VICTIM_DATA},
            {"status": 200, "body": DENIED_PAGE},
            denied_baseline={"status": 200, "body": DENIED_PAGE})
        assert out["verdict"] == "denied"

    def test_attacker_own_object_not_flagged(self):
        # Attacker gets 200 but it's THEIR data, not the victim's -> inconclusive.
        out = I.classify_idor(
            {"status": 200, "body": VICTIM_DATA},
            {"status": 200, "body": ATTACKER_OWN})
        assert out["verdict"] == "inconclusive"


class TestOrchestrator:
    def test_audit_confirms_with_two_contexts(self):
        def as_victim(oid):
            return {"status": 200, "body": VICTIM_DATA}

        def as_attacker(oid):
            # Attacker can read everyone's record -> IDOR.
            return {"status": 200, "body": VICTIM_DATA if oid == "42"
                    else DENIED_PAGE}

        out = I.audit_idor("https://app/api?user_id=42", "42",
                           fetch_as_victim=as_victim,
                           fetch_as_attacker=as_attacker,
                           denied_id="999999")
        assert out["verdict"] == "confirmed"
        assert out["victim_id"] == "42"

    def test_audit_denied_when_authz_enforced(self):
        def as_victim(oid):
            return {"status": 200, "body": VICTIM_DATA}

        def as_attacker(oid):
            return {"status": 403, "body": DENIED_PAGE}

        out = I.audit_idor("https://app/api?user_id=42", "42",
                           fetch_as_victim=as_victim,
                           fetch_as_attacker=as_attacker)
        assert out["verdict"] == "denied"
