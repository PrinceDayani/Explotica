"""Offline verification of the GraphQL depth/cost + field-fuzz analyzers.

We craft a minimal introspection schema with a real type cycle (User <-> Post)
and assert cycle detection, PoC generation, depth/cost scoring, sensitive-field
surfacing, and suggestion harvesting from real error text.
"""

from explotica.active import graphql_audit as G


def _t(name, fields):
    """fields: {fname: (type_name, is_list)} -> introspection-shaped type."""
    return {"name": name, "kind": "OBJECT", "fields": [
        {"name": fn, "type": _typeref(ty, is_list)}
        for fn, (ty, is_list) in fields.items()]}


def _typeref(name, is_list):
    base = {"kind": "OBJECT", "name": name, "ofType": None}
    return {"kind": "LIST", "name": None, "ofType": base} if is_list else base


SCHEMA = {"data": {"__schema": {"types": [
    _t("Query", {"user": ("User", False), "me": ("User", False)}),
    _t("User", {"id": ("ID", False), "posts": ("Post", True),
                "password": ("String", False)}),
    _t("Post", {"id": ("ID", False), "author": ("User", False),
                "title": ("String", False)}),
    {"name": "__Type", "kind": "OBJECT", "fields": []},  # meta — must be skipped
]}}}


class TestParse:
    def test_builds_type_map(self):
        tm = G.parse_introspection(SCHEMA)
        assert set(tm) == {"Query", "User", "Post"}  # meta-type skipped
        assert tm["User"]["fields"]["posts"]["type"] == "Post"
        assert tm["User"]["fields"]["posts"]["is_list"] is True


class TestCycles:
    def test_detects_user_post_cycle(self):
        tm = G.parse_introspection(SCHEMA)
        cycles = G.find_cycles(tm)
        assert any(set(c) >= {"User", "Post"} for c in cycles)

    def test_poc_query_generated(self):
        tm = G.parse_introspection(SCHEMA)
        cycles = G.find_cycles(tm)
        cyc = next(c for c in cycles if set(c) >= {"User", "Post"})
        poc = G.generate_deep_query(cyc, tm, repeats=5)
        assert poc is not None
        # The PoC must nest the cycle fields deeply.
        assert G.query_depth(poc) >= 10
        assert "posts" in poc and "author" in poc


class TestDepthCost:
    def test_depth(self):
        q = "query { user { posts { author { id } } } }"
        assert G.query_depth(q) == 4

    def test_depth_ignores_braces_in_strings(self):
        q = 'query { user(filter: "a{b}c") { id } }'
        assert G.query_depth(q) == 2

    def test_alias_count(self):
        q = "query { a: user { id } b: user { id } c: user { id } }"
        assert G.count_aliases(q) >= 3

    def test_cost_weights_list_fields(self):
        tm = G.parse_introspection(SCHEMA)
        cheap = G.query_cost("query { me { id } }", tm)
        pricey = G.query_cost("query { user { posts { id } } }", tm)
        assert pricey > cheap

    def test_evaluate_flags_excessive_depth(self):
        deep = "query " + "{ a " * 15 + "id" + " }" * 15
        out = G.evaluate_query(deep, max_depth=10)
        assert any(i["issue"] == "excessive_depth" for i in out["issues"])

    def test_evaluate_flags_alias_amplification(self):
        q = "query { " + " ".join(f"a{i}: me {{ id }}" for i in range(20)) + " }"
        out = G.evaluate_query(q, max_aliases=15)
        assert any(i["issue"] == "alias_amplification" for i in out["issues"])


class TestSensitiveFields:
    def test_surfaces_password_field(self):
        tm = G.parse_introspection(SCHEMA)
        sens = G.sensitive_fields(tm)
        assert any(s["field"] == "password" for s in sens)


class TestSuggestionHarvest:
    def test_parses_did_you_mean_json(self):
        err = {"errors": [{"message": 'Cannot query field "passwrd" on type '
                           '"User". Did you mean "password" or "posts"?'}]}
        fields = G.parse_field_suggestions(err)
        assert "password" in fields and "posts" in fields

    def test_parses_plain_text(self):
        text = 'Cannot query field "x". Did you mean "user"?'
        assert G.parse_field_suggestions(text) == ["user"]

    def test_no_suggestions_empty(self):
        assert G.parse_field_suggestions({"errors": [{"message": "nope"}]}) == []


class TestAudit:
    def test_full_audit_reports_cycle_and_poc(self):
        out = G.audit_schema(SCHEMA)
        assert out["type_count"] == 3
        assert any(f["issue"] == "schema_cycle_depth_dos" for f in out["findings"])
        assert out["depth_dos_poc"] is not None
        assert any(f.get("field") == "password" for f in out["findings"])
