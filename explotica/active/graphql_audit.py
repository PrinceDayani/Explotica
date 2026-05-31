"""GraphQL security audit — depth/cost analysis + field-level fuzzing.

Phase 73B. The existing `http_audit.graphql_introspect` only confirms that
introspection is enabled and counts types. The limitation: "GraphQL support is
introspection-only — no query depth/cost analysis, no field-level fuzz." This
module adds the analysis that actually finds GraphQL-specific vulns:

  - Query depth + cost/complexity calculation for an arbitrary operation.
  - Schema cycle detection — type relationships like User.posts -> Post.author
    -> User let an attacker nest a query unboundedly = denial of service.
  - Deep-query PoC generation from a detected cycle (the actual DoS payload).
  - Alias-based amplification detection (one request, N copies of an
    expensive field).
  - Field-level fuzzing: surface sensitive fields (password/token/secret/…)
    from the schema, and — when introspection is DISABLED — harvest field
    names from the server's "Did you mean …?" suggestion errors.

Honesty: the parser/analyzers are pure functions over a schema JSON and query
strings (offline unit tests). Sending probe queries to a live endpoint is a
separate, caller-driven step; the suggestion harvester parses real server
errors and never invents field names.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

# Field-name patterns that warrant a closer look if exposed in the schema.
SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(password|passwd|secret|token|apikey|api_key|private|ssn|credit|"
    r"card|cvv|salt|hash|seed|mnemonic|otp|recovery|sessionid|session_id|"
    r"authorization|bearer|refresh)", re.IGNORECASE)


# ── introspection schema parsing ─────────────────────────────────────────
def _resolve_type(type_ref: dict) -> tuple[Optional[str], bool]:
    """Unwrap a GraphQL type reference -> (named_type, is_list)."""
    is_list = False
    cur = type_ref
    while cur:
        kind = cur.get("kind")
        if kind == "LIST":
            is_list = True
        if cur.get("name") and kind not in ("LIST", "NON_NULL"):
            return cur["name"], is_list
        cur = cur.get("ofType")
    return None, is_list


def parse_introspection(schema_json: dict) -> dict:
    """Build a {type_name: {field: {type, is_list}}} map from introspection."""
    schema = schema_json.get("data", schema_json).get("__schema", {})
    type_map: dict[str, dict] = {}
    for t in schema.get("types", []):
        name = t.get("name")
        if not name or name.startswith("__"):
            continue
        if t.get("kind") not in ("OBJECT", "INTERFACE"):
            continue
        fields: dict[str, dict] = {}
        for f in t.get("fields") or []:
            named, is_list = _resolve_type(f.get("type", {}))
            fields[f["name"]] = {"type": named, "is_list": is_list}
        type_map[name] = {"kind": t.get("kind"), "fields": fields}
    return type_map


# ── query parsing: depth / cost / aliases ────────────────────────────────
def _strip(query: str) -> str:
    """Remove string literals and comments so brace counting is reliable."""
    query = re.sub(r'"""(?:.|\n)*?"""', '""', query)
    query = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
    query = re.sub(r"#[^\n]*", "", query)
    return query


def query_depth(query: str) -> int:
    """Maximum selection-set nesting depth of a GraphQL operation."""
    s = _strip(query)
    depth = max_depth = 0
    for ch in s:
        if ch == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == "}":
            depth = max(0, depth - 1)
    # The outermost { } is the operation selection set (depth 1 = top fields).
    return max_depth


def count_aliases(query: str) -> int:
    """Count field aliases (alias: field) — the batching/amplification signal."""
    s = _strip(query)
    return len(re.findall(r"[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*", s))


def query_cost(query: str, type_map: Optional[dict] = None, *,
               list_multiplier: int = 10) -> int:
    """Estimate query cost: each field = 1, fields returning lists weight more.

    Without a schema we approximate by depth (deeper = costlier); with a schema
    we weight list-returning fields by `list_multiplier`.
    """
    s = _strip(query)
    field_tokens = re.findall(r"[A-Za-z_]\w*", s)
    cost = 0
    list_fields = set()
    if type_map:
        for t in type_map.values():
            for fname, meta in t["fields"].items():
                if meta["is_list"]:
                    list_fields.add(fname)
    for tok in field_tokens:
        if tok in ("query", "mutation", "subscription", "fragment", "on",
                   "true", "false", "null"):
            continue
        cost += list_multiplier if tok in list_fields else 1
    # Depth amplifies cost (nested lists multiply server work).
    return cost * max(1, query_depth(query))


# ── schema cycle detection (depth-DoS substrate) ─────────────────────────
def find_cycles(type_map: dict, *, max_cycles: int = 10) -> list[list[str]]:
    """Find object-type reference cycles. Each cycle is a list ending where it
    began, e.g. ['User', 'Post', 'User']."""
    adj: dict[str, set] = {}
    for tname, t in type_map.items():
        targets = set()
        for meta in t["fields"].values():
            ref = meta["type"]
            if ref in type_map and ref != tname:
                targets.add(ref)
            elif ref == tname:
                targets.add(tname)  # self-reference is a trivial cycle
        adj[tname] = targets

    cycles: list[list[str]] = []
    seen_keys: set = set()

    def dfs(start, node, path, visiting):
        if len(cycles) >= max_cycles:
            return
        for nxt in adj.get(node, ()):
            if nxt == start and len(path) >= 1:
                cycle = path + [start]
                key = frozenset(path)
                if key not in seen_keys:
                    seen_keys.add(key)
                    cycles.append(cycle)
            elif nxt not in visiting and len(path) < 6:
                dfs(start, nxt, path + [nxt], visiting | {nxt})

    for tname in type_map:
        if len(cycles) >= max_cycles:
            break
        dfs(tname, tname, [tname], {tname})
    return cycles


def generate_deep_query(cycle: list[str], type_map: dict, *,
                        repeats: int = 12) -> Optional[str]:
    """Build a deeply-nested DoS PoC query by repeating a type cycle.

    `cycle` like ['User','Post','User']; we walk the field edges that realize
    it and nest them `repeats` times.
    """
    if len(cycle) < 2:
        return None
    # Resolve the field name that goes from cycle[i] -> cycle[i+1].
    edges = []
    for a, b in zip(cycle, cycle[1:]):
        field = next((fn for fn, m in type_map.get(a, {}).get("fields", {}).items()
                      if m["type"] == b), None)
        if field is None:
            return None
        edges.append(field)
    # Find an entry field on the root Query type that returns cycle[0].
    root = type_map.get("Query", {}).get("fields", {})
    entry = next((fn for fn, m in root.items() if m["type"] == cycle[0]), None)
    inner = "id"
    body = inner
    for _ in range(repeats):
        for field in reversed(edges):
            body = f"{field} {{ {body} }}"
    selection = f"{entry} {{ {body} }}" if entry else f"{cycle[0].lower()} {{ {body} }}"
    return f"query DepthDoS {{ {selection} }}"


# ── field-level fuzzing ──────────────────────────────────────────────────
def sensitive_fields(type_map: dict) -> list[dict]:
    """List schema fields whose names match sensitive patterns."""
    out = []
    for tname, t in type_map.items():
        for fname in t["fields"]:
            if SENSITIVE_FIELD_PATTERNS.search(fname):
                out.append({"type": tname, "field": fname,
                            "severity": "MEDIUM",
                            "note": "Sensitive field exposed in schema — verify "
                                    "authorization on this field"})
    return out


_SUGGESTION_RE = re.compile(r"Did you mean ([^?]+)\?")
_QUOTED_RE = re.compile(r"[\"'`]([A-Za-z_]\w*)[\"'`]")


def parse_field_suggestions(error_response) -> list[str]:
    """Harvest field names from GraphQL 'Did you mean …?' suggestion errors.

    Works even when introspection is disabled — the server leaks valid field
    names in its validation errors. Parses real error text; invents nothing.
    """
    if isinstance(error_response, (bytes, bytearray)):
        error_response = error_response.decode("utf-8", "replace")
    if isinstance(error_response, str):
        try:
            error_response = json.loads(error_response)
        except json.JSONDecodeError:
            text = error_response
            return _extract_suggestions(text)
    messages = []
    for err in (error_response.get("errors") or []):
        if isinstance(err, dict) and err.get("message"):
            messages.append(err["message"])
    found: list[str] = []
    for m in messages:
        found.extend(_extract_suggestions(m))
    # de-dupe, preserve order
    seen, out = set(), []
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _extract_suggestions(text: str) -> list[str]:
    out: list[str] = []
    for frag in _SUGGESTION_RE.findall(text):
        out.extend(_QUOTED_RE.findall(frag))
    return out


# ── orchestrator ──────────────────────────────────────────────────────────
DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_COST = 1000


def audit_schema(schema_json: dict, *, max_depth: int = DEFAULT_MAX_DEPTH,
                 max_cost: int = DEFAULT_MAX_COST) -> dict:
    """Full offline schema audit: cycles, depth-DoS PoCs, sensitive fields."""
    type_map = parse_introspection(schema_json)
    cycles = find_cycles(type_map)
    findings: list[dict] = []
    poc = None
    if cycles:
        poc = generate_deep_query(cycles[0], type_map)
        findings.append({
            "issue": "schema_cycle_depth_dos", "severity": "HIGH",
            "cycle": " -> ".join(cycles[0]),
            "note": "Type cycle enables unbounded query nesting (DoS). Enforce "
                    "a query depth limit and/or cost analysis.",
            "poc_query": poc})
    sens = sensitive_fields(type_map)
    findings.extend(sens)
    return {
        "type_count": len(type_map),
        "cycles": cycles,
        "sensitive_fields": sens,
        "depth_dos_poc": poc,
        "recommended_limits": {"max_depth": max_depth, "max_cost": max_cost},
        "findings": findings,
    }


def evaluate_query(query: str, type_map: Optional[dict] = None, *,
                   max_depth: int = DEFAULT_MAX_DEPTH,
                   max_cost: int = DEFAULT_MAX_COST,
                   max_aliases: int = 15) -> dict:
    """Score one query against depth/cost/alias thresholds."""
    depth = query_depth(query)
    cost = query_cost(query, type_map)
    aliases = count_aliases(query)
    issues = []
    if depth > max_depth:
        issues.append({"issue": "excessive_depth", "severity": "HIGH",
                       "value": depth, "limit": max_depth})
    if cost > max_cost:
        issues.append({"issue": "excessive_cost", "severity": "HIGH",
                       "value": cost, "limit": max_cost})
    if aliases > max_aliases:
        issues.append({"issue": "alias_amplification", "severity": "MEDIUM",
                       "value": aliases, "limit": max_aliases})
    return {"depth": depth, "cost": cost, "aliases": aliases, "issues": issues}
