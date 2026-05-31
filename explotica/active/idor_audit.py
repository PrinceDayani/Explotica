"""IDOR / broken-object-level-authorization testing (deepened).

Phase 73E. The limitation: "No business-logic testing — IDOR detection is
shallow." A shallow IDOR check ("request id+1, got 200 -> vuln") is mostly
false positives: a 200 might be a generic page, a soft-404, or the attacker's
*own* object. Real IDOR confirmation needs two authenticated contexts and a
response comparison:

  victim accesses their object        -> this is what authorized data looks like
  attacker accesses victim's object   -> if the response matches the victim's
                                         authorized data (and isn't the generic
                                         denied/empty page), authorization is
                                         broken.

This module provides:
  - Object-reference detection + typing (numeric / UUID / Mongo ObjectId /
    hex / base64 / hashid) with a predictability score.
  - Candidate mutation generation (neighbors for sequential IDs).
  - A response-similarity metric (Jaccard shingles + length ratio).
  - A two-context classifier that returns confirmed / denied / inconclusive.

Honesty: detection, mutation, similarity, and classification are pure and
offline-unit-tested. Actually fetching objects needs two live sessions;
`audit_idor()` takes an injected request function and never assumes a verdict
the comparison didn't support.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qsl

log = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
_B64_RE = re.compile(r"^[A-Za-z0-9_\-]{6,}={0,2}$")

# Param names that strongly indicate an object reference.
_REF_PARAM_HINTS = re.compile(
    r"(^id$|_id$|^uid$|user|account|order|invoice|doc|file|object|item|"
    r"record|profile|customer|ticket|message|note|report|key|ref|num)",
    re.IGNORECASE)


def classify_reference(value: str) -> dict:
    """Type an identifier value and score how predictable it is (0..1)."""
    v = str(value)
    if _NUM_RE.match(v):
        return {"type": "numeric", "predictability": 1.0,
                "note": "Sequential integer — trivially enumerable"}
    if _UUID_RE.match(v):
        return {"type": "uuid", "predictability": 0.05,
                "note": "UUID — not guessable, but still test if leaked"}
    if _OBJECTID_RE.match(v):
        return {"type": "mongo_objectid", "predictability": 0.4,
                "note": "Mongo ObjectId — timestamp+counter prefix is partly "
                        "predictable"}
    if _HEX_RE.match(v):
        return {"type": "hex", "predictability": 0.2,
                "note": "Hex token"}
    if _B64_RE.match(v):
        return {"type": "base64ish", "predictability": 0.3,
                "note": "Base64-like ref — decode for an inner numeric id"}
    return {"type": "opaque", "predictability": 0.2, "note": "Opaque ref"}


def detect_object_refs(url: str, extra_params: Optional[dict] = None
                       ) -> list[dict]:
    """Find object-reference candidates in a URL's query + path + extra params."""
    refs: list[dict] = []
    parsed = urlparse(url)

    for name, value in parse_qsl(parsed.query):
        if _REF_PARAM_HINTS.search(name) or _NUM_RE.match(value) \
                or _UUID_RE.match(value) or _OBJECTID_RE.match(value):
            refs.append({"location": "query", "param": name, "value": value,
                         **classify_reference(value)})

    # Path segments that look like identifiers (/users/123, /doc/<uuid>).
    segs = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segs):
        if _NUM_RE.match(seg) or _UUID_RE.match(seg) or _OBJECTID_RE.match(seg):
            prev = segs[i - 1] if i > 0 else "path"
            refs.append({"location": "path", "param": prev, "value": seg,
                         "path_index": i, **classify_reference(seg)})

    for name, value in (extra_params or {}).items():
        if _REF_PARAM_HINTS.search(name) or _NUM_RE.match(str(value)):
            refs.append({"location": "body", "param": name, "value": str(value),
                         **classify_reference(str(value))})
    return refs


def generate_candidates(ref: dict, *, count: int = 5) -> list[str]:
    """Generate alternate identifier values to probe for a reference."""
    v = ref["value"]
    out: list[str] = []
    if ref["type"] == "numeric":
        n = int(v)
        for delta in (1, -1, 2, -2, 10):
            cand = n + delta
            if cand >= 0 and str(cand) != v:
                out.append(str(cand))
        for edge in ("0", "1", "999999999"):
            if edge != v and edge not in out:
                out.append(edge)
    elif ref["type"] == "mongo_objectid":
        # Decrement the trailing counter — same timestamp, adjacent object.
        try:
            tail = int(v[-6:], 16)
            for delta in (1, -1, 2):
                out.append(v[:-6] + format((tail + delta) & 0xFFFFFF, "06x"))
        except ValueError:
            pass
    # UUID/opaque: not guessable; caller must supply a known victim id.
    return out[:count]


# ── response similarity ────────────────────────────────────────────────────
def _shingles(text: str, k: int = 4) -> set:
    tokens = re.findall(r"\w+", text.lower())
    if len(tokens) < k:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def response_similarity(a, b) -> float:
    """Similarity in [0,1] combining Jaccard shingle overlap + length ratio."""
    if isinstance(a, (bytes, bytearray)):
        a = a.decode("utf-8", "replace")
    if isinstance(b, (bytes, bytearray)):
        b = b.decode("utf-8", "replace")
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    sa, sb = _shingles(a), _shingles(b)
    if not sa and not sb:
        jac = 1.0
    elif not sa or not sb:
        jac = 0.0
    else:
        jac = len(sa & sb) / len(sa | sb)
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    return round(0.7 * jac + 0.3 * len_ratio, 4)


# ── two-context classifier ────────────────────────────────────────────────
DENIED_STATUSES = {401, 403, 404, 405, 410}
SUCCESS_STATUSES = {200, 201, 202, 203, 206}
CONFIRM_THRESHOLD = 0.85
DENIED_BASELINE_THRESHOLD = 0.9


def classify_idor(victim_authorized: dict, attacker_response: dict, *,
                  denied_baseline: Optional[dict] = None) -> dict:
    """Decide whether attacker access to the victim's object is a real IDOR.

    Each arg: {"status": int, "body": str|bytes}. denied_baseline is an
    example of what a properly-denied response looks like (e.g. attacker
    fetching a definitely-forbidden id), used to avoid flagging generic
    'access denied' pages.
    """
    a_status = attacker_response.get("status", 0)
    a_body = attacker_response.get("body", "")
    v_body = victim_authorized.get("body", "")

    sim_to_victim = response_similarity(a_body, v_body)
    sim_to_denied = (response_similarity(a_body, denied_baseline.get("body", ""))
                     if denied_baseline else 0.0)

    if a_status in DENIED_STATUSES:
        verdict, sev = "denied", "INFO"
        reason = f"Attacker received {a_status} — authorization enforced."
    elif denied_baseline and sim_to_denied >= DENIED_BASELINE_THRESHOLD:
        verdict, sev = "denied", "INFO"
        reason = ("Attacker response matches the denied-baseline page — soft "
                  "denial, not data exposure.")
    elif a_status in SUCCESS_STATUSES and sim_to_victim >= CONFIRM_THRESHOLD:
        verdict, sev = "confirmed", "HIGH"
        reason = (f"Attacker received the victim's object data "
                  f"(similarity {sim_to_victim} >= {CONFIRM_THRESHOLD}) with "
                  f"status {a_status} — broken object-level authorization.")
    elif a_status in SUCCESS_STATUSES:
        verdict, sev = "inconclusive", "LOW"
        reason = (f"Attacker got {a_status} but content differs from the "
                  f"victim's (similarity {sim_to_victim}); may be the "
                  f"attacker's own object or a generic page.")
    else:
        verdict, sev = "inconclusive", "LOW"
        reason = f"Unexpected status {a_status}; cannot conclude."

    return {"verdict": verdict, "severity": sev,
            "similarity_to_victim": sim_to_victim,
            "similarity_to_denied": sim_to_denied,
            "attacker_status": a_status, "reason": reason}


# ── orchestrator ──────────────────────────────────────────────────────────
def audit_idor(url: str, victim_id: str, *,
               fetch_as_victim: Callable[[str], dict],
               fetch_as_attacker: Callable[[str], dict],
               denied_id: Optional[str] = None) -> dict:
    """Confirm IDOR on `url` for `victim_id` using two auth contexts.

    fetch_as_victim(object_id) / fetch_as_attacker(object_id) each perform the
    request in their session and return {"status", "body"}. This is the only
    network-touching part; the verdict comes solely from the real responses.
    """
    victim_authorized = fetch_as_victim(victim_id)
    attacker_response = fetch_as_attacker(victim_id)
    denied_baseline = fetch_as_attacker(denied_id) if denied_id else None
    result = classify_idor(victim_authorized, attacker_response,
                           denied_baseline=denied_baseline)
    result.update({"url": url, "victim_id": victim_id})
    return result
