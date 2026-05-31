"""Offline verification of active JWT manipulation.

The crypto is real: we mint tokens with known secrets and prove the auditor
recovers them, that forgeries verify, and that strong secrets resist cracking.
"""

import time

from explotica.active import jwt_audit as J


def make_token(payload, secret, alg="HS256", header_extra=None):
    return J.forge_with_secret(payload, secret, alg=alg, extra_header=header_extra)


class TestCodec:
    def test_decode_roundtrip(self):
        tok = make_token({"sub": "alice", "admin": False}, "secret")
        dec = J.decode_jwt(tok)
        assert dec["payload"] == {"sub": "alice", "admin": False}
        assert dec["alg"] == "HS256"

    def test_decode_rejects_malformed(self):
        assert J.decode_jwt("not.a.jwt.token") is None
        assert J.decode_jwt("onlyonepart") is None

    def test_b64url_no_padding(self):
        # Encoded segments must not contain '=' padding (JWT requirement).
        tok = make_token({"a": 1}, "k")
        assert "=" not in tok


class TestSignVerify:
    def test_verify_correct_secret(self):
        tok = make_token({"sub": "x"}, "topsecret")
        assert J.verify_hmac(tok, "topsecret") is True

    def test_verify_wrong_secret(self):
        tok = make_token({"sub": "x"}, "topsecret")
        assert J.verify_hmac(tok, "wrong") is False

    def test_hs384_hs512(self):
        for alg in ("HS384", "HS512"):
            tok = make_token({"sub": "x"}, "k", alg=alg)
            assert J.verify_hmac(tok, "k") is True
            assert J.verify_hmac(tok, "k2") is False


class TestSecretCracking:
    def test_cracks_default_wordlist_secret(self):
        tok = make_token({"sub": "alice"}, "secret")
        assert J.crack_hmac_secret(tok) == "secret"

    def test_cracks_custom_wordlist(self):
        tok = make_token({"sub": "alice"}, "Hunter#2024")
        assert J.crack_hmac_secret(tok, ["nope", "Hunter#2024", "x"]) == "Hunter#2024"

    def test_strong_secret_not_cracked(self):
        tok = make_token({"sub": "alice"}, "f9c2b7e1-not-in-any-wordlist-4471")
        assert J.crack_hmac_secret(tok) is None

    def test_non_hmac_returns_none(self):
        # An alg:none token has no HMAC to crack.
        tok = J.forge_alg_none({"sub": "x"})[0]["token"]
        assert J.crack_hmac_secret(tok) is None


class TestForgeries:
    def test_alg_none_variants(self):
        forced = J.forge_alg_none({"sub": "admin"})
        variants = {f["alg_variant"] for f in forced}
        assert variants == {"none", "None", "NONE", "nOnE"}
        for f in forced:
            assert f["token"].endswith(".")  # empty signature

    def test_alg_confusion_verifies_with_pubkey(self):
        pub = "-----BEGIN PUBLIC KEY-----\nMFkw...fakepem...\n-----END PUBLIC KEY-----"
        forg = J.forge_alg_confusion({"sub": "admin"}, pub)
        # The forged HS256 token must verify when the public key is the secret.
        assert J.verify_hmac(forg["token"], pub) is True

    def test_kid_injection_tokens_valid(self):
        forged = J.forge_kid_injection({"sub": "admin"})
        attacks = {f["attack"] for f in forged}
        assert "kid_path_traversal" in attacks
        # /dev/null forgery is signed with an empty key.
        null = [f for f in forged if f["attack"] == "kid_path_traversal"][0]
        assert J.verify_hmac(null["token"], b"") is True

    def test_jku_ssrf(self):
        f = J.forge_jku_ssrf({"sub": "x"}, "https://evil/jwks.json")
        assert f["jku"] == "https://evil/jwks.json"


class TestClaims:
    def test_no_exp_flagged(self):
        issues = {i["issue"] for i in J.analyze_claims({"sub": "x"})}
        assert "no_exp" in issues

    def test_expired_flagged(self):
        issues = {i["issue"] for i in
                  J.analyze_claims({"exp": 1000}, now=2000)}
        assert "expired" in issues

    def test_valid_token_no_exp_issue(self):
        issues = {i["issue"] for i in
                  J.analyze_claims({"exp": 9999999999}, now=time.time())}
        assert "expired" not in issues


class TestAuditOrchestrator:
    def test_weak_secret_full_takeover(self):
        tok = make_token({"sub": "alice", "admin": False}, "secret")
        out = J.audit_jwt(tok)
        assert out["cracked_secret"] == "secret"
        assert any(f["issue"] == "weak_hmac_secret" for f in out["findings"])
        # A re-signed escalation forgery must exist and verify.
        tamper = [f for f in out["forgeries"]
                  if f.get("attack") == "claim_tamper_resign"][0]
        assert J.verify_hmac(tamper["token"], "secret")
        assert J.decode_jwt(tamper["token"])["payload"].get("admin") is True

    def test_strong_token_no_crack(self):
        tok = make_token({"sub": "alice"}, "9f8e-uncrackable-secret-0001")
        out = J.audit_jwt(tok)
        assert out["cracked_secret"] is None
        # alg:none + jku candidates are still offered for live testing.
        assert any(f["attack"] == "alg_none" for f in out["forgeries"])

    def test_alg_none_token_flagged(self):
        tok = J.forge_alg_none({"sub": "x"})[0]["token"]
        out = J.audit_jwt(tok)
        assert any(f["issue"] == "alg_none_accepted_by_token"
                   for f in out["findings"])


class TestLiveAcceptanceHonesty:
    def test_acceptance_judged_only_from_server(self):
        forgeries = J.forge_alg_none({"sub": "admin"})

        def fake_send(token):
            return 200  # server accepts everything

        results = J.live_acceptance_test(forgeries, fake_send)
        assert all(r["accepted"] for r in results)
        assert all(r["live_status"] == 200 for r in results)

    def test_rejection_not_assumed_accepted(self):
        forgeries = J.forge_alg_none({"sub": "admin"})
        results = J.live_acceptance_test(forgeries, lambda t: 401)
        assert not any(r["accepted"] for r in results)

    def test_transport_error_is_not_acceptance(self):
        forgeries = J.forge_alg_none({"sub": "x"})

        def boom(token):
            raise OSError("connection refused")

        results = J.live_acceptance_test(forgeries, boom)
        assert all(r["live_status"] == -1 and not r["accepted"]
                   for r in results)
