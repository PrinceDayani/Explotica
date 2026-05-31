"""Offline verification of Golden/Silver ticket *enabler* detection.

Deterministic: every assessment takes an injected reference `now`, and
pwdLastSet is encoded as a real Windows FILETIME relative to it.
"""

from datetime import datetime, timedelta, timezone

from explotica.ad import ticket_risk as T

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_days_ago(days: int) -> str:
    dt = NOW - timedelta(days=days)
    ticks = int((dt - EPOCH).total_seconds() * 10_000_000)
    return str(ticks)


def krbtgt_entry(age_days, enc=None):
    attrs = {"sAMAccountName": ["krbtgt"],
             "pwdLastSet": [filetime_days_ago(age_days)]}
    if enc is not None:
        attrs["msDS-SupportedEncryptionTypes"] = [str(enc)]
    return {"attributes": attrs}


def svc_entry(sam, enc=None, spns=None, uac=0x200, pwd_age=10):
    attrs = {"sAMAccountName": [sam],
             "userAccountControl": [str(uac)],
             "pwdLastSet": [filetime_days_ago(pwd_age)],
             "servicePrincipalName": spns or []}
    if enc is not None:
        attrs["msDS-SupportedEncryptionTypes"] = [str(enc)]
    return {"attributes": attrs}


class TestKrbtgtGolden:
    def test_old_password_high(self):
        f = T.assess_krbtgt(krbtgt_entry(400, enc=T.ENC_AES256), NOW)
        assert f["severity"] == "HIGH"
        assert f["krbtgt_password_age_days"] == 400
        assert f["detection_type"] == "enabler"

    def test_medium_window(self):
        f = T.assess_krbtgt(krbtgt_entry(200, enc=T.ENC_AES256), NOW)
        assert f["severity"] == "MEDIUM"

    def test_recent_is_info(self):
        f = T.assess_krbtgt(krbtgt_entry(30, enc=T.ENC_AES256), NOW)
        assert f["severity"] == "INFO"

    def test_rc4_note_added(self):
        f = T.assess_krbtgt(krbtgt_entry(30, enc=T.ENC_RC4 | T.ENC_AES256), NOW)
        assert "RC4" in f["reason"]

    def test_unset_etypes_treated_rc4(self):
        f = T.assess_krbtgt(krbtgt_entry(30), NOW)  # no enc attr
        assert f["encryption"]["rc4_capable"] is True
        assert "RC4" in f["reason"]


class TestSilver:
    def test_rc4_only_service_account_high(self):
        f = T.assess_silver_risk(
            svc_entry("svc_sql", enc=T.ENC_RC4,
                      spns=["MSSQLSvc/db.corp.local:1433"]), NOW)
        assert f is not None
        assert f["severity"] == "HIGH"
        assert f["kind"] == "silver_ticket_risk"

    def test_aes_service_account_not_flagged(self):
        f = T.assess_silver_risk(
            svc_entry("svc_web", enc=T.ENC_AES256,
                      spns=["HTTP/web.corp.local"]), NOW)
        assert f is None

    def test_unset_etypes_flagged(self):
        f = T.assess_silver_risk(
            svc_entry("svc_legacy", enc=None,
                      spns=["HTTP/legacy.corp.local"]), NOW)
        assert f is not None
        assert f["encryption"]["unset"] is True

    def test_stale_machine_account_flagged(self):
        f = T.assess_silver_risk(
            svc_entry("WS01$", enc=T.ENC_AES256, spns=["HOST/WS01"],
                      uac=0x1000, pwd_age=120), NOW)  # WORKSTATION_TRUST_ACCOUNT
        assert f is not None
        assert "rotation likely disabled" in f["reason"]

    def test_fresh_aes_machine_not_flagged(self):
        f = T.assess_silver_risk(
            svc_entry("WS02$", enc=T.ENC_AES256, spns=["HOST/WS02"],
                      uac=0x1000, pwd_age=15), NOW)
        assert f is None


class TestEtypeSummary:
    def test_unset_is_rc4_only(self):
        s = T.etype_summary(None)
        assert s["unset"] and s["rc4_only"] and s["rc4_capable"]

    def test_aes_only(self):
        s = T.etype_summary(T.ENC_AES128 | T.ENC_AES256)
        assert s["aes_capable"] and not s["rc4_capable"] and not s["rc4_only"]

    def test_mixed(self):
        s = T.etype_summary(T.ENC_RC4 | T.ENC_AES256)
        assert s["rc4_capable"] and s["aes_capable"] and not s["rc4_only"]


class TestAssembly:
    def test_assess_counts_and_honesty_note(self):
        out = T.assess(
            krbtgt_entry(400, enc=T.ENC_RC4),
            [svc_entry("svc_sql", enc=T.ENC_RC4, spns=["MSSQLSvc/db:1433"]),
             svc_entry("svc_web", enc=T.ENC_AES256, spns=["HTTP/web"])],
            now=NOW)
        assert out["summary"]["golden_ticket_risks"] == 1
        assert out["summary"]["silver_ticket_risks"] == 1
        # Honesty: must state these are enablers, not active-forgery detections.
        assert "not detections of active forged" in out["note"]
        assert all(f["detection_type"] == "enabler" for f in out["findings"])
