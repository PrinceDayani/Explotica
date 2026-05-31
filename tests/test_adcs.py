"""Offline verification of the ADCS ESC analyzers.

ESC conditions are pure booleans over template/CA attribute dicts plus a DACL
check, so we build templates with real enrollment-granting security
descriptors and assert the right ESC fires (and, importantly, does NOT fire
when a precondition is absent).
"""

from explotica.ad import adcs
from explotica.ad.secdesc import (ADS_RIGHT_DS_CONTROL_ACCESS, GENERIC_ALL,
                                  GENERIC_WRITE)
from tests.test_secdesc import make_sd, make_object_ace, make_allowed_ace

DOMAIN_USERS = "S-1-5-21-1111111111-2222222222-3333333333-513"
DOMAIN_ADMIN = "S-1-5-21-1111111111-2222222222-3333333333-512"


def enroll_sd(sid=DOMAIN_USERS):
    """SD granting the Certificate-Enrollment extended right to `sid`."""
    return make_sd([make_object_ace(ADS_RIGHT_DS_CONTROL_ACCESS, sid,
                                    adcs.GUID_ENROLL)])


def base_template(**over):
    tpl = {
        "name": "VulnTemplate", "display_name": "Vuln Template",
        "name_flag": 0, "enrollment_flag": 0, "ra_signature": 0,
        "ekus": [adcs.EKU_CLIENT_AUTH], "schema_version": 2,
        "sd_blob": enroll_sd(),
    }
    tpl.update(over)
    return tpl


class TestESC1:
    def test_fires(self):
        tpl = base_template(name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        escs = {f["esc"] for f in adcs.analyze_template(tpl)}
        assert "ESC1" in escs

    def test_not_when_manager_approval(self):
        tpl = base_template(
            name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            enrollment_flag=adcs.CT_FLAG_PEND_ALL_REQUESTS)
        assert "ESC1" not in {f["esc"] for f in adcs.analyze_template(tpl)}

    def test_not_when_signature_required(self):
        tpl = base_template(
            name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, ra_signature=1)
        assert "ESC1" not in {f["esc"] for f in adcs.analyze_template(tpl)}

    def test_not_when_only_admin_can_enroll(self):
        tpl = base_template(
            name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            sd_blob=enroll_sd(DOMAIN_ADMIN))
        assert "ESC1" not in {f["esc"] for f in adcs.analyze_template(tpl)}

    def test_not_when_no_auth_eku(self):
        tpl = base_template(
            name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            ekus=[adcs.EKU_SERVER_AUTH])  # server-auth only, can't auth as user
        assert "ESC1" not in {f["esc"] for f in adcs.analyze_template(tpl)}

    def test_severity_critical(self):
        tpl = base_template(name_flag=adcs.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        f = [x for x in adcs.analyze_template(tpl) if x["esc"] == "ESC1"][0]
        assert f["severity"] == "CRITICAL"


class TestESC2:
    def test_any_purpose(self):
        tpl = base_template(ekus=[adcs.EKU_ANY_PURPOSE])
        assert "ESC2" in {f["esc"] for f in adcs.analyze_template(tpl)}

    def test_no_eku(self):
        tpl = base_template(ekus=[])
        assert "ESC2" in {f["esc"] for f in adcs.analyze_template(tpl)}


class TestESC3:
    def test_enrollment_agent(self):
        tpl = base_template(ekus=[adcs.EKU_ENROLLMENT_AGENT])
        assert "ESC3" in {f["esc"] for f in adcs.analyze_template(tpl)}


class TestESC4:
    def test_writable_template(self):
        tpl = base_template(
            sd_blob=make_sd([make_allowed_ace(GENERIC_WRITE, DOMAIN_USERS)]))
        escs = {f["esc"] for f in adcs.analyze_template(tpl)}
        assert "ESC4" in escs

    def test_generic_all_is_write(self):
        tpl = base_template(
            sd_blob=make_sd([make_allowed_ace(GENERIC_ALL, DOMAIN_USERS)]))
        assert "ESC4" in {f["esc"] for f in adcs.analyze_template(tpl)}


class TestCA:
    def test_esc6_unknown_when_no_edit_flags(self):
        findings = adcs.analyze_ca({"name": "CORP-CA", "dns_host": "ca.corp.local",
                                    "sd_blob": b"", "edit_flags": None})
        esc6 = [f for f in findings if f["esc"] == "ESC6"][0]
        assert esc6.get("requires_verification") is True

    def test_esc6_critical_when_flag_set(self):
        findings = adcs.analyze_ca({"name": "CORP-CA", "dns_host": "ca",
                                    "sd_blob": b"", "edit_flags": 0x00040000})
        esc6 = [f for f in findings if f["esc"] == "ESC6"][0]
        assert esc6["severity"] == "CRITICAL"

    def test_esc7_low_priv_control(self):
        findings = adcs.analyze_ca({
            "name": "CORP-CA", "dns_host": "ca",
            "sd_blob": make_sd([make_allowed_ace(GENERIC_ALL, DOMAIN_USERS)]),
            "edit_flags": 0})
        assert "ESC7" in {f["esc"] for f in findings}


class TestHelpers:
    def test_is_low_priv(self):
        assert adcs.is_low_priv("S-1-5-11")        # Authenticated Users
        assert adcs.is_low_priv(DOMAIN_USERS)      # -513
        assert not adcs.is_low_priv(DOMAIN_ADMIN)  # -512

    def test_auth_capable(self):
        assert adcs._is_auth_capable([adcs.EKU_CLIENT_AUTH])
        assert adcs._is_auth_capable([])            # no EKU = any purpose
        assert adcs._is_auth_capable([adcs.EKU_ANY_PURPOSE])
        assert not adcs._is_auth_capable([adcs.EKU_SERVER_AUTH])

    def test_parse_template_entry(self):
        entry = {"attributes": {
            "cn": ["WebServer"],
            "msPKI-Certificate-Name-Flag": ["1"],
            "msPKI-Enrollment-Flag": ["0"],
            "pKIExtendedKeyUsage": [adcs.EKU_CLIENT_AUTH],
            "nTSecurityDescriptor": [enroll_sd()],
        }}
        tpl = adcs.parse_template_entry(entry)
        assert tpl["name"] == "WebServer"
        assert tpl["name_flag"] == 1
        assert tpl["ekus"] == [adcs.EKU_CLIENT_AUTH]
        assert isinstance(tpl["sd_blob"], (bytes, bytearray))
