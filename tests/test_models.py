"""Data model tests — round-trip JSON, defaults, helpers."""

import json

from explotica.models import CVE, Exploit, Host, Port, ScanResult


class TestPort:
    def test_default_state_is_open(self):
        p = Port(number=80)
        assert p.state == "open"
        assert p.protocol == "tcp"
        assert p.service is None
        assert p.iana_guess is False
        assert p.probes_attempted == []

    def test_to_dict_roundtrip(self):
        p = Port(number=443, state="open", service="https",
                 state_reason="tcp-connect succeeded",
                 banner="HTTP/1.1 200", probes_attempted=["passive-read"])
        d = p.to_dict()
        assert d["number"] == 443
        assert d["state"] == "open"
        assert d["service"] == "https"
        assert d["banner"] == "HTTP/1.1 200"

    def test_state_classification_serialized(self):
        for state in ("open", "closed", "filtered", "unknown"):
            p = Port(number=22, state=state, state_reason="test")
            d = p.to_dict()
            assert d["state"] == state


class TestHost:
    def test_open_ports_filters_state(self):
        h = Host(ip="10.0.0.1", ports=[
            Port(number=22, state="open"),
            Port(number=80, state="closed"),
            Port(number=443, state="filtered"),
            Port(number=8080, state="open"),
        ])
        opens = h.open_ports()
        assert len(opens) == 2
        assert {p.number for p in opens} == {22, 8080}

    def test_empty_ports(self):
        h = Host(ip="10.0.0.1")
        assert h.open_ports() == []

    def test_to_dict_basic(self):
        h = Host(ip="10.0.0.1", hostname="srv01", mac="aa:bb:cc:dd:ee:ff",
                 vendor="Dell", is_up=True)
        d = h.to_dict()
        assert d["ip"] == "10.0.0.1"
        assert d["hostname"] == "srv01"


class TestScanResult:
    def test_scanner_version_from_constants(self):
        from explotica.constants import SCANNER_VERSION
        r = ScanResult(target="x", started_at="t", finished_at="t",
                       duration_s=0.0)
        assert r.scanner_version == SCANNER_VERSION

    def test_roundtrip_to_dict_from_dict(self):
        original = ScanResult(
            target="192.168.1.0/24",
            started_at="2026-05-28T00:00:00Z",
            finished_at="2026-05-28T00:01:00Z",
            duration_s=60.0,
            hosts=[Host(ip="192.168.1.1", hostname="rtr",
                         ports=[Port(number=80, state="open",
                                      service="http")])],
            extra_findings={"compliance": {"cis": {"score_pct": 80}}},
        )
        d = original.to_dict()
        # Should be JSON-serializable
        s = json.dumps(d)
        assert "192.168.1.1" in s
        # Round-trip
        d2 = json.loads(s)
        restored = ScanResult.from_dict(d2)
        assert restored.target == original.target
        assert len(restored.hosts) == 1
        assert restored.hosts[0].ports[0].service == "http"


class TestCVE:
    def test_to_dict_includes_all_fields(self):
        c = CVE(id="CVE-2021-44228", severity="CRITICAL", cvss=10.0,
                summary="Log4Shell", epss_score=0.97, in_kev=True)
        d = c.to_dict()
        assert d["id"] == "CVE-2021-44228"
        assert d["severity"] == "CRITICAL"
        assert d["in_kev"] is True
