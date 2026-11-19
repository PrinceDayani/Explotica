"""Tests for the CSV and SARIF exporters."""
import csv
import json

from explotica.core.models import CVE, Host, Port, ScanResult
from explotica.output.exporters import build_sarif, write_csv, write_sarif


def _sample() -> ScanResult:
    cve = CVE(id="CVE-2021-44228", severity="CRITICAL", cvss=10.0,
              summary="Log4Shell", in_kev=True, epss_score=0.97)
    port = Port(number=8080, protocol="tcp", state="open", service="http",
                product_name="apache", product_version="2.4.1", cves=[cve])
    bare = Port(number=22, protocol="tcp", state="open", service="ssh")
    host = Host(ip="10.0.0.5", hostname="web1", ports=[port, bare])
    empty = Host(ip="10.0.0.6", ports=[])
    return ScanResult(target="10.0.0.0/24", started_at="t0", finished_at="t1",
                      duration_s=1.0, hosts=[host, empty],
                      scanner_version="9.9.9")


def test_csv_rows(tmp_path):
    out = write_csv(_sample(), tmp_path / "o.csv")
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    # CVE row + bare-port row + empty-host row = 3
    assert len(rows) == 3
    cve_row = next(r for r in rows if r["cve_id"])
    assert cve_row["ip"] == "10.0.0.5"
    assert cve_row["port"] == "8080"
    assert cve_row["in_kev"] == "true"
    assert cve_row["severity"] == "CRITICAL"
    # bare open port with no CVE still present
    assert any(r["port"] == "22" and not r["cve_id"] for r in rows)
    # empty host still inventoried
    assert any(r["ip"] == "10.0.0.6" and not r["port"] for r in rows)


def test_sarif_shape(tmp_path):
    log = build_sarif(_sample())
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "Explotica"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["CVE-2021-44228"]
    res = run["results"]
    assert len(res) == 1
    assert res[0]["ruleId"] == "CVE-2021-44228"
    assert res[0]["level"] == "error"
    assert "10.0.0.5:8080/tcp" in (
        res[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    )


def test_sarif_written_is_valid_json(tmp_path):
    out = write_sarif(_sample(), tmp_path / "o.sarif")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["runs"][0]["results"][0]["ruleId"] == "CVE-2021-44228"


def test_empty_scan_sarif_has_no_results():
    empty = ScanResult(target="x", started_at="t0", finished_at="t1",
                       duration_s=0.0, hosts=[])
    log = build_sarif(empty)
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []
