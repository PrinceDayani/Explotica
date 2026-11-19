"""Basic classification tests for the previously-untested port_classifier."""
from explotica.core import port_classifier as pc


def test_http_ports():
    assert pc.is_http(80)
    assert pc.is_http(8080)
    assert not pc.is_http(443)  # that's https


def test_https_and_tls():
    assert pc.is_https(443)
    assert pc.is_tls(443)


def test_http_like_covers_alt_ports():
    assert pc.is_http_like(80)
    assert pc.is_http_like(443)
    assert pc.is_http_like(8443)


def test_database_ports():
    assert pc.is_database(3306)   # mysql
    assert pc.is_database(5432)   # postgres
    assert not pc.is_database(80)


def test_infra_ports():
    assert pc.is_dns(53)
    assert pc.is_smb(445)
    assert pc.is_remote_admin(22)   # ssh
    assert not pc.is_remote_admin(80)
