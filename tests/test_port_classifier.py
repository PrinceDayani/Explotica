"""Port classifier — content wins over port-number hints (Phase 57)."""

from explotica.models import Port
from explotica.port_classifier import (
    is_http, is_https, is_http_like, is_tls, is_smb,
    is_dns, is_database, is_remote_admin, is_email,
)


class TestContentWins:
    """Content-based service evidence should override port-number hints."""

    def test_ssh_on_port_80_not_http(self):
        ssh = Port(number=80, state="open", service="ssh", iana_guess=False)
        assert not is_http(ssh)
        assert is_remote_admin(ssh)

    def test_http_on_port_31337_is_http(self):
        http = Port(number=31337, state="open", service="http",
                    iana_guess=False)
        assert is_http(http)

    def test_iana_guess_ignored(self):
        """A guessed service name must NOT count as evidence."""
        p = Port(number=22, state="open", service="ssh", iana_guess=True)
        # Falls back to port-number hint (22 IS in remote-admin)
        assert is_remote_admin(p)
        # Should NOT be classified as http
        assert not is_http(p)


class TestPortNumberFallback:
    """When no service evidence, port-number hints should fire."""

    def test_port_80_alone_is_http(self):
        assert is_http(80)
        assert is_http_like(80)

    def test_port_443_alone_is_https(self):
        assert is_https(443)
        assert is_tls(443)
        assert is_http_like(443)

    def test_port_445_is_smb(self):
        assert is_smb(445)

    def test_port_53_is_dns(self):
        assert is_dns(53)

    def test_port_3306_is_database(self):
        assert is_database(3306)

    def test_port_22_is_remote_admin(self):
        assert is_remote_admin(22)

    def test_port_25_is_email(self):
        assert is_email(25)


class TestAcceptsBothPortAndInt:
    """Back-compat: classifier should accept both Port objects and raw ints."""

    def test_int_form(self):
        assert is_https(443)

    def test_port_form(self):
        assert is_https(Port(number=443, state="open"))

    def test_int_and_port_same_result(self):
        p = Port(number=443, state="open")
        assert is_https(443) == is_https(p)


class TestUnknownPort:
    def test_random_high_port_no_evidence(self):
        """Port 47000 with no service info → no match anywhere."""
        p = Port(number=47000, state="open")
        assert not is_http(p)
        assert not is_https(p)
        assert not is_smb(p)
        assert not is_database(p)
