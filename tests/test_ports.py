"""TCP port scanner — state classification + IANA fallback."""

import errno

import pytest

from explotica.models import Port
from explotica.ports import (
    ALL_TCP_PORTS, IANA_SERVICE_HINTS, TOP_100_PORTS,
    _errno_to_state, apply_iana_guess, probe_tcp, scan_ports,
)


class TestErrnoClassification:
    def test_zero_is_open(self):
        state, reason = _errno_to_state(0)
        assert state == "open"
        assert "succeeded" in reason

    def test_econnrefused_is_closed(self):
        state, reason = _errno_to_state(errno.ECONNREFUSED)
        assert state == "closed"
        assert "RST" in reason

    def test_etimedout_is_filtered(self):
        state, reason = _errno_to_state(errno.ETIMEDOUT)
        assert state == "filtered"
        assert "timeout" in reason

    def test_ehostunreach_is_filtered(self):
        state, reason = _errno_to_state(errno.EHOSTUNREACH)
        assert state == "filtered"
        assert "unreachable" in reason

    def test_unknown_errno_is_unknown(self):
        state, _reason = _errno_to_state(9999)
        assert state == "unknown"


class TestPresets:
    def test_top100_has_100ish(self):
        assert 50 < len(TOP_100_PORTS) < 120

    def test_all_tcp_is_full_range(self):
        assert len(ALL_TCP_PORTS) == 65535
        assert ALL_TCP_PORTS[0] == 1
        assert ALL_TCP_PORTS[-1] == 65535


class TestIANAGuess:
    def test_known_port_gets_label(self):
        p = Port(number=22, state="open")
        apply_iana_guess(p)
        assert p.service == "ssh"
        assert p.iana_guess is True

    def test_does_not_overwrite_evidence(self):
        p = Port(number=22, state="open", service="http",
                  iana_guess=False)
        apply_iana_guess(p)
        # service was already set with evidence — should not change
        assert p.service == "http"
        assert p.iana_guess is False

    def test_closed_port_not_labeled(self):
        p = Port(number=22, state="closed")
        apply_iana_guess(p)
        assert p.service is None

    def test_unknown_port_no_label(self):
        p = Port(number=65000, state="open")
        apply_iana_guess(p)
        assert p.service is None

    def test_iana_hints_has_common_ports(self):
        # Verify the hint table covers what the test expects
        assert IANA_SERVICE_HINTS[22] == "ssh"
        assert IANA_SERVICE_HINTS[80] == "http"
        assert IANA_SERVICE_HINTS[443] == "https"
        assert IANA_SERVICE_HINTS[3306] == "mysql"


@pytest.mark.network
class TestProbeTCP:
    """These hit localhost — fast, no external network needed."""

    def test_probe_returns_port_object(self):
        result = probe_tcp("127.0.0.1", 1, timeout=0.3)
        assert isinstance(result, Port)
        assert result.number == 1

    def test_probe_closed_port_localhost(self):
        # Port 1 is almost never open
        result = probe_tcp("127.0.0.1", 1, timeout=0.3)
        # Localhost will refuse (closed) or timeout (filtered)
        assert result.state in ("closed", "filtered")
        assert result.state_reason

    def test_scan_ports_filters_states(self):
        # All-closed ports — include_closed=False should return empty
        results = scan_ports("127.0.0.1", [1, 2, 3], timeout=0.3,
                              include_closed=False,
                              include_filtered=False)
        assert results == []

    def test_scan_ports_include_filtered(self):
        results = scan_ports("127.0.0.1", [1, 2, 3], timeout=0.3,
                              include_closed=True,
                              include_filtered=True)
        # We get back 3 Port objects regardless of state
        assert all(isinstance(r, Port) for r in results)
