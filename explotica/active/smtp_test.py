"""SMTP audits — open-relay test + VRFY/EXPN user enumeration.

  - Open relay test: speak SMTP enough to determine if the server accepts
    mail from an external sender to an external recipient. Critically we
    DON'T actually deliver — we send MAIL FROM + RCPT TO + QUIT (no DATA).
    A 250 OK on RCPT for an external recipient = open relay.

  - VRFY/EXPN enumeration: many MTAs respond to VRFY (verify user exists)
    or EXPN (expand mailing list). When enabled, these allow username
    enumeration. Disabled by default on modern Postfix/Sendmail/Exim.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

log = logging.getLogger(__name__)


def _read_response(sock: socket.socket, timeout: float = 3.0) -> str:
    """Read a SMTP response (one or more lines ending in 'NNN ')."""
    sock.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sock.recv(1024)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        # End of response: line starting with 3 digits + space (vs '-')
        text = buf.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        for line in lines[:-1]:  # last empty
            if len(line) >= 4 and line[0:3].isdigit() and line[3] == " ":
                return text
        if len(buf) > 16384:
            break
    return buf.decode("utf-8", errors="replace")


def _send_cmd(sock: socket.socket, cmd: str, timeout: float = 3.0) -> str:
    """Send an SMTP command line, return response."""
    sock.sendall((cmd + "\r\n").encode())
    return _read_response(sock, timeout=timeout)


def test_open_relay(host: str, port: int = 25, *,
                     from_addr: str = "explotica-relay-test@example.com",
                     to_addr: str = "external-recipient@example.org",
                     timeout: float = 6.0) -> Optional[dict]:
    """Test whether the SMTP server accepts external→external mail.

    We DO NOT send DATA — we abort right after RCPT TO.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        greeting = _read_response(sock, timeout=timeout)
        if not greeting.startswith("220"):
            sock.close()
            return None

        # EHLO
        ehlo_resp = _send_cmd(sock, "EHLO explotica.example.com")
        if not ehlo_resp.startswith("250"):
            # Fall back to HELO
            _send_cmd(sock, "HELO explotica.example.com")

        # MAIL FROM
        mail_resp = _send_cmd(sock, f"MAIL FROM:<{from_addr}>")
        mail_ok = mail_resp.startswith("250")

        # RCPT TO (external)
        rcpt_resp = _send_cmd(sock, f"RCPT TO:<{to_addr}>")
        rcpt_ok = rcpt_resp.startswith("250")

        # IMMEDIATELY abort — don't send DATA
        _send_cmd(sock, "RSET")
        _send_cmd(sock, "QUIT")
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("SMTP relay test %s:%d failed: %s", host, port, e)
        return None

    result = {
        "greeting": greeting.strip()[:100],
        "ehlo_response": ehlo_resp.strip()[:200],
        "mail_from_accepted": mail_ok,
        "rcpt_to_accepted": rcpt_ok,
        "rcpt_response": rcpt_resp.strip()[:200],
        "from_addr": from_addr,
        "to_addr": to_addr,
    }

    if mail_ok and rcpt_ok:
        result["finding"] = "OPEN_RELAY"
        result["severity"] = "CRITICAL"
        result["note"] = ("Server accepted MAIL FROM external + RCPT TO external — "
                          "open relay. Verify manually before exploitation.")
    elif mail_ok and not rcpt_ok:
        result["finding"] = "PROTECTED"
        result["severity"] = "INFO"
        result["note"] = "Server requires recipient be local — not an open relay"
    else:
        result["finding"] = "UNCLEAR"
        result["severity"] = "INFO"
        result["note"] = "Server rejected MAIL FROM (may require auth or specific senders)"
    return result


def vrfy_expn_enum(host: str, port: int = 25,
                    usernames: Optional[list[str]] = None,
                    timeout: float = 4.0) -> dict:
    """Test VRFY/EXPN commands against a list of usernames.

    Returns dict with:
      - vrfy_enabled (bool)
      - expn_enabled (bool)
      - users_found: list of usernames with positive VRFY/EXPN responses
    """
    usernames = usernames or [
        "root", "admin", "administrator", "test", "user",
        "postmaster", "info", "webmaster", "noreply", "support",
        "service", "backup", "sales", "ftp", "mysql",
    ]

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        greeting = _read_response(sock, timeout=timeout)
        if not greeting.startswith("220"):
            sock.close()
            return {"error": "no_smtp_greeting"}
        _send_cmd(sock, "EHLO explotica.example.com")
    except (socket.timeout, OSError):
        return {"error": "connection_failed"}

    # Check VRFY availability with a known-bad name
    test_resp = _send_cmd(sock, "VRFY nonexistent-user-12345")
    vrfy_enabled = not (test_resp.startswith("502") or test_resp.startswith("252"))

    test_resp = _send_cmd(sock, "EXPN nonexistent-list-12345")
    expn_enabled = not test_resp.startswith("502")

    users_found: list[dict] = []
    if vrfy_enabled or expn_enabled:
        for user in usernames:
            if vrfy_enabled:
                r = _send_cmd(sock, f"VRFY {user}")
                code = r[:3] if len(r) >= 3 else "000"
                if code.startswith("250"):
                    users_found.append({"user": user, "via": "VRFY",
                                         "response": r.strip()[:120]})
            if expn_enabled:
                r = _send_cmd(sock, f"EXPN {user}")
                if r.startswith("250"):
                    users_found.append({"user": user, "via": "EXPN",
                                         "response": r.strip()[:120]})

    try:
        _send_cmd(sock, "QUIT")
        sock.close()
    except Exception:
        pass

    return {
        "vrfy_enabled": vrfy_enabled,
        "expn_enabled": expn_enabled,
        "users_found": users_found,
        "severity": ("MEDIUM" if (vrfy_enabled or expn_enabled) else "INFO"),
        "note": ("VRFY/EXPN enabled — user enumeration possible"
                 if (vrfy_enabled or expn_enabled)
                 else "VRFY/EXPN disabled (modern default)"),
    }


def audit_smtp(host: str, port: int = 25, timeout: float = 6.0) -> dict:
    """Run all SMTP audits on one host:port."""
    findings: dict = {}
    relay = test_open_relay(host, port, timeout=timeout)
    if relay:
        findings["relay_test"] = relay
    vrfy = vrfy_expn_enum(host, port, timeout=timeout)
    if vrfy:
        findings["vrfy_expn"] = vrfy
    return findings
