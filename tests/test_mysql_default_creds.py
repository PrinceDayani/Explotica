"""Active MySQL empty-password check against a controlled fake server.

Verifies the real HandshakeResponse41 exchange end-to-end offline: a tiny
server speaks the MySQL handshake, reads the client's login packet, and
replies OK (empty password accepted) or ERR 1045 (access denied).
"""
import socket
import struct
import threading

from explotica.protocols import mysql_protocol as m
from explotica.active.default_creds import check_mysql_empty_root

_CAPS = (m.CLIENT_PROTOCOL_41 | m.CLIENT_PLUGIN_AUTH | m.CLIENT_SECURE_CONNECTION
         | m.CLIENT_LONG_PASSWORD | m.CLIENT_TRANSACTIONS | m.CLIENT_DEPRECATE_EOF)


def _wrap(body: bytes, seq: int = 0) -> bytes:
    return struct.pack("<I", len(body))[:3] + bytes([seq]) + body


def _handshake() -> bytes:
    salt = b"ABCDEFGH" + b"ijklmnopqrst"  # 20 bytes
    body = b"\x0a" + b"8.0.33-fake\x00" + struct.pack("<I", 1234)
    body += salt[:8] + b"\x00"
    body += struct.pack("<H", _CAPS & 0xFFFF) + bytes([m.CHARSET_UTF8])
    body += struct.pack("<H", 0x0002) + struct.pack("<H", (_CAPS >> 16) & 0xFFFF)
    body += bytes([21]) + b"\x00" * 10 + salt[8:] + b"\x00"
    body += b"mysql_native_password\x00"
    return _wrap(body, 0)


def _ok_packet() -> bytes:
    return _wrap(b"\x00\x00\x00\x02\x00\x00\x00", 2)


def _err_1045() -> bytes:
    body = b"\xff" + struct.pack("<H", 1045) + b"#28000" + b"Access denied"
    return _wrap(body, 2)


class _FakeMySQL:
    def __init__(self, accept: bool):
        self.accept = accept
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self._stop = False
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        while not self._stop:
            try:
                self.srv.settimeout(0.5)
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(_handshake())
                conn.recv(4096)  # the client's login packet
                conn.sendall(_ok_packet() if self.accept else _err_1045())
                conn.recv(256)   # COM_QUIT (best effort)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


def test_empty_password_accepted_is_critical():
    srv = _FakeMySQL(accept=True)
    try:
        res = check_mysql_empty_root("127.0.0.1", srv.port, timeout=3.0)
    finally:
        srv.close()
    assert res is not None
    assert res["severity"] == "CRITICAL"
    assert res["confirmed"] is True
    assert "root:(empty)" in res["credentials"]


def test_access_denied_is_not_vulnerable():
    srv = _FakeMySQL(accept=False)
    try:
        res = check_mysql_empty_root("127.0.0.1", srv.port, timeout=3.0)
    finally:
        srv.close()
    assert res is not None
    assert res["severity"] == "INFO"
    assert res["confirmed"] is False


def test_not_mysql_returns_none():
    # A port that is not a MySQL server (immediate close) → None.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()  # nothing listening now
    assert check_mysql_empty_root("127.0.0.1", port, timeout=1.0) is None
