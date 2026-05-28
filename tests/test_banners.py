"""Banner-grab content classification — Phase 56 cascade."""

from explotica.banners import _identify_protocol


class TestProtocolIdentification:
    def test_ssh_classified(self):
        data = b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
        service, product, version = _identify_protocol(data)
        assert service == "ssh"
        assert product and "OpenSSH" in product

    def test_ftp_classified(self):
        data = b"220 ProFTPD 1.3.6 Server (Debian) [::ffff:192.168.1.1]\r\n"
        service, product, version = _identify_protocol(data)
        assert service == "ftp"
        assert product == "ProFTPD"
        assert version == "1.3.6"

    def test_smtp_specific_beats_generic_220(self):
        """SMTP ESMTP banner must NOT misclassify as generic FTP 220."""
        data = b"220 mail.example.com ESMTP Postfix\r\n"
        service, product, version = _identify_protocol(data)
        assert service == "smtp"
        assert product == "Postfix"

    def test_http_response(self):
        data = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "http"

    def test_pop3(self):
        data = b"+OK Dovecot ready.\r\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "pop3"

    def test_imap(self):
        data = b"* OK IMAP4rev1 Service Ready.\r\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "imap"

    def test_rdp_binary(self):
        # X.224 connect confirm
        data = b"\x03\x00\x00\x0e\x0d\xd0\x00\x12\x34\x00\x02\x00\x08\x00"
        service, _product, _version = _identify_protocol(data)
        assert service == "rdp"

    def test_redis_pong(self):
        data = b"+PONG\r\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "redis"

    def test_memcached_stat(self):
        data = b"STAT version 1.6.21\r\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "memcached"

    def test_vnc(self):
        data = b"RFB 003.008\n"
        service, _product, _version = _identify_protocol(data)
        assert service == "vnc"

    def test_empty_data_returns_nothing(self):
        service, product, version = _identify_protocol(b"")
        assert service is None
        assert product is None
        assert version is None

    def test_random_garbage_returns_nothing(self):
        service, _product, _version = _identify_protocol(b"\x00\x01\x02 random")
        assert service is None
