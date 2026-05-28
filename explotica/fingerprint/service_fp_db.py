"""Service fingerprint database — nmap-service-probes class matching.

Structure: each entry is a dict containing:
  - probe: optional bytes to send (None = passive read only)
  - ports: tuple of common port numbers where this service is expected
  - match: list of regex patterns; each match yields product/version
  - service: human-readable service name
  - vendor: NVD vendor slug (or None if generic)

The matcher takes a (port, banner_bytes) pair and returns the best match:
  (service_name, vendor, product, version)

This is more accurate than my original regex set because:
  1. Probes are protocol-specific (not just passive reads)
  2. Patterns are anchored more precisely
  3. Multiple patterns per service catch version-string variants
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Pattern

log = logging.getLogger(__name__)


# Each entry: {service, ports, match: [(pattern, captures), ...], vendor, probe}
# `captures` keys: product, version, vendor (each optional, gets pulled from regex groups)
FINGERPRINT_DB: list[dict] = [
    # ── SSH ────────────────────────────────────────────────────────────
    {
        "service": "ssh",
        "ports": (22,),
        "probe": None,  # SSH greets unprompted
        "vendor": None,
        "match": [
            (re.compile(rb"SSH-(\d+\.\d+)-OpenSSH[_-](?P<version>\d+\.\d+(?:p\d+)?)"),
             {"vendor": "openbsd", "product": "openssh"}),
            (re.compile(rb"SSH-(\d+\.\d+)-dropbear[_ -](?P<version>\d+\.\d+(?:\.\d+)?)"),
             {"vendor": "dropbear_ssh_project", "product": "dropbear_ssh"}),
            (re.compile(rb"SSH-(\d+\.\d+)-libssh[_ -](?P<version>\d+\.\d+(?:\.\d+)?)"),
             {"vendor": "libssh", "product": "libssh"}),
            (re.compile(rb"SSH-(\d+\.\d+)-Cisco"),
             {"vendor": "cisco", "product": "ios_ssh"}),
        ],
    },
    # ── HTTP servers ──────────────────────────────────────────────────
    {
        "service": "http",
        "ports": (80, 8080, 8000, 8008, 81, 8888, 3000),
        "probe": b"HEAD / HTTP/1.0\r\nHost: x\r\nUser-Agent: explotica\r\n\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"Server:\s*nginx/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "nginx", "product": "nginx"}),
            (re.compile(rb"Server:\s*Apache/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "apache", "product": "http_server"}),
            (re.compile(rb"Server:\s*Microsoft-IIS/(?P<version>\d+\.\d+)", re.I),
             {"vendor": "microsoft", "product": "internet_information_services"}),
            (re.compile(rb"Server:\s*lighttpd/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "lighttpd", "product": "lighttpd"}),
            (re.compile(rb"Server:\s*Werkzeug/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "pallets", "product": "werkzeug"}),
            (re.compile(rb"Server:\s*gunicorn/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "gunicorn", "product": "gunicorn"}),
            (re.compile(rb"Server:\s*Caddy", re.I),
             {"vendor": "caddyserver", "product": "caddy"}),
            (re.compile(rb"Server:\s*TornadoServer/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "tornadoweb", "product": "tornado"}),
            (re.compile(rb"Server:\s*Boa/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "boa", "product": "boa"}),
            (re.compile(rb"Server:\s*CUPS/(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
             {"vendor": "cups", "product": "cups"}),
        ],
    },
    # ── HTTPS (port-specific override) ────────────────────────────────
    {
        "service": "https",
        "ports": (443, 8443),
        "probe": None,
        "vendor": None,
        "match": [],  # TLS scan handles this elsewhere
    },
    # ── FTP ────────────────────────────────────────────────────────────
    {
        "service": "ftp",
        "ports": (21,),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"\(ProFTPD\s+(?P<version>\d+\.\d+\.\d+)"),
             {"vendor": "proftpd", "product": "proftpd"}),
            (re.compile(rb"NASFTPD\s+Turbo\s+Station\s+(?P<version>\d+\.\d+\.\d+)"),
             {"vendor": "proftpd", "product": "proftpd"}),  # Synology repackages ProFTPD
            (re.compile(rb"vsFTPd\s+(?P<version>\d+\.\d+(?:\.\d+)?)"),
             {"vendor": "vsftpd_project", "product": "vsftpd"}),
            (re.compile(rb"Pure-FTPd"),
             {"vendor": "pureftpd", "product": "pure-ftpd"}),
            (re.compile(rb"FileZilla Server\s+(?P<version>\d+\.\d+(?:\.\d+)?)"),
             {"vendor": "filezilla-project", "product": "filezilla_server"}),
            (re.compile(rb"Microsoft FTP Service"),
             {"vendor": "microsoft", "product": "ftp_server"}),
        ],
    },
    # ── SMTP ──────────────────────────────────────────────────────────
    {
        "service": "smtp",
        "ports": (25, 587, 465),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"Postfix"),
             {"vendor": "postfix", "product": "postfix"}),
            (re.compile(rb"Exim\s+(?P<version>\d+\.\d+)"),
             {"vendor": "exim", "product": "exim"}),
            (re.compile(rb"Sendmail\s+(?P<version>\d+\.\d+\.\d+)"),
             {"vendor": "sendmail", "product": "sendmail"}),
            (re.compile(rb"Microsoft ESMTP MAIL Service"),
             {"vendor": "microsoft", "product": "exchange_server"}),
        ],
    },
    # ── IMAP / POP3 ───────────────────────────────────────────────────
    {
        "service": "imap",
        "ports": (143, 993),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"Dovecot ready"),
             {"vendor": "dovecot", "product": "dovecot"}),
            (re.compile(rb"Courier"),
             {"vendor": "courier", "product": "courier-imap"}),
        ],
    },
    # ── Databases ─────────────────────────────────────────────────────
    {
        "service": "mysql",
        "ports": (3306,),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"^.{4}.\x00(?P<version>[0-9.]+)[^\x00]*MariaDB", re.S),
             {"vendor": "mariadb", "product": "mariadb"}),
            (re.compile(rb"^.{4}.\x00(?P<version>[0-9.]+)", re.S),
             {"vendor": "oracle", "product": "mysql"}),
        ],
    },
    {
        "service": "redis",
        "ports": (6379,),
        "probe": b"*1\r\n$4\r\nINFO\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"redis_version:(?P<version>\d+\.\d+\.\d+)"),
             {"vendor": "redis", "product": "redis"}),
            (re.compile(rb"NOAUTH"),
             {"vendor": "redis", "product": "redis"}),
        ],
    },
    {
        "service": "memcached",
        "ports": (11211,),
        "probe": b"stats\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"STAT version (?P<version>\d+\.\d+\.\d+)"),
             {"vendor": "memcached", "product": "memcached"}),
        ],
    },
    {
        "service": "mongodb",
        "ports": (27017, 27018),
        "probe": None,  # MongoDB requires binary BSON probe; handled by service_probes_v2
        "vendor": "mongodb",
        "match": [
            (re.compile(rb"It looks like you are trying to access MongoDB over HTTP"),
             {"vendor": "mongodb", "product": "mongodb"}),
        ],
    },
    {
        "service": "postgres",
        "ports": (5432,),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"PostgreSQL\s+(?P<version>\d+\.\d+)"),
             {"vendor": "postgresql", "product": "postgresql"}),
        ],
    },
    # ── Rsync ─────────────────────────────────────────────────────────
    {
        "service": "rsync",
        "ports": (873,),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"@RSYNCD:\s*(?P<proto>\d+\.\d+)"),
             {"vendor": "samba", "product": "rsync"}),  # version is protocol — ambiguous
        ],
    },
    # ── DNS ───────────────────────────────────────────────────────────
    {
        "service": "dns",
        "ports": (53,),
        "probe": None,
        "vendor": None,
        "match": [],
    },
    # ── VNC ────────────────────────────────────────────────────────────
    {
        "service": "vnc",
        "ports": (5900, 5901, 5902, 5903),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"RFB (?P<version>\d{3}\.\d{3})"),
             {"vendor": "realvnc", "product": "vnc"}),
        ],
    },
    # ── IRC ────────────────────────────────────────────────────────────
    {
        "service": "irc",
        "ports": (6667, 6697),
        "probe": b"VERSION\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"InspIRCd-(?P<version>[\d.]+)"),
             {"vendor": "inspircd", "product": "inspircd"}),
            (re.compile(rb"UnrealIRCd-(?P<version>[\d.]+)"),
             {"vendor": "unrealircd", "product": "unrealircd"}),
        ],
    },
    # ── MQTT ───────────────────────────────────────────────────────────
    {
        "service": "mqtt",
        "ports": (1883, 8883),
        "probe": bytes.fromhex(
            "101000044d51545404020000000548454c4c4f"  # CONNECT for client "HELLO"
        ),
        "vendor": None,
        "match": [
            (re.compile(rb"\x20\x02"),  # CONNACK packet
             {"vendor": "mqtt", "product": "mqtt-broker"}),
        ],
    },
    # ── Telnet ────────────────────────────────────────────────────────
    {
        "service": "telnet",
        "ports": (23,),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"\xff[\xfa-\xff].\xff"),  # Telnet negotiation bytes
             {"vendor": None, "product": "telnet"}),
        ],
    },
    # ── Elasticsearch ─────────────────────────────────────────────────
    {
        "service": "elasticsearch",
        "ports": (9200,),
        "probe": b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb'"number"\s*:\s*"(?P<version>[\d.]+)"'),
             {"vendor": "elastic", "product": "elasticsearch"}),
        ],
    },
    # ── Kafka ─────────────────────────────────────────────────────────
    {
        "service": "kafka",
        "ports": (9092,),
        "probe": None,
        "vendor": None,
        "match": [],
    },
    # ── Zookeeper ─────────────────────────────────────────────────────
    {
        "service": "zookeeper",
        "ports": (2181,),
        "probe": b"stat\n",
        "vendor": None,
        "match": [
            (re.compile(rb"Zookeeper version:\s*(?P<version>[\d.]+)"),
             {"vendor": "apache", "product": "zookeeper"}),
        ],
    },
    # ── etcd ──────────────────────────────────────────────────────────
    {
        "service": "etcd",
        "ports": (2379, 2380),
        "probe": b"GET /v2/keys HTTP/1.0\r\nHost: x\r\n\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb'"etcdserver"\s*:\s*"(?P<version>[\d.]+)"'),
             {"vendor": "etcd", "product": "etcd"}),
        ],
    },
    # ── Docker registry ───────────────────────────────────────────────
    {
        "service": "docker-registry",
        "ports": (5000,),
        "probe": b"GET /v2/ HTTP/1.0\r\nHost: x\r\n\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"Docker-Distribution-Api-Version"),
             {"vendor": "docker", "product": "docker_registry"}),
        ],
    },
    # ── RDP ────────────────────────────────────────────────────────────
    {
        "service": "rdp",
        "ports": (3389,),
        "probe": bytes.fromhex("030000130ee000000000000100080001000000"),
        "vendor": "microsoft",
        "match": [
            (re.compile(rb"\x03\x00", re.S),
             {"vendor": "microsoft", "product": "remote_desktop"}),
        ],
    },
    # ── SMB ────────────────────────────────────────────────────────────
    {
        "service": "smb",
        "ports": (445, 139),
        "probe": None,
        "vendor": "microsoft",
        "match": [
            (re.compile(rb"\xffSMB"),
             {"vendor": "microsoft", "product": "windows_smb"}),
            (re.compile(rb"\xfeSMB"),
             {"vendor": "microsoft", "product": "windows_smb2"}),
        ],
    },
    # ── NetBIOS ───────────────────────────────────────────────────────
    {
        "service": "netbios-ssn",
        "ports": (139,),
        "probe": None,
        "vendor": None,
        "match": [],
    },
    # ── LDAP ───────────────────────────────────────────────────────────
    {
        "service": "ldap",
        "ports": (389, 636),
        "probe": None,
        "vendor": None,
        "match": [],
    },
    # ── Kerberos ──────────────────────────────────────────────────────
    {
        "service": "kerberos",
        "ports": (88, 464),
        "probe": None,
        "vendor": "mit",
        "match": [],
    },
    # ── SIP ────────────────────────────────────────────────────────────
    {
        "service": "sip",
        "ports": (5060, 5061),
        "probe": None,
        "vendor": None,
        "match": [
            (re.compile(rb"Server:\s*(?P<server>[^\r\n]+)", re.I),
             {"vendor": None, "product": "sip"}),
        ],
    },
    # ── Printers (PJL/IPP/JetDirect) ──────────────────────────────────
    {
        "service": "jetdirect",
        "ports": (9100,),
        "probe": b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n",
        "vendor": "hp",
        "match": [
            (re.compile(rb'"(?P<product>[^"\r\n]+)"'),
             {"vendor": "hp", "product": "jetdirect"}),
        ],
    },
    # ── RTSP ───────────────────────────────────────────────────────────
    {
        "service": "rtsp",
        "ports": (554, 8554),
        "probe": b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        "vendor": None,
        "match": [
            (re.compile(rb"RTSP/1\.0", re.I),
             {"vendor": None, "product": "rtsp"}),
            (re.compile(rb"Server:\s*Hikvision", re.I),
             {"vendor": "hikvision", "product": "ip_camera"}),
            (re.compile(rb"Server:\s*Dahua", re.I),
             {"vendor": "dahua", "product": "ip_camera"}),
            (re.compile(rb"Server:\s*Axis", re.I),
             {"vendor": "axis", "product": "ip_camera"}),
        ],
    },
]


# Build a quick port → entries index for fast lookup
_PORT_INDEX: dict[int, list[dict]] = {}
for entry in FINGERPRINT_DB:
    for p in entry.get("ports", ()):
        _PORT_INDEX.setdefault(p, []).append(entry)


def match_response(port: int, response: bytes) -> Optional[dict]:
    """Identify the service from a port + response bytes.

    Returns dict with keys: service, vendor, product, version (any may be None).
    Returns None if no match found.
    """
    if not response:
        return None

    entries = _PORT_INDEX.get(port, [])
    # Also try unanchored matches (response may indicate a service even on
    # an unexpected port, like nginx on 8081)
    if not entries:
        entries = FINGERPRINT_DB

    for entry in entries:
        for pattern, captures in entry["match"]:
            m = pattern.search(response)
            if not m:
                continue
            result = {
                "service": entry["service"],
                "vendor": captures.get("vendor") or entry.get("vendor"),
                "product": captures.get("product"),
                "version": None,
            }
            try:
                if "version" in m.groupdict():
                    result["version"] = m.group("version").decode("ascii", "replace")
            except (IndexError, AttributeError):
                pass
            return result
    return None


def fingerprint_count() -> dict[str, int]:
    """Stats — how many entries, patterns, port coverage."""
    return {
        "entries": len(FINGERPRINT_DB),
        "total_patterns": sum(len(e["match"]) for e in FINGERPRINT_DB),
        "ports_covered": len(_PORT_INDEX),
        "services": sorted({e["service"] for e in FINGERPRINT_DB}),
    }


def get_probe(port: int) -> Optional[bytes]:
    """Return the active probe payload for this port, if any."""
    for entry in _PORT_INDEX.get(port, []):
        if entry.get("probe"):
            return entry["probe"]
    return None
