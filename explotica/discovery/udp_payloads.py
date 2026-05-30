"""UDP probe payload registry — the 'speak each service's language' database.

An *open* UDP port is almost always SILENT. A DNS server ignores garbage; it
only answers a real DNS query. So the single biggest lever in UDP scanning is
sending the protocol-correct bytes that *provoke a reply*. This is what nmap's
``nmap-payloads`` file does, and it's 80% of why nmap's UDP scan is "excellent".

This module is that database, built from scratch:

  - ``PAYLOADS``: ``{port: (proto_name, payload_bytes)}`` — one crafted probe
    per well-known UDP service.
  - ``EMPTY_PAYLOAD``: zero-length datagram, the fallback for the other ~65k
    ports where we have no protocol knowledge. (An empty datagram still elicits
    an ICMP port-unreachable from a closed port, so we can classify it; an open
    port that needs a real payload stays ``open|filtered`` — same as nmap.)

Each payload is built by a small function so the construction is auditable —
no opaque hex blobs you can't reason about.
"""

from __future__ import annotations

import struct

EMPTY_PAYLOAD = b""


# ── DNS (53) — CHAOS TXT version.bind, leaks BIND version on misconfigured DNS ─
def _dns_version_bind() -> bytes:
    # Header: id=0x1337, flags=0x0100 (standard query, recursion desired),
    #         qdcount=1, the rest 0.
    header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    # Question: "version.bind" / type TXT (16) / class CHAOS (3)
    qname = b"\x07version\x04bind\x00"
    question = qname + struct.pack(">HH", 0x0010, 0x0003)
    return header + question


# ── NTP (123) — standard v4 client request (mode 3), elicits a time reply ─────
def _ntp_client() -> bytes:
    # First byte: LI=0 (00) | VN=4 (100) | Mode=3 client (011) = 0b00100011
    return b"\x23" + b"\x00" * 47


# ── NTP (123) — mode-7 monlist (amplification / CVE-2013-5211 exposure) ───────
def _ntp_monlist() -> bytes:
    # ntpdc MON_GETLIST_1: response can be 100x request size → DDoS reflector.
    # Response presence is itself a finding (parser flags amplification factor).
    return b"\x17\x00\x03\x2a" + b"\x00" * 4


# ── SNMP (161) — v2c GetRequest sysDescr.0 with community 'public' ────────────
def _snmp_get_sysdescr(community: bytes = b"public") -> bytes:
    request_id = b"\x02\x04\x13\x37\x13\x37"          # 4-byte request-id
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"
    var_bindings = (
        b"\x30\x10"                                    # SEQUENCE len 16
        b"\x30\x0e"                                    # SEQUENCE len 14
        b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"    # OID 1.3.6.1.2.1.1.1.0
        b"\x05\x00"                                     # NULL
    )
    pdu_body = request_id + error_status + error_index + var_bindings
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body  # GetRequest
    body = (b"\x02\x01\x01"                             # version v2c (1)
            + b"\x04" + bytes([len(community)]) + community
            + pdu)
    return b"\x30" + bytes([len(body)]) + body


# ── NetBIOS-NS (137) — node-status (NBSTAT) query for '*' ─────────────────────
def _netbios_node_status() -> bytes:
    header = struct.pack(">HHHHHH", 0xA6B6, 0, 1, 0, 0, 0)
    name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # encoded '*'
    return header + name + struct.pack(">HH", 0x21, 1)   # NBSTAT, class IN


# ── SSDP (1900) — UPnP M-SEARCH discovery ─────────────────────────────────────
def _ssdp_msearch() -> bytes:
    return (b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n")


# ── mDNS (5353) — service enumeration ─────────────────────────────────────────
def _mdns_services() -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return header + name + struct.pack(">HH", 12, 1)     # PTR, class IN


# ── LLMNR (5355) — link-local name resolution query ───────────────────────────
def _llmnr_query() -> bytes:
    header = struct.pack(">HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0)
    name = b"\x07explica\x00"                            # arbitrary hostname
    return header + name + struct.pack(">HH", 0x01, 0x01)  # A, IN


# ── RPC portmapper (111) — DUMP call, lists every registered RPC service ──────
def _rpc_portmap_dump() -> bytes:
    # ONC-RPC CALL: xid, msgtype=0(call), rpcvers=2, prog=100000(portmap),
    #   vers=2, proc=4 (DUMP), null auth ×2.
    return struct.pack(
        ">IIIIIIIIIIII",
        0x13371337,   # xid
        0,            # msg type = CALL
        2,            # RPC version
        100000,       # program: portmapper
        2,            # program version
        4,            # procedure: DUMP
        0, 0,         # cred:  AUTH_NULL, length 0
        0, 0,         # verf:  AUTH_NULL, length 0
        0, 0,         # padding so the datagram is comfortably > min size
    )


# ── IKE / ISAKMP (500) — main-mode SA proposal (VPN endpoint fingerprint) ─────
def _ike_main_mode() -> bytes:
    # One proposal, one transform (3DES / SHA1 / PSK / MODP-1024, lifetime 28800).
    # A responding VPN gateway returns its chosen transform + Vendor IDs, which
    # the parser fingerprints (Cisco, Fortinet, strongSwan, etc.).
    def attr(t, v):  # basic (TV) attribute
        return struct.pack(">HH", 0x8000 | t, v)
    transform_attrs = (
        attr(1, 5) +      # Encryption = 3DES
        attr(2, 2) +      # Hash       = SHA1
        attr(3, 1) +      # Auth       = pre-shared key
        attr(4, 2)        # DH group   = MODP-1024
    )
    # Transform payload: next=0, len, transform#1, id=1(KEY_IKE), reserved
    transform = struct.pack(">BBHBBH", 0, 0,
                            8 + len(transform_attrs), 1, 1, 0) + transform_attrs
    # Proposal payload: next=0, len, proposal#1, proto=1(ISAKMP), spi_size=0,
    #   num_transforms=1
    proposal = struct.pack(">BBHBBBB", 0, 0,
                           8 + len(transform), 1, 1, 0, 1) + transform
    # SA payload: next=0, reserved, len, DOI=1(IPsec), situation=1(identity)
    sa_body = struct.pack(">II", 1, 1) + proposal
    sa = struct.pack(">BBH", 0, 0, 4 + len(sa_body)) + sa_body
    # ISAKMP header: init cookie (random-ish), resp cookie 0, next=SA(1),
    #   version 0x10, exch=2 (identity protect / main mode), flags 0, msgid 0
    init_cookie = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    length = 28 + len(sa)
    header = (init_cookie + b"\x00" * 8 +
              struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, length))
    return header + sa


# ── IPMI / RMCP (623) — Get Channel Authentication Capabilities ───────────────
def _ipmi_channel_auth() -> bytes:
    # RMCP header (ver 6, class IPMI 0x07) + IPMI session (auth NONE, seq 0,
    #   session 0) + IPMI message: Get Channel Auth Capabilities (NetFn App
    #   0x06, cmd 0x38), channel 0x0e (current), privilege ADMIN (0x04).
    rmcp = b"\x06\x00\xff\x07"
    session = b"\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"  # authtype/seq/sid
    # IPMI message body
    rs_addr, netfn_lun = 0x20, (0x06 << 2)
    chk1 = (0x100 - ((rs_addr + netfn_lun) & 0xFF)) & 0xFF
    rq_addr, rq_seq = 0x81, 0x00
    cmd = 0x38
    data = bytes([0x8e, 0x04])  # channel 0x0e | get-IPMI-v2 bit, priv ADMIN
    body_wo_chk2 = bytes([rq_addr, rq_seq, cmd]) + data
    chk2 = (0x100 - (sum(body_wo_chk2) & 0xFF)) & 0xFF
    msg = bytes([rs_addr, netfn_lun, chk1]) + body_wo_chk2 + bytes([chk2])
    return rmcp + session + bytes([len(msg)]) + msg


# ── STUN (3478) — binding request (NAT / WebRTC infra discovery) ──────────────
def _stun_binding() -> bytes:
    # type=0x0001 (Binding Request), length 0, magic cookie, 12-byte txid.
    return struct.pack(">HHI", 0x0001, 0, 0x2112A442) + b"\x13\x37" * 6


# ── memcached (11211 UDP) — stats (version leak + amplification reflector) ────
def _memcached_stats() -> bytes:
    # 8-byte UDP frame header (req-id, seq=0, n-datagrams=1, reserved) + cmd.
    return b"\x00\x00\x00\x00\x00\x01\x00\x00" + b"stats\r\n"


# ── MSSQL browser (1434) — SQL Server Resolution Protocol, lists instances ────
def _mssql_browser() -> bytes:
    return b"\x02"   # CLNT_UCAST_EX — enumerate all instances


# ── TFTP (69) — read request for a bogus file → ERROR reply proves it's open ──
def _tftp_rrq() -> bytes:
    return b"\x00\x01" + b"explica.probe\x00" + b"netascii\x00"


# ── SIP (5060) — OPTIONS ping, reveals SIP server/UA ──────────────────────────
def _sip_options() -> bytes:
    return (b"OPTIONS sip:probe@target SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP probe:5060;branch=z9hG4bK1337\r\n"
            b"Max-Forwards: 70\r\n"
            b"From: <sip:probe@probe>;tag=1337\r\n"
            b"To: <sip:probe@target>\r\n"
            b"Call-ID: 1337@probe\r\n"
            b"CSeq: 1 OPTIONS\r\n"
            b"Content-Length: 0\r\n\r\n")


# ── CoAP (5683) — GET /.well-known/core, IoT resource discovery ───────────────
def _coap_wellknown() -> bytes:
    # ver=1 type=CON(0) tkl=0, code=GET(0.01), msg-id; then Uri-Path options.
    header = b"\x40\x01\x13\x37"
    # Option 11 (Uri-Path) ".well-known", then "core"
    return (header
            + bytes([0xB0 | 11]) + b".well-known"
            + bytes([0x00 | 4]) + b"core")


# ── BACnet (47808) — Who-Is (building automation / ICS discovery) ─────────────
def _bacnet_whois() -> bytes:
    # BVLC (type 0x81, func 0x0B Original-Broadcast) + NPDU + APDU Who-Is.
    apdu = b"\x10\x08"                # unconfirmed-req, Who-Is
    npdu = b"\x01\x20\xff\xff\x00\xff"
    body = npdu + apdu
    return b"\x81\x0b" + struct.pack(">H", 4 + len(body)) + body


# ── RIP (520) — request full routing table ────────────────────────────────────
def _rip_request() -> bytes:
    # command=1 (request), version=2, then a single AF=0, metric=16 entry.
    return struct.pack(">BBH", 1, 2, 0) + struct.pack(
        ">HHIIII", 0, 0, 0, 0, 0, 16)


# ── chargen (19) — any datagram triggers a character flood (amplifier) ────────
def _chargen() -> bytes:
    return b"\x0d\x0a"


# ── The registry ──────────────────────────────────────────────────────────────
# port → (protocol_label, payload_bytes). The protocol_label routes the
# response to the right parser in udp_parsers.py.
PAYLOADS: dict[int, tuple[str, bytes]] = {
    19:    ("chargen",      _chargen()),
    53:    ("dns",          _dns_version_bind()),
    69:    ("tftp",         _tftp_rrq()),
    111:   ("rpcbind",      _rpc_portmap_dump()),
    123:   ("ntp",          _ntp_client()),
    137:   ("netbios-ns",   _netbios_node_status()),
    161:   ("snmp",         _snmp_get_sysdescr()),
    500:   ("ike",          _ike_main_mode()),
    520:   ("rip",          _rip_request()),
    623:   ("ipmi",         _ipmi_channel_auth()),
    1434:  ("mssql-browser", _mssql_browser()),
    1900:  ("ssdp",         _ssdp_msearch()),
    3478:  ("stun",         _stun_binding()),
    5060:  ("sip",          _sip_options()),
    5353:  ("mdns",         _mdns_services()),
    5355:  ("llmnr",        _llmnr_query()),
    5683:  ("coap",         _coap_wellknown()),
    11211: ("memcached",    _memcached_stats()),
    47808: ("bacnet",       _bacnet_whois()),
}

# A second probe for ports where one payload elicits ordinary data and another
# elicits a security-relevant amplification reply. Sent only in deep mode.
SECONDARY_PAYLOADS: dict[int, tuple[str, bytes]] = {
    123: ("ntp-monlist", _ntp_monlist()),
}

# Ports we consider "high-value" — the curated set used when the caller asks
# for a fast triage instead of the full 65535-port sweep.
HIGH_VALUE_UDP_PORTS: list[int] = sorted(PAYLOADS.keys()) + [
    67, 68, 88, 177, 389, 427, 443, 514, 1645, 1701, 1812, 2049, 4500,
    5061, 6481, 17185, 27015, 27960, 32768, 49152, 51820,
]


def payload_for(port: int) -> tuple[str, bytes]:
    """Return (proto_label, payload) for a port — crafted if known, else empty.

    The empty fallback still lets us classify closed ports (they emit ICMP
    port-unreachable regardless of payload); we just can't coax a banner from
    an open port we don't know how to talk to.
    """
    return PAYLOADS.get(port, ("unknown", EMPTY_PAYLOAD))
