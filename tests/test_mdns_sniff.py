"""Tests for the mDNS passive-sniff parser (pure, offline)."""
import socket
import struct

from explotica.discovery.mdns_sniff import parse_mdns_packet, _decode_name


def _name(s: str) -> bytes:
    out = b""
    for label in s.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _rr(name: bytes, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return name + struct.pack(">HHIH", rtype, 0x8001, ttl, len(rdata)) + rdata


def _build_announcement() -> bytes:
    # header: id=0, flags=0x8400 (response, AA), qd=0, an=4, ns=0, ar=0
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 4, 0, 0)
    # PTR: _http._tcp.local -> printer._http._tcp.local
    ptr = _rr(_name("_http._tcp.local"), 12, _name("printer._http._tcp.local"))
    # SRV: printer._http._tcp.local -> prio/weight/port 631 + target printer.local
    srv_rdata = struct.pack(">HHH", 0, 0, 631) + _name("printer.local")
    srv = _rr(_name("printer._http._tcp.local"), 33, srv_rdata)
    # A: printer.local -> 192.168.1.50
    a = _rr(_name("printer.local"), 1, socket.inet_aton("192.168.1.50"))
    # TXT: printer._http._tcp.local -> "ty=HP LaserJet"
    txt_item = b"ty=HP LaserJet"
    txt_rdata = bytes([len(txt_item)]) + txt_item
    txt = _rr(_name("printer._http._tcp.local"), 16, txt_rdata)
    return header + ptr + srv + a + txt


def test_parse_announcement():
    pkt = _build_announcement()
    result = parse_mdns_packet(pkt)
    assert result["responded"] is True
    assert "printer._http._tcp.local" in result["ptr"]
    assert result["addresses"]["printer.local"] == "192.168.1.50"
    srv = result["srv"][0]
    assert srv["port"] == 631
    assert srv["target"] == "printer.local"
    assert result["txt"]["printer._http._tcp.local"] == ["ty=HP LaserJet"]


def test_name_decompression():
    # "foo.local" at offset 12, then a pointer to it later.
    base = struct.pack(">HHHHHH", 0, 0x8400, 0, 0, 0, 0)  # 12-byte header
    assert len(base) == 12
    data = base + _name("foo.local")
    ptr_pos = len(data)
    data += b"\xc0\x0c"  # pointer to offset 12
    name, nxt = _decode_name(data, ptr_pos)
    assert name == "foo.local"
    assert nxt == ptr_pos + 2


def test_non_dns_returns_none():
    assert parse_mdns_packet(b"\x00\x01") is None
    assert parse_mdns_packet(b"") is None


def test_no_records_returns_none():
    # Valid header but zero resource records.
    hdr = struct.pack(">HHHHHH", 0, 0x8400, 0, 0, 0, 0)
    assert parse_mdns_packet(hdr) is None
