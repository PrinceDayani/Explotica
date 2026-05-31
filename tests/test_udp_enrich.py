"""Tests for Phase 72 — new high-intel parsers + second-hop enrichment chains."""

from __future__ import annotations

from explotica.discovery import udp_parsers as PR
from explotica.discovery import udp_enrich as E
from explotica.discovery import udp_payloads as P
from explotica.core.models import Port


# ── New payloads registered + curated set stays unique ────────────────────────
def test_new_payloads_present():
    for port, proto in [(3702, "ws-discovery"), (10001, "ubiquiti"),
                        (27015, "a2s"), (64738, "mumble")]:
        assert P.PAYLOADS[port][0] == proto
        assert P.PAYLOADS[port][1]            # non-empty payload


def test_high_value_still_unique_after_expansion():
    assert len(P.HIGH_VALUE_UDP_PORTS) == len(set(P.HIGH_VALUE_UDP_PORTS))


# ── New parsers ───────────────────────────────────────────────────────────────
def test_a2s_parses_server_info():
    pkt = (b"\xff\xff\xff\xffI\x11my server\x00de_dust2\x00csgo\x00"
           b"Counter-Strike\x00")
    out = PR.parse_a2s(pkt)
    assert out["name"] == "my server" and out["map"] == "de_dust2"


def test_mumble_parses_version_and_users():
    pkt = (bytes([0, 1, 4, 0]) + b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
           + (42).to_bytes(4, "big") + (100).to_bytes(4, "big")
           + (0).to_bytes(4, "big"))
    out = PR.parse_mumble(pkt)
    assert out["version"] == "1.4.0"
    assert out["users"] == 42 and out["max_users"] == 100


def test_ubiquiti_extracts_mac_and_fields():
    # header + TLV: type 0x01 MAC(6), type 0x03 firmware text
    mac = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
    fw = b"XW.v5.6.15"
    tlvs = (bytes([0x01]) + (6).to_bytes(2, "big") + mac
            + bytes([0x03]) + len(fw).to_bytes(2, "big") + fw)
    out = PR.parse_ubiquiti(b"\x01\x00\x00\x00" + tlvs)
    assert out["mac"] == "de:ad:be:ef:00:01"
    assert "XW.v5.6.15" in out.get("info", [])
    assert "finding" in out


def test_ws_discovery_extracts_xaddrs():
    xml = ("<d:ProbeMatches><d:ProbeMatch><d:Types>tdn:NetworkVideoTransmitter"
           "</d:Types><d:XAddrs>http://192.168.1.64/onvif/device_service"
           "</d:XAddrs></d:ProbeMatch></d:ProbeMatches>")
    out = PR.parse_ws_discovery(xml.encode())
    assert "192.168.1.64" in out["xaddrs"]
    assert "finding" in out


# ── SNMP BER encoding / decoding (the enrichment correctness core) ────────────
def test_snmp_oid_encode_known_value():
    assert E._encode_oid((1, 3, 6, 1, 2, 1, 1, 5, 0)).hex() == "2b06010201010500"


def test_snmp_oid_roundtrip_multibyte_arc():
    arcs = (1, 3, 6, 1, 4, 1, 2021, 0)        # 2021 needs base-128 encoding
    assert E._decode_oid(E._encode_oid(arcs)) == "1.3.6.1.4.1.2021.0"


def test_snmp_get_is_wellformed():
    get = E.build_snmp_get((1, 3, 6, 1, 2, 1, 1, 5, 0))
    assert get[0] == 0x30                       # outer SEQUENCE
    assert b"public" in get


def test_snmp_extract_octet_string_value():
    oid = E._encode_oid((1, 3, 6, 1, 2, 1, 1, 5, 0))
    val = b"router-01"
    resp = b"\x06" + bytes([len(oid)]) + oid + b"\x04" + bytes([len(val)]) + val
    assert E._snmp_extract_value(resp, oid) == "router-01"


def test_snmp_extract_timeticks_int():
    oid = E._encode_oid((1, 3, 6, 1, 2, 1, 1, 3, 0))
    ticks = (123456).to_bytes(4, "big")
    resp = b"\x06" + bytes([len(oid)]) + oid + b"\x43\x04" + ticks
    assert E._snmp_extract_value(resp, oid) == 123456


# ── Enrichment orchestrator merges into service_intel (mocked I/O) ────────────
def test_enrich_merges_snmp_walk(monkeypatch):
    monkeypatch.setattr(E, "snmp_walk",
                        lambda ip, *a, **k: {"sysName": "core-sw-1"})
    p = Port(number=161, protocol="udp", state="open",
             service="snmp", service_intel={"snmp": {"responded": True}})
    E.enrich_udp_ports("10.0.0.1", [p])
    assert p.service_intel["snmp"]["walk"]["sysName"] == "core-sw-1"
    assert "finding" in p.service_intel["snmp"]


def test_enrich_fetches_ssdp_device(monkeypatch):
    monkeypatch.setattr(E, "ssdp_fetch_device",
                        lambda loc, *a, **k: {"manufacturer": "Sonos",
                                              "modelName": "Play:1"})
    p = Port(number=1900, protocol="udp", state="open", service="ssdp",
             service_intel={"ssdp": {"location": "http://10.0.0.5:1400/xml/d"}})
    E.enrich_udp_ports("10.0.0.5", [p])
    dev = p.service_intel["ssdp"]["device"]
    assert dev["modelName"] == "Play:1"
    assert "Sonos" in p.service_intel["ssdp"]["finding"]


def test_enrich_skips_closed_ports(monkeypatch):
    called = []
    monkeypatch.setattr(E, "snmp_walk",
                        lambda ip, *a, **k: called.append(ip) or {})
    p = Port(number=161, protocol="udp", state="closed")
    E.enrich_udp_ports("10.0.0.1", [p])
    assert called == []                          # never enrich a closed port


# ── mDNS PTR→SRV→TXT→A resolution (Phase 74) ──────────────────────────────────
def _name(s):
    return b"".join(bytes([len(x)]) + x.encode() for x in s.split(".") if x) \
        + b"\x00"


def _mdns_response():
    import struct
    inst = "Printer._ipp._tcp.local"
    hdr = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 3)
    ptr = _name("_ipp._tcp.local") + struct.pack(">HHIH", 12, 1, 120,
                                                 len(_name(inst))) + _name(inst)
    srvrd = struct.pack(">HHH", 0, 0, 631) + _name("printer.local")
    srv = _name(inst) + struct.pack(">HHIH", 33, 1, 120, len(srvrd)) + srvrd
    txtrd = bytes([7]) + b"ty=HP41"
    txt = _name(inst) + struct.pack(">HHIH", 16, 1, 120, len(txtrd)) + txtrd
    a = _name("printer.local") + struct.pack(">HHIH", 1, 1, 120, 4) \
        + bytes([192, 168, 1, 9])
    return hdr + ptr + srv + txt + a


def test_dns_parses_all_record_types():
    recs = E._dns_parse_records(_mdns_response())
    types = sorted(r["type"] for r in recs)
    assert types == [1, 12, 16, 33]              # A, PTR, TXT, SRV


def test_dns_read_name_follows_compression():
    import struct
    # "printer.local" at offset 12, then a pointer to it at the end.
    base = struct.pack(">HHHHHH", 0, 0, 0, 0, 0, 0) + _name("printer.local")
    ptr_off = len(base)
    data = base + b"\xc0\x0c"                     # pointer to offset 12
    name, _ = E._dns_read_name(data, ptr_off)
    assert name == "printer.local"


def test_assemble_instances_stitches_srv_txt_a():
    recs = E._dns_parse_records(_mdns_response())
    inst = E._assemble_instances(recs)[0]
    assert inst["instance"] == "Printer._ipp._tcp.local"
    assert inst["port"] == 631
    assert inst["target"] == "printer.local"
    assert inst["addr"] == "192.168.1.9"
    assert inst["txt"] == ["ty=HP41"]


def test_mdns_query_is_ptr_in():
    import struct
    q = E._mdns_query("_ipp._tcp.local")
    assert q.endswith(struct.pack(">HH", 12, 1))   # PTR / IN
    assert b"_ipp" in q


def test_enrich_resolves_mdns(monkeypatch):
    monkeypatch.setattr(E, "mdns_resolve",
                        lambda ip, svcs, *a, **k: {"_ipp._tcp.local":
                                                   [{"instance": "P", "port": 631}]})
    p = Port(number=5353, protocol="udp", state="open", service="mdns",
             service_intel={"mdns": {"services": ["_ipp._tcp.local"]}})
    E.enrich_udp_ports("10.0.0.9", [p])
    assert p.service_intel["mdns"]["resolved"]["_ipp._tcp.local"][0]["port"] == 631


def test_enrich_dumps_ipmi_rakp(monkeypatch):
    from explotica.discovery import ipmi_rakp as K
    monkeypatch.setattr(K, "dump_hash",
                        lambda ip, *a, **k: {"hashcat_7300": "deadbeef:cafe",
                                             "finding": "RAKP hash"})
    p = Port(number=623, protocol="udp", state="open", service="ipmi",
             service_intel={"ipmi": {"ipmi_2_0": True}})
    E.enrich_udp_ports("10.0.0.7", [p])
    assert p.service_intel["ipmi"]["rakp_hash"]["hashcat_7300"] == "deadbeef:cafe"
    assert p.service_intel["ipmi"]["severity"] == "high"
