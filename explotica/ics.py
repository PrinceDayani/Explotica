"""Industrial Control Systems probes — Modbus, BACnet, DNP3, S7Comm, EtherNet/IP.

ICS protocols often run on dedicated networks but are increasingly exposed.
Finding one of these in a corporate scan is a major flag — usually means
poorly-segmented OT/IT network or accidentally-exposed factory floor.

These probes use protocol-correct fingerprinting bytes to identify each
service. No exploitation, no destructive operations.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)


# ── Modbus TCP (port 502) ─────────────────────────────────────────────────
def probe_modbus(host: str, port: int = 502,
                  timeout: float = 4.0) -> Optional[dict]:
    """Send Modbus 'Read Device Identification' (function 43, MEI 14)."""
    # Modbus MBAP header + Function 43, Subfunction 14, Object ID 0
    # txn_id=1, proto=0, length=5, unit_id=1, func=43 (0x2b), MEI=14 (0x0e),
    # read_device_id_code=1, object_id=0
    pkt = struct.pack(">HHHBBBBB", 1, 0, 5, 1, 0x2b, 0x0e, 1, 0)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 8:
        return None
    # Validate MBAP header
    if data[0:2] != b"\x00\x01":
        return None
    # Look for vendor/product strings embedded in the response
    # (Modbus Read Device ID returns ASCII strings)
    printable: list[str] = []
    cur: list[int] = []
    for b in data[8:]:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= 4:
                printable.append(bytes(cur).decode("ascii", "ignore"))
            cur = []
    if cur and len(cur) >= 4:
        printable.append(bytes(cur).decode("ascii", "ignore"))
    return {
        "protocol": "modbus",
        "responded": True,
        "strings": printable[:8],
        "severity": "HIGH",
        "note": "Modbus TCP exposed — ICS/SCADA equipment likely present",
    }


# ── BACnet (port 47808 UDP) ───────────────────────────────────────────────
def probe_bacnet(host: str, timeout: float = 3.0) -> Optional[dict]:
    """Send BACnet 'Who-Is' broadcast (UDP)."""
    # BVLC (4 bytes): type=0x81, function=0x0b (original-broadcast-NPDU),
    # length=0x000c
    # NPDU (2 bytes): version=0x01, control=0x20 (expecting reply, no dest)
    # APDU: 0x10 (unconfirmed-Req), 0x08 (Who-Is, no constraints)
    pkt = bytes([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0x10, 0x08])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, 47808))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        sock.close()
        return None
    finally:
        sock.close()
    if not data or len(data) < 8:
        return None
    if data[0] != 0x81:
        return None
    return {
        "protocol": "bacnet",
        "responded": True,
        "response_bytes": len(data),
        "severity": "HIGH",
        "note": "BACnet device exposed — building automation system",
    }


# ── DNP3 (port 20000) ─────────────────────────────────────────────────────
def probe_dnp3(host: str, port: int = 20000,
               timeout: float = 4.0) -> Optional[dict]:
    """Send DNP3 link-layer 'request link status'."""
    # DNP3 frame: start=0x0564, length=5, control=0xc9 (DIR=1, PRM=1,
    # FCB=0, FCV=0, code=9=request-link-status), dest=0x0000,
    # src=0xffff, CRC=0x0000 (we don't bother computing valid CRC)
    pkt = bytes([0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00])
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 10:
        return None
    if data[0:2] != b"\x05\x64":
        return None
    return {
        "protocol": "dnp3",
        "responded": True,
        "response_bytes": len(data),
        "severity": "HIGH",
        "note": "DNP3 exposed — SCADA (power grid / utility) protocol",
    }


# ── S7Comm / S7 (port 102) — Siemens PLCs ────────────────────────────────
def probe_s7(host: str, port: int = 102,
              timeout: float = 4.0) -> Optional[dict]:
    """Send a COTP TPKT + S7Comm Connect Request to a Siemens PLC."""
    # TPKT: 0x03 0x00 length(2)
    # COTP: 0x11 (length) 0xe0 (CR) 0x00 0x00 (dst_ref) 0x00 0x01 (src_ref) 0x00
    #       parameter: 0xc0 0x01 0x0a (TPDU size = 1024)
    #       parameter: 0xc1 0x02 0x01 0x00 (src TSAP)
    #       parameter: 0xc2 0x02 0x01 0x02 (dst TSAP for slot 0/PG)
    pkt = bytes([
        0x03, 0x00, 0x00, 0x16,         # TPKT
        0x11,                            # COTP length
        0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,  # CR
        0xc0, 0x01, 0x0a,                # TPDU size
        0xc1, 0x02, 0x01, 0x00,          # src TSAP
        0xc2, 0x02, 0x01, 0x02,          # dst TSAP (PG)
    ])
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 11:
        return None
    if data[0] != 0x03 or data[1] != 0x00:
        return None
    # CC TPDU (Connect Confirm) has type 0xd0 at byte 5
    cotp_type = data[5] if len(data) > 5 else 0
    if cotp_type != 0xd0:
        return None
    return {
        "protocol": "s7comm",
        "responded": True,
        "response_bytes": len(data),
        "severity": "HIGH",
        "note": "Siemens S7 PLC exposed",
    }


# ── EtherNet/IP (port 44818) — Allen-Bradley / Rockwell ──────────────────
def probe_enip(host: str, port: int = 44818,
                timeout: float = 4.0) -> Optional[dict]:
    """Send EtherNet/IP 'List Identity' (command 0x63)."""
    # ENIP encapsulation header (24 bytes minimum): command=0x0063,
    # length=0, session=0, status=0, sender=0, options=0
    pkt = struct.pack("<HHIIQI",
                       0x0063,  # command: ListIdentity
                       0,        # length
                       0,        # session handle
                       0,        # status
                       0,        # sender context
                       0)        # options
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 24:
        return None
    # Look for printable product name in the response
    printable: list[str] = []
    cur: list[int] = []
    for b in data[24:]:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= 4:
                printable.append(bytes(cur).decode("ascii", "ignore"))
            cur = []
    if cur and len(cur) >= 4:
        printable.append(bytes(cur).decode("ascii", "ignore"))
    return {
        "protocol": "ethernet-ip",
        "responded": True,
        "strings": printable[:5],
        "severity": "HIGH",
        "note": "EtherNet/IP exposed (Rockwell/Allen-Bradley PLC)",
    }


# ── Dispatch ─────────────────────────────────────────────────────────────
ICS_PROBES: dict[int, callable] = {
    502: probe_modbus,
    102: probe_s7,
    20000: probe_dnp3,
    44818: probe_enip,
}


def probe_ics_port(host: str, port: int, timeout: float = 4.0) -> Optional[dict]:
    """Run the ICS probe registered for this port."""
    handler = ICS_PROBES.get(port)
    if handler is None:
        return None
    try:
        return handler(host, port=port, timeout=timeout)
    except TypeError:
        return handler(host, timeout=timeout)
    except Exception as e:
        log.debug("ICS probe %s:%d failed: %s", host, port, e)
        return None


def probe_ics_host(host: str, ports: list[int],
                   timeout: float = 4.0) -> dict[int, dict]:
    """Run all applicable ICS probes against ports on a host."""
    findings = {}
    # Also probe UDP BACnet regardless of TCP scan
    bacnet = probe_bacnet(host, timeout=timeout)
    if bacnet:
        findings[47808] = bacnet
    for p in ports:
        if p in ICS_PROBES:
            r = probe_ics_port(host, p, timeout=timeout)
            if r:
                findings[p] = r
    return findings


def ics_port_set() -> set[int]:
    """Ports we have ICS probes for (for orchestrator hints)."""
    return set(ICS_PROBES.keys()) | {47808}
