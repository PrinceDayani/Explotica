"""SSH algorithm enumeration via the SSH KEXINIT packet.

Protocol exchange:
  1. Connect to TCP port 22 (or any port running SSH)
  2. Server sends a banner line (e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
  3. We send our banner
  4. Server sends SSH_MSG_KEXINIT containing all algorithms it supports
  5. We parse that packet — no need to actually negotiate a session

What we learn:
  - Server software banner (already in passive — but this confirms version)
  - Supported KEX algorithms
  - Server host key algorithms (which key types exist on the server)
  - Encryption / MAC / compression algorithms
  - First-KEX-packet-follows flag
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)

# Algorithm names that are considered weak/legacy
_WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "rsa1024-sha1",
}
_WEAK_HOSTKEY = {"ssh-dss", "ssh-rsa"}  # ssh-rsa = SHA-1 signatures
_WEAK_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
    "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
}
_WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160",
}


def _read_namelist(buf: bytes, offset: int) -> tuple[list[str], int]:
    """SSH name-list: uint32 length + comma-separated ASCII."""
    if offset + 4 > len(buf):
        raise ValueError("short namelist")
    length = struct.unpack_from(">I", buf, offset)[0]
    offset += 4
    if offset + length > len(buf):
        raise ValueError("namelist overflow")
    raw = buf[offset:offset + length].decode("ascii", errors="ignore")
    return (raw.split(",") if raw else []), offset + length


def enum_ssh(host: str, port: int = 22, timeout: float = 4.0) -> Optional[dict]:
    """Return dict of SSH algorithms supported by the server."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # 1. Read server banner
        banner = b""
        while b"\n" not in banner and len(banner) < 256:
            ch = sock.recv(256)
            if not ch:
                break
            banner += ch
        banner_str = banner.decode("ascii", errors="ignore").strip()
        if not banner_str.startswith("SSH-"):
            sock.close()
            return None

        # 2. Send our banner
        sock.sendall(b"SSH-2.0-explotica_0.1\r\n")

        # 3. Read KEXINIT packet from server
        # SSH binary packet: uint32 packet_length, byte padding_length, payload, padding, MAC
        hdr = b""
        while len(hdr) < 5:
            ch = sock.recv(5 - len(hdr))
            if not ch:
                break
            hdr += ch
        if len(hdr) < 5:
            sock.close()
            return None
        packet_length = struct.unpack(">I", hdr[:4])[0]
        padding_length = hdr[4]

        payload_len = packet_length - 1 - padding_length
        payload = b""
        remaining = packet_length - 1  # already read padding_length byte
        while len(payload) < remaining:
            ch = sock.recv(remaining - len(payload))
            if not ch:
                break
            payload += ch
        sock.close()

        if len(payload) < payload_len:
            return None
        actual_payload = payload[:payload_len]
    except (socket.timeout, OSError, struct.error, ValueError) as e:
        log.debug("ssh enum %s:%d failed: %s", host, port, e)
        return None

    if not actual_payload:
        return None

    # First byte = msg type. KEXINIT = 20 (0x14)
    if actual_payload[0] != 20:
        return {"banner": banner_str,
                "note": f"first message was type {actual_payload[0]}, not KEXINIT"}

    # Skip 1 byte msg-type + 16 bytes cookie = 17
    offset = 17
    try:
        kex_algs, offset = _read_namelist(actual_payload, offset)
        host_keys, offset = _read_namelist(actual_payload, offset)
        enc_c2s, offset = _read_namelist(actual_payload, offset)
        enc_s2c, offset = _read_namelist(actual_payload, offset)
        mac_c2s, offset = _read_namelist(actual_payload, offset)
        mac_s2c, offset = _read_namelist(actual_payload, offset)
        comp_c2s, offset = _read_namelist(actual_payload, offset)
        comp_s2c, offset = _read_namelist(actual_payload, offset)
        lang_c2s, offset = _read_namelist(actual_payload, offset)
        lang_s2c, offset = _read_namelist(actual_payload, offset)
    except ValueError as e:
        log.debug("ssh parse error %s:%d: %s", host, port, e)
        return {"banner": banner_str}

    issues: list[str] = []
    weak_kex_used = [a for a in kex_algs if a in _WEAK_KEX]
    weak_hk = [a for a in host_keys if a in _WEAK_HOSTKEY]
    weak_enc = [a for a in (enc_c2s + enc_s2c) if a in _WEAK_CIPHERS]
    weak_mac = [a for a in (mac_c2s + mac_s2c) if a in _WEAK_MACS]
    if weak_kex_used:
        issues.append(f"Weak KEX: {', '.join(weak_kex_used)}")
    if weak_hk:
        issues.append(f"Weak hostkey alg: {', '.join(weak_hk)}")
    if weak_enc:
        issues.append(f"Weak cipher: {', '.join(set(weak_enc))}")
    if weak_mac:
        issues.append(f"Weak MAC: {', '.join(set(weak_mac))}")

    # Library hint from banner
    library = "OpenSSH" if "openssh" in banner_str.lower() else \
              "Dropbear" if "dropbear" in banner_str.lower() else \
              "libssh" if "libssh" in banner_str.lower() else \
              "unknown"

    return {
        "banner": banner_str,
        "library_hint": library,
        "kex_algorithms": kex_algs,
        "server_host_key_algorithms": host_keys,
        "encryption_client_to_server": enc_c2s,
        "encryption_server_to_client": enc_s2c,
        "mac_client_to_server": mac_c2s,
        "mac_server_to_client": mac_s2c,
        "compression_client_to_server": comp_c2s,
        "compression_server_to_client": comp_s2c,
        "issues": issues,
    }
