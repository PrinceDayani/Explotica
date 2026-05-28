"""SMB enumeration — minimal pure-Python share/dialect/signing detection.

For deep SMB enumeration (NULL session share list, full negotiation), nmap NSE
scripts `smb-enum-shares`, `smb-os-discovery`, `smb-protocols`, and
`smb-security-mode` are more reliable. This module returns what we can extract
without external dependencies, then suggests nmap for the rest.

What we extract via raw socket:
  - Whether SMB1/SMB2/SMB3 protocols respond
  - Server name + OS hint from the SMB1 NEGOTIATE response (if reachable)
  - Signing requirement flag
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

log = logging.getLogger(__name__)


# Pre-built SMB1 NEGOTIATE PROTOCOL request that offers SMB1+SMB2 dialects
_SMB1_NEGOTIATE = bytes.fromhex(
    "000000d4ff534d4272000000001853c8000000000000000000000000ffff"
    "0000000000b100025043204e4554574f524b2050524f4752414d20312e30"
    "00024c414e4d414e312e3000024c414e4d414e322e3100024c414e4d414e"
    "322e310002534d422033202e3000024e54204c4d20302e313200025357"
    "32000253616d626100025357305700"
)


def _printable_runs(data: bytes, min_len: int = 6) -> list[str]:
    """Pull printable ASCII runs of at least min_len chars out of binary data.

    SMB negotiation responses embed Server / OS strings as plaintext in an
    otherwise binary payload.
    """
    out: list[str] = []
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
            cur = []
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out


def scan_smb(host: str, port: int = 445, timeout: float = 3.0) -> Optional[dict]:
    """SMB negotiate + extract OS/server/signing hints. Returns dict or None."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(_SMB1_NEGOTIATE)
        data = sock.recv(2048)
    except (socket.timeout, OSError) as e:
        log.debug("smb negotiate %s:%d failed: %s", host, port, e)
        try:
            sock.close()
        except Exception:
            pass
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if not data or len(data) < 36:
        return None

    info: dict = {
        "responded": True,
        "raw_bytes": len(data),
        "strings": _printable_runs(data, min_len=6)[:8],
    }

    # SMB1 header offset 4 → 0xff S M B (SMB1 marker)
    # SMB2 header offset 4 → 0xfe S M B (SMB2 marker)
    if data[4:8] == b"\xffSMB":
        info["dialect_response"] = "SMB1"
    elif data[4:8] == b"\xfeSMB":
        info["dialect_response"] = "SMB2+"
    else:
        info["dialect_response"] = "unknown"

    # SMB1 security mode is at a fixed offset in the NEGOTIATE response.
    # Bit 0x01 set = user-level security, bit 0x04 set = signing required.
    if info["dialect_response"] == "SMB1" and len(data) > 39:
        sec_mode = data[39]
        info["security_mode_raw"] = sec_mode
        info["signing_required"] = bool(sec_mode & 0x08)
        info["signing_enabled"] = bool(sec_mode & 0x04)
        info["user_security"] = bool(sec_mode & 0x01)

    info["likely_windows"] = any("Windows" in s for s in info["strings"])
    info["likely_samba"] = any("Samba" in s for s in info["strings"])

    info["recommendations"] = []
    if not info.get("signing_required"):
        info["recommendations"].append(
            "SMB signing NOT required — vulnerable to SMB relay attacks"
        )
    if info["dialect_response"] == "SMB1":
        info["recommendations"].append(
            "SMB1 enabled — should be disabled (EternalBlue family)"
        )

    return info
