"""TLS/SSL deep analysis — protocols, cipher suites, certificate details.

For every HTTPS-like port, extracts:
  - Supported TLS protocol versions (SSLv2, SSLv3, TLSv1.0/1.1/1.2/1.3)
  - Certificate chain (subject, issuer, validity, SANs)
  - Cipher suite negotiated (and detection of weak ones)
  - Weakness flags (heartbleed-vulnerable openssl versions, expired certs, etc.)

Pure-Python via the stdlib `ssl` module; no external scanner.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Optional

log = logging.getLogger(__name__)

# Protocol candidates to test (newest → oldest)
_PROTOCOLS: list[tuple[str, int]] = [
    ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),  # via OP_NO_TLSv1_2 etc.
    ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT),
    ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT),
    ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT),
    # SSLv2/SSLv3 — most Python builds don't support these; we'll skip if absent
]

# Cipher names containing these substrings are flagged as weak
_WEAK_CIPHER_PATTERNS = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXP", "anon", "ADH",
    "PSK", "SRP", "IDEA", "SEED", "CAMELLIA",
)


def _try_protocol(host: str, port: int, version_name: str,
                  timeout: float = 3.0) -> Optional[dict]:
    """Attempt a handshake at the given protocol level.

    Returns dict with cipher info on success, None on failure.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pin the protocol by disabling all others
    all_versions = {"TLSv1": ssl.OP_NO_TLSv1,
                    "TLSv1.1": ssl.OP_NO_TLSv1_1,
                    "TLSv1.2": ssl.OP_NO_TLSv1_2,
                    "TLSv1.3": ssl.OP_NO_TLSv1_3}
    requested = version_name.replace(".0", "")  # 'TLSv1.0' → 'TLSv1'
    for name, flag in all_versions.items():
        if name != requested:
            ctx.options |= flag

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cipher = ssock.cipher()  # (name, version, bits)
                return {
                    "protocol": ssock.version() or version_name,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "negotiated_protocol_version": cipher[1] if cipher else None,
                }
    except (ssl.SSLError, OSError, socket.timeout) as e:
        log.debug("TLS %s on %s:%d failed: %s", version_name, host, port, e)
        return None


def _get_certificate(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """Pull the server's certificate (PEM + parsed)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError, socket.timeout) as e:
        log.debug("cert fetch %s:%d failed: %s", host, port, e)
        return None

    if not cert:
        return None

    info: dict = {}
    # Flatten subject + issuer (list-of-tuples-of-tuples → dict)
    for field in ("subject", "issuer"):
        d = {}
        for tup in cert.get(field, []):
            for k, v in tup:
                d[k] = v
        info[field] = d

    info["serial"] = cert.get("serialNumber")
    info["version"] = cert.get("version")
    info["not_before"] = cert.get("notBefore")
    info["not_after"] = cert.get("notAfter")

    sans = cert.get("subjectAltName", [])
    info["san"] = [v for _, v in sans]

    # Expiry assessment
    try:
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (not_after - datetime.datetime.utcnow()).days
        info["days_until_expiry"] = days_left
        info["expired"] = days_left < 0
    except (ValueError, KeyError):
        info["days_until_expiry"] = None
        info["expired"] = False

    # Self-signed? subject == issuer
    info["self_signed"] = info.get("subject") == info.get("issuer")
    info["cert_size_bytes"] = len(cert_bin) if cert_bin else None
    return info


def scan_tls(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """Comprehensive TLS scan for one host:port.

    Returns a dict with:
      protocols_supported: list of strings like ["TLSv1.2", "TLSv1.3"]
      ciphers: dict {protocol: {cipher, bits}}
      cert: parsed certificate dict
      weak_protocols: list of bad protocols found (TLSv1.0, TLSv1.1)
      weak_ciphers: list of ciphers matching weak patterns
      issues: human-readable findings list
    """
    result: dict = {
        "protocols_supported": [],
        "ciphers": {},
        "cert": None,
        "weak_protocols": [],
        "weak_ciphers": [],
        "issues": [],
    }

    # Probe each protocol
    for version_name, _ in _PROTOCOLS:
        info = _try_protocol(host, port, version_name, timeout=timeout)
        if info is None:
            continue
        result["protocols_supported"].append(version_name)
        result["ciphers"][version_name] = {
            "cipher": info.get("cipher"),
            "bits": info.get("cipher_bits"),
        }
        cipher_name = info.get("cipher") or ""
        for pat in _WEAK_CIPHER_PATTERNS:
            if pat in cipher_name.upper():
                if cipher_name not in result["weak_ciphers"]:
                    result["weak_ciphers"].append(cipher_name)
                break
        if version_name in ("TLSv1.0", "TLSv1.1"):
            result["weak_protocols"].append(version_name)

    # Certificate
    cert = _get_certificate(host, port, timeout=timeout)
    result["cert"] = cert

    # Build human-readable issues list
    if result["weak_protocols"]:
        result["issues"].append(
            f"Weak TLS protocols enabled: {', '.join(result['weak_protocols'])}"
        )
    if result["weak_ciphers"]:
        result["issues"].append(
            f"Weak cipher(s): {', '.join(result['weak_ciphers'][:3])}"
        )
    if cert and cert.get("expired"):
        result["issues"].append("Certificate is EXPIRED")
    elif cert and cert.get("days_until_expiry") is not None \
            and cert["days_until_expiry"] < 30:
        result["issues"].append(
            f"Certificate expires in {cert['days_until_expiry']} day(s)"
        )
    if cert and cert.get("self_signed"):
        result["issues"].append("Self-signed certificate")
    if not result["protocols_supported"]:
        result["issues"].append("No standard TLS protocol negotiated")

    return result if (result["protocols_supported"] or cert) else None
