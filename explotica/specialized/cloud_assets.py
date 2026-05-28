"""Cloud asset discovery — find S3/Azure/GCP buckets via name permutation.

For a given company/keyword:
  1. Generate likely bucket names: keyword, keyword-prod, keyword-dev,
     keyword-backup, backups-keyword, keyword-static, etc.
  2. For each candidate, probe the well-known endpoint of each cloud provider
  3. Classify response: not found / private / public / found-but-listing-disabled

This finds assets that aren't linked from anywhere — pure brute-force
enumeration of namespace.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

log = logging.getLogger(__name__)


# Suffixes for bucket name generation
_COMMON_SUFFIXES = [
    "", "-prod", "-production", "-dev", "-development", "-staging",
    "-test", "-qa", "-uat", "-backup", "-backups", "-bak",
    "-static", "-assets", "-cdn", "-media", "-public", "-private",
    "-archive", "-data", "-logs", "-temp", "-tmp", "-old",
    "-internal", "-app", "-api", "-web",
]
_COMMON_PREFIXES = [
    "", "backup-", "backups-", "old-", "archive-", "logs-",
    "static-", "media-", "data-", "internal-",
]


def generate_bucket_names(keyword: str, *,
                           include_company_variants: bool = True
                           ) -> list[str]:
    """From a keyword, generate likely bucket names."""
    base = keyword.lower().strip()
    if not base:
        return []
    names: set[str] = set()
    # Core variants
    names.add(base)
    for suf in _COMMON_SUFFIXES:
        names.add(base + suf)
    for pre in _COMMON_PREFIXES:
        if pre:
            names.add(pre + base)
    if include_company_variants:
        # Common -com / -corp / -inc patterns
        for tld in ("com", "corp", "inc", "io", "co"):
            names.add(f"{base}-{tld}")
    return sorted(names)


def _http_head(host: str, path: str = "/", *, tls: bool = True,
                timeout: float = 4.0,
                host_header: Optional[str] = None) -> Optional[tuple[int, dict, bytes]]:
    """Send a single HEAD request and return (status, headers, partial body)."""
    port = 443 if tls else 80
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host_header or host}\r\n"
            f"User-Agent: explotica\r\n\r\n"
        ).encode()
        sock.sendall(req)
        data = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    if not data:
        return None
    sep = b"\r\n\r\n"
    head, _, body = data.partition(sep)
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return (status, headers, body)


# ── AWS S3 ────────────────────────────────────────────────────────────────
def check_s3_bucket(bucket: str, timeout: float = 4.0) -> Optional[dict]:
    """Probe https://<bucket>.s3.amazonaws.com/ for existence + accessibility."""
    host = f"{bucket}.s3.amazonaws.com"
    r = _http_head(host, timeout=timeout)
    if r is None:
        # DNS may not resolve for non-existent buckets — also try regional
        return None
    status, headers, body = r
    if status == 200:
        return {
            "provider": "aws_s3",
            "bucket": bucket,
            "url": f"https://{host}/",
            "status": "public_listing",
            "severity": "CRITICAL",
            "note": "S3 bucket allows public ListObjects",
        }
    if status == 403:
        if b"AccessDenied" in body:
            return {
                "provider": "aws_s3",
                "bucket": bucket,
                "url": f"https://{host}/",
                "status": "exists_private",
                "severity": "INFO",
                "note": "S3 bucket exists but listing denied",
            }
    if status == 404 and b"NoSuchBucket" in body:
        return None  # doesn't exist
    return None


# ── Azure Storage ─────────────────────────────────────────────────────────
def check_azure_blob(account: str, timeout: float = 4.0) -> Optional[dict]:
    """Probe https://<account>.blob.core.windows.net/ for existence."""
    host = f"{account}.blob.core.windows.net"
    # First check DNS resolves at all (Azure account names get parked)
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return None
    r = _http_head(host, timeout=timeout)
    if r is None:
        return None
    status, _, body = r
    if status == 200:
        return {
            "provider": "azure_blob",
            "account": account,
            "url": f"https://{host}/",
            "status": "exists",
            "severity": "INFO",
            "note": "Azure storage account exists",
        }
    if status == 400 or status == 403:
        return {
            "provider": "azure_blob",
            "account": account,
            "url": f"https://{host}/",
            "status": "exists_restricted",
            "severity": "INFO",
            "note": f"Azure storage account exists (status {status})",
        }
    return None


# ── Google Cloud Storage ──────────────────────────────────────────────────
def check_gcp_bucket(bucket: str, timeout: float = 4.0) -> Optional[dict]:
    """Probe https://storage.googleapis.com/<bucket>/ for existence."""
    r = _http_head("storage.googleapis.com", path=f"/{bucket}/",
                    timeout=timeout)
    if r is None:
        return None
    status, _, body = r
    if status == 200:
        return {
            "provider": "gcp_gcs",
            "bucket": bucket,
            "url": f"https://storage.googleapis.com/{bucket}/",
            "status": "public_listing",
            "severity": "CRITICAL",
            "note": "GCS bucket allows public listing",
        }
    if status == 403:
        return {
            "provider": "gcp_gcs",
            "bucket": bucket,
            "url": f"https://storage.googleapis.com/{bucket}/",
            "status": "exists_private",
            "severity": "INFO",
            "note": "GCS bucket exists, listing denied",
        }
    return None


def discover_cloud_assets(keyword: str, *,
                          check_aws: bool = True,
                          check_azure: bool = True,
                          check_gcp: bool = True,
                          workers: int = 16,
                          timeout: float = 4.0) -> list[dict]:
    """Enumerate candidate buckets across providers for a keyword.

    Returns list of finding dicts (one per matched bucket).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    names = generate_bucket_names(keyword)
    log.info("cloud_assets: generated %d candidate names for '%s'",
             len(names), keyword)
    findings: list[dict] = []
    tasks: list = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for n in names:
            if check_aws:
                tasks.append(pool.submit(check_s3_bucket, n, timeout))
            if check_azure:
                # Azure names must be lowercase 3-24 chars, alphanumeric only
                if 3 <= len(n) <= 24 and n.replace("-", "").isalnum():
                    azure_name = n.replace("-", "")[:24]
                    tasks.append(pool.submit(check_azure_blob, azure_name, timeout))
            if check_gcp:
                tasks.append(pool.submit(check_gcp_bucket, n, timeout))
        for f in as_completed(tasks):
            try:
                r = f.result()
                if r:
                    findings.append(r)
            except Exception as e:
                log.debug("cloud_assets task error: %s", e)
    return findings
