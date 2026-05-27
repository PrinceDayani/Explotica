"""Async I/O primitives — uvloop-accelerated when available.

This module provides async equivalents of the hot path:
  - async_scan_ports(): asyncio.open_connection-based port probe
  - async_grab_banner(): single async banner grab
  - async_http_probe(): async HTTP HEAD/GET with optional TLS

Why async over threads for I/O-bound scanning:
  - Threads: ~256-1000 max before context-switch dominates. GIL-bound.
  - Asyncio: single event loop, 10k+ concurrent connections easily.
  - Add uvloop (Cython asyncio impl) and dispatch overhead drops further.

Usage:
    asyncio.run(async_scan_ports("192.168.1.1", [22, 80, 443]))

Or via the run_scan_async() entrypoint in scanner.py.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Optional

log = logging.getLogger(__name__)


# ── uvloop install (no-op if not present) ─────────────────────────────────
def install_uvloop() -> bool:
    """Try to install uvloop as the asyncio event loop policy.

    Returns True if uvloop became the loop policy, False otherwise.
    uvloop is a Cython reimplementation of asyncio — typically 2-4x faster
    on real network workloads. Available on Linux/macOS, not Windows.
    """
    try:
        import uvloop  # type: ignore
        uvloop.install()
        log.info("uvloop installed as event loop policy")
        return True
    except ImportError:
        log.debug("uvloop not available — using stdlib asyncio")
        return False


# ── Port probing ──────────────────────────────────────────────────────────
async def async_probe_port(ip: str, port: int, timeout: float = 0.4) -> Optional[int]:
    """Single async TCP connect. Returns port number if open, None otherwise.

    No state tracking, no socket cleanup leaks — asyncio handles it. Each
    probe is independent and can be batched via gather().
    """
    fut = asyncio.open_connection(ip, port)
    try:
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    try:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass
    except Exception:
        pass
    return port


async def async_scan_ports(ip: str, ports: list[int],
                            timeout: float = 0.4,
                            concurrency: int = 1000) -> list[int]:
    """Probe many ports on one host concurrently.

    Concurrency capped by a semaphore. 1000 is a safe default — kernel
    file descriptor limits + scapy/raw socket pressure tend to be elsewhere.
    """
    if not ports:
        return []
    sem = asyncio.Semaphore(concurrency)

    async def probe_one(p: int) -> Optional[int]:
        async with sem:
            return await async_probe_port(ip, p, timeout=timeout)

    results = await asyncio.gather(*(probe_one(p) for p in ports))
    open_ports = sorted(p for p in results if p is not None)
    return open_ports


# ── Banner grabbing ───────────────────────────────────────────────────────
HTTP_PORTS_AIO = {80, 81, 8000, 8008, 8080, 8081, 3000, 5000, 8888}
HTTPS_PORTS_AIO = {443, 8443}
QUIET_PORTS_AIO = {22, 21, 25, 110, 143, 587, 993, 995}


async def _async_http_probe(ip: str, port: int, *, tls: bool,
                              timeout: float = 1.5) -> Optional[str]:
    """Async HTTP HEAD probe — returns first line + Server header."""
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = None
    try:
        fut = asyncio.open_connection(ip, port, ssl=ctx,
                                       server_hostname=ip if ctx else None)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None

    try:
        req = (f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: explotica/0.1\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    keep: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if keep:
                break
            continue
        if (line.startswith("HTTP/")
                or line.lower().startswith(("server:", "x-powered-by:"))):
            keep.append(line)
        if len(keep) >= 3:
            break
    return " | ".join(keep)[:240] or None


async def _async_passive_read(ip: str, port: int,
                                timeout: float = 1.5) -> Optional[str]:
    """Connect and read whatever the server volunteers (SSH/FTP/SMTP/etc.)."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
    if not data:
        return None
    # Same binary-detection logic as the threaded version
    printable = sum(1 for b in data
                     if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    if printable / max(len(data), 1) < 0.7:
        return f"<binary {len(data)}B: {data[:16].hex(' ')}…>"
    text = data.decode("utf-8", errors="replace").strip()
    first = next((line for line in text.splitlines() if line.strip()), text)
    return first[:200] if first else None


async def async_grab_banner(ip: str, port: int,
                              timeout: float = 1.5) -> Optional[str]:
    """Dispatch to the right probe for this port (HTTP / HTTPS / passive)."""
    if port in HTTP_PORTS_AIO:
        return await _async_http_probe(ip, port, tls=False, timeout=timeout)
    if port in HTTPS_PORTS_AIO:
        return await _async_http_probe(ip, port, tls=True, timeout=timeout)
    if port in QUIET_PORTS_AIO:
        return await _async_passive_read(ip, port, timeout)
    # Fallback: try passive read
    return await _async_passive_read(ip, port, timeout)


async def async_grab_all_banners(ip: str, ports: list[int],
                                   timeout: float = 1.5,
                                   concurrency: int = 64) -> dict[int, str]:
    """Grab banners for many ports on one host concurrently."""
    if not ports:
        return {}
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int) -> tuple[int, Optional[str]]:
        async with sem:
            return (p, await async_grab_banner(ip, p, timeout))

    results = await asyncio.gather(*(one(p) for p in ports))
    return {p: b for p, b in results if b}


# ── Full-host async pipeline (port scan + banner grab) ────────────────────
async def async_scan_host(ip: str, ports: list[int], *,
                            port_timeout: float = 0.4,
                            banner_timeout: float = 1.5,
                            port_concurrency: int = 1000,
                            banner_concurrency: int = 64,
                            grab_banners: bool = True
                            ) -> tuple[list[int], dict[int, str]]:
    """Run port scan and banner grab for one host async, return (open_ports, banners)."""
    open_ports = await async_scan_ports(
        ip, ports, timeout=port_timeout, concurrency=port_concurrency
    )
    banners: dict[int, str] = {}
    if grab_banners and open_ports:
        banners = await async_grab_all_banners(
            ip, open_ports, timeout=banner_timeout,
            concurrency=banner_concurrency
        )
    return (open_ports, banners)


# ── Multi-host async pipeline ─────────────────────────────────────────────
async def async_scan_many(hosts: list[str], ports: list[int], *,
                            port_timeout: float = 0.4,
                            banner_timeout: float = 1.5,
                            host_concurrency: int = 32,
                            port_concurrency: int = 1000,
                            grab_banners: bool = True
                            ) -> dict[str, tuple[list[int], dict[int, str]]]:
    """Scan many hosts in parallel using one shared event loop.

    With uvloop installed and host_concurrency=32, this can do a /24 of
    27 live hosts × 1000 ports + banners in ~3-5 seconds on a fast LAN.
    """
    host_sem = asyncio.Semaphore(host_concurrency)

    async def one(ip: str) -> tuple[str, tuple[list[int], dict[int, str]]]:
        async with host_sem:
            res = await async_scan_host(
                ip, ports, port_timeout=port_timeout,
                banner_timeout=banner_timeout,
                port_concurrency=port_concurrency,
                grab_banners=grab_banners,
            )
        return (ip, res)

    results = await asyncio.gather(*(one(h) for h in hosts))
    return dict(results)


# ── Sync wrapper — call from non-async code ──────────────────────────────
def run_async_scan(hosts: list[str], ports: list[int],
                    use_uvloop: bool = True, **kwargs
                    ) -> dict[str, tuple[list[int], dict[int, str]]]:
    """Run async_scan_many from sync code. Returns the same dict.

    Installs uvloop if available + requested.
    """
    if use_uvloop:
        install_uvloop()
    return asyncio.run(async_scan_many(hosts, ports, **kwargs))
