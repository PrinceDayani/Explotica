"""Async I/O primitives — uvloop-accelerated when available.

Phase 57 rewrite. Brought into consistency with Phase 56's sync scanner:

  - async_probe_port: now returns a state-aware Port (open/closed/filtered/
    unknown with state_reason), not Optional[int]. Mirrors ports.probe_tcp.
  - async_grab_banner: uses the SAME content-based cascade as banners.py.
    No more HTTP_PORTS_AIO / HTTPS_PORTS_AIO / QUIET_PORTS_AIO port-keyed
    dispatch — that was the same bug we fixed in the sync path.
  - All HTTP/TLS port hints come from port_classifier (the SINGLE source
    of truth) instead of being redefined per module.

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
import errno
import logging
import ssl
from typing import Optional

from .banners import _identify_protocol, _clean_text
from .constants import USER_AGENT
from .models import Port
from .port_classifier import is_https, is_http_like, is_tls
from .ports import _errno_to_state

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


# ── Port probing — state-aware ────────────────────────────────────────────
async def async_probe_port(ip: str, port: int,
                            timeout: float = 0.4) -> Port:
    """Single async TCP-connect probe. ALWAYS returns a Port.

    Phase 57 — classifies state from the OSError errno, matching the sync
    ports.probe_tcp behavior. open / closed / filtered / unknown all have
    structured reasons in state_reason.
    """
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        # Connected — port is open. Close politely.
        try:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
            except (asyncio.TimeoutError, Exception):
                pass
        except Exception:
            pass
        return Port(number=port, protocol="tcp",
                    state="open", state_reason="tcp-connect succeeded")
    except asyncio.TimeoutError:
        return Port(number=port, protocol="tcp",
                    state="filtered", state_reason=f"timeout {timeout}s")
    except ConnectionRefusedError:
        return Port(number=port, protocol="tcp",
                    state="closed", state_reason="RST received")
    except OSError as e:
        err = e.errno or 0
        state, reason = _errno_to_state(err)
        return Port(number=port, protocol="tcp",
                    state=state, state_reason=reason)


async def async_scan_ports(ip: str, ports: list[int],
                            timeout: float = 0.4,
                            concurrency: int = 2000,
                            include_closed: bool = True,
                            include_filtered: bool = True
                            ) -> list[Port]:
    """Probe many ports on one host concurrently — returns full Port objects.

    Phase 57: state-aware (matches sync ports.scan_ports). The legacy
    list[int]-of-open-ports return type is gone; callers needing just
    open numbers can do `[p.number for p in result if p.state == 'open']`.
    """
    if not ports:
        return []
    sem = asyncio.Semaphore(concurrency)

    async def probe_one(p: int) -> Port:
        async with sem:
            return await async_probe_port(ip, p, timeout=timeout)

    results = await asyncio.gather(*(probe_one(p) for p in ports))
    out: list[Port] = []
    for r in results:
        if r.state == "open":
            out.append(r)
        elif r.state == "closed" and include_closed:
            out.append(r)
        elif r.state == "filtered" and include_filtered:
            out.append(r)
    return sorted(out, key=lambda p: p.number)


# ── Banner grabbing — content-based, NOT port-keyed ──────────────────────
async def _async_passive_read(ip: str, port: int,
                                timeout: float = 1.0) -> Optional[bytes]:
    """Connect and read whatever the server volunteers (SSH/FTP/SMTP/etc.).
    Returns RAW BYTES — caller does the protocol classification."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
    return data or None


async def _async_http_probe(ip: str, port: int, *, tls: bool,
                              timeout: float = 1.5) -> Optional[bytes]:
    """Async HTTP HEAD probe — returns raw response bytes."""
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
        req = (f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: {USER_AGENT}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        data = b""
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
    return data or None


async def async_grab_banner_full(ip: str, port: int,
                                   timeout: float = 1.0
                                   ) -> tuple[Optional[str], Optional[str],
                                                Optional[str], Optional[str],
                                                list[str]]:
    """Async version of banners.grab_banner_full.

    Returns (banner_text, service_from_content, product, version,
              probes_attempted).
    Same cascade as the sync version — passive read → classify → if no
    response, run HTTP/TLS/HTTPS/CRLF cascade based on port HINTS (not gates).
    """
    probes: list[str] = []

    # Step 1: passive read (chatty services: SSH/FTP/SMTP/POP3/IMAP/Redis/...)
    probes.append("passive-read")
    data = await _async_passive_read(ip, port, timeout=min(timeout, 0.8))
    if data:
        svc, prod, ver = _identify_protocol(data)
        return (_clean_text(data), svc, prod, ver, probes)

    # Step 2: cascade by port hint (just for ORDERING)
    if is_tls(port):
        cascade = ["https-get", "http-get", "crlf-kick"]
    elif is_http_like(port):
        cascade = ["http-get", "https-get", "crlf-kick"]
    else:
        cascade = ["http-get", "https-get", "crlf-kick"]

    for probe_name in cascade:
        probes.append(probe_name)
        if probe_name == "http-get":
            data = await _async_http_probe(ip, port, tls=False, timeout=timeout)
        elif probe_name == "https-get":
            data = await _async_http_probe(ip, port, tls=True, timeout=timeout)
        elif probe_name == "crlf-kick":
            # Reuse passive_read with a tiny send — async event loop makes
            # this minimal extra work.
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024),
                                                 timeout=timeout)
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
                except Exception:
                    pass
            except (asyncio.TimeoutError, OSError):
                data = None
        else:
            data = None
        if data:
            svc, prod, ver = _identify_protocol(data)
            return (_clean_text(data), svc, prod, ver, probes)

    return (None, None, None, None, probes)


async def async_grab_banner(ip: str, port: int,
                              timeout: float = 1.0) -> Optional[str]:
    """Back-compat single-string banner grab."""
    banner, _, _, _, _ = await async_grab_banner_full(ip, port, timeout=timeout)
    return banner


async def async_grab_all_banners(ip: str, ports: list[int],
                                   timeout: float = 1.0,
                                   concurrency: int = 64
                                   ) -> dict[int, str]:
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
                            banner_timeout: float = 1.0,
                            port_concurrency: int = 2000,
                            banner_concurrency: int = 64,
                            grab_banners: bool = True
                            ) -> tuple[list[Port], dict[int, str]]:
    """Run port scan and banner grab for one host async.

    Phase 57: returns full Port objects (not just numbers) so closed/filtered
    info is preserved end-to-end.
    """
    probed = await async_scan_ports(
        ip, ports, timeout=port_timeout, concurrency=port_concurrency
    )
    banners: dict[int, str] = {}
    if grab_banners and probed:
        open_nums = [p.number for p in probed if p.state == "open"]
        if open_nums:
            banners = await async_grab_all_banners(
                ip, open_nums, timeout=banner_timeout,
                concurrency=banner_concurrency
            )
    return (probed, banners)


# ── Multi-host async pipeline ─────────────────────────────────────────────
async def async_scan_many(hosts: list[str], ports: list[int], *,
                            port_timeout: float = 0.4,
                            banner_timeout: float = 1.0,
                            host_concurrency: int = 32,
                            port_concurrency: int = 2000,
                            grab_banners: bool = True
                            ) -> dict[str, tuple[list[Port], dict[int, str]]]:
    """Scan many hosts in parallel using one shared event loop.

    With uvloop installed and host_concurrency=32, this does a /24 of
    27 live hosts × 65535 ports + banners in ~25-40 seconds on a fast LAN.
    """
    host_sem = asyncio.Semaphore(host_concurrency)

    async def one(ip: str) -> tuple[str, tuple[list[Port], dict[int, str]]]:
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
                    ) -> dict[str, tuple[list[Port], dict[int, str]]]:
    """Run async_scan_many from sync code. Returns the same dict.

    Installs uvloop if available + requested.
    """
    if use_uvloop:
        install_uvloop()
    return asyncio.run(async_scan_many(hosts, ports, **kwargs))
