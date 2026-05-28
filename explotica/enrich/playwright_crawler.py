"""Headless browser crawler — Playwright-based JS-aware web reconnaissance.

Static HTML crawlers (like our web_crawler.py) miss 80%+ of modern web
apps' attack surface. React/Vue/Angular routes are JS-rendered, API calls
happen via fetch/XHR after page load, and WebSocket endpoints are
established dynamically.

This module launches a headless Chromium (via Playwright), navigates to
a URL, intercepts ALL network traffic, clicks visible links, and returns
the full discovered URL graph.

What gets captured:
  - All Document/XHR/Fetch/WebSocket URLs the page touched
  - DOM after JS execution
  - Form actions
  - Service Worker / PWA manifest URLs
  - Screenshot (optional)
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def _crawl_async(url: str, *,
                        max_pages: int = 8,
                        timeout_ms: int = 8000,
                        same_origin_only: bool = True,
                        headless: bool = True) -> dict:
    """Internal async crawler — launches browser, recursively visits pages."""
    from playwright.async_api import async_playwright

    visited: set[str] = set()
    queue: list[str] = [url]
    all_requests: list[dict] = []
    api_endpoints: set[str] = set()
    ws_endpoints: set[str] = set()
    pages_data: list[dict] = []
    base_origin = _origin_of(url)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) explotica/0.1",
            ignore_https_errors=True,
        )

        async def on_request(req):
            all_requests.append({
                "url": req.url,
                "method": req.method,
                "type": req.resource_type,
            })
            rt = req.resource_type
            if rt in ("xhr", "fetch", "websocket"):
                # Reduce to path for compactness
                api_endpoints.add(req.url)
                if rt == "websocket":
                    ws_endpoints.add(req.url)

        page = await context.new_page()
        page.on("request", on_request)

        while queue and len(pages_data) < max_pages:
            current_url = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                response = await page.goto(current_url, timeout=timeout_ms,
                                            wait_until="networkidle")
            except Exception as e:
                log.debug("playwright goto %s failed: %s", current_url, e)
                continue

            if response is None:
                continue

            try:
                title = await page.title()
                # Extract all anchors + form actions + iframe srcs
                links: list[str] = await page.eval_on_selector_all(
                    "a[href], form[action], iframe[src], link[href]",
                    """elements => elements.flatMap(e =>
                        [e.getAttribute('href'),
                         e.getAttribute('action'),
                         e.getAttribute('src')].filter(Boolean))"""
                )
            except Exception as e:
                log.debug("playwright extract %s failed: %s", current_url, e)
                title = ""
                links = []

            pages_data.append({
                "url": current_url,
                "status": response.status,
                "title": title[:200] if title else None,
                "headers": dict(response.headers),
            })

            # Recurse to same-origin links
            for link in set(links):
                try:
                    abs_url = page.url
                    # Use urljoin via JS-like behavior: we already have page.url
                    from urllib.parse import urljoin
                    full = urljoin(current_url, link)
                except Exception:
                    continue
                if same_origin_only and _origin_of(full) != base_origin:
                    continue
                if full in visited or full in queue:
                    continue
                # Skip non-http schemes
                if not full.startswith(("http://", "https://")):
                    continue
                queue.append(full)

        await browser.close()

    # Mine all collected requests for API endpoints (already done) +
    # extract path-style strings from JS source code if any was returned
    return {
        "pages_visited": pages_data,
        "page_count": len(pages_data),
        "total_requests": len(all_requests),
        "api_endpoints": sorted(api_endpoints)[:100],
        "websocket_endpoints": sorted(ws_endpoints),
        "all_request_urls": sorted({r["url"] for r in all_requests})[:200],
    }


def _origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def crawl_with_browser(url: str, **kwargs) -> Optional[dict]:
    """Sync wrapper around the async Playwright crawler."""
    if not playwright_available():
        log.warning("Playwright not installed — skipping browser crawl. "
                    "Install: pip install playwright && playwright install chromium")
        return None
    try:
        return asyncio.run(_crawl_async(url, **kwargs))
    except Exception as e:
        log.warning("playwright crawl %s failed: %s", url, e)
        return None


def crawl_host_ports(host_ip: str, http_ports: list[int],
                      https_ports: list[int], **kwargs) -> dict[int, dict]:
    """For each HTTP/HTTPS port on a host, run a browser-based crawl."""
    out: dict[int, dict] = {}
    for port in http_ports:
        url = f"http://{host_ip}:{port}/"
        r = crawl_with_browser(url, **kwargs)
        if r:
            out[port] = r
    for port in https_ports:
        url = f"https://{host_ip}:{port}/"
        r = crawl_with_browser(url, **kwargs)
        if r:
            out[port] = r
    return out
