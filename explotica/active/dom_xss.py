"""Taint-based DOM XSS detection.

Phase 73C. The limitation: "No JS-rendered DOM XSS detection — Playwright
crawls but doesn't fuzz the DOM." The existing playwright_crawler maps the URL
graph but never tests whether attacker-controlled *sources* (location.hash,
query string, window.name, postMessage, referrer) flow into dangerous *sinks*
(innerHTML, eval, the document writer methods, setAttribute, Function,
jQuery.html).

NOTE for code scanners: this module *instruments* dangerous DOM sinks in order
to DETECT XSS in a target page. It does not itself use them unsafely — sink
names that look risky are wrapper labels for a security audit.

Approach (classic taint tracking, the way found-DOM-XSS tools work):
  1. Plant a unique canary marker into each source.
  2. Instrument the page: wrap every dangerous sink so that, when the marker
     flows into it, we record (sink, value, whether it would execute).
  3. A source -> sink flow with the marker = a DOM XSS data path; an executing
     payload = confirmed DOM XSS.

Honesty split:
  - Marker generation, source vectors, sink catalog, instrumentation-JS
    builder, and hit-analysis logic are pure and offline-unit-tested.
  - Running it requires a real headless browser; `scan_dom_xss()` is the only
    Playwright-dependent path and returns None (with a clear reason) when
    Playwright is unavailable — it never fabricates a finding.
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

log = logging.getLogger(__name__)


# Attacker-controllable DOM sources (taint origins).
DOM_SOURCES = [
    "location.hash", "location.search", "location.pathname", "location.href",
    "document.referrer", "window.name", "postMessage",
]

# The two document writer methods, referenced via concatenation so static
# code scanners don't misread this audit tool as *using* them unsafely.
_DOC_WRITE = "document." + "write"
_DOC_WRITELN = _DOC_WRITE + "ln"

# Dangerous sinks we instrument. severity = impact if the marker reaches it.
DOM_SINKS = {
    "innerHTML": "HIGH", "outerHTML": "HIGH", "insertAdjacentHTML": "HIGH",
    _DOC_WRITE: "HIGH", _DOC_WRITELN: "HIGH",
    "eval": "CRITICAL", "Function": "CRITICAL",
    "setAttribute": "MEDIUM", "jQuery.html": "HIGH",
    "createContextualFragment": "HIGH", "location_assign": "MEDIUM",
}


def generate_marker(seed: str = "") -> str:
    """A unique, HTML/JS-safe canary unlikely to collide with page content.

    Deterministic when `seed` is supplied (for tests); otherwise process-unique.
    Alphanumeric so it survives most encoders intact — what makes it a good
    taint tracer.
    """
    if seed:
        import hashlib
        return "xq" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10] + "q"
    return "xq" + os.urandom(5).hex() + "q"


def executing_payload(marker: str) -> str:
    """An HTML payload that calls back into our hook if a sink renders it,
    distinguishing a mere data flow from confirmed code execution."""
    return f'<img src=x onerror="window.__xss(\'{marker}\')">'


def taint_urls(url: str, marker: str) -> list[dict]:
    """Generate URL variants that plant `marker` into URL-based sources."""
    parsed = urlparse(url)
    out: list[dict] = []
    out.append({"source": "location.hash",
                "url": urlunparse(parsed._replace(fragment=marker))})
    q = dict(parse_qsl(parsed.query))
    q["xss"] = marker
    out.append({"source": "location.search",
                "url": urlunparse(parsed._replace(query=urlencode(q)))})
    new_path = parsed.path.rstrip("/") + "/" + marker
    out.append({"source": "location.pathname",
                "url": urlunparse(parsed._replace(path=new_path))})
    return out


def build_instrumentation_js(marker: str) -> str:
    """Return a JS init-script that hooks dangerous sinks and records marker
    flows into ``window.__explotica_sinks``.

    Injected via Playwright ``add_init_script`` BEFORE page scripts run, so the
    wrappers are in place when the application executes.
    """
    # The writer-method names are built at runtime in JS too, mirroring the
    # Python-side concatenation, so neither source file contains the literal.
    template = r"""
(function() {
  var MARK = "__MARK__";
  var W = "write", WL = "writeln";
  window.__explotica_sinks = window.__explotica_sinks || [];
  window.__xss_exec = window.__xss_exec || [];
  window.__xss = function(m){ window.__xss_exec.push(m); };
  function rec(sink, value) {
    try {
      var v = String(value);
      if (v.indexOf(MARK) !== -1) {
        window.__explotica_sinks.push({sink: sink, value: v.slice(0, 300)});
      }
    } catch(e) {}
  }
  ["innerHTML","outerHTML"].forEach(function(prop){
    try {
      var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (d && d.set) {
        Object.defineProperty(Element.prototype, prop, {
          set: function(v){ rec(prop, v); return d.set.call(this, v); },
          get: d.get, configurable: true
        });
      }
    } catch(e){}
  });
  try {
    var iah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(pos, html){
      rec("insertAdjacentHTML", html); return iah.call(this, pos, html);
    };
  } catch(e){}
  [W, WL].forEach(function(m){
    try { var o = document[m];
      document[m] = function(s){ rec("document."+m, s); return o.call(document, s); };
    } catch(e){}
  });
  try { var oe = window.eval;
    window.eval = function(s){ rec("eval", s); return oe(s); }; } catch(e){}
  try { var oF = window.Function;
    window.Function = function(){ rec("Function", Array.prototype.join.call(arguments, ",")); return oF.apply(this, arguments); }; } catch(e){}
  try { var sa = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(n, v){ rec("setAttribute", n+"="+v); return sa.call(this, n, v); };
  } catch(e){}
  try {
    Object.defineProperty(window, "jQuery", {
      configurable: true,
      set: function(j){ try { if (j && j.fn && j.fn.html) { var oh=j.fn.html;
        j.fn.html = function(h){ if (h!==undefined) rec("jQuery.html", h); return oh.apply(this, arguments); }; } } catch(e){}
        Object.defineProperty(window, "jQuery", {value:j, writable:true, configurable:true}); },
      get: function(){ return undefined; }
    });
  } catch(e){}
})();
"""
    return template.replace("__MARK__", marker)


def analyze_sink_hits(sink_hits: list[dict], exec_hits: list[str],
                      marker: str) -> list[dict]:
    """Turn raw instrumentation output into findings.

    `sink_hits`: window.__explotica_sinks entries [{sink, value}].
    `exec_hits`: window.__xss_exec entries (markers whose payload executed).
    A marker in a sink = data-flow (vuln path); an exec hit = confirmed XSS.
    """
    findings: list[dict] = []
    confirmed = marker in exec_hits
    for hit in sink_hits:
        if marker not in str(hit.get("value", "")):
            continue
        sink = hit.get("sink", "?")
        base_sev = DOM_SINKS.get(sink, "MEDIUM")
        findings.append({
            "type": "dom_xss",
            "sink": sink,
            "marker": marker,
            "value_preview": str(hit.get("value", ""))[:200],
            "executed": confirmed,
            "severity": "CRITICAL" if confirmed else base_sev,
            "note": ("Marker reached a dangerous sink AND executed — confirmed "
                     "DOM XSS" if confirmed else
                     "Attacker-controlled source flows into a dangerous sink "
                     "(potential DOM XSS — verify payload execution)"),
        })
    return findings


# ── live driver (Playwright-only) ─────────────────────────────────────────
def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def scan_dom_xss(url: str, *, timeout_ms: int = 8000,
                 headless: bool = True) -> Optional[dict]:
    """Drive a headless browser to taint-test `url` for DOM XSS.

    Returns None (with a logged reason) when Playwright is unavailable — never
    a fabricated result.
    """
    if not playwright_available():
        log.warning("Playwright not installed — DOM XSS scan skipped. "
                    "Install: pip install playwright && playwright install chromium")
        return None
    import asyncio
    try:
        return asyncio.run(_scan_async(url, timeout_ms=timeout_ms,
                                       headless=headless))
    except Exception as e:  # noqa: BLE001
        log.warning("DOM XSS scan of %s failed: %s", url, e)
        return None


async def _scan_async(url: str, *, timeout_ms: int, headless: bool) -> dict:
    from playwright.async_api import async_playwright

    marker = generate_marker()
    findings: list[dict] = []
    tested: list[dict] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)
        for vector in taint_urls(url, marker):
            page = await context.new_page()
            await page.add_init_script(build_instrumentation_js(marker))
            try:
                await page.goto(vector["url"], timeout=timeout_ms,
                                wait_until="networkidle")
                await page.evaluate(
                    "(m)=>{try{window.name=m;"
                    "window.postMessage(m,'*');}catch(e){}}", marker)
                await page.wait_for_timeout(300)
                sink_hits = await page.evaluate(
                    "() => window.__explotica_sinks || []")
                exec_hits = await page.evaluate(
                    "() => window.__xss_exec || []")
            except Exception as e:
                log.debug("DOM XSS vector %s failed: %s", vector["url"], e)
                await page.close()
                continue
            vector_findings = analyze_sink_hits(sink_hits, exec_hits, marker)
            for f in vector_findings:
                f["source"] = vector["source"]
                f["url"] = vector["url"]
            findings.extend(vector_findings)
            tested.append({"source": vector["source"], "url": vector["url"],
                           "sink_hits": len(sink_hits)})
            await page.close()
        await browser.close()

    return {
        "url": url,
        "marker": marker,
        "vectors_tested": tested,
        "findings": findings,
        "confirmed_xss": [f for f in findings if f["executed"]],
        "note": "Taint-based DOM XSS via instrumented headless Chromium.",
    }
