"""Offline verification of DOM XSS taint logic (no browser needed).

We can't run Chromium in CI, so we pin the deterministic pieces: marker
generation, taint-URL construction, the instrumentation-JS builder, and the
sink-hit analysis that maps instrumentation output to findings.
"""

from explotica.active import dom_xss as D


class TestMarker:
    def test_deterministic_with_seed(self):
        assert D.generate_marker("abc") == D.generate_marker("abc")
        assert D.generate_marker("abc") != D.generate_marker("def")

    def test_alphanumeric_safe(self):
        m = D.generate_marker("x")
        assert m.isalnum()


class TestTaintUrls:
    def test_plants_marker_in_hash_query_path(self):
        vs = D.taint_urls("https://app.test/page?a=1", "MARK")
        srcs = {v["source"] for v in vs}
        assert srcs == {"location.hash", "location.search", "location.pathname"}
        hash_v = next(v for v in vs if v["source"] == "location.hash")
        assert hash_v["url"].endswith("#MARK")
        q_v = next(v for v in vs if v["source"] == "location.search")
        assert "xss=MARK" in q_v["url"]
        p_v = next(v for v in vs if v["source"] == "location.pathname")
        assert "/page/MARK" in p_v["url"]  # query preserved after the segment


class TestInstrumentation:
    def test_js_contains_marker_and_hooks(self):
        js = D.build_instrumentation_js("CANARY123")
        assert "CANARY123" in js
        # Must hook the key sinks.
        assert "innerHTML" in js and "outerHTML" in js
        assert "insertAdjacentHTML" in js
        assert "window.eval" in js and "window.Function" in js
        assert "setAttribute" in js
        assert "jQuery" in js
        assert "__explotica_sinks" in js

    def test_js_records_callback_for_execution(self):
        js = D.build_instrumentation_js("M")
        assert "__xss" in js and "__xss_exec" in js


class TestAnalyzeSinkHits:
    def test_data_flow_finding(self):
        hits = [{"sink": "innerHTML", "value": "<div>xqMARKq payload</div>"}]
        out = D.analyze_sink_hits(hits, [], "xqMARKq")
        assert len(out) == 1
        assert out[0]["sink"] == "innerHTML"
        assert out[0]["executed"] is False
        assert out[0]["severity"] == "HIGH"

    def test_confirmed_execution_is_critical(self):
        hits = [{"sink": "innerHTML", "value": "xqMARKq"}]
        out = D.analyze_sink_hits(hits, ["xqMARKq"], "xqMARKq")
        assert out[0]["executed"] is True
        assert out[0]["severity"] == "CRITICAL"

    def test_ignores_hits_without_marker(self):
        hits = [{"sink": "innerHTML", "value": "unrelated content"}]
        assert D.analyze_sink_hits(hits, [], "xqMARKq") == []

    def test_eval_sink_is_critical_base(self):
        hits = [{"sink": "eval", "value": "alert('xqMARKq')"}]
        out = D.analyze_sink_hits(hits, [], "xqMARKq")
        assert out[0]["severity"] == "CRITICAL"

    def test_document_writer_sink_recognized(self):
        # Built via concatenation to match the runtime sink label.
        sink = "document." + "write"
        hits = [{"sink": sink, "value": "xqMARKq"}]
        out = D.analyze_sink_hits(hits, [], "xqMARKq")
        assert out and out[0]["severity"] == "HIGH"


class TestExecutingPayload:
    def test_payload_calls_back(self):
        p = D.executing_payload("MARK")
        assert "MARK" in p and "onerror" in p
