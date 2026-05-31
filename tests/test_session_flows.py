"""Offline verification of the CSRF-rotation + multi-step flow engine.

A mock server rotates the anti-CSRF token on every response; we assert the
session always re-extracts and resubmits the freshest token, and that a scripted
multi-step flow threads cookies + captured variables + rotated tokens correctly.
"""

from urllib.parse import parse_qs

from explotica.active import session_flows as S


class RotatingServer:
    """Issues a fresh csrf token each response; records tokens submitted."""

    def __init__(self, *, fail_step=None):
        self.counter = 0
        self.received_tokens = []
        self.issued = []
        self.requests = []
        self.fail_step = fail_step

    def __call__(self, method, url, headers, body):
        self.requests.append({"method": method, "url": url,
                              "cookie": headers.get("Cookie")})
        form = parse_qs(body.decode("utf-8")) if body else {}
        if method == "POST":
            self.received_tokens.append(form.get("csrf_token", [None])[0])
        self.counter += 1
        tok = f"token{self.counter}"
        self.issued.append(tok)
        # Optionally fail a specific URL to test halt behavior.
        status = 500 if (self.fail_step and self.fail_step in url) else 200
        body_html = (
            f'<html><form><input type="hidden" name="csrf_token" '
            f'value="{tok}"></form>'
            f'<div id="cart">cart_id=CART{self.counter}</div></html>')
        headers_out = {"Set-Cookie": f"session=sess{self.counter}"}
        return (status, headers_out, body_html.encode())


class TestCookieJar:
    def test_update_and_header(self):
        jar = S.CookieJar()
        jar.update({"Set-Cookie": "session=abc; Path=/; HttpOnly"})
        jar.update({"Set-Cookie": ["csrf=xyz; Secure"]})
        assert jar.get("session") == "abc"
        assert jar.get("csrf") == "xyz"
        h = jar.header()
        assert "session=abc" in h and "csrf=xyz" in h


class TestTokenExtraction:
    def test_hidden_input(self):
        html = '<input type="hidden" name="csrf_token" value="T123">'
        assert S.extract_tokens(html)["csrf_token"] == "T123"

    def test_meta_tag(self):
        html = '<meta name="csrf-token" content="M456">'
        assert S.extract_tokens(html)["csrf-token"] == "M456"

    def test_django_field(self):
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="D789">'
        assert S.extract_tokens(html)["csrfmiddlewaretoken"] == "D789"

    def test_cookie_token(self):
        jar = S.CookieJar()
        jar.update({"Set-Cookie": "XSRF-TOKEN=cookieval"})
        toks = S.extract_tokens("", {}, jar)
        assert toks["XSRF-TOKEN"] == "cookieval"

    def test_non_csrf_hidden_ignored(self):
        html = '<input type="hidden" name="page_id" value="5">'
        assert "page_id" not in S.extract_tokens(html)


class TestSessionRotation:
    def test_resubmits_freshest_token(self):
        srv = RotatingServer()
        sess = S.Session(srv)
        # GET issues token1.
        sess.request("GET", "http://app/login")
        assert sess.tokens["csrf_token"] == "token1"
        # POST must submit token1 (the freshest), then server issues token2.
        sess.request("POST", "http://app/login", data={"user": "a", "pw": "b"})
        assert srv.received_tokens == ["token1"]
        assert sess.tokens["csrf_token"] == "token2"
        # Second POST must submit the rotated token2.
        sess.request("POST", "http://app/action")
        assert srv.received_tokens == ["token1", "token2"]

    def test_cookies_carried(self):
        srv = RotatingServer()
        sess = S.Session(srv)
        sess.request("GET", "http://app/")
        sess.request("GET", "http://app/next")
        # Second request must carry the session cookie set by the first.
        assert srv.requests[1]["cookie"] is not None
        assert "session=sess1" in srv.requests[1]["cookie"]

    def test_rotation_flagged(self):
        srv = RotatingServer()
        sess = S.Session(srv)
        sess.request("GET", "http://app/")
        r2 = sess.request("GET", "http://app/2")
        assert r2["token_rotated"] is True


class TestMultiStepFlow:
    def test_login_cart_checkout(self):
        srv = RotatingServer()
        steps = [
            # Real flows GET the form first to obtain the initial token.
            S.FlowStep("get_login", "GET", "http://app/login"),
            S.FlowStep("login", "POST", "http://app/login",
                       data={"user": "a", "pw": "b"}),
            S.FlowStep("view_cart", "GET", "http://app/cart",
                       extract={"cart_id": r"cart_id=(CART\d+)"}),
            S.FlowStep("checkout", "POST", "http://app/checkout/{{cart_id}}",
                       data={"confirm": "1"}),
        ]
        report = S.run_flow(steps, srv)
        assert report["completed"] is True
        assert len(report["steps"]) == 4
        # The captured cart_id must have been interpolated into the checkout URL.
        checkout = report["steps"][3]
        assert "CART" in checkout["url"]
        # Once a token exists, every POST carried a freshest token — never None.
        assert srv.received_tokens and None not in srv.received_tokens

    def test_flow_halts_on_unexpected_status(self):
        srv = RotatingServer(fail_step="/checkout")
        steps = [
            S.FlowStep("login", "POST", "http://app/login", data={"u": "a"}),
            S.FlowStep("checkout", "POST", "http://app/checkout",
                       data={"c": "1"}),
            S.FlowStep("receipt", "GET", "http://app/receipt"),
        ]
        report = S.run_flow(steps, srv)
        assert report["completed"] is False
        # Flow must stop at the failing step — receipt never runs.
        assert len(report["steps"]) == 2
        assert report["steps"][1]["ok"] is False
