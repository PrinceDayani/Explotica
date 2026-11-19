"""Dashboard launch-endpoint security: capability token + DNS-rebinding guard.

Exercises build_app() with FastAPI's TestClient so no real server is started
and no scan subprocess is spawned (the token check runs before mgr.start).
"""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from explotica.output import dashboard  # noqa: E402


class _DummyMgr:
    """Stand-in job manager; start() must never be reached in these tests."""
    def start(self, *a, **k):  # pragma: no cover - should not be called
        raise AssertionError("mgr.start reached despite auth failure")

    def list_jobs(self):
        return []

    def get(self, job_id):
        return None

    def active_count(self):
        return 0


def _client(allow_launch=True):
    state = {"scan_path": None}
    app, token = dashboard.build_app(
        state, _DummyMgr(), host="127.0.0.1", allow_launch=allow_launch
    )
    # base_url sets the default Host header to a loopback name so ordinary
    # requests pass the DNS-rebinding guard.
    return TestClient(app, base_url="http://127.0.0.1"), token


class _OkMgr(_DummyMgr):
    """Manager whose start() succeeds, to prove a valid token launches."""
    def start(self, target, profile, aggressive):
        return {"id": "job-1", "target": target, "status": "running"}


def test_launch_accepted_with_valid_token():
    state = {"scan_path": None}
    app, token = dashboard.build_app(
        state, _OkMgr(), host="127.0.0.1", allow_launch=True
    )
    client = TestClient(app, base_url="http://127.0.0.1")
    r = client.post(
        "/api/scan",
        json={"target": "10.0.0.1", "profile": "quick"},
        headers={"X-Explotica-Token": token},
    )
    assert r.status_code == 200
    assert r.json()["job_id"] == "job-1"


def test_launch_rejected_without_token():
    client, _token = _client()
    r = client.post("/api/scan", json={"target": "10.0.0.1", "profile": "quick"})
    assert r.status_code == 403


def test_launch_rejected_with_wrong_token():
    client, _token = _client()
    r = client.post(
        "/api/scan",
        json={"target": "10.0.0.1", "profile": "quick"},
        headers={"X-Explotica-Token": "not-the-token"},
    )
    assert r.status_code == 403


def test_token_is_embedded_in_page():
    client, token = _client()
    body = client.get("/").text
    assert token in body


def test_dns_rebinding_host_header_rejected():
    client, token = _client()
    r = client.get("/api/health", headers={"host": "attacker.example.com"})
    assert r.status_code == 421


def test_loopback_host_header_allowed():
    client, _token = _client()
    r = client.get("/api/health", headers={"host": "127.0.0.1:8765"})
    assert r.status_code == 200


def _remote_client(auth_token="s3cret"):
    state = {"scan_path": None}
    app, _tok = dashboard.build_app(
        state, _OkMgr(), host="0.0.0.0", allow_launch=True, auth_token=auth_token
    )
    # Remote bind: no loopback Host guard, so any Host is fine; auth is Basic.
    return TestClient(app, base_url="http://example.com")


def test_remote_requires_basic_auth():
    client = _remote_client()
    r = client.get("/api/health")
    assert r.status_code == 401
    assert r.headers.get("www-authenticate", "").startswith("Basic")


def test_remote_accepts_correct_basic_auth():
    client = _remote_client(auth_token="s3cret")
    r = client.get("/api/health", auth=("admin", "s3cret"))
    assert r.status_code == 200


def test_remote_rejects_wrong_basic_auth():
    client = _remote_client(auth_token="s3cret")
    r = client.get("/api/health", auth=("admin", "wrong"))
    assert r.status_code == 401


def test_remote_page_also_requires_auth():
    client = _remote_client(auth_token="s3cret")
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("x", "s3cret")).status_code == 200


def test_viewer_mode_disables_launch():
    client, _token = _client(allow_launch=False)
    r = client.post(
        "/api/scan",
        json={"target": "10.0.0.1"},
        headers={"X-Explotica-Token": "anything"},
    )
    assert r.status_code == 403
