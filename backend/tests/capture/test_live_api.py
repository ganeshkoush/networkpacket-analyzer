import pytest
from fastapi.testclient import TestClient
from live_helpers import FakeSource, make_manager, scan

import app.api.live as live_api
from app.capture import CaptureStartError
from app.main import create_app


@pytest.fixture
def client(monkeypatch):
    def _make(source=None):
        mgr, src, _ = make_manager(source)
        monkeypatch.setattr(live_api, "_manager", mgr)
        return TestClient(create_app()), mgr, src
    return _make


def test_interfaces_endpoint_lists_real_interfaces(client):
    c, *_ = client()
    r = c.get("/api/live/interfaces")
    assert r.status_code == 200 and {"name", "kind", "description"} <= set(r.json()[0])


def test_status_before_start_is_stopped_and_idle(client):
    c, mgr, src = client()
    assert c.get("/api/live/status").json()["state"] == "stopped" and src.callback is None


def test_start_requires_confirm(client):
    c, _, src = client()
    r = c.post("/api/live/start", json={"interface": "test0"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "confirmation_required" and src.callback is None
    r = c.post("/api/live/start", json={"interface": "nope", "confirm": True})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "unknown_interface"


def test_start_status_stop_flow(client):
    c, mgr, src = client()
    assert c.post("/api/live/start", json={"interface": "test0", "confirm": True}).json()["state"] == "capturing"
    assert c.post("/api/live/start", json={"interface": "test0", "confirm": True}).status_code == 409
    src.emit(scan(10))
    s = c.get("/api/live/status").json()
    assert s["state"] == "capturing" and s["packets_total"] == 20 and s["auto_investigate"] is False
    assert c.post("/api/live/stop").json()["state"] == "stopped"


def test_permission_error_returns_403_with_hint_and_status_shows_it(client):
    err = CaptureStartError("permission_denied", "Permission denied", "use sudo", permission=True)
    c, *_ = client(FakeSource(error=err))
    r = c.post("/api/live/start", json={"interface": "test0", "confirm": True})
    assert r.status_code == 403 and r.json()["detail"]["hint"] == "use sudo"
    assert c.get("/api/live/status").json()["state"] == "permission_error"
    assert c.post("/api/live/stop").json()["state"] == "stopped"
