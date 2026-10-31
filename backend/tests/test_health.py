from fastapi.testclient import TestClient

from app.main import app


def test_health():
    with TestClient(app) as client:
        res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["app"] == "PacketMind"


def test_system_info_has_no_secrets(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "super-secret-key")
    with TestClient(app) as client:
        res = client.get("/api/system")
    assert res.status_code == 200
    body = res.json()
    assert body["ai"]["configured"] is True and body["ai"]["provider"] == "Google Gemini"
    assert body["live"]["privileges"] in {"likely", "unlikely", "unknown"}
    assert "super-secret-key" not in res.text


def test_system_info_reports_unconfigured_ai(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("app.api.system.get_ai_settings", lambda: __import__("app.config", fromlist=["AiSettings"]).AiSettings(_env_file=None))
    with TestClient(app) as client:
        assert client.get("/api/system").json()["ai"]["configured"] is False


def test_unhandled_error_returns_structured_500(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")
    with TestClient(app, raise_server_exceptions=False) as client:
        monkeypatch.setattr("app.main.engine.connect", boom)  # after startup, which needs the real DB
        res = client.get("/api/health")
    assert res.status_code == 500 and res.json()["detail"]["code"] == "server_error"
    assert "kaboom" not in res.text
