"""Packaged-app support: per-launch API token, application data directory, permission hint, parent watchdog."""
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app import config
from app.main import create_app


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(config.settings, "api_token", SecretStr("per-launch-secret"))
    return "per-launch-secret"


def test_api_requires_the_token_when_one_is_configured(token):
    with TestClient(create_app()) as c:
        assert c.get("/api/settings").status_code == 401
        body = c.get("/api/settings").json()["detail"]
        assert body["code"] == "unauthorized" and token not in str(body)
        assert c.get("/api/settings", headers={"X-PacketMind-Token": "wrong"}).status_code == 401
        assert c.get("/api/settings", headers={"X-PacketMind-Token": token}).status_code == 200


def test_readiness_probe_and_cors_preflight_stay_open(token):
    with TestClient(create_app()) as c:
        assert c.get("/api/health").status_code == 200
        pre = c.options("/api/analyses", headers={"Origin": "tauri://localhost", "Access-Control-Request-Method": "POST",
                                                  "Access-Control-Request-Headers": "x-packetmind-token"})
        assert pre.status_code == 200


def test_destructive_and_file_endpoints_are_protected_too(token):
    with TestClient(create_app()) as c:
        for method, path in [("delete", "/api/captures/x?confirm=true"), ("post", "/api/captures/x/export"),
                             ("put", "/api/settings"), ("post", "/api/live/start"), ("delete", "/api/baselines?confirm=true")]:
            assert getattr(c, method)(path).status_code == 401, path


def test_no_token_configured_keeps_development_behaviour():
    assert config.settings.api_token is None
    with TestClient(create_app()) as c:
        assert c.get("/api/settings").status_code == 200


def _config_in_subprocess(code: str, env: dict[str, str], frozen: bool = False) -> subprocess.CompletedProcess:
    """Evaluate app.config in a fresh interpreter, so reloading it can never leak into other tests."""
    import os

    backend = Path(__file__).resolve().parents[1]
    prelude = "import sys;" + ("sys.frozen=True;" if frozen else "") + f"sys.path.insert(0,{str(backend)!r});"
    clean = {k: v for k, v in os.environ.items() if not k.startswith("PACKETMIND_")}
    return subprocess.run([sys.executable, "-c", prelude + code], env={**clean, **env}, capture_output=True, text=True, timeout=60, cwd=str(backend))


def test_data_dir_moves_every_writable_location(tmp_path):
    base = tmp_path / "Application Support"
    r = _config_in_subprocess(
        "from app import config as c;s=c.Settings();print(s.database_url);print(s.captures_dir);print(s.reports_dir);print(s.uploads_dir);print(s.log_file)",
        {"PACKETMIND_DATA_DIR": str(base)})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split("\n")[:5] == [f"sqlite:///{base / 'packetmind.db'}", str(base / "captures"), str(base / "reports"),
                                        str(base / "uploads"), str(base / "logs" / "packetmind.log")]


def test_without_data_dir_development_paths_are_unchanged():
    r = _config_in_subprocess("from app import config as c;s=c.Settings();print(s.captures_dir==c.PROJECT_ROOT/'captures', s.reports_dir==c.PROJECT_ROOT/'reports')", {})
    assert r.stdout.strip() == "True True", r.stderr


def test_frozen_backend_refuses_to_start_without_a_data_dir():
    """Frozen code lives in the read-only app bundle: it must never fall back to writing next to itself."""
    r = _config_in_subprocess("from app import config", {}, frozen=True)
    assert r.returncode != 0 and "PACKETMIND_DATA_DIR" in r.stderr


def test_frozen_backend_reads_no_env_files(tmp_path):
    r = _config_in_subprocess("from app import config as c;print(c.AiSettings.model_config['env_file'])", {"PACKETMIND_DATA_DIR": str(tmp_path)}, frozen=True)
    assert r.stdout.strip() == "()", r.stderr


def test_installed_app_permission_hint_names_the_bundled_script(monkeypatch):
    from app.capture import sniffer

    monkeypatch.setattr(sniffer.sys, "platform", "darwin")
    monkeypatch.setenv("PACKETMIND_BPF_SCRIPT", "/Applications/PacketMind.app/Contents/Resources/scripts/macos-bpf-access.sh")
    hint = sniffer.permission_hint()
    assert "/Applications/PacketMind.app/Contents/Resources/scripts/macos-bpf-access.sh" in hint
    assert "Offline PCAP analysis does not need this" in hint
    monkeypatch.delenv("PACKETMIND_BPF_SCRIPT")
    assert "scripts/macos-bpf-access.sh install" in sniffer.permission_hint()


def test_backend_exits_when_its_parent_dies(tmp_path):
    """Orphan protection: started by a parent that then exits, the backend must stop itself."""
    backend = Path(__file__).resolve().parents[1]
    marker = tmp_path / "pid"
    child_code = (
        "import os,sys;sys.path.insert(0, %r);import main;main._exit_when_parent_dies(int(os.environ['PACKETMIND_PARENT_PID']));"
        "import time;open(%r,'w').write(str(os.getpid()));time.sleep(60)" % (str(backend), str(marker)))
    parent_code = (
        "import os,subprocess,sys;env=dict(os.environ,PACKETMIND_PARENT_PID=str(os.getpid()));"
        "subprocess.Popen([sys.executable,'-c',%r],env=env,cwd=%r);import time;time.sleep(3)" % (child_code, str(backend)))
    subprocess.run([sys.executable, "-c", parent_code], check=True, timeout=30)
    import os
    import time

    pid = int(marker.read_text())
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.25)
    os.kill(pid, 9)
    pytest.fail("orphaned backend kept running after its parent exited")
