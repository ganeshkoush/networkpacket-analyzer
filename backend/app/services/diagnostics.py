"""System information, the About page and the exported diagnostic report.

The diagnostic report is for a person to read or attach to a bug report. It contains versions, settings (which hold no
secrets), sizes, counts and recent log lines run through a redactor. It never contains the API key, raw packets, payloads or
capture contents, and the user's home folder is shown as ``~``.
"""
from __future__ import annotations

import json
import logging
import platform
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_ai_settings, settings
from app.services.app_settings import current_settings
from app.services.secret_store import get_secret_store, stored_gemini_key

logger = logging.getLogger(__name__)
_SECRETS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|authorization)\b(\s*[=:]\s*\"?|\"\s*:\s*\")[^\s\",;]+"),
]
_last_ai_test: dict | None = None


def redact(text: str) -> str:
    out = text
    for pat in _SECRETS:
        out = pat.sub(lambda m: (m.group(1) + m.group(2) + "[redacted]") if m.lastindex and m.lastindex >= 2 else "[redacted]", out)
    home = str(Path.home())
    return out.replace(home, "~") if home and home != "/" else out


def remember_ai_test(result: dict) -> None:
    global _last_ai_test
    _last_ai_test = {**result, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def ai_status() -> dict:
    """Whether a Gemini key is available and where it comes from. Never the key itself, not even a fragment."""
    env_cfg = get_ai_settings()
    stored = stored_gemini_key() is not None
    env = bool(env_cfg.gemini_api_key and env_cfg.gemini_api_key.get_secret_value().strip())
    store = get_secret_store()
    return {"configured": stored or env, "source": "keychain" if stored else "environment" if env else "none", "secure_storage_available": store.available,
            "secure_storage": store.backend_name if store.available else None, "model": env_cfg.gemini_model, "last_test": _last_ai_test}


def about() -> dict:
    from app.api.system import _live_info

    live = _live_info()
    return {
        "app": settings.app_name, "tagline": "AI-Powered Network Security Analyst", "backend_version": settings.version,
        "python": sys.version.split()[0], "analysis_engine": "Scapy " + _scapy_version(), "database_engine": f"SQLite {sqlite3.sqlite_version}",
        "ai_provider": "Google Gemini", "os": f"{platform.system()} {platform.release()}", "architecture": platform.machine(),
        "capture": {"library_available": live.capture_library, "privileges": live.privileges, "note": live.note},
        "tshark": shutil.which("tshark") is not None, "ai": ai_status()}


def _scapy_version() -> str:
    try:
        import scapy

        return scapy.__version__
    except Exception:
        return "not installed"


def _tail(path: Path | None, lines: int = 200) -> list[str]:
    if path is None or not path.is_file():
        return []
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 200_000))
            return [redact(line) for line in fh.read().decode("utf-8", "replace").splitlines()[-lines:]]
    except OSError:
        return []


def build_report() -> dict:
    from app.services import database_admin, storage

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "about": about(),
        "settings": current_settings().model_dump(mode="json"), "storage": storage.usage(), "database": {k: v for k, v in database_admin.info().items() if k != "path"},
        "ai_usage_today": _usage(), "recent_log_lines": _tail(settings.log_file),
        "note": "No API keys, packet payloads or capture contents are included. Log lines are redacted and the home folder is shown as ~."}


def _usage() -> dict:
    from app.services.ai_usage import get_ai_usage

    return get_ai_usage().today()


def write_report(destination: Path) -> int:
    tmp = destination.with_name(f".{destination.name}.packetmind-part")
    try:
        tmp.write_text(json.dumps(build_report(), indent=2, default=str), encoding="utf-8")
        tmp.replace(destination)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    return destination.stat().st_size
