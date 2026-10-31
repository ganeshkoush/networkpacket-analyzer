import os
import sys
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
# True inside the PyInstaller bundle: PROJECT_ROOT is then inside the (read-only) app, so nothing may be written there.
FROZEN = bool(getattr(sys, "frozen", False))


def _data_dir() -> Path | None:
    """PACKETMIND_DATA_DIR: where the installed app keeps everything it writes (set by the desktop shell to the macOS
    Application Support folder). Unset in development, where the project folders are used as before."""
    raw = os.environ.get("PACKETMIND_DATA_DIR", "").strip()
    return Path(raw).expanduser() if raw else None


DATA_DIR = _data_dir()
if FROZEN and DATA_DIR is None:
    raise RuntimeError("PACKETMIND_DATA_DIR must be set when running the packaged backend (the desktop app sets it).")


def _under_data(sub: str, dev: Path) -> Path:
    return DATA_DIR / sub if DATA_DIR else dev


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PACKETMIND_", env_file=None if FROZEN else ".env", extra="ignore")

    app_name: str = "PacketMind"
    version: str = "0.1.0"
    # Bind to loopback only: packet data never leaves the machine via this API.
    host: str = "127.0.0.1"
    port: int = 8765
    database_url: str = f"sqlite:///{_under_data('packetmind.db', PROJECT_ROOT / 'backend' / 'data' / 'packetmind.db')}"
    # Per-launch secret shared with the desktop shell. When set, every /api request except the readiness check must carry it
    # in the X-PacketMind-Token header (stops other local programs and web pages from calling the API). env: PACKETMIND_API_TOKEN
    api_token: SecretStr | None = None
    # Uploads are streamed to disk, analyzed, then deleted.
    uploads_dir: Path = _under_data("uploads", PROJECT_ROOT / "backend" / "data" / "uploads")
    max_upload_bytes: int = 4 * 1024**3  # 4 GiB
    max_retained_analyses: int = 10
    # Remember per-domain performance aggregates (names + numbers only) in the local database to learn baselines.
    # env: PACKETMIND_PERF_HISTORY_ENABLED=false turns recording off.
    perf_history_enabled: bool = True
    perf_history_max_per_domain: int = 500
    analysis_workers: int = 2
    captures_dir: Path = _under_data("captures", PROJECT_ROOT / "captures")
    reports_dir: Path = _under_data("reports", PROJECT_ROOT / "reports")
    log_level: str = "INFO"  # env: PACKETMIND_LOG_LEVEL
    log_file: Path | None = _under_data("logs/packetmind.log", PROJECT_ROOT / "backend" / "data" / "logs" / "packetmind.log")
    cors_origins: list[str] = [
        "http://localhost:1420",
        "http://127.0.0.1:1420",
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
    ]

    def database_path_dir(self) -> Path:
        """Directory holding the SQLite file (or the working dir for non-file URLs)."""
        prefix = "sqlite:///"
        return Path(self.database_url[len(prefix):]).parent if self.database_url.startswith(prefix) else Path(".")


settings = Settings()


class AiSettings(BaseSettings):
    """Gemini configuration, loaded centrally from the environment / `.env` (never committed)."""

    model_config = SettingsConfigDict(
        # An installed app has no source tree, so no .env is read there: the key comes from the keychain (Settings) or the environment.
        env_file=() if FROZEN else (PROJECT_ROOT / ".env", PROJECT_ROOT / "backend" / ".env"), extra="ignore", populate_by_name=True)

    gemini_api_key: SecretStr | None = None  # env: GEMINI_API_KEY; SecretStr keeps it out of repr/logs
    gemini_model: str = "gemini-2.5-flash"  # env: GEMINI_MODEL
    gemini_timeout_seconds: float = 60.0  # env: GEMINI_TIMEOUT_SECONDS
    gemini_max_output_tokens: int = 4096  # env: GEMINI_MAX_OUTPUT_TOKENS

    def api_key_value(self) -> str | None:
        """The key in use: one the user saved in the OS keychain (Settings → AI / Gemini) wins over GEMINI_API_KEY."""
        try:
            from app.services.secret_store import stored_gemini_key

            stored = stored_gemini_key()
        except Exception:
            stored = None
        if stored:
            return stored
        key = self.gemini_api_key.get_secret_value().strip() if self.gemini_api_key else ""
        return key or None


def get_ai_settings() -> AiSettings:
    """Read fresh each call so changes to the environment/.env apply without restarting tests.

    The model and timeout the user chose in Settings → AI / Gemini take precedence over GEMINI_MODEL / GEMINI_TIMEOUT_SECONDS.
    """
    cfg = AiSettings()
    try:
        from app.services.app_settings import current_settings

        chosen = current_settings().ai
        if chosen.model:
            cfg.gemini_model = chosen.model
        if chosen.timeout_seconds:
            cfg.gemini_timeout_seconds = float(chosen.timeout_seconds)
    except Exception:
        pass
    return cfg
