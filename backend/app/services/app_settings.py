"""The settings service: the single place user settings are loaded, validated, saved, reset, exported and imported.

Backend code never reads a setting from the database itself: it calls ``current()`` (cheap, in-memory) or one of the
builders in ``effective_config.py``. Saves are validated as a whole (``AppSettings``) before anything is stored.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine, text

from app.models.app_settings import SECTIONS, AppSettings

logger = logging.getLogger(__name__)
EXPORT_FORMAT = "packetmind-settings"
EXPORT_VERSION = 1


class SettingsError(Exception):
    """The settings were rejected; ``errors`` are clear, per-field messages safe to show."""

    def __init__(self, errors: list[dict[str, str]]):
        super().__init__("; ".join(e["message"] for e in errors))
        self.errors = errors


def _label(path: tuple) -> str:
    return " → ".join(str(p).replace("_", " ") for p in path)


def describe_errors(exc: ValidationError) -> list[dict[str, str]]:
    out = []
    for e in exc.errors():
        loc = tuple(p for p in e["loc"] if p != "__root__")
        ctx, kind, field = e.get("ctx", {}), e["type"], ".".join(str(p) for p in e["loc"])
        name = _label(loc) or "Settings"
        if kind == "greater_than_equal":
            msg = f"{name} must be at least {ctx['ge']}."
        elif kind == "greater_than":
            msg = f"{name} must be greater than {ctx['gt']}."
        elif kind == "less_than_equal":
            msg = f"{name} must be at most {ctx['le']}."
        elif kind == "extra_forbidden":
            msg = f"'{loc[-1] if loc else '?'}' is not a PacketMind setting."
        elif kind in ("literal_error", "enum"):
            msg = f"{name} must be one of: {ctx.get('expected', 'the listed options')}."
        elif kind in ("bool_parsing", "bool_type"):
            msg = f"{name} must be on or off."
        elif kind in ("int_parsing", "float_parsing", "int_type", "float_type"):
            msg = f"{name} must be a number."
        elif kind == "string_pattern_mismatch":
            msg = f"{name} contains characters that are not allowed."
        elif kind == "value_error":
            msg = str(e["msg"]).removeprefix("Value error, ")
        else:
            msg = f"{name} is not valid."
        out.append({"field": field, "message": msg})
    return out


def merge(base: dict, patch: dict) -> dict:
    """Deep-merge ``patch`` into ``base`` (new dict). Only dicts merge; everything else is replaced."""
    out = dict(base)
    for k, v in patch.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


class SettingsService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._lock = threading.RLock()
        self._current: AppSettings | None = None
        self.version = 0
        self._listeners: list = []

    def on_change(self, fn) -> None:
        self._listeners.append(fn)

    # ------------------------------------------------------------------ read
    def current(self) -> AppSettings:
        with self._lock:
            if self._current is None:
                self._current = self._load()
            return self._current

    def _load(self) -> AppSettings:
        try:
            with self._engine.connect() as conn:
                row = conn.execute(text("SELECT content FROM app_settings WHERE id = 1")).first()
            if row is None:
                return AppSettings()
            return AppSettings.model_validate_json(row[0])
        except Exception:
            # Unreadable or invalid stored settings must never stop PacketMind: fall back to the defaults (and say so).
            logger.warning("Stored settings could not be read; using defaults")
            return AppSettings()

    # ------------------------------------------------------------------ write
    def update(self, patch: dict[str, Any]) -> AppSettings:
        """Apply a (partial) change. All-or-nothing: an invalid value changes nothing."""
        with self._lock:
            merged = merge(self.current().model_dump(mode="json"), patch)
            return self._save(self._validate(merged))

    def replace(self, data: dict[str, Any]) -> AppSettings:
        with self._lock:
            return self._save(self._validate(merge(AppSettings().model_dump(mode="json"), data)))

    def reset(self, section: str | None = None) -> AppSettings:
        with self._lock:
            if section is None:
                return self._save(AppSettings())
            if section not in SECTIONS:
                raise SettingsError([{"field": section, "message": f"'{section}' is not a settings section."}])
            data = self.current().model_dump(mode="json")
            data[section] = AppSettings().model_dump(mode="json")[section]
            return self._save(self._validate(data))

    @staticmethod
    def _validate(data: dict) -> AppSettings:
        try:
            return AppSettings.model_validate(data)
        except ValidationError as exc:
            raise SettingsError(describe_errors(exc)) from None

    def _save(self, new: AppSettings) -> AppSettings:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO app_settings (id, content, updated_at) VALUES (1, :c, :t)
                ON CONFLICT(id) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at"""),
                {"c": new.model_dump_json(), "t": now})
        old, self._current = self._current, new
        self.version += 1
        for fn in list(self._listeners):
            try:
                fn(old, new)
            except Exception:
                logger.exception("A settings listener failed")
        return new

    # ------------------------------------------------------------------ export / import
    def export(self) -> dict:
        """Everything except secrets (there are none in the model) in a self-describing, versioned document."""
        return {"format": EXPORT_FORMAT, "version": EXPORT_VERSION,
                "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "settings": self.current().model_dump(mode="json")}

    def import_document(self, doc: Any) -> AppSettings:
        if not isinstance(doc, dict) or doc.get("format") != EXPORT_FORMAT:
            raise SettingsError([{"field": "format", "message": "This is not a PacketMind settings file."}])
        if doc.get("version") != EXPORT_VERSION:
            raise SettingsError([{"field": "version", "message": f"Unsupported settings file version ({doc.get('version')!r}); expected {EXPORT_VERSION}."}])
        body = doc.get("settings")
        if not isinstance(body, dict):
            raise SettingsError([{"field": "settings", "message": "The settings file has no settings."}])
        return self.replace(body)


_service: SettingsService | None = None
_svc_lock = threading.Lock()


def get_settings_service() -> SettingsService:
    global _service
    with _svc_lock:
        if _service is None:
            from app.database import engine
            from app.migrations import migrate

            migrate(engine)
            _service = SettingsService(engine)
        return _service


def current_settings() -> AppSettings:
    """What every backend module calls. Never raises: a broken store yields the defaults."""
    try:
        return get_settings_service().current()
    except Exception:
        logger.warning("Settings unavailable; using defaults")
        return AppSettings()
