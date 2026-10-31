"""HTTP API for Settings. One document (``AppSettings``) is read and written as a whole; everything else is an explicit action.

Secrets: the Gemini API key can be *written* here and removed, never read back. Dangerous actions (reset, restore, clear,
cleanup, delete key) need ``confirm=true``. Every file location a request names is validated by ``services/paths.py``.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, get_args

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.config import settings as env
from app.models.app_settings import AI_DATA_POLICY, AI_PERMISSIONS, RESTART_REQUIRED, SECTIONS, UNAVAILABLE, AppSettings
from app.services import database_admin, diagnostics, paths, storage
from app.services.ai_usage import get_ai_usage
from app.services.app_settings import SettingsError, get_settings_service
from app.services.secret_store import GEMINI_KEY, SecretStoreUnavailable, get_secret_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/settings", tags=["settings"])
_KEY = re.compile(r"^[\x21-\x7e]{20,512}$")  # printable ASCII, no spaces: what real API keys look like


def _error(status: int, code: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, **extra})


def _settings_error(exc: SettingsError) -> HTTPException:
    return _error(422, "invalid_settings", exc.errors[0]["message"] if len(exc.errors) == 1 else f"{len(exc.errors)} settings are not valid.", errors=exc.errors)


def _constraints(model: type[BaseModel], prefix: str = "") -> dict[str, dict]:
    """Per-field limits taken from the model itself, so the UI validates with exactly the rules the backend enforces."""
    out: dict[str, dict] = {}
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        ann = field.annotation
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            out.update(_constraints(ann, path + "."))
            continue
        info: dict[str, Any] = {}
        for m in field.metadata:
            for attr, key in (("ge", "min"), ("gt", "exclusive_min"), ("le", "max"), ("lt", "exclusive_max"), ("max_length", "max_length")):
                if getattr(m, attr, None) is not None:
                    info[key] = getattr(m, attr)
        if info:
            args = [a for a in (get_args(ann) or (ann,)) if a is not type(None)]
            info["type"] = "integer" if args and args[0] is int else "number"
            out[path] = info
    return out


_CONSTRAINTS = _constraints(AppSettings)


def _payload() -> dict:
    svc = get_settings_service()
    return {"settings": svc.current().model_dump(mode="json"), "defaults": AppSettings().model_dump(mode="json"), "constraints": _CONSTRAINTS,
            "unavailable": UNAVAILABLE, "restart_required": list(RESTART_REQUIRED), "sections": list(SECTIONS), "version": svc.version,
            "ai": diagnostics.ai_status(), "ai_permissions": AI_PERMISSIONS, "ai_data_policy": AI_DATA_POLICY}


@router.get("")
def get_settings() -> dict:
    return _payload()


@router.put("")
def update_settings(patch: dict[str, Any]) -> dict:
    """Merge a (partial) change into the settings. All-or-nothing: nothing changes if any value is invalid."""
    try:
        get_settings_service().update(patch)
    except SettingsError as exc:
        raise _settings_error(exc) from None
    return _payload()


class ResetRequest(BaseModel):
    section: str | None = Field(None, max_length=40)
    confirm: bool = False


@router.post("/reset")
def reset_settings(req: ResetRequest) -> dict:
    """Restore defaults (one section or all). Touches settings only: captures, reports, findings and the database are kept."""
    if not req.confirm:
        raise _error(400, "confirmation_required", "Resetting settings restores their default values; confirm it explicitly (confirm=true).")
    try:
        get_settings_service().reset(req.section)
    except SettingsError as exc:
        raise _settings_error(exc) from None
    return _payload()


# ------------------------------------------------------------------------------------------------ export / import
@router.get("/export")
def export_settings() -> Response:
    """The settings document (no secrets exist in it) as a download."""
    body = json.dumps(get_settings_service().export(), indent=2)
    return Response(body, media_type="application/json", headers={"Content-Disposition": 'attachment; filename="packetmind-settings.json"',
                                                                   "X-Content-Type-Options": "nosniff"})


class FileDestination(BaseModel):
    destination: str = Field(min_length=1, max_length=4096)
    overwrite: bool = False


def _destination(req: FileDestination, ext: str, protect_data: bool = True) -> Path:
    try:
        return paths.validate_destination(req.destination, extensions=(ext,), default_extension=ext, overwrite=req.overwrite,
                                          protected_dirs=(env.captures_dir, env.reports_dir, env.database_path_dir()) if protect_data else ())
    except paths.PathRejected as exc:
        raise _error(exc.status, exc.code, exc.message) from None


@router.post("/export-file")
def export_settings_file(req: FileDestination) -> dict:
    dest = _destination(req, ".json")
    try:
        dest.write_text(json.dumps(get_settings_service().export(), indent=2), encoding="utf-8")
    except OSError:
        raise _error(500, "export_failed", "The settings could not be written to that location.") from None
    return {"filename": dest.name, "directory": str(dest.parent)}


class ImportRequest(BaseModel):
    document: Any


@router.post("/import")
def import_settings(req: ImportRequest) -> dict:
    """Validate a settings document completely, then apply it. A file can only set known settings to valid values."""
    try:
        get_settings_service().import_document(req.document)
    except SettingsError as exc:
        raise _settings_error(exc) from None
    return _payload()


# ------------------------------------------------------------------------------------------------ AI key / test / usage
class KeyRequest(BaseModel):
    api_key: str = Field(max_length=2000, repr=False)  # repr=False: never printed in logs or tracebacks


@router.put("/ai/key")
def save_api_key(req: KeyRequest) -> dict:
    """Store the Gemini API key in the OS keychain. Write-only: no endpoint ever returns it."""
    key = req.api_key.strip()
    if not _KEY.match(key):
        raise _error(422, "invalid_api_key", "That does not look like an API key (20+ visible characters, no spaces).")
    try:
        get_secret_store().set(GEMINI_KEY, key)
    except SecretStoreUnavailable as exc:
        raise _error(409, "no_secure_storage", f"{exc.args[0]} Set GEMINI_API_KEY in the environment instead.") from None
    get_ai_usage().clear_cache()
    return _payload()


@router.delete("/ai/key")
def delete_api_key(confirm: bool = Query(False)) -> dict:
    if not confirm:
        raise _error(400, "confirmation_required", "Removing the saved API key needs confirmation (confirm=true).")
    get_secret_store().delete(GEMINI_KEY)
    return _payload()


class _Pong(BaseModel):
    ok: bool = True


@router.post("/ai/test")
def test_ai_connection() -> dict:
    """One tiny request to Gemini (counted as a request) that checks the key, the model and the network. Sends no capture data."""
    from app.ai.gemini_client import GeminiClient
    from app.ai.provider import AIProviderError

    started = time.perf_counter()
    try:
        if not get_settings_service().current().security.allow_ai:
            raise _AiOff()
        client = GeminiClient(usage=False)
        client.generate_structured(system_instruction="Reply with the JSON object {\"ok\": true}. Nothing else.", user_content="ping", response_schema=_Pong)
        get_ai_usage().count("request")
        result = {"ok": True, "message": "Connected to Gemini.", "code": None, "model": client.model, "latency_ms": round((time.perf_counter() - started) * 1000)}
    except _AiOff:
        result = {"ok": False, "message": "AI features are turned off in Settings → Security.", "code": "ai_disabled", "model": None, "latency_ms": None}
    except AIProviderError as exc:
        result = {"ok": False, "message": exc.message, "code": exc.code, "model": None, "latency_ms": None}
    except Exception:
        logger.exception("AI connection test failed unexpectedly")
        result = {"ok": False, "message": "The connection test failed unexpectedly.", "code": "unexpected", "model": None, "latency_ms": None}
    diagnostics.remember_ai_test(result)
    return result


class _AiOff(Exception):
    pass


@router.get("/ai/usage")
def ai_usage() -> dict:
    return get_ai_usage().today()


# ------------------------------------------------------------------------------------------------ storage
@router.get("/storage")
def storage_info() -> dict:
    s = get_settings_service().current().storage
    locs = storage.locations()
    return {"usage": storage.usage(), "locations": {k: (str(v) if v else None) for k, v in locs.items()},
            "limits": {"max_capture_storage_gb": s.max_capture_storage_gb}, "note": "Folders are set with PACKETMIND_* environment variables, not from the UI."}


class CleanupRequest(BaseModel):
    dry_run: bool = True
    confirm: bool = False


@router.post("/storage/cleanup")
def storage_cleanup(req: CleanupRequest) -> dict:
    """Preview (default) or perform the capture cleanup described by the retention rules. Deleting needs confirm=true."""
    if not req.dry_run and not req.confirm:
        raise _error(400, "confirmation_required", "Deleting captures needs confirmation (confirm=true). Preview with dry_run first.")
    return storage.cleanup(dry_run=req.dry_run)


class FolderRequest(BaseModel):
    folder: str = Field(max_length=20)


@router.post("/open-folder")
def open_folder(req: FolderRequest) -> dict:
    try:
        storage.open_folder(req.folder)
    except ValueError:
        raise _error(400, "unknown_folder", "That folder cannot be opened from here.") from None
    except (FileNotFoundError, OSError):
        raise _error(404, "folder_unavailable", "That folder could not be opened.") from None
    return {"opened": req.folder}


# ------------------------------------------------------------------------------------------------ database
@router.get("/database")
def database_info() -> dict:
    return database_admin.info()


def _db_error(exc: database_admin.DatabaseError) -> HTTPException:
    return _error(exc.status, exc.code, exc.message)


@router.post("/database/backup")
def database_backup(req: FileDestination) -> dict:
    dest = _destination(req, ".sqlite3")
    try:
        size = database_admin.backup(dest)
    except database_admin.DatabaseError as exc:
        raise _db_error(exc) from None
    return {"filename": dest.name, "directory": str(dest.parent), "size_bytes": size}


class RestoreRequest(BaseModel):
    source: str = Field(min_length=1, max_length=4096)
    confirm: bool = False


@router.post("/database/restore")
def database_restore(req: RestoreRequest) -> dict:
    """Replace PacketMind's database with a backup. Destructive: needs confirm=true; a safety copy of the current one is made first."""
    if not req.confirm:
        raise _error(400, "confirmation_required", "Restoring replaces the current database; confirm it explicitly (confirm=true).")
    src = Path(req.source)
    if not src.is_absolute() or ".." in src.parts or "\x00" in req.source:
        raise _error(400, "invalid_backup", "Choose the backup file in the file dialog.")
    try:
        return database_admin.restore(src.resolve())
    except database_admin.DatabaseError as exc:
        raise _db_error(exc) from None


class ClearRequest(BaseModel):
    performance_history: bool = True
    reports: bool = False
    capture_summaries: bool = True
    delete_capture_files: bool = False
    confirm: bool = False


@router.post("/database/clear")
def database_clear(req: ClearRequest) -> dict:
    """Clear analysis history. Capture files (PCAPs) are only deleted when delete_capture_files is explicitly true."""
    if not req.confirm:
        raise _error(400, "confirmation_required", "Clearing history is permanent; confirm it explicitly (confirm=true).")
    return database_admin.clear_history(performance_history=req.performance_history, reports=req.reports,
                                        capture_summaries=req.capture_summaries, delete_capture_files=req.delete_capture_files)


# ------------------------------------------------------------------------------------------------ diagnostics / about
@router.post("/diagnostics/export")
def export_diagnostics(req: FileDestination) -> dict:
    dest = _destination(req, ".json")
    try:
        size = diagnostics.write_report(dest)
    except OSError:
        raise _error(500, "export_failed", "The diagnostic report could not be written to that location.") from None
    return {"filename": dest.name, "directory": str(dest.parent), "size_bytes": size}


@router.get("/about")
def about() -> dict:
    return diagnostics.about()
