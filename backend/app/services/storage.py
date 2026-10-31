"""Disk usage, retention and cleanup of PacketMind's own data folders.

Nothing is deleted unless (a) the user turned on automatic cleanup in Settings → Storage, or (b) the user confirmed a cleanup
they could preview. Cleanup only ever removes capture-library entries (file + row) chosen by the rules below; reports,
the database and logs are never touched here.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.models.app_settings import StorageSettings
from app.models.capture import CaptureSession
from app.services.app_settings import current_settings
from app.services.capture_store import CaptureStore, get_capture_store

logger = logging.getLogger(__name__)
GB = 1024**3
_BUSY = ("CAPTURING", "ANALYZING")


def dir_size(path: Path) -> int:
    """Total bytes under ``path`` (links are not followed; unreadable entries count as 0)."""
    total = 0
    try:
        for root, _, files in os.walk(path, followlinks=False):
            for name in files:
                try:
                    p = Path(root) / name
                    if not p.is_symlink():
                        total += p.stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total


def database_file() -> Path | None:
    prefix = "sqlite:///"
    url = settings.database_url
    return Path(url[len(prefix):]) if url.startswith(prefix) and ":memory:" not in url else None


def log_dir() -> Path | None:
    return settings.log_file.parent if settings.log_file else None


def locations() -> dict[str, Path | None]:
    return {"captures": settings.captures_dir, "reports": settings.reports_dir, "logs": log_dir(), "database": database_file()}


def usage() -> dict:
    db = database_file()
    db_bytes = sum((db.parent / (db.name + suffix)).stat().st_size for suffix in ("", "-wal", "-shm") if (db.parent / (db.name + suffix)).exists()) if db else 0
    logs = log_dir()
    parts = {"captures": dir_size(settings.captures_dir), "reports": dir_size(settings.reports_dir), "database": db_bytes,
             "logs": dir_size(logs) if logs else 0}
    return {**parts, "total": sum(parts.values()), "temporary_uploads": dir_size(settings.uploads_dir)}


# ------------------------------------------------------------------------------------------------ cleanup rules
def _age_days(c: CaptureSession, now: datetime) -> float:
    try:
        return (now - datetime.fromisoformat(c.created_at)).total_seconds() / 86400
    except ValueError:
        return 0.0


def cleanup_candidates(store: CaptureStore, s: StorageSettings, now: datetime | None = None) -> list[dict]:
    """Which captures the retention rules would remove, oldest first, each with the reason. Pure read."""
    now = now or datetime.now(timezone.utc)
    eligible = [c for c in store.list(limit=2000) if c.status not in _BUSY
                and not (c.status == "ANALYZED" and s.keep_analyzed) and not (c.status == "FAILED" and s.keep_failed)]
    eligible.sort(key=lambda c: c.created_at)
    chosen: dict[str, dict] = {}
    for c in eligible:
        if _age_days(c, now) > s.capture_retention_days:
            chosen[c.id] = {"id": c.id, "name": c.original_filename, "size": c.file_size, "reason": f"older than {s.capture_retention_days} days"}
    limit = int(s.max_capture_storage_gb * GB)
    used = dir_size(store.directory) - sum(v["size"] for v in chosen.values())
    for c in eligible:
        if used <= limit:
            break
        if c.id not in chosen:
            chosen[c.id] = {"id": c.id, "name": c.original_filename, "size": c.file_size, "reason": "needed to stay under the maximum capture storage"}
            used -= c.file_size
    return list(chosen.values())


def cleanup(store: CaptureStore | None = None, *, dry_run: bool = True) -> dict:
    store = store or get_capture_store()
    items = cleanup_candidates(store, current_settings().storage)
    deleted = 0
    if not dry_run:
        for item in items:
            try:
                if store.delete(item["id"]):
                    deleted += 1
            except Exception:
                logger.warning("Could not delete capture %s during cleanup", item["id"])
    return {"dry_run": dry_run, "candidates": items, "deleted": deleted, "freed_bytes": sum(i["size"] for i in items) if not dry_run else 0,
            "would_free_bytes": sum(i["size"] for i in items)}


def ensure_capacity(store: CaptureStore | None = None) -> None:
    """Called before a capture is recorded: refuse (clearly) when the capture storage limit is reached.

    With automatic cleanup *enabled by the user* old captures are removed first; otherwise nothing is deleted.
    """
    from app.capture.live_capture import CaptureRefused

    store = store or get_capture_store()
    s = current_settings().storage
    limit = int(s.max_capture_storage_gb * GB)
    if dir_size(store.directory) < limit:
        return
    if s.auto_delete_old:
        cleanup(store, dry_run=False)
        if dir_size(store.directory) < limit:
            return
    raise CaptureRefused("storage_full", f"The capture storage limit ({s.max_capture_storage_gb:g} GB) is reached. Delete old captures or raise the limit in Settings → Storage.")


def run_automatic_cleanup(store: CaptureStore | None = None) -> int:
    """At startup: only when the user enabled automatic deletion."""
    s = current_settings().storage
    if not s.auto_delete_old:
        return 0
    return cleanup(store, dry_run=False)["deleted"]


def clear_temporary_uploads() -> int:
    """Remove leftover staged uploads (the 'clear temporary capture data on exit' setting). Library captures are never touched."""
    n = 0
    folder = settings.uploads_dir
    if folder.is_dir():
        for p in folder.iterdir():
            try:
                if p.is_file() and not p.is_symlink():
                    p.unlink()
                    n += 1
            except OSError:
                continue
    return n


# ------------------------------------------------------------------------------------------------ open a folder
def open_folder(which: str) -> Path:
    """Open one of PacketMind's own folders in the file manager. The set of folders is fixed; no path comes from the client."""
    targets = {"captures": settings.captures_dir, "reports": settings.reports_dir, "logs": log_dir(), "docs": Path(__file__).resolve().parents[3] / "docs"}
    folder = targets.get(which)
    if folder is None:
        raise ValueError("unknown folder")
    folder.mkdir(parents=True, exist_ok=True) if which != "docs" else None
    if not folder.is_dir():
        raise FileNotFoundError(str(folder))
    cmd = ["open", str(folder)] if sys.platform == "darwin" else ["explorer", str(folder)] if sys.platform.startswith("win") else ["xdg-open", str(folder)]
    subprocess.Popen(cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603 - fixed argv, fixed folders
    return folder
