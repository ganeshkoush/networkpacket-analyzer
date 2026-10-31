"""Database information, backup, restore and clearing analysis history (Settings → Database).

All dangerous actions are explicit (``confirm``), never delete capture files unless that exact option is chosen, and restore
makes a safety copy of the current database first.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from app.config import settings
from app.database import engine
from app.migrations import MIGRATIONS, current_version, migrate
from app.services.app_settings import current_settings, get_settings_service
from app.services.capture_store import get_capture_store
from app.services.performance_history import get_history
from app.services.storage import database_file

logger = logging.getLogger(__name__)
MAX_RESTORE_BYTES = 4 * 1024**3
_SQLITE_MAGIC = b"SQLite format 3\x00"
_REQUIRED_TABLES = {"reports", "captures", "perf_sources"}


class DatabaseError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _count(table: str, where: str = "") -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(f"SELECT COUNT(*) FROM {table} {where}")).scalar() or 0)  # table names are literals from this module


def info() -> dict:
    from app.services.storage import usage

    path = database_file()
    with engine.connect() as conn:
        findings = int(conn.execute(text("SELECT COALESCE(SUM(finding_count), 0) FROM reports")).scalar() or 0)
    s = current_settings()
    return {"type": "SQLite", "path": str(path) if path else None, "size_bytes": usage()["database"], "schema_version": current_version(engine),
            "captures": _count("captures"), "reports": _count("reports"), "findings_in_reports": findings,
            "history_domains_observations": _count("perf_observations"), "retention_days": s.privacy.data_retention_days,
            "notes": ["Findings are not stored on their own: they exist while an analysis is open and in saved reports."]}


def backup(destination: Path) -> int:
    """Write a consistent copy of the database (SQLite online backup) to ``destination`` (already validated). Returns its size."""
    src_path = database_file()
    if src_path is None or not src_path.exists():
        raise DatabaseError("no_database", "The database file was not found.", 404)
    tmp = destination.with_name(f".{destination.name}.packetmind-part")
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            dst.close()
        tmp.replace(destination)
    except (OSError, sqlite3.Error):
        tmp.unlink(missing_ok=True)
        raise DatabaseError("backup_failed", "The database could not be backed up to that location.", 500) from None
    finally:
        src.close()
    return destination.stat().st_size


def validate_backup_file(path: Path) -> None:
    """Refuse anything that is not a healthy PacketMind database of this version or older."""
    try:
        if not path.is_file() or path.is_symlink():
            raise DatabaseError("invalid_backup", "That is not a regular file.")
        if path.stat().st_size > MAX_RESTORE_BYTES:
            raise DatabaseError("invalid_backup", "That file is too large to be a PacketMind database.")
        with path.open("rb") as fh:
            if fh.read(16) != _SQLITE_MAGIC:
                raise DatabaseError("invalid_backup", "That file is not a PacketMind database backup.")
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise DatabaseError("invalid_backup", "That backup is damaged (integrity check failed).")
            version = con.execute("PRAGMA user_version").fetchone()[0]
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        finally:
            con.close()
    except sqlite3.Error:
        raise DatabaseError("invalid_backup", "That file could not be read as a database.") from None
    if version > max(n for n, _ in MIGRATIONS):
        raise DatabaseError("invalid_backup", "That backup was made by a newer PacketMind and cannot be restored here.")
    if not _REQUIRED_TABLES <= tables and version >= 3:
        raise DatabaseError("invalid_backup", "That backup is missing PacketMind tables.")


def restore(source: Path) -> dict:
    """Replace the database content with a validated backup. The current database is saved first (``backups`` folder)."""
    validate_backup_file(source)
    live = database_file()
    if live is None:
        raise DatabaseError("no_database", "The database file was not found.", 404)
    safety_dir = live.parent / "backups"
    safety_dir.mkdir(parents=True, exist_ok=True)
    safety = safety_dir / f"before-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.sqlite3"
    backup(safety)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(live, timeout=30)
        try:
            src.backup(dst)
        finally:
            dst.close()
    except sqlite3.Error:
        raise DatabaseError("restore_failed", "The backup could not be restored. Your previous data is unchanged or saved in the backups folder.", 500) from None
    finally:
        src.close()
    migrate(engine)  # an older backup is brought up to the current schema
    get_settings_service()._current = None  # noqa: SLF001 - settings may have come back with the backup
    return {"safety_copy": safety.name, "info": info()}


def clear_history(*, performance_history: bool, reports: bool, capture_summaries: bool, delete_capture_files: bool) -> dict:
    """Clear analysis history. Capture *files* are deleted only when ``delete_capture_files`` is explicitly true."""
    out = {"performance_history": 0, "reports": 0, "capture_summaries": 0, "captures_deleted": 0}
    if performance_history:
        out["performance_history"] = get_history().clear()
    if reports:
        with engine.begin() as conn:
            out["reports"] = conn.execute(text("DELETE FROM reports")).rowcount or 0
    store = get_capture_store()
    if delete_capture_files:
        for c in store.list(limit=2000):
            if c.status not in ("CAPTURING", "ANALYZING"):
                store.delete(c.id)
                out["captures_deleted"] += 1
    elif capture_summaries:
        out["capture_summaries"] = store.clear_summaries()
    return out


def prune_by_retention() -> dict:
    """Apply the retention settings: old performance history and old saved reports. 0 days = keep."""
    s, now = current_settings(), datetime.now(timezone.utc).timestamp()
    out = {"history_sources": 0, "reports": 0}
    if s.domains.retention_days:
        out["history_sources"] = get_history().prune_older_than(now - s.domains.retention_days * 86400)
    if s.privacy.data_retention_days:
        cutoff = datetime.fromtimestamp(now - s.privacy.data_retention_days * 86400, timezone.utc).isoformat(timespec="seconds")
        with engine.begin() as conn:
            out["reports"] = conn.execute(text("DELETE FROM reports WHERE created_at < :c"), {"c": cutoff}).rowcount or 0
    return out
