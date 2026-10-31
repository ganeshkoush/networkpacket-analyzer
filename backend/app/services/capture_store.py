"""The capture library: SQLite rows (``captures`` table) + files in the managed capture folder.

Safety rules enforced here, not by callers:

* file names on disk are generated (timestamp + random id); user-supplied names are only ever sanitised *display* names
* every path is resolved and must stay inside the managed folder
* capture files are created owner-only (0600): captured traffic can contain sensitive information
* deleting a capture removes its file and row; the original bytes are never modified by analysis or export
"""
from __future__ import annotations

import os
import re
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Engine, text

from app.models.capture import CaptureFormat, CaptureSession, CaptureStatus, CaptureSummary, SourceType

_ID = re.compile(r"^[0-9a-f]{32}$")
_COLUMNS = ("id, filename, original_filename, source_type, capture_format, interface, start_time, end_time, duration_seconds, "
            "packet_count, byte_count, file_size, status, error_message, created_at, analyzed_at, summary")
_UPDATABLE = {"original_filename", "interface", "start_time", "end_time", "duration_seconds", "packet_count", "byte_count",
              "file_size", "status", "error_message", "analyzed_at", "capture_format"}
EXTENSIONS = {"pcap": ".pcap", "pcapng": ".pcapng"}


class CaptureStoreError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def is_valid_id(value: str) -> bool:
    return bool(_ID.match(value or ""))


def sanitize_display_name(raw: str | None, default: str = "capture.pcap") -> str:
    """A name safe to show and to suggest in a save dialog: no directories, no control characters, bounded length."""
    name = Path(str(raw or "").replace("\\", "/")).name
    name = "".join(c for c in unicodedata.normalize("NFC", name) if c.isprintable() and c not in '<>:"|?*\x7f').strip(" .")
    return name[:150] or default


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CaptureStore:
    def __init__(self, engine: Engine, directory: Path) -> None:
        self._engine = engine
        self._dir = Path(directory)
        self._lock = threading.Lock()

    @property
    def directory(self) -> Path:
        return self._dir

    # ------------------------------------------------------------------ files
    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    def generate_filename(self, prefix: str, fmt: CaptureFormat, when: datetime | None = None) -> str:
        """``packetmind_capture_2026-10-07_23-30-15.pcap``-style name; a short random suffix keeps duplicates apart."""
        stamp = (when or datetime.now()).strftime("%Y-%m-%d_%H-%M-%S")
        return f"packetmind_{prefix}_{stamp}_{uuid.uuid4().hex[:6]}{EXTENSIONS[fmt]}"

    def path_of(self, session: CaptureSession) -> Path:
        """The capture's file, verified to be inside the managed folder (defence in depth: names are generated)."""
        root = self._dir.resolve()
        path = (root / session.filename).resolve()
        if path.parent != root:
            raise CaptureStoreError("unsafe_path", "That capture file is outside the managed capture folder.")
        return path

    def reserve_file(self, filename: str) -> Path:
        """Create a new empty capture file (owner read/write only, never replacing an existing one) and return its path."""
        self._ensure_dir()
        root = self._dir.resolve()
        path = (root / filename).resolve()
        if path.parent != root:
            raise CaptureStoreError("unsafe_path", "Refusing to write outside the managed capture folder.")
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return path

    # ------------------------------------------------------------------ rows
    def create(self, *, source_type: SourceType, capture_format: CaptureFormat, original_filename: str, filename: str | None = None,
               interface: str | None = None, start_time: float | None = None, status: CaptureStatus = "COMPLETED",
               file_size: int = 0) -> CaptureSession:
        filename = filename or self.generate_filename("capture" if source_type == "LIVE_CAPTURE" else "import", capture_format)
        capture_id = uuid.uuid4().hex
        with self._engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO captures (id, filename, original_filename, source_type, capture_format, interface, start_time,
                                      file_size, status, created_at)
                VALUES (:id, :filename, :orig, :src, :fmt, :iface, :start, :size, :status, :created)"""),
                {"id": capture_id, "filename": filename, "orig": sanitize_display_name(original_filename), "src": source_type,
                 "fmt": capture_format, "iface": interface, "start": start_time, "size": file_size, "status": status, "created": now_iso()})
        session = self.get(capture_id)
        assert session is not None
        return session

    def get(self, capture_id: str) -> CaptureSession | None:
        if not is_valid_id(capture_id):
            return None
        with self._engine.connect() as conn:
            row = conn.execute(text(f"SELECT {_COLUMNS} FROM captures WHERE id = :id"), {"id": capture_id}).mappings().first()
        return self._to_model(row) if row else None

    def list(self, limit: int = 500, offset: int = 0) -> list[CaptureSession]:
        with self._engine.connect() as conn:
            rows = conn.execute(text(f"SELECT {_COLUMNS} FROM captures ORDER BY created_at DESC, rowid DESC LIMIT :l OFFSET :o"),
                                {"l": limit, "o": offset}).mappings().all()
        return [self._to_model(r) for r in rows]

    def update(self, capture_id: str, summary: CaptureSummary | None = None, **fields) -> CaptureSession | None:
        unknown = set(fields) - _UPDATABLE
        if unknown:
            raise ValueError(f"cannot update {sorted(unknown)}")
        sets = [f"{k} = :{k}" for k in fields]
        params: dict = dict(fields, id=capture_id)
        if summary is not None:
            sets.append("summary = :summary")
            params["summary"] = summary.model_dump_json()
        if sets:
            with self._engine.begin() as conn:
                conn.execute(text(f"UPDATE captures SET {', '.join(sets)} WHERE id = :id"), params)  # column names are from _UPDATABLE
        return self.get(capture_id)

    def delete(self, capture_id: str) -> bool:
        """Remove the row and the file. Returns False when the capture does not exist."""
        session = self.get(capture_id)
        if session is None:
            return False
        try:
            self.path_of(session).unlink(missing_ok=True)
        except OSError as exc:
            raise CaptureStoreError("delete_failed", "The capture file could not be deleted (is it open in another program?).") from exc
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM captures WHERE id = :id"), {"id": capture_id})
        return True

    def clear_summaries(self) -> int:
        """Forget analysis summaries (rows and files stay): analysed captures go back to 'Ready'."""
        with self._engine.begin() as conn:
            return conn.execute(text("UPDATE captures SET summary = NULL, analyzed_at = NULL, status = 'COMPLETED' WHERE status = 'ANALYZED'")).rowcount or 0

    def fail_interrupted(self) -> int:
        """Called at startup: a capture still marked CAPTURING/ANALYZING belongs to a previous run that never finished."""
        with self._engine.begin() as conn:
            a = conn.execute(text("UPDATE captures SET status = 'FAILED', error_message = 'PacketMind stopped before this capture finished saving.' "
                                  "WHERE status = 'CAPTURING'")).rowcount
            b = conn.execute(text("UPDATE captures SET status = 'COMPLETED' WHERE status = 'ANALYZING'")).rowcount
        return (a or 0) + (b or 0)

    @staticmethod
    def _to_model(row) -> CaptureSession:
        data = dict(row)
        raw = data.pop("summary", None)
        data["summary"] = CaptureSummary.model_validate_json(raw) if raw else None
        return CaptureSession(**data)


_store: CaptureStore | None = None


def get_capture_store() -> CaptureStore:
    global _store
    if _store is None:
        from app.config import settings
        from app.database import engine
        from app.migrations import migrate

        migrate(engine)  # idempotent
        _store = CaptureStore(engine, settings.captures_dir)
    return _store
