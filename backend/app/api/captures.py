"""HTTP API for the capture library: list, inspect, (re-)analyze, export and delete saved captures.

Captures are files in the managed capture folder; the API never takes a path from the client except an explicit *export
destination* chosen in the OS save dialog, which is validated here. Nothing in this module changes a stored capture.
"""
from __future__ import annotations

import errno
import logging
import os
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from app.api.analyses import JobStatus, _status, get_manager
from app.models.capture import CaptureSession, ExportRequest, ExportResult
from app.services import paths
from app.services.capture_library import start_analysis
from app.services.capture_store import CaptureStoreError, get_capture_store, sanitize_display_name

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/captures", tags=["captures"])
_EXPORTABLE = ("COMPLETED", "ANALYZING", "ANALYZED")
_PCAP_EXT = (".pcap", ".pcapng")


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _get(capture_id: str) -> CaptureSession:
    capture = get_capture_store().get(capture_id)
    if capture is None:
        raise _error(404, "not_found", "That capture is not in the library.")
    return capture


@router.get("", response_model=list[CaptureSession])
def list_captures(limit: int = Query(500, ge=1, le=2000), offset: int = Query(0, ge=0)) -> list[CaptureSession]:
    """Saved captures, newest first."""
    return get_capture_store().list(limit, offset)


@router.get("/{capture_id}", response_model=CaptureSession)
def get_capture(capture_id: str) -> CaptureSession:
    return _get(capture_id)


@router.post("/{capture_id}/analyze", response_model=JobStatus, status_code=202)
def analyze_capture(capture_id: str, force: bool = Query(False, description="Run the analysis again even if one is available")) -> JobStatus:
    """Analyze (or re-analyze) a saved capture with the current analysis pipeline. The capture file is not modified."""
    capture = _get(capture_id)
    if capture.status == "CAPTURING":
        raise _error(409, "capture_in_progress", "This capture is still recording. Stop it first.")
    if capture.status == "FAILED" and capture.error_message and capture.packet_count == 0 and capture.source_type == "LIVE_CAPTURE":
        raise _error(409, "capture_failed", capture.error_message)
    try:
        job = start_analysis(capture, get_manager(), get_capture_store(), force=force)
    except CaptureStoreError as exc:
        raise _error(404 if exc.code == "file_missing" else 400, exc.code, exc.message) from None
    return _status(job)


@router.get("/{capture_id}/download")
def download_capture(capture_id: str) -> FileResponse:
    """The capture as a standard PCAP/PCAPNG file (streamed from disk; used when there is no native save dialog)."""
    capture = _get(capture_id)
    if capture.status not in _EXPORTABLE:
        raise _error(409, "not_ready", "This capture has no saved file to download.")
    path = get_capture_store().path_of(capture)
    if not path.is_file():
        raise _error(404, "file_missing", "The capture file is no longer on disk.")
    name = export_name(capture)
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=name)


def export_name(capture: CaptureSession) -> str:
    base = sanitize_display_name(capture.original_filename if capture.source_type == "UPLOADED_PCAP" else capture.filename)
    if base.lower().endswith(_PCAP_EXT):
        base = base[: base.rfind(".")]
    return base + (".pcapng" if capture.capture_format == "pcapng" else ".pcap")  # the extension always matches the actual format


def validate_destination(raw: str, capture: CaptureSession, managed_dir: Path, overwrite: bool) -> Path:
    """Turn the save-dialog path into a safe destination file, or raise a clear error. Never creates directories."""
    try:
        return paths.validate_destination(raw, extensions=_PCAP_EXT, default_extension=".pcapng" if capture.capture_format == "pcapng" else ".pcap",
                                          protected_dirs=(managed_dir,), overwrite=overwrite)
    except paths.PathRejected as exc:
        raise _error(exc.status, exc.code, exc.message) from None


@router.post("/{capture_id}/export", response_model=ExportResult)
def export_capture(capture_id: str, req: ExportRequest) -> ExportResult:
    """Copy the capture to a location the user chose. The managed copy is kept; the copy is written atomically."""
    store = get_capture_store()
    capture = _get(capture_id)
    if capture.status not in _EXPORTABLE:
        raise _error(409, "not_ready", "This capture has no saved file to export.")
    src = store.path_of(capture)
    if not src.is_file():
        raise _error(404, "file_missing", "The capture file is no longer on disk.")
    dest = validate_destination(req.destination, capture, store.directory, req.overwrite)
    if dest.exists() and dest.samefile(src):
        raise _error(400, "invalid_destination", "That is the capture's own file.")
    tmp = dest.with_name(f".{dest.name}.packetmind-part")
    try:
        shutil.copyfile(src, tmp)  # streamed in chunks by the OS: large files are never held in memory
        os.replace(tmp, dest)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise _error(507, "disk_full", "There is not enough free space at the destination.") from None
        if isinstance(exc, PermissionError):
            raise _error(403, "destination_not_writable", "PacketMind is not allowed to write to that folder.") from None
        logger.error("Export failed: %s", type(exc).__name__)
        raise _error(500, "export_failed", "The capture could not be exported.") from None
    return ExportResult(filename=dest.name, directory=str(dest.parent), size_bytes=dest.stat().st_size)


@router.delete("/{capture_id}", status_code=204)
def delete_capture(capture_id: str, confirm: bool = Query(False)) -> None:
    """Permanently delete a saved capture (file and library entry). Requires explicit confirmation."""
    capture = _get(capture_id)
    if not confirm:
        raise _error(400, "confirmation_required", "Deleting a capture is permanent; confirm it explicitly (confirm=true).")
    if capture.status in ("CAPTURING", "ANALYZING"):
        raise _error(409, "capture_busy", "This capture is being recorded or analyzed. Wait for it to finish.")
    try:
        get_capture_store().delete(capture_id)
    except CaptureStoreError as exc:
        raise _error(500, exc.code, exc.message) from None
