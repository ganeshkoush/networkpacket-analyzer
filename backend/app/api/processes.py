"""HTTP API for local process <-> connection mapping.

Nothing runs unless the user asks: snapshots and the watch need ``confirm=true``. The OS is only *read* (see
``app/platform``); nothing is changed. Snapshots live in memory only.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.process import ProcessSourceStatus
from app.platform import ProcessSourceError
from app.services.process_mapper import get_process_mapper

router = APIRouter(prefix="/api/processes", tags=["processes"])


class SnapshotSummary(BaseModel):
    timestamp: float
    platform: str
    sockets: int
    processes: int
    applications: int
    truncated: bool
    notes: list[str]


class WatchRequest(BaseModel):
    confirm: bool = False
    interval_seconds: float = Field(5.0, ge=2.0, le=60.0)


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _require_confirmation(confirm: bool, what: str) -> None:
    if not confirm:
        raise _error(400, "confirmation_required", f"{what} reads the operating system's process list and must be requested explicitly (confirm=true).")


@router.get("", response_model=ProcessSourceStatus)
def process_status() -> ProcessSourceStatus:
    """Whether process mapping exists on this OS, what permission it needs, and what has been collected."""
    return get_process_mapper().status()


@router.post("/snapshot", response_model=SnapshotSummary)
def take_snapshot(confirm: bool = Query(False)) -> SnapshotSummary:
    """Read the OS socket table once (read-only, no administrator rights) and remember it in memory."""
    _require_confirmation(confirm, "Taking a process snapshot")
    mapper = get_process_mapper()
    try:
        snap = mapper.snapshot()
    except ProcessSourceError as exc:
        unsupported = not mapper.status().supported
        raise _error(501 if unsupported else 503, "unsupported_platform" if unsupported else "process_source_unavailable", str(exc)) from None
    return SnapshotSummary(timestamp=snap.timestamp, platform=snap.platform, sockets=len(snap.mappings), processes=snap.processes,
                           applications=len({m.application or m.process_name for m in snap.mappings}), truncated=snap.truncated, notes=snap.notes)


@router.post("/watch", response_model=ProcessSourceStatus)
def start_watch(req: WatchRequest) -> ProcessSourceStatus:
    """Take a snapshot every few seconds (bounded to one hour) until stopped."""
    _require_confirmation(req.confirm, "Watching processes")
    mapper = get_process_mapper()
    try:
        mapper.start_watch(req.interval_seconds)
    except ProcessSourceError as exc:
        raise _error(501, "unsupported_platform", str(exc)) from None
    return mapper.status()


@router.delete("/watch", response_model=ProcessSourceStatus)
def stop_watch() -> ProcessSourceStatus:
    mapper = get_process_mapper()
    mapper.stop_watch()
    return mapper.status()


@router.delete("")
def clear_snapshots(confirm: bool = Query(False)) -> dict[str, int]:
    """Forget all collected process snapshots."""
    if not confirm:
        raise _error(400, "confirmation_required", "Clearing process snapshots requires confirm=true.")
    return {"deleted_snapshots": get_process_mapper().clear()}
