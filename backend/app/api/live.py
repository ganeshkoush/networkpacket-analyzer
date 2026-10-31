"""HTTP API for live capture. Capture never starts unless POST /start is called with confirm=true."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.capture import CaptureRefused, CaptureStartError, LiveCaptureManager, list_interfaces
from app.analysis.dashboard import build_dashboard
from app.models.dashboard import Dashboard, RangeKey
from app.models.live import InterfaceInfo, LiveStatus, StartRequest

router = APIRouter(prefix="/api/live", tags=["live"])

_manager: LiveCaptureManager | None = None


def _record_live_session(result, session_id: str, interface: str, started_at: float) -> None:
    """Remember the stopped session's per-domain performance (local database only)."""
    from app.services.performance_history import get_history

    get_history().record(result, source_kind="live", source_id=session_id, name=f"live:{interface}", captured_at=started_at)


def _analyze_saved_capture(capture) -> None:
    """A live capture was saved: analyze that file with the standard pipeline so the summary matches what an import would show."""
    from app.api.analyses import get_manager
    from app.services.capture_library import start_analysis
    from app.services.capture_store import get_capture_store

    from app.services.app_settings import current_settings

    if current_settings().capture.auto_analyze:  # Settings → Capture; otherwise the capture waits in the library as "Ready"
        start_analysis(capture, get_manager(), get_capture_store())


def get_live_manager() -> LiveCaptureManager:
    global _manager
    if _manager is None:
        from app.services.capture_store import get_capture_store

        from app.services.ai_usage import get_ai_usage
        from app.services.storage import ensure_capacity

        _manager = LiveCaptureManager(on_session_end=_record_live_session, capture_store=get_capture_store(),
                                      on_capture_saved=_analyze_saved_capture, before_recording=ensure_capacity,
                                      auto_investigation_budget=get_ai_usage())
    return _manager


def _error(status: int, code: str, message: str, hint: str | None = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message, "hint": hint})


@router.get("/interfaces", response_model=list[InterfaceInfo])
def interfaces() -> list[InterfaceInfo]:
    """Interfaces visible to the capture library. Listing does not capture or need privileges."""
    return list_interfaces()


@router.get("/status", response_model=LiveStatus)
def status() -> LiveStatus:
    return get_live_manager().status()


@router.post("/start", response_model=LiveStatus)
def start(req: StartRequest) -> LiveStatus:
    try:
        return get_live_manager().start(req)
    except CaptureRefused as exc:
        code = 409 if exc.code == "already_capturing" else 400
        raise _error(code, exc.code, exc.message) from None
    except CaptureStartError as exc:
        raise _error(403 if exc.permission else 500, exc.code, exc.message, exc.hint) from None


@router.post("/stop", response_model=LiveStatus)
def stop() -> LiveStatus:
    return get_live_manager().stop()


@router.get("/dashboard", response_model=Dashboard)
def dashboard(range: RangeKey = "all") -> Dashboard:  # noqa: A002
    """The dashboard for the live capture's rolling window (no history anomalies: a live window has no stable identity)."""
    result, findings, _, _ = get_live_manager().snapshot()
    if result is None:
        from app.analysis import analyze_records

        result = analyze_records([], source_name="live")
    return build_dashboard(result, findings, [], range, source="live")
