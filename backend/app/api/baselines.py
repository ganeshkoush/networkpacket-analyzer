"""HTTP API for the local performance history (status and explicit, confirmed clearing).

Baselines and anomalies for a capture are served under /api/analyses/{id}/anomalies and
/api/analyses/{id}/web-activity/{domain}/baseline.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.models.baseline import HistoryStatus
from app.services.performance_history import get_history

router = APIRouter(prefix="/api/baselines", tags=["baselines"])


@router.get("", response_model=HistoryStatus)
def history_status() -> HistoryStatus:
    """How much performance history is stored locally (names and aggregate numbers only)."""
    return get_history().status()


@router.delete("")
def clear_history(confirm: bool = Query(False)) -> dict[str, int]:
    """Permanently delete all stored performance history. Refused unless ``confirm=true`` (the UI asks first)."""
    if not confirm:
        raise HTTPException(status_code=400, detail={"code": "confirmation_required",
                                                      "message": "Clearing history requires confirm=true."})
    return {"deleted_observations": get_history().clear()}
