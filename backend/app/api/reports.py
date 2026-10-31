"""HTTP API for saved investigation reports (local SQLite history)."""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException, Query, Response

from app.ai.provider import AIProviderError
from app.api.analyses import get_manager
from app.api.live import get_live_manager
from app.config import settings
from app.database import engine
from app.migrations import migrate
from app.models.report import CreateReportRequest, ReportAi, ReportListItem, SavedReport
from app.services.anonymize import anonymize_report
from app.services.app_settings import current_settings
from app.services.report_builder import ai_from_report, build_report
from app.services.report_export import FORMATS, export_filename, render
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])

_store: ReportStore | None = None
_ID = re.compile(r"^[0-9a-f]{32}$")


def get_store() -> ReportStore:
    global _store
    if _store is None:
        migrate(engine)  # idempotent; guarantees the schema even if startup hooks did not run
        _store = ReportStore(engine)
    return _store


def investigator_factory():
    from app.ai.investigator import Investigator

    return Investigator()


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _valid_id(report_id: str) -> str:
    if not _ID.match(report_id):
        raise _error(404, "not_found", "Report not found.")
    return report_id


def _run_ai(analysis, findings) -> ReportAi:
    if not findings:
        return ReportAi(status="not_run", message="No findings were detected, so no AI investigation was run.")
    try:
        return ai_from_report(investigator_factory().investigate_analysis(analysis, findings))
    except AIProviderError as exc:
        return ReportAi(status="failed", message=f"AI investigation unavailable: {exc.message}")
    except Exception:
        logger.exception("Unexpected AI investigation failure while building a report")
        return ReportAi(status="failed", message="AI investigation failed unexpectedly.")


@router.post("", status_code=201, response_model=SavedReport)
def create_report(req: CreateReportRequest) -> SavedReport:
    """Save an investigation report. The report is stored even if the optional AI step fails."""
    finding_ai, interface = {}, None
    if req.source == "live":
        analysis, findings, interface, finding_ai = get_live_manager().snapshot()
        if analysis is None:
            raise _error(409, "no_live_data", "There is no live capture data to report yet.")
        kind = "live"
    else:
        job = get_manager().get(req.analysis_id or "")
        if job is None:
            raise _error(404, "analysis_not_found", "Unknown analysis (the backend may have restarted).")
        if job.status != "completed" or job.result is None:
            raise _error(409, "not_ready", "The analysis has not completed.")
        analysis, findings, kind = job.result, job.findings, "pcap"
    ai = _run_ai(analysis, findings) if req.run_ai else None
    content = build_report(analysis, findings, source_kind=kind, title=req.title, notes=req.notes, ai=ai,
                           finding_ai=finding_ai, interface=interface)
    if current_settings().privacy.anonymize_ips:  # Settings → Privacy: saved reports carry host-N labels instead of addresses
        content = anonymize_report(content)
    return get_store().save(content)


@router.get("", response_model=list[ReportListItem])
def list_reports(limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0)) -> list[ReportListItem]:
    return get_store().list(limit, offset)


@router.get("/{report_id}", response_model=SavedReport)
def get_report(report_id: str) -> SavedReport:
    saved = get_store().get(_valid_id(report_id))
    if saved is None:
        raise _error(404, "not_found", "Report not found.")
    return saved


def _format(fmt: str) -> str:
    if fmt not in FORMATS:
        raise _error(400, "bad_format", f"Format must be one of: {', '.join(FORMATS)}.")
    return fmt


@router.get("/{report_id}/export")
def download_report(report_id: str, format: str = "html") -> Response:
    """Return the report as a file download (html, md or json)."""
    fmt = _format(format)
    saved = get_store().get(_valid_id(report_id))
    if saved is None:
        raise _error(404, "not_found", "Report not found.")
    return Response(render(saved, fmt), media_type=FORMATS[fmt], headers={
        "Content-Disposition": f'attachment; filename="{export_filename(saved, fmt)}"',
        "X-Content-Type-Options": "nosniff"})


@router.post("/{report_id}/export")
def save_export(report_id: str, format: str = "html") -> dict[str, str]:
    """Write the export into the reports folder (the desktop app's export action)."""
    fmt = _format(format)
    saved = get_store().get(_valid_id(report_id))
    if saved is None:
        raise _error(404, "not_found", "Report not found.")
    folder = settings.reports_dir
    try:
        folder.mkdir(parents=True, exist_ok=True)
        name = export_filename(saved, fmt)  # generated from [a-z0-9-] only: no path components
        path = folder / name
        path.write_bytes(render(saved, fmt))
    except OSError as exc:
        logger.warning("Report export failed: %s", exc)
        raise _error(500, "export_failed", "Could not write the export file to the reports folder.") from None
    return {"path": str(path), "filename": name, "format": fmt}


@router.delete("/{report_id}", status_code=204)
def delete_report(report_id: str, confirm: bool = False) -> Response:
    """Permanently delete a report. Requires confirm=true (the UI asks the user first)."""
    _valid_id(report_id)
    if not confirm:
        raise _error(400, "confirmation_required", "Deleting a report requires confirm=true.")
    if not get_store().delete(report_id):
        raise _error(404, "not_found", "Report not found.")
    return Response(status_code=204)
