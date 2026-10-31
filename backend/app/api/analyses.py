"""HTTP API for submitting captures and retrieving analysis results.

Upload is a raw request body (``Content-Type: application/octet-stream``) with the original
file name in the ``X-Filename`` header (URL-encoded). The body is streamed to disk, so memory
use does not depend on file size. Non-simple content type + custom header means browsers
require a CORS preflight, so other websites cannot post captures to this local service.
"""
from __future__ import annotations

import errno
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Literal
from urllib.parse import unquote

import anyio
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from app.analysis import InvalidCaptureError
from app.analysis.connection_tracker import ConnectionFilter, TCP_STATES, filter_connections, normalize_ip
from app.analysis.pcap_parser import detect_format
from app.config import settings
from app.detection import Finding
from app.analysis import web_activity
from app.analysis.dashboard import build_dashboard
from app.models.dashboard import Dashboard, RangeKey
from app.analysis.network_map import build_network_map
from app.correlation import CorrelationList, correlate
from app.models.network_map import NetworkMap
from app.models.network_investigation import NetworkInvestigation
from app.models.process import DomainApplications
from app.services.network_investigation import run_investigation
from app.services.process_mapper import get_process_mapper
from app.services.capture_store import CaptureStoreError, get_capture_store
from app.services.performance_history import get_history, source_id_for
from app.models.baseline import AnomalyList, DomainBaselineView
from app.models.web_activity import WebActivityList, WebDomainDetail
from app.models.analysis import (
    AnalysisResult, Connection, ConnectionSummary, DomainActivity, DomainPerformance, DomainSummary,
    MeasurementConfidence, PerformanceMetrics, PerformanceSummary,
)
from app.services.analysis_jobs import AnalysisJobManager, Job

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analyses", tags=["analyses"])

_manager: AnalysisJobManager | None = None


def get_manager() -> AnalysisJobManager:
    global _manager
    if _manager is None:
        from app.services.app_settings import current_settings

        workers = current_settings().advanced.max_concurrent_analyses  # Settings → Advanced (applied when the backend starts)
        _manager = AnalysisJobManager(workers, settings.max_retained_analyses, history=get_history())
    return _manager


class ErrorBody(BaseModel):
    code: str
    message: str


class JobStatus(BaseModel):
    id: str
    filename: str
    size_bytes: int
    status: Literal["queued", "running", "completed", "failed"]
    progress_percent: float | None
    packets_read: int
    capture_id: str | None = None  # the capture-library entry (saved copy) this analysis belongs to
    elapsed_seconds: float | None
    error: ErrorBody | None = None


class AnalysisBundle(BaseModel):
    job: JobStatus
    analysis: AnalysisResult
    findings: list[Finding]
    detector_errors: dict[str, str]


def _status(job: Job) -> JobStatus:
    import time

    end = job.finished_at or time.time()
    return JobStatus(
        id=job.id, filename=job.filename, size_bytes=job.size_bytes, status=job.status, capture_id=job.capture_id,  # type: ignore[arg-type]
        progress_percent=job.progress_percent, packets_read=job.packets_read,
        elapsed_seconds=round(end - job.started_at, 1) if job.started_at else None,
        error=ErrorBody(code=job.error_code, message=job.error_message or "") if job.error_code else None,
    )


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _clean_filename(raw: str | None) -> str:
    name = Path(unquote(raw or "")).name.strip()
    return name[:200] or "capture.pcap"


_UPLOAD_EXTENSIONS = (".pcap", ".pcapng", ".cap")


@router.post("", status_code=202, response_model=JobStatus)
async def submit_capture(request: Request) -> JobStatus:
    """Accept a PCAP/PCAPNG body (streamed to disk, never held in memory), validate it and start analysis in the background.

    By default the file is also kept in the capture library (``X-Save-To-Library: false`` analyses it once and deletes it).
    """
    limit = settings.max_upload_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise _error(413, "file_too_large", f"File exceeds the {limit // 1024**2} MiB upload limit.")

    filename = _clean_filename(request.headers.get("x-filename"))
    if not filename.lower().endswith(_UPLOAD_EXTENSIONS):
        raise _error(400, "unsupported_file_type", f"'{filename}' is not a .pcap or .pcapng file.")
    save = request.headers.get("x-save-to-library", "true").strip().lower() != "false"
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    path = settings.uploads_dir / f"{uuid.uuid4().hex}.upload"
    size = 0
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only: captured traffic is sensitive
        with os.fdopen(fd, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise _error(413, "file_too_large", f"File exceeds the {limit // 1024**2} MiB upload limit.")
                await anyio.to_thread.run_sync(fh.write, chunk)
        if size == 0:
            raise _error(400, "empty_file", "The uploaded file is empty (0 bytes).")
        try:
            fmt = detect_format(path)
        except InvalidCaptureError:
            raise _error(400, "invalid_capture",
                         f"'{filename}' is not a valid PCAP or PCAPNG capture file.") from None
    except OSError as exc:
        path.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise _error(507, "disk_full", "The disk is full, so the file could not be imported. Free some space and try again.") from None
        logger.error("Import failed while writing the upload: %s", type(exc).__name__)
        raise _error(500, "import_failed", "The file could not be imported.") from None
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if not save:
        return _status(get_manager().submit(path, filename, size))
    try:
        store = get_capture_store()
        session = store.create(source_type="UPLOADED_PCAP", capture_format=fmt, original_filename=filename, file_size=size, status="ANALYZING")  # type: ignore[arg-type]
        await anyio.to_thread.run_sync(_move_into_library, path, store.path_of(session), store)
    except (OSError, CaptureStoreError) as exc:
        path.unlink(missing_ok=True)
        if "session" in locals():
            store.delete(session.id)
        if getattr(exc, "errno", None) == errno.ENOSPC:
            raise _error(507, "disk_full", "The disk is full, so the file could not be imported. Free some space and try again.") from None
        logger.error("Could not move the upload into the capture library: %s", type(exc).__name__)
        raise _error(500, "import_failed", "The file could not be saved to the capture library.") from None
    return _status(get_manager().submit(store.path_of(session), filename, size, keep=True, capture_id=session.id))


def _move_into_library(src: Path, dest: Path, store) -> None:
    store.directory.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))  # same file system: a rename; otherwise one streamed copy


@router.get("/{job_id}", response_model=JobStatus)
def get_status(job_id: str) -> JobStatus:
    """Progress and state of an analysis job."""
    job = get_manager().get(job_id)
    if job is None:
        raise _error(404, "not_found", "Unknown analysis id (the backend may have restarted).")
    return _status(job)


@router.get("/{job_id}/result", response_model=AnalysisBundle)
def get_result(job_id: str) -> AnalysisBundle:
    """Full analysis and findings of a completed job."""
    job = get_manager().get(job_id)
    if job is None:
        raise _error(404, "not_found", "Unknown analysis id (the backend may have restarted).")
    if job.status == "failed":
        raise _error(409, job.error_code or "analysis_failed", job.error_message or "Analysis failed.")
    if job.status != "completed" or job.result is None:
        raise _error(409, "not_ready", "The analysis is still running.")
    return AnalysisBundle(job=_status(job), analysis=job.result, findings=job.findings,
                          detector_errors=job.detector_errors)


class DomainList(BaseModel):
    summary: DomainSummary
    total_matching: int
    domains: list[DomainActivity]


DomainSort = Literal["traffic", "connections", "recent", "name"]
_DOMAIN_SORTS = {
    "traffic": lambda d: (d.total_bytes_sent + d.total_bytes_received, d.connection_count),
    "connections": lambda d: (d.connection_count, d.total_bytes_sent + d.total_bytes_received),
    "recent": lambda d: (d.last_seen, d.connection_count),
}


def _completed_job(job_id: str) -> Job:
    job = get_manager().get(job_id)
    if job is None:
        raise _error(404, "not_found", "Unknown analysis id (the backend may have restarted).")
    if job.status == "failed":
        raise _error(409, job.error_code or "analysis_failed", job.error_message or "Analysis failed.")
    if job.status != "completed" or job.result is None:
        raise _error(409, "not_ready", "The analysis is still running.")
    return job


def _completed_result(job_id: str) -> AnalysisResult:
    return _completed_job(job_id).result  # type: ignore[return-value]


@router.get("/{job_id}/domains", response_model=DomainList)
def list_domains(job_id: str, search: str = Query("", max_length=253), sort: DomainSort = "traffic",
                 limit: int = Query(200, ge=1, le=1000)) -> DomainList:
    """Domains inferred from DNS and the connections that followed (not exact URLs)."""
    stats = _completed_result(job_id).domain_statistics
    needle = search.strip().lower()
    items = [d for d in stats.domains if needle in d.domain] if needle else list(stats.domains)
    if sort == "name":
        items.sort(key=lambda d: d.domain)
    else:
        items.sort(key=_DOMAIN_SORTS[sort], reverse=True)
    return DomainList(summary=stats.summary, total_matching=len(items), domains=items[:limit])


@router.get("/{job_id}/domains/{domain}", response_model=DomainActivity)
def get_domain(job_id: str, domain: str) -> DomainActivity:
    name = domain.strip().lower().rstrip(".")
    for d in _completed_result(job_id).domain_statistics.domains:
        if d.domain == name:
            return d
    raise _error(404, "not_found", "That domain was not seen in this analysis.")


class ConnectionList(BaseModel):
    summary: ConnectionSummary
    total_matching: int
    connections: list[Connection]


@router.get("/{job_id}/connections", response_model=ConnectionList)
def list_connections(
    job_id: str,
    domain: str | None = Query(None, max_length=253, description="Substring of the inferred domain"),
    src_ip: str | None = Query(None, max_length=45, description="Initiator (first sender seen)"),
    dst_ip: str | None = Query(None, max_length=45, description="Responder"),
    protocol: str | None = Query(None, max_length=10, description="TCP, UDP, ICMP, ICMPv6"),
    port: int | None = Query(None, ge=0, le=65535, description="Either endpoint's port"),
    state: str | None = Query(None, max_length=16, description="TCP state, e.g. ESTABLISHED"),
    limit: int = Query(200, ge=1, le=1000),
) -> ConnectionList:
    """Tracked connections (top by bytes, bounded by the analysis options), optionally filtered.

    Domains are inferred from DNS and may be absent: a connection without a lookup is still listed.
    """
    for name, value in (("src_ip", src_ip), ("dst_ip", dst_ip)):
        if value:
            try:
                normalize_ip(value)
            except ValueError:
                raise _error(422, "invalid_ip", f"{name} is not a valid IPv4/IPv6 address.") from None
    if state and state.strip().upper() not in TCP_STATES:
        raise _error(422, "invalid_state", f"state must be one of: {', '.join(TCP_STATES)}.")
    analysis = _completed_result(job_id)
    matches = filter_connections(analysis.connections, ConnectionFilter(
        domain=domain, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=port, state=state))
    return ConnectionList(summary=analysis.connection_summary, total_matching=len(matches),
                          connections=matches[:limit])


@router.get("/{job_id}/connections/{connection_id}", response_model=Connection)
def get_connection(job_id: str, connection_id: str) -> Connection:
    for c in _completed_result(job_id).connections:
        if c.id == connection_id:
            return c
    raise _error(404, "not_found", "That connection was not found in this analysis.")


class PerformanceList(BaseModel):
    summary: PerformanceSummary
    total_matching: int
    domains: list[DomainPerformance]


class PerformanceConnectionList(BaseModel):
    summary: PerformanceSummary
    total_matching: int
    metrics: list[PerformanceMetrics]


PerformanceSort = Literal["connections", "rtt", "handshake", "dns", "response", "name"]
_PERFORMANCE_SORTS = {  # slowest first; domains without that measurement go last
    "rtt": lambda d: d.avg_rtt_ms,
    "handshake": lambda d: d.tcp_handshake_ms,
    "dns": lambda d: d.dns_latency_ms,
    "response": lambda d: d.application_response_ms,
}


@router.get("/{job_id}/performance", response_model=PerformanceList)
def list_performance(job_id: str, search: str = Query("", max_length=253), sort: PerformanceSort = "connections",
                     limit: int = Query(200, ge=1, le=1000)) -> PerformanceList:
    """Latency by domain: DNS lookup, TCP handshake, RTT and (cleartext HTTP only) response time.

    Handshake time is connection set-up time and is never reported as response time; fields are
    null when the capture does not contain the packets needed to measure them.
    """
    stats = _completed_result(job_id).performance_statistics
    needle = search.strip().lower()
    items = [d for d in stats.domains if needle in d.domain] if needle else list(stats.domains)
    if sort == "name":
        items.sort(key=lambda d: d.domain)
    elif sort == "connections":
        items.sort(key=lambda d: (-d.connections, d.domain))
    else:
        key = _PERFORMANCE_SORTS[sort]
        items.sort(key=lambda d: (key(d) is None, -(key(d) or 0), d.domain))
    return PerformanceList(summary=stats.summary, total_matching=len(items), domains=items[:limit])


@router.get("/{job_id}/performance/connections", response_model=PerformanceConnectionList)
def list_connection_performance(
    job_id: str,
    domain: str | None = Query(None, max_length=253, description="Substring of the inferred domain"),
    protocol: str | None = Query(None, max_length=10, description="TCP, UDP, ..."),
    confidence: MeasurementConfidence | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> PerformanceConnectionList:
    """Per-connection latency metrics (same connections as the analysis's connection list)."""
    stats = _completed_result(job_id).performance_statistics
    needle = domain.strip().lower().rstrip(".") if domain else None
    proto = protocol.strip().upper() if protocol else None
    items = [m for m in stats.metrics
             if (not needle or needle in (m.domain or "")) and (not proto or m.protocol.upper() == proto)
             and (confidence is None or m.measurement_confidence == confidence)]
    return PerformanceConnectionList(summary=stats.summary, total_matching=len(items), metrics=items[:limit])


@router.get("/{job_id}/performance/connections/{connection_id}", response_model=PerformanceMetrics)
def get_connection_performance(job_id: str, connection_id: str) -> PerformanceMetrics:
    for m in _completed_result(job_id).performance_statistics.metrics:
        if m.connection_id == connection_id:
            return m
    raise _error(404, "not_found", "No performance metrics for that connection in this analysis.")


WebSort = Literal["traffic", "connections", "dns", "handshake", "rtt", "p95", "health", "recent", "name"]
WebHealth = Literal["good", "fair", "poor", "unknown"]


@router.get("/{job_id}/web-activity", response_model=WebActivityList)
def list_web_activity(
    job_id: str,
    search: str = Query("", max_length=253),
    sort: WebSort = "traffic",
    health: WebHealth | None = None,
    include_dns_only: bool = Query(False, description="Also list domains that were looked up but never connected to"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> WebActivityList:
    """Domain / web activity table: traffic, DNS latency, TCP handshake, RTT and a heuristic health rating.

    Sorting, filtering and paging happen here; latency fields are null where the capture lacks the packets to
    measure them. Domains are inferred from DNS, not read from traffic.
    """
    result = _completed_result(job_id)
    page = web_activity.query(result, search=search, sort=sort, health=health,
                              include_dns_only=include_dns_only, offset=offset, limit=limit)
    counts = get_history().anomaly_counts(source_id_for(result), [r.domain for r in page.domains])
    for row in page.domains:
        row.anomalies = counts.get(row.domain, 0)
    return page


@router.get("/{job_id}/web-activity/{domain}", response_model=WebDomainDetail)
def get_web_domain(job_id: str, domain: str) -> WebDomainDetail:
    """Overview, performance, traffic, connections and time series (RTT, handshake, traffic) of one domain."""
    detail = web_activity.build_detail(_completed_result(job_id), domain)
    if detail is None:
        raise _error(404, "not_found", "That domain was not seen in this analysis.")
    return detail


@router.get("/{job_id}/anomalies", response_model=AnomalyList)
def list_performance_anomalies(job_id: str) -> AnomalyList:
    """Performance anomalies of this capture relative to the domains' own earlier captures (local history).

    A domain is only judged once it has enough earlier observations; otherwise nothing is flagged.
    """
    return get_history().anomalies_for(source_id_for(_completed_result(job_id)))


@router.get("/{job_id}/web-activity/{domain}/baseline", response_model=DomainBaselineView)
def get_domain_baseline(job_id: str, domain: str) -> DomainBaselineView:
    """Historical baseline vs this capture's values for one domain, plus its stored history (for charts)."""
    result = _completed_result(job_id)
    name = domain.strip().lower().rstrip(".")
    if not any(d.domain == name for d in result.domain_statistics.domains):
        raise _error(404, "not_found", "That domain was not seen in this analysis.")
    return get_history().domain_view(name, source_id_for(result))


@router.get("/{job_id}/correlations", response_model=CorrelationList)
def list_correlations(job_id: str, finding_id: str | None = Query(None, max_length=200)) -> CorrelationList:
    """Security findings and performance changes that are *potentially related* (correlation, not causation).

    Pass ``finding_id`` for one finding's related events. Each record carries the evidence, the time difference,
    the shared IPs/domains and a confidence capped well below certainty. ``not_evaluated`` lists checks that lacked data.
    """
    job = _completed_job(job_id)
    findings = [f for f in job.findings if finding_id in (None, f.id)]
    if finding_id is not None and not findings:
        raise _error(404, "not_found", "That finding is not part of this analysis.")
    result = job.result
    assert result is not None
    history = get_history().anomalies_for(source_id_for(result)).anomalies
    report = correlate(findings, result, history)
    return CorrelationList(
        finding_id=finding_id, correlations=report.correlations, not_evaluated=report.not_evaluated,
        no_related_change=report.no_related_change, flow_data_thinned=report.flow_data_thinned,
        notes=["Correlation is not proof of causation: related events share a time window and scope, which can also happen by coincidence "
               "or through a common underlying cause."])


@router.get("/{job_id}/web-activity/{domain}/applications", response_model=DomainApplications)
def get_domain_applications(job_id: str, domain: str) -> DomainApplications:
    """Local applications that held this domain's connections, from operating-system snapshots (not from packets).

    Unavailable (with the reason) unless snapshots were taken while the traffic was captured on this computer.
    """
    result = _completed_result(job_id)
    name = domain.strip().lower().rstrip(".")
    if not any(d.domain == name for d in result.domain_statistics.domains):
        raise _error(404, "not_found", "That domain was not seen in this analysis.")
    return get_process_mapper().applications_for_domain(result, name)


@router.get("/{job_id}/network-map", response_model=NetworkMap)
def get_network_map(
    job_id: str,
    local: str | None = Query(None, max_length=45, description="Local host IP, or 'all' (default: the busiest local host)"),
    search: str = Query("", max_length=200),
    protocol: Literal["TCP", "UDP"] | None = None,
    start: float | None = Query(None, description="Only connections active at or after this time (epoch seconds)"),
    end: float | None = Query(None, description="Only connections active at or before this time (epoch seconds)"),
    health: Literal["healthy", "degraded", "suspicious", "unknown"] | None = None,
    max_nodes: int = Query(60, ge=10, le=200, description="Node budget; lower-traffic destinations are folded into one node"),
    include_applications: bool = Query(False, description="Add local applications from OS process snapshots, when available"),
) -> NetworkMap:
    """Network map: local host -> (applications) -> domains -> IP addresses -> ports, with health state and filters applied server-side.

    Bounded by design (never thousands of nodes). Application nodes come only from operating-system process snapshots,
    never from packets; if unavailable the reason is returned in ``applications_status``.
    """
    job = _completed_job(job_id)
    result = job.result
    assert result is not None
    if start is not None and end is not None and start > end:
        raise _error(422, "invalid_range", "start must not be after end.")
    if local not in (None, "all"):
        try:
            normalize_ip(local)  # type: ignore[arg-type]
        except ValueError:
            raise _error(422, "invalid_ip", "local must be an IP address or 'all'.") from None
    matches, status = None, None
    if include_applications:
        conns = [c for c in result.connections if c.protocol in ("TCP", "UDP")]
        found, why = get_process_mapper().capture_matches(result, conns)
        matches, status = (found or None), why
    return build_network_map(result, job.findings, local=local, search=search, protocol=protocol, start=start, end=end, health=health,
                             max_nodes=max_nodes, matches=matches, applications_status=status)


class InvestigateRequest(BaseModel):
    use_ai: bool = True  # False: only the local measurements and rating (nothing is sent anywhere)


def network_investigator_factory():
    from app.ai.network_health import NetworkInvestigator

    return NetworkInvestigator()


@router.post("/{job_id}/investigate-network", response_model=NetworkInvestigation)
def investigate_network(job_id: str, req: InvestigateRequest | None = None) -> NetworkInvestigation:
    """One-click network investigation: local measurements and rating, plus an optional Gemini analysis.

    Explicit by design (POST, one click): with ``use_ai`` the backend sends Gemini a summary of the measurements, never the
    capture. The answer is analysis and safe recommendations only; nothing is executed or changed. Always returns the local
    layer, even when the AI is unavailable or its output fails the safety checks.
    """
    job = _completed_job(job_id)
    assert job.result is not None
    return run_investigation(job.result, job.findings, get_history(), use_ai=(req or InvestigateRequest()).use_ai,
                             investigator_factory=network_investigator_factory)


@router.get("/{job_id}/dashboard", response_model=Dashboard)
def get_dashboard(job_id: str, range: RangeKey = "all") -> Dashboard:  # noqa: A002 - the query parameter is called `range`
    """Network Intelligence Dashboard: KPIs, health score, top/slowest domains, findings, anomalies, connections and a timeline.

    All aggregation happens here over the finished analysis (bounded lists); the time range is measured back from the last
    packet of the capture.
    """
    job = _completed_job(job_id)
    anomalies = get_history().anomalies_for(source_id_for(job.result)).anomalies
    return build_dashboard(job.result, job.findings, anomalies, range)
