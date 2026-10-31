"""Glue between analysis jobs and the capture library (status, summary, "analyze again").

Analysis always goes through the one existing pipeline (``AnalysisJobManager`` -> ``analyze_pcap`` -> detectors); this module only
decides which file to feed it and records the outcome on the library row. The stored file is never modified.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.models.capture import CaptureSession, CaptureSummary, ProtocolShare
from app.services.analysis_jobs import AnalysisJobManager, Job
from app.services.capture_store import CaptureStore, CaptureStoreError, get_capture_store

logger = logging.getLogger(__name__)
MAX_PROTOCOLS = 8


def summarize(job: Job) -> CaptureSummary:
    result = job.result
    assert result is not None
    return CaptureSummary(
        protocols=[ProtocolShare(protocol=p.protocol, packets=p.packets, percent=p.percent_of_packets)
                   for p in result.protocol_statistics.distribution[:MAX_PROTOCOLS]],
        domains=result.domain_statistics.total_domains if hasattr(result.domain_statistics, "total_domains") else len(result.domain_statistics.domains),
        findings=len(job.findings), connections=result.connection_summary.total_connections)


def record_analysis(job: Job, store: CaptureStore | None = None) -> None:
    """Called when a library capture's analysis ends: ANALYZED + summary on success, FAILED + message otherwise."""
    store = store or get_capture_store()
    if not job.capture_id:
        return
    if job.status == "completed" and job.result is not None:
        r = job.result
        fields = dict(status="ANALYZED", error_message=None, analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      packet_count=r.packet_statistics.total_packets, byte_count=r.packet_statistics.total_bytes,
                      start_time=r.metadata.first_packet_time, end_time=r.metadata.last_packet_time, duration_seconds=r.metadata.duration_seconds,
                      capture_format=r.metadata.capture_format)
        store.update(job.capture_id, summary=summarize(job), **fields)
    else:
        store.update(job.capture_id, status="FAILED", error_message=job.error_message or "The analysis failed.")


def start_analysis(capture: CaptureSession, manager: AnalysisJobManager, store: CaptureStore | None = None, *, force: bool = False) -> Job:
    """Analyze a library capture. Without ``force`` an analysis that is already running/finished in memory is reused."""
    store = store or get_capture_store()
    if not force:
        existing = manager.latest_for_capture(capture.id)
        if existing is not None:
            return existing
    path = store.path_of(capture)
    if not path.is_file():
        raise CaptureStoreError("file_missing", "The capture file is no longer on disk (it may have been moved or deleted).")
    store.update(capture.id, status="ANALYZING", error_message=None)
    return manager.submit(path, capture.original_filename, path.stat().st_size, keep=True, capture_id=capture.id)
