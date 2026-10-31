"""Background analysis jobs.

An uploaded capture is analyzed on a worker thread so the API stays responsive; clients poll
the job for progress and fetch the result when it completes. Jobs live in memory (the most
recent ``retain`` are kept) and the uploaded file is always deleted when the job ends.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis import CaptureError, analyze_pcap
from app.detection import DetectorEngine, Finding
from app.models.analysis import AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class Job:
    id: str
    filename: str
    size_bytes: int
    status: str = "queued"  # queued | running | completed | failed
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    packets_read: int = 0
    bytes_read: int = 0
    result: AnalysisResult | None = None
    findings: list[Finding] = field(default_factory=list)
    detector_errors: dict[str, str] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    capture_id: str | None = None  # the capture-library entry this job analyses, if any
    keep_file: bool = False  # the file belongs to the capture library: never delete it

    @property
    def progress_percent(self) -> float | None:
        if self.status == "completed":
            return 100.0
        if self.size_bytes <= 0 or self.status == "queued":
            return 0.0 if self.status == "queued" else None
        return round(min(99.0, 100 * self.bytes_read / self.size_bytes), 1)


class AnalysisJobManager:
    """Creates, runs and remembers analysis jobs (thread-safe)."""

    def __init__(self, workers: int = 2, retain: int = 10, history=None) -> None:
        # ``history`` (PerformanceHistory) remembers each finished capture's per-domain performance locally.
        self._history = history
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="analysis")
        self._retain = retain
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()

    def submit(self, path: Path, filename: str, size_bytes: int, *, keep: bool = False, capture_id: str | None = None) -> Job:
        """Analyze ``path`` in the background. ``keep=True`` leaves the file alone (it belongs to the capture library);
        otherwise it is a temporary upload and is deleted when the job ends."""
        job = Job(id=uuid.uuid4().hex[:16], filename=filename, size_bytes=size_bytes, capture_id=capture_id, keep_file=keep)
        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > self._retain:
                oldest = next(iter(self._jobs))
                if self._jobs[oldest].status in ("queued", "running"):
                    break
                self._jobs.pop(oldest)
        self._pool.submit(self._run, job, path)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def latest_for_capture(self, capture_id: str) -> Job | None:
        """The newest job of a library capture that is still in memory (running or completed)."""
        with self._lock:
            matches = [j for j in self._jobs.values() if j.capture_id == capture_id and j.status != "failed"]
        return matches[-1] if matches else None

    def _run(self, job: Job, path: Path) -> None:
        job.status, job.started_at = "running", time.time()

        def progress(packets: int, bytes_read: int) -> None:
            job.packets_read, job.bytes_read = packets, bytes_read

        try:
            result = analyze_pcap(path, on_progress=progress)
            # The file on disk is an internal temp upload: report the user's file name instead.
            result.metadata.file_name = job.filename
            result.metadata.file_path = job.filename
            engine = DetectorEngine()
            job.findings = engine.run(result)
            job.detector_errors = engine.errors
            job.result = result
            self._record_history(job, result)
            job.status = "completed"
        except FileNotFoundError:
            self._fail(job, "file_missing", "The uploaded capture could not be found.")
        except CaptureError as exc:
            logger.warning("Job %s: %s", job.id, exc)
            self._fail(job, "invalid_capture", f"Unable to read '{job.filename}'. The file may be corrupted or use an unsupported capture format.")
        except Exception:
            logger.exception("Analysis job %s failed", job.id)
            self._fail(job, "analysis_failed", "The analysis failed unexpectedly. See the backend log for details.")
        finally:
            job.finished_at = time.time()
            if not job.keep_file:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not delete upload %s", path)
            if job.capture_id:  # keep the capture library's status/summary in step with the analysis
                try:
                    from app.services.capture_library import record_analysis

                    record_analysis(job)
                except Exception:
                    logger.exception("Could not update the capture library after job %s", job.id)

    def _record_history(self, job: Job, result: AnalysisResult) -> None:
        """Learn from this capture; recording problems must never fail or delay the analysis result."""
        if self._history is None or not getattr(self._history, "enabled", False):
            return
        from app.services.performance_history import source_id_for

        source_id = source_id_for(result)
        if source_id is None:
            return
        try:
            self._history.record(result, source_kind="pcap", source_id=source_id, name=job.filename)
        except Exception:
            logger.exception("Could not record performance history for job %s", job.id)

    @staticmethod
    def _fail(job: Job, code: str, message: str) -> None:
        job.status, job.error_code, job.error_message = "failed", code, message
