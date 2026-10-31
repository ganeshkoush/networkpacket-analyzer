"""Live capture session: explicit start/stop, rolling window, periodic local analysis.

Pipeline (nothing here sends individual packets anywhere):

    packets -> PacketRecord (small, in a bounded rolling window)
            -> every `refresh_seconds`: analyze_records(window) + detect_threats   [local]
            -> suspicious events (findings) tracked across windows
            -> only if the user opted in AND a finding crosses the configured thresholds
               (and cooldown / hourly budget allow): Investigator gets aggregated evidence

Capture is passive. There is no injection, traffic modification or blocking anywhere. Packets never
leave this process. When a capture store is configured (the app always does), the packets are also written
to a standard .pcap/.pcapng file in the managed capture folder (owner-only) so the user can export and
re-analyze them; that file is local, is never sent to the AI provider, and is the user's to delete.
"""
from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field

from app.analysis.pcap_parser import PacketRecord, extract_record
from app.analysis.service import analyze_records
from app.capture.interfaces import list_interfaces
from app.capture.recorder import CaptureRecorder, RecorderError, verify_capture_file
from app.capture.sniffer import CaptureStartError, PacketSource, ScapySource
from app.detection import detect_threats
from app.detection.models import Finding
from app.detection.severity import Severity
from app.models.analysis import AnalysisResult
from app.models.capture import CaptureSession
from app.services.app_settings import current_settings
from app.models.live import (
    LiveCaptureFile,
    LiveError,
    LiveFindingEvent,
    LiveInvestigation,
    LiveState,
    LiveStatus,
    StartRequest,
)

logger = logging.getLogger(__name__)


class LiveConfig(BaseModel):
    window_seconds: float = Field(60.0, gt=0, description="Length of the rolling analysis window")
    max_window_packets: int = Field(50_000, ge=100, description="Hard cap on records kept (memory bound)")
    refresh_seconds: float = Field(5.0, gt=0, description="How often the window is analysed")
    rate_window_seconds: int = Field(5, ge=1, description="Window used for packets/s and bits/s")
    investigate_min_severity: Severity = Severity.MEDIUM
    investigate_min_confidence: float = Field(0.6, ge=0, le=1)
    investigation_cooldown_seconds: float = Field(300.0, ge=0)
    max_investigations_per_hour: int = Field(6, ge=0)
    max_events: int = Field(100, ge=1)


class CaptureRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class _Event:
    def __init__(self, finding: Finding, now: float):
        self.finding, self.first, self.last = finding, now, now
        self.detections, self.active = 1, True
        self.investigation: LiveInvestigation | None = None


class LiveCaptureManager:
    def __init__(
        self,
        config: LiveConfig | None = None,
        source_factory: Callable[[], PacketSource] = ScapySource,
        investigator_factory: Callable[[], object] | None = None,
        clock: Callable[[], float] = time.time,
        interface_lister: Callable[[], list] = list_interfaces,
        on_session_end: Callable[[AnalysisResult, str, str, float], None] | None = None,
        capture_store=None,
        on_capture_saved: Callable[[CaptureSession], None] | None = None,
        before_recording: Callable[[], None] | None = None,
        auto_investigation_budget=None,
    ) -> None:
        # ``before_recording`` may raise CaptureRefused (e.g. the capture storage limit is reached) before a file is created.
        # ``auto_investigation_budget`` (AiUsage) enforces the daily cap on automatic AI investigations.
        self._before_recording = before_recording
        self._budget = auto_investigation_budget
        # With a store, every capture is also recorded to a standard PCAP in the managed folder (and described in the
        # capture library); without one (tests, embedding) nothing touches the disk.
        self._store = capture_store
        self._on_capture_saved = on_capture_saved
        self.config = config or LiveConfig()
        # Called once when a capture is stopped: (final window analysis, session id, interface, capture time).
        # Used to learn performance baselines locally; failures never affect stopping the capture.
        self._on_session_end = on_session_end
        self._source_factory = source_factory
        self._investigator_factory = investigator_factory
        self._clock = clock
        self._list_interfaces = interface_lister
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="packetmind-investigate")
        self._source: PacketSource | None = None
        self._thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._reset()

    # ------------------------------------------------------------------ state
    def _reset(self) -> None:
        self._state: LiveState = "stopped"
        self._error: LiveError | None = None
        self._interface: str | None = None
        self._auto = False
        self._started_at: float | None = None
        self._stopped_at: float | None = None
        self._records: deque[PacketRecord] = deque(maxlen=self.config.max_window_packets)
        self._truncated = False
        self._counter = itertools.count(1)
        self._packets = 0
        self._bytes = 0
        self._parse_errors = 0
        self._buckets: dict[int, list[int]] = {}  # arrival second -> [packets, bytes]
        self._result: AnalysisResult | None = None
        self._last_analysis: float | None = None
        self._events: dict[str, _Event] = {}
        self._investigation_times: deque[float] = deque()
        self._pending = 0
        self._recorder: CaptureRecorder | None = None
        self._capture: CaptureSession | None = None  # the library row of this capture (kept after stop for the summary)
        self._capture_error: str | None = None
        self._limits = (0, 0.0, 0, 0.0)  # max file bytes, max seconds, rotate bytes, rotate seconds (0 = off), from Settings at start
        self._file_started: float = 0.0
        self._rotations = 0
        self._rotated_bytes = 0  # size of the files this capture was already split into
        self._rotating = False
        self._notice: str | None = None

    # ------------------------------------------------------------------ start / stop
    def start(self, req: StartRequest) -> LiveStatus:
        if not req.confirm:
            raise CaptureRefused("confirmation_required", "Capture must be started explicitly (confirm=true).")
        known = {i.name for i in self._list_interfaces()}
        if req.interface not in known:
            raise CaptureRefused("unknown_interface", "That interface does not exist on this machine.")
        with self._lock:
            if self._state == "capturing":
                raise CaptureRefused("already_capturing", "A capture is already running; stop it first.")
            self._reset()
            cfg = current_settings()
            req = req.model_copy(update={"save": cfg.capture.auto_save if req.save is None else req.save,
                                         "format": req.format or cfg.capture.format})
            c = cfg.capture
            self._limits = (c.max_size_mb * 1024 * 1024, c.max_duration_minutes * 60.0,
                            c.rotation_size_mb * 1024 * 1024 if c.rotation_enabled else 0, c.rotation_minutes * 60.0 if c.rotation_enabled else 0.0)
            self._headers_only = not cfg.privacy.store_payloads
            self._interface, self._auto = req.interface, req.auto_investigate
            label = next((i.description for i in self._list_interfaces() if i.name == req.interface and i.description), req.interface)
            started = self._clock()
            try:
                self._open_recording(req, label, started)
            except CaptureStartError as exc:
                self._state = "error"
                self._error = LiveError(code=exc.code, message=exc.message, hint=exc.hint)
                raise
            source = self._source_factory()
            try:
                source.start(req.interface, self._on_packet)
            except CaptureStartError as exc:
                self._discard_recording()
                self._state = "permission_error" if exc.permission else "error"
                self._error = LiveError(code=exc.code, message=exc.message, hint=exc.hint)
                raise
            self._source, self._state = source, "capturing"
            self._started_at = self._file_started = started
            self._stop_evt.clear()
            self._thread = threading.Thread(target=self._loop, name="packetmind-live-analysis", daemon=True)
            self._thread.start()
        logger.info("Live capture started on %s (auto_investigate=%s)", req.interface, req.auto_investigate)
        return self.status()

    def stop(self) -> LiveStatus:
        with self._lock:
            was_capturing = self._state == "capturing"
            source, thread = self._source, self._thread
            self._source = self._thread = None
        self._stop_evt.set()
        if source is not None:
            source.stop()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=10)
        if was_capturing:
            try:
                self._analyze()  # final pass so the last seconds are reflected
            except Exception:
                logger.exception("Final live analysis failed")
        self._finish_recording()  # after the source stopped: no packet can arrive any more
        if was_capturing and self._on_session_end is not None and self._capture is None:
            with self._lock:
                result, started, interface = self._result, self._started_at, self._interface
            if result is not None and started is not None:
                try:
                    self._on_session_end(result, f"live-{int(started)}-{interface}", interface or "live", started)
                except Exception:
                    logger.exception("Recording the live session's performance history failed")
        with self._lock:
            if was_capturing:
                self._stopped_at = self._clock()
                self._state = "stopped"
            elif self._state in ("permission_error", "error"):
                self._reset()  # acknowledge the error
        logger.info("Live capture stopped")
        return self.status()

    def shutdown(self) -> None:
        self.stop()
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ packet path
    def _on_packet(self, pkt) -> None:
        now = self._clock()
        try:
            rec = extract_record(next(self._counter), pkt)
        except Exception:
            with self._lock:
                self._parse_errors += 1
            return
        with self._lock:
            if self._state != "capturing":
                return
            self._packets += 1
            self._bytes += rec.size
            b = self._buckets.setdefault(int(now), [0, 0])
            b[0] += 1
            b[1] += rec.size
            if len(self._records) == self._records.maxlen:
                self._truncated = True
            self._records.append(rec)
            recorder = self._recorder
        if recorder is not None:
            if not recorder.write(pkt) and recorder.error:
                self._fail("capture_write_failed", recorder.error, "Free disk space or check permissions, then start a new capture.")
            else:
                self._check_limits(recorder, now)

    # ------------------------------------------------------------------ analysis loop
    def _loop(self) -> None:
        while not self._stop_evt.wait(self.config.refresh_seconds):
            try:
                with self._lock:
                    if self._state != "capturing":
                        return
                    failure = self._source.failure() if self._source else None
                if failure:
                    self._fail("capture_interrupted", f"Capture stopped unexpectedly ({failure}).",
                               "The interface may have gone down. Start the capture again.")
                    return
                if self._recorder is not None:
                    self._recorder.flush()
                    self._check_limits(self._recorder, self._clock())
                self._analyze()  # not under the lock: packets keep flowing while we analyse
            except Exception:
                logger.exception("Live analysis pass failed; will retry next interval")

    # ------------------------------------------------------------------ recording
    def _open_recording(self, req: StartRequest, label: str, started: float) -> None:
        """Create the library row and the capture file. Called under the lock, before the interface is opened."""
        if self._store is None or not req.save:
            return
        if self._before_recording is not None:
            self._before_recording()  # may refuse (storage limit)
        filename = self._store.generate_filename("capture", req.format)
        try:
            recorder = CaptureRecorder(self._store.reserve_file(filename), req.format, headers_only=getattr(self, "_headers_only", False))
        except CaptureStartError:
            raise
        except Exception as exc:
            logger.error("Could not create the capture file: %s", type(exc).__name__)
            raise CaptureStartError("capture_file_failed", "PacketMind could not create the capture file in its capture folder.",
                                    "Check that the folder exists, is writable and the disk is not full.") from None
        self._recorder = recorder
        self._capture = self._store.create(source_type="LIVE_CAPTURE", capture_format=req.format, original_filename=filename, filename=filename,
                                           interface=label, start_time=started, status="CAPTURING")

    def _discard_recording(self) -> None:
        """The interface could not be opened: nothing was captured, so drop the empty file and its row."""
        recorder, capture = self._recorder, self._capture
        self._recorder = self._capture = None
        if recorder is not None:
            recorder.close()
        if capture is not None and self._store is not None:
            try:
                self._store.delete(capture.id)
            except Exception:
                logger.exception("Could not remove the unused capture file")

    def _fail(self, code: str, message: str, hint: str | None = None) -> None:
        """A capture died while running (interface gone, disk full...): stop the source, save what exists, say so clearly."""
        with self._lock:
            if self._state != "capturing":
                return
            self._state = "error"
            self._error = LiveError(code=code, message=message, hint=hint)
            self._capture_error = message if code == "capture_write_failed" else None
            source = self._source
        self._stop_evt.set()

        def _wind_down() -> None:
            if source is not None:
                source.stop()
            self._finish_recording()

        threading.Thread(target=_wind_down, name="packetmind-capture-failure", daemon=True).start()

    def _finish_recording(self) -> None:
        """Close the writer, verify the file and record the final metadata. Idempotent; never raises."""
        with self._lock:
            recorder, capture = self._recorder, self._capture
            self._recorder = None
            started = self._file_started or self._started_at
        if recorder is None or capture is None or self._store is None:
            return
        saved = self._finalize(recorder, capture, started, self._clock(), self._capture_error)
        with self._lock:
            self._capture = saved
        if saved.status == "FAILED" and self._error is None:
            with self._lock:
                self._error = LiveError(code="capture_not_saved", message=saved.error_message or "The capture was not saved.", hint=None)

    def _finalize(self, recorder: CaptureRecorder, capture: CaptureSession, started: float, end: float, forced_failure: str | None = None) -> CaptureSession:
        """Close one capture file, verify it, update its library row, and hand a good file to the analysis."""
        recorder.close()
        failure = recorder.error or forced_failure
        size = 0
        try:
            size = self._store.path_of(capture).stat().st_size
        except OSError:
            size = 0
        if not failure:
            try:
                size = verify_capture_file(self._store.path_of(capture), recorder.packets)
            except RecorderError as exc:
                failure = str(exc)
            except Exception:
                logger.exception("Verifying the capture file failed")
                failure = "The saved capture file could not be verified."
        if not failure and recorder.packets == 0:
            failure = "No packets were captured, so there is nothing to save."
        fields = dict(end_time=end, duration_seconds=round(max(0.0, end - started), 3), packet_count=recorder.packets,
                      byte_count=recorder.bytes, file_size=size, status="FAILED" if failure else "COMPLETED", error_message=failure)
        try:
            saved = self._store.update(capture.id, **fields) or capture
        except Exception:
            logger.exception("Could not record the final capture metadata")
            saved = capture
        if failure:
            logger.warning("Capture %s was not saved cleanly: %s", capture.id, failure)
        elif self._on_capture_saved is not None:
            try:
                self._on_capture_saved(saved)
            except Exception:
                logger.exception("Starting the analysis of the saved capture failed")
        return saved

    # ------------------------------------------------------------------ limits and rotation (from Settings → Capture)
    def _check_limits(self, recorder: CaptureRecorder, now: float) -> None:
        max_bytes, max_seconds, rot_bytes, rot_seconds = self._limits
        if max_seconds and self._started_at is not None and now - self._started_at >= max_seconds:
            self._stop_by_limit(f"Capture stopped automatically: the maximum duration ({int(max_seconds // 60)} min) was reached.")
        elif max_bytes and self._rotated_bytes + recorder.approx_size >= max_bytes:
            self._stop_by_limit(f"Capture stopped automatically: the maximum capture size ({max_bytes // 1024 // 1024} MB) was reached.")
        elif (rot_bytes and recorder.approx_size >= rot_bytes) or (rot_seconds and now - self._file_started >= rot_seconds):
            self._rotate(now)

    def _stop_by_limit(self, notice: str) -> None:
        with self._lock:
            if self._state != "capturing" or self._notice:
                return
            self._notice = notice
        logger.info(notice)
        threading.Thread(target=self.stop, name="packetmind-capture-limit", daemon=True).start()

    def _rotate(self, now: float) -> None:
        """Start a new capture file and finish the old one (it is saved, verified and analysed like any other)."""
        if self._store is None:
            return
        with self._lock:
            if self._rotating or self._state != "capturing" or self._recorder is None or self._capture is None:
                return
            self._rotating = True
            old_rec, old_cap, old_started = self._recorder, self._capture, self._file_started
        try:
            fmt = old_cap.capture_format
            filename = self._store.generate_filename("capture", fmt)
            new_rec = CaptureRecorder(self._store.reserve_file(filename), fmt, headers_only=self._headers_only)
            new_cap = self._store.create(source_type="LIVE_CAPTURE", capture_format=fmt, original_filename=filename, filename=filename,
                                         interface=old_cap.interface, start_time=now, status="CAPTURING")
        except Exception:
            logger.exception("Could not start the next capture file; continuing with the current one")
            with self._lock:
                self._rotating = False
            return
        with self._lock:
            self._recorder, self._capture, self._file_started = new_rec, new_cap, now
            self._rotations += 1
            self._rotated_bytes += old_rec.approx_size
            self._rotating = False
        self._finalize(old_rec, old_cap, old_started, now)

    def _capture_info(self) -> LiveCaptureFile | None:
        c = self._capture
        if c is None:
            return None
        r = self._recorder
        error = c.error_message or (r.error if r else None) or self._capture_error
        return LiveCaptureFile(id=c.id, filename=c.filename, format=c.capture_format, status="FAILED" if error else c.status,
                               packets=r.packets if r else c.packet_count, bytes=r.bytes if r else c.byte_count, file_size=c.file_size, error=error,
                               rotated=self._rotations)

    def _analyze(self) -> None:
        """Run local analysis + detection on the rolling window, then record events."""
        with self._lock:
            if self._records:
                horizon = self._records[-1].timestamp - self.config.window_seconds
                while self._records and self._records[0].timestamp < horizon:
                    self._records.popleft()
                if len(self._records) < (self._records.maxlen or 0):
                    self._truncated = False
            records = list(self._records)
            interface = self._interface
            for sec in [s for s in self._buckets if s < int(self._clock()) - 120]:
                del self._buckets[sec]
        result = analyze_records(records, source_name=f"live:{interface}")
        findings = detect_threats(result)
        now = self._clock()
        with self._lock:
            self._result, self._last_analysis = result, now
            self._update_events(findings, now)
            if self._auto:
                for f in findings:
                    self._maybe_investigate(f, result, now)

    # ------------------------------------------------------------------ events & escalation
    def _update_events(self, findings: list[Finding], now: float) -> None:
        seen = set()
        for f in findings:
            seen.add(f.id)
            ev = self._events.get(f.id)
            if ev is None:
                self._events[f.id] = _Event(f, now)
            else:
                ev.finding, ev.last, ev.active = f, now, True
                ev.detections += 1
        for key, ev in self._events.items():
            if key not in seen:
                ev.active = False
        while len(self._events) > self.config.max_events:
            victim = next((k for k, e in self._events.items() if not e.active and e.investigation is None), None) \
                or next(iter(self._events))
            del self._events[victim]

    def _maybe_investigate(self, finding: Finding, result: AnalysisResult, now: float) -> None:
        cfg = self.config
        ai = current_settings().ai
        allowed = {"CRITICAL": ai.auto_critical, "HIGH": ai.auto_high, "MEDIUM": ai.auto_medium, "LOW": ai.auto_low}.get(finding.severity.name, False)
        if (not allowed or finding.severity.rank < cfg.investigate_min_severity.rank
                or finding.confidence < max(cfg.investigate_min_confidence, ai.auto_min_confidence)):
            return
        ev = self._events[finding.id]
        if ev.investigation is not None and (
                ev.investigation.status == "pending" or now - ev.investigation.requested_at < cfg.investigation_cooldown_seconds):
            return
        while self._investigation_times and now - self._investigation_times[0] > 3600:
            self._investigation_times.popleft()
        if len(self._investigation_times) >= cfg.max_investigations_per_hour or self._pending >= 1:
            return
        if self._budget is not None and not self._budget.auto_allowed():
            return  # today's automatic-investigation budget (Settings → AI Usage) is used up
        if self._budget is not None:
            self._budget.note_auto()
        self._investigation_times.append(now)
        self._pending += 1
        inv = ev.investigation = LiveInvestigation(status="pending", requested_at=now)
        self._pool.submit(self._run_investigation, inv, result, finding)

    def _run_investigation(self, inv: LiveInvestigation, result: AnalysisResult, finding: Finding) -> None:
        from app.ai.provider import AIProviderError

        try:
            if self._investigator_factory is None:
                from app.ai.investigator import Investigator
                investigator = Investigator()
            else:
                investigator = self._investigator_factory()
            report = investigator.investigate_analysis(result, [finding], finding_id=finding.id)
            outcome = ("completed", report, None)
        except AIProviderError as exc:
            outcome = ("failed", None, LiveError(code=exc.code, message=exc.message))
        except Exception:
            logger.exception("Unexpected investigation failure")
            outcome = ("failed", None, LiveError(code="investigation_failed", message="The investigation failed unexpectedly."))
        with self._lock:
            inv.status, inv.report, inv.error = outcome
            self._pending = max(0, self._pending - 1)

    # ------------------------------------------------------------------ status
    def status(self) -> LiveStatus:
        with self._lock:
            now = self._clock()
            end = now if self._state == "capturing" else (self._stopped_at or now)
            elapsed = max(0.0, end - self._started_at) if self._started_at else 0.0
            r = self._result
            pps = bps = 0.0
            if self._state == "capturing":
                sec, span = int(now), self.config.rate_window_seconds
                covered = max(1.0, min(span + (now - sec), elapsed))  # seconds of traffic actually summed
                recent = [b for s, b in self._buckets.items() if sec - span <= s <= sec]
                pps = round(sum(b[0] for b in recent) / covered, 2)
                bps = round(sum(b[1] for b in recent) * 8 / covered, 1)
            events = sorted(self._events.values(), key=lambda e: (e.active, e.finding.severity.rank, e.finding.confidence), reverse=True)
            return LiveStatus(
                state=self._state, interface=self._interface, started_at=self._started_at,
                elapsed_seconds=round(elapsed, 1), packets_total=self._packets, bytes_total=self._bytes,
                packets_per_second=pps, bits_per_second=bps,
                window_seconds=round(r.metadata.duration_seconds, 1) if r else 0.0,
                window_packets=r.metadata.packets_read if r else 0, window_truncated=self._truncated,
                last_analysis_at=self._last_analysis,
                protocols=r.protocol_statistics.distribution[:10] if r else [],
                top_talkers=r.ip_statistics.top_talkers[:10] if r else [],
                top_ports=r.port_statistics.top_destination_ports[:10] if r else [],
                findings=[LiveFindingEvent(
                    finding=e.finding, first_detected_at=e.first, last_detected_at=e.last, detections=e.detections,
                    active=e.active, investigation=e.investigation.model_copy(deep=True) if e.investigation else None)
                    for e in events],
                capture=self._capture_info(), notice=self._notice, auto_investigate=self._auto, parse_errors=self._parse_errors, error=self._error,
            )

    def snapshot(self):
        """(analysis result, findings seen so far, interface, completed per-finding AI results) for reports."""
        with self._lock:
            need = self._result is None and bool(self._records)
        if need:
            self._analyze()
        with self._lock:
            ai = {fid: e.investigation.report.result for fid, e in self._events.items()
                  if e.investigation and e.investigation.status == "completed" and e.investigation.report}
            return self._result, [e.finding for e in self._events.values()], self._interface, ai

    def analyze_now(self) -> None:
        """Run one analysis pass immediately (used by tests)."""
        self._analyze()
