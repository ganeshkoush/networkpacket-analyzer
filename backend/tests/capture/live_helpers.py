"""Fakes for live-capture tests: no privileges, interfaces or network are needed."""
from __future__ import annotations

import time

import pcap_factory as pf

from app.ai.provider import AIProviderError, InvalidApiKeyError
from app.ai.schemas import InvestigationReport, InvestigationResult
from app.capture import CaptureStartError, LiveCaptureManager, LiveConfig, PacketSource
from app.detection.severity import Severity
from app.models.live import InterfaceInfo

SCANNER, TARGET = "45.33.32.156", "10.0.0.9"
IFACE = InterfaceInfo(name="test0", description="Test", kind="ethernet")


class FakeSource(PacketSource):
    def __init__(self, error: CaptureStartError | None = None):
        self.error, self.callback, self.stopped, self.dead = error, None, False, None

    def start(self, interface, on_packet):
        if self.error:
            raise self.error
        self.interface, self.callback = interface, on_packet

    def emit(self, packets):
        for p in packets:
            if hasattr(p, "time"):  # a real sniffer delivers packets dissected from wire bytes
                q = p.__class__(bytes(p))
                q.time = p.time
                p = q
            self.callback(p)

    def stop(self):
        self.stopped = True

    def failure(self):
        return self.dead


class Clock:
    def __init__(self, t=pf.T0):
        self.t = t

    def __call__(self):
        return self.t


class FakeInvestigator:
    def __init__(self, error: AIProviderError | None = None):
        self.calls, self.error = [], error

    def investigate_analysis(self, analysis, findings, question=None, finding_id=None):
        self.calls.append((analysis, findings, finding_id))
        if self.error:
            raise self.error
        return InvestigationReport(provider="fake", model="m", result=InvestigationResult(
            investigation_summary="Possible scan.", finding_type=findings[0].type.value, severity=Severity.HIGH,
            confidence=0.8, evidence=["observed"], interpretation="Consistent with scanning."))


def make_manager(source=None, investigator=None, store=None, on_saved=None, **cfg):
    src = source or FakeSource()
    clock = Clock()
    cfg.setdefault("refresh_seconds", 3600)  # tests drive analysis explicitly via analyze_now()
    mgr = LiveCaptureManager(LiveConfig(**cfg), source_factory=lambda: src,
                             investigator_factory=(lambda: investigator) if investigator else None,
                             clock=clock, interface_lister=lambda: [IFACE], capture_store=store, on_capture_saved=on_saved)
    return mgr, src, clock


def wait_until(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


def scan(n=120, t0=pf.T0):
    return pf.scan_packets(SCANNER, TARGET, range(1, n + 1), t0=t0, step=0.05)
