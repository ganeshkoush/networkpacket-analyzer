"""A stopped live session can be handed to the performance history; failures never block stopping."""
from live_helpers import IFACE, FakeSource, scan
from pcap_factory import T0

from app.capture import LiveCaptureManager, LiveConfig
from app.models.live import StartRequest


def make(source, hook):
    return LiveCaptureManager(LiveConfig(refresh_seconds=3600), source_factory=lambda: source, clock=lambda: T0,
                              interface_lister=lambda: [IFACE], on_session_end=hook)


def test_a_stopped_live_session_is_reported_once_and_failures_do_not_block_stopping():
    calls = []
    src = FakeSource()
    mgr = make(src, lambda result, sid, iface, started: calls.append((sid, iface, started)))
    mgr.start(StartRequest(interface="test0", confirm=True))
    src.emit(scan(30))
    mgr.stop()
    assert calls == [(f"live-{int(T0)}-test0", "test0", T0)]
    mgr.stop()  # stopping again does not record again
    assert len(calls) == 1

    def boom(*a):
        raise RuntimeError("nope")

    src2 = FakeSource()
    bad = make(src2, boom)
    bad.start(StartRequest(interface="test0", confirm=True))
    src2.emit(scan(10))
    assert bad.stop().state == "stopped"
