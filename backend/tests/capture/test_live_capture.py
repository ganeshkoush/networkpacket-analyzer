import errno
import threading

import pcap_factory as pf
import pytest
from live_helpers import IFACE, SCANNER, TARGET, FakeInvestigator, FakeSource, make_manager, scan, wait_until

from app.ai.provider import InvalidApiKeyError
from app.capture import CaptureRefused, CaptureStartError
from app.detection import FindingType, Severity
from app.models.live import StartRequest

GO = StartRequest(interface="test0", confirm=True)


# ---------------------------------------------------------------- explicit start / stop
def test_nothing_is_started_by_constructing_the_manager():
    started = []
    from app.capture import LiveCaptureManager
    mgr = LiveCaptureManager(source_factory=lambda: started.append(1) or FakeSource())
    assert started == [] and mgr.status().state == "stopped"


def test_start_requires_confirmation_and_known_interface():
    mgr, src, _ = make_manager()
    with pytest.raises(CaptureRefused) as e:
        mgr.start(StartRequest(interface="test0"))
    assert e.value.code == "confirmation_required" and src.callback is None
    with pytest.raises(CaptureRefused) as e:
        mgr.start(StartRequest(interface="../../etc/passwd", confirm=True))
    assert e.value.code == "unknown_interface"
    assert mgr.status().state == "stopped"


def test_start_stop_lifecycle_and_double_start():
    mgr, src, _ = make_manager()
    assert mgr.start(GO).state == "capturing" and src.interface == "test0"
    with pytest.raises(CaptureRefused) as e:
        mgr.start(GO)
    assert e.value.code == "already_capturing"
    src.emit([pf.tcp("1.1.1.1", "10.0.0.2", 1, 2)])
    st = mgr.stop()
    assert st.state == "stopped" and src.stopped and st.packets_total == 1
    assert mgr.stop().state == "stopped"  # idempotent
    assert mgr.start(GO).state == "capturing"  # can restart; counters reset
    assert mgr.status().packets_total == 0
    mgr.stop()


# ---------------------------------------------------------------- permission errors
def test_permission_error_is_reported_not_raised_to_crash():
    err = CaptureStartError("permission_denied", "Permission denied", "run with sudo", permission=True)
    mgr, _, _ = make_manager(FakeSource(error=err))
    with pytest.raises(CaptureStartError):
        mgr.start(GO)
    st = mgr.status()
    assert st.state == "permission_error" and st.error.code == "permission_denied" and st.error.hint == "run with sudo"
    assert mgr.stop().state == "stopped" and mgr.status().error is None  # stop acknowledges the error


def test_other_start_failure_is_error_state():
    mgr, _, _ = make_manager(FakeSource(error=CaptureStartError("capture_failed", "boom")))
    with pytest.raises(CaptureStartError):
        mgr.start(GO)
    assert mgr.status().state == "error"


def test_capture_dying_midway_becomes_error_state():
    mgr, src, _ = make_manager(refresh_seconds=0.05)
    mgr.start(GO)
    src.dead = "OSError"
    assert wait_until(lambda: mgr.status().state == "error")
    assert mgr.status().error.code == "capture_interrupted"
    mgr.stop()


# ---------------------------------------------------------------- counters / stats
def test_counts_rate_protocols_talkers_ports():
    mgr, src, clock = make_manager()
    mgr.start(GO)
    pk = [pf.tcp("8.8.4.4", "10.0.0.2", 50000 + i, 443, "A", payload=b"x" * 10, ts=pf.T0 + i * 0.01) for i in range(50)]
    pk += [pf.dns_query("10.0.0.2", "8.8.8.8", "example.com", txid=i, ts=pf.T0 + i * 0.01) for i in range(10)]
    src.emit(pk)
    clock.t = pf.T0 + 2
    mgr.analyze_now()
    st = mgr.status()
    assert st.packets_total == 60 and st.bytes_total > 0
    assert st.packets_per_second == pytest.approx(30.0)  # 60 packets, 2 s elapsed
    assert {p.protocol for p in st.protocols} == {"TCP", "DNS"}
    assert st.top_talkers[0].ip in ("10.0.0.2", "8.8.4.4")
    ports = {(p.protocol, p.port) for p in st.top_ports}
    assert ("TCP", 443) in ports and ("UDP", 53) in ports
    assert st.window_packets == 60 and st.last_analysis_at
    mgr.stop()


def test_unparseable_packets_are_counted_not_fatal():
    mgr, src, _ = make_manager()
    mgr.start(GO)
    src.emit([object(), pf.tcp("1.1.1.1", "10.0.0.2", 1, 2)])
    st = mgr.status()
    assert st.parse_errors == 1 and st.packets_total == 1
    mgr.stop()


def test_rolling_window_discards_old_packets_but_keeps_totals():
    mgr, src, clock = make_manager(window_seconds=10)
    mgr.start(GO)
    src.emit([pf.tcp("1.1.1.1", "10.0.0.2", 1, 80, ts=pf.T0 + i) for i in range(5)])
    src.emit([pf.tcp("2.2.2.2", "10.0.0.2", 1, 80, ts=pf.T0 + 100 + i) for i in range(3)])
    mgr.analyze_now()
    st = mgr.status()
    assert st.packets_total == 8 and st.window_packets == 3
    assert [t.ip for t in st.top_talkers if t.ip == "1.1.1.1"] == []
    mgr.stop()


def test_window_packet_cap_bounds_memory_and_is_flagged():
    mgr, src, _ = make_manager(max_window_packets=100)
    mgr.start(GO)
    src.emit([pf.tcp("1.1.1.1", "10.0.0.2", 1, 80, ts=pf.T0 + i * 0.001) for i in range(250)])
    mgr.analyze_now()
    st = mgr.status()
    assert st.packets_total == 250 and st.window_packets == 100 and st.window_truncated
    mgr.stop()


# ---------------------------------------------------------------- detection & investigation
def test_detection_generates_findings_and_keeps_them_after_window_passes():
    mgr, src, clock = make_manager(window_seconds=10)
    mgr.start(GO)
    src.emit(scan())
    mgr.analyze_now()
    (ev,) = [e for e in mgr.status().findings if e.finding.type == FindingType.PORT_SCAN]
    assert ev.active and ev.finding.source_ip == SCANNER and ev.finding.evidence and ev.investigation is None
    src.emit([pf.tcp("1.1.1.1", "10.0.0.2", 1, 80, ts=pf.T0 + 1000)])  # window moves on
    mgr.analyze_now()
    (ev,) = [e for e in mgr.status().findings if e.finding.type == FindingType.PORT_SCAN]
    assert not ev.active and ev.detections == 1
    mgr.stop()


def test_no_ai_call_unless_user_opted_in():
    inv = FakeInvestigator()
    mgr, src, _ = make_manager(investigator=inv)
    mgr.start(GO)  # auto_investigate defaults to False
    src.emit(scan())
    mgr.analyze_now()
    assert inv.calls == [] and mgr.status().findings
    mgr.stop()


def test_suspicious_event_triggers_one_investigation_with_aggregated_evidence_only():
    inv = FakeInvestigator()
    mgr, src, clock = make_manager(investigator=inv)
    mgr.start(StartRequest(interface="test0", confirm=True, auto_investigate=True))
    src.emit(scan())
    mgr.analyze_now()
    assert wait_until(lambda: inv.calls and mgr.status().findings[0].investigation.status == "completed")
    analysis, findings, fid = inv.calls[0]
    assert len(inv.calls) == 1 and fid == findings[0].id and findings[0].type == FindingType.PORT_SCAN
    assert analysis.metadata.file_path == "" and analysis.metadata.capture_format == "live"
    # same event again within cooldown: no second call
    mgr.analyze_now()
    clock.t += 10
    mgr.analyze_now()
    assert len(inv.calls) == 1
    inv_state = mgr.status().findings[0].investigation
    assert inv_state.report.result.finding_type == "PORT_SCAN"
    mgr.stop()


def test_investigation_repeats_after_cooldown_and_respects_hourly_budget():
    inv = FakeInvestigator()
    mgr, src, clock = make_manager(investigator=inv, investigation_cooldown_seconds=10, max_investigations_per_hour=2)
    mgr.start(StartRequest(interface="test0", confirm=True, auto_investigate=True))
    src.emit(scan())
    for _ in range(4):
        mgr.analyze_now()
        wait_until(lambda: mgr.status().findings[0].investigation.status != "pending")
        clock.t += 11
    assert len(inv.calls) == 2
    mgr.stop()


def test_low_severity_or_confidence_does_not_trigger():
    inv = FakeInvestigator()
    mgr, src, _ = make_manager(investigator=inv, investigate_min_severity=Severity.CRITICAL)
    mgr.start(StartRequest(interface="test0", confirm=True, auto_investigate=True))
    src.emit(scan())
    mgr.analyze_now()
    assert inv.calls == []
    mgr.stop()


def test_ai_failure_is_recorded_and_capture_continues():
    inv = FakeInvestigator(error=InvalidApiKeyError())
    mgr, src, _ = make_manager(investigator=inv)
    mgr.start(StartRequest(interface="test0", confirm=True, auto_investigate=True))
    src.emit(scan())
    mgr.analyze_now()
    assert wait_until(lambda: mgr.status().findings[0].investigation.status == "failed")
    assert mgr.status().findings[0].investigation.error.code == "invalid_api_key"
    assert mgr.status().state == "capturing"
    mgr.stop()


def test_background_loop_runs_analysis_periodically():
    mgr, src, _ = make_manager(refresh_seconds=0.05)
    mgr.start(GO)
    src.emit(scan())
    assert wait_until(lambda: any(e.finding.type == FindingType.PORT_SCAN for e in mgr.status().findings))
    mgr.stop()


def test_packets_can_arrive_while_analysing():
    mgr, src, _ = make_manager(refresh_seconds=0.02)
    mgr.start(GO)
    def feed():
        for i in range(300):
            src.emit([pf.tcp("1.1.1.1", "10.0.0.2", i, 80, ts=pf.T0 + i * 0.001)])
    t = threading.Thread(target=feed); t.start(); t.join()
    assert mgr.stop().packets_total == 300


# ---------------------------------------------------------------- passive-only guarantee
def test_capture_code_never_sends_or_modifies_traffic():
    import pathlib, re
    root = pathlib.Path(__file__).parents[2] / "app" / "capture"
    code = "\n".join(p.read_text() for p in root.glob("*.py"))
    assert not re.search(r"\b(sendp?|srp?1?|send_|L3RawSocket|\.send\(|iptables|pfctl|netsh|subprocess\.Popen)\b", code.replace("subprocess.run", ""))
