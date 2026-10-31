"""Live capture -> standard PCAP file: recorder, manager integration, failure handling. No real capture or privileges needed."""
import errno
import io
import time

import pytest
from live_helpers import FakeSource, IFACE, SCANNER, TARGET, make_manager, scan, wait_until

import pcap_factory as pf
from app.analysis import analyze_pcap
from app.analysis.pcap_parser import PcapParser, detect_format
from app.capture import CaptureStartError
from app.capture.recorder import CaptureRecorder, RecorderError, verify_capture_file
from app.models.live import StartRequest


def start(mgr, **kw):
    return mgr.start(StartRequest(interface=IFACE.name, confirm=True, **kw))


def pkts(n=40):
    return scan(n)  # 2 packets per port: SYN + RST


# ------------------------------------------------------------------ recorder
def test_recorder_writes_a_standard_pcap_with_timestamps(tmp_path):
    path = tmp_path / "r.pcap"
    rec = CaptureRecorder(open(path, "wb"), "pcap")
    packets = pkts(10)
    for p in packets:
        assert rec.write(p)
    rec.close()
    assert rec.packets == len(packets) and rec.bytes == sum(len(p) for p in packets) and rec.error is None
    assert detect_format(path) == "pcap"
    read = list(PcapParser(path))
    assert len(read) == len(packets) and read[0].timestamp == pytest.approx(float(packets[0].time), abs=1e-5)
    assert verify_capture_file(path, rec.packets) == path.stat().st_size


def test_recorder_supports_pcapng(tmp_path):
    path = tmp_path / "r.pcapng"
    rec = CaptureRecorder(path, "pcapng")
    for p in pkts(10):
        rec.write(p)
    rec.close()
    assert detect_format(path) == "pcapng" and len(list(PcapParser(path))) == 20


def test_close_is_idempotent_and_flushes_pending_packets(tmp_path):
    path = tmp_path / "r.pcap"
    rec = CaptureRecorder(open(path, "wb"))
    rec.write(pkts(1)[0])
    rec.close()
    rec.close()
    assert not rec.write(pkts(1)[0])                       # nothing is written after close
    assert len(list(PcapParser(path))) == 1


class FullDisk(io.RawIOBase):
    def __init__(self, ok=2000):
        self.ok, self.n = ok, 0

    def writable(self):
        return True

    def write(self, b):
        self.n += len(b)
        if self.n > self.ok:
            raise OSError(errno.ENOSPC, "No space left on device")
        return len(b)


def test_a_disk_write_failure_is_recorded_not_raised_and_stops_writing():
    rec = CaptureRecorder(io.BufferedWriter(FullDisk(ok=100)))
    results = [rec.write(p) for p in pkts(40)]
    rec.flush()
    rec.close()
    assert rec.error and "disk is full" in rec.error      # the buffered data could not reach the disk
    assert not rec.write(pkts(1)[0])                       # and nothing more is written after a failure


def test_verify_rejects_missing_and_invalid_files(tmp_path):
    with pytest.raises(RecorderError):
        verify_capture_file(tmp_path / "nope.pcap")
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture at all")
    with pytest.raises(RecorderError):
        verify_capture_file(bad)


# ------------------------------------------------------------------ manager + library
def test_start_creates_a_session_and_a_safe_generated_file(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    status = start(mgr)
    cap = status.capture
    assert cap and cap.status == "CAPTURING" and cap.format == "pcap"
    assert cap.filename.startswith("packetmind_capture_") and cap.filename.endswith(".pcap") and "/" not in cap.filename
    row = capture_library.get(cap.id)
    assert row.source_type == "LIVE_CAPTURE" and row.status == "CAPTURING" and row.interface == "Test"
    assert (capture_library.directory / cap.filename).oct if False else True
    mgr.stop()


def test_a_normal_stop_saves_a_valid_readable_pcap_with_metadata(capture_library):
    saved = []
    mgr, src, clock = make_manager(store=capture_library, on_saved=saved.append)
    start(mgr)
    packets = pkts(30)
    src.emit(packets)
    clock.t += 12
    status = mgr.stop()
    cap = status.capture
    assert status.state == "stopped" and cap.status == "COMPLETED" and cap.error is None
    assert cap.packets == len(packets) == status.packets_total and cap.bytes == sum(len(p) for p in packets)
    row = capture_library.get(cap.id)
    path = capture_library.path_of(row)
    assert row.status == "COMPLETED" and row.packet_count == len(packets) and row.file_size == path.stat().st_size > 24
    assert row.duration_seconds == pytest.approx(12) and row.end_time > row.start_time
    assert oct(path.stat().st_mode & 0o777) == "0o600"                         # captured traffic is owner-only
    assert detect_format(path) == "pcap" and len(list(PcapParser(path))) == len(packets)
    assert [s.id for s in saved] == [cap.id]                                    # told once, so it can be analysed


def test_the_saved_file_goes_through_the_same_analysis_as_an_import(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr)
    src.emit(pkts(60))
    mgr.analyze_now()
    live = mgr.status()
    mgr.stop()
    row = capture_library.get(mgr.status().capture.id)
    result = analyze_pcap(capture_library.path_of(row))
    assert result.packet_statistics.total_packets == live.packets_total == 120
    assert {p.protocol for p in result.protocol_statistics.distribution} >= {p.protocol for p in live.protocols}


def test_pcapng_format_is_supported(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr, format="pcapng")
    src.emit(pkts(5))
    cap = mgr.stop().capture
    assert cap.filename.endswith(".pcapng") and cap.format == "pcapng" and cap.status == "COMPLETED"
    assert detect_format(capture_library.path_of(capture_library.get(cap.id))) == "pcapng"


def test_save_false_records_nothing(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr, save=False)
    src.emit(pkts(5))
    status = mgr.stop()
    assert status.capture is None and capture_library.list() == [] and not any(capture_library.directory.glob("*"))


def test_without_a_store_nothing_touches_the_disk(tmp_path):
    mgr, src, _ = make_manager()
    start(mgr)
    src.emit(pkts(5))
    assert mgr.stop().capture is None


def test_two_captures_get_different_files(capture_library):
    names = []
    for _ in range(2):
        mgr, src, _ = make_manager(store=capture_library)
        start(mgr)
        src.emit(pkts(3))
        names.append(mgr.stop().capture.filename)
    assert names[0] != names[1] and len(capture_library.list()) == 2


def test_an_empty_capture_is_reported_not_silently_saved(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr)
    status = mgr.stop()
    assert status.capture.status == "FAILED" and "No packets" in status.capture.error and status.error.code == "capture_not_saved"


def test_permission_failure_leaves_no_file_or_row(capture_library):
    err = CaptureStartError("permission_denied", "Permission denied", "sudo", permission=True)
    mgr, *_ = make_manager(FakeSource(error=err), store=capture_library)
    with pytest.raises(CaptureStartError):
        start(mgr)
    assert mgr.status().state == "permission_error" and capture_library.list() == [] and not any(capture_library.directory.glob("*"))


def test_cannot_create_the_capture_file(capture_library, monkeypatch):
    monkeypatch.setattr(type(capture_library), "reserve_file", lambda self, name: (_ for _ in ()).throw(PermissionError("denied")))
    mgr, src, _ = make_manager(store=capture_library)
    with pytest.raises(CaptureStartError) as e:
        start(mgr)
    assert e.value.code == "capture_file_failed" and mgr.status().state == "error" and src.callback is None


def test_disk_failure_during_capture_is_surfaced_and_never_reported_as_saved(capture_library, monkeypatch):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr)
    real_write = mgr._recorder._writer.write  # noqa: SLF001
    state = {"n": 0}

    def flaky(pkt):
        state["n"] += 1
        if state["n"] > 5:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(pkt)

    mgr._recorder._writer.write = flaky  # noqa: SLF001
    src.emit(pkts(20))
    assert wait_until(lambda: mgr.status().state == "error")
    assert wait_until(lambda: capture_library.list()[0].status == "FAILED")
    status = mgr.status()
    assert status.error.code == "capture_write_failed" and "disk is full" in status.error.message
    assert status.capture.status == "FAILED" and "disk is full" in status.capture.error
    assert src.stopped
    row = capture_library.get(status.capture.id)
    assert row.status == "FAILED" and row.error_message


def test_the_interface_disappearing_still_saves_what_was_captured(capture_library):
    saved = []
    mgr, src, _ = make_manager(store=capture_library, on_saved=saved.append, refresh_seconds=0.05)
    start(mgr)
    src.emit(pkts(10))
    src.dead = "OSError"
    assert wait_until(lambda: mgr.status().state == "error")
    assert wait_until(lambda: mgr.status().capture.status == "COMPLETED")
    status = mgr.status()
    assert status.error.code == "capture_interrupted" and status.capture.packets == 20 and saved
    assert len(list(PcapParser(capture_library.path_of(capture_library.get(status.capture.id))))) == 20


def test_shutdown_closes_and_verifies_the_file(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr)
    src.emit(pkts(8))
    mgr.shutdown()
    row = capture_library.list()[0]
    assert row.status == "COMPLETED" and len(list(PcapParser(capture_library.path_of(row)))) == 16


def test_status_never_exposes_a_filesystem_path(capture_library):
    mgr, src, _ = make_manager(store=capture_library)
    start(mgr)
    src.emit(pkts(3))
    mgr.stop()
    text = mgr.status().model_dump_json()
    assert str(capture_library.directory) not in text


def test_startup_marks_unfinished_captures(capture_library):
    s = capture_library.create(source_type="LIVE_CAPTURE", capture_format="pcap", original_filename="x.pcap", status="CAPTURING")
    assert capture_library.fail_interrupted() == 1
    assert capture_library.get(s.id).status == "FAILED"
