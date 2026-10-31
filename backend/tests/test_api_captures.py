"""Capture library API: import (upload), analyze/re-analyze, export, delete, live -> library -> analysis. No real capture needed."""
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from app.api import analyses, live as live_api
from app.config import settings
from app.main import create_app
from app.services.analysis_jobs import AnalysisJobManager
from app.services.capture_library import start_analysis
from capture.live_helpers import make_manager, scan
from correlation import scenarios as sc


@pytest.fixture
def client(tmp_path, monkeypatch, history, capture_library):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(create_app()) as c:
        yield c


def upload(client, data: bytes, name="office.pcap", **headers):
    return client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": name, **headers})


def pcap(tmp_path, packets=None, name="x.pcap", fmt="pcap"):
    packets = sorted(packets if packets is not None else pf.build_attack_demo(), key=lambda p: p.time)
    return (pf.write_pcapng if fmt == "pcapng" else pf.write_pcap)(tmp_path / name, packets).read_bytes()


def wait_job(client, job_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        body = client.get(f"/api/analyses/{job_id}").json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def wait_status(client, capture_id, status, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        body = client.get(f"/api/captures/{capture_id}").json()
        if body["status"] == status:
            return body
        time.sleep(0.05)
    raise AssertionError(f"capture never reached {status}: {body}")


def imported(client, tmp_path, upload_name="office.pcap", **kw):
    job = upload(client, pcap(tmp_path, **kw), upload_name).json()
    wait_job(client, job["id"])
    return job, wait_status(client, job["capture_id"], "ANALYZED")


# ------------------------------------------------------------------ import
def test_an_imported_pcap_is_kept_in_the_library_and_analysed_by_the_existing_pipeline(client, tmp_path, capture_library):
    job, cap = imported(client, tmp_path)
    assert cap["source_type"] == "UPLOADED_PCAP" and cap["original_filename"] == "office.pcap" and cap["capture_format"] == "pcap"
    assert cap["filename"].startswith("packetmind_import_") and cap["filename"] != "office.pcap"        # a generated name, not the user's
    assert cap["packet_count"] > 1000 and cap["file_size"] > 0 and cap["analyzed_at"] and cap["duration_seconds"] > 0
    s = cap["summary"]
    assert s["findings"] > 0 and s["domains"] >= 0 and s["connections"] > 0 and s["protocols"][0]["percent"] > 0
    bundle = client.get(f"/api/analyses/{job['id']}/result").json()          # the same result an upload without the library gives
    assert bundle["analysis"]["packet_statistics"]["total_packets"] == cap["packet_count"] and len(bundle["findings"]) == s["findings"]
    assert bundle["analysis"]["metadata"]["file_path"] == "office.pcap"
    assert not list(settings.uploads_dir.iterdir())                              # the temp upload was moved, not copied
    assert capture_library.path_of(capture_library.get(cap["id"])).stat().st_size == cap["file_size"]


def test_pcapng_import(client, tmp_path):
    _, cap = imported(client, tmp_path, name="x.pcapng", fmt="pcapng", packets=[pf.arp()] + pf.tcp_session())
    assert cap["capture_format"] == "pcapng" and cap["filename"].endswith(".pcapng") and cap["packet_count"] == 8


@pytest.mark.parametrize("name,data,code", [("notes.txt", b"hello", "unsupported_file_type"), ("a.exe", b"MZ", "unsupported_file_type"),
                                            ("empty.pcap", b"", "empty_file"), ("fake.pcap", b"definitely not a capture", "invalid_capture"),
                                            ("truncated.pcap", b"\xd4\xc3\xb2\xa1", None)])
def test_invalid_imports_are_rejected_clearly_and_leave_nothing_behind(client, tmp_path, capture_library, name, data, code):
    r = upload(client, data, name)
    if code:
        assert r.status_code == 400 and r.json()["detail"]["code"] == code
        assert capture_library.list() == [] and not (settings.uploads_dir.exists() and list(settings.uploads_dir.iterdir()))
    else:                                                    # right signature, no packets: accepted, then reported by the analysis
        job = wait_job(client, r.json()["id"])
        assert job["status"] in ("completed", "failed")


def test_path_traversal_in_the_filename_never_reaches_the_disk(client, tmp_path, capture_library):
    job = upload(client, pcap(tmp_path, [pf.arp()]), "../../etc/passwd.pcap").json()
    assert job["filename"] == "passwd.pcap"
    wait_job(client, job["id"])
    cap = capture_library.get(job["capture_id"])
    assert "/" not in cap.filename and capture_library.path_of(cap).parent == capture_library.directory.resolve()


def test_duplicate_names_are_fine(client, tmp_path):
    data = pcap(tmp_path, [pf.arp()])
    a, b = upload(client, data, "same.pcap").json(), upload(client, data, "same.pcap").json()
    assert a["capture_id"] != b["capture_id"]
    names = {c["filename"] for c in client.get("/api/captures").json()}
    assert len(names) == 2


def test_x_save_to_library_false_keeps_the_old_behaviour(client, tmp_path, capture_library):
    job = upload(client, pcap(tmp_path, [pf.arp()]), "once.pcap", **{"X-Save-To-Library": "false"}).json()
    assert job["capture_id"] is None
    wait_job(client, job["id"])
    assert capture_library.list() == [] and not list(settings.uploads_dir.iterdir())


def test_a_large_import_is_streamed_and_analysed(client, tmp_path):
    packets = []
    for i in range(1500):
        packets += pf.tcp_session(client="10.0.%d.%d" % (i // 250, i % 250 + 1), sport=1024 + i % 60000, t=pf.T0 + i * 0.01)
    data = pcap(tmp_path, packets, "large.pcap")
    assert len(data) > 500_000
    job = upload(client, data, "large.pcap").json()
    final = wait_job(client, job["id"])
    assert final["status"] == "completed" and final["packets_read"] == 1500 * 7
    cap = wait_status(client, job["capture_id"], "ANALYZED")
    assert cap["packet_count"] == 1500 * 7 and cap["file_size"] == len(data)


def test_a_progress_percentage_comes_from_bytes_read(client, tmp_path, monkeypatch):
    import threading
    gate = threading.Event()
    real = AnalysisJobManager._run

    def slow(self, job, path):
        gate.wait(5)
        return real(self, job, path)

    monkeypatch.setattr(AnalysisJobManager, "_run", slow)
    job = upload(client, pcap(tmp_path, [pf.arp()])).json()
    assert client.get(f"/api/captures/{job['capture_id']}").json()["status"] == "ANALYZING"
    gate.set()
    wait_status(client, job["capture_id"], "ANALYZED")


# ------------------------------------------------------------------ library
def test_list_get_and_unknown_ids(client, tmp_path):
    _, cap = imported(client, tmp_path)
    listing = client.get("/api/captures").json()
    assert [c["id"] for c in listing] == [cap["id"]]
    assert client.get(f"/api/captures/{cap['id']}").json()["original_filename"] == "office.pcap"
    for bad in ("nope", "../../etc/passwd", "0" * 32):
        assert client.get(f"/api/captures/{bad}").status_code == 404
    assert str(settings.captures_dir) not in client.get("/api/captures").text                          # no filesystem paths


def test_analyze_reuses_a_finished_analysis_and_analyze_again_reruns_the_pipeline_without_touching_the_file(client, tmp_path, capture_library):
    job, cap = imported(client, tmp_path)
    path = capture_library.path_of(capture_library.get(cap["id"]))
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    same = client.post(f"/api/captures/{cap['id']}/analyze").json()
    assert same["id"] == job["id"] and same["capture_id"] == cap["id"]                                  # cached
    again = client.post(f"/api/captures/{cap['id']}/analyze", params={"force": True})
    assert again.status_code == 202 and again.json()["id"] != job["id"]
    wait_job(client, again.json()["id"])
    cap2 = wait_status(client, cap["id"], "ANALYZED")
    assert cap2["packet_count"] == cap["packet_count"] and cap2["summary"] == cap["summary"]
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before                                       # the original is untouched
    assert client.get(f"/api/analyses/{again.json()['id']}/result").status_code == 200


def test_analysing_after_a_backend_restart_works_from_the_saved_file(client, tmp_path, monkeypatch, history):
    _, cap = imported(client, tmp_path)
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=1, retain=5, history=history))      # a fresh backend: no jobs in memory
    job = client.post(f"/api/captures/{cap['id']}/analyze").json()
    assert wait_job(client, job["id"])["status"] == "completed"


def test_a_capture_whose_file_vanished_is_reported(client, tmp_path, capture_library):
    _, cap = imported(client, tmp_path)
    capture_library.path_of(capture_library.get(cap["id"])).unlink()
    r = client.post(f"/api/captures/{cap['id']}/analyze", params={"force": True})
    assert r.status_code == 404 and r.json()["detail"]["code"] == "file_missing"
    assert client.get(f"/api/captures/{cap['id']}/download").status_code == 404


def test_a_corrupt_saved_file_fails_the_analysis_with_a_clear_message(client, tmp_path, capture_library):
    s = capture_library.create(source_type="UPLOADED_PCAP", capture_format="pcap", original_filename="bad.pcap")
    capture_library.directory.mkdir(parents=True, exist_ok=True)
    capture_library.path_of(s).write_bytes(b"this is not a capture file")
    job = client.post(f"/api/captures/{s.id}/analyze").json()
    assert wait_job(client, job["id"])["status"] == "failed"
    cap = client.get(f"/api/captures/{s.id}").json()
    assert cap["status"] == "FAILED" and "may be corrupted or use an unsupported capture format" in cap["error_message"] and "packetmind_import_" not in cap["error_message"] and "Traceback" not in cap["error_message"]


# ------------------------------------------------------------------ delete
def test_delete_needs_explicit_confirmation(client, tmp_path, capture_library):
    _, cap = imported(client, tmp_path)
    path = capture_library.path_of(capture_library.get(cap["id"]))
    r = client.delete(f"/api/captures/{cap['id']}")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "confirmation_required" and path.exists()
    assert client.delete(f"/api/captures/{cap['id']}", params={"confirm": True}).status_code == 204
    assert not path.exists() and client.get(f"/api/captures/{cap['id']}").status_code == 404


def test_a_busy_capture_cannot_be_deleted(client, capture_library):
    s = capture_library.create(source_type="LIVE_CAPTURE", capture_format="pcap", original_filename="x.pcap", status="CAPTURING")
    assert client.delete(f"/api/captures/{s.id}", params={"confirm": True}).status_code == 409
    assert client.post(f"/api/captures/{s.id}/analyze").json()["detail"]["code"] == "capture_in_progress"


# ------------------------------------------------------------------ export / download
def test_export_copies_the_file_and_keeps_the_managed_copy(client, tmp_path, capture_library):
    _, cap = imported(client, tmp_path)
    out = tmp_path / "exports"
    out.mkdir()
    r = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(out / "mine.pcap")})
    assert r.status_code == 200 and r.json() == {"filename": "mine.pcap", "directory": str(out.resolve()), "size_bytes": cap["file_size"]}
    managed = capture_library.path_of(capture_library.get(cap["id"]))
    assert (out / "mine.pcap").read_bytes() == managed.read_bytes() and managed.exists()                # original kept
    assert not list(out.glob(".*part"))                                                                  # no temp left behind
    assert analyses.detect_format(out / "mine.pcap") == "pcap"                                           # a standard capture file


def test_export_adds_the_extension_and_requires_confirmation_to_overwrite(client, tmp_path):
    _, cap = imported(client, tmp_path)
    r = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(tmp_path / "noext")})
    assert r.json()["filename"] == "noext.pcap"
    again = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(tmp_path / "noext.pcap")})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "destination_exists"
    ok = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(tmp_path / "noext.pcap"), "overwrite": True})
    assert ok.status_code == 200


@pytest.mark.parametrize("dest", ["relative/out.pcap", "out.pcap", "{t}/../escape.pcap", "{t}/missing-folder/out.pcap", "{t}/bad\x00name.pcap", "{t}/"])
def test_export_rejects_unsafe_or_invalid_destinations(client, tmp_path, dest):
    _, cap = imported(client, tmp_path)
    r = client.post(f"/api/captures/{cap['id']}/export", json={"destination": dest.format(t=tmp_path)})
    assert r.status_code == 400 and r.json()["detail"]["code"] in ("invalid_destination", "destination_folder_missing")


def test_export_refuses_the_managed_folder_a_directory_and_a_symlink(client, tmp_path, capture_library):
    _, cap = imported(client, tmp_path)
    for dest in (str(capture_library.directory / "copy.pcap"), str(tmp_path)):
        assert client.post(f"/api/captures/{cap['id']}/export", json={"destination": dest}).status_code == 400
    target = tmp_path / "victim.txt"
    target.write_text("keep me")
    link = tmp_path / "link.pcap"
    link.symlink_to(target)
    r = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(link), "overwrite": True})
    assert r.status_code == 400 and target.read_text() == "keep me"


@pytest.mark.skipif(sys.platform.startswith("win") or os.geteuid() == 0, reason="needs POSIX permissions and a non-root user")
def test_export_to_a_read_only_folder_is_a_clear_error(client, tmp_path):
    _, cap = imported(client, tmp_path)
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        r = client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(ro / "x.pcap")})
    finally:
        ro.chmod(0o700)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "destination_not_writable"


def test_download_streams_the_capture(client, tmp_path, capture_library):
    _, cap = imported(client, tmp_path, upload_name="x.pcapng", name="x.pcapng", fmt="pcapng", packets=pf.tcp_session())
    r = client.get(f"/api/captures/{cap['id']}/download")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "x.pcapng" in r.headers["content-disposition"]
    assert r.content == capture_library.path_of(capture_library.get(cap["id"])).read_bytes()


def test_a_recording_in_progress_cannot_be_exported(client, capture_library, tmp_path):
    s = capture_library.create(source_type="LIVE_CAPTURE", capture_format="pcap", original_filename="x.pcap", status="CAPTURING")
    assert client.post(f"/api/captures/{s.id}/export", json={"destination": str(tmp_path / "o.pcap")}).status_code == 409
    assert client.get(f"/api/captures/{s.id}/download").status_code == 409


# ------------------------------------------------------------------ live -> library -> analysis
def test_live_capture_to_saved_pcap_to_analysis_to_export_and_reimport(client, tmp_path, monkeypatch, capture_library):
    def saved(capture):
        start_analysis(capture, analyses.get_manager(), capture_library)

    mgr, src, _ = make_manager(store=capture_library, on_saved=saved)
    monkeypatch.setattr(live_api, "_manager", mgr)
    assert client.post("/api/live/start", json={"interface": "test0", "confirm": True}).json()["capture"]["status"] == "CAPTURING"
    src.emit(scan(60))
    done = client.post("/api/live/stop").json()
    assert done["state"] == "stopped" and done["capture"]["packets"] == 120
    cap = wait_status(client, done["capture"]["id"], "ANALYZED")                      # the saved file was analysed automatically
    assert cap["source_type"] == "LIVE_CAPTURE" and cap["packet_count"] == 120 and cap["interface"] == "Test" and cap["summary"]["findings"] >= 1

    out = tmp_path / "exported.pcap"
    assert client.post(f"/api/captures/{cap['id']}/export", json={"destination": str(out)}).status_code == 200
    back = upload(client, out.read_bytes(), "exported.pcap").json()                    # import what was exported
    wait_job(client, back["id"])
    again = wait_status(client, back["capture_id"], "ANALYZED")
    assert again["packet_count"] == cap["packet_count"] and again["summary"] == cap["summary"]       # the same capture, the same results


def test_no_secret_is_present_in_a_capture_file(client, tmp_path, monkeypatch, capture_library):
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-test-secret-key-123")
    mgr, src, _ = make_manager(store=capture_library)
    monkeypatch.setattr(live_api, "_manager", mgr)
    client.post("/api/live/start", json={"interface": "test0", "confirm": True})
    src.emit(scan(10))
    cap = client.post("/api/live/stop").json()["capture"]
    assert b"AIza-test-secret-key-123" not in capture_library.path_of(capture_library.get(cap["id"])).read_bytes()
