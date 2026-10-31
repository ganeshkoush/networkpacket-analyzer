import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from pcap_factory import T0
from app.api import analyses
from app.config import settings
from app.main import app
from app.models.process import ProcessConnectionMapping, ProcessSnapshot
from app.platform.base import ProcessConnectionSource, ProcessSourceError, UnsupportedProcessSource
from app.services import process_mapper as pm
from app.services.analysis_jobs import AnalysisJobManager

C, GH = "192.168.1.10", "140.82.112.3"


class FakeSource(ProcessConnectionSource):
    platform, mechanism, permission_note = "macOS", "lsof + ps (read-only)", "No administrator rights needed; only your own processes are visible."

    def __init__(self, mappings=(), fail=None):
        self.mappings, self.fail, self.calls = list(mappings), fail, 0

    def snapshot(self, now):
        self.calls += 1
        if self.fail:
            raise self.fail
        return ProcessSnapshot(timestamp=now, platform="macOS", mappings=[m.model_copy(update={"timestamp": now}) for m in self.mappings],
                               processes=len({m.pid for m in self.mappings}))


def m(name, pid, sport, app=None, remote=GH, rport=443):
    return ProcessConnectionMapping(process_name=name, pid=pid, application=app, local_ip=C, local_port=sport, remote_ip=remote, remote_port=rport,
                                    protocol="TCP", timestamp=0, confidence="HIGH")


@pytest.fixture
def use_source(monkeypatch):
    def _use(source, clock=lambda: T0 + 3):
        mapper = pm.ProcessMapper(source, clock=clock)
        monkeypatch.setattr(pm, "_mapper", mapper)
        return mapper
    return _use


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------------ explicit, read-only process API
def test_status_describes_support_and_permissions_without_touching_the_os(client, use_source):
    src = FakeSource()
    use_source(src)
    body = client.get("/api/processes").json()
    assert body["supported"] and body["platform"] == "macOS" and body["mechanism"].startswith("lsof")
    assert "administrator rights" in body["permission_note"] and body["snapshots"] == 0 and body["watching"] is False
    assert src.calls == 0


def test_snapshots_need_explicit_confirmation(client, use_source):
    src = FakeSource([m("Code Helper", 1, 50000, "Visual Studio Code")])
    use_source(src)
    r = client.post("/api/processes/snapshot")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "confirmation_required" and src.calls == 0
    ok = client.post("/api/processes/snapshot", params={"confirm": "true"}).json()
    assert ok["sockets"] == 1 and ok["processes"] == 1 and ok["applications"] == 1 and ok["platform"] == "macOS" and src.calls == 1
    assert client.get("/api/processes").json()["snapshots"] == 1


def test_os_errors_and_unsupported_platforms_are_reported_honestly(client, use_source):
    use_source(FakeSource(fail=ProcessSourceError("lsof did not answer within 15 seconds.")))
    r = client.post("/api/processes/snapshot", params={"confirm": "true"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "process_source_unavailable" and "did not answer" in r.json()["detail"]["message"]
    use_source(UnsupportedProcessSource("Windows"))
    r = client.post("/api/processes/snapshot", params={"confirm": "true"})
    assert r.status_code == 501 and r.json()["detail"]["code"] == "unsupported_platform"
    status = client.get("/api/processes").json()
    assert status["supported"] is False and "not implemented for Windows" in status["permission_note"]
    assert client.post("/api/processes/watch", json={"confirm": True}).status_code == 501


def test_watching_is_explicit_bounded_and_stoppable(client, use_source, monkeypatch):
    monkeypatch.setattr(pm, "MIN_INTERVAL_SECONDS", 0.01)
    src = FakeSource([m("x", 1, 1)])
    use_source(src)
    assert client.post("/api/processes/watch", json={}).status_code == 400 and src.calls == 0
    assert client.post("/api/processes/watch", json={"confirm": True, "interval_seconds": 1}).status_code == 422   # faster than allowed
    started = client.post("/api/processes/watch", json={"confirm": True, "interval_seconds": 2}).json()
    assert started["watching"] is True and started["watch_interval_seconds"] == 2.0
    stopped = client.delete("/api/processes/watch").json()
    assert stopped["watching"] is False


def test_clearing_snapshots_needs_confirmation(client, use_source):
    use_source(FakeSource([m("x", 1, 1)]))
    client.post("/api/processes/snapshot", params={"confirm": "true"})
    assert client.delete("/api/processes").status_code == 400 and client.get("/api/processes").json()["snapshots"] == 1
    assert client.delete("/api/processes", params={"confirm": "true"}).json() == {"deleted_snapshots": 1}
    assert client.get("/api/processes").json()["snapshots"] == 0


# ------------------------------------------------------------------ the domain dashboard
def github_capture():
    """DNS lookup of github.com, then 5 connections to it from source ports 50000-50004 (each with a request and a response)."""
    pk = [pf.dns_query(C, "8.8.8.8", "github.com", ts=T0), pf.dns_response(C, "8.8.8.8", "github.com", answers=[GH], ts=T0 + 0.02)]
    for i in range(5):
        sp, t = 50000 + i, T0 + 1 + i * 0.1
        pk += [pf.tcp(C, GH, sp, 443, "S", seq=100, ts=t), pf.tcp(GH, C, 443, sp, "SA", seq=500, ack=101, ts=t + 0.02),
               pf.tcp(C, GH, sp, 443, "A", seq=101, ack=501, ts=t + 0.03),
               pf.tcp(C, GH, sp, 443, "PA", seq=101, ack=501, payload=b"x" * 50, ts=t + 4),
               pf.tcp(GH, C, 443, sp, "PA", seq=501, ack=151, payload=b"y" * 50, ts=t + 4.1)]
    return sorted(pk, key=lambda p: p.time)


def analyze(client, tmp_path, packets):
    data = pf.write_pcap(tmp_path / "g.pcap", packets).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "g.pcap"}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            return job_id
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def apps(client, job, domain="github.com"):
    return client.get(f"/api/analyses/{job}/web-activity/{domain}/applications")


def test_applications_of_a_domain_from_mocked_process_information(client, tmp_path, use_source):
    job = analyze(client, tmp_path, github_capture())
    mapper = use_source(FakeSource([m("Code Helper", 1020, 50000 + i, "Visual Studio Code") for i in range(3)]
                                    + [m("Google Chrome Helper", 1045, 50003 + i, "Google Chrome") for i in range(2)]), clock=lambda: T0 + 3)
    mapper.snapshot()
    body = apps(client, job).json()
    assert body["status"] == "available" and body["connections_considered"] == 5 and body["connections_matched"] == 5
    assert [(a["name"], a["connections"]) for a in body["applications"]] == [("Visual Studio Code", 3), ("Google Chrome", 2)]
    assert body["applications"][0]["confidence_counts"] == {"HIGH": 3} and "not from the captured packets" in body["source_note"]
    assert "administrator rights" in body["permission_note"]


def test_without_snapshots_the_domain_says_process_information_is_unavailable(client, tmp_path, use_source):
    job = analyze(client, tmp_path, github_capture())
    use_source(FakeSource([m("Code Helper", 1020, 50000, "Visual Studio Code")]))
    body = apps(client, job).json()
    assert body["status"] == "no_snapshots" and body["applications"] == [] and body["message"].startswith("Process information unavailable")


def test_a_snapshot_taken_long_after_the_capture_is_not_used(client, tmp_path, use_source):
    job = analyze(client, tmp_path, github_capture())
    mapper = use_source(FakeSource([m("Code Helper", 1020, 50000 + i, "Visual Studio Code") for i in range(5)]), clock=lambda: T0 + 3600)
    mapper.snapshot()
    body = apps(client, job).json()
    assert body["status"] == "no_overlap" and body["applications"] == [] and body["message"].startswith("Process information unavailable")


def test_unmatched_sockets_never_produce_an_application_name(client, tmp_path, use_source):
    job = analyze(client, tmp_path, github_capture())
    mapper = use_source(FakeSource([m("Chrome", 5, 40000), m("Chrome", 5, 50001, remote="1.1.1.1")]), clock=lambda: T0 + 3)
    mapper.snapshot()
    body = apps(client, job).json()
    assert body["status"] == "no_matches" and body["applications"] == [] and body["connections_unmatched"] == 5


def test_unknown_domain_and_analysis(client, tmp_path):
    job = analyze(client, tmp_path, github_capture())
    assert apps(client, job, "nope.example").json()["detail"]["code"] == "not_found"
    assert client.get("/api/analyses/nope/web-activity/github.com/applications").status_code == 404


def test_process_information_never_leaks_into_the_analysis_result(client, tmp_path, use_source):
    job = analyze(client, tmp_path, github_capture())
    mapper = use_source(FakeSource([m("Code Helper", 1020, 50000 + i, "Visual Studio Code") for i in range(5)]), clock=lambda: T0 + 3)
    mapper.snapshot()
    assert b"Visual Studio Code" not in client.get(f"/api/analyses/{job}/result").content
    assert b"Visual Studio Code" not in client.get(f"/api/analyses/{job}/web-activity/github.com").content   # packet-derived views stay packet-derived
