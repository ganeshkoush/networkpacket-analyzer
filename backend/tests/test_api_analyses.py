import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from app.api import analyses
from app.config import settings
from app.main import app
from app.services.analysis_jobs import AnalysisJobManager


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10))
    with TestClient(app) as c:
        yield c


def leftovers():
    return list(settings.uploads_dir.iterdir()) if settings.uploads_dir.exists() else []


def upload(client, data: bytes, name="cap.pcap"):
    return client.post("/api/analyses", content=data, headers={
        "Content-Type": "application/octet-stream", "X-Filename": name})


def wait(client, job_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/analyses/{job_id}").json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def pcap_bytes(tmp_path, packets):
    return pf.write_pcap(tmp_path / "x.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()


def test_health_reports_upload_limit(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["max_upload_bytes"] == settings.max_upload_bytes


def test_end_to_end_upload_analyze_fetch(client, tmp_path):
    res = upload(client, pcap_bytes(tmp_path, pf.build_attack_demo()), "attack demo.pcap")
    assert res.status_code == 202
    job = res.json()
    assert job["filename"] == "attack demo.pcap" and job["status"] in ("queued", "running", "completed")
    assert wait(client, job["id"])["status"] == "completed"

    bundle = client.get(f"/api/analyses/{job['id']}/result").json()
    meta = bundle["analysis"]["metadata"]
    assert meta["file_name"] == "attack demo.pcap" and meta["file_path"] == "attack demo.pcap"  # no temp path leaked
    assert bundle["analysis"]["packet_statistics"]["total_packets"] > 1000
    types = {f["type"] for f in bundle["findings"]}
    assert {"PORT_SCAN", "SYN_FLOOD", "ARP_SPOOFING"} <= types
    f = bundle["findings"][0]
    for key in ("severity", "confidence", "source_ip", "destination_ip", "description", "evidence",
                "reasoning", "recommendation"):
        assert key in f
    assert bundle["job"]["progress_percent"] == 100.0
    assert leftovers() == []  # upload deleted after analysis


def test_filename_is_sanitised(client, tmp_path):
    job = upload(client, pcap_bytes(tmp_path, [pf.arp()]), "..%2F..%2Fetc%2Fpasswd.pcap").json()
    assert "/" not in job["filename"] and job["filename"] == "passwd.pcap"


def test_invalid_file_rejected_with_400_and_cleaned_up(client):
    res = upload(client, b"this is not a pcap file at all", "notes.pcap")
    assert res.status_code == 400
    assert res.json()["detail"]["code"] == "invalid_capture"
    assert leftovers() == []


def test_empty_upload_rejected(client):
    res = upload(client, b"")
    assert res.status_code == 400 and res.json()["detail"]["code"] == "empty_file"


def test_too_large_rejected(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    res = upload(client, pcap_bytes(tmp_path, pf.tcp_session()))
    assert res.status_code == 413 and res.json()["detail"]["code"] == "file_too_large"
    assert leftovers() == []


def test_too_large_without_content_length_is_caught_while_streaming(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 200)
    data = pcap_bytes(tmp_path, pf.tcp_session())
    res = client.post("/api/analyses", content=iter([data[:100], data[100:]]), headers={"X-Filename": "a.pcap"})
    assert res.status_code == 413
    assert leftovers() == []


def test_empty_capture_analyzes_successfully(client, tmp_path):
    job = upload(client, pcap_bytes(tmp_path, [])).json()
    assert wait(client, job["id"])["status"] == "completed"
    bundle = client.get(f"/api/analyses/{job['id']}/result").json()
    assert bundle["analysis"]["packet_statistics"]["total_packets"] == 0
    assert bundle["findings"] == []
    assert any("no packets" in w for w in bundle["analysis"]["metadata"]["warnings"])


def test_truncated_capture_reports_warning_not_failure(client, tmp_path):
    data = pcap_bytes(tmp_path, pf.tcp_session())
    job = upload(client, data[: len(data) - 40]).json()
    assert wait(client, job["id"])["status"] == "completed"


def test_unknown_job_is_404(client):
    for path in ("/api/analyses/nope", "/api/analyses/nope/result"):
        res = client.get(path)
        assert res.status_code == 404 and res.json()["detail"]["code"] == "not_found"


def test_failed_job_reports_error(client, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("internal secret detail")
    monkeypatch.setattr("app.services.analysis_jobs.analyze_pcap", boom)
    job = upload(client, pcap_bytes(tmp_path, [pf.arp()])).json()
    status = wait(client, job["id"])
    assert status["status"] == "failed" and status["error"]["code"] == "analysis_failed"
    assert "secret" not in status["error"]["message"]  # internals are not leaked
    assert client.get(f"/api/analyses/{job['id']}/result").status_code == 409


def test_result_before_completion_is_409(client, tmp_path, monkeypatch):
    import threading
    gate = threading.Event()
    real = analyses.get_manager().__class__._run

    def slow(self, job, path):
        gate.wait(5)
        return real(self, job, path)

    monkeypatch.setattr(AnalysisJobManager, "_run", slow)
    job = upload(client, pcap_bytes(tmp_path, [pf.arp()])).json()
    res = client.get(f"/api/analyses/{job['id']}/result")
    assert res.status_code == 409 and res.json()["detail"]["code"] == "not_ready"
    gate.set()
    assert wait(client, job["id"])["status"] == "completed"


def test_progress_callback_invoked(tmp_path):
    from app.analysis import analyze_pcap
    path = pf.write_pcap(tmp_path / "p.pcap", sorted(pf.build_attack_demo(), key=lambda p: p.time))
    calls = []
    analyze_pcap(path, on_progress=lambda n, b: calls.append((n, b)))
    assert len(calls) >= 2 and calls[-1][0] > 1000
    assert calls == sorted(calls) and 0 < calls[-1][1] <= path.stat().st_size


def test_progress_callback_errors_do_not_break_analysis(tmp_path):
    from app.analysis import analyze_pcap
    path = pf.write_pcap(tmp_path / "p.pcap", [pf.arp()])
    def bad(n, b):
        raise ValueError("x")
    assert analyze_pcap(path, on_progress=bad).packet_statistics.total_packets == 1


def test_cors_preflight_allows_desktop_origin_only(client):
    ok = client.options("/api/analyses", headers={
        "Origin": "tauri://localhost", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-filename,content-type"})
    assert ok.status_code == 200 and ok.headers["access-control-allow-origin"] == "tauri://localhost"
    bad = client.options("/api/analyses", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


def _domain_job(client, tmp_path):
    c, s = "192.168.1.10", "8.8.8.8"
    pk = []
    for i, (name, ip, up, down) in enumerate([("github.com", "140.82.112.3", 100, 5000), ("example.org", "93.184.216.34", 9000, 100)]):
        t = pf.T0 + i
        pk += [pf.dns_query(c, s, name, txid=i + 1, ts=t), pf.dns_response(c, s, name, txid=i + 1, answers=[ip], ts=t + 0.01),
               pf.tcp(c, ip, 50000 + i, 443, "PA", payload=b"u" * up, ts=t + 0.5), pf.tcp(ip, c, 443, 50000 + i, "PA", payload=b"d" * down, ts=t + 0.6)]
    job = upload(client, pcap_bytes(tmp_path, pk)).json()
    assert wait(client, job["id"])["status"] == "completed"
    return job["id"]


def test_domain_endpoints_search_sort_and_detail(client, tmp_path):
    jid = _domain_job(client, tmp_path)
    body = client.get(f"/api/analyses/{jid}/domains").json()
    assert [d["domain"] for d in body["domains"]] == ["example.org", "github.com"]  # default sort: traffic
    assert body["summary"]["attributed_connections"] == 2 and body["total_matching"] == 2
    by_traffic = client.get(f"/api/analyses/{jid}/domains?sort=traffic").json()["domains"]
    assert by_traffic[0]["domain"] == "example.org"  # 9,000 B sent beats 5,000 B received
    recent = client.get(f"/api/analyses/{jid}/domains?sort=recent").json()["domains"]
    assert recent[0]["domain"] == "example.org"
    found = client.get(f"/api/analyses/{jid}/domains?search=GITHUB").json()
    assert found["total_matching"] == 1 and found["domains"][0]["domain"] == "github.com"
    assert client.get(f"/api/analyses/{jid}/domains?limit=1").json()["domains"].__len__() == 1
    one = client.get(f"/api/analyses/{jid}/domains/GitHub.com.").json()
    assert one["resolved_ips"] == ["140.82.112.3"] and one["connection_count"] == 1


def test_domain_endpoints_errors(client, tmp_path):
    jid = _domain_job(client, tmp_path)
    assert client.get(f"/api/analyses/{jid}/domains/nope.example").status_code == 404
    assert client.get(f"/api/analyses/{jid}/domains?sort=bogus").status_code == 422
    assert client.get("/api/analyses/unknown/domains").status_code == 404
