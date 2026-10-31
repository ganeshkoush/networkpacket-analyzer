import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from pcap_factory import T0
from app.api import analyses
from app.config import settings
from app.main import app
from app.services.analysis_jobs import AnalysisJobManager

C = "192.168.1.10"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10))
    with TestClient(app) as c:
        yield c


def site(name, ip, n, t, rtt_ms=40, dns_ms=20):
    """DNS lookup + a TCP connection with a timed handshake and five RTT samples."""
    pk = [pf.dns_query(C, "8.8.8.8", name, txid=n, sport=30000 + n, ts=t),
          pf.dns_response(C, "8.8.8.8", name, txid=n, dport=30000 + n, answers=[ip], ts=t + dns_ms / 1000)]
    sp = 40000 + n
    pk += [pf.tcp(C, ip, sp, 443, "S", seq=100, ts=t + 1), pf.tcp(ip, C, 443, sp, "SA", seq=500, ack=101, ts=t + 1.02),
           pf.tcp(C, ip, sp, 443, "A", seq=101, ack=501, ts=t + 1.03)]
    for i in range(5):
        pk += [pf.tcp(ip, C, 443, sp, "PA", seq=501 + i * 10, ack=101, payload=b"d" * 10, ts=t + 2 + i),
               pf.tcp(C, ip, sp, 443, "A", seq=101, ack=511 + i * 10, ts=t + 2 + i + rtt_ms / 1000)]
    return pk


def submit(client, tmp_path, packets):
    data = pf.write_pcap(tmp_path / "w.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "w.pcap"}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    return job_id


def web(client, job, path="", **params):
    res = client.get(f"/api/analyses/{job}/web-activity{path}", params=params)
    assert res.status_code == 200, res.text
    return res.json()


@pytest.fixture
def job(client, tmp_path):
    pk = site("fast.example.com", "140.82.112.3", 1, T0, rtt_ms=30) + site("slow.example.com", "142.250.80.46", 2, T0 + 50, rtt_ms=450, dns_ms=30)
    return submit(client, tmp_path, pk)


def test_table_endpoint(client, job):
    body = web(client, job)
    assert body["total_matching"] == 2 and body["limit"] == 50 and body["offset"] == 0
    rows = {r["domain"]: r for r in body["domains"]}
    fast = rows["fast.example.com"]
    assert fast["connections"] == 1 and fast["total_bytes"] > 0
    assert fast["dns_latency_ms"] == pytest.approx(20, abs=0.01) and fast["tcp_handshake_ms"] == pytest.approx(30, abs=0.01)
    assert fast["avg_rtt_ms"] == pytest.approx(30, abs=0.01) and fast["health"] == "good"
    slow = rows["slow.example.com"]
    assert slow["health"] == "poor" and any("Average RTT" in r for r in slow["health_reasons"])
    assert body["summary"]["health_counts"] == {"good": 1, "poor": 1}
    assert any("not a verdict" in n for n in body["summary"]["notes"])


def test_table_sorting_filtering_and_paging(client, job):
    assert [r["domain"] for r in web(client, job, sort="rtt")["domains"]] == ["slow.example.com", "fast.example.com"]
    assert [r["domain"] for r in web(client, job, sort="name")["domains"]] == ["fast.example.com", "slow.example.com"]
    assert [r["domain"] for r in web(client, job, health="poor")["domains"]] == ["slow.example.com"]
    assert [r["domain"] for r in web(client, job, search="FAST")["domains"]] == ["fast.example.com"]
    page = web(client, job, sort="name", limit=1, offset=1)
    assert page["total_matching"] == 2 and [r["domain"] for r in page["domains"]] == ["slow.example.com"]
    for bad in ({"sort": "bogus"}, {"health": "bogus"}, {"limit": 0}, {"limit": 501}, {"offset": -1}):
        assert client.get(f"/api/analyses/{job}/web-activity", params=bad).status_code == 422


def test_detail_endpoint(client, job):
    d = web(client, job, "/slow.example.com")
    assert d["domain"] == "slow.example.com" and d["health"] == "poor"
    assert d["overview"]["connection_count"] == 1 and d["overview"]["packets_sent"] > 0 and d["overview"]["packets_received"] > 0
    assert d["performance"]["max_rtt_ms"] == pytest.approx(450, abs=0.01) and d["performance"]["retransmissions"] == 0
    assert len(d["connections"]) == 1 and d["connections"][0]["avg_rtt_ms"] == pytest.approx(450, abs=0.01)
    assert len(d["series"]["rtt"]) == 1 and len(d["series"]["handshake"]) == 1 and d["series"]["traffic"]
    assert web(client, job, "/SLOW.example.com.")["domain"] == "slow.example.com"
    assert client.get(f"/api/analyses/{job}/web-activity/unknown.example").json()["detail"]["code"] == "not_found"
    assert client.get("/api/analyses/nope/web-activity").status_code == 404


def test_series_are_not_in_the_main_result_bundle(client, job):
    bundle = client.get(f"/api/analyses/{job}/result").json()
    assert "series" not in bundle["analysis"]["performance_statistics"]
    assert bundle["analysis"]["performance_statistics"]["domains"]  # per-domain latency summary still is


def test_large_capture_is_paged_and_the_bundle_stays_small(client, tmp_path):
    pk = []
    for i in range(1, 121):
        pk += site(f"site{i:03d}.example.com", f"198.51.{i // 200 + 100}.{i}", i, T0 + i * 20, rtt_ms=20 + i)
    job_id = submit(client, tmp_path, pk)
    first = web(client, job_id, sort="name", limit=50)
    assert first["total_matching"] == 120 and len(first["domains"]) == 50 and first["summary"]["total_domains"] == 120
    last = web(client, job_id, sort="name", limit=50, offset=100)
    assert len(last["domains"]) == 20 and last["domains"][-1]["domain"] == "site120.example.com"
    seen = {r["domain"] for off in (0, 50, 100) for r in web(client, job_id, sort="name", limit=50, offset=off)["domains"]}
    assert len(seen) == 120
    assert [r["domain"] for r in web(client, job_id, sort="rtt", limit=2)["domains"]] == ["site120.example.com", "site119.example.com"]
    assert len(client.get(f"/api/analyses/{job_id}/result").content) < 5_000_000


def test_empty_capture(client, tmp_path):
    data = pf.write_pcap(tmp_path / "e.pcap", []).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "e.pcap"}).json()["id"]
    for _ in range(200):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    body = web(client, job_id)
    assert body["total_matching"] == 0 and body["domains"] == [] and body["summary"]["total_domains"] == 0
