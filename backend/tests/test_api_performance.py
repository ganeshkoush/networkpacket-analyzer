import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from pcap_factory import T0
from app.api import analyses
from app.config import settings
from app.main import app
from app.services.analysis_jobs import AnalysisJobManager

C, S, S2 = "192.168.1.10", "142.250.80.46", "151.101.1.69"
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\n\r\n"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10))
    with TestClient(app) as c:
        yield c


def conn(server, sport, t, rtt_ms, dns_ms=None):
    pk = []
    if dns_ms is not None:
        pk += [pf.dns_query(C, "8.8.8.8", f"h{sport}.example.com", txid=sport, ts=t - 1),
               pf.dns_response(C, "8.8.8.8", f"h{sport}.example.com", txid=sport, answers=[server], ts=t - 1 + dns_ms / 1000)]
    pk += [pf.tcp(C, server, sport, 80, "S", seq=100, ts=t), pf.tcp(server, C, 80, sport, "SA", seq=500, ack=101, ts=t + 0.01),
           pf.tcp(C, server, sport, 80, "A", seq=101, ack=501, ts=t + 0.02)]
    for i in range(5):
        pk += [pf.tcp(server, C, 80, sport, "PA", seq=501 + i * 10, ack=101, payload=b"d" * 10, ts=t + 1 + i),
               pf.tcp(C, server, sport, 80, "A", seq=101, ack=511 + i * 10, ts=t + 1 + i + rtt_ms / 1000)]
    return pk


@pytest.fixture
def job(client, tmp_path):
    packets = conn(S, 50001, T0 + 10, rtt_ms=40, dns_ms=20) + conn(S2, 50002, T0 + 30, rtt_ms=90, dns_ms=35)
    packets += [pf.tcp(C, "198.18.7.7", 50003, 80, "PA", seq=1, payload=REQ, ts=T0 + 50),
                pf.tcp("198.18.7.7", C, 80, 50003, "PA", seq=1, ack=1 + len(REQ), payload=RESP, ts=T0 + 50.07)]
    data = pf.write_pcap(tmp_path / "p.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "p.pcap"}).json()["id"]
    for _ in range(400):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    return job_id


def get(client, job, path, **params):
    res = client.get(f"/api/analyses/{job}/performance{path}", params=params)
    assert res.status_code == 200, res.text
    return res.json()


def test_domain_performance_list(client, job):
    body = get(client, job, "")
    assert body["total_matching"] == 2
    d = {x["domain"]: x for x in body["domains"]}["h50001.example.com"]
    assert d["avg_rtt_ms"] == pytest.approx(40, abs=0.01) and d["dns_latency_ms"] == pytest.approx(20, abs=0.01)
    assert d["tcp_handshake_ms"] == pytest.approx(20, abs=0.01) and d["application_response_ms"] is None
    assert d["rtt_samples"] == 5 and d["p95_rtt_ms"] == pytest.approx(40, abs=0.01) and d["measurement_confidence"] == "MEDIUM"
    assert any("not website or application response time" in n for n in body["summary"]["notes"])


def test_sorting_and_search(client, job):
    assert [d["domain"] for d in get(client, job, "", sort="rtt")["domains"]] == ["h50002.example.com", "h50001.example.com"]
    assert [d["domain"] for d in get(client, job, "", sort="dns")["domains"]][0] == "h50002.example.com"
    assert [d["domain"] for d in get(client, job, "", sort="name")["domains"]][0] == "h50001.example.com"
    assert get(client, job, "", search="50002")["total_matching"] == 1
    assert get(client, job, "", search="nothing")["domains"] == []
    assert client.get(f"/api/analyses/{job}/performance", params={"sort": "bogus"}).status_code == 422


def test_connection_metrics_filters_and_detail(client, job):
    body = get(client, job, "/connections")
    assert body["total_matching"] == len(body["metrics"]) == 4  # 3 TCP connections + 1 DNS flow (both lookups share a port)
    dns = next(m for m in body["metrics"] if m["application_protocol"] == "DNS")
    assert dns["dns_lookups"] == 2 and dns["dns_latency_ms"] == pytest.approx(27.5, abs=0.01)
    http = next(m for m in body["metrics"] if m["application_protocol"] == "HTTP")
    assert http["application_response_ms"] == pytest.approx(70, abs=0.01) and http["domain"] is None
    assert http["tcp_handshake_ms"] is None and http["measurement_confidence"] == "UNAVAILABLE"
    assert get(client, job, "/connections", protocol="udp")["total_matching"] == 1
    assert get(client, job, "/connections", domain="50001")["total_matching"] == 1
    assert get(client, job, "/connections", confidence="MEDIUM")["total_matching"] == 2
    one = get(client, job, f"/connections/{http['connection_id']}")
    assert one == http
    assert client.get(f"/api/analyses/{job}/performance/connections/nope").status_code == 404
    assert client.get(f"/api/analyses/{job}/performance/connections", params={"confidence": "BOGUS"}).status_code == 422
    assert client.get("/api/analyses/unknown/performance").status_code == 404
