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


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def job(client, tmp_path):
    packets = [
        pf.dns_query(C, "8.8.8.8", "google.com", ts=T0), pf.dns_response(C, "8.8.8.8", "google.com", answers=[S], ts=T0 + 0.02),
        pf.tcp(C, S, 52341, 443, "S", seq=100, ts=T0 + 1), pf.tcp(S, C, 443, 52341, "SA", seq=500, ack=101, ts=T0 + 1.01),
        pf.tcp(C, S, 52341, 443, "A", seq=101, ack=501, ts=T0 + 1.02),
        pf.tcp(C, S, 52341, 443, "PA", seq=101, ack=501, payload=b"x" * 300, ts=T0 + 1.1),
        pf.tcp(C, S2, 52342, 80, "S", ts=T0 + 2),  # no DNS, never answered
        pf.udp(C, "8.8.4.4", 41000, 5000, b"q", ts=T0 + 3),
    ]
    data = pf.write_pcap(tmp_path / "x.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    res = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "c.pcap"})
    job_id = res.json()["id"]
    for _ in range(400):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    return job_id


def listing(client, job, **params):
    res = client.get(f"/api/analyses/{job}/connections", params=params)
    assert res.status_code == 200, res.text
    return res.json()


def test_lists_all_connections_with_summary(client, job):
    body = listing(client, job)
    assert body["total_matching"] == len(body["connections"]) == 4  # DNS flow, HTTPS, no-DNS HTTP, UDP
    assert body["summary"]["by_state"] == {"ESTABLISHED": 1, "SYN_SENT": 1}
    c = next(c for c in body["connections"] if c["server_port"] == 443)
    assert c["domain"] == "google.com" and c["state"] == "ESTABLISHED" and len(c["id"]) == 12


def test_connection_without_dns_is_listed_with_null_domain(client, job):
    c = next(c for c in listing(client, job)["connections"] if c["server_port"] == 80)
    assert c["domain"] is None and c["server_ip"] == S2 and c["state"] == "SYN_SENT"


@pytest.mark.parametrize("params,ports", [
    ({"domain": "GOOGLE"}, {443}),
    ({"src_ip": C, "protocol": "udp"}, {53, 5000}),
    ({"dst_ip": S2}, {80}),
    ({"port": 80}, {80}),
    ({"port": 52341}, {443}),
    ({"state": "established"}, {443}),
    ({"protocol": "TCP", "domain": "nope"}, set()),
])
def test_filters(client, job, params, ports):
    body = listing(client, job, **params)
    assert {c["server_port"] for c in body["connections"]} == ports
    assert body["total_matching"] == len(body["connections"])


def test_limit_and_total_matching(client, job):
    body = listing(client, job, limit=1)
    assert len(body["connections"]) == 1 and body["total_matching"] == 4


def test_invalid_filters_are_rejected(client, job):
    assert client.get(f"/api/analyses/{job}/connections", params={"src_ip": "999.1.1.1"}).json()["detail"]["code"] == "invalid_ip"
    assert client.get(f"/api/analyses/{job}/connections", params={"state": "BOGUS"}).status_code == 422
    assert client.get(f"/api/analyses/{job}/connections", params={"port": 70000}).status_code == 422


def test_detail_by_id_and_unknown_ids(client, job):
    first = listing(client, job)["connections"][0]
    detail = client.get(f"/api/analyses/{job}/connections/{first['id']}")
    assert detail.status_code == 200 and detail.json() == first
    assert client.get(f"/api/analyses/{job}/connections/doesnotexist").status_code == 404
    assert client.get("/api/analyses/unknown/connections").status_code == 404


def test_handshake_fields_are_exposed_by_the_api(client, job):
    https = next(c for c in listing(client, job)["connections"] if c["server_port"] == 443)
    assert https["handshake_status"] == "completed" and https["handshake_incomplete_reason"] is None
    assert https["tcp_syn_ack_latency_ms"] == pytest.approx(10, abs=0.01)
    assert https["tcp_ack_latency_ms"] == pytest.approx(10, abs=0.01)
    assert https["tcp_handshake_time_ms"] == pytest.approx(20, abs=0.01)
    assert https["tcp_syn_timestamp"] == pytest.approx(T0 + 1)
    unanswered = next(c for c in listing(client, job)["connections"] if c["server_port"] == 80)
    assert unanswered["handshake_status"] == "incomplete" and unanswered["handshake_incomplete_reason"] == "no_synack"
    assert unanswered["tcp_handshake_time_ms"] is None
    udp = next(c for c in listing(client, job)["connections"] if c["protocol"] == "UDP" and c["server_port"] == 5000)
    assert udp["handshake_status"] is None
    summary = listing(client, job)["summary"]
    assert summary["handshakes_timed"] == 1 and summary["handshakes_incomplete"] == 1
    assert [(d["domain"], d["samples"]) for d in summary["handshake_by_domain"]] == [("google.com", 1)]
    assert summary["handshake_by_domain"][0]["avg_handshake_ms"] == pytest.approx(20, abs=0.01)
