import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from app.api import analyses
from app.config import settings
from app.main import app
from app.services.analysis_jobs import AnalysisJobManager
from correlation import scenarios as sc


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(app) as c:
        yield c


def analyze(client, tmp_path, packets, name="c.pcap"):
    data = pf.write_pcap(tmp_path / name, sorted(packets, key=lambda p: p.time)).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": name}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            return job_id
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def findings(client, job):
    return client.get(f"/api/analyses/{job}/result").json()["findings"]


def test_lists_correlations_for_a_capture(client, tmp_path):
    job = analyze(client, tmp_path, sc.syn_flood_scenario())
    body = client.get(f"/api/analyses/{job}/correlations").json()
    (c,) = body["correlations"]
    assert c["relationship"] == "Potentially related" and c["type"] == "SYN_FLOOD_HANDSHAKE_LATENCY"
    assert c["headline"] == "TCP handshake latency increased 4.5x (40 ms → 180 ms)"
    assert c["performance"]["basis"] == "capture" and c["performance"]["metric"] == "tcp_handshake_ms"
    assert c["temporal_relation"] == "overlapping" and c["shared_ips"] == [sc.SERVER] and c["evidence"] and c["caveats"]
    assert 0.25 <= c["confidence"] <= 0.85 and c["confidence_label"] in ("Medium", "High")
    assert any("not proof of causation" in n for n in body["notes"]) and body["flow_data_thinned"] is False
    # the heavy sample data never leaves the backend
    assert b"flow_samples" not in client.get(f"/api/analyses/{job}/result").content


def test_correlations_for_one_finding(client, tmp_path):
    job = analyze(client, tmp_path, sc.syn_flood_scenario())
    flood = next(f for f in findings(client, job) if f["type"] == "SYN_FLOOD")
    body = client.get(f"/api/analyses/{job}/correlations", params={"finding_id": flood["id"]}).json()
    assert body["finding_id"] == flood["id"] and [c["finding_id"] for c in body["correlations"]] == [flood["id"]]
    assert client.get(f"/api/analyses/{job}/correlations", params={"finding_id": "nope"}).json()["detail"]["code"] == "not_found"


def test_a_finding_with_no_related_change_says_what_was_checked(client, tmp_path):
    job = analyze(client, tmp_path, sc.syn_flood_scenario(with_slowdown=False))
    body = client.get(f"/api/analyses/{job}/correlations").json()
    assert body["correlations"] == [] and any("no significant change" in n for n in body["no_related_change"])


def test_a_capture_without_findings(client, tmp_path):
    job = analyze(client, tmp_path, pf.tcp_session())
    body = client.get(f"/api/analyses/{job}/correlations").json()
    assert body["correlations"] == [] and body["not_evaluated"] == [] and body["no_related_change"] == []


def test_unknown_analysis(client):
    assert client.get("/api/analyses/nope/correlations").status_code == 404
