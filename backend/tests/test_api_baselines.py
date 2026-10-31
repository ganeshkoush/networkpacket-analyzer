import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from pcap_factory import T0
from app.api import analyses
from app.config import settings
from app.main import app
from app.services.analysis_jobs import AnalysisJobManager

C, IP = "192.168.1.10", "140.82.112.3"
JITTER = [-3, 2, -1, 0, 1, -2, 3, 0, -1, 2, 1, -2, 0, 3, -3, 1]


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=30, history=history))
    with TestClient(app) as c:
        yield c


def capture(i, handshake_ms=45.0, rtt_ms=38.0, domain="github.com"):
    """One capture of ~1 minute at T0 + i hours: 2 timed DNS lookups and 3 HTTPS-port connections with 5 RTT samples each."""
    t0, pk = T0 + i * 3600, []
    for n in range(2):
        pk += [pf.dns_query(C, "8.8.8.8", domain, txid=n + 1, sport=30000 + n, ts=t0 + n),
               pf.dns_response(C, "8.8.8.8", domain, txid=n + 1, dport=30000 + n, answers=[IP], ts=t0 + n + 0.02)]
    for n in range(3):
        sp, t = 40000 + n, t0 + 5 + n * 10
        hs = handshake_ms / 1000
        pk += [pf.tcp(C, IP, sp, 443, "S", seq=100, ts=t), pf.tcp(IP, C, 443, sp, "SA", seq=500, ack=101, ts=t + hs * 0.6),
               pf.tcp(C, IP, sp, 443, "A", seq=101, ack=501, ts=t + hs)]
        for k in range(5):
            pk += [pf.tcp(IP, C, 443, sp, "PA", seq=501 + k * 10, ack=101, payload=b"d" * 10, ts=t + 1 + k),
                   pf.tcp(C, IP, sp, 443, "A", seq=101, ack=511 + k * 10, ts=t + 1 + k + rtt_ms / 1000)]
    return sorted(pk, key=lambda p: p.time)


def analyze(client, tmp_path, packets, name="c.pcap"):
    data = pf.write_pcap(tmp_path / name, packets).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": name}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            return job_id
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def learn(client, tmp_path, n):
    return [analyze(client, tmp_path, capture(i, 45 + JITTER[i % 16], 38 + JITTER[i % 16]), f"c{i}.pcap") for i in range(n)]


def get(client, path, **params):
    res = client.get(path, params=params)
    assert res.status_code == 200, res.text
    return res.json()


def test_the_first_captures_only_learn(client, tmp_path):
    jobs = learn(client, tmp_path, 3)
    out = get(client, f"/api/analyses/{jobs[-1]}/anomalies")
    assert out["history_enabled"] and out["anomalies"] == [] and out["domains_with_baseline"] == 0
    assert any("several earlier observations" in n for n in out["notes"])
    view = get(client, f"/api/analyses/{jobs[-1]}/web-activity/github.com/baseline")
    assert view["prior_observations"] == 2 and len(view["history"]) == 3
    assert all(c["status"] in ("insufficient_baseline", "no_data") for c in view["comparisons"])
    assert get(client, "/api/baselines")["observations"] == 3


def test_a_slow_capture_after_a_normal_history_is_reported(client, tmp_path):
    learn(client, tmp_path, 10)
    slow = analyze(client, tmp_path, capture(10, handshake_ms=131.0, rtt_ms=102.0), "slow.pcap")
    out = get(client, f"/api/analyses/{slow}/anomalies")
    by = {a["metric"]: a for a in out["anomalies"]}
    assert {"tcp_handshake_ms", "avg_rtt_ms"} <= set(by) and out["domains_with_baseline"] == 1
    hs = by["tcp_handshake_ms"]
    assert hs["domain"] == "github.com" and hs["baseline"] == pytest.approx(45, abs=1) and hs["current_value"] == pytest.approx(131, abs=0.1)
    assert hs["deviation"] == pytest.approx(1.9, abs=0.1) and hs["severity"] in ("LOW", "MEDIUM", "HIGH")
    assert hs["confidence_label"] in ("Low", "Medium", "High") and 0.3 <= hs["confidence"] <= 0.95
    assert hs["first_seen"] == hs["last_seen"] and hs["evidence"] and hs["caveats"]

    view = get(client, f"/api/analyses/{slow}/web-activity/github.com/baseline")
    assert len(view["history"]) == 11 and view["history"][-1]["current"] and view["prior_observations"] == 10
    comp = next(c for c in view["comparisons"] if c["metric"] == "tcp_handshake_ms")
    assert comp["status"] == "anomalous" and comp["baseline"]["median"] == pytest.approx(45, abs=1)
    assert {a["metric"] for a in view["anomalies"]} == set(by)

    row = get(client, f"/api/analyses/{slow}/web-activity")["domains"][0]
    assert row["domain"] == "github.com" and row["anomalies"] == len(by)


def test_a_normal_capture_after_the_history_is_quiet(client, tmp_path):
    learn(client, tmp_path, 10)
    ok = analyze(client, tmp_path, capture(10, handshake_ms=47.0, rtt_ms=40.0), "ok.pcap")
    out = get(client, f"/api/analyses/{ok}/anomalies")
    assert out["anomalies"] == [] and out["domains_with_baseline"] == 1
    assert get(client, f"/api/analyses/{ok}/web-activity")["domains"][0]["anomalies"] == 0


def test_analysing_the_same_file_again_does_not_double_count(client, tmp_path):
    learn(client, tmp_path, 3)
    again = analyze(client, tmp_path, capture(2, 45 + JITTER[2], 38 + JITTER[2]), "c2.pcap")  # byte-identical to capture 2
    assert get(client, "/api/baselines")["observations"] == 3
    assert get(client, f"/api/analyses/{again}/web-activity/github.com/baseline")["prior_observations"] == 2


def test_unknown_domain_and_analysis(client, tmp_path):
    job = learn(client, tmp_path, 1)[0]
    assert client.get(f"/api/analyses/{job}/web-activity/nothing.example/baseline").json()["detail"]["code"] == "not_found"
    assert client.get("/api/analyses/nope/anomalies").status_code == 404


def test_clearing_history_needs_confirmation_and_removes_everything(client, tmp_path):
    jobs = learn(client, tmp_path, 4)
    r = client.delete("/api/baselines")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "confirmation_required"
    assert get(client, "/api/baselines")["observations"] == 4
    assert client.delete("/api/baselines", params={"confirm": "true"}).json() == {"deleted_observations": 4}
    assert get(client, "/api/baselines")["observations"] == 0
    assert get(client, f"/api/analyses/{jobs[-1]}/anomalies")["anomalies"] == []


def test_history_can_be_turned_off(client, tmp_path, history):
    history.enabled = False
    job = analyze(client, tmp_path, capture(0), "off.pcap")
    out = get(client, f"/api/analyses/{job}/anomalies")
    assert out["history_enabled"] is False and "turned off" in out["notes"][0]
    assert get(client, "/api/baselines") ["enabled"] is False
    assert get(client, f"/api/analyses/{job}/web-activity/github.com/baseline")["history_enabled"] is False
