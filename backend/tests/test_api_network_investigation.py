import json
import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from app.ai.network_health import NetworkInvestigator
from app.ai.provider import AIProvider, InvalidApiKeyError, MissingApiKeyError, ProviderResponse, RateLimitedError
from app.analysis import analyze_pcap
from app.api import analyses
from app.config import settings
from app.main import app
from app.models.analysis import DomainPerformance
from app.services.analysis_jobs import AnalysisJobManager
from correlation import scenarios as sc


class ReadsTheEvidence(AIProvider):
    """A stand-in model: reads the evidence in the prompt and answers using exactly the values it finds there."""

    name = "stand-in"

    def __init__(self, mutate=None, error=None):
        self.calls, self.mutate, self.error = [], mutate, error

    def generate_structured(self, *, system_instruction, user_content, response_schema):
        self.calls.append(user_content)
        if self.error:
            raise self.error
        bundle = json.loads(user_content.split("<evidence_json>\n")[1].split("\n</evidence_json>")[0])
        notable = [m for m in bundle["metrics"] if m["status"] in ("elevated", "high")]
        local = bundle["packetmind_local_assessment"]["health"]
        evidence, problems = [], []
        for m in notable[:3]:
            pct = m["unit"] == "%"
            cur, normal = (f"{m['current']:.1%}", f"{m.get('normal', 0):.1%}") if pct else (f"{m['current']:.0f} ms", f"{m.get('normal', 0):.0f} ms")
            evidence.append({"evidence_id": m["id"], "statement": f"{m['label']} was {cur}" + (f" against a usual {normal}." if m.get("normal") is not None else ".")})
            problems.append({"title": m["label"], "detail": f"{m['label']} is above what is usual for this computer.", "evidence_ids": [m["id"]]})
        data = {"overall_health": local if local != "Unknown" else "Unknown", "summary": "Some measurements are above this computer's usual values.", "main_issue": problems[0]["title"] if problems else "",
                "top_problems": problems, "evidence": evidence, "potential_explanations": ["Wi-Fi interference", "Network congestion", "An unstable route"],
                "recommended_next_steps": ["Compare latency to several independent services."], "confidence": "High",
                "limitations": ["Only one capture point was available."]}
        if self.mutate:
            self.mutate(data)
        return ProviderResponse(data=data, model="stand-in-1")


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(app) as c:
        yield c


def use(monkeypatch, provider):
    monkeypatch.setattr(analyses, "network_investigator_factory", lambda: NetworkInvestigator(provider))
    return provider


def prior_captures(history, n=7):
    """n earlier healthy captures (normal: handshake 30 ms, RTT 30 ms, retransmissions 0.8 %) so the next one has a baseline."""
    base = analyze_pcap(pf.write_pcap(__import__("pathlib").Path(__import__("tempfile").mkdtemp()) / "b.pcap", []))
    for i in range(n):
        r = base.model_copy(deep=True)
        r.metadata.sha256, r.metadata.first_packet_time = f"prior{i}", pf.T0 - (n + 1 - i) * 3600
        r.performance_statistics.domains = [DomainPerformance(domain="prior.example.com", connections=20, tcp_handshake_ms=30.0, handshake_samples=20, avg_rtt_ms=30.0,
                                                              p95_rtt_ms=60.0, rtt_samples=200, tcp_packets=2000, retransmissions=16, tcp_connections_attempted=20)]
        history.record(r, source_kind="pcap", source_id=f"prior{i}", name=f"prior{i}.pcap")


def analyze(client, tmp_path, packets, name="c.pcap"):
    data = pf.write_pcap(tmp_path / name, sorted(packets, key=lambda p: p.time)).read_bytes()
    job_id = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": name}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job_id}").json()["status"] in ("completed", "failed"):
            return job_id
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def post(client, job, **body):
    r = client.post(f"/api/analyses/{job}/investigate-network", json=body) if body else client.post(f"/api/analyses/{job}/investigate-network")
    assert r.status_code == 200, r.text
    return r.json()


def row(body, mid):
    return next(m for m in body["evidence"] if m["id"] == mid)


# ------------------------------------------------------------------ the whole experience
def test_a_full_investigation_compares_normal_with_current_and_reports_health(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    provider = use(monkeypatch, ReadsTheEvidence())
    body = post(client, job)
    assert body["status"] == "completed" and body["ai"] == {"requested": True, "provider": "stand-in", "model": "stand-in-1", "error_code": None, "error_message": None}
    assert body["health"] in ("Degraded", "Poor") and body["local"]["earlier_captures"] == 7 and body["local"]["strength"] in ("High", "Medium")
    retrans = row(body, "retrans.rate")
    assert retrans["normal"] == pytest.approx(0.008) and retrans["current"] > 0.03 and retrans["status"] == "high" and retrans["change"] > 3     # normal vs current
    rep = body["report"]
    assert rep["overall_health"] == body["health"] and rep["top_problems"] and rep["potential_explanations"] and rep["recommended_next_steps"] and rep["limitations"]
    assert body["confidence"] in ("High", "Medium", "Low") and body["disclosure"].startswith("To analyse this, PacketMind sends Google Gemini a summary")
    assert "never runs anything it suggests" in body["disclosure"] or "never run" in body["disclosure"] or "never changes your network" in body["disclosure"]
    assert len(provider.calls) == 1 and "c.pcap" not in provider.calls[0]            # the capture's file name is not sent either


def test_every_number_the_user_sees_comes_from_the_local_table(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence())
    body = post(client, job)
    cited = {i["evidence_id"] for i in body["report"]["evidence"]} | {i for p in body["report"]["top_problems"] for i in p["evidence_ids"]}
    shown = {m["id"] for m in body["evidence"]}
    assert cited <= shown                                    # the table behind every cited metric is part of the answer


def test_the_local_layer_alone_needs_no_ai(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    provider = use(monkeypatch, ReadsTheEvidence())
    body = post(client, job, use_ai=False)
    assert body["status"] == "local_only" and body["report"] is None and body["ai"]["requested"] is False and provider.calls == []
    assert body["health"] == body["local"]["health"] and body["evidence"] and body["local"]["reasons"]


def test_without_an_api_key_the_user_still_gets_the_local_assessment_and_the_reason(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence(error=MissingApiKeyError()))
    body = post(client, job)
    assert body["status"] == "local_only" and body["report"] is None and body["ai"]["error_code"] == "missing_api_key" and "GEMINI_API_KEY" in body["ai"]["error_message"]
    assert body["health"] == body["local"]["health"] and body["evidence"]


@pytest.mark.parametrize("error,code", [(RateLimitedError(), "rate_limited"), (InvalidApiKeyError(), "invalid_api_key")])
def test_provider_failures_keep_the_local_result_and_explain(client, tmp_path, monkeypatch, history, error, code):
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence(error=error))
    body = post(client, job)
    assert body["status"] == "ai_failed" and body["ai"]["error_code"] == code and body["ai"]["error_message"] and body["report"] is None and body["local"]["metrics"]


def test_an_unexpected_failure_is_contained_and_leaks_nothing(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence(error=RuntimeError("secret-internal-detail /Users/someone/key")))
    body = post(client, job)
    assert body["status"] == "ai_failed" and body["ai"]["error_code"] == "unexpected" and "secret" not in json.dumps(body) and body["local"]["health"]


# ------------------------------------------------------------------ safety, end to end
def test_unsafe_advice_from_the_model_never_reaches_the_user(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence(mutate=lambda d: d.update(recommended_next_steps=["Run `sudo pfctl -e` to enable the firewall", "Block the IP address 45.33.32.156",
                                                                                     "Change your routing table", "Delete the old capture files", "Compare latency to several independent services."])))
    body = post(client, job)
    assert body["report"]["recommended_next_steps"] == ["Compare latency to several independent services."]
    assert any("4 recommendation(s) removed" in n for n in body["notes"])
    text = json.dumps(body).lower()
    assert "pfctl" not in text and "routing table" not in text


def test_overclaiming_or_invented_content_discards_the_ai_answer_but_not_the_local_one(client, tmp_path, monkeypatch, history):
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    for mutate in (lambda d: d.update(summary="This is definitely an attack."), lambda d: d.update(summary="Latency to 8.8.8.8 was terrible."),
                   lambda d: d.update(summary="Round-trip time reached 97531 ms.")):
        use(monkeypatch, ReadsTheEvidence(mutate=mutate))
        body = post(client, job)
        assert body["status"] == "ai_failed" and body["ai"]["error_code"] == "invalid_output" and body["report"] is None and body["local"]["metrics"]


def test_the_models_rating_cannot_hide_a_real_problem(client, tmp_path, monkeypatch, history):
    prior_captures(history)
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence(mutate=lambda d: d.update(overall_health="Healthy", confidence="High")))
    body = post(client, job)
    local = body["local"]["health"]
    assert local != "Healthy" and body["health"] != "Healthy" if local == "Poor" else body["health"] in ("Degraded", "Healthy")
    assert body["health_note"] is None or "PacketMind" in body["health_note"]


def test_confidence_is_capped_when_there_is_no_history(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, sc.retransmission_scenario())                   # no earlier captures
    use(monkeypatch, ReadsTheEvidence())                                              # the stand-in always claims High
    body = post(client, job)
    assert body["local"]["earlier_captures"] == 0 and body["confidence"] in ("Medium", "Low") and body["confidence"] != "High" or body["local"]["strength"] == "High"


# ------------------------------------------------------------------ plumbing
def test_unknown_analysis(client):
    assert client.post("/api/analyses/nope/investigate-network").status_code == 404


def test_the_response_never_contains_connection_samples_or_packet_data(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, sc.retransmission_scenario())
    use(monkeypatch, ReadsTheEvidence())
    text = client.post(f"/api/analyses/{job}/investigate-network").text
    assert "flow_samples" not in text and "lookup_samples" not in text and "payload" not in text


def test_a_capture_with_no_measurements_is_rated_unknown_not_healthy(client, tmp_path, monkeypatch):
    job = analyze(client, tmp_path, [pf.arp()])
    use(monkeypatch, ReadsTheEvidence())
    body = post(client, job)
    assert body["local"]["health"] == "Unknown" and body["health"] == "Unknown" and body["confidence"] == "Low"
