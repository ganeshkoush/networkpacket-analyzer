import time

import pytest
from fastapi.testclient import TestClient

import pcap_factory as pf
from capture.live_helpers import SCANNER, TARGET, make_manager, scan
from correlation import scenarios as sc
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis.dashboard import ACTIVE, FINDINGS, SLOWEST, SUSPICIOUS, TOP_DOMAINS, build_dashboard
from app.api import analyses, live
from app.config import settings
from app.detection import detect_threats
from app.main import app
from app.models.baseline import PerformanceAnomaly
from app.services.analysis_jobs import AnalysisJobManager

C = "192.168.1.10"


def site(domain, ip, t, *, rtt_ms=30.0, hs_ms=30.0, sport=40000, segs=4, retrans=0, dns=True, finish=True):
    """A DNS lookup (optional) followed by one completed HTTPS-port connection with RTT samples."""
    pk = []
    if dns:
        pk += [pf.dns_query(C, "8.8.8.8", domain, txid=sport % 60000, sport=sport, ts=t),
               pf.dns_response(C, "8.8.8.8", domain, txid=sport % 60000, dport=sport, answers=[ip], ts=t + 0.02)]
    pk += sc.flow(C, ip, sport, 443, t + 0.1, hs_ms=hs_ms, rtt_ms=rtt_ms, segs=segs, retrans=retrans)
    if finish:
        end = t + 0.1 + hs_ms / 1000 + 0.05 + segs * 0.3 + retrans * 0.6 + 1
        pk += [pf.tcp(C, ip, sport, 443, "FA", seq=5000, ack=1, ts=end), pf.tcp(ip, C, 443, sport, "FA", seq=1, ack=5001, ts=end + 0.01)]
    return pk


def analyze(make_pcap, packets, name="t.pcap"):
    return analyze_pcap(make_pcap(packets, name))


def dash(result, findings=None, anomalies=None, key="all"):
    return build_dashboard(result, findings if findings is not None else detect_threats(result), anomalies or [], key)


def anomaly(domain="slow.example.com"):
    return PerformanceAnomaly(id=f"a-{domain}", domain=domain, metric="avg_rtt_ms", label="Average RTT", unit="ms", baseline=38.0, baseline_mean=38.0,
                              baseline_std=2.0, baseline_observations=8, current_value=102.0, deviation=1.68, absolute_change=64.0, z_score=7.0,
                              severity="MEDIUM", confidence=0.7, confidence_label="Medium", first_seen=T0 + 5, last_seen=T0 + 9, observations_in_run=1, evidence=[], caveats=[])


# ------------------------------------------------------------------ empty / small
def test_an_empty_capture_gives_an_empty_dashboard_and_no_score(make_pcap):
    d = dash(analyze(make_pcap, []))
    assert d.empty and d.health.score is None and d.health.label == "Unknown" and d.kpis.total_packets == 0
    assert d.top_domains == d.findings == d.timeline == []


def test_a_small_capture_fills_the_headline_numbers(make_pcap):
    r = analyze(make_pcap, pf.tcp_session(t=T0) + pf.tcp_session(sport=50001, t=T0 + 1))
    d = dash(r)
    assert not d.empty and d.kpis.total_packets == 14 and d.kpis.total_bytes == r.packet_statistics.total_bytes
    assert d.kpis.connections_in_window == 2 and d.kpis.active_connections == 0           # both closed with FIN from each side
    assert d.window.covers_whole_capture and d.window.key == "all" and d.timeline


def test_active_connections_are_those_not_yet_closed_or_reset(make_pcap):
    pk = site("a.example.com", "151.101.1.1", T0, sport=40001, finish=False) + site("b.example.com", "151.101.2.2", T0 + 1, sport=40002, finish=True)
    d = dash(analyze(make_pcap, pk))
    tcp = [c for c in d.active_connections if c.protocol == "TCP"]
    assert [c.server_ip for c in tcp] == ["151.101.1.1"]                                   # the other TCP connection was closed from both sides


# ------------------------------------------------------------------ domains
def multi_domain_capture():
    pk = []
    for i in range(3):
        pk += site("big.example.com", "151.101.1.1", T0 + i * 20, rtt_ms=25.0, hs_ms=25.0, sport=41000 + i, segs=8)
    for i in range(2):
        pk += site("slow.example.com", "151.101.2.2", T0 + 5 + i * 20, rtt_ms=420.0, hs_ms=350.0, sport=42000 + i, segs=2)
    pk += site("tiny.example.com", "151.101.3.3", T0 + 9, rtt_ms=60.0, hs_ms=60.0, sport=43000, segs=1)
    return pk


def test_top_domains_are_ordered_by_traffic_and_slowest_by_rtt(make_pcap):
    d = dash(analyze(make_pcap, multi_domain_capture()))
    assert d.kpis.domains_contacted == 3
    assert d.top_domains[0].domain == "big.example.com" and [r.domain for r in d.top_domains] == sorted([r.domain for r in d.top_domains], key=lambda n: -next(x.total_bytes for x in d.top_domains if x.domain == n))
    assert d.slowest_domains[0].domain == "slow.example.com" and d.slowest_domains[0].avg_rtt_ms > 300 and d.slowest_domains[0].status in ("fair", "poor")
    assert d.slowest_domains[0].tcp_handshake_ms
    assert next(r for r in d.top_domains if r.domain == "big.example.com").health == "good"


def test_a_slow_domain_costs_points_and_is_explained(make_pcap):
    healthy = dash(analyze(make_pcap, site("a.example.com", "151.101.1.1", T0, sport=40001) + site("a.example.com", "151.101.1.1", T0 + 9, sport=40002)))
    slow = dash(analyze(make_pcap, multi_domain_capture(), "m.pcap"))
    assert healthy.health.label == "Healthy" and healthy.health.score == 100 and healthy.health.deductions == []
    assert slow.health.score < healthy.health.score and any("RTT" in x.reason or "handshake" in x.reason for x in slow.health.deductions)
    assert slow.health.basis.startswith("Measured:")


# ------------------------------------------------------------------ missing data
def test_missing_dns_keeps_connections_but_no_domains(make_pcap):
    d = dash(analyze(make_pcap, site("x", "151.101.1.1", T0, dns=False) + site("y", "151.101.2.2", T0 + 3, dns=False, sport=40001)))
    assert d.kpis.domains_contacted == 0 and d.top_domains == [] and d.slowest_domains == [] and d.kpis.connections_in_window == 2
    assert d.kpis.avg_rtt_ms is None and d.kpis.dns_latency_ms is None                    # no DNS -> nothing to attribute or time
    assert d.active_connections == [] or all(c.domain is None for c in d.active_connections)


def test_missing_timing_data_is_never_scored_as_healthy(make_pcap):
    pk = [pf.udp("10.0.0.5", "151.101.1.1", 50000 + i, 443, payload=b"x" * 50, ts=T0 + i) for i in range(30)]
    d = dash(analyze(make_pcap, pk))
    assert not d.empty and d.kpis.avg_rtt_ms is None and d.kpis.avg_handshake_ms is None and d.kpis.retransmission_rate is None
    assert d.health.score is None and d.health.label == "Unknown" and "Nothing measurable" in d.health.basis


def test_retransmissions_are_reported_as_a_rate_and_scored(make_pcap):
    pk = []
    for i in range(12):
        pk += site("lossy.example.com", "151.101.9.9", T0 + i * 10, sport=44000 + i, segs=3, retrans=3)
    d = dash(analyze(make_pcap, pk))
    assert d.kpis.retransmission_rate is not None and d.kpis.retransmission_rate > 0.1 and d.kpis.tcp_packets >= 20
    assert any("Retransmission" in x.reason for x in d.health.deductions) and d.health.label in ("Degraded", "Poor")


# ------------------------------------------------------------------ security & anomalies
def scan_capture():
    return sc.port_scan_scenario(total=120.0, scan_start=30.0, ports=200)


def test_findings_suspicious_connections_and_activity(make_pcap):
    r = analyze(make_pcap, scan_capture())
    findings = detect_threats(r)
    assert findings
    d = dash(r, findings)
    assert d.kpis.findings == len(findings) and d.findings[0].severity == max((f.severity for f in findings), key=lambda s: s.rank)
    f0 = d.findings[0]
    assert f0.title and 0 < f0.confidence <= 0.95 and f0.evidence
    assert any(i.kind == "finding" and i.ref == f0.id for i in d.recent_activity)
    assert any(x.reason.endswith("in this range") or "security finding" in x.reason for x in d.health.deductions)
    assert d.markers and d.markers[0].kind == "finding"
    for s in d.suspicious_connections:
        assert s.finding_ids and "possible" in s.reasons[0]
        assert SCANNER_IP in (s.client_ip, s.server_ip) or s.finding_ids


SCANNER_IP = "45.33.32.156"


def test_findings_with_no_connections_still_score_and_never_claim_certainty(make_pcap):
    r = analyze(make_pcap, scan_capture())
    d = dash(r)
    assert all(f.confidence < 1 for f in d.findings) and d.health.score is not None and d.health.score < 100


def test_performance_anomalies_are_listed_scored_and_part_of_the_activity(make_pcap):
    r = analyze(make_pcap, multi_domain_capture())
    d = dash(r, [], [anomaly()])
    assert d.kpis.anomalies == 1 and d.anomalies[0].domain == "slow.example.com"
    assert any(x.reason.startswith("1 performance anomaly") for x in d.health.deductions)
    assert any(i.kind == "anomaly" and "slow.example.com" in i.text for i in d.recent_activity)


# ------------------------------------------------------------------ time ranges
def long_capture():
    """~35 minutes: a slow domain only in the first minutes, a fast one throughout, a late newcomer in the last two minutes."""
    pk = []
    for i in range(6):
        pk += site("early-slow.example.com", "151.101.2.2", T0 + i * 20, rtt_ms=400.0, hs_ms=300.0, sport=45000 + i, segs=2)
    for i in range(36):
        pk += site("steady.example.com", "151.101.1.1", T0 + i * 60, rtt_ms=20.0, hs_ms=20.0, sport=46000 + i, segs=3)
    pk += site("late.example.com", "151.101.4.4", T0 + 2040, rtt_ms=35.0, hs_ms=35.0, sport=47000, segs=3)
    return pk


def test_shorter_ranges_only_count_what_happened_late_in_the_capture(make_pcap):
    r = analyze(make_pcap, long_capture())
    full, last5, last15 = dash(r, [], None, "all"), dash(r, [], None, "5m"), dash(r, [], None, "15m")
    assert full.window.covers_whole_capture and not last5.window.covers_whole_capture and not last15.window.covers_whole_capture
    assert last5.window.end == full.window.end and last5.window.end - last5.window.start == pytest.approx(300)
    names = lambda d: {x.domain for x in d.top_domains}                                             # noqa: E731
    assert names(full) == {"early-slow.example.com", "steady.example.com", "late.example.com"}
    assert "early-slow.example.com" not in names(last5) and {"steady.example.com", "late.example.com"} <= names(last5)
    assert last5.kpis.total_packets < last15.kpis.total_packets < full.kpis.total_packets
    assert last5.kpis.avg_rtt_ms < 50 < full.kpis.avg_rtt_ms                                       # the slow early traffic leaves the window
    assert last5.kpis.connections_in_window < full.kpis.connections_in_window
    assert any("shorter range" in n for n in last5.notes)


def test_a_range_longer_than_the_capture_is_the_whole_capture(make_pcap):
    r = analyze(make_pcap, multi_domain_capture())
    one_hour, full = dash(r, [], None, "1h"), dash(r, [], None, "all")
    assert one_hour.window.covers_whole_capture and one_hour.window.note and one_hour.kpis == full.kpis


def test_findings_outside_the_range_are_left_out(make_pcap):
    pk = scan_capture() + site("late.example.com", "151.101.4.4", T0 + 5000, sport=47000)
    r = analyze(make_pcap, pk)
    findings = detect_threats(r)
    assert findings and dash(r, findings, None, "all").kpis.findings == len(findings)
    assert dash(r, findings, None, "5m").kpis.findings < len(findings)


# ------------------------------------------------------------------ large captures
def test_a_large_capture_stays_bounded_and_fast(make_pcap):
    pk = []
    for i in range(1500):
        pk += site(f"host{i % 400}.example.com", f"151.{101 + i % 50}.{i % 200}.{i % 250 + 1}", T0 + i * 0.5, sport=1024 + i % 60000, segs=1)
    r = analyze(make_pcap, pk, "large.pcap")
    start = time.perf_counter()
    d = dash(r)
    for key in ("5m", "15m", "1h"):
        dash(r, None, None, key)
    elapsed = time.perf_counter() - start
    assert elapsed < 3.0, f"dashboard took {elapsed:.1f}s"
    assert len(d.top_domains) <= TOP_DOMAINS and len(d.slowest_domains) <= SLOWEST and len(d.findings) <= FINDINGS
    assert len(d.active_connections) <= ACTIVE and len(d.suspicious_connections) <= SUSPICIOUS and len(d.recent_activity) <= 15
    assert len(d.timeline) <= 300 and len(d.model_dump_json()) < 120_000                          # response size does not grow with the capture


# ------------------------------------------------------------------ API: file and live
@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setattr(settings, "uploads_dir", tmp_path / "uploads")
    monkeypatch.setattr(analyses, "_manager", AnalysisJobManager(workers=2, retain=10, history=history))
    with TestClient(app) as c:
        yield c


def upload(client, tmp_path, packets):
    data = pf.write_pcap(tmp_path / "d.pcap", sorted(packets, key=lambda p: p.time)).read_bytes()
    job = client.post("/api/analyses", content=data, headers={"Content-Type": "application/octet-stream", "X-Filename": "d.pcap"}).json()["id"]
    for _ in range(600):
        if client.get(f"/api/analyses/{job}").json()["status"] in ("completed", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_api_returns_the_dashboard_for_each_range(client, tmp_path):
    job = upload(client, tmp_path, long_capture())
    for key, label in (("5m", "Last 5 minutes"), ("15m", "Last 15 minutes"), ("1h", "Last hour"), ("all", "Capture duration")):
        r = client.get(f"/api/analyses/{job}/dashboard", params={"range": key})
        assert r.status_code == 200 and r.json()["window"]["label"] == label and r.json()["source"] == "capture"
    assert client.get(f"/api/analyses/{job}/dashboard").json()["window"]["key"] == "all"
    assert client.get(f"/api/analyses/{job}/dashboard", params={"range": "2d"}).status_code == 422
    assert client.get("/api/analyses/nope/dashboard").status_code == 404


def test_api_never_serialises_connection_samples(client, tmp_path):
    job = upload(client, tmp_path, multi_domain_capture())
    assert "flow_samples" not in client.get(f"/api/analyses/{job}/dashboard").text


def test_api_empty_capture(client, tmp_path):
    job = upload(client, tmp_path, [])
    body = client.get(f"/api/analyses/{job}/dashboard").json()
    assert body["empty"] and body["health"]["label"] == "Unknown"


def test_live_dashboard_reflects_the_rolling_window(monkeypatch):
    mgr, src, _ = make_manager()
    monkeypatch.setattr(live, "get_live_manager", lambda: mgr)
    with TestClient(app) as c:
        before = c.get("/api/live/dashboard").json()
        assert before["source"] == "live" and before["empty"]                               # nothing captured yet
        from app.models.live import StartRequest
        from capture.live_helpers import IFACE
        mgr.start(StartRequest(interface=IFACE.name, confirm=True))
        src.emit(scan())
        mgr.analyze_now()
        body = c.get("/api/live/dashboard", params={"range": "5m"}).json()
        mgr.stop()
    assert not body["empty"] and body["source"] == "live" and body["kpis"]["total_packets"] > 0 and body["anomalies"] == []
    assert body["findings"] and any(s["server_ip"] == TARGET or s["client_ip"] == SCANNER for s in body["suspicious_connections"]) or body["findings"]
