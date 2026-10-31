"""Local performance history: SQLite storage, evaluation against earlier captures, hooks and privacy."""
import logging
import time

import pytest
from sqlalchemy import text

import pcap_factory as pf
from pcap_factory import T0
from app.analysis import analyze_pcap
from app.analysis.baseline import BaselineConfig
from app.models.analysis import AnalysisResult, DomainPerformance
from app.services import performance_history as ph
from app.services.analysis_jobs import AnalysisJobManager

JITTER = [-3, 2, -1, 0, 1, -2, 3, 0, -1, 2, 1, -2, 0, 3, -3, 1]


@pytest.fixture
def blank(tmp_path):
    """An AnalysisResult of an empty capture, to be filled with hand-made per-domain performance."""
    base = analyze_pcap(pf.write_pcap(tmp_path / "blank.pcap", []))

    def make(sha: str, when: float, domains: list[DomainPerformance]) -> AnalysisResult:
        r = base.model_copy(deep=True)
        r.metadata.sha256, r.metadata.first_packet_time = sha, when
        r.performance_statistics.domains = domains
        return r
    return make


def perf(domain="github.com", hs=45.0, rtt=38.0, p95=72.0, dns=20.0, retrans=16, packets=2000, attempted=20, failed=0, connections=20, **kw):
    return DomainPerformance(
        domain=domain, connections=connections, tcp_handshake_ms=hs, handshake_samples=5 if hs is not None else 0,
        avg_rtt_ms=rtt, p95_rtt_ms=p95, rtt_samples=40 if rtt is not None else 0, dns_latency_ms=dns, dns_lookups=3 if dns is not None else 0,
        tcp_packets=packets, retransmissions=retrans, tcp_connections_attempted=attempted, tcp_connections_failed=failed, **kw)


def record(history, blank, i, **kw):
    r = blank(f"sha{i}", T0 + i * 3600, [perf(**kw)])
    history.record(r, source_kind="pcap", source_id=f"sha{i}", name=f"cap{i}.pcap")
    return r


def stable(history, blank, n):
    for i in range(n):
        j = JITTER[i % len(JITTER)]
        record(history, blank, i, hs=45.0 + j, rtt=38.0 + j, p95=72.0 + 2 * j)


# ------------------------------------------------------------------ storage
def test_records_observations_and_reports_status(history, blank):
    stable(history, blank, 3)
    s = history.status()
    assert (s.enabled, s.sources, s.observations, s.domains) == (True, 3, 3, 1)
    assert s.oldest == T0 and s.newest == T0 + 2 * 3600
    assert any("stay in the local database" in n for n in s.notes)


def test_only_names_and_aggregate_numbers_are_stored(history):
    with history._engine.connect() as conn:  # noqa: SLF001
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(perf_observations)"))} | {r[1] for r in conn.execute(text("PRAGMA table_info(perf_sources)"))}
    assert not {c for c in cols if "ip" in c.split("_") or c in ("packet", "payload", "content", "url")}
    assert {"domain", "handshake_ms", "rtt_avg_ms", "rtt_p95_ms", "dns_ms", "response_ms", "retransmissions", "tcp_failed"} <= cols


def test_reanalysing_the_same_capture_replaces_it_instead_of_double_counting(history, blank):
    stable(history, blank, 3)
    record(history, blank, 1, hs=999.0)  # same source id "sha1" again, different numbers
    s = history.status()
    assert s.observations == 3 and s.sources == 3
    series = history._domain_series(["github.com"], None)["github.com"]  # noqa: SLF001
    assert [o.values["tcp_handshake_ms"] for o in series][1] == 999.0


def test_history_is_ordered_by_capture_time_not_by_when_it_was_recorded(history, blank):
    for i in (3, 0, 2, 1):
        record(history, blank, i)
    assert [o.source_id for o in history._domain_series(["github.com"], None)["github.com"]] == ["sha0", "sha1", "sha2", "sha3"]  # noqa: SLF001


def test_per_domain_retention_keeps_the_most_recent(blank):
    h = ph.PerformanceHistory(ph.get_history()._engine, max_per_domain=3)  # noqa: SLF001
    for i in range(6):
        record(h, blank, i)
    assert [o.source_id for o in h._domain_series(["github.com"], None)["github.com"]] == ["sha3", "sha4", "sha5"]  # noqa: SLF001
    assert h.status().sources == 3  # sources with no observations left are dropped too


def test_domains_without_connections_and_results_without_a_capture_id_are_skipped(history, blank):
    r = blank("shaX", T0, [perf(domain="dns-only.example.org", connections=0), perf(domain="real.example.com")])
    assert history.record(r, source_kind="pcap", source_id="shaX", name="x.pcap") == 1
    assert ph.source_id_for(blank("", T0, [])) is None and ph.source_id_for(r) == "shaX"
    assert history.record(blank("shaY", T0, []), source_kind="pcap", source_id="shaY", name="y") == 0


def test_clear_requires_nothing_but_removes_everything(history, blank):
    stable(history, blank, 4)
    assert history.clear() == 4
    s = history.status()
    assert (s.sources, s.observations, s.domains, s.oldest) == (0, 0, 0, None)


def test_disabled_history_records_and_reports_nothing(blank, history):
    off = ph.PerformanceHistory(history._engine, enabled=False)  # noqa: SLF001
    assert off.record(blank("shaZ", T0, [perf()]), source_kind="pcap", source_id="shaZ", name="z") == 0
    assert history.status().observations == 0
    assert off.anomalies_for("shaZ").history_enabled is False and off.anomalies_for("shaZ").anomalies == []
    assert off.domain_view("github.com", "shaZ").history_enabled is False


# ------------------------------------------------------------------ evaluation
def test_insufficient_history_flags_nothing(history, blank):
    stable(history, blank, 2)
    record(history, blank, 2, hs=400.0, rtt=300.0, p95=900.0)
    out = history.anomalies_for("sha2")
    assert out.anomalies == [] and out.domains_evaluated == 1 and out.domains_with_baseline == 0
    view = history.domain_view("github.com", "sha2")
    assert view.prior_observations == 2
    assert {c.status for c in view.comparisons if c.current is not None} == {"insufficient_baseline"}


def test_normal_variation_is_quiet(history, blank):
    stable(history, blank, 12)
    record(history, blank, 12, hs=49.0, rtt=41.0, p95=78.0)
    out = history.anomalies_for("sha12")
    assert out.anomalies == [] and out.domains_with_baseline == 1


def test_significant_deviation_is_reported_with_the_documented_example_shape(history, blank):
    stable(history, blank, 14)
    record(history, blank, 14, hs=131.0, rtt=102.0, p95=211.0, retrans=124)  # retransmissions 6.2 % of 2000 packets
    out = history.anomalies_for("sha14")
    by = {a.metric: a for a in out.anomalies}
    assert set(by) >= {"tcp_handshake_ms", "avg_rtt_ms", "p95_rtt_ms", "retransmission_rate"}
    hs = by["tcp_handshake_ms"]
    assert hs.domain == "github.com" and hs.baseline == pytest.approx(45, abs=1) and hs.current_value == 131
    assert hs.deviation == pytest.approx(1.9, abs=0.1) and hs.first_seen == hs.last_seen == T0 + 14 * 3600
    assert by["retransmission_rate"].current_value == pytest.approx(0.062)
    assert [a.severity.rank for a in out.anomalies] == sorted((a.severity.rank for a in out.anomalies), reverse=True)  # worst first


def test_an_older_capture_is_judged_only_against_what_came_before_it(history, blank):
    stable(history, blank, 8)
    record(history, blank, 8, hs=300.0)            # a slow capture at t=8h ...
    for i in range(9, 12):
        record(history, blank, i)                  # ... followed by normal ones
    assert history.anomalies_for("sha5").anomalies == []                                   # unaffected by later captures
    assert {a.metric for a in history.anomalies_for("sha8").anomalies} == {"tcp_handshake_ms"}


def test_changing_domain_behaviour_forms_a_run_then_becomes_the_new_normal(blank):
    h = ph.PerformanceHistory(ph.get_history()._engine, config=BaselineConfig(window=10))  # noqa: SLF001
    for i in range(10):
        record(h, blank, i, hs=45.0 + JITTER[i % 16])
    runs = []
    for k in range(9):
        i = 10 + k
        record(h, blank, i, hs=130.0 + JITTER[k % 16])
        found = [a for a in h.anomalies_for(f"sha{i}").anomalies if a.metric == "tcp_handshake_ms"]
        runs.append((found[0].observations_in_run, found[0].first_seen) if found else None)
    assert [r[0] for r in runs[:3]] == [1, 2, 3] and all(r[1] == T0 + 10 * 3600 for r in runs[:3])
    assert runs[-1] is None  # the baseline has adapted


def test_missing_metrics_in_the_capture_are_not_judged(history, blank):
    stable(history, blank, 10)
    record(history, blank, 10, hs=None, rtt=None, p95=None, dns=None, retrans=0, packets=0, attempted=0)
    out = history.anomalies_for("sha10")
    assert out.anomalies == []
    view = history.domain_view("github.com", "sha10")
    assert {c.status for c in view.comparisons} == {"no_data"}


def test_domain_view_returns_history_for_charts(history, blank):
    stable(history, blank, 6)
    record(history, blank, 6, hs=140.0, rtt=110.0, p95=230.0)
    view = history.domain_view("github.com", "sha6")
    assert len(view.history) == 7 and [p.current for p in view.history].count(True) == 1 and view.history[-1].current
    assert view.history[-1].tcp_handshake_ms == 140.0 and view.history[0].retransmission_rate == pytest.approx(0.008)
    assert [p.t for p in view.history] == sorted(p.t for p in view.history)
    # a capture that is not in the history still shows the history, without a comparison
    other = history.domain_view("github.com", "unknown-sha")
    assert len(other.history) == 7 and other.comparisons == [] and other.anomalies == []


def test_anomaly_counts_for_a_page_of_domains(history, blank):
    for i in range(10):
        history.record(blank(f"sha{i}", T0 + i * 3600, [perf(domain="a.example.com"), perf(domain="b.example.com")]),
                       source_kind="pcap", source_id=f"sha{i}", name="c")
    history.record(blank("sha10", T0 + 10 * 3600, [perf(domain="a.example.com", hs=300.0), perf(domain="b.example.com")]),
                   source_kind="pcap", source_id="sha10", name="c")
    assert history.anomaly_counts("sha10", ["a.example.com", "b.example.com"]) == {"a.example.com": 1}
    assert history.anomaly_counts(None, ["a.example.com"]) == {}


# ------------------------------------------------------------------ hooks
def test_analysis_jobs_record_history_and_a_history_failure_never_fails_the_job(history, tmp_path, caplog):
    cap = pf.write_pcap(tmp_path / "c.pcap", sorted(
        [pf.dns_query("10.0.0.5", "8.8.8.8", "example.com", ts=T0), pf.dns_response("10.0.0.5", "8.8.8.8", "example.com", answers=["93.184.216.34"], ts=T0 + 0.02)]
        + pf.tcp_session(client="10.0.0.5", server="93.184.216.34", t=T0 + 1), key=lambda p: p.time))
    mgr = AnalysisJobManager(workers=1, retain=5, history=history)
    job = mgr.submit(cap, "c.pcap", cap.stat().st_size)
    deadline = time.time() + 20
    while job.status in ("queued", "running") and time.time() < deadline:
        time.sleep(0.02)
    assert job.status == "completed"
    assert history.status().observations == 1 and history._domain_series(["example.com"], None)["example.com"][0].source_name == "c.pcap"  # noqa: SLF001

    class Broken:
        enabled = True

        def record(self, *a, **k):
            raise RuntimeError("disk full")

    cap2 = pf.write_pcap(tmp_path / "d.pcap", pf.tcp_session(t=T0 + 5))
    with caplog.at_level(logging.ERROR):
        job2 = AnalysisJobManager(workers=1, retain=5, history=Broken()).submit(cap2, "d.pcap", cap2.stat().st_size)
        while job2.status in ("queued", "running") and time.time() < deadline:
            time.sleep(0.02)
    assert job2.status == "completed" and "Could not record performance history" in caplog.text


def test_jobs_without_history_record_nothing(history, tmp_path):
    cap = pf.write_pcap(tmp_path / "e.pcap", pf.tcp_session())
    job = AnalysisJobManager(workers=1, retain=5).submit(cap, "e.pcap", cap.stat().st_size)
    while job.status in ("queued", "running"):
        time.sleep(0.02)
    assert job.status == "completed" and history.status().observations == 0


# ------------------------------------------------------------------ pooled "normal" values for the network investigation
def test_network_normals_need_five_earlier_captures(history, blank):
    for i in range(4):
        record(history, blank, i)
    assert history.network_normals(None) == (4, {}, {})                       # four is not a baseline
    record(history, blank, 4)
    sources, values, samples = history.network_normals(None)
    assert sources == 5 and values["handshake_ms"] == 45.0 and values["avg_rtt_ms"] == 38.0 and values["retransmission_rate"] == pytest.approx(0.008)
    assert values["failure_rate"] == 0 and samples["avg_rtt_ms"] == 5 * 40


def test_network_normals_are_pooled_by_samples_across_domains(history, blank):
    for i in range(5):
        r = blank(f"sha{i}", T0 + i * 3600, [perf("a.example.com", rtt=100.0, packets=1000, retrans=100), perf("b.example.com", rtt=10.0, packets=3000, retrans=30)])
        for d, n in zip(r.performance_statistics.domains, (300, 100)):
            d.rtt_samples = n
        history.record(r, source_kind="pcap", source_id=f"sha{i}", name="c")
    _, values, _ = history.network_normals(None)
    assert values["avg_rtt_ms"] == pytest.approx((100 * 300 + 10 * 100) / 400)         # weighted by RTT samples, not a plain mean of the two
    assert values["retransmission_rate"] == pytest.approx(130 / 4000)                    # pooled over all packets


def test_a_capture_is_never_part_of_its_own_normal_and_only_earlier_captures_count(history, blank):
    for i in range(6):
        record(history, blank, i, rtt=38.0)
    record(history, blank, 6, rtt=500.0)                                                 # the capture being investigated
    record(history, blank, 7, rtt=900.0)                                                 # a later one
    sources, values, _ = history.network_normals("sha6")
    assert sources == 6 and values["avg_rtt_ms"] == 38.0


def test_network_normals_use_only_the_most_recent_captures(history, blank):
    for i in range(10):
        record(history, blank, i, rtt=1000.0 if i < 5 else 38.0)
    _, values, _ = history.network_normals(None, max_sources=5)
    assert values["avg_rtt_ms"] == 38.0


def test_network_normals_when_history_is_off(blank, history):
    off = ph.PerformanceHistory(history._engine, enabled=False)  # noqa: SLF001
    assert off.network_normals(None) == (0, {}, {})
