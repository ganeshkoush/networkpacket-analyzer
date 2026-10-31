"""Baseline statistics: minimum data, normal variation, significant deviation, missing metrics, changing behaviour."""
import pytest

from app.analysis.baseline import (
    SPECS, BaselineConfig, Observation, compare_metric, evaluate_observation, percentile,
)
from app.detection.severity import Severity

DOMAIN = "github.com"
T = 1_700_000_000.0
# Deterministic, roughly symmetric jitter with median exactly 0.
JITTER = [-3, 2, -1, 0, 1, -2, 3, 0, -1, 2, 1, -2, 0, 3, -3, 1]


def obs(i, handshake=45.0, hs_n=5, rtt=38.0, rtt_p95=72.0, rtt_n=40, dns=20.0, dns_n=3, response=None, resp_n=0,
        packets=2000, retrans=16, attempted=20, failed=0, domain=DOMAIN):
    return Observation(
        source_id=f"s{i}", source_name=f"cap{i}.pcap", captured_at=T + i * 3600, domain=domain, connections=attempted,
        values={"tcp_handshake_ms": handshake, "avg_rtt_ms": rtt, "p95_rtt_ms": rtt_p95, "dns_latency_ms": dns, "response_ms": response},
        samples={"tcp_handshake_ms": hs_n if handshake is not None else 0, "avg_rtt_ms": rtt_n, "p95_rtt_ms": rtt_n,
                 "dns_latency_ms": dns_n, "response_ms": resp_n},
        tcp_packets=packets, retransmissions=retrans, attempted=attempted, failed=failed)


def history(n, **base):
    """n earlier observations with natural jitter around the base values."""
    out = []
    for i in range(n):
        j = JITTER[i % len(JITTER)]
        kw = dict(base)
        kw.setdefault("handshake", 45.0)
        kw["handshake"] = None if kw["handshake"] is None else kw["handshake"] + j
        kw["rtt"] = kw.get("rtt", 38.0) + j
        kw["rtt_p95"] = kw.get("rtt_p95", 72.0) + 2 * j
        out.append(obs(i, **kw))
    return out


def evaluate(series):
    return evaluate_observation(series, len(series) - 1)


def status(comparisons, metric):
    return next(c for c in comparisons if c.metric == metric)


# ------------------------------------------------------------------ insufficient baseline
def test_too_little_history_never_declares_an_anomaly():
    prior = history(3)
    series = prior + [obs(3, handshake=400.0, rtt=300.0, rtt_p95=900.0)]  # a huge change, but only 3 earlier observations
    comparisons, anomalies = evaluate(series)
    assert anomalies == []
    c = status(comparisons, "tcp_handshake_ms")
    assert c.status == "insufficient_baseline" and "needs 5" in c.note and "3 so far" in c.note
    assert c.baseline is not None and c.baseline.observations == 3  # what has been learned so far is still shown


def test_first_ever_observation_has_no_baseline():
    comparisons, anomalies = evaluate([obs(0)])
    assert anomalies == [] and all(c.status == "insufficient_baseline" for c in comparisons if c.current is not None)
    assert status(comparisons, "tcp_handshake_ms").baseline is None


def test_exactly_the_minimum_history_can_be_judged():
    assert status(evaluate(history(4) + [obs(4)])[0], "tcp_handshake_ms").status == "insufficient_baseline"
    assert status(evaluate(history(5) + [obs(5)])[0], "tcp_handshake_ms").status == "normal"


def test_too_few_samples_in_the_current_capture_is_not_judged():
    series = history(12) + [obs(12, handshake=131.0, hs_n=1)]  # one handshake only
    c = status(evaluate(series)[0], "tcp_handshake_ms")
    assert c.status == "insufficient_current" and "at least 3" in c.note and c.z_score > 3.5
    assert evaluate(series)[1] == []


def test_baseline_observations_with_too_few_samples_do_not_count():
    thin = [obs(i, rtt_n=2) for i in range(10)]  # each had only 2 RTT samples (< 5 needed to enter a baseline)
    c = status(evaluate(thin + [obs(10, rtt=300.0)])[0], "avg_rtt_ms")
    assert c.status == "insufficient_baseline" and c.baseline is None


# ------------------------------------------------------------------ normal variation
def test_values_within_the_usual_spread_are_normal():
    prior = history(14)
    for value in (40.0, 45.0, 48.0, 52.0):
        c = status(evaluate(prior + [obs(14, handshake=value)])[0], "tcp_handshake_ms")
        assert c.status == "normal", value


def test_a_noisy_domain_tolerates_bigger_swings_than_a_steady_one():
    noisy = [obs(i, handshake=h) for i, h in enumerate([20, 90, 35, 140, 28, 75, 50, 110, 30, 95, 40, 60])]
    steady = [obs(i, handshake=45.0) for i in range(12)]
    assert status(evaluate(noisy + [obs(12, handshake=160.0)])[0], "tcp_handshake_ms").status == "normal"
    assert status(evaluate(steady + [obs(12, handshake=160.0)])[0], "tcp_handshake_ms").status == "anomalous"


def test_a_perfectly_flat_history_does_not_make_small_wobble_significant():
    flat = [obs(i, handshake=45.0) for i in range(12)]  # MAD = 0
    assert status(evaluate(flat + [obs(12, handshake=48.0)])[0], "tcp_handshake_ms").status == "normal"
    assert status(evaluate(flat + [obs(12, handshake=60.0)])[0], "tcp_handshake_ms").status == "normal"   # +33 %, z below threshold
    assert status(evaluate(flat + [obs(12, handshake=70.0)])[0], "tcp_handshake_ms").status == "anomalous"


def test_improvements_are_not_anomalies():
    c = status(evaluate(history(14) + [obs(14, handshake=10.0, rtt=5.0)])[0], "tcp_handshake_ms")
    assert c.status == "normal" and c.relative_change < 0


def test_trivial_absolute_changes_are_ignored_even_when_statistically_large():
    tiny = [obs(i, handshake=2.0) for i in range(12)]
    c = status(evaluate(tiny + [obs(12, handshake=5.0)])[0], "tcp_handshake_ms")  # +150 %, but only 3 ms
    assert c.status == "normal" and c.z_score > 3.5


def test_an_earlier_isolated_spike_is_not_learned_from_and_does_not_excuse_a_recurrence():
    series = [obs(i, handshake=h) for i, h in enumerate([44, 46, 45, 43, 47, 45, 44, 46, 45, 120, 45, 44])]
    c = status(evaluate(series + [obs(12, handshake=100.0)])[0], "tcp_handshake_ms")
    assert c.status == "anomalous" and c.baseline.excluded_outliers == 1 and c.baseline.p95 < 60 and c.baseline.observations == 12


def test_a_value_must_also_exceed_the_percentile_of_the_usual_history():
    # a wide but healthy spread: 90 is high-ish on the log scale yet inside what this domain regularly does
    wide = [obs(i, handshake=h) for i, h in enumerate([40, 95, 45, 90, 50, 100, 42, 88, 55, 97, 48, 92])]
    assert status(evaluate(wide + [obs(12, handshake=90.0)])[0], "tcp_handshake_ms").status == "normal"


# ------------------------------------------------------------------ significant deviation
def test_significant_deviation_creates_a_complete_anomaly_record():
    prior = history(14)
    current = obs(14, handshake=131.0, hs_n=12, rtt=102.0, rtt_p95=211.0)
    comparisons, anomalies = evaluate(prior + [current])
    hs = next(a for a in anomalies if a.metric == "tcp_handshake_ms")
    assert hs.domain == DOMAIN and hs.label == "TCP handshake" and hs.unit == "ms"
    assert hs.baseline == pytest.approx(45, abs=0.5) and hs.current_value == 131.0
    assert hs.deviation == pytest.approx(131 / hs.baseline - 1, abs=0.01) and hs.deviation == pytest.approx(1.91, abs=0.05)
    assert hs.absolute_change == pytest.approx(131 - hs.baseline, abs=0.01) and hs.z_score >= 3.5
    assert hs.baseline_observations == 14 and hs.baseline_std > 0
    assert hs.severity in (Severity.MEDIUM, Severity.HIGH) and 0.3 <= hs.confidence <= 0.95 and hs.confidence_label in ("Medium", "High")
    assert hs.first_seen == hs.last_seen == current.captured_at and hs.observations_in_run == 1
    joined = " ".join(hs.evidence)
    assert "131 ms" in joined and "previous 14 observations" in joined and "95th percentile" in joined and "z-score" in joined
    assert any("not a diagnosis" in c for c in hs.caveats)
    assert {a.metric for a in anomalies} >= {"tcp_handshake_ms", "avg_rtt_ms", "p95_rtt_ms"}
    assert status(comparisons, "tcp_handshake_ms").status == "anomalous"


def test_confidence_is_never_certainty_and_grows_with_evidence():
    small = next(a for a in evaluate(history(5) + [obs(5, handshake=131.0, hs_n=3)])[1] if a.metric == "tcp_handshake_ms")
    large = next(a for a in evaluate(history(16) + [obs(16, handshake=131.0, hs_n=40)])[1] if a.metric == "tcp_handshake_ms")
    assert small.confidence < large.confidence <= 0.95
    assert small.severity.rank <= large.severity.rank and small.confidence_label in ("Low", "Medium")


def test_a_weakly_supported_deviation_is_never_rated_high():
    a = next(x for x in evaluate(history(5) + [obs(5, handshake=900.0, hs_n=3)])[1] if x.metric == "tcp_handshake_ms")
    assert a.z_score > 8 and a.severity.rank <= Severity.MEDIUM.rank


# ------------------------------------------------------------------ rate metrics
def test_retransmission_rate_against_its_baseline():
    base = [obs(i, packets=1000, retrans=8 + (i % 3) - 1) for i in range(12)]  # about 0.8 %
    bad = evaluate(base + [obs(12, packets=1000, retrans=62)])  # 6.2 %
    a = next(x for x in bad[1] if x.metric == "retransmission_rate")
    assert a.unit == "%" and a.baseline == pytest.approx(0.008, abs=0.001) and a.current_value == pytest.approx(0.062)
    assert a.deviation > 5 and "6.2%" in " ".join(a.evidence)
    ok = status(evaluate(base + [obs(12, packets=1000, retrans=10)])[0], "retransmission_rate")
    assert ok.status == "normal"


def test_rates_need_enough_packets_and_a_meaningful_increase():
    base = [obs(i, packets=1000, retrans=8) for i in range(12)]
    assert status(evaluate(base + [obs(12, packets=50, retrans=10)])[0], "retransmission_rate").status == "insufficient_current"
    # 0.8 % -> 1.4 %: statistically visible in a large capture, but under the 1-point effect-size floor
    assert status(evaluate(base + [obs(12, packets=100_000, retrans=1400)])[0], "retransmission_rate").status == "normal"


def test_connection_failure_rate():
    base = [obs(i, attempted=20, failed=i % 2) for i in range(12)]  # about 2-3 % failing
    a = next(x for x in evaluate(base + [obs(12, attempted=20, failed=9)])[1] if x.metric == "failure_rate")
    assert a.current_value == pytest.approx(0.45) and a.label == "Connection failure rate"
    assert status(evaluate(base + [obs(12, attempted=4, failed=4)])[0], "failure_rate").status == "insufficient_current"


# ------------------------------------------------------------------ missing metrics
def test_missing_metrics_are_reported_not_invented():
    current = obs(12, handshake=None, rtt=None, rtt_p95=None, dns=None, response=None, packets=0, retrans=0, attempted=0)
    comparisons, anomalies = evaluate(history(12) + [current])
    assert anomalies == [] and len(comparisons) == len(SPECS)
    assert {c.status for c in comparisons} == {"no_data"} and all(c.current is None for c in comparisons)


def test_metric_missing_in_some_earlier_observations_only_uses_the_ones_that_have_it():
    series = [obs(i, response=(80.0 if i % 2 else None), resp_n=(5 if i % 2 else 0)) for i in range(12)]
    c = status(evaluate(series + [obs(12, response=82.0, resp_n=5)])[0], "response_ms")
    assert c.status == "normal" and c.baseline.observations == 6


def test_a_domain_that_never_had_response_times_has_no_response_baseline():
    c = status(evaluate(history(12) + [obs(12, response=300.0, resp_n=5)])[0], "response_ms")
    assert c.status == "insufficient_baseline" and c.baseline is None


# ------------------------------------------------------------------ changing domain behaviour
def test_a_level_shift_is_flagged_as_a_run_and_the_baseline_then_adapts():
    cfg = BaselineConfig(window=10)
    series = [obs(i, handshake=45.0 + JITTER[i % 16]) for i in range(10)]            # 10 normal captures
    shifted = [obs(10 + k, handshake=130.0 + JITTER[k % 16]) for k in range(9)]      # then the domain gets slower
    flags, runs = [], []
    for k in range(len(shifted)):
        data = series + shifted[: k + 1]
        comps, anomalies = evaluate_observation(data, len(data) - 1, cfg)
        a = next((x for x in anomalies if x.metric == "tcp_handshake_ms"), None)
        flags.append(a is not None)
        runs.append(a.observations_in_run if a else 0)
    assert flags[0] and flags[1] and flags[2]            # the change is noticed at once
    assert runs[:3] == [1, 2, 3]                          # ... as one growing run
    assert not flags[-1]                                  # once the window is mostly "new normal", it is no longer unusual
    run3 = next(x for x in evaluate_observation(series + shifted[:3], 12, cfg)[1] if x.metric == "tcp_handshake_ms")
    assert run3.first_seen == shifted[0].captured_at and run3.last_seen == shifted[2].captured_at
    assert run3.confidence >= next(x for x in evaluate_observation(series + shifted[:1], 10, cfg)[1] if x.metric == "tcp_handshake_ms").confidence


def test_one_off_spike_is_a_single_observation_run():
    series = history(12) + [obs(12, handshake=140.0)] + [obs(13, handshake=46.0)]
    comps, anomalies = evaluate(series)
    assert [a for a in anomalies if a.metric == "tcp_handshake_ms"] == []          # back to normal straight away
    earlier = evaluate_observation(series, 12)[1]
    assert next(a for a in earlier if a.metric == "tcp_handshake_ms").observations_in_run == 1


def test_percentile_helper():
    assert percentile([5, 1, 3, 2, 4], 95) == 5 and percentile([5, 1, 3, 2, 4], 50) == 3
