"""Correlation engine on hand-made flow/lookup samples: scoping, thresholds, timing, confidence, wording."""
import re
from datetime import datetime, timezone

import pytest

from app.correlation import correlate
from app.correlation.engine import CorrelationConfig
from app.detection.models import Finding, FindingType
from app.detection.severity import Severity
from app.models.analysis import FlowSample, LookupSample, PerformanceStatistics
from app.models.baseline import PerformanceAnomaly
from detection_helpers import T0, blank_result

TARGET, ATTACKER, OTHER = "10.0.0.9", "203.0.113.50", "10.0.0.77"
FORBIDDEN = re.compile(r"\b(caused|causes|causing|because of|due to|result of|resulted|responsible for|proves?|proof that)\b", re.I)


def finding(type=FindingType.SYN_FLOOD, *, conf=0.87, src=None, dst=TARGET, first=T0 + 100, last=T0 + 110, title=None):
    return Finding(id=f"{type.value}-1", type=type, severity=Severity.HIGH, confidence=conf, source_ip=src, destination_ip=dst,
                   title=title or f"Possible {type.value.replace('_', ' ').lower()} against {dst}", description="d", recommendation="r",
                   detector="d", first_seen=first, last_seen=last)


def fs(t, server=TARGET, client="10.0.1.1", **kw):
    return FlowSample(t=t, client_ip=client, server_ip=server, server_port=80, **kw)


def handshakes(values_by_time, server=TARGET, client="10.0.1.1", domain=None):
    return [fs(T0 + t, server, client, handshake_ms=v, attempted=True, domain=domain) for t, v in values_by_time]


def steady(n=120, ms=40.0, server=TARGET, domain=None):
    return handshakes([(float(i), ms + (i % 5) - 2) for i in range(n)], server, domain=domain)


def result(flows=(), lookups=(), span=(0.0, 200.0), stride=1):
    r = blank_result()
    r.metadata.first_packet_time, r.metadata.last_packet_time = T0 + span[0], T0 + span[1]
    r.performance_statistics = PerformanceStatistics(flow_samples=list(flows), lookup_samples=list(lookups), flow_sample_stride=stride)
    return r


def slow_window(ms=180.0, start=100, end=115, **kw):
    return [f for f in handshakes([(float(t), ms) for t in range(start, end)], **kw)]


def baseline_without_window(ms=40.0, n=200, **kw):
    return [f for f in steady(n, ms, **kw) if not 100 <= f.t - T0 < 115]


def all_text(c):
    return " ".join([c.summary, c.headline, *c.evidence, *c.caveats, c.relationship, *c.performance.evidence, *c.performance.caveats])


# ------------------------------------------------------------------ the headline example
def test_syn_flood_with_slower_handshakes_is_potentially_related():
    r = result(baseline_without_window(40.0) + slow_window(180.0))
    rep = correlate([finding(conf=0.87)], r)
    (c,) = rep.correlations
    assert c.type.value == "SYN_FLOOD_HANDSHAKE_LATENCY" and c.relationship == "Potentially related"
    assert c.finding_confidence == 0.87 and c.finding_type == FindingType.SYN_FLOOD
    p = c.performance
    assert p.metric == "tcp_handshake_ms" and p.basis == "capture" and p.baseline == pytest.approx(40, abs=1) and p.current_value == 180
    assert p.ratio == pytest.approx(4.5, abs=0.2) and p.deviation == pytest.approx(3.5, abs=0.2) and p.z_score >= 3.5
    assert c.headline == "TCP handshake latency increased 4.5x (40 ms → 180 ms)"
    assert c.summary == "Possible syn flood against 10.0.0.9: potentially related to TCP handshake latency increased 4.5x (40 ms → 180 ms)."
    assert c.temporal_relation == "overlapping" and c.time_difference_seconds == pytest.approx(0.0, abs=5.5)
    assert c.shared_ips == [TARGET] and c.scope == "host" and c.evidence and c.caveats
    assert any("40 ms" in e and "180 ms" in e for e in c.evidence) and any("z-score" in e for e in c.evidence)
    assert 0.25 <= c.confidence <= 0.85 and c.confidence_label in ("Medium", "High")
    assert rep.not_evaluated == [] and rep.no_related_change == []


def test_never_uses_causal_wording():
    r = result(baseline_without_window() + slow_window())
    for c in correlate([finding()], r).correlations:
        assert not FORBIDDEN.search(all_text(c)), FORBIDDEN.search(all_text(c)).group(0)
        assert "not proof of causation" in " ".join(c.caveats)


# ------------------------------------------------------------------ scope
def test_the_flagged_source_is_left_out_of_the_comparison():
    noise = [fs(T0 + t, TARGET, ATTACKER, handshake_ms=900.0, attempted=True) for t in range(100, 115)]  # would distort the median
    quiet = result(baseline_without_window() + handshakes([(float(t), 41.0) for t in range(100, 115)]) + noise)
    assert correlate([finding(src=ATTACKER)], quiet).correlations == []
    assert correlate([finding(src=ATTACKER)], quiet).no_related_change


def test_slowdown_on_another_host_is_not_related():
    r = result(baseline_without_window() + slow_window(server=OTHER) + handshakes([(float(t), 41.0) for t in range(100, 115)]))
    rep = correlate([finding()], r)
    assert rep.correlations == [] and "no significant change" in rep.no_related_change[0]


def test_normal_variation_is_not_correlated():
    r = result(baseline_without_window() + handshakes([(float(t), 40.0 + (t % 7) - 3) for t in range(100, 115)]))
    rep = correlate([finding()], r)
    assert rep.correlations == [] and rep.not_evaluated == [] and len(rep.no_related_change) == 1


# ------------------------------------------------------------------ insufficient data
def test_too_few_measurements_inside_or_outside_are_reported_not_concluded():
    around = [f for f in steady(200, 40.0) if not 95 <= f.t - T0 < 120]       # nothing at all in the padded window ...
    few_inside = result(around + slow_window(end=102))                          # ... except 2 slow handshakes
    rep = correlate([finding()], few_inside)
    assert rep.correlations == [] and "inside the window" in rep.not_evaluated[0]
    few_outside = result(slow_window() + handshakes([(0.0, 40.0), (1.0, 41.0)]))
    assert "reference" in correlate([finding()], few_outside).not_evaluated[0]
    assert correlate([finding()], result()).correlations == []


def test_findings_without_a_target_or_a_time_window_say_so():
    r = result(baseline_without_window() + slow_window())
    assert "no single target" in correlate([finding(dst=None)], r).not_evaluated[0]
    assert "no time window" in correlate([finding(first=None, last=None)], r).not_evaluated[0]


def test_unrelated_finding_types_are_ignored():
    r = result(baseline_without_window() + slow_window())
    assert correlate([finding(FindingType.ARP_SPOOFING)], r).correlations == []


# ------------------------------------------------------------------ timing
def test_performance_change_after_the_event_has_a_positive_time_difference():
    flows = steady(200, 40.0) + [fs(T0 + t, handshake_ms=190.0, attempted=True) for t in range(125, 140)]
    flows = [f for f in flows if not 125 <= f.t - T0 < 140 or f.handshake_ms == 190.0]
    (c,) = correlate([finding(first=T0 + 100, last=T0 + 110)], result(flows), config=CorrelationConfig(pad_min_seconds=40.0)).correlations
    assert c.temporal_relation == "performance_follows_finding" and c.time_difference_seconds == pytest.approx(25.0, abs=1.0)
    assert any("after the security event began" in e for e in c.evidence)


def test_performance_change_before_the_event_has_a_negative_time_difference_and_lower_confidence():
    flows = [f for f in steady(200, 40.0) if not 70 <= f.t - T0 < 85] + [fs(T0 + t, handshake_ms=190.0, attempted=True) for t in range(70, 85)]
    (c,) = correlate([finding(first=T0 + 100, last=T0 + 110)], result(flows), config=CorrelationConfig(pad_min_seconds=40.0)).correlations
    on_time = correlate([finding()], result(baseline_without_window() + slow_window(190.0))).correlations[0]
    assert c.temporal_relation == "performance_precedes_finding" and c.time_difference_seconds < -20
    assert c.confidence < on_time.confidence


# ------------------------------------------------------------------ confidence
def test_confidence_is_capped_and_grows_with_evidence():
    big = correlate([finding(conf=0.99)], result(baseline_without_window(ms=40.0) + slow_window(2000.0, 100, 160)),
                    config=CorrelationConfig(pad_min_seconds=60)).correlations[0]
    weak = correlate([finding(conf=0.30)], result([f for f in steady(30, 40.0) if not 20 <= f.t - T0 < 24] + handshakes([(20.0 + i, 80.0) for i in range(4)]),
                                                  span=(0, 30)), config=CorrelationConfig(pad_min_seconds=3)).correlations
    assert big.confidence <= 0.85 and big.confidence_label == "High"
    assert weak == [] or weak[0].confidence < big.confidence


def test_finding_confidence_feeds_into_the_correlation_confidence():
    r = result(baseline_without_window() + slow_window())
    hi = correlate([finding(conf=0.95)], r).correlations[0].confidence
    lo = correlate([finding(conf=0.35)], r).correlations[0].confidence
    assert hi > lo


def test_history_corroboration_raises_confidence_and_is_cited():
    domain_flows = baseline_without_window(domain="shop.example.com") + slow_window(domain="shop.example.com")
    hist = PerformanceAnomaly(id="h", domain="shop.example.com", metric="tcp_handshake_ms", label="TCP handshake", unit="ms", baseline=45, baseline_mean=46,
                              baseline_std=3, baseline_observations=14, current_value=131, deviation=1.9, absolute_change=86, z_score=9, severity=Severity.MEDIUM,
                              confidence=0.6, confidence_label="Medium", first_seen=T0, last_seen=T0, observations_in_run=1, evidence=[], caveats=[])
    without = correlate([finding()], result(domain_flows)).correlations[0]
    with_h = correlate([finding()], result(domain_flows), [hist]).correlations[0]
    assert with_h.confidence > without.confidence and with_h.shared_domains == ["shop.example.com"]
    assert any("also unusual against shop.example.com's own history" in e for e in with_h.evidence)


def test_history_only_evidence_gives_a_lower_confidence_capture_level_correlation():
    flows = [fs(T0 + t, domain="shop.example.com") for t in range(0, 200, 5)]  # connections exist, but no timed handshakes
    hist = PerformanceAnomaly(id="h", domain="shop.example.com", metric="tcp_handshake_ms", label="TCP handshake", unit="ms", baseline=45, baseline_mean=46,
                              baseline_std=3, baseline_observations=14, current_value=131, deviation=1.9, absolute_change=86, z_score=9, severity=Severity.MEDIUM,
                              confidence=0.6, confidence_label="Medium", first_seen=T0, last_seen=T0, observations_in_run=1, evidence=[], caveats=[])
    rep = correlate([finding()], result(flows), [hist])
    (c,) = rep.correlations
    assert c.temporal_relation == "capture_level" and c.time_difference_seconds == 0 and c.performance.basis == "history"
    assert c.confidence < correlate([finding()], result(baseline_without_window() + slow_window())).correlations[0].confidence
    assert any("Only capture-level timing" in e for e in c.evidence) and "History baselines" in " ".join(c.caveats)
    assert correlate([finding()], result(flows), []).correlations == []   # no history, no localisable data: nothing to say


def test_a_real_no_change_result_is_not_overridden_by_capture_level_history():
    hist = PerformanceAnomaly(id="h", domain="shop.example.com", metric="tcp_handshake_ms", label="TCP handshake", unit="ms", baseline=45, baseline_mean=46,
                              baseline_std=3, baseline_observations=14, current_value=131, deviation=1.9, absolute_change=86, z_score=9, severity=Severity.MEDIUM,
                              confidence=0.6, confidence_label="Medium", first_seen=T0, last_seen=T0, observations_in_run=1, evidence=[], caveats=[])
    r = result(baseline_without_window(domain="shop.example.com") + handshakes([(float(t), 41.0) for t in range(100, 115)], domain="shop.example.com"))
    rep = correlate([finding()], r, [hist])
    assert rep.correlations == [] and rep.no_related_change


# ------------------------------------------------------------------ port scan
def scan_flows(own_share):
    background = [fs(T0 + i * 2.0, client=f"10.0.3.{i % 50 + 1}", attempted=True) for i in range(100)]
    n = 300
    scanner = [fs(T0 + 100 + k / 30, client=ATTACKER, attempted=True, failed=True) for k in range(int(n * own_share))]
    others = [fs(T0 + 100 + k / 30 + 0.001, client=f"10.0.8.{k % 100 + 1}", attempted=True) for k in range(n - int(n * own_share))]
    return background + scanner + others


def test_port_scan_with_more_connection_attempts():
    (c,) = correlate([finding(FindingType.PORT_SCAN, src=ATTACKER, first=T0 + 100, last=T0 + 110)], result(scan_flows(1.0))).correlations
    assert c.type.value == "PORT_SCAN_CONNECTION_ATTEMPTS" and c.performance.metric == "connection_attempts_per_s" and c.performance.unit == "/s"
    assert c.performance.ratio > 10 and c.scope == "host" and TARGET in c.shared_ips and ATTACKER in c.shared_ips
    assert any("almost entirely the flagged source's own probing" in e for e in c.evidence)
    assert any("restates the scan" in x for x in c.caveats)


def test_the_flagged_sources_own_probes_lower_the_confidence():
    own = correlate([finding(FindingType.PORT_SCAN, src=ATTACKER, first=T0 + 100, last=T0 + 110)], result(scan_flows(1.0))).correlations[0]
    mixed = correlate([finding(FindingType.PORT_SCAN, src=ATTACKER, first=T0 + 100, last=T0 + 110)], result(scan_flows(0.3))).correlations[0]
    assert own.confidence < mixed.confidence


def test_a_scan_of_many_hosts_has_no_single_target():
    assert "no single target" in correlate([finding(FindingType.PORT_SCAN, src=ATTACKER, dst=None)], result(scan_flows(1.0))).not_evaluated[0]


def test_stride_thinning_is_disclosed_and_counts_are_scaled():
    (c,) = correlate([finding(FindingType.PORT_SCAN, src=ATTACKER, first=T0 + 100, last=T0 + 110)], result(scan_flows(1.0), stride=4)).correlations
    assert any("thinned to 1 in 4" in e for e in c.evidence)
    assert correlate([finding(FindingType.PORT_SCAN, src=ATTACKER)], result(scan_flows(1.0), stride=4)).flow_data_thinned


# ------------------------------------------------------------------ DNS
def lookups(slow_for_others=True, others=3, own=True):
    out = []
    for i in range(200):
        for c in range(others):
            slow = slow_for_others and 100 <= i < 118
            out.append(LookupSample(t=T0 + i, ms=150.0 if slow else 20.0 + (i % 3), client_ip=f"10.0.2.{c + 1}", server_ip="8.8.8.8"))
    if own:
        out += [LookupSample(t=T0 + 100 + k / 20, ms=20.0, client_ip="10.0.2.99", server_ip="8.8.8.8") for k in range(200)]
    return out


def dns_finding():
    return finding(FindingType.DNS_HIGH_NXDOMAIN, src="10.0.2.99", dst=None, first=T0 + 100, last=T0 + 110, title="High NXDOMAIN rate from 10.0.2.99")


def test_dns_anomaly_with_slower_resolver_responses():
    (c,) = correlate([dns_finding()], result(lookups=lookups())).correlations
    assert c.type.value == "DNS_ANOMALY_DNS_LATENCY" and c.performance.metric == "dns_latency_ms" and c.performance.ratio > 5
    assert "other clients on the same resolver" in " ".join(c.evidence) and "8.8.8.8" in c.shared_ips and "10.0.2.99" in c.shared_ips
    assert c.performance.baseline == pytest.approx(21, abs=2) and c.performance.current_value == pytest.approx(150)


def test_dns_without_a_slowdown_finds_nothing():
    rep = correlate([dns_finding()], result(lookups=lookups(slow_for_others=False)))
    assert rep.correlations == [] and "DNS response time" in rep.no_related_change[0]


def test_dns_falls_back_to_the_flagged_clients_own_lookups():
    own = [LookupSample(t=T0 + i, ms=150.0 if 100 <= i < 118 else 20.0, client_ip="10.0.2.99", server_ip="8.8.8.8") for i in range(200)]
    (c,) = correlate([dns_finding()], result(lookups=own)).correlations
    assert "10.0.2.99's own lookups" in " ".join(c.evidence)


# ------------------------------------------------------------------ retransmissions / resets
def retrans_flows(rtt_with=120.0, resp_with=400.0, n_with=40):
    out = [fs(T0 + i, client=f"10.0.4.{i % 90 + 1}", rtt_ms=30.0 + (i % 4), rtt_samples=5, response_ms=60.0 + (i % 5)) for i in range(100)]
    out += [fs(T0 + i * 1.5, client=f"10.0.5.{i % 40 + 1}", rtt_ms=rtt_with + (i % 5), rtt_samples=5, response_ms=resp_with + i, retransmissions=2) for i in range(n_with)]
    return out


def retrans_finding():
    return finding(FindingType.TCP_HIGH_RETRANSMISSION, src=None, dst=None, first=None, last=None, title="High TCP retransmission rate")


def test_retransmissions_with_higher_rtt_and_response_time():
    rep = correlate([retrans_finding()], result(retrans_flows()))
    types = {c.type.value: c for c in rep.correlations}
    assert set(types) == {"PACKET_LOSS_RTT", "RETRANSMISSIONS_RESPONSE_TIME"}
    rtt = types["PACKET_LOSS_RTT"]
    assert rtt.temporal_relation == "same_connections" and rtt.time_difference_seconds == 0 and rtt.scope == "network"
    assert rtt.performance.ratio == pytest.approx(122 / 31.5, rel=0.15) and "connections with retransmitted segments" in " ".join(rtt.evidence)
    assert types["RETRANSMISSIONS_RESPONSE_TIME"].performance.metric == "response_ms"


def test_retransmissions_without_a_latency_difference_are_not_related():
    rep = correlate([retrans_finding()], result(retrans_flows(rtt_with=32.0, resp_with=62.0)))
    assert rep.correlations == [] and len(rep.no_related_change) == 2


def test_too_few_retransmitting_connections_to_compare():
    rep = correlate([retrans_finding()], result(retrans_flows(n_with=2)))
    assert rep.correlations == [] and any("round-trip time" in n and "inside the window" in n for n in rep.not_evaluated)


def reset_flows(refused=100, ok=40, ok_failed=0):
    out = [fs(T0 + i, client=f"10.0.6.{i % 40 + 1}", attempted=True, failed=i < ok_failed) for i in range(ok)]
    out += [fs(T0 + 50 + i * 0.2, client=f"10.0.7.{i % 50 + 1}", server="172.16.2.2", attempted=True, failed=True, reset=True) for i in range(refused)]
    return out


def reset_finding():
    return finding(FindingType.TCP_EXCESSIVE_RESETS, src=None, dst=None, first=None, last=None, title="Unusually high share of TCP resets")


def test_resets_with_failed_connections():
    (c,) = correlate([reset_finding()], result(reset_flows())).correlations
    assert c.type.value == "RESETS_FAILED_CONNECTIONS" and c.performance.metric == "failure_rate" and c.performance.unit == "%"
    assert c.performance.current_value == pytest.approx(1.0) and c.performance.baseline == pytest.approx(0.0)
    assert c.headline == "Connection failure rate was 100% on connections with resets vs 0% without"
    assert any("by definition" in e for e in c.evidence) and "172.16.2.2" in c.shared_ips


def test_resets_without_more_failures_are_not_related():
    flows = reset_flows(ok_failed=0)
    for f in flows:
        if f.reset:
            f.failed = False  # resets after an established handshake: not failed connections
    rep = correlate([reset_finding()], result(flows))
    assert rep.correlations == [] and rep.no_related_change


# ------------------------------------------------------------------ several findings, determinism
def test_multiple_findings_are_correlated_independently_and_ordered_by_confidence():
    flows = baseline_without_window() + slow_window() + retrans_flows()
    rep = correlate([finding(), retrans_finding()], result(flows))
    assert {c.finding_id for c in rep.correlations} == {"SYN_FLOOD-1", "TCP_HIGH_RETRANSMISSION-1"}
    assert [c.confidence for c in rep.correlations] == sorted((c.confidence for c in rep.correlations), reverse=True)


def test_results_and_ids_are_deterministic():
    r = result(baseline_without_window() + slow_window())
    a, b = correlate([finding()], r).correlations, correlate([finding()], r).correlations
    assert [c.model_dump() for c in a] == [c.model_dump() for c in b] and len(a[0].id) == 12


def test_no_performance_data_at_all_is_harmless():
    assert correlate([finding(), retrans_finding(), reset_finding(), dns_finding()], result()).correlations == []
