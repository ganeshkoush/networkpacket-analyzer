"""Correlation engine on real generated captures: analysis + detectors + engine, end to end."""
import re

import pytest

import pcap_factory as pf
import scenarios as sc
from app.analysis import analyze_pcap
from app.correlation import correlate
from app.detection import FindingType, detect_threats

FORBIDDEN = re.compile(r"\b(caused|causes|because of|due to|result of|responsible for|proves?)\b", re.I)


@pytest.fixture
def run(make_pcap):
    def _run(packets, history=None):
        analysis = analyze_pcap(make_pcap(packets))
        findings = detect_threats(analysis)
        return analysis, findings, correlate(findings, analysis, history)
    return _run


def by_type(report):
    return {c.type.value: c for c in report.correlations}


def test_syn_flood_with_slower_handshakes(run):
    analysis, findings, rep = run(sc.syn_flood_scenario())
    (flood,) = [f for f in findings if f.type == FindingType.SYN_FLOOD]
    c = by_type(rep)["SYN_FLOOD_HANDSHAKE_LATENCY"]
    assert c.finding_id == flood.id and c.relationship == "Potentially related" and c.shared_ips == [sc.SERVER] and c.scope == "host"
    assert c.performance.baseline == pytest.approx(40, abs=2) and c.performance.current_value == pytest.approx(180, abs=3)
    assert c.headline == "TCP handshake latency increased 4.5x (40 ms → 180 ms)"
    assert c.temporal_relation == "overlapping" and abs(c.time_difference_seconds) <= 1.5
    assert any("SYN burst itself ran from" in e for e in c.evidence)       # the flood's own span was localised
    assert c.confidence_label in ("Medium", "High") and c.confidence <= 0.85
    assert not FORBIDDEN.search(" ".join([c.summary, c.headline, *c.evidence, *c.caveats]))


def test_syn_flood_without_a_slowdown_is_not_correlated(run):
    _, findings, rep = run(sc.syn_flood_scenario(with_slowdown=False))
    assert any(f.type == FindingType.SYN_FLOOD for f in findings)
    assert rep.correlations == [] and any("no significant change in TCP handshake latency" in n for n in rep.no_related_change)


def test_dns_anomaly_with_slower_lookups(run):
    _, findings, rep = run(sc.dns_scenario())
    assert any(f.type == FindingType.DNS_HIGH_NXDOMAIN for f in findings)
    c = by_type(rep)["DNS_ANOMALY_DNS_LATENCY"]
    assert c.performance.baseline == pytest.approx(20, abs=2) and c.performance.current_value == pytest.approx(150, abs=3)
    assert c.temporal_relation == "overlapping" and "8.8.8.8" in c.shared_ips and "10.0.2.99" in c.shared_ips


def test_dns_anomaly_without_a_slowdown(run):
    _, _, rep = run(sc.dns_scenario(with_slowdown=False))
    assert rep.correlations == [] and rep.no_related_change


def test_port_scan_with_more_connection_attempts(run):
    _, findings, rep = run(sc.port_scan_scenario())
    (scan,) = [f for f in findings if f.type == FindingType.PORT_SCAN]
    c = by_type(rep)["PORT_SCAN_CONNECTION_ATTEMPTS"]
    assert c.finding_id == scan.id and c.performance.ratio > 10 and c.shared_ips == ["45.33.32.156", sc.SERVER]
    assert c.temporal_relation == "overlapping" and abs(c.time_difference_seconds) <= 2
    assert c.confidence_label in ("Low", "Medium")           # the scan's own probes make this weak evidence
    assert any("own probing" in e for e in c.evidence)


def test_no_scan_no_correlation(run):
    _, findings, rep = run(sc.port_scan_scenario(with_scan=False))
    assert findings == [] and rep.correlations == []


def test_retransmissions_with_higher_rtt_and_slower_responses(run):
    _, findings, rep = run(sc.retransmission_scenario())
    assert any(f.type == FindingType.TCP_HIGH_RETRANSMISSION for f in findings)
    types = by_type(rep)
    rtt, resp = types["PACKET_LOSS_RTT"], types["RETRANSMISSIONS_RESPONSE_TIME"]
    assert rtt.performance.baseline == pytest.approx(30, abs=3) and rtt.performance.current_value == pytest.approx(120, abs=6)
    assert resp.performance.baseline == pytest.approx(60, abs=6) and resp.performance.current_value == pytest.approx(400, abs=15)
    assert rtt.temporal_relation == resp.temporal_relation == "same_connections" and rtt.scope == "network"


def test_retransmissions_without_a_latency_difference(run):
    _, findings, rep = run(sc.retransmission_scenario(with_effect=False))
    assert any(f.type == FindingType.TCP_HIGH_RETRANSMISSION for f in findings)
    assert "PACKET_LOSS_RTT" not in by_type(rep) and "RETRANSMISSIONS_RESPONSE_TIME" not in by_type(rep)


def test_resets_with_failed_connections(run):
    _, findings, rep = run(sc.reset_scenario())
    assert any(f.type == FindingType.TCP_EXCESSIVE_RESETS for f in findings)
    c = by_type(rep)["RESETS_FAILED_CONNECTIONS"]
    assert c.performance.current_value == pytest.approx(1.0) and c.performance.baseline == pytest.approx(0.0)
    assert c.temporal_relation == "same_connections" and "172.16.2.2" in c.shared_ips


def test_a_capture_with_no_findings_has_nothing_to_correlate(run):
    _, findings, rep = run(pf.tcp_session())
    assert findings == [] and rep.correlations == [] and rep.not_evaluated == [] and rep.no_related_change == []


def test_samples_are_kept_in_memory_but_never_serialised(run):
    analysis, _, _ = run(sc.syn_flood_scenario(total=60.0, flood_start=20.0))
    assert analysis.performance_statistics.flow_samples and analysis.performance_statistics.flow_sample_stride == 1
    assert "flow_samples" not in analysis.model_dump()["performance_statistics"]
    assert "flow_samples" not in analysis.model_dump_json() and "lookup_samples" not in analysis.model_dump_json()
