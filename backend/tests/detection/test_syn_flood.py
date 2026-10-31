import pcap_factory as pf
from scapy.layers.inet import IP  # noqa: F401
from detection_helpers import assert_well_formed
from app.detection import DetectionConfig, FindingType, Severity
from app.detection.config import SynFloodConfig

TARGET = "10.0.0.9"


def floods(findings):
    return [f for f in findings if f.type == FindingType.SYN_FLOOD]


def test_distributed_syn_flood_detected(detect):
    findings, _ = detect(pf.syn_flood_packets(TARGET, 80, 2000, per_second=1000))
    (f,) = floods(findings)
    assert f.destination_ip == TARGET and f.source_ip is None  # no dominant source
    ev = f.evidence
    assert ev["target"] == f"{TARGET}:80" and ev["syn_packets"] == 2000
    assert ev["peak_syn_per_second"] >= 900 and ev["unique_sources"] == 2000
    assert ev["ack_packets_in"] == 0 and ev["completion_ratio"] == 0
    assert f.severity in (Severity.HIGH, Severity.CRITICAL) and f.confidence >= 0.8
    assert_well_formed(f)


def test_single_source_flood_names_the_source(detect):
    findings, _ = detect(pf.syn_flood_packets(TARGET, 443, 800, single_source="203.0.113.7", per_second=800))
    (f,) = floods(findings)
    assert f.source_ip == "203.0.113.7" and f.evidence["top_source_share"] == 1.0


def test_flood_with_synacks_from_target_still_detected(detect):
    pk = syn = pf.syn_flood_packets(TARGET, 80, 600, per_second=600)
    pk = pk + [pf.tcp(TARGET, p[IP].src, 80, p["TCP"].sport, "SA", seq=1, ack=p["TCP"].seq + 1, ts=float(p.time) + 0.001)
               for p in syn]
    (f,) = floods(detect(pk)[0])
    assert f.evidence["syn_ack_packets_sent_by_target"] == 600


def test_busy_legitimate_server_not_flagged(detect):
    """300 clients complete handshakes in ~1 s: high SYN rate but connections complete."""
    findings, _ = detect(pf.busy_server_packets(TARGET, clients=300, per_second=300))
    assert floods(findings) == []


def test_below_volume_threshold_not_flagged(detect):
    assert floods(detect(pf.syn_flood_packets(TARGET, 80, 150, per_second=500))[0]) == []


def test_slow_syn_stream_not_flagged(detect):
    """Plenty of SYNs overall but never a burst: peak rate stays below the threshold."""
    assert floods(detect(pf.syn_flood_packets(TARGET, 80, 300, per_second=20))[0]) == []


def test_port_scan_is_not_reported_as_flood(detect):
    findings, _ = detect(pf.scan_packets("10.0.0.99", TARGET, range(1, 400), step=0.001))
    assert floods(findings) == []  # each port gets one SYN


def test_confidence_grows_with_intensity(detect):
    weak = floods(detect(pf.syn_flood_packets(TARGET, 80, 250, per_second=150))[0])
    strong = floods(detect(pf.syn_flood_packets(TARGET, 80, 4000, per_second=2000))[0])
    assert weak and strong and strong[0].confidence > weak[0].confidence
    assert strong[0].severity is Severity.CRITICAL and weak[0].severity.rank < strong[0].severity.rank


def test_config_threshold_and_disable(detect):
    pk = syn = pf.syn_flood_packets(TARGET, 80, 300, per_second=300)
    assert floods(detect(pk)[0])
    assert floods(detect(pk, DetectionConfig(syn_flood=SynFloodConfig(min_syn_packets=1000)))[0]) == []
    assert floods(detect(pk, DetectionConfig(syn_flood=SynFloodConfig(enabled=False)))[0]) == []
