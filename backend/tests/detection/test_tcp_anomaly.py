import pcap_factory as pf
from detection_helpers import assert_well_formed, blank_result
from app.analysis.tcp_analyzer import abnormal_flag_label
from app.detection import DetectionConfig, FindingType, Severity, detect_threats
from app.detection.config import TcpAnomalyConfig
from app.models.analysis import RetransmissionFlow, RetransmissionStatistics, TcpStatistics

SRC, DST = "10.0.0.99", "10.0.0.9"


def of_type(findings, t):
    return [f for f in findings if f.type == t]


# ----------------------------------------------------------------- flag classification
def test_abnormal_flag_labels():
    S, F, R, P, A, U = 0x02, 0x01, 0x04, 0x08, 0x10, 0x20
    assert abnormal_flag_label(0) == "NULL"
    assert abnormal_flag_label(S | F) == "SYN+FIN"
    assert abnormal_flag_label(S | R) == "SYN+RST"
    assert abnormal_flag_label(F | R) == "FIN+RST"
    assert abnormal_flag_label(F | P | U) == "XMAS"
    assert abnormal_flag_label(F) == "FIN_NO_ACK"
    assert abnormal_flag_label(P) == "NO_ACK"
    for normal in (S, S | A, A, P | A, F | A, R, R | A, F | P | A):
        assert abnormal_flag_label(normal) is None


# ----------------------------------------------------------------- abnormal flags
def probes(flags, n, src=SRC, dst=DST):
    return [pf.tcp(src, dst, 40000 + i, 1000 + i, flags, seq=i, ts=pf.T0 + i * 0.1) for i in range(n)]


def test_null_scan_flags_detected(detect):
    (f,) = of_type(detect(probes("", 30))[0], FindingType.TCP_ABNORMAL_FLAGS)
    assert f.source_ip == SRC and f.destination_ip == DST
    assert f.evidence["kinds"] == {"NULL": 30} and f.evidence["packets"] == 30
    assert_well_formed(f)


def test_high_signal_kind_scores_higher_than_low_signal(detect):
    high = of_type(detect(probes("", 20))[0], FindingType.TCP_ABNORMAL_FLAGS)[0]  # NULL
    low = of_type(detect(probes("F", 20))[0], FindingType.TCP_ABNORMAL_FLAGS)[0]  # FIN without ACK
    assert high.confidence > low.confidence


def test_xmas_and_syn_fin_labelled(detect):
    pk = probes("FPU", 5) + probes("SF", 5, src="10.0.0.98")
    findings = of_type(detect(pk)[0], FindingType.TCP_ABNORMAL_FLAGS)
    kinds = {f.source_ip: set(f.evidence["kinds"]) for f in findings}
    assert kinds == {SRC: {"XMAS"}, "10.0.0.98": {"SYN+FIN"}}


def test_flags_below_min_packets_not_flagged(detect):
    assert detect(probes("", 2))[0] == []


def test_normal_sessions_have_no_flag_anomalies(detect):
    pk = []
    for i in range(10):
        pk += pf.tcp_session(client=f"10.0.0.{20 + i}", sport=50000 + i, t=pf.T0 + i)
    findings, result = detect(pk)
    assert findings == [] and result.tcp_statistics.flag_anomalies == []


def test_flags_config_threshold(detect):
    pk = probes("", 5)
    assert detect(pk)[0]
    assert detect(pk, DetectionConfig(tcp_anomaly=TcpAnomalyConfig(flags_min_packets=10)))[0] == []


# ----------------------------------------------------------------- retransmissions
def retrans_packets(total, dup_every, src="10.0.0.7", dst="10.0.0.9"):
    pk, t = [], pf.T0
    for i in range(total):
        pk.append(pf.tcp(src, dst, 51000, 8080, "PA", seq=1 + i * 3, payload=b"abc", ts=t))
        t += 0.01
        if dup_every and i % dup_every == 0:
            pk.append(pf.tcp(src, dst, 51000, 8080, "PA", seq=1 + i * 3, payload=b"abc", ts=t))
            t += 0.01
    return pk


def test_high_retransmission_rate_detected(detect):
    findings, result = detect(retrans_packets(200, 2))  # ~100 dup of 300 segments
    (f,) = of_type(findings, FindingType.TCP_HIGH_RETRANSMISSION)
    assert f.source_ip == "10.0.0.7" and f.destination_ip == "10.0.0.9"
    assert f.evidence["rate"] >= 0.3 and f.evidence["top_flows"][0]["dst_port"] == 8080
    assert f.severity.rank <= Severity.MEDIUM.rank
    assert_well_formed(f)


def test_low_retransmission_rate_and_small_samples_ignored(detect):
    assert of_type(detect(retrans_packets(400, 100))[0], FindingType.TCP_HIGH_RETRANSMISSION) == []  # ~1%
    assert of_type(detect(retrans_packets(30, 1))[0], FindingType.TCP_HIGH_RETRANSMISSION) == []  # too few segments


def test_retransmission_unit_without_dominant_flow():
    flows = [RetransmissionFlow(src_ip=f"10.0.0.{i}", src_port=1, dst_ip="10.0.0.9", dst_port=80, retransmissions=20, segments=100)
             for i in range(5)]
    tcp = TcpStatistics(total_packets=1000, retransmissions=RetransmissionStatistics(
        retransmitted_segments=100, sequence_bearing_segments=1000, retransmission_rate=0.1, top_flows=flows))
    (f,) = detect_threats(blank_result(tcp_statistics=tcp))
    assert f.source_ip is None and f.destination_ip is None  # no single flow dominates


# ----------------------------------------------------------------- resets
def test_excessive_resets_detected(detect):
    pk = [pf.tcp("10.0.0.50", "10.0.0.60", 1000 + i, 80, "RA", seq=i, ts=pf.T0 + i * 0.01) for i in range(120)]
    pk += pf.tcp_session()
    (f,) = of_type(detect(pk)[0], FindingType.TCP_EXCESSIVE_RESETS)
    assert f.evidence["rst_packets"] == 120 and f.evidence["rst_ratio"] > 0.9
    assert_well_formed(f)


def test_resets_below_ratio_or_count_ignored(detect):
    few = [pf.tcp("10.0.0.50", "10.0.0.60", 1000 + i, 80, "RA", seq=i, ts=pf.T0 + i) for i in range(10)]
    assert of_type(detect(few)[0], FindingType.TCP_EXCESSIVE_RESETS) == []
    mixed = [pf.tcp("10.0.0.50", "10.0.0.60", 1000 + i, 80, "RA", seq=i, ts=pf.T0 + i * 0.01) for i in range(60)]
    mixed += [pf.tcp("10.0.0.51", "10.0.0.60", 2000 + i, 80, "A", seq=i, ack=1, ts=pf.T0 + 5 + i * 0.01) for i in range(600)]
    assert of_type(detect(mixed)[0], FindingType.TCP_EXCESSIVE_RESETS) == []  # 60/660 = 9%
