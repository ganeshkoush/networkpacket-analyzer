import pcap_factory as pf
from detection_helpers import assert_well_formed
from app.detection import DetectionConfig, FindingType, Severity
from app.detection.config import PortScanConfig
from app.detection.severity import Severity as S

SCANNER, TARGET = "10.0.0.99", "10.0.0.9"


def of_type(findings, t):
    return [f for f in findings if f.type == t]


def test_vertical_scan_is_detected_with_evidence(detect):
    findings, _ = detect(pf.scan_packets(SCANNER, TARGET, range(1, 101), open_ports={22}))
    (f,) = of_type(findings, FindingType.PORT_SCAN)
    assert f.source_ip == SCANNER and f.destination_ip == TARGET
    assert f.evidence["unique_ports"] == 100
    assert f.evidence["syn_packets"] == 100
    assert f.evidence["syn_ack_packets"] == 1
    assert f.evidence["rst_packets_received"] == 99
    assert f.severity in (Severity.HIGH, Severity.MEDIUM) and f.confidence >= 0.75
    assert "duration_seconds" in f.evidence
    assert_well_formed(f)


def test_scan_without_any_replies_is_still_detected(detect):
    pk = [pf.tcp(SCANNER, TARGET, 40000 + i, 1000 + i, "S", seq=i, ts=pf.T0 + i * 0.05) for i in range(40)]
    (f,) = of_type(detect(pk)[0], FindingType.PORT_SCAN)
    assert f.evidence["syn_ack_packets"] == 0 and f.evidence["failure_ratio"] == 1.0


def test_threshold_edge_just_below_and_at_minimum(detect):
    below, _ = detect(pf.scan_packets(SCANNER, TARGET, range(1, 15), step=0.5))  # 14 ports
    assert of_type(below, FindingType.PORT_SCAN) == []
    at, _ = detect(pf.scan_packets(SCANNER, TARGET, range(1, 16), step=0.5))  # 15 ports
    (f,) = of_type(at, FindingType.PORT_SCAN)
    strong, _ = detect(pf.scan_packets(SCANNER, TARGET, range(1, 101)))
    assert f.confidence < of_type(strong, FindingType.PORT_SCAN)[0].confidence  # minimal case is less confident
    assert f.severity.rank < Severity.HIGH.rank


def test_normal_web_clients_are_not_flagged(detect):
    pk = []
    for i in range(20):
        pk += pf.tcp_session(client=f"10.0.0.{10 + i}", sport=50000 + i, dport=443, t=pf.T0 + i)
    findings, _ = detect(pk)
    assert findings == []


def test_false_positive_many_answered_ports_not_flagged(detect):
    """A client using 40 different, working ports (FTP passive data, P2P) is not a scan."""
    pk = []
    for i in range(40):
        pk += pf.tcp_session(client="10.0.0.20", server=TARGET, sport=50000 + i, dport=20000 + i, t=pf.T0 + i * 0.2)
    findings, _ = detect(pk)
    assert of_type(findings, FindingType.PORT_SCAN) == []


def test_false_positive_many_answered_hosts_not_flagged(detect):
    pk = []
    for i in range(60):
        pk += pf.tcp_session(client="10.0.0.20", server=f"10.9.0.{i + 1}", sport=50000 + i, dport=443, t=pf.T0 + i * 0.2)
    findings, _ = detect(pk)
    assert findings == []


def test_host_sweep_detected(detect):
    pk = [pf.tcp(SCANNER, f"10.2.0.{i + 1}", 40000 + i, 445, "S", seq=i, ts=pf.T0 + i * 0.05) for i in range(60)]
    findings, _ = detect(pk)
    (f,) = of_type(findings, FindingType.HOST_SWEEP)
    assert f.source_ip == SCANNER and f.evidence["unique_hosts"] == 60 and f.evidence["unique_ports"] == 1
    assert of_type(findings, FindingType.PORT_SCAN) == []
    assert_well_formed(f)


def test_scanner_hitting_several_hosts_gives_one_finding(detect):
    pk = []
    for j in range(3):
        pk += pf.scan_packets(SCANNER, f"10.0.0.{j + 1}", range(1, 51), t0=pf.T0 + j * 10)
    findings, _ = detect(pk)
    (f,) = of_type(findings, FindingType.PORT_SCAN)
    assert f.evidence["targets_scanned"] == 3 and f.destination_ip is None
    assert of_type(findings, FindingType.HOST_SWEEP) == []


def test_configuration_changes_behaviour(detect):
    pk = pf.scan_packets(SCANNER, TARGET, range(1, 31))
    assert of_type(detect(pk)[0], FindingType.PORT_SCAN)
    strict = DetectionConfig(port_scan=PortScanConfig(min_unique_ports=50))
    assert of_type(detect(pk, strict)[0], FindingType.PORT_SCAN) == []
    off = DetectionConfig(port_scan=PortScanConfig(enabled=False))
    assert detect(pk, off)[0] == []
    capped = DetectionConfig(port_scan=PortScanConfig(max_severity=S.LOW))
    assert of_type(detect(pf.scan_packets(SCANNER, TARGET, range(1, 200)), capped)[0], FindingType.PORT_SCAN)[0].severity is S.LOW


def test_finding_ids_are_stable(detect):
    pk = pf.scan_packets(SCANNER, TARGET, range(1, 60))
    a = of_type(detect(pk)[0], FindingType.PORT_SCAN)[0].id
    b = of_type(detect(pk)[0], FindingType.PORT_SCAN)[0].id
    assert a == b and a.startswith("PORT_SCAN-")
