import json
import random

import pcap_factory as pf
from detection_helpers import assert_well_formed, blank_result
from app.analysis import analyze_pcap
from app.detection import DetectionConfig, DetectorEngine, FindingType, Severity, detect_threats
from app.detection.base_detector import BaseDetector
from app.detection.config import PortScanConfig, SynFloodConfig
from app.detection.severity import ConfidenceBounds


mixed_attack_capture = pf.build_attack_demo


def test_clean_capture_has_no_findings(sample_pcap):
    assert detect_threats(analyze_pcap(sample_pcap)) == []


def test_empty_result_has_no_findings():
    assert detect_threats(blank_result()) == []


def test_mixed_capture_finds_each_class_and_orders_by_severity(detect):
    findings, _ = detect(mixed_attack_capture())
    types = {f.type for f in findings}
    assert {FindingType.PORT_SCAN, FindingType.SYN_FLOOD, FindingType.ARP_SPOOFING, FindingType.DNS_DGA_LIKE} <= types
    ranks = [(f.severity.rank, f.confidence) for f in findings]
    assert ranks == sorted(ranks, reverse=True)
    for f in findings:
        assert_well_formed(f)
    assert len({f.id for f in findings}) == len(findings)  # unique ids


def test_every_finding_is_json_serialisable_with_required_fields(detect):
    findings, _ = detect(mixed_attack_capture())
    for f in findings:
        d = json.loads(f.model_dump_json())
        for key in ("id", "type", "severity", "confidence", "source_ip", "destination_ip", "description",
                    "evidence", "recommendation"):
            assert key in d
        assert d["severity"] in {s.value for s in Severity}


def test_confidence_never_reaches_certainty(detect):
    findings, _ = detect(mixed_attack_capture())
    assert max(f.confidence for f in findings) <= 0.95 < 1.0
    tight = DetectionConfig(confidence=ConfidenceBounds(floor=0.1, ceiling=0.8))
    findings, _ = detect(mixed_attack_capture(), tight)
    assert max(f.confidence for f in findings) <= 0.8


def test_normal_traffic_alongside_attack_is_not_blamed(detect):
    findings, _ = detect(mixed_attack_capture())
    assert not any(f.source_ip and f.source_ip.startswith("10.1.") for f in findings)
    assert not any(f.destination_ip == "10.0.0.80" for f in findings)


def test_one_failing_detector_does_not_stop_others(monkeypatch, detect):
    from app.detection import port_scan_detector

    def boom(self, result):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(port_scan_detector.PortScanDetector, "detect", boom)
    result = analyze_pcap_of(mixed_attack_capture(), detect)
    engine = DetectorEngine()
    findings = engine.run(result)
    assert "port_scan" in engine.errors and "detector bug" in engine.errors["port_scan"]
    assert any(f.type == FindingType.SYN_FLOOD for f in findings)
    assert not any(f.type == FindingType.PORT_SCAN for f in findings)


def analyze_pcap_of(packets, detect):
    return detect(packets)[1]


def test_disabling_detectors_via_config(detect):
    cfg = DetectionConfig(port_scan=PortScanConfig(enabled=False), syn_flood=SynFloodConfig(enabled=False))
    types = {f.type for f in detect(mixed_attack_capture(), cfg)[0]}
    assert FindingType.PORT_SCAN not in types and FindingType.SYN_FLOOD not in types
    assert FindingType.ARP_SPOOFING in types


def test_min_confidence_filter(detect):
    all_, _ = detect(mixed_attack_capture())
    cfg = DetectionConfig(min_confidence_to_report=0.9)
    strict, _ = detect(mixed_attack_capture(), cfg)
    assert 0 < len(strict) < len(all_) and all(f.confidence >= 0.9 for f in strict)


def test_custom_detector_can_be_plugged_in():
    class Always(BaseDetector):
        name = "always"

        def detect(self, result):
            return [self.build(type=FindingType.PORT_SCAN, factors=[("x", 1.0, 1.0, "")], max_severity=Severity.LOW,
                               title="t", description="possible thing, requires investigation", evidence={"a": 1},
                               reasoning=["r"], caveats=["c"], recommendation="look")]

    (f,) = DetectorEngine(detectors=(Always,)).run(blank_result())
    assert f.severity is Severity.LOW and f.detector == "always"  # capped at LOW despite max confidence


def test_cli_detect_flag(tmp_path, make_pcap, capsys):
    from app.analysis.cli import main
    path = make_pcap(pf.scan_packets("10.0.0.99", "10.0.0.9", range(1, 80)))
    assert main([str(path), "--detect"]) == 0
    out = capsys.readouterr().out
    assert "Detection findings" in out and "PORT_SCAN" in out and "not verdicts" in out
    assert main([str(path), "--detect", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["type"] == "PORT_SCAN" and "analysis" in data


def test_cli_detect_on_clean_capture(sample_pcap, capsys):
    from app.analysis.cli import main
    assert main([str(sample_pcap), "--detect"]) == 0
    assert "No findings" in capsys.readouterr().out
