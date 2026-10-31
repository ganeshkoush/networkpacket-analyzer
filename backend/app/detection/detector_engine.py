"""Runs all detectors and merges their findings."""
from __future__ import annotations

import logging

from app.detection.arp_spoof_detector import ArpSpoofDetector
from app.detection.base_detector import BaseDetector
from app.detection.config import DetectionConfig, default_detection_config
from app.detection.connection_behavior_detector import ConnectionBehaviorDetector
from app.detection.dns_anomaly_detector import DnsAnomalyDetector
from app.detection.models import Finding
from app.detection.port_scan_detector import PortScanDetector
from app.detection.syn_flood_detector import SynFloodDetector
from app.detection.tcp_anomaly_detector import TcpAnomalyDetector
from app.models.analysis import AnalysisResult

logger = logging.getLogger(__name__)

DEFAULT_DETECTORS: tuple[type[BaseDetector], ...] = (
    PortScanDetector, SynFloodDetector, DnsAnomalyDetector, ArpSpoofDetector,
    TcpAnomalyDetector, ConnectionBehaviorDetector,
)


class DetectorEngine:
    """Runs detectors against an analysis result. One failing detector never stops the others."""

    def __init__(self, config: DetectionConfig | None = None,
                 detectors: tuple[type[BaseDetector], ...] = DEFAULT_DETECTORS) -> None:
        self.config = config or default_detection_config()
        self.detectors = [cls(self.config) for cls in detectors]
        self.errors: dict[str, str] = {}

    def run(self, result: AnalysisResult) -> list[Finding]:
        """Return findings sorted by severity then confidence (highest first)."""
        self.errors = {}
        findings: list[Finding] = []
        for detector in self.detectors:
            try:
                findings.extend(detector.detect(result))
            except Exception as exc:
                self.errors[detector.name] = f"{type(exc).__name__}: {exc}"
                logger.exception("Detector '%s' failed; continuing with the others", detector.name)
        per = self.config.min_confidence_by_detector
        findings = [f for f in findings if f.confidence >= max(self.config.min_confidence_to_report, per.get(f.detector, 0.0))]
        findings.sort(key=lambda f: (f.severity.rank, f.confidence), reverse=True)
        return findings


def detect_threats(analysis_result: AnalysisResult, config: DetectionConfig | None = None) -> list[Finding]:
    """Run every local detector over ``analysis_result`` and return structured findings.

    Findings are possibilities with evidence and a confidence score, ordered most severe
    first. Nothing here touches the network, blocks addresses or runs commands.
    """
    return DetectorEngine(config).run(analysis_result)
