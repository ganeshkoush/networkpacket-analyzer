"""Local, explainable detection over structured analysis results (no AI, no I/O)."""
from app.detection.config import DetectionConfig
from app.detection.detector_engine import DetectorEngine, detect_threats
from app.detection.models import Finding, FindingType
from app.detection.severity import Severity

__all__ = ["detect_threats", "DetectorEngine", "DetectionConfig", "Finding", "FindingType", "Severity"]
