"""Base class for detectors."""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.detection.config import DetectionConfig
from app.detection.models import ConfidenceFactor, Finding, FindingType
from app.detection.severity import (
    Severity,
    confidence_from_score,
    severity_for_confidence,
    weighted_score,
)
from app.models.analysis import AnalysisResult


def fmt_ts(ts: float | None) -> str:
    """Human-readable UTC time for descriptions."""
    if ts is None:
        return "unknown time"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S UTC")


def span(first: float | None, last: float | None, floor: float = 0.0) -> float:
    """Seconds between two timestamps, at least ``floor``."""
    if first is None or last is None:
        return floor
    return max(floor, last - first)


class BaseDetector(ABC):
    """A detector reads an :class:`AnalysisResult` and returns zero or more findings.

    Detectors are pure functions of the analysis result: no I/O, no network, no packet
    access. Subclasses implement :meth:`detect` and build findings with :meth:`build`,
    which applies the shared confidence/severity model.
    """

    name: str = "base"

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    @abstractmethod
    def detect(self, result: AnalysisResult) -> list[Finding]:
        """Return findings for ``result`` (empty list when nothing noteworthy)."""

    def build(
        self,
        *,
        type: FindingType,
        factors: list[tuple[str, float, float, str]],
        max_severity: Severity,
        title: str,
        description: str,
        evidence: dict[str, Any],
        reasoning: list[str],
        caveats: list[str],
        recommendation: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        key: str = "",
        first_seen: float | None = None,
        last_seen: float | None = None,
    ) -> Finding:
        """Create a finding, computing confidence and severity from ``factors``.

        ``factors`` is a list of ``(name, score 0..1, weight, detail)``.
        """
        score = weighted_score([(w, s) for _, s, w, _ in factors])
        confidence = confidence_from_score(score, self.config.confidence)
        severity = severity_for_confidence(confidence, self.config.severity, max_severity)
        digest = hashlib.sha1(f"{type.value}|{source_ip}|{destination_ip}|{key}".encode()).hexdigest()[:12]
        return Finding(
            id=f"{type.value}-{digest}",
            type=type,
            severity=severity,
            confidence=confidence,
            source_ip=source_ip,
            destination_ip=destination_ip,
            title=title,
            description=description,
            evidence=evidence,
            reasoning=reasoning,
            caveats=caveats,
            confidence_factors=[
                ConfidenceFactor(name=n, score=round(s, 3), weight=w, detail=d) for n, s, w, d in factors
            ],
            recommendation=recommendation,
            detector=self.name,
            first_seen=first_seen,
            last_seen=last_seen,
        )
