"""Severity levels and the confidence/severity scoring primitives shared by all detectors.

Scoring model (deliberately simple and explainable):

1. A detector turns each piece of evidence into a *factor score* in [0, 1] using
   :func:`ramp` - 0 at or below a configured "start" value, 1 at or above a configured
   "full" value, linear in between.
2. Factors carry configured weights; :func:`weighted_score` is their weighted mean.
3. :func:`confidence_from_score` maps that onto ``[floor, ceiling]``. The ceiling is
   below 1.0 on purpose: local heuristics never reach certainty.
4. :func:`severity_for_confidence` maps confidence onto a severity band, then caps it
   at the detector's configured maximum (a possible DNS oddity is never CRITICAL).
"""
from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric order: INFO=0 ... CRITICAL=4."""
        return _RANK[self]


_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def min_severity(a: Severity, b: Severity) -> Severity:
    """The lower of two severities."""
    return a if a.rank <= b.rank else b


class ConfidenceBounds(BaseModel):
    """Range every confidence score is mapped into. Never reaches 1.0 (no certainty)."""

    floor: float = Field(0.30, ge=0.0, le=1.0)
    ceiling: float = Field(0.95, ge=0.0, le=1.0)


class SeverityThresholds(BaseModel):
    """Minimum confidence for each severity band; below ``low`` is INFO."""

    critical: float = 0.90
    high: float = 0.75
    medium: float = 0.55
    low: float = 0.40


def ramp(value: float, start: float, full: float) -> float:
    """Linear 0..1 score: 0 at/below ``start``, 1 at/above ``full``.

    If ``full <= start`` the ramp degenerates to a step at ``start``.
    """
    if full <= start:
        return 1.0 if value >= start else 0.0
    return max(0.0, min(1.0, (value - start) / (full - start)))


def weighted_score(factors: Sequence[tuple[float, float]]) -> float:
    """Weighted mean of ``(weight, score)`` pairs, in [0, 1]; 0.0 if there are no weights."""
    total = sum(w for w, _ in factors)
    if total <= 0:
        return 0.0
    return max(0.0, min(1.0, sum(w * s for w, s in factors) / total))


def confidence_from_score(score: float, bounds: ConfidenceBounds) -> float:
    """Map a 0..1 evidence score into the configured confidence range (2 decimals)."""
    return round(bounds.floor + (bounds.ceiling - bounds.floor) * max(0.0, min(1.0, score)), 2)


def severity_for_confidence(confidence: float, thresholds: SeverityThresholds, cap: Severity) -> Severity:
    """Severity band for ``confidence``, never above ``cap``."""
    if confidence >= thresholds.critical:
        band = Severity.CRITICAL
    elif confidence >= thresholds.high:
        band = Severity.HIGH
    elif confidence >= thresholds.medium:
        band = Severity.MEDIUM
    elif confidence >= thresholds.low:
        band = Severity.LOW
    else:
        band = Severity.INFO
    return min_severity(band, cap)
