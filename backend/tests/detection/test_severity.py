import pytest

from app.detection.severity import (
    ConfidenceBounds, Severity, SeverityThresholds, confidence_from_score, min_severity,
    ramp, severity_for_confidence, weighted_score,
)


def test_severity_ordering():
    ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks) and len(set(ranks)) == 5
    assert min_severity(Severity.HIGH, Severity.LOW) is Severity.LOW


@pytest.mark.parametrize("value,expected", [(0, 0), (10, 0), (15, 0.5), (20, 1), (99, 1), (-5, 0)])
def test_ramp(value, expected):
    assert ramp(value, 10, 20) == expected


def test_ramp_degenerate_is_a_step():
    assert ramp(4, 5, 5) == 0 and ramp(5, 5, 5) == 1 and ramp(6, 6, 2) == 1


def test_weighted_score():
    assert weighted_score([(1, 1.0), (1, 0.0)]) == 0.5
    assert weighted_score([(3, 1.0), (1, 0.0)]) == 0.75
    assert weighted_score([]) == 0.0
    assert weighted_score([(0, 1.0)]) == 0.0


def test_confidence_is_bounded_and_never_certain():
    b = ConfidenceBounds()
    assert confidence_from_score(0, b) == 0.30
    assert confidence_from_score(1, b) == 0.95 < 1.0
    assert confidence_from_score(5, b) == 0.95 and confidence_from_score(-1, b) == 0.30


@pytest.mark.parametrize("conf,expected", [
    (0.95, Severity.CRITICAL), (0.90, Severity.CRITICAL), (0.89, Severity.HIGH), (0.75, Severity.HIGH),
    (0.60, Severity.MEDIUM), (0.45, Severity.LOW), (0.39, Severity.INFO),
])
def test_severity_bands(conf, expected):
    assert severity_for_confidence(conf, SeverityThresholds(), Severity.CRITICAL) is expected


def test_severity_is_capped():
    assert severity_for_confidence(0.95, SeverityThresholds(), Severity.MEDIUM) is Severity.MEDIUM
    assert severity_for_confidence(0.45, SeverityThresholds(), Severity.HIGH) is Severity.LOW
