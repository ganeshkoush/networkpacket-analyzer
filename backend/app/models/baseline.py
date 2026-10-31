"""Models for historical performance baselines and performance anomalies.

Only domain names and aggregate numbers are ever stored or returned here (no packets, no IP addresses).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.detection.severity import Severity

MetricName = Literal[
    "tcp_handshake_ms", "avg_rtt_ms", "p95_rtt_ms", "dns_latency_ms", "response_ms", "retransmission_rate", "failure_rate",
    "connection_attempts_per_s",
]
ComparisonStatus = Literal["normal", "anomalous", "insufficient_baseline", "insufficient_current", "no_data"]
ConfidenceLabel = Literal["Low", "Medium", "High"]


class MetricBaseline(BaseModel):
    """Distribution of one metric over the rolling window of earlier observations of a domain."""

    observations: int  # earlier observations in the window that had this metric
    excluded_outliers: int = 0  # of those, unusually high ones that the statistics below do not learn from
    mean: float
    std: float
    median: float  # the typical value anomaly detection compares against
    p95: float
    min: float
    max: float


class MetricComparison(BaseModel):
    """Current value of one metric against its historical baseline (``status`` says why nothing was concluded)."""

    metric: MetricName
    label: str
    unit: Literal["ms", "%"]
    status: ComparisonStatus
    current: float | None = None
    current_samples: int = 0
    baseline: MetricBaseline | None = None
    relative_change: float | None = None  # (current - baseline median) / baseline median
    z_score: float | None = None
    note: str | None = None  # e.g. "Baseline needs 5 observations; 3 so far."


class PerformanceAnomaly(BaseModel):
    """A statistically significant worsening of one metric for one domain, relative to its own history.

    "Possible" by design: it is a deviation from this domain's earlier observations, not a diagnosis. A different
    network, capture point or time of day can shift latency.
    """

    id: str
    domain: str
    metric: MetricName
    label: str
    unit: Literal["ms", "%", "/s"]
    baseline: float  # typical (median) historical value
    baseline_mean: float
    baseline_std: float
    baseline_observations: int
    current_value: float
    deviation: float  # relative change vs baseline: 1.91 means +191 %
    absolute_change: float
    z_score: float
    severity: Severity
    confidence: float  # 0..1, never certainty
    confidence_label: ConfidenceLabel
    first_seen: float  # capture time of the first observation in the current run of anomalies
    last_seen: float
    observations_in_run: int
    evidence: list[str]
    caveats: list[str]
    # "history": against the domain's earlier captures. "capture": a time window against the rest of the same capture
    # (used by the correlation engine); then first_seen/last_seen is that window and baseline_observations the reference samples.
    basis: Literal["history", "capture"] = "history"
    scope_ips: list[str] = Field(default_factory=list)
    ratio: float | None = None  # current / baseline


class HistoryPoint(BaseModel):
    """One earlier observation of a domain (for the history charts). Rates are fractions (0.062 = 6.2 %)."""

    t: float
    source_name: str
    current: bool = False  # the observation being viewed
    tcp_handshake_ms: float | None = None
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    dns_latency_ms: float | None = None
    response_ms: float | None = None
    retransmission_rate: float | None = None
    failure_rate: float | None = None


class AnomalyList(BaseModel):
    history_enabled: bool
    domains_evaluated: int = 0
    domains_with_baseline: int = 0  # at least one metric had enough history to be judged
    anomalies: list[PerformanceAnomaly] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DomainBaselineView(BaseModel):
    domain: str
    history_enabled: bool
    prior_observations: int = 0  # earlier observations of this domain
    comparisons: list[MetricComparison] = Field(default_factory=list)
    anomalies: list[PerformanceAnomaly] = Field(default_factory=list)
    history: list[HistoryPoint] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class HistoryStatus(BaseModel):
    enabled: bool
    sources: int = 0
    observations: int = 0
    domains: int = 0
    oldest: float | None = None
    newest: float | None = None
    notes: list[str] = Field(default_factory=list)
