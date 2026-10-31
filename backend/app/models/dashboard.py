"""API models for the Network Intelligence Dashboard.

Everything here is aggregated from results the analysis already computed (connections, per-domain performance, timeline,
findings, history anomalies). The dashboard is bounded by construction: no list exceeds a fixed cap, whatever the capture size.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.detection.models import Severity
from app.models.baseline import PerformanceAnomaly
from app.models.web_activity import Health, WebDomainRow

RangeKey = Literal["5m", "15m", "1h", "all"]
RANGE_LABELS: dict[str, str] = {"5m": "Last 5 minutes", "15m": "Last 15 minutes", "1h": "Last hour", "all": "Capture duration"}
RANGE_SECONDS: dict[str, float | None] = {"5m": 300.0, "15m": 900.0, "1h": 3600.0, "all": None}
ScoreLabel = Literal["Healthy", "Degraded", "Poor", "Unknown"]


class DashboardWindow(BaseModel):
    key: RangeKey
    label: str
    start: float | None = None  # epoch seconds; None when the capture has no packets
    end: float | None = None
    capture_start: float | None = None
    capture_end: float | None = None
    covers_whole_capture: bool = True  # a longer range than the capture is the same as "Capture duration"
    note: str | None = None


class Deduction(BaseModel):
    reason: str
    points: int


class HealthScore(BaseModel):
    """A quick 0-100 summary with every deduction listed. A heuristic, not a verdict; the AI investigation has the detail."""

    score: int | None = None  # None: nothing measurable, so no score is claimed
    label: ScoreLabel = "Unknown"
    deductions: list[Deduction] = Field(default_factory=list)
    basis: str = ""  # what was and was not measurable


class DashboardKpis(BaseModel):
    active_connections: int = 0
    connections_in_window: int = 0
    domains_contacted: int = 0
    total_bytes: int = 0
    total_packets: int = 0
    avg_handshake_ms: float | None = None
    handshake_samples: int = 0
    avg_rtt_ms: float | None = None
    rtt_samples: int = 0
    dns_latency_ms: float | None = None
    dns_samples: int = 0
    retransmission_rate: float | None = None
    tcp_packets: int = 0
    findings: int = 0
    anomalies: int = 0


class SlowDomainRow(BaseModel):
    domain: str
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    tcp_handshake_ms: float | None = None
    rtt_samples: int = 0
    status: Health = "unknown"
    reasons: list[str] = Field(default_factory=list)


class DashboardFinding(BaseModel):
    id: str
    type: str
    title: str
    severity: Severity
    confidence: float
    evidence: list[str] = Field(default_factory=list)  # the first few measured values, as "name: value"
    source_ip: str | None = None
    destination_ip: str | None = None
    first_seen: float | None = None
    last_seen: float | None = None


class DashboardConnection(BaseModel):
    id: str
    protocol: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    domain: str | None = None
    state: str | None = None
    bytes: int
    start_time: float
    end_time: float
    handshake_ms: float | None = None
    retransmissions: int | None = None
    finding_ids: list[str] = Field(default_factory=list)  # findings that name an endpoint of this connection
    reasons: list[str] = Field(default_factory=list)


class ActivityItem(BaseModel):
    time: float
    kind: Literal["finding", "anomaly", "domain", "connection"]
    text: str
    severity: Severity | None = None
    ref: str | None = None  # finding id / domain


class TimelineBin(BaseModel):
    start_time: float
    interval_seconds: int
    packets: int
    bytes: int


class TimelineMarker(BaseModel):
    time: float
    kind: Literal["finding", "anomaly"]
    label: str
    severity: Severity | None = None


class Dashboard(BaseModel):
    source: Literal["capture", "live"] = "capture"
    empty: bool = False
    window: DashboardWindow
    health: HealthScore
    kpis: DashboardKpis
    top_domains: list[WebDomainRow] = Field(default_factory=list)
    slowest_domains: list[SlowDomainRow] = Field(default_factory=list)
    findings: list[DashboardFinding] = Field(default_factory=list)
    anomalies: list[PerformanceAnomaly] = Field(default_factory=list)
    suspicious_connections: list[DashboardConnection] = Field(default_factory=list)
    active_connections: list[DashboardConnection] = Field(default_factory=list)
    recent_activity: list[ActivityItem] = Field(default_factory=list)
    timeline: list[TimelineBin] = Field(default_factory=list)
    markers: list[TimelineMarker] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
