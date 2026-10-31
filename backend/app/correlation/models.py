"""Correlation records: a security finding and a performance anomaly that are *potentially related*.

Correlation is not proof of causation. Records only say two events share a time window and/or scope, with the
evidence for that; they never say one caused the other.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from app.detection.models import FindingType
from app.detection.severity import Severity
from app.models.baseline import ConfidenceLabel, PerformanceAnomaly

RELATIONSHIP = "Potentially related"


class CorrelationType(str, Enum):
    SYN_FLOOD_HANDSHAKE_LATENCY = "SYN_FLOOD_HANDSHAKE_LATENCY"
    PORT_SCAN_CONNECTION_ATTEMPTS = "PORT_SCAN_CONNECTION_ATTEMPTS"
    DNS_ANOMALY_DNS_LATENCY = "DNS_ANOMALY_DNS_LATENCY"
    PACKET_LOSS_RTT = "PACKET_LOSS_RTT"
    RETRANSMISSIONS_RESPONSE_TIME = "RETRANSMISSIONS_RESPONSE_TIME"
    RESETS_FAILED_CONNECTIONS = "RESETS_FAILED_CONNECTIONS"


TemporalRelation = Literal[
    "overlapping",             # performance change began inside the finding's window
    "performance_follows_finding",   # began shortly after the window started/ended
    "performance_precedes_finding",  # began shortly before the finding's window
    "same_connections",        # the finding has no time window; both show up on the same connections
    "capture_level",           # only capture-level (history) timing is available
]


class Correlation(BaseModel):
    id: str
    type: CorrelationType
    relationship: Literal["Potentially related"] = "Potentially related"  # never "caused by"
    finding_id: str
    finding_type: FindingType
    finding_title: str
    finding_severity: Severity
    finding_confidence: float
    finding_first_seen: float | None = None
    finding_last_seen: float | None = None
    performance: PerformanceAnomaly
    headline: str  # e.g. "TCP handshake latency increased 3.2x (40 ms → 180 ms)"
    summary: str  # finding + relationship + headline, hedged
    time_difference_seconds: float  # performance onset minus finding start; negative = the performance change came first
    temporal_relation: TemporalRelation
    shared_ips: list[str] = Field(default_factory=list)
    shared_domains: list[str] = Field(default_factory=list)
    scope: Literal["host", "network"]  # a specific shared host, or network-wide
    evidence: list[str]
    caveats: list[str]
    confidence: float  # 0..1 that the two events are related; capped well below certainty
    confidence_label: ConfidenceLabel


class CorrelationList(BaseModel):
    finding_id: str | None = None
    correlations: list[Correlation] = Field(default_factory=list)
    not_evaluated: list[str] = Field(default_factory=list)  # rules that could not be checked, and why
    no_related_change: list[str] = Field(default_factory=list)  # checked: the related metric did not change significantly
    flow_data_thinned: bool = False  # only every n-th connection was kept for very large captures
    notes: list[str] = Field(default_factory=list)
