"""API models for the Domain / Web Activity dashboard.

They only reshape results the analysis already computed (domain activity, per-domain performance, connections,
time series); nothing here is measured again.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.models.analysis import DomainActivity, DomainPerformance, DomainSeries, MeasurementConfidence

Health = Literal["good", "fair", "poor", "unknown"]


class WebDomainRow(BaseModel):
    """One table row. Latency fields are None when the capture does not contain the packets to measure them."""

    domain: str
    connections: int  # TCP/UDP connections attributed to the domain via DNS
    total_bytes: int
    bytes_sent: int
    bytes_received: int
    first_seen: float
    last_seen: float
    dns_latency_ms: float | None = None
    tcp_handshake_ms: float | None = None  # connection set-up time, not response time
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    rtt_samples: int = 0
    health: Health = "unknown"
    health_reasons: list[str] = Field(default_factory=list)
    anomalies: int = 0  # performance anomalies vs the domain's own history in this capture


class WebActivitySummary(BaseModel):
    total_domains: int = 0
    domains_with_connections: int = 0
    health_counts: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class WebActivityList(BaseModel):
    summary: WebActivitySummary
    total_matching: int
    offset: int
    limit: int
    domains: list[WebDomainRow]


class DomainConnection(BaseModel):
    """One connection of a domain: connection facts joined with its latency measurements."""

    id: str
    protocol: str
    application_protocol: str | None = None
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    state: str | None = None
    start_time: float
    duration_seconds: float
    bytes: int
    packets: int
    handshake_ms: float | None = None
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    application_response_ms: float | None = None  # cleartext HTTP only
    retransmissions: int | None = None
    resets: int | None = None
    measurement_confidence: MeasurementConfidence = "UNAVAILABLE"


class WebDomainDetail(BaseModel):
    domain: str
    health: Health
    health_reasons: list[str]
    overview: DomainActivity  # connections, first/last seen, traffic, packets, resolved IPs, ports
    performance: DomainPerformance | None = None  # None when the domain has no TCP connections
    connections: list[DomainConnection]  # the largest connections the analysis reports (bounded)
    connections_total: int  # all connections attributed to the domain
    series: DomainSeries
    notes: list[str] = Field(default_factory=list)
