"""Models for saved investigation reports.

A report is a self-contained, JSON-serialisable snapshot: it never references raw packets and
holds no model internals (no chain-of-thought) - only conclusions, evidence, concise detector
reasoning steps and recommendations.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.ai.schemas import InvestigationResult
from app.detection.severity import Severity
from app.models.analysis import PortCount, ProtocolStat, Talker

REPORT_SCHEMA_VERSION = 1
ReportSource = Literal["pcap", "live"]
AiStatus = Literal["completed", "failed", "not_run"]


class ReportDomain(BaseModel):
    """Inferred from DNS; not a visited URL."""

    domain: str
    connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0


class ReportCapture(BaseModel):
    source_kind: ReportSource
    name: str
    capture_format: str
    size_bytes: int = 0
    sha256: str = ""
    packets: int = 0
    duration_seconds: float = 0.0
    first_packet_time_iso: str | None = None
    last_packet_time_iso: str | None = None
    interface: str | None = None  # live captures
    warnings: list[str] = Field(default_factory=list)


class ReportSummary(BaseModel):
    total_packets: int
    total_bytes: int
    duration_seconds: float
    avg_packets_per_second: float | None = None
    peak_packets_per_second: int | None = None
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    highest_severity: Severity | None = None
    headline: str


class ReportFinding(BaseModel):
    id: str
    type: str
    severity: Severity
    confidence: float
    title: str
    description: str
    source_ip: str | None = None
    destination_ip: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    investigation_steps: list[str] = Field(default_factory=list)  # concise detector reasoning
    caveats: list[str] = Field(default_factory=list)  # benign explanations
    recommendation: str
    first_seen_iso: str | None = None
    last_seen_iso: str | None = None
    ai_assessment: InvestigationResult | None = None


class ReportAi(BaseModel):
    status: AiStatus = "not_run"
    provider: str | None = None
    model: str | None = None
    result: InvestigationResult | None = None
    notes: list[str] = Field(default_factory=list)  # safeguards applied to the model output
    message: str | None = None  # why it is missing (not run / failed)


class RecommendedAction(BaseModel):
    action: str
    priority: Severity | None = None
    source: Literal["detector", "ai"]
    related_finding: str | None = None


class ReportContent(BaseModel):
    schema_version: int = REPORT_SCHEMA_VERSION
    title: str
    investigation_timestamp: datetime  # when the report/investigation was produced (UTC)
    app_version: str
    capture: ReportCapture
    summary: ReportSummary
    protocols: list[ProtocolStat] = Field(default_factory=list)
    top_talkers: list[Talker] = Field(default_factory=list)
    top_ports: list[PortCount] = Field(default_factory=list)
    domains: list[ReportDomain] = Field(default_factory=list)  # additive; absent in older reports
    findings: list[ReportFinding] = Field(default_factory=list)
    ai_investigation: ReportAi = Field(default_factory=ReportAi)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    analyst_notes: str | None = None


class SavedReport(BaseModel):
    id: str
    content: ReportContent


class ReportListItem(BaseModel):
    id: str
    title: str
    created_at: datetime
    source_kind: ReportSource
    capture_name: str
    highest_severity: Severity | None = None
    finding_count: int
    total_packets: int
    ai_status: AiStatus


class CreateReportRequest(BaseModel):
    source: Literal["analysis", "live"] = "analysis"
    analysis_id: str | None = Field(None, max_length=64, description="Completed analysis job (source=analysis)")
    title: str | None = Field(None, max_length=200)
    notes: str | None = Field(None, max_length=5000)
    run_ai: bool = Field(False, description="Ask the AI provider for an investigation summary (sends aggregated evidence)")
