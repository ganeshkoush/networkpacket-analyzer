"""Data models for detection findings."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.detection.severity import Severity


class FindingType(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    HOST_SWEEP = "HOST_SWEEP"
    SYN_FLOOD = "SYN_FLOOD"
    DNS_HIGH_NXDOMAIN = "DNS_HIGH_NXDOMAIN"
    DNS_DGA_LIKE = "DNS_DGA_LIKE"
    DNS_TUNNELING_LIKE = "DNS_TUNNELING_LIKE"
    DNS_EXCESSIVE_QUERIES = "DNS_EXCESSIVE_QUERIES"
    DNS_UNSOLICITED_RESPONSES = "DNS_UNSOLICITED_RESPONSES"
    ARP_SPOOFING = "ARP_SPOOFING"
    ARP_MULTI_IP_MAC = "ARP_MULTI_IP_MAC"
    TCP_ABNORMAL_FLAGS = "TCP_ABNORMAL_FLAGS"
    TCP_HIGH_RETRANSMISSION = "TCP_HIGH_RETRANSMISSION"
    TCP_EXCESSIVE_RESETS = "TCP_EXCESSIVE_RESETS"
    UNUSUAL_OUTBOUND_TRANSFER = "UNUSUAL_OUTBOUND_TRANSFER"
    CLEARTEXT_PROTOCOL = "CLEARTEXT_PROTOCOL"


class ConfidenceFactor(BaseModel):
    """One weighted contribution to a finding's confidence score."""

    name: str
    score: float = Field(ge=0.0, le=1.0)
    weight: float = Field(gt=0.0)
    detail: str = ""


class Finding(BaseModel):
    """A possible issue found by a local detector.

    Findings are *hypotheses for a human to check*, never verdicts. ``evidence`` holds
    the concrete measured values; ``reasoning`` says why they triggered the detector;
    ``caveats`` lists benign explanations to rule out.
    """

    id: str
    type: FindingType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source_ip: str | None = None
    destination_ip: str | None = None
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    reasoning: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    confidence_factors: list[ConfidenceFactor] = Field(default_factory=list)
    recommendation: str
    detector: str
    first_seen: float | None = None
    last_seen: float | None = None
