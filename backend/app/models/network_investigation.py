"""Models for the one-click "Investigate Network" experience.

Three layers, kept apart on purpose:

* ``NetworkMetric`` / ``LocalAssessment``: facts PacketMind measured and a rule-based health rating computed locally, before
  any AI is involved. These are authoritative: every number the user sees comes from here.
* ``NetworkHealthResult``: what the model returns (also its response schema). It has *no* reasoning field, and it can only
  point at metric/finding ids PacketMind issued; it cannot introduce numbers of its own.
* ``NetworkInvestigation``: what the API returns: the local layer, the grounded model result (if any), and how it went.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

Health = Literal["Healthy", "Degraded", "Poor", "Unknown"]  # Unknown: nothing measurable, so no rating is claimed
ConfidenceLevel = Literal["High", "Medium", "Low"]
MetricStatus = Literal["ok", "elevated", "high", "info", "unmeasured"]
Category = Literal["traffic", "dns", "handshake", "rtt", "retransmissions", "resets", "failures", "response", "domains",
                   "anomalies", "findings", "baseline"]
HEALTH_ORDER: dict[str, int] = {"Unknown": 0, "Healthy": 1, "Degraded": 2, "Poor": 3}


class NetworkMetric(BaseModel):
    """One measurement, with its usual (historical) value when PacketMind has one."""

    id: str
    category: Category
    label: str
    unit: Literal["ms", "%", "count", "packets", "bytes", "seconds", "packets/s"]
    current: float | None = None  # None: not measurable in this capture
    normal: float | None = None  # the pooled value over this computer's earlier captures; None if no baseline yet
    change: float | None = None  # relative change vs normal (1.0 = +100 %), when both exist
    status: MetricStatus = "info"
    samples: int = 0  # what the current value is based on (connections, lookups, packets...)
    note: str | None = None


class LocalAssessment(BaseModel):
    """PacketMind's own rule-based rating: explainable, computed before and independently of any AI."""

    health: Health
    reasons: list[str] = Field(default_factory=list)
    strength: ConfidenceLevel  # how much evidence the rating rests on (history baseline, sample counts)
    strength_reason: str
    earlier_captures: int = 0  # captures of this computer used as "normal"
    metrics: list[NetworkMetric] = Field(default_factory=list)


class Problem(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    detail: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(default_factory=list, max_length=8)  # metric / finding / anomaly / domain ids from the evidence


class EvidenceItem(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=400)


class NetworkHealthResult(BaseModel):
    """The model's answer and its response schema. There is deliberately no field for reasoning or a scratchpad."""

    overall_health: Health
    summary: str = Field(min_length=1, max_length=900)
    main_issue: str = Field("", max_length=500)
    top_problems: list[Problem] = Field(default_factory=list, max_length=5)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=12)
    potential_explanations: list[str] = Field(default_factory=list, max_length=8)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=8)
    confidence: ConfidenceLevel
    limitations: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("potential_explanations", "recommended_next_steps", "limitations")
    @classmethod
    def _bounded(cls, items: list[str]) -> list[str]:
        cleaned = [i.strip() for i in items if isinstance(i, str) and i.strip()]
        if any(len(i) > 500 for i in cleaned):
            raise ValueError("list item too long")
        return cleaned


class AiRun(BaseModel):
    requested: bool
    provider: str | None = None
    model: str | None = None
    error_code: str | None = None  # stable code, e.g. missing_api_key
    error_message: str | None = None  # safe to show


class NetworkInvestigation(BaseModel):
    status: Literal["completed", "local_only", "ai_failed"]
    generated_at: str
    local: LocalAssessment
    report: NetworkHealthResult | None = None  # the grounded model answer; None when the AI was skipped or failed
    evidence: list[NetworkMetric] = Field(default_factory=list)  # the measurements the report cites (authoritative numbers)
    health: Health  # the rating shown: the model's if accepted, otherwise the local one
    health_note: str | None = None  # why it differs from the model's own rating, if it does
    confidence: ConfidenceLevel
    ai: AiRun
    notes: list[str] = Field(default_factory=list)  # safeguards applied to the model output
    disclosure: str
