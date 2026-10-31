"""Pydantic models for the AI investigation layer (requests, evidence bundles, results)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.detection.models import Finding, FindingType
from app.detection.severity import Severity

MAX_CONFIDENCE = 0.95  # model output is never allowed to claim certainty
UNDETERMINED = "UNDETERMINED"  # finding_type when evidence does not support a known category


class EvidenceBundle(BaseModel):
    """Everything the model may reason about: structured, bounded, JSON-serialisable.

    `data` is aggregated analysis evidence (never raw packets / PCAP bytes). `findings` are the
    local detectors' findings. All strings inside are untrusted packet-derived data.
    """

    data: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    question: str | None = Field(None, max_length=1000, description="Optional analyst question")
    finding_id: str | None = Field(None, description="Focus the investigation on one finding")


class InvestigationResult(BaseModel):
    """Validated output of an investigation. Also used as the Gemini response schema."""

    investigation_summary: str = Field(min_length=1, max_length=1500)
    finding_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list, max_length=25)
    interpretation: str = Field(min_length=1, max_length=2500)
    possible_explanations: list[str] = Field(default_factory=list, max_length=15)
    recommended_next_steps: list[str] = Field(default_factory=list, max_length=15)
    additional_evidence_needed: list[str] = Field(default_factory=list, max_length=15)
    limitations: list[str] = Field(default_factory=list, max_length=15)

    @field_validator("finding_type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        v = v.strip().upper()
        if v != UNDETERMINED and v not in {t.value for t in FindingType}:
            raise ValueError(f"unknown finding_type {v[:40]!r}")
        return v

    @field_validator("evidence", "possible_explanations", "recommended_next_steps",
                     "additional_evidence_needed", "limitations")
    @classmethod
    def _bounded_items(cls, items: list[str]) -> list[str]:
        cleaned = [i.strip() for i in items if isinstance(i, str) and i.strip()]
        if any(len(i) > 800 for i in cleaned):
            raise ValueError("list item too long")
        return cleaned


class InvestigationReport(BaseModel):
    """What the application/UI receives: the result plus provenance, no model internals."""

    result: InvestigationResult
    model: str
    provider: str
    notes: list[str] = Field(default_factory=list, description="Safeguard actions taken on the model output")
