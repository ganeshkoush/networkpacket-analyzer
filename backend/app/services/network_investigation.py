"""Orchestrates "Investigate Network": gather local evidence, optionally ask Gemini, return a layered, honest result.

The local layer (measurements and a rule-based rating) is always produced and never depends on AI. The model is asked only
when the user pressed the button with AI enabled; if it is unavailable, misconfigured, or its answer fails the safety checks,
the user still gets the local layer plus the reason. Nothing the model says is executed or applied anywhere.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from app.ai.network_health import NetworkInvestigator
from app.ai.provider import AIProviderError
from app.correlation import correlate
from app.detection.models import Finding
from app.models.analysis import AnalysisResult
from app.models.network_investigation import AiRun, NetworkInvestigation, NetworkMetric
from app.services.network_evidence import NetworkEvidence, build_network_evidence
from app.services.performance_history import PerformanceHistory, source_id_for

logger = logging.getLogger(__name__)

DISCLOSURE = (
    "To analyse this, PacketMind sends Google Gemini a summary of the measurements: domain names, IP addresses, latency, loss and "
    "failure figures, and security findings. The capture file and packet contents are never sent. Gemini can only write an "
    "analysis: PacketMind never runs anything it suggests and never changes your network, firewall, routing or files."
)
_STATUS_RANK = {"high": 0, "elevated": 1, "ok": 2, "info": 3, "unmeasured": 4}
_MAX_EVIDENCE_ROWS = 14


def gather_evidence(result: AnalysisResult, findings: list[Finding], history: PerformanceHistory) -> NetworkEvidence:
    source_id = source_id_for(result)
    anomalies = history.anomalies_for(source_id).anomalies
    return build_network_evidence(
        result, findings, normals=history.network_normals(source_id), anomalies=anomalies,
        correlations=correlate(findings, result, anomalies).correlations)


def _evidence_rows(evidence: NetworkEvidence, cited: list[str]) -> list[NetworkMetric]:
    """The measurements to show: those the report cites, plus anything notable, worst first."""
    wanted = set(cited)
    rows = [m for m in evidence.metrics if m.id in wanted or (m.status in ("elevated", "high") and m.current is not None)]
    rows.sort(key=lambda m: (_STATUS_RANK[m.status], m.category, m.id))
    return rows[:_MAX_EVIDENCE_ROWS]


def run_investigation(
    result: AnalysisResult, findings: list[Finding], history: PerformanceHistory, *, use_ai: bool = True,
    investigator_factory: Callable[[], NetworkInvestigator] = NetworkInvestigator,
) -> NetworkInvestigation:
    evidence = gather_evidence(result, findings, history)
    local = evidence.local
    base = dict(generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), local=local, disclosure=DISCLOSURE)
    local_view = dict(health=local.health, confidence=local.strength, evidence=_evidence_rows(evidence, []))
    if not use_ai:
        return NetworkInvestigation(status="local_only", ai=AiRun(requested=False), **base, **local_view)

    try:
        grounded, model, provider = investigator_factory().investigate(evidence)
    except AIProviderError as exc:
        logger.info("Network investigation: AI unavailable (%s)", exc.code)
        status = "local_only" if exc.code in ("missing_api_key", "ai_disabled") else "ai_failed"
        return NetworkInvestigation(status=status, ai=AiRun(requested=True, error_code=exc.code, error_message=exc.message), **base, **local_view)
    except Exception:  # an unexpected failure must not take the local result away
        logger.exception("Unexpected failure during the AI network investigation")
        return NetworkInvestigation(status="ai_failed", ai=AiRun(requested=True, error_code="unexpected", error_message="The AI analysis failed unexpectedly."),
                                    **base, **local_view)
    return NetworkInvestigation(
        status="completed", report=grounded.result, health=grounded.health, health_note=grounded.health_note, confidence=grounded.confidence,
        evidence=_evidence_rows(evidence, grounded.cited_ids), notes=grounded.notes, ai=AiRun(requested=True, provider=provider, model=model), **base)
