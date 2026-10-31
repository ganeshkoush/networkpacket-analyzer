"""Build a `ReportContent` from local analysis results, findings and (optional) AI output."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.ai.schemas import InvestigationReport, InvestigationResult
from app.config import settings
from app.detection.models import Finding
from app.detection.severity import Severity
from app.models.analysis import AnalysisResult
from app.models.report import (
    ReportAi,
    ReportCapture,
    ReportContent,
    ReportDomain,
    ReportFinding,
    ReportSource,
    ReportSummary,
    RecommendedAction,
)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")
BASE_LIMITATIONS = [
    "Findings are possibilities supported by the listed evidence, not confirmed incidents.",
    "Results reflect only the traffic contained in this capture; host-level activity and user intent cannot be established from it.",
]


def clean(value: Any, depth: int = 0) -> Any:
    """Strip control/bidi characters and bound sizes of packet-derived values (they are untrusted)."""
    if isinstance(value, str):
        value = _CONTROL.sub("", value)
        return value if len(value) <= 300 else value[:300] + "…"
    if depth > 4:
        return str(value)[:100]
    if isinstance(value, dict):
        return {clean(str(k)): clean(v, depth + 1) for k, v in list(value.items())[:60]}
    if isinstance(value, (list, tuple)):
        return [clean(v, depth + 1) for v in list(value)[:50]]
    return value


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


def ai_from_report(report: InvestigationReport) -> ReportAi:
    return ReportAi(status="completed", provider=report.provider, model=report.model, result=report.result, notes=report.notes)


def build_report(
    analysis: AnalysisResult,
    findings: list[Finding],
    *,
    source_kind: ReportSource,
    title: str | None = None,
    notes: str | None = None,
    ai: ReportAi | None = None,
    finding_ai: dict[str, InvestigationResult] | None = None,
    interface: str | None = None,
    now: datetime | None = None,
) -> ReportContent:
    now = now or datetime.now(timezone.utc)
    finding_ai = finding_ai or {}
    ai = ai or ReportAi(status="not_run", message="AI investigation was not requested.")
    m, ps, ips = analysis.metadata, analysis.packet_statistics, analysis.ip_statistics

    ordered = sorted(findings, key=lambda f: (f.severity.rank, f.confidence), reverse=True)
    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    highest = ordered[0].severity if ordered else None

    if ordered:
        headline = (f"Analysis of {ps.total_packets:,} packets over {m.duration_seconds:.1f} s produced {len(ordered)} "
                    f"possible finding(s); the highest severity is {highest.value}. These are possibilities that "
                    f"require investigation, not confirmed incidents.")
    else:
        headline = (f"Analysis of {ps.total_packets:,} packets over {m.duration_seconds:.1f} s produced no findings. "
                    f"This is not proof that the traffic is safe.")

    name = clean(m.file_name.replace("\\", "/").rsplit("/", 1)[-1])
    r_findings = [ReportFinding(
        id=f.id, type=f.type.value, severity=f.severity, confidence=round(f.confidence, 2),
        title=clean(f.title), description=clean(f.description), source_ip=f.source_ip, destination_ip=f.destination_ip,
        evidence=clean(f.evidence), investigation_steps=clean(f.reasoning), caveats=clean(f.caveats),
        recommendation=clean(f.recommendation), first_seen_iso=_iso(f.first_seen), last_seen_iso=_iso(f.last_seen),
        ai_assessment=finding_ai.get(f.id)) for f in ordered]

    actions: list[RecommendedAction] = []
    seen: set[str] = set()

    def add(text: str, priority: Severity | None, source: str, related: str | None) -> None:
        text = clean(text).strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            actions.append(RecommendedAction(action=text, priority=priority, source=source, related_finding=related))  # type: ignore[arg-type]

    for f in ordered:
        add(f.recommendation, f.severity, "detector", f.id)
    if ai.result:
        for step in ai.result.recommended_next_steps:
            add(step, highest, "ai", None)
    for fid, res in finding_ai.items():
        sev = next((f.severity for f in ordered if f.id == fid), None)
        for step in res.recommended_next_steps:
            add(step, sev, "ai", fid)

    limitations = list(BASE_LIMITATIONS)
    for res in ([ai.result] if ai.result else []) + list(finding_ai.values()):
        for lim in res.limitations:
            if lim not in limitations:
                limitations.append(clean(lim))

    return ReportContent(
        title=(clean(title).strip() if title and title.strip() else f"Investigation of {name}")[:200],
        investigation_timestamp=now, app_version=settings.version,
        capture=ReportCapture(
            source_kind=source_kind, name=name, capture_format=m.capture_format, size_bytes=m.file_size_bytes,
            sha256=m.sha256, packets=m.packets_read, duration_seconds=m.duration_seconds,
            first_packet_time_iso=_iso(m.first_packet_time), last_packet_time_iso=_iso(m.last_packet_time),
            interface=interface, warnings=clean(m.warnings[:10])),
        summary=ReportSummary(
            total_packets=ps.total_packets, total_bytes=ps.total_bytes, duration_seconds=m.duration_seconds,
            avg_packets_per_second=ps.avg_packets_per_second, peak_packets_per_second=ps.peak_packets_per_second,
            unique_source_ips=ips.unique_source_ips, unique_destination_ips=ips.unique_destination_ips,
            finding_count=len(ordered), severity_counts=counts, highest_severity=highest, headline=headline),
        protocols=analysis.protocol_statistics.distribution[:10], top_talkers=ips.top_talkers[:10],
        top_ports=analysis.port_statistics.top_destination_ports[:10],
        domains=[ReportDomain(domain=clean(d.domain), connections=d.connection_count, bytes_sent=d.total_bytes_sent,
                              bytes_received=d.total_bytes_received)
                 for d in analysis.domain_statistics.domains[:15] if d.connection_count],
        findings=r_findings,
        ai_investigation=ai, recommended_actions=actions, limitations=limitations,
        analyst_notes=clean(notes).strip() if notes and notes.strip() else None)
