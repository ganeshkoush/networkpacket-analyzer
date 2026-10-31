"""Domain / Web Activity dashboard data, assembled from an existing ``AnalysisResult``.

No packets are read and nothing is re-measured: domain activity (DomainAnalyzer), per-domain latency
(performance), connections and time series are joined, filtered, sorted and paged here so the UI only renders.

Health is a heuristic summary of measured latency/loss *indicators*, never a verdict on a site. Every rating
other than "good" lists the observations behind it, and "unknown" is used when nothing could be measured.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.models.analysis import AnalysisResult, DomainActivity, DomainPerformance, DomainSeries
from app.models.web_activity import (
    DomainConnection, Health, WebActivityList, WebActivitySummary, WebDomainDetail, WebDomainRow,
)


@dataclass(frozen=True)
class HealthThresholds:
    """All limits in one place. Each metric has a 'fair' (worth a look) and a 'poor' (clearly degraded) limit."""

    handshake_ms: tuple[float, float] = (100.0, 300.0)
    avg_rtt_ms: tuple[float, float] = (100.0, 300.0)
    p95_rtt_ms: tuple[float, float] = (250.0, 600.0)
    dns_ms: tuple[float, float] = (100.0, 500.0)
    retransmission_rate: tuple[float, float] = (0.01, 0.05)  # retransmitted segments / TCP packets
    reset_share: tuple[float, float] = (0.05, 0.25)  # connections with an RST / TCP connections
    min_tcp_packets_for_rate: int = 20
    min_connections_for_reset_share: int = 3


DEFAULT_THRESHOLDS = HealthThresholds()


def effective_thresholds() -> HealthThresholds:
    """The limits the user's Performance settings describe (the defaults above when unchanged)."""
    try:
        from app.services.effective_config import health_thresholds

        return health_thresholds()
    except Exception:
        return DEFAULT_THRESHOLDS
_RANK: dict[str, int] = {"unknown": 0, "good": 1, "fair": 2, "poor": 3}
NOTES = [
    "Domains are inferred from DNS lookups that preceded each connection, not read from the traffic itself.",
    "Health is a heuristic summary of measured latency and loss indicators (handshake, RTT, DNS, retransmissions, "
    "resets). It is not a verdict on a site; connection set-up time is never treated as response time.",
]


def _ms(x: float) -> str:
    return f"{x:.0f} ms"


def _pct(x: float) -> str:
    return f"{x:.1%}"


def assess_health(perf: DomainPerformance | None, dns_ms: float | None,
                  t: HealthThresholds | None = None) -> tuple[Health, list[str]]:
    """Worst rating across the measurable indicators, with the observations behind any non-good rating.

    "unknown" when none of the indicators could be measured (nothing is assumed good).
    ``t`` defaults to the 'slow' limits from the user's Performance settings.
    """
    t = t or effective_thresholds()
    checks: list[tuple[str, float | None, tuple[float, float], Callable[[float], str]]] = [
        ("TCP handshake (average)", perf.tcp_handshake_ms if perf else None, t.handshake_ms, _ms),
        ("Average RTT", perf.avg_rtt_ms if perf else None, t.avg_rtt_ms, _ms),
        ("P95 RTT", perf.p95_rtt_ms if perf else None, t.p95_rtt_ms, _ms),
        ("DNS lookup (median)", dns_ms, t.dns_ms, _ms),
    ]
    if perf and perf.tcp_packets >= t.min_tcp_packets_for_rate:
        checks.append(("Retransmission indicators", perf.retransmissions / perf.tcp_packets, t.retransmission_rate, _pct))
    if perf and perf.tcp_packets and perf.connections >= t.min_connections_for_reset_share:
        checks.append(("Connections with resets", perf.connections_reset / perf.connections, t.reset_share, _pct))

    worst, reasons, evaluated = "good", [], 0
    for label, value, (fair, poor), fmt in checks:
        if value is None:
            continue
        evaluated += 1
        level = "poor" if value >= poor else "fair" if value >= fair else "good"
        if level != "good":
            reasons.append(f"{label} {fmt(value)} is {'high' if level == 'poor' else 'elevated'} "
                           f"(threshold {fmt(poor if level == 'poor' else fair)})")
        if _RANK[level] > _RANK[worst]:
            worst = level
    return ("unknown", []) if evaluated == 0 else (worst, reasons)  # type: ignore[return-value]


def _dns_ms(perf: DomainPerformance | None) -> float | None:
    return perf.dns_latency_ms if perf else None


def build_rows(result: AnalysisResult) -> list[WebDomainRow]:
    from app.analysis.domain_visibility import is_hidden
    from app.services.app_settings import current_settings

    visibility = current_settings().domains
    perf = {d.domain: d for d in result.performance_statistics.domains}
    rows = []
    for a in result.domain_statistics.domains:
        if is_hidden(a.domain, a.resolved_ips, visibility):
            continue
        p = perf.get(a.domain)
        dns_ms = p.dns_latency_ms if p else None
        health, reasons = assess_health(p, dns_ms)
        rows.append(WebDomainRow(
            domain=a.domain, connections=a.connection_count, total_bytes=a.total_bytes_sent + a.total_bytes_received,
            bytes_sent=a.total_bytes_sent, bytes_received=a.total_bytes_received, first_seen=a.first_seen, last_seen=a.last_seen,
            dns_latency_ms=dns_ms, tcp_handshake_ms=p.tcp_handshake_ms if p else None,
            avg_rtt_ms=p.avg_rtt_ms if p else None, p95_rtt_ms=p.p95_rtt_ms if p else None,
            rtt_samples=p.rtt_samples if p else 0, health=health, health_reasons=reasons))
    return rows


SORTS = ("traffic", "connections", "dns", "handshake", "rtt", "p95", "health", "recent", "name")
_NUMERIC = {  # "slowest / largest first"; rows without the measurement go last
    "traffic": lambda r: r.total_bytes, "connections": lambda r: r.connections, "dns": lambda r: r.dns_latency_ms,
    "handshake": lambda r: r.tcp_handshake_ms, "rtt": lambda r: r.avg_rtt_ms, "p95": lambda r: r.p95_rtt_ms,
    "recent": lambda r: r.last_seen,
}


def query(result: AnalysisResult, *, search: str = "", sort: str = "traffic", health: str | None = None,
          include_dns_only: bool = False, offset: int = 0, limit: int = 50) -> WebActivityList:
    rows = build_rows(result)
    counts: dict[str, int] = {}
    for r in rows:
        if r.connections or include_dns_only:
            counts[r.health] = counts.get(r.health, 0) + 1
    needle = search.strip().lower()
    matching = [r for r in rows
                if (r.connections or include_dns_only) and (not needle or needle in r.domain)
                and (health is None or r.health == health)]
    if sort == "name":
        matching.sort(key=lambda r: r.domain)
    elif sort == "health":
        matching.sort(key=lambda r: (-_RANK[r.health], -r.total_bytes, r.domain))
    else:
        key = _NUMERIC[sort]
        matching.sort(key=lambda r: (key(r) is None, -(key(r) or 0), r.domain))
    summary = WebActivitySummary(
        total_domains=len(rows), domains_with_connections=sum(1 for r in rows if r.connections),
        health_counts=counts, notes=list(NOTES))
    return WebActivityList(summary=summary, total_matching=len(matching), offset=offset, limit=limit,
                           domains=matching[offset: offset + limit])


def build_detail(result: AnalysisResult, domain: str) -> WebDomainDetail | None:
    name = domain.strip().lower().rstrip(".")
    activity: DomainActivity | None = next((d for d in result.domain_statistics.domains if d.domain == name), None)
    if activity is None:
        return None
    perf_stats = result.performance_statistics
    perf = next((d for d in perf_stats.domains if d.domain == name), None)
    health, reasons = assess_health(perf, _dns_ms(perf))
    metrics = {m.connection_id: m for m in perf_stats.metrics}
    connections = []
    for c in result.connections:
        if c.domain != name:
            continue
        m = metrics.get(c.id)
        connections.append(DomainConnection(
            id=c.id, protocol=c.protocol, application_protocol=m.application_protocol if m else None,
            client_ip=c.client_ip, client_port=c.client_port, server_ip=c.server_ip, server_port=c.server_port,
            state=c.state, start_time=c.start_time, duration_seconds=c.duration_seconds, bytes=c.bytes, packets=c.packets,
            handshake_ms=c.tcp_handshake_time_ms, avg_rtt_ms=m.avg_rtt_ms if m else None, p95_rtt_ms=m.p95_rtt_ms if m else None,
            application_response_ms=m.application_response_ms if m else None,
            retransmissions=c.retransmissions, resets=c.resets,
            measurement_confidence=m.measurement_confidence if m else "UNAVAILABLE"))
    notes = list(NOTES)
    if len(connections) < activity.connection_count:
        notes.append(f"Showing the {len(connections)} largest of {activity.connection_count} connections; the analysis "
                     "keeps per-connection detail only for the top connections by bytes.")
    return WebDomainDetail(
        domain=name, health=health, health_reasons=reasons, overview=activity, performance=perf, connections=connections,
        connections_total=activity.connection_count, series=perf_stats.series.get(name, DomainSeries()), notes=notes)
