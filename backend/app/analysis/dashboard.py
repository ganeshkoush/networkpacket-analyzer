"""Aggregation for the Network Intelligence Dashboard.

A pure function of an ``AnalysisResult`` (+ findings and history anomalies): nothing is re-measured and no packets are read.
Every list is capped, so the response size does not grow with the capture.

Time ranges are measured back from the last packet of the capture ("Last 5 minutes" = the last five minutes *of this
capture*, not wall-clock). For a shorter range the per-domain latency is rebuilt from the per-connection samples that started
in the window; DNS latency from the lookups in it; traffic from the timeline bins in it. "Capture duration" uses the
capture-wide figures exactly.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass

from app.analysis.web_activity import DEFAULT_THRESHOLDS, HealthThresholds, assess_health, effective_thresholds
from app.detection.models import Finding
from app.models.analysis import AnalysisResult, Connection, DomainPerformance
from app.models.baseline import PerformanceAnomaly
from app.models.dashboard import (
    RANGE_LABELS, RANGE_SECONDS, ActivityItem, Dashboard, DashboardConnection, DashboardFinding, DashboardKpis, DashboardWindow,
    Deduction, HealthScore, RangeKey, SlowDomainRow, TimelineBin, TimelineMarker,
)
from app.models.web_activity import WebDomainRow

TOP_DOMAINS = 10
SLOWEST = 10
FINDINGS = 10
ANOMALIES = 10
ACTIVE = 20
SUSPICIOUS = 15
ACTIVITY = 15
MARKERS = 30
MAX_TIMELINE = 300
MIN_TCP_PACKETS = 20      # below this a retransmission rate is too noisy to score
MIN_ATTEMPTS = 5
_FINISHED = {"CLOSED", "RESET"}
UDP_ACTIVE_SECONDS = 30.0  # connectionless flows have no state: "active" means seen in the last seconds of the window
_SEVERITY_POINTS = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
_RATE_GUIDE = {"retrans": (0.02, 0.10), "failures": (0.10, 0.30)}   # capture-wide (fair, poor); same bands as the investigation


@dataclass
class _Perf:
    """Per-domain performance for the window, in the shape ``assess_health`` expects."""

    by_domain: dict[str, DomainPerformance]
    attempted: int = 0
    failed: int = 0


def _p95(values: list[float]) -> float | None:
    if len(values) < 2:
        return values[0] if values else None
    return statistics.quantiles(values, n=20, method="inclusive")[-1]


def _window(result: AnalysisResult, key: RangeKey) -> DashboardWindow:
    first, last = result.metadata.first_packet_time, result.metadata.last_packet_time
    label = RANGE_LABELS[key]
    if not result.packet_statistics.total_packets or first is None or last is None:
        return DashboardWindow(key=key, label=label, covers_whole_capture=True)
    span = RANGE_SECONDS[key]
    start = first if span is None else max(first, last - span)
    whole = start <= first
    note = None
    if span is not None and whole:
        note = f"The capture is shorter than this range ({last - first:.0f} s), so the whole capture is shown."
    return DashboardWindow(key=key, label=label, start=start, end=last, capture_start=first, capture_end=last,
                           covers_whole_capture=whole, note=note)


def _windowed_perf(result: AnalysisResult, w: DashboardWindow) -> _Perf:
    """Capture-wide per-domain performance, or (for a shorter range) rebuilt from the connections that started in the window."""
    ps = result.performance_statistics
    if w.covers_whole_capture or w.start is None:
        return _Perf({d.domain: d for d in ps.domains},
                     sum(d.tcp_connections_attempted for d in ps.domains), sum(d.tcp_connections_failed for d in ps.domains))
    groups: dict[str, list] = defaultdict(list)
    attempted = failed = 0
    for s in ps.flow_samples:
        if s.t < w.start:
            continue
        attempted += s.attempted
        failed += s.failed
        if s.domain:
            groups[s.domain].append(s)
    dns = {d.domain: d for d in ps.domains}  # DNS latency is per lookup, not per connection: keep the capture-wide value
    out: dict[str, DomainPerformance] = {}
    for domain, samples in groups.items():
        hs = [s.handshake_ms for s in samples if s.handshake_ms is not None]
        rtts = [(s.rtt_ms, s.rtt_samples) for s in samples if s.rtt_ms is not None and s.rtt_samples > 0]
        weight = sum(n for _, n in rtts)
        out[domain] = DomainPerformance(
            domain=domain, connections=len(samples), dns_latency_ms=dns[domain].dns_latency_ms if domain in dns else None,
            tcp_handshake_ms=sum(hs) / len(hs) if hs else None, handshake_samples=len(hs),
            avg_rtt_ms=sum(r * n for r, n in rtts) / weight if weight else None, p95_rtt_ms=_p95([r for r, _ in rtts]),
            rtt_samples=weight, retransmissions=sum(s.retransmissions for s in samples), tcp_packets=sum(s.packets for s in samples),
            resets=sum(s.reset for s in samples), connections_reset=sum(s.reset for s in samples),
            tcp_connections_attempted=sum(s.attempted for s in samples), tcp_connections_failed=sum(s.failed for s in samples))
    return _Perf(out, attempted, failed)


def _in_window(c: Connection, w: DashboardWindow) -> bool:
    return w.covers_whole_capture or w.start is None or c.end_time >= w.start


def _domain_rows(result: AnalysisResult, perf: _Perf, w: DashboardWindow, conns: list[Connection], th: HealthThresholds) -> list[WebDomainRow]:
    rows: list[WebDomainRow] = []
    if w.covers_whole_capture:
        for a in result.domain_statistics.domains:
            if not a.connection_count:
                continue
            p = perf.by_domain.get(a.domain)
            health, reasons = assess_health(p, p.dns_latency_ms if p else None, th)
            rows.append(WebDomainRow(
                domain=a.domain, connections=a.connection_count, total_bytes=a.total_bytes_sent + a.total_bytes_received,
                bytes_sent=a.total_bytes_sent, bytes_received=a.total_bytes_received, first_seen=a.first_seen, last_seen=a.last_seen,
                dns_latency_ms=p.dns_latency_ms if p else None, tcp_handshake_ms=p.tcp_handshake_ms if p else None,
                avg_rtt_ms=p.avg_rtt_ms if p else None, p95_rtt_ms=p.p95_rtt_ms if p else None, rtt_samples=p.rtt_samples if p else 0,
                health=health, health_reasons=reasons))
        return rows
    agg: dict[str, list[Connection]] = defaultdict(list)
    for c in conns:
        if c.domain:
            agg[c.domain].append(c)
    for domain, cs in agg.items():
        p = perf.by_domain.get(domain)
        health, reasons = assess_health(p, p.dns_latency_ms if p else None, th)
        sent, received = sum(c.bytes_client_to_server for c in cs), sum(c.bytes_server_to_client for c in cs)
        rows.append(WebDomainRow(
            domain=domain, connections=len(cs), total_bytes=sent + received, bytes_sent=sent, bytes_received=received,
            first_seen=min(c.start_time for c in cs), last_seen=max(c.end_time for c in cs),
            dns_latency_ms=p.dns_latency_ms if p else None, tcp_handshake_ms=p.tcp_handshake_ms if p else None,
            avg_rtt_ms=p.avg_rtt_ms if p else None, p95_rtt_ms=p.p95_rtt_ms if p else None, rtt_samples=p.rtt_samples if p else 0,
            health=health, health_reasons=reasons))
    return rows


def _pool(perf: _Perf, attr: str, weight: str) -> tuple[float | None, int]:
    items = [(getattr(d, attr), getattr(d, weight)) for d in perf.by_domain.values() if getattr(d, attr) is not None and getattr(d, weight) > 0]
    n = sum(w for _, w in items)
    return (sum(v * w for v, w in items) / n, n) if n else (None, 0)


def _dns(result: AnalysisResult, w: DashboardWindow) -> tuple[float | None, int]:
    ps = result.performance_statistics
    if w.covers_whole_capture or w.start is None:
        ms = result.dns_statistics.avg_response_ms
        return (ms, ps.summary.dns_lookups_timed or len(ps.lookup_samples)) if ms is not None else (None, 0)
    ms = [s.ms for s in ps.lookup_samples if s.t >= w.start]
    return (sum(ms) / len(ms), len(ms)) if ms else (None, 0)


def _traffic(result: AnalysisResult, w: DashboardWindow) -> tuple[int, int, list[TimelineBin]]:
    pts = [p for p in result.timeline if w.covers_whole_capture or w.start is None or p.start_time + p.interval_seconds > w.start]
    bins = [TimelineBin(start_time=p.start_time, interval_seconds=p.interval_seconds, packets=p.packets, bytes=p.bytes) for p in pts[-MAX_TIMELINE:]]
    if w.covers_whole_capture:
        return result.packet_statistics.total_bytes, result.packet_statistics.total_packets, bins
    return sum(b.bytes for b in bins), sum(b.packets for b in bins), bins


def _retrans(result: AnalysisResult, perf: _Perf) -> tuple[float | None, int]:
    packets = sum(d.tcp_packets for d in perf.by_domain.values())
    if packets:
        return sum(d.retransmissions for d in perf.by_domain.values()) / packets, packets
    return None, 0


def _score(k: DashboardKpis, perf: _Perf, findings: list[DashboardFinding], anomalies: int, th: HealthThresholds) -> HealthScore:
    deductions: list[Deduction] = []
    measured: list[str] = []
    missing: list[str] = []

    def ms_check(name: str, value: float | None, samples: int, band: tuple[float, float]) -> None:
        if value is None:
            missing.append(name)
            return
        measured.append(name)
        fair, poor = band
        if value >= poor:
            deductions.append(Deduction(reason=f"{name} {value:.0f} ms is high (>= {poor:.0f} ms)", points=20))
        elif value >= fair:
            deductions.append(Deduction(reason=f"{name} {value:.0f} ms is elevated (>= {fair:.0f} ms)", points=8))

    ms_check("TCP handshake", k.avg_handshake_ms, k.handshake_samples, th.handshake_ms)
    ms_check("Average RTT", k.avg_rtt_ms, k.rtt_samples, th.avg_rtt_ms)
    ms_check("DNS latency", k.dns_latency_ms, k.dns_samples, th.dns_ms)
    if k.retransmission_rate is not None and k.tcp_packets >= MIN_TCP_PACKETS:
        measured.append("Retransmission rate")
        fair, poor = _RATE_GUIDE["retrans"]
        r = k.retransmission_rate
        if r >= poor:
            deductions.append(Deduction(reason=f"Retransmission rate {r:.1%} is high (>= {poor:.0%})", points=25))
        elif r >= fair:
            deductions.append(Deduction(reason=f"Retransmission rate {r:.1%} is elevated (>= {fair:.0%})", points=10))
    else:
        missing.append("Retransmission rate")
    if perf.attempted >= MIN_ATTEMPTS:
        measured.append("Connection failures")
        rate = perf.failed / perf.attempted
        fair, poor = _RATE_GUIDE["failures"]
        if rate >= poor:
            deductions.append(Deduction(reason=f"{rate:.0%} of connection attempts failed (>= {poor:.0%})", points=20))
        elif rate >= fair:
            deductions.append(Deduction(reason=f"{rate:.0%} of connection attempts failed (>= {fair:.0%})", points=8))
    else:
        missing.append("Connection failures")

    f_points = 0
    for f in findings:
        pts = _SEVERITY_POINTS.get(f.severity.value, 0)
        if pts:
            f_points += pts
    if f_points:
        deductions.append(Deduction(reason=f"{len(findings)} security finding(s) in this range", points=min(30, f_points)))
    if anomalies:
        deductions.append(Deduction(reason=f"{anomalies} performance anomaly(ies) against this computer's history", points=min(12, 4 * anomalies)))

    if not measured and not findings and not anomalies:
        return HealthScore(basis="Nothing measurable in this range (no timing data and no findings), so no score is claimed.")
    score = max(0, 100 - sum(d.points for d in deductions))
    label = "Healthy" if score >= 80 else "Degraded" if score >= 50 else "Poor"
    basis = f"Measured: {', '.join(measured) or 'nothing from timing'}."
    if missing:
        basis += f" Not measurable here: {', '.join(missing)}."
    return HealthScore(score=score, label=label, deductions=deductions, basis=basis)  # type: ignore[arg-type]


def _finding_view(f: Finding) -> DashboardFinding:
    evidence = [f"{k}: {v}" for k, v in list(f.evidence.items())[:3] if isinstance(v, (str, int, float, bool))]
    return DashboardFinding(id=f.id, type=f.type.value if hasattr(f.type, "value") else str(f.type), title=f.title, severity=f.severity,
                            confidence=f.confidence, evidence=evidence, source_ip=f.source_ip, destination_ip=f.destination_ip,
                            first_seen=f.first_seen, last_seen=f.last_seen)


def _conn_view(c: Connection, finding_ids: list[str], reasons: list[str]) -> DashboardConnection:
    return DashboardConnection(
        id=c.id, protocol=c.protocol, client_ip=c.client_ip, client_port=c.client_port, server_ip=c.server_ip, server_port=c.server_port,
        domain=c.domain, state=c.state, bytes=c.bytes, start_time=c.start_time, end_time=c.end_time,
        handshake_ms=c.tcp_handshake_time_ms, retransmissions=c.retransmissions, finding_ids=finding_ids, reasons=reasons)


def build_dashboard(result: AnalysisResult, findings: list[Finding], anomalies: list[PerformanceAnomaly], key: RangeKey = "all", *,
                    source: str = "capture", thresholds: HealthThresholds | None = None) -> Dashboard:
    thresholds = thresholds or effective_thresholds()
    w = _window(result, key)
    if w.start is None:
        return Dashboard(source=source, empty=True, window=w, health=HealthScore(basis="This capture contains no packets."),  # type: ignore[arg-type]
                         kpis=DashboardKpis(), notes=["No packets to summarise."])

    perf = _windowed_perf(result, w)
    conns = [c for c in result.connections if _in_window(c, w)]
    rows = _domain_rows(result, perf, w, conns, thresholds)
    from app.analysis.domain_visibility import is_hidden
    from app.services.app_settings import current_settings

    visibility, resolved = current_settings().domains, {a.domain: a.resolved_ips for a in result.domain_statistics.domains}
    rows = [r for r in rows if not is_hidden(r.domain, resolved.get(r.domain, []), visibility)]
    visible = [f for f in findings if f.last_seen is None or w.covers_whole_capture or f.last_seen >= (w.start or 0)]
    visible.sort(key=lambda f: (-f.severity.rank, -f.confidence))
    fviews = [_finding_view(f) for f in visible]

    total_bytes, total_packets, bins = _traffic(result, w)
    hs, hs_n = _pool(perf, "tcp_handshake_ms", "handshake_samples")
    rtt, rtt_n = _pool(perf, "avg_rtt_ms", "rtt_samples")
    dns_ms, dns_n = _dns(result, w)
    rate, tcp_packets = _retrans(result, perf)
    active = [c for c in conns if (c.state or "") not in _FINISHED and (c.protocol == "TCP" or c.end_time >= (w.end or 0) - UDP_ACTIVE_SECONDS)]
    kpis = DashboardKpis(
        active_connections=len(active), connections_in_window=len(conns), domains_contacted=len(rows), total_bytes=total_bytes,
        total_packets=total_packets, avg_handshake_ms=hs, handshake_samples=hs_n, avg_rtt_ms=rtt, rtt_samples=rtt_n,
        dns_latency_ms=dns_ms, dns_samples=dns_n, retransmission_rate=rate, tcp_packets=tcp_packets,
        findings=len(visible), anomalies=len(anomalies))

    top = sorted(rows, key=lambda r: (-r.total_bytes, r.domain))[:TOP_DOMAINS]
    slow_pool = [r for r in rows if r.avg_rtt_ms is not None or r.tcp_handshake_ms is not None]
    slow_pool.sort(key=lambda r: (r.avg_rtt_ms is None, -(r.avg_rtt_ms or 0), -(r.tcp_handshake_ms or 0), r.domain))
    slowest = [SlowDomainRow(domain=r.domain, avg_rtt_ms=r.avg_rtt_ms, p95_rtt_ms=r.p95_rtt_ms, tcp_handshake_ms=r.tcp_handshake_ms,
                             rtt_samples=r.rtt_samples, status=r.health, reasons=r.health_reasons) for r in slow_pool[:SLOWEST]]

    # Suspicious = a connection one of whose endpoints a visible finding names (the same rule the network map uses).
    named: dict[str, list[str]] = defaultdict(list)
    for f in visible:
        for ip in (f.source_ip, f.destination_ip):
            if ip:
                named[ip].append(f.id)
    suspicious: list[DashboardConnection] = []
    for c in sorted(conns, key=lambda c: -c.bytes):
        ids = sorted({*named.get(c.client_ip, []), *named.get(c.server_ip, [])})
        if ids:
            suspicious.append(_conn_view(c, ids, [f"An endpoint is named by {len(ids)} finding(s): possible, requires investigation"]))
        if len(suspicious) >= SUSPICIOUS:
            break
    active_views = [_conn_view(c, [], []) for c in sorted(active, key=lambda c: -c.bytes)[:ACTIVE]]

    activity: list[ActivityItem] = []
    for f in visible:
        activity.append(ActivityItem(time=f.first_seen or f.last_seen or w.end or 0, kind="finding", text=f.title, severity=f.severity, ref=f.id))
    for a in anomalies:
        activity.append(ActivityItem(time=a.last_seen, kind="anomaly", text=f"{a.domain}: {a.label} is {a.deviation:+.0%} against its usual", severity=a.severity, ref=a.domain))
    for r in sorted(rows, key=lambda r: -r.first_seen)[:5]:
        activity.append(ActivityItem(time=r.first_seen, kind="domain", text=f"First contact with {r.domain}", ref=r.domain))
    activity.sort(key=lambda i: -i.time)

    markers = [TimelineMarker(time=f.first_seen, kind="finding", label=f.title, severity=f.severity) for f in visible if f.first_seen is not None]
    markers = markers[:MARKERS]

    notes = ["Domains are inferred from DNS lookups, not read from traffic.",
             "The health score is a quick heuristic summary with its deductions listed; run Investigate Network for the full analysis."]
    cs = result.connection_summary
    if cs.total_connections > cs.reported_connections:
        notes.append(f"Connection detail is kept for the {cs.reported_connections:,} largest of {cs.total_connections:,} connections; "
                     "connection counts here cover those.")
    if not w.covers_whole_capture:
        notes.append("For a shorter range, latency is rebuilt from connections that started in the range and traffic from the timeline; "
                     "per-domain bytes are the full byte counts of connections active in the range, and DNS latency per domain is capture-wide.")
    if result.performance_statistics.flow_sample_stride > 1:
        notes.append(f"Very large capture: timing is based on every {result.performance_statistics.flow_sample_stride}th connection.")
    if anomalies and not w.covers_whole_capture:
        notes.append("Performance anomalies compare the whole capture with its history and are not filtered by range.")
    if w.note:
        notes.append(w.note)

    return Dashboard(
        source=source, window=w, kpis=kpis, health=_score(kpis, perf, fviews, len(anomalies), thresholds),  # type: ignore[arg-type]
        top_domains=top, slowest_domains=slowest, findings=fviews[:FINDINGS], anomalies=anomalies[:ANOMALIES],
        suspicious_connections=suspicious, active_connections=active_views, recent_activity=activity[:ACTIVITY],
        timeline=bins, markers=markers, notes=notes)
