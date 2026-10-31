"""Local evidence for the "Investigate Network" experience: measurements, "normal" values, and a rule-based health rating.

Everything here is computed locally from results PacketMind already has (analysis, findings, history, correlations); no
packets are read and no AI is involved. The 11 areas covered: overall traffic, DNS latency, TCP handshake latency, RTT,
retransmissions, TCP resets, connection failures, domain performance, performance anomalies, security findings and the
historical baseline (plus HTTP response time where it is visible).

The rating is explainable and deliberately simple: a metric far above this computer's own usual value (or above generic
guidelines when there is no history yet) makes the network "Degraded" or "Poor", and a rating is only claimed when
something was actually measured. Security findings are not network *health* by themselves (a port scan is not a latency
problem); only availability-affecting ones (a SYN flood) lower the rating.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from app.ai.tools import sanitize
from app.analysis.web_activity import DEFAULT_THRESHOLDS, HealthThresholds, assess_health, effective_thresholds
from app.correlation.models import Correlation
from app.detection.models import Finding, FindingType
from app.models.analysis import AnalysisResult, DomainPerformance
from app.models.baseline import PerformanceAnomaly
from app.models.network_investigation import HEALTH_ORDER, Health, LocalAssessment, NetworkMetric

MAX_DOMAINS, MAX_ANOMALIES, MAX_FINDINGS, MAX_RELATED, MAX_HOTSPOTS = 15, 10, 10, 8, 5
MIN_BASELINE_CAPTURES = 5
_RELATIVE_ELEVATED, _RELATIVE_HIGH = 1.5, 2.5          # current / normal
_ABS_FLOOR = {"ms": (10.0, 20.0), "%": (0.01, 0.03)}   # smallest change worth calling elevated / high
_AVAILABILITY_FINDINGS = {FindingType.SYN_FLOOD}
# Capture-wide guideline bands (fair, poor) for rates; the ms bands come from the domain health thresholds. These are looser
# than the per-domain ones: a few percent of retransmissions across a whole capture is worth noting, not alarming.
_RATE_GUIDE = {"retrans": (0.02, 0.10), "failures": (0.10, 0.30), "resets": (0.20, 0.50)}


@dataclass
class NetworkEvidence:
    metrics: list[NetworkMetric]
    local: LocalAssessment
    bundle: dict[str, Any]                                   # what the model may see (sanitised, bounded)
    citable: dict[str, str] = field(default_factory=dict)    # id -> kind: the only ids the model may cite
    ips: set[str] = field(default_factory=set)


# --------------------------------------------------------------------- measuring
def _pooled(items: list, value: str, weight: str) -> tuple[float | None, int]:
    pairs = [(getattr(i, value), getattr(i, weight)) for i in items if getattr(i, value) is not None and getattr(i, weight) > 0]
    n = sum(w for _, w in pairs)
    return ((sum(v * w for v, w in pairs) / n) if n else None), n


def _guide(key: str, th: HealthThresholds) -> tuple[float, float] | None:
    return {"handshake": th.handshake_ms, "rtt": th.avg_rtt_ms, "p95": th.p95_rtt_ms, "dns": th.dns_ms}.get(key) or _RATE_GUIDE.get(key)


def _status(key: str, current: float | None, normal: float | None, th: HealthThresholds) -> tuple[str, str | None]:
    """("ok" | "elevated" | "high" | "unmeasured", note). History wins over generic guidelines when it exists."""
    if current is None:
        return "unmeasured", None
    absolute = _guide(key, th)
    if normal is None:
        if absolute is None:
            return "ok", None
        fair, poor = absolute
        return ("high" if current >= poor else "elevated" if current >= fair else "ok"), "no history yet: compared with general guidelines"
    unit = "%" if key in ("retrans", "resets", "failures") else "ms"
    low, high = _ABS_FLOOR[unit]
    delta = current - normal
    ratio = current / normal if normal > 0 else float("inf")
    if ratio >= _RELATIVE_HIGH and delta >= high:
        return "high", None
    if ratio >= _RELATIVE_ELEVATED and delta >= low:
        return "elevated", None
    note = "already high compared with general guidelines, but in line with this computer's history" if absolute and current >= absolute[1] else None
    return "ok", note


def _relative(current: float | None, normal: float | None) -> float | None:
    return round((current - normal) / normal, 4) if current is not None and normal else None


def build_network_evidence(
    result: AnalysisResult, findings: list[Finding], *, normals: tuple[int, dict[str, float], dict[str, int]] = (0, {}, {}),
    anomalies: list[PerformanceAnomaly] | None = None, correlations: list[Correlation] | None = None,
    thresholds: HealthThresholds | None = None,
) -> NetworkEvidence:
    thresholds = thresholds or effective_thresholds()
    sources, normal, _ = normals
    have_baseline = bool(normal)
    perf, doms, flows = result.performance_statistics, result.performance_statistics.domains, result.performance_statistics.flow_samples
    meta, ps, tcp, dns, cs = result.metadata, result.packet_statistics, result.tcp_statistics, result.dns_statistics, result.connection_summary
    metrics: list[NetworkMetric] = []

    def add(mid: str, category, label: str, unit, current, *, normal_value=None, samples=0, status=None, note=None, key=None) -> None:
        st, auto_note = ("info", None) if key is None else _status(key, current, normal_value, thresholds)
        metrics.append(NetworkMetric(
            id=mid, category=category, label=label, unit=unit, current=None if current is None else round(float(current), 6),
            normal=None if normal_value is None else round(float(normal_value), 6), change=_relative(current, normal_value),
            status=status or st, samples=samples, note=note or auto_note))

    # ---- 1 overall traffic
    add("traffic.packets", "traffic", "Packets captured", "packets", ps.total_packets, samples=ps.total_packets)
    add("traffic.bytes", "traffic", "Bytes captured", "bytes", ps.total_bytes)
    add("traffic.duration", "traffic", "Capture duration", "seconds", meta.duration_seconds)
    add("traffic.rate", "traffic", "Average packet rate", "packets/s", ps.avg_packets_per_second,
        note=f"peak {ps.peak_packets_per_second:,} packets/s" if ps.peak_packets_per_second else None)

    # ---- 2 DNS latency
    dns_ms, dns_n = _pooled(doms, "dns_latency_ms", "dns_lookups")
    if dns_ms is None and perf.lookup_samples:
        dns_ms, dns_n = statistics.median(s.ms for s in perf.lookup_samples), len(perf.lookup_samples)
    add("dns.latency", "dns", "DNS lookup time", "ms", dns_ms, normal_value=normal.get("dns_ms"), samples=dns_n, key="dns")
    answered_share = dns.unanswered_queries / dns.total_queries if dns.total_queries else None
    unanswered_status = None if answered_share is None else "high" if answered_share >= 0.3 else "elevated" if answered_share >= 0.1 else "ok"
    add("dns.unanswered", "dns", "DNS queries without an answer", "%", answered_share, samples=dns.total_queries, status=unanswered_status)

    # ---- 3 TCP handshake latency
    hs, hs_n = _pooled(doms, "tcp_handshake_ms", "handshake_samples")
    if hs is None:
        timed = [f.handshake_ms for f in flows if f.handshake_ms is not None]
        hs, hs_n = (statistics.fmean(timed), len(timed)) if timed else (None, 0)
    add("handshake.time", "handshake", "TCP handshake time (connection set-up)", "ms", hs, normal_value=normal.get("handshake_ms"), samples=hs_n, key="handshake")

    # ---- 4 RTT
    rtt, rtt_n = _pooled(doms, "avg_rtt_ms", "rtt_samples")
    if rtt is None:
        rs = [(f.rtt_ms, f.rtt_samples) for f in flows if f.rtt_ms is not None and f.rtt_samples]
        rtt_n = sum(w for _, w in rs)
        rtt = sum(v * w for v, w in rs) / rtt_n if rtt_n else None
    p95, _ = _pooled(doms, "p95_rtt_ms", "rtt_samples")
    add("rtt.avg", "rtt", "Average round-trip time", "ms", rtt, normal_value=normal.get("avg_rtt_ms"), samples=rtt_n, key="rtt")
    add("rtt.p95", "rtt", "95th-percentile round-trip time", "ms", p95, normal_value=normal.get("p95_rtt_ms"), samples=rtt_n, key="p95")

    # ---- 5 retransmissions
    # Domain-attributed figures first: they are the same basis as the history "normal". Then per-connection samples, then capture-wide TCP counts.
    packets_d, retrans_d = sum(d.tcp_packets for d in doms), sum(d.retransmissions for d in doms)
    packets_f, retrans_f = sum(f.packets for f in flows), sum(f.retransmissions for f in flows)
    if packets_d:
        rate, rate_n = retrans_d / packets_d, packets_d
    elif packets_f:
        rate, rate_n = retrans_f / packets_f, packets_f
    elif tcp.retransmissions.sequence_bearing_segments:
        rate, rate_n = tcp.retransmissions.retransmission_rate, tcp.retransmissions.sequence_bearing_segments
    else:
        rate, rate_n = None, 0
    add("retrans.rate", "retransmissions", "Retransmission rate", "%", rate, normal_value=normal.get("retransmission_rate"), samples=rate_n, key="retrans")
    add("retrans.segments", "retransmissions", "Retransmitted TCP segments", "count", tcp.retransmissions.retransmitted_segments, samples=tcp.retransmissions.sequence_bearing_segments,
        note="a heuristic indicator of loss, not a measurement of it")

    # ---- 6 TCP resets
    rst_share = tcp.rst_packets / tcp.total_packets if tcp.total_packets else None
    add("resets.share", "resets", "TCP packets that were resets", "%", rst_share, samples=tcp.total_packets, key="resets")
    tcp_conns = cs.by_protocol.get("TCP", 0)
    add("resets.connections", "resets", "TCP connections that saw a reset", "%", (cs.tcp_with_rst / tcp_conns) if tcp_conns else None, samples=tcp_conns, key="resets")

    # ---- 7 connection failures
    attempted, failed = sum(d.tcp_connections_attempted for d in doms), sum(d.tcp_connections_failed for d in doms)
    if not attempted:
        attempted, failed = sum(1 for f in flows if f.attempted), sum(1 for f in flows if f.failed)
    add("failures.rate", "failures", "Connection attempts that failed", "%", (failed / attempted) if attempted else None, normal_value=normal.get("failure_rate"),
        samples=attempted, key="failures", note="a SYN that got no answer or was reset during the handshake; a capture ending mid-handshake can look like this")

    # ---- HTTP response time (only visible cleartext HTTP)
    resp, resp_n = _pooled(doms, "application_response_ms", "application_response_samples")
    add("response.http", "response", "HTTP response time (cleartext only)", "ms", resp, normal_value=normal.get("response_ms"), samples=resp_n,
        note="HTTPS response time is not visible")

    # ---- 8 domain performance
    rows = _domain_rows(doms, thresholds)
    degraded_domains = sum(1 for r in rows if r["health"] in ("fair", "poor"))
    add("domains.degraded", "domains", "Domains rated fair or poor", "count", degraded_domains, samples=len(rows),
        status="high" if any(r["health"] == "poor" for r in rows) else "elevated" if degraded_domains else "ok" if rows else "unmeasured")

    # ---- 9 performance anomalies (vs this computer's history)
    anomalies = sorted(anomalies or [], key=lambda a: (-a.severity.rank, -a.confidence))
    add("anomalies.count", "anomalies", "Performance anomalies vs history", "count", len(anomalies),
        status="high" if any(a.severity.rank >= 3 for a in anomalies) else "elevated" if anomalies else ("ok" if have_baseline else "unmeasured"),
        note=None if have_baseline else "no baseline yet, so nothing can be compared with history")

    # ---- 10 security findings
    sev = {s: sum(1 for f in findings if f.severity.value == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    add("findings.count", "findings", "Security findings", "count", len(findings), note=", ".join(f"{n} {s.lower()}" for s, n in sev.items() if n) or None)

    # ---- 11 historical baseline
    add("baseline.captures", "baseline", "Earlier captures used as 'normal'", "count", sources,
        status="ok" if have_baseline else "unmeasured",
        note=None if have_baseline else f"a baseline needs at least {MIN_BASELINE_CAPTURES} earlier captures")

    local = _assess(metrics, findings, anomalies, sources, have_baseline, thresholds)
    bundle, citable, ips = _bundle(result, findings, metrics, local, rows, anomalies, correlations or [], flows, tcp)
    return NetworkEvidence(metrics=metrics, local=local, bundle=bundle, citable=citable, ips=ips)


# --------------------------------------------------------------------- domains
def _domain_rows(doms: list[DomainPerformance], th: HealthThresholds) -> list[dict[str, Any]]:
    rows = []
    for d in doms:
        health, reasons = assess_health(d, d.dns_latency_ms, th)
        rows.append({"id": f"domain:{d.domain}", "domain": d.domain, "health": health, "reasons": reasons[:2], "connections": d.connections,
                     "tcp_handshake_ms": d.tcp_handshake_ms, "avg_rtt_ms": d.avg_rtt_ms, "p95_rtt_ms": d.p95_rtt_ms, "dns_ms": d.dns_latency_ms,
                     "retransmission_rate": round(d.retransmissions / d.tcp_packets, 4) if d.tcp_packets else None, "rtt_samples": d.rtt_samples})
    rank = {"poor": 0, "fair": 1, "good": 2, "unknown": 3}
    rows.sort(key=lambda r: (rank[r["health"]], -r["connections"]))
    return rows


# --------------------------------------------------------------------- the local rating
_KEY_OF = {"handshake.time": "handshake", "rtt.avg": "rtt", "rtt.p95": "p95", "dns.latency": "dns", "retrans.rate": "retrans", "failures.rate": "failures",
           "resets.share": "resets"}


def _assess(metrics: list[NetworkMetric], findings: list[Finding], anomalies: list[PerformanceAnomaly], sources: int, have_baseline: bool,
            th: HealthThresholds = DEFAULT_THRESHOLDS) -> LocalAssessment:
    by_id = {m.id: m for m in metrics}
    key = [by_id[i] for i in ("handshake.time", "rtt.avg", "rtt.p95", "dns.latency", "retrans.rate", "failures.rate", "resets.share", "response.http") if i in by_id]
    measured = [m for m in key if m.current is not None]
    reasons: list[str] = []
    health: Health = "Unknown"
    if measured:
        health = "Healthy"
        for m in measured:
            if m.status in ("elevated", "high"):
                # "Degraded": clearly worse than usual. "Poor": that AND bad in absolute terms (or no history to call it usual).
                guide = _guide(_KEY_OF.get(m.id, ""), th)
                poor = m.status == "high" and (m.normal is None or (guide is not None and m.current is not None and m.current >= guide[1]))
                health = "Poor" if poor else (health if health == "Poor" else "Degraded")
                vs = f" against a usual {_fmt(m.normal, m.unit)}" if m.normal is not None else ""
                reasons.append(f"{m.label} is {_fmt(m.current, m.unit)}{vs} ({'well above' if m.status == 'high' else 'above'} normal).")
    if anomalies and health in ("Healthy", "Unknown"):
        health = "Degraded"
    if anomalies:
        reasons.append(f"{len(anomalies)} performance anomal{'y' if len(anomalies) == 1 else 'ies'} against this computer's history.")
    availability = [f for f in findings if f.type in _AVAILABILITY_FINDINGS]
    if availability:
        health = health if HEALTH_ORDER[health] >= HEALTH_ORDER["Degraded"] else "Degraded"
        reasons.append(f"A possible availability problem was detected ({availability[0].title}).")
    if health == "Unknown":
        reasons.append("Not enough latency, loss or connection measurements were captured to rate network health.")

    rtt_n = by_id["rtt.avg"].samples
    strong = have_baseline and (rtt_n >= 100 or by_id["handshake.time"].samples >= 20)
    medium = have_baseline or rtt_n >= 30 or by_id["handshake.time"].samples >= 10
    strength = "High" if strong else "Medium" if medium else "Low"
    why = (f"{sources} earlier captures give a baseline and there are {rtt_n:,} RTT samples." if strong else
           ("There is either a history baseline or a reasonable number of samples, but not both." if medium else
            "No history baseline yet and few latency samples, so the rating rests on general guidelines."))
    if health == "Unknown":
        strength, why = "Low", "Nothing was measurable."
    return LocalAssessment(health=health, reasons=reasons[:8], strength=strength, strength_reason=why, earlier_captures=sources, metrics=metrics)


def _fmt(v: float | None, unit: str) -> str:
    if v is None:
        return "not measured"
    return f"{v:.1%}" if unit == "%" else f"{v:.0f} ms" if unit == "ms" else f"{v:,.0f}"


# --------------------------------------------------------------------- what the model may see
def _bundle(result, findings, metrics, local, rows, anomalies, correlations, flows, tcp):
    ps, meta = result.packet_statistics, result.metadata
    protocols = [{"protocol": p.protocol, "percent_of_packets": p.percent_of_packets} for p in result.protocol_statistics.distribution[:5]]
    talkers = [{"ip": t.ip, "packets": t.total_packets, "bytes": t.total_bytes} for t in result.ip_statistics.top_talkers[:5]]
    destinations: dict[tuple[str, int | None], list[int]] = {}
    for f in flows:
        if f.attempted:
            d = destinations.setdefault((f.server_ip, f.server_port), [0, 0])
            d[0] += 1
            d[1] += 1 if f.failed else 0
    failing = sorted(((k, v) for k, v in destinations.items() if v[1]), key=lambda kv: -kv[1][1])[:MAX_HOTSPOTS]
    hotspots = [{"source": f"{x.src_ip}:{x.src_port}", "destination": f"{x.dst_ip}:{x.dst_port}", "retransmissions": x.retransmissions, "segments": x.segments}
                for x in tcp.retransmissions.top_flows[:MAX_HOTSPOTS]]
    citable: dict[str, str] = {m.id: "metric" for m in metrics}
    findings_out = [{"id": f"finding:{f.id}", "type": f.type.value, "severity": f.severity.value, "confidence": f.confidence, "title": f.title,
                     "source_ip": f.source_ip, "destination_ip": f.destination_ip} for f in findings[:MAX_FINDINGS]]
    anomalies_out = [{"id": f"anomaly:{a.id}", "domain": a.domain, "metric": a.label, "typical": round(a.baseline, 4), "now": round(a.current_value, 4),
                      "change": a.deviation, "severity": a.severity.value, "confidence": a.confidence_label} for a in anomalies[:MAX_ANOMALIES]]
    related_out = [{"id": f"related:{c.id}", "finding": f"finding:{c.finding_id}", "relationship": c.relationship, "performance_change": c.headline,
                    "timing": c.temporal_relation, "shared_ips": c.shared_ips[:4], "confidence": c.confidence_label} for c in correlations[:MAX_RELATED]]
    domains_out = rows[:MAX_DOMAINS]
    for group, kind in ((findings_out, "finding"), (anomalies_out, "anomaly"), (related_out, "related"), (domains_out, "domain")):
        citable.update({g["id"]: kind for g in group})
    bundle = {
        "capture": {"packets": ps.total_packets, "bytes": ps.total_bytes, "duration_seconds": meta.duration_seconds, "protocol_mix": protocols, "top_talkers": talkers},
        "packetmind_local_assessment": {"health": local.health, "reasons": local.reasons, "evidence_strength": local.strength, "why": local.strength_reason,
                                      "earlier_captures_used_as_normal": local.earlier_captures},
        "metrics": [m.model_dump(exclude_none=True) for m in metrics],
        "domains": domains_out, "anomalies": anomalies_out, "related_events": related_out, "findings": findings_out,
        "destinations_with_failed_connections": [{"destination": f"{ip}:{port}", "attempts": a, "failed": b} for (ip, port), (a, b) in failing],
        "retransmission_hotspots": hotspots, "citable_ids": sorted(citable),
    }
    bundle = sanitize(bundle)
    ips = {m for m in _all_ips(bundle)}
    return bundle, citable, ips


def _all_ips(value: Any) -> set[str]:
    import json

    from app.ai.investigator import _ips_in

    return _ips_in(json.dumps(value, default=str))
