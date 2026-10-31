"""Correlation engine: links security findings to performance changes that are *potentially related*.

For each finding there are up to three kinds of evidence, tried in this order per rule:

1. **Time window** (findings with first/last seen): the metric in the finding's window (+ a small pad) is compared with
   the *rest of the same capture*, restricted to the finding's scope (the targeted host / the DNS client) and with the
   flagged source's own traffic left out where it would make the comparison circular. Works on a domain's very first
   capture; no history is needed.
2. **Same connections** (network-wide findings without a window, e.g. high retransmissions or resets): connections that
   show the security indicator are compared with those that do not.
3. **Capture level**: an anomaly of the same metric against the domain's *history* (``baseline.py``). Timing is only
   known to be the same capture, so confidence is lower.

Correlation is not causation: every record says "Potentially related", carries its evidence and caveats, and confidence
is capped well below certainty. Nothing here reads packets; it works on the analysis result's bounded flow/lookup samples.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from app.analysis.baseline import DEFAULT_CONFIG, BaselineConfig, confidence_label, severity_for
from app.correlation.measures import Comparison, Gates, compare_latency, compare_proportions, compare_rates, find_burst
from app.correlation.models import Correlation, CorrelationType, TemporalRelation
from app.detection.models import Finding, FindingType
from app.detection.severity import ConfidenceBounds, confidence_from_score, ramp, weighted_score
from app.models.analysis import AnalysisResult, FlowSample, LookupSample
from app.models.baseline import PerformanceAnomaly

_DNS_TYPES = {FindingType.DNS_HIGH_NXDOMAIN, FindingType.DNS_DGA_LIKE, FindingType.DNS_TUNNELING_LIKE, FindingType.DNS_EXCESSIVE_QUERIES}

GENERAL_CAVEAT = ("Correlation is not proof of causation: the two events share a time window and scope, which can also "
                  "happen by coincidence or through a common underlying cause.")


@dataclass(frozen=True)
class CorrelationConfig:
    pad_fraction: float = 0.5     # window padding as a share of the finding's duration ...
    pad_min_seconds: float = 5.0  # ... within these limits
    pad_max_seconds: float = 120.0
    handshake: Gates = Gates(min_in=3, min_out=5, min_abs=10.0, min_ratio=1.25)
    rtt: Gates = Gates(min_in=3, min_out=5, min_abs=10.0, min_ratio=1.25)
    response: Gates = Gates(min_in=3, min_out=5, min_abs=20.0, min_ratio=1.25)
    dns: Gates = Gates(min_in=3, min_out=5, min_abs=10.0, min_ratio=1.25)
    attempts: Gates = Gates(min_in=10, min_out=5, min_abs=0.5, min_ratio=1.5)   # connection attempts per second
    failures: Gates = Gates(min_in=5, min_out=10, min_abs=0.05, min_ratio=1.0)  # failed share of attempts
    bounds: ConfidenceBounds = field(default_factory=lambda: ConfidenceBounds(floor=0.25, ceiling=0.85))
    baseline: BaselineConfig = DEFAULT_CONFIG


DEFAULT_CORRELATION_CONFIG = CorrelationConfig()


@dataclass
class CorrelationReport:
    correlations: list[Correlation] = field(default_factory=list)
    not_evaluated: list[str] = field(default_factory=list)   # a rule applied but there was too little data
    no_related_change: list[str] = field(default_factory=list)  # checked: nothing unusual in the related metric
    flow_data_thinned: bool = False


@dataclass
class _Ctx:
    analysis: AnalysisResult
    cfg: CorrelationConfig
    history: list[PerformanceAnomaly]
    flows: list[FlowSample]
    lookups: list[LookupSample]
    stride: int
    t0: float
    t1: float
    ip_domains: dict[str, list[str]]

    @property
    def span(self) -> float:
        return max(self.t1 - self.t0, 0.0)


@dataclass
class _Hit:
    """A rule's result before it is turned into a record."""

    corr_type: CorrelationType
    metric: str
    label: str
    unit: str
    comparison: Comparison
    gates: Gates
    scope_ips: list[str]
    scope: str  # "host" | "network"
    mode: str   # "window" | "connections"
    headline: str
    evidence: list[str]
    caveats: list[str]
    shared_ips: list[str]
    penalty: float = 0.0
    window: tuple[float, float] | None = None   # padded window actually compared
    event: tuple[float, float] | None = None    # the security event's own span (the finding's, or its localised burst)


def _sentence_case_tail(text: str) -> str:
    """Lowercase the first letter to continue a sentence, unless it starts an acronym ("TCP", "DNS", "HTTP")."""
    return text if text[:2].isupper() else text[:1].lower() + text[1:]


def _fmt_ts(t: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")


def _fmt(unit: str, v: float) -> str:
    return f"{v:.0f} ms" if unit == "ms" else f"{v:.1%}" if unit == "%" else f"{v:.1f}/s"


# --------------------------------------------------------------------- helpers
def _event_span(f: Finding, burst_times: list[float] | None = None) -> tuple[float, float] | None:
    """The finding's own time span, narrowed to the dense burst of ``burst_times`` when there is one."""
    if f.first_seen is None or f.last_seen is None:
        return None
    if burst_times:
        burst = find_burst(burst_times, f.first_seen, f.last_seen)
        if burst:
            return burst
    return f.first_seen, f.last_seen


def _pad(span: tuple[float, float], cfg: CorrelationConfig) -> tuple[float, float]:
    pad = min(max(cfg.pad_fraction * (span[1] - span[0]), cfg.pad_min_seconds), cfg.pad_max_seconds)
    return span[0] - pad, span[1] + pad


def _window(f: Finding, cfg: CorrelationConfig, t0: float, t1: float) -> tuple[float, float] | None:
    span = _event_span(f)
    return _pad(span, cfg) if span else None


def _split(samples: list[tuple[float, float]], w: tuple[float, float]):
    inside = [s for s in samples if w[0] <= s[0] <= w[1]]
    outside = [s for s in samples if not (w[0] <= s[0] <= w[1])]
    return inside, outside


def _stride_note(ctx: _Ctx) -> list[str]:
    return [f"Connection data was thinned to 1 in {ctx.stride} for this large capture, so counts are a uniform sample."] if ctx.stride > 1 else []


# --------------------------------------------------------------------- rules (return a hit, or a reason string)
def _rule_syn_flood(f: Finding, ctx: _Ctx):
    target = f.destination_ip
    if not target:
        return "the finding has no single target host to measure"
    attempts = [s.t for s in ctx.flows if s.server_ip == target and s.attempted]
    event = _event_span(f, attempts)
    if event is None:
        return "the finding has no time window"
    w = _pad(event, ctx.cfg)
    skip = {f.source_ip} if f.source_ip else set()
    samples = [(s.t, s.handshake_ms) for s in ctx.flows if s.server_ip == target and s.handshake_ms is not None and s.client_ip not in skip]
    inside, outside = _split(samples, w)
    comp = compare_latency(inside, outside, ctx.cfg.handshake, ctx.cfg.baseline)
    if comp.status != "significant":
        return comp
    ev = [f"TCP handshakes to {target} had a median of {comp.inside:.0f} ms across {comp.n_in} consecutive slow handshakes between "
          f"{_fmt_ts(comp.onset or w[0])} and {_fmt_ts(comp.last or w[1])} UTC (searched {_fmt_ts(w[0])}–{_fmt_ts(w[1])}), against "
          f"{comp.outside:.0f} ms over {comp.n_out} handshakes in the rest of the capture: {comp.ratio:.1f}x."]
    if skip:
        ev.append(f"Handshakes from {f.source_ip}, the source named in the finding, were left out of both sides.")
    if event != (f.first_seen, f.last_seen):
        ev.append(f"The SYN burst itself ran from {_fmt_ts(event[0])} to {_fmt_ts(event[1])} UTC (found from per-second connection attempts); "
                  f"the finding's own first/last-seen also covers ordinary traffic to the target.")
    return _Hit(CorrelationType.SYN_FLOOD_HANDSHAKE_LATENCY, "tcp_handshake_ms", "TCP handshake latency", "ms", comp, ctx.cfg.handshake,
                [target], "host", "window", _latency_headline("TCP handshake latency", "ms", comp), ev,
                ["Legitimate load spikes, a busy or restarting server, or path congestion can also slow handshakes.",
                 "Only completed handshakes can be timed; connections that never completed are not in this comparison."],
                [target], window=w, event=event)


def _rule_port_scan(f: Finding, ctx: _Ctx):
    target = f.destination_ip
    if not target:
        return "the scan touched several hosts, so there is no single target to measure"
    w = _window(f, ctx.cfg, ctx.t0, ctx.t1)
    if w is None:
        return "the finding has no time window"
    w = (max(w[0], ctx.t0), min(w[1], ctx.t1))
    span_in = w[1] - w[0]
    times = [s.t for s in ctx.flows if s.server_ip == target and s.attempted]
    inside = [t for t in times if w[0] <= t <= w[1]]
    outside = [t for t in times if not (w[0] <= t <= w[1])]
    comp = compare_rates(inside, span_in, outside, ctx.span - span_in, ctx.cfg.attempts, ctx.cfg.baseline)
    if comp.status != "significant":
        return comp
    own = sum(1 for s in ctx.flows if s.server_ip == target and s.attempted and w[0] <= s.t <= w[1] and s.client_ip == f.source_ip)
    share = own / len(inside) if inside else 0.0
    scale = ctx.stride
    ev = [f"Connection attempts to {target} ran at {comp.inside * scale:.1f}/s between {_fmt_ts(w[0])} and {_fmt_ts(w[1])} UTC "
          f"({comp.n_in * scale} attempts) against {comp.outside * scale:.2f}/s in the rest of the capture ({comp.n_out * scale} attempts): {comp.ratio:.1f}x.",
          f"{share:.0%} of the attempts in the window came from the flagged source {f.source_ip}."
          + (" The rise is therefore almost entirely the flagged source's own probing." if share >= 0.95 else "")]
    ev += _stride_note(ctx)
    return _Hit(CorrelationType.PORT_SCAN_CONNECTION_ATTEMPTS, "connection_attempts_per_s", "Connection attempts", "/s", comp, ctx.cfg.attempts,
                [target], "host", "window",
                f"Connection attempts to {target} rose {comp.ratio:.1f}x ({comp.outside * scale:.2f}/s → {comp.inside * scale:.1f}/s)", ev,
                ["The scan's own probes are included in this count, so this largely restates the scan; it is weak evidence of any wider effect."],
                [x for x in (f.source_ip, target) if x], penalty=0.5 * share, window=w, event=(f.first_seen, f.last_seen))


def _rule_dns(f: Finding, ctx: _Ctx):
    """Resolver latency in the finding's window: other clients on the same resolver first, the flagged client's own lookups second."""
    client = f.source_ip
    if not client:
        return "the finding has no client host to measure"
    w = _window(f, ctx.cfg, ctx.t0, ctx.t1)
    if w is None:
        return "the finding has no time window"
    mine = [s for s in ctx.lookups if s.client_ip == client]
    resolvers = sorted({s.server_ip for s in mine})
    others = [s for s in ctx.lookups if s.server_ip in resolvers and s.client_ip != client]
    results = []
    for who, group in (("other clients on the same resolver", others), (f"{client}'s own lookups", mine)):
        inside, outside = _split([(s.t, s.ms) for s in group], w)
        comp = compare_latency(inside, outside, ctx.cfg.dns, ctx.cfg.baseline)
        if comp.status == "significant":
            ev = [f"DNS lookups by {who} took a median of {comp.inside:.0f} ms across {comp.n_in} consecutive slow lookups between "
                  f"{_fmt_ts(comp.onset or w[0])} and {_fmt_ts(comp.last or w[1])} UTC (searched {_fmt_ts(w[0])}–{_fmt_ts(w[1])}), against "
                  f"{comp.outside:.0f} ms over {comp.n_out} lookups in the rest of the capture: {comp.ratio:.1f}x.",
                  f"Resolver(s): {', '.join(resolvers[:3]) or 'unknown'}."]
            return _Hit(CorrelationType.DNS_ANOMALY_DNS_LATENCY, "dns_latency_ms", "DNS response time", "ms", comp, ctx.cfg.dns, [client, *resolvers[:3]],
                        "host", "window", _latency_headline("DNS response time", "ms", comp), ev,
                        ["A slow or overloaded resolver, an unusually heavy query volume or an upstream outage can also slow lookups.",
                         "Only answered lookups can be timed; unanswered queries are not in this comparison."], [client, *resolvers[:3]], window=w,
                        event=(f.first_seen, f.last_seen))
        results.append(comp)
    return next((c for c in results if c.status == "not_significant"), results[0])


def _cooccurrence(f: Finding, ctx: _Ctx, *, metric: str, label: str, gates: Gates, corr_type: CorrelationType,
                  getter: Callable[[FlowSample], float | None], caveat: str):
    """Connections that show retransmissions vs. those that do not, compared on ``getter``."""
    with_r = [(s.t, getter(s)) for s in ctx.flows if s.retransmissions > 0 and getter(s) is not None]
    without = [(s.t, getter(s)) for s in ctx.flows if s.retransmissions == 0 and getter(s) is not None]
    comp = compare_latency(with_r, without, gates, ctx.cfg.baseline, temporal=False)  # type: ignore[arg-type]
    if comp.status != "significant":
        return comp
    top = sorted({s.server_ip for s in ctx.flows if s.retransmissions > 0}, key=lambda ip: -sum(x.retransmissions for x in ctx.flows if x.server_ip == ip))[:3]
    shared = [x for x in (f.source_ip, f.destination_ip) if x] or top
    ev = [f"{label} had a median of {comp.inside:.0f} ms on {comp.n_in} connections with retransmitted segments against {comp.outside:.0f} ms on "
          f"{comp.n_out} connections without: {comp.ratio:.1f}x."] + _stride_note(ctx)
    return _Hit(corr_type, metric, label, "ms", comp, gates, shared, "host" if (f.source_ip and f.destination_ip) else "network", "connections",
                _latency_headline(label, "ms", comp) + " on connections with retransmissions", ev,
                [caveat, "Both effects can come from the same underlying problem (for example congestion), or the capture point can inflate retransmission counts."],
                shared)


def _rule_loss_rtt(f: Finding, ctx: _Ctx):
    return _cooccurrence(f, ctx, metric="avg_rtt_ms", label="Round-trip time", gates=ctx.cfg.rtt, corr_type=CorrelationType.PACKET_LOSS_RTT,
                         getter=lambda s: s.rtt_ms if s.rtt_samples >= 3 else None,
                         caveat="Retransmissions are a loss indicator, not a measurement of loss; RTT is estimated from acknowledged data segments.")


def _rule_retrans_response(f: Finding, ctx: _Ctx):
    return _cooccurrence(f, ctx, metric="response_ms", label="HTTP response time", gates=ctx.cfg.response, corr_type=CorrelationType.RETRANSMISSIONS_RESPONSE_TIME,
                         getter=lambda s: s.response_ms,
                         caveat="Response time is only measurable for visible cleartext HTTP; encrypted traffic is not included.")


def _rule_resets_failures(f: Finding, ctx: _Ctx):
    att = [s for s in ctx.flows if s.attempted]
    with_rst = [s for s in att if s.reset]
    without = [s for s in att if not s.reset]
    comp = compare_proportions([s.t for s in with_rst if s.failed], len(with_rst), sum(1 for s in without if s.failed), len(without),
                               ctx.cfg.failures, ctx.cfg.baseline)
    if comp.status != "significant":
        return comp
    top = sorted({s.server_ip for s in with_rst if s.failed}, key=lambda ip: -sum(1 for s in with_rst if s.server_ip == ip))[:3]
    shared = [x for x in (f.source_ip, f.destination_ip) if x] or top
    ev = [f"{sum(1 for s in with_rst if s.failed)} of {comp.n_in} connection attempts that saw an RST never completed their handshake ({comp.inside:.0%}), "
          f"against {comp.outside:.0%} of the {comp.n_out} attempts without an RST.",
          "A connection refused with an RST counts both as a reset and as a failed connection, so part of this link is by definition."] + _stride_note(ctx)
    return _Hit(CorrelationType.RESETS_FAILED_CONNECTIONS, "failure_rate", "Connection failure rate", "%", comp, ctx.cfg.failures, shared, "network", "connections",
                f"Connection failure rate was {comp.inside:.0%} on connections with resets vs {comp.outside:.0%} without", ev,
                ["Refused connections (closed ports, firewall rejects) produce exactly this pattern and are often benign."], shared, penalty=0.15)


def _latency_headline(label: str, unit: str, c: Comparison) -> str:
    return f"{label} increased {c.ratio:.1f}x ({_fmt(unit, c.outside)} → {_fmt(unit, c.inside)})"


# type -> [(rule label, rule fn)]; a finding type can have several rules
RULES: dict[FindingType, list[tuple[str, Callable]]] = {
    FindingType.SYN_FLOOD: [("TCP handshake latency", _rule_syn_flood)],
    FindingType.PORT_SCAN: [("connection attempts", _rule_port_scan)],
    **{t: [("DNS response time", _rule_dns)] for t in _DNS_TYPES},
    FindingType.TCP_HIGH_RETRANSMISSION: [("round-trip time", _rule_loss_rtt), ("HTTP response time", _rule_retrans_response)],
    FindingType.TCP_EXCESSIVE_RESETS: [("connection failures", _rule_resets_failures)],
}
# which history metric corroborates (or, without a time window, stands in for) each rule
_HISTORY_METRIC = {"tcp_handshake_ms": "tcp_handshake_ms", "dns_latency_ms": "dns_latency_ms", "avg_rtt_ms": "avg_rtt_ms",
                   "response_ms": "response_ms", "failure_rate": "failure_rate"}


# --------------------------------------------------------------------- record building
def _history_match(ctx: _Ctx, metric: str, ips: list[str], scope: str) -> list[PerformanceAnomaly]:
    if metric not in _HISTORY_METRIC:
        return []
    domains = {d for ip in ips for d in ctx.ip_domains.get(ip, [])}
    return [a for a in ctx.history if a.metric == metric and a.basis == "history" and (scope == "network" or a.domain in domains)]


def _build(f: Finding, hit: _Hit, ctx: _Ctx) -> Correlation:
    c = hit.comparison
    domains = sorted({d for ip in hit.shared_ips for d in ctx.ip_domains.get(ip, [])})
    corroborating = _history_match(ctx, hit.metric, hit.shared_ips, hit.scope)
    ev = list(hit.evidence)
    z_line = f"Robust z-score {c.z:.1f} against the reference samples (significance threshold {ctx.cfg.baseline.z_threshold:g})."
    ev.append(z_line)

    onset = c.onset if c.onset is not None else (hit.window[0] if hit.window else (f.first_seen or ctx.t0))
    if hit.mode == "window" and hit.event is not None:
        start, end = hit.event
        lag = onset - start
        relation: TemporalRelation = ("overlapping" if start <= onset <= end
                                      else "performance_follows_finding" if onset > end else "performance_precedes_finding")
        ev.append(f"The first affected measurement was at {_fmt_ts(onset)} UTC, {abs(lag):.1f} s {'after' if lag >= 0 else 'before'} the security "
                  f"event began ({_fmt_ts(start)} UTC).")
        temporal = 1 - ramp(abs(lag), 0, max(30.0, 2 * (end - start)))
    else:
        lag, relation, temporal = 0.0, "same_connections", 0.8
        ev.append("The finding has no time window; both signals were observed on the same connections within this capture.")
    if corroborating:
        a = max(corroborating, key=lambda x: x.z_score)
        ev.append(f"The same metric is also unusual against {a.domain}'s own history: typical {_fmt(a.unit, a.baseline)}, now {_fmt(a.unit, a.current_value)}.")

    factors = [
        (0.30, ramp(c.z, ctx.cfg.baseline.z_threshold, 3 * ctx.cfg.baseline.z_threshold)),
        (0.20, temporal),
        (0.15, 1.0 if hit.scope == "host" else 0.5),
        (0.15, ramp(min(c.n_in, c.n_out), hit.gates.min_in, 5 * hit.gates.min_in)),
        (0.10, f.confidence),
        (0.10, 1.0 if corroborating else 0.0),
    ]
    score = max(0.0, weighted_score(factors) - hit.penalty)
    confidence = confidence_from_score(score, ctx.cfg.bounds)

    perf_conf = confidence_from_score(weighted_score([(0.5, ramp(c.z, ctx.cfg.baseline.z_threshold, 3 * ctx.cfg.baseline.z_threshold)),
                                                      (0.3, ramp(c.n_in, hit.gates.min_in, 5 * hit.gates.min_in)),
                                                      (0.2, ramp(c.n_out, hit.gates.min_out, 5 * hit.gates.min_out))]), ctx.cfg.bounds)
    base_floor = 0.01 if hit.unit == "%" else 1e-9
    deviation = (c.inside - c.outside) / max(c.outside, base_floor)  # relative to the reference (1 % floor for rates)
    perf = PerformanceAnomaly(
        id=hashlib.sha1(f"{f.id}|{hit.metric}|perf".encode()).hexdigest()[:12], domain=(domains[0] if len(domains) == 1 else (hit.scope_ips[0] if hit.scope_ips else "network-wide")),
        metric=hit.metric, label=hit.label, unit=hit.unit, baseline=c.outside, baseline_mean=c.outside_mean or c.outside, baseline_std=c.outside_std,
        baseline_observations=c.n_out, current_value=c.inside, deviation=round(deviation, 4), absolute_change=round(c.inside - c.outside, 6),
        z_score=round(c.z, 2), severity=severity_for(c.z, perf_conf), confidence=perf_conf, confidence_label=confidence_label(perf_conf),
        first_seen=c.onset if c.onset is not None else onset, last_seen=c.last if c.last is not None else onset, observations_in_run=c.n_in,
        evidence=[hit.evidence[0], z_line], caveats=hit.caveats, basis="capture", scope_ips=hit.scope_ips,
        ratio=round(c.ratio, 3) if c.ratio is not None else None)
    return Correlation(
        id=hashlib.sha1(f"{f.id}|{hit.corr_type.value}".encode()).hexdigest()[:12], type=hit.corr_type, finding_id=f.id, finding_type=f.type,
        finding_title=f.title, finding_severity=f.severity, finding_confidence=f.confidence, finding_first_seen=f.first_seen, finding_last_seen=f.last_seen,
        performance=perf, headline=hit.headline, summary=f"{f.title}: potentially related to {_sentence_case_tail(hit.headline)}.",
        time_difference_seconds=round(lag, 3), temporal_relation=relation, shared_ips=hit.shared_ips, shared_domains=domains, scope=hit.scope,  # type: ignore[arg-type]
        evidence=ev, caveats=[GENERAL_CAVEAT, *hit.caveats], confidence=confidence, confidence_label=confidence_label(confidence))  # type: ignore[arg-type]


def _from_history(f: Finding, corr_type: CorrelationType, metric: str, label: str, ctx: _Ctx) -> Correlation | None:
    """No time localisation possible: use a history anomaly of the same metric in the same capture (lower confidence)."""
    ips = [x for x in (f.source_ip, f.destination_ip) if x]
    scope = "host" if ips else "network"
    matches = _history_match(ctx, metric, ips, scope)
    if not matches:
        return None
    a = max(matches, key=lambda x: (x.severity.rank, x.z_score))
    domains = sorted({m.domain for m in matches})[:5]
    ev = [f"{a.label} for {a.domain} was {_fmt(a.unit, a.current_value)} against a typical {_fmt(a.unit, a.baseline)} over its previous "
          f"{a.baseline_observations} captures ({a.deviation:+.0%}).",
          "Only capture-level timing is available: the security finding and the performance change were both observed in this capture, "
          "but their order and overlap within it are not known."]
    score = weighted_score([(0.30, ramp(a.z_score, ctx.cfg.baseline.z_threshold, 3 * ctx.cfg.baseline.z_threshold)), (0.20, 0.3),
                            (0.15, 1.0 if scope == "host" else 0.5), (0.15, ramp(a.baseline_observations, 5, 30)), (0.10, f.confidence), (0.10, 0.0)])
    confidence = confidence_from_score(score, ctx.cfg.bounds)
    headline = f"{a.label} was {a.deviation:+.0%} against its history ({_fmt(a.unit, a.baseline)} → {_fmt(a.unit, a.current_value)})"
    return Correlation(
        id=hashlib.sha1(f"{f.id}|{corr_type.value}".encode()).hexdigest()[:12], type=corr_type, finding_id=f.id, finding_type=f.type, finding_title=f.title,
        finding_severity=f.severity, finding_confidence=f.confidence, finding_first_seen=f.first_seen, finding_last_seen=f.last_seen,
        performance=a, headline=headline, summary=f"{f.title}: potentially related to {_sentence_case_tail(headline)}.", time_difference_seconds=0.0,
        temporal_relation="capture_level", shared_ips=ips, shared_domains=domains, scope=scope, evidence=ev,  # type: ignore[arg-type]
        caveats=[GENERAL_CAVEAT, "History baselines compare this capture with earlier ones; different networks or times of day can differ."],
        confidence=confidence, confidence_label=confidence_label(confidence))  # type: ignore[arg-type]


# --------------------------------------------------------------------- entry point
def correlate(findings: list[Finding], analysis: AnalysisResult, history_anomalies: list[PerformanceAnomaly] | None = None,
              config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG) -> CorrelationReport:
    """Correlations between ``findings`` and performance changes in ``analysis`` (and, optionally, its history anomalies)."""
    perf = analysis.performance_statistics
    meta = analysis.metadata
    t0 = meta.first_packet_time if meta.first_packet_time is not None else 0.0
    t1 = meta.last_packet_time if meta.last_packet_time is not None else t0
    ip_domains: dict[str, set[str]] = {}
    for s in perf.flow_samples:
        if s.domain:
            ip_domains.setdefault(s.server_ip, set()).add(s.domain)
    ctx = _Ctx(analysis, config, list(history_anomalies or []), perf.flow_samples, perf.lookup_samples, perf.flow_sample_stride, t0, t1,
               {ip: sorted(d) for ip, d in ip_domains.items()})
    report = CorrelationReport(flow_data_thinned=ctx.stride > 1)

    for f in findings:
        for rule_label, rule in RULES.get(f.type, []):
            outcome = rule(f, ctx)
            if isinstance(outcome, _Hit):
                report.correlations.append(_build(f, outcome, ctx))
                continue
            # not a significant window/connection comparison: fall back to capture-level history evidence if possible
            fallback = None
            metric = {"TCP handshake latency": "tcp_handshake_ms", "DNS response time": "dns_latency_ms", "round-trip time": "avg_rtt_ms",
                      "HTTP response time": "response_ms", "connection failures": "failure_rate"}.get(rule_label)
            ctype = {"TCP handshake latency": CorrelationType.SYN_FLOOD_HANDSHAKE_LATENCY, "DNS response time": CorrelationType.DNS_ANOMALY_DNS_LATENCY,
                     "round-trip time": CorrelationType.PACKET_LOSS_RTT, "HTTP response time": CorrelationType.RETRANSMISSIONS_RESPONSE_TIME,
                     "connection failures": CorrelationType.RESETS_FAILED_CONNECTIONS}.get(rule_label)
            insufficient = isinstance(outcome, str) or (isinstance(outcome, Comparison) and outcome.status == "insufficient")
            if metric and ctype and insufficient:  # a real "no change" result is not overridden by capture-level evidence
                fallback = _from_history(f, ctype, metric, rule_label, ctx)
            if fallback is not None:
                report.correlations.append(fallback)
            elif isinstance(outcome, str):
                report.not_evaluated.append(f"{f.title}: {rule_label} could not be checked because {outcome}.")
            elif outcome.status == "insufficient":
                report.not_evaluated.append(f"{f.title}: {rule_label} could not be checked because {outcome.reason}.")
            else:
                report.no_related_change.append(f"{f.title}: no significant change in {rule_label} was found for the same scope and time.")
    report.correlations.sort(key=lambda c: (-c.confidence, c.finding_id, c.type.value))
    return report
