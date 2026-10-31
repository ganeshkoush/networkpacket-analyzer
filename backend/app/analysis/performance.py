"""Assemble latency measurements into ``PerformanceMetrics`` (per connection) and ``DomainPerformance``.

This module only combines results other analyzers already computed (TCP handshake from the connection
analyzer, RTT/HTTP/TLS from the latency analyzer, lookup times from the DNS analyzer); it never reads
packets. Keeping the sources apart is the point: handshake time, RTT, TLS hello time and HTTP response time
are distinct measurements and are exposed as distinct fields.
"""
from __future__ import annotations

import random
import statistics
from collections.abc import Callable
from dataclasses import dataclass, field

from app.analysis.connection_analyzer import TrackedFlow
from app.analysis.connection_tracker import NO_SYN_SEEN, NO_SYNACK, RESET_IN_HANDSHAKE, SIMULTANEOUS_OPEN, FlowKey
from app.analysis.dns_analyzer import DnsAnalyzer
from app.analysis.latency_analyzer import MIN_SAMPLES_FOR_P95, FlowLatency, LatencyAnalyzer, percentile
from app.models.analysis import (
    FlowSample, DomainPerformance, DomainSeries, HandshakePoint, MeasurementConfidence, PerformanceMetrics, PerformanceStatistics,
    PerformanceSummary, RttPoint, TrafficPoint,
)

_POOL_CAP = 2000
_POINTS_CAP = 300  # time-series points kept per domain and series
_FLOW_SAMPLE_CAP = 100_000  # TCP connections kept as time-stamped samples (uniformly thinned beyond this)
_AMBIGUOUS_RATIO_LIMIT = 0.10

NOTES = [
    "TCP handshake time is connection set-up time (SYN to final ACK). It is not website or application response time.",
    "RTT is derived from data segments acknowledged by pure ACKs, measured between the capture point and the "
    "farther endpoint. Retransmitted or reordered segments are excluded and delayed ACKs can inflate samples.",
    "Response time is only reported for cleartext HTTP where requests and responses are both visible. For HTTPS "
    "the encrypted request/response timing is not visible; handshake, TLS hello time, RTT and duration are shown instead.",
]


def confidence(samples: int, ambiguous_ratio: float = 0.0) -> MeasurementConfidence:
    """HIGH >= 10 samples, MEDIUM 3-9, LOW 1-2, UNAVAILABLE none; one step lower when many segments were ambiguous."""
    if samples <= 0:
        return "UNAVAILABLE"
    level = 3 if samples >= 10 else 2 if samples >= 3 else 1
    if ambiguous_ratio > _AMBIGUOUS_RATIO_LIMIT and level > 1:
        level -= 1
    return ("LOW", "MEDIUM", "HIGH")[level - 1]


@dataclass(slots=True)
class _DomainAcc:
    connections: int = 0
    handshakes: list[float] = field(default_factory=list)
    rtt_n: int = 0
    rtt_sum: float = 0.0
    rtt_pool: list[float] = field(default_factory=list)
    pool_seen: int = 0
    responses: list[float] = field(default_factory=list)
    http: int = 0
    encrypted: int = 0
    rtt_max: float | None = None
    retransmissions: int = 0
    resets: int = 0
    connections_reset: int = 0
    tcp_packets: int = 0
    attempted: int = 0
    failed: int = 0
    rtt_points: list[RttPoint] = field(default_factory=list)
    rtt_points_seen: int = 0
    handshake_points: list[HandshakePoint] = field(default_factory=list)
    handshake_points_seen: int = 0


def _keep(points: list, seen: int, item, rng: random.Random) -> None:
    """Reservoir-add ``item`` to ``points`` (``seen`` = items offered so far, including this one)."""
    if len(points) < _POINTS_CAP:
        points.append(item)
    elif (j := rng.randrange(seen)) < _POINTS_CAP:
        points[j] = item


def build_performance(
    flows: list[TrackedFlow],
    latency: LatencyAnalyzer,
    dns: DnsAnalyzer,
    domain_for_flow: Callable[[FlowKey], tuple[str, bool] | None] | None,
    max_connections: int,
    max_domains: int,
    retransmissions: Callable[[tuple[str, int | None], tuple[str, int | None]], int] | None = None,
    traffic_series: Callable[[str], tuple[int, list[tuple[float, int, int]]] | None] | None = None,
    series_domains: list[str] | None = None,
    lookup_samples: list | None = None,
) -> PerformanceStatistics:
    """Latency per connection and per domain.

    ``retransmissions(a, b)`` (TcpAnalyzer) gives retransmission indicators per connection;
    ``traffic_series(domain)`` (DomainAnalyzer) gives exact per-packet traffic bins. ``series_domains`` are the
    domains that get a time series (the ones the web-activity dashboard can show).
    """
    rng = random.Random(0)
    dns_by_domain = dns.domain_lookup_latencies_ms()
    domains: dict[str, _DomainAcc] = {}
    rows: list[PerformanceMetrics] = []
    with_rtt = responses = encrypted_total = 0
    tcp_total = sum(1 for f in flows if f.protocol == "TCP")
    stride = max(1, -(-tcp_total // _FLOW_SAMPLE_CAP))
    samples: list[FlowSample] = []
    tcp_seen = 0

    for i, f in enumerate(flows):
        hit = domain_for_flow(f.key) if domain_for_flow else None
        domain = hit[0] if hit else None
        fl = latency.flow(f.key) if f.protocol == "TCP" else None
        row = _row(f, domain, fl, dns)
        if f.protocol == "TCP":
            if tcp_seen % stride == 0:
                judged = bool(f.handshake_status) and f.handshake_reason not in (NO_SYN_SEEN, SIMULTANEOUS_OPEN)
                samples.append(FlowSample(
                    t=f.start, client_ip=f.client[0], server_ip=f.server[0], server_port=f.server[1], domain=domain,
                    attempted=judged, failed=judged and f.handshake_reason in (NO_SYNACK, RESET_IN_HANDSHAKE),
                    reset=f.resets > 0, handshake_ms=f.handshake_ms,
                    rtt_ms=fl.rtt.avg_ms if fl and fl.rtt else None, rtt_samples=fl.rtt.samples if fl and fl.rtt else 0,
                    response_ms=round(statistics.median(fl.http_response_ms), 3) if fl and fl.http_response_ms else None,
                    retransmissions=retransmissions(f.client, f.server) if retransmissions else 0, packets=f.packets))
            tcp_seen += 1
        if i < max_connections:
            rows.append(row)
        if fl and fl.rtt:
            with_rtt += 1
        responses += len(fl.http_response_ms) if fl else 0
        encrypted_total += row.encrypted
        if domain and f.protocol == "TCP":
            acc = domains.setdefault(domain, _DomainAcc())
            acc.connections += 1
            if f.handshake_ms is not None:
                acc.handshakes.append(f.handshake_ms)
            acc.encrypted += row.encrypted
            acc.tcp_packets += f.packets
            if f.handshake_status and f.handshake_reason not in (NO_SYN_SEEN, SIMULTANEOUS_OPEN):
                acc.attempted += 1  # a SYN was captured and the handshake could be judged
                acc.failed += 1 if f.handshake_reason in (NO_SYNACK, RESET_IN_HANDSHAKE) else 0
            acc.resets += f.resets
            acc.connections_reset += 1 if f.resets else 0
            if retransmissions:
                acc.retransmissions += retransmissions(f.client, f.server)
            if f.handshake_ms is not None:
                acc.handshake_points_seen += 1
                _keep(acc.handshake_points, acc.handshake_points_seen, HandshakePoint(t=f.start, handshake_ms=f.handshake_ms), rng)
            if fl:
                acc.http += 1 if fl.http_requests else 0
                acc.responses.extend(fl.http_response_ms)
                if fl.rtt or fl.http_response_ms:
                    acc.rtt_points_seen += 1
                    _keep(acc.rtt_points, acc.rtt_points_seen, RttPoint(
                        t=f.start, avg_rtt_ms=fl.rtt.avg_ms if fl.rtt else None, p95_rtt_ms=fl.rtt.p95_ms if fl.rtt else None,
                        response_ms=round(statistics.median(fl.http_response_ms), 3) if fl.http_response_ms else None), rng)
                if fl.rtt:
                    acc.rtt_max = fl.rtt.max_ms if acc.rtt_max is None else max(acc.rtt_max, fl.rtt.max_ms)
                    acc.rtt_n += fl.rtt.samples
                    acc.rtt_sum += fl.rtt.avg_ms * fl.rtt.samples
                    for v in fl.rtt.retained:  # uniform reservoir over every retained sample of the domain
                        acc.pool_seen += 1
                        if len(acc.rtt_pool) < _POOL_CAP:
                            acc.rtt_pool.append(v)
                        elif (j := rng.randrange(acc.pool_seen)) < _POOL_CAP:
                            acc.rtt_pool[j] = v

    domain_rows = [_domain_row(name, acc, dns_by_domain.get(name, [])) for name, acc in domains.items()]
    domain_rows.sort(key=lambda d: (-d.connections, d.domain))
    summary = PerformanceSummary(
        tracked_connections=len(flows), connections_with_rtt=with_rtt, http_responses_timed=responses,
        encrypted_connections=encrypted_total,
        dns_lookups_timed=sum(len(v) for v in dns_by_domain.values()), notes=list(NOTES))
    series: dict[str, DomainSeries] = {}
    for name in dict.fromkeys([*(series_domains or []), *(d.domain for d in domain_rows[:max_domains])]):
        acc = domains.get(name)
        traffic = traffic_series(name) if traffic_series else None
        if acc is None and traffic is None:
            continue
        series[name] = DomainSeries(
            bin_seconds=traffic[0] if traffic else 1.0,
            rtt=sorted(acc.rtt_points, key=lambda p: p.t) if acc else [],
            handshake=sorted(acc.handshake_points, key=lambda p: p.t) if acc else [],
            traffic=[TrafficPoint(t=t, bytes_sent=s, bytes_received=r) for t, s, r in traffic[1]] if traffic else [])
    return PerformanceStatistics(summary=summary, metrics=rows, domains=domain_rows[:max_domains], series=series,
                                 flow_samples=samples, flow_sample_stride=stride, lookup_samples=list(lookup_samples or []))


def _row(f: TrackedFlow, domain: str | None, fl: FlowLatency | None, dns: DnsAnalyzer) -> PerformanceMetrics:
    row = PerformanceMetrics(connection_id=f.id, domain=domain, protocol=f.protocol,
                             connection_duration_ms=round((f.end - f.start) * 1000, 3))
    if f.protocol == "UDP":
        lookups = dns.flow_lookup_latencies_ms(f.key)
        if lookups:
            row.application_protocol = "DNS"
            row.dns_latency_ms = round(statistics.median(lookups), 3)
            row.dns_lookups = len(lookups)
            row.measurement_confidence = "HIGH"  # each sample is a transaction-id-matched query/response pair
            row.notes.append("DNS response time: query to matching response (same transaction id), "
                             "excluding queries that were retransmitted.")
        return row
    if f.protocol != "TCP":
        return row

    row.tcp_handshake_ms = f.handshake_ms
    if domain:
        looked_up = dns.lookup_latency_ms(f.client[0], domain)
        if looked_up:
            row.dns_latency_ms, row.dns_lookups = looked_up
    if fl is None:
        row.notes.append("No data segments were captured, so no RTT can be derived.")
        return row

    rtt = fl.rtt
    if rtt:
        row.min_rtt_ms, row.avg_rtt_ms, row.median_rtt_ms = rtt.min_ms, rtt.avg_ms, rtt.median_ms
        row.p95_rtt_ms, row.max_rtt_ms, row.rtt_samples = rtt.p95_ms, rtt.max_ms, rtt.samples
        sender = f.key[1 + rtt.direction]
        row.rtt_basis = "client_to_server" if sender == f.client else "server_to_client"
        row.measurement_confidence = confidence(rtt.samples, rtt.ambiguous_ratio)
        if rtt.p95_ms is None:
            row.notes.append(f"P95 needs at least {MIN_SAMPLES_FOR_P95} RTT samples.")
        if rtt.ambiguous_ratio > 0:
            row.notes.append(f"{rtt.ambiguous_ratio:.0%} of segments in this direction were retransmitted or "
                             "reordered and were excluded from the RTT samples.")
    else:
        row.notes.append("Not enough data segments acknowledged by pure ACKs to derive an RTT.")

    if fl.tls_seen:
        row.application_protocol, row.encrypted = "TLS", True
        row.tls_server_hello_ms = fl.tls_hello_ms
        row.notes.append("Encrypted (TLS): HTTP request/response timing is not visible, so no response time is "
                         "reported. ClientHello to ServerHello time is not a response time either.")
    elif fl.http_requests:
        row.application_protocol = "HTTP"
        if fl.http_response_ms:
            row.application_response_ms = round(statistics.median(fl.http_response_ms), 3)
            row.application_response_samples = len(fl.http_response_ms)
            row.notes.append("HTTP response time: last request packet to first response packet "
                             "(network + server processing); it does not include the TCP handshake.")
        else:
            row.notes.append("HTTP requests were seen but no request/response pair could be matched reliably.")
    if fl.http_untimed:
        row.notes.append(f"{fl.http_untimed} HTTP exchange(s) were not timed (pipelined or out of order).")
    return row


def _domain_row(name: str, acc: _DomainAcc, dns_ms: list[float]) -> DomainPerformance:
    pool = sorted(acc.rtt_pool)
    return DomainPerformance(
        domain=name, connections=acc.connections,
        dns_latency_ms=round(statistics.median(dns_ms), 3) if dns_ms else None, dns_lookups=len(dns_ms),
        tcp_handshake_ms=round(sum(acc.handshakes) / len(acc.handshakes), 3) if acc.handshakes else None,
        handshake_samples=len(acc.handshakes),
        avg_rtt_ms=round(acc.rtt_sum / acc.rtt_n, 3) if acc.rtt_n else None,
        p95_rtt_ms=round(percentile(pool, 95), 3) if len(pool) >= MIN_SAMPLES_FOR_P95 else None,
        rtt_samples=acc.rtt_n,
        application_response_ms=round(statistics.median(acc.responses), 3) if acc.responses else None,
        application_response_samples=len(acc.responses),
        http_connections=acc.http, encrypted_connections=acc.encrypted,
        measurement_confidence=confidence(acc.rtt_n),
        max_rtt_ms=acc.rtt_max, retransmissions=acc.retransmissions, resets=acc.resets,
        connections_reset=acc.connections_reset, tcp_packets=acc.tcp_packets,
        tcp_connections_attempted=acc.attempted, tcp_connections_failed=acc.failed,
    )
