"""Builders for network-health tests: a capture shaped like the spec's example, and a well-formed model answer."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from app.models.analysis import DomainPerformance, FlowSample, PerformanceStatistics
from app.services.network_evidence import build_network_evidence
from detection_helpers import T0, blank_result

NORMAL = {"handshake": 45.0, "rtt": 38.0, "retrans": 0.008}


def domain(name="github.com", **kw) -> DomainPerformance:
    base = dict(domain=name, connections=20, tcp_handshake_ms=45.0, handshake_samples=20, avg_rtt_ms=38.0, p95_rtt_ms=72.0, rtt_samples=200,
                dns_latency_ms=20.0, dns_lookups=10, tcp_packets=2000, retransmissions=16, tcp_connections_attempted=20, tcp_connections_failed=0)
    base.update(kw)
    return DomainPerformance(**base)


def result(domains=(), flows=(), **meta):
    r = blank_result()
    r.metadata.first_packet_time, r.metadata.last_packet_time, r.metadata.duration_seconds = T0, T0 + 100, 100.0
    r.packet_statistics.total_packets, r.packet_statistics.total_bytes = 5000, 900_000
    r.performance_statistics = PerformanceStatistics(domains=list(domains), flow_samples=list(flows))
    for k, v in meta.items():
        setattr(r.metadata, k, v)
    return r


def normals(sources=7, **over):
    vals = {"handshake_ms": NORMAL["handshake"], "avg_rtt_ms": NORMAL["rtt"], "p95_rtt_ms": 72.0, "dns_ms": 20.0, "retransmission_rate": NORMAL["retrans"], "failure_rate": 0.0}
    vals.update(over)
    return sources, vals, {k: 1000 for k in vals}


def degraded_result():
    """The spec's example: retransmissions 0.8% -> 6.2%, average RTT 38 ms -> 102 ms."""
    return result([domain(avg_rtt_ms=102.0, p95_rtt_ms=211.0, tcp_handshake_ms=131.0, retransmissions=124)])


def poor_result():
    """Bad in absolute terms AND far from this computer's usual: 450 ms round trips against a usual 38 ms."""
    return result([domain(avg_rtt_ms=450.0, p95_rtt_ms=900.0, tcp_handshake_ms=410.0)])


def evidence(r=None, findings=(), n=None, **kw):
    return build_network_evidence(r or degraded_result(), list(findings), normals=n if n is not None else normals(), **kw)


GOOD = {
    "overall_health": "Degraded",
    "summary": "Elevated packet retransmissions are affecting network latency compared with this computer's usual behaviour.",
    "main_issue": "Elevated packet retransmissions are affecting network latency.",
    "top_problems": [
        {"title": "High retransmission rate", "detail": "The retransmission rate is well above this computer's usual rate.", "evidence_ids": ["retrans.rate"]},
        {"title": "Higher round-trip time", "detail": "Round-trip time is above its usual value.", "evidence_ids": ["rtt.avg", "domain:github.com"]},
    ],
    "evidence": [
        {"evidence_id": "retrans.rate", "statement": "Retransmission rate was 6.2% against a usual 0.8%."},
        {"evidence_id": "rtt.avg", "statement": "Average round-trip time was 102 ms against a usual 38 ms."},
    ],
    "potential_explanations": ["Wi-Fi interference", "Network congestion", "An unstable route", "Remote service issues"],
    "recommended_next_steps": ["Compare latency to several independent services.", "Repeat the capture at a different time of day."],
    "confidence": "Medium",
    "limitations": ["Only one capture point was available.", "Encrypted HTTPS response times are not visible."],
}


def good(**over) -> dict:
    d = copy.deepcopy(GOOD)
    d.update(over)
    return d


def flow(t, **kw):
    return FlowSample(t=T0 + t, client_ip="10.0.0.5", server_ip="140.82.112.3", server_port=443, **kw)


NOW = datetime.now(timezone.utc)
