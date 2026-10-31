"""Possible TCP port scans (vertical) and host sweeps (horizontal)."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector, fmt_ts, span
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, SynPair, SynSource

_CAVEATS = [
    "Authorized vulnerability scanners, inventory and monitoring tools produce this pattern.",
    "Load-balancer or uptime health checks that cycle ports can look similar.",
    "The capture may cover only part of the activity; counts are lower bounds.",
]
_RECOMMENDATION = (
    "Check whether {src} is an authorized scanner or monitoring host. If it is not, review its "
    "traffic in Wireshark (filter: ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0), "
    "look for follow-up connections to ports that answered, and decide on any containment manually."
)


class PortScanDetector(BaseDetector):
    """Flags sources whose SYN traffic is wide (many ports or hosts) and mostly unanswered.

    Evidence: per source/destination pair SYN profiles (``tcp_statistics.syn_pairs``) for
    vertical scans and per-source SYN profiles (``top_syn_sources``) for host sweeps.
    A source qualifies as a *port scan* when it probed at least ``min_unique_ports`` ports on
    one host and at least ``min_failure_ratio`` of its SYNs received no SYN-ACK. Wide-but-
    answered traffic (a client using many working ports) is deliberately not flagged.
    """

    name = "port_scan"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.port_scan
        if not cfg.enabled:
            return []
        findings: list[Finding] = []
        scanners: set[str] = set()

        pairs_by_src: dict[str, list[SynPair]] = {}
        for pair in result.tcp_statistics.syn_pairs:
            failure = self._failure(pair.syn_ack_received, pair.syn_packets)
            if pair.unique_destination_ports >= cfg.min_unique_ports and failure >= cfg.min_failure_ratio:
                pairs_by_src.setdefault(pair.src_ip, []).append(pair)

        sources = {s.ip: s for s in result.tcp_statistics.top_syn_sources}
        for src, pairs in pairs_by_src.items():
            findings.append(self._vertical(src, pairs, sources.get(src)))
            scanners.add(src)

        for source in result.tcp_statistics.top_syn_sources:
            if source.ip in scanners:
                continue
            failure = source.unanswered_ratio
            if source.unique_destination_hosts >= cfg.min_unique_hosts and failure >= cfg.min_failure_ratio:
                findings.append(self._sweep(source))
        return findings

    @staticmethod
    def _failure(syn_acks: int, syns: int) -> float:
        return max(0.0, 1 - syn_acks / syns) if syns else 0.0

    def _vertical(self, src: str, pairs: list[SynPair], source: SynSource | None) -> Finding:
        cfg = self.config.port_scan
        best = max(pairs, key=lambda p: (p.unique_destination_ports, p.syn_packets))
        first = min(p.first_syn_time for p in pairs)
        last = max(p.last_syn_time for p in pairs)
        duration = span(best.first_syn_time, best.last_syn_time, cfg.min_duration_seconds)
        failure = self._failure(best.syn_ack_received, best.syn_packets)
        rate = best.syn_packets / duration
        per_port = best.unique_destination_ports / best.syn_packets if best.syn_packets else 0.0
        w = cfg.weights
        factors = [
            ("port_breadth", ramp(best.unique_destination_ports, cfg.min_unique_ports, cfg.strong_unique_ports),
             w["port_breadth"], f"{best.unique_destination_ports} distinct ports (full score at {cfg.strong_unique_ports})"),
            ("failure_ratio", ramp(failure, cfg.min_failure_ratio, cfg.strong_failure_ratio),
             w["failure_ratio"], f"{failure:.0%} of SYNs got no SYN-ACK"),
            ("probe_rate", ramp(rate, cfg.min_syn_per_second, cfg.strong_syn_per_second),
             w["probe_rate"], f"{rate:.1f} SYN/s"),
            ("one_probe_per_port", ramp(per_port, cfg.min_ports_per_syn, cfg.strong_ports_per_syn),
             w["one_probe_per_port"], f"{per_port:.2f} distinct ports per SYN"),
        ]
        evidence = {
            "unique_ports": best.unique_destination_ports,
            "syn_packets": best.syn_packets,
            "syn_ack_packets": best.syn_ack_received,
            "rst_packets_received": best.rst_received,
            "failure_ratio": round(failure, 4),
            "duration_seconds": round(span(best.first_syn_time, best.last_syn_time), 3),
            "syn_per_second": round(rate, 2),
            "sample_ports": best.sample_ports,
            "targets_scanned": len(pairs),
            "top_targets": [
                {"ip": p.dst_ip, "unique_ports": p.unique_destination_ports, "syn_packets": p.syn_packets}
                for p in sorted(pairs, key=lambda p: p.unique_destination_ports, reverse=True)[:5]
            ],
        }
        if source is not None:
            evidence["source_unique_destination_hosts"] = source.unique_destination_hosts
        target = f"{best.dst_ip}" + (f" and {len(pairs) - 1} other host(s)" if len(pairs) > 1 else "")
        return self.build(
            type=FindingType.PORT_SCAN,
            factors=factors,
            max_severity=cfg.max_severity,
            title=f"Possible TCP port scan from {src}",
            description=(
                f"{src} sent {best.syn_packets} SYN packets to {best.unique_destination_ports} distinct ports on "
                f"{target} between {fmt_ts(first)} and {fmt_ts(last)}, and only {best.syn_ack_received} received a "
                f"SYN-ACK. This is consistent with possible TCP port scanning and requires investigation."
            ),
            evidence=evidence,
            reasoning=[
                f"Probed {best.unique_destination_ports} distinct ports (threshold {cfg.min_unique_ports}).",
                f"{failure:.0%} of SYNs were unanswered (threshold {cfg.min_failure_ratio:.0%}).",
                f"About {per_port:.2f} distinct ports per SYN: each port was probed roughly {1 / per_port:.1f} time(s)."
                if per_port else "No SYN packets counted.",
            ],
            caveats=_CAVEATS,
            recommendation=_RECOMMENDATION.format(src=src),
            source_ip=src,
            destination_ip=best.dst_ip if len(pairs) == 1 else None,
            key=src,
            first_seen=first,
            last_seen=last,
        )

    def _sweep(self, s: SynSource) -> Finding:
        cfg = self.config.port_scan
        duration = span(s.first_syn_time, s.last_syn_time, cfg.min_duration_seconds)
        rate = s.syn_sent / duration
        w = cfg.sweep_weights
        focus = 1 - ramp(s.unique_destination_ports, cfg.focused_ports_max, cfg.unfocused_ports_full)
        factors = [
            ("host_breadth", ramp(s.unique_destination_hosts, cfg.min_unique_hosts, cfg.strong_unique_hosts),
             w["host_breadth"], f"{s.unique_destination_hosts} distinct hosts (full score at {cfg.strong_unique_hosts})"),
            ("failure_ratio", ramp(s.unanswered_ratio, cfg.min_failure_ratio, cfg.strong_failure_ratio),
             w["failure_ratio"], f"{s.unanswered_ratio:.0%} of SYNs got no SYN-ACK"),
            ("probe_rate", ramp(rate, cfg.min_syn_per_second, cfg.strong_syn_per_second),
             w["probe_rate"], f"{rate:.1f} SYN/s"),
            ("port_focus", focus, w["port_focus"], f"{s.unique_destination_ports} distinct port(s) across the hosts"),
        ]
        return self.build(
            type=FindingType.HOST_SWEEP,
            factors=factors,
            max_severity=cfg.max_severity,
            title=f"Possible host sweep from {s.ip}",
            description=(
                f"{s.ip} sent SYN packets to {s.unique_destination_hosts} distinct hosts "
                f"({s.unique_destination_ports} distinct port(s)) and {s.unanswered_ratio:.0%} went unanswered. "
                f"This is consistent with a possible host sweep or network discovery and requires investigation."
            ),
            evidence={
                "unique_hosts": s.unique_destination_hosts,
                "unique_ports": s.unique_destination_ports,
                "syn_packets": s.syn_sent,
                "syn_ack_packets": s.syn_ack_received,
                "rst_packets_received": s.rst_received,
                "failure_ratio": s.unanswered_ratio,
                "duration_seconds": round(span(s.first_syn_time, s.last_syn_time), 3),
                "syn_per_second": round(rate, 2),
            },
            reasoning=[
                f"Contacted {s.unique_destination_hosts} distinct hosts (threshold {cfg.min_unique_hosts}).",
                f"{s.unanswered_ratio:.0%} of SYNs were unanswered (threshold {cfg.min_failure_ratio:.0%}).",
            ],
            caveats=_CAVEATS + ["Normal clients contacting many servers (e.g. a crawler) usually complete their handshakes."],
            recommendation=_RECOMMENDATION.format(src=s.ip),
            source_ip=s.ip,
            key=s.ip,
            first_seen=s.first_syn_time,
            last_seen=s.last_syn_time,
        )
