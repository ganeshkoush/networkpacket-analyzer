"""TCP connection anomalies: abnormal flags, retransmissions, resets."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, FlagAnomaly


class TcpAnomalyDetector(BaseDetector):
    """Three checks over aggregate TCP evidence.

    * **Abnormal flags** (``flag_anomalies``) - NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST, FIN or
      data without ACK. Grouped per source; "high-signal" kinds (typical of stealth probes)
      score higher than odd-but-possible ones.
    * **High retransmission rate** (``retransmissions``) - repeated sequence numbers; points
      at loss/congestion or an unresponsive peer rather than an attack.
    * **Excessive resets** - a large share of TCP packets are RSTs (refused/aborted
      connections, often a side effect of scanning).
    """

    name = "tcp_anomaly"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.tcp_anomaly
        if not cfg.enabled:
            return []
        findings = self._flags(result)
        if (f := self._retrans(result)) is not None:
            findings.append(f)
        if (f := self._resets(result)) is not None:
            findings.append(f)
        return findings

    # ------------------------------------------------------------------ flags
    def _flags(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.tcp_anomaly
        by_src: dict[str, list[FlagAnomaly]] = {}
        for a in result.tcp_statistics.flag_anomalies:
            by_src.setdefault(a.src_ip, []).append(a)
        out = []
        for src, items in by_src.items():
            total = sum(a.packets for a in items)
            if total < cfg.flags_min_packets:
                continue
            kinds: dict[str, int] = {}
            for a in items:
                kinds[a.anomaly] = kinds.get(a.anomaly, 0) + a.packets
            hosts = {a.dst_ip for a in items}
            high = any(k in cfg.flags_high_signal for k in kinds)
            w = cfg.flags_weights
            factors = [
                ("packet_count", ramp(total, cfg.flags_min_packets, cfg.flags_strong_packets), w["packet_count"],
                 f"{total} packets"),
                ("anomaly_kind", 1.0 if high else cfg.flags_low_signal_score, w["anomaly_kind"],
                 f"kinds: {', '.join(sorted(kinds))}"),
                ("destination_breadth", ramp(len(hosts), 1, cfg.flags_strong_hosts), w["destination_breadth"],
                 f"{len(hosts)} destination host(s)"),
            ]
            first = min(a.first_time for a in items)
            last = max(a.last_time for a in items)
            out.append(self.build(
                type=FindingType.TCP_ABNORMAL_FLAGS, factors=factors, max_severity=cfg.max_severity,
                title=f"Suspicious TCP flag combinations from {src}",
                description=(
                    f"{src} sent {total} TCP packets with abnormal flag combinations ({', '.join(f'{k}: {v}' for k, v in sorted(kinds.items()))}) "
                    f"to {len(hosts)} host(s). Such packets are consistent with possible stealth scanning, OS "
                    f"fingerprinting or evasion attempts, but can also come from buggy stacks; this requires investigation."
                ),
                evidence={"packets": total, "kinds": kinds, "destination_hosts": len(hosts),
                          "sample_destinations": sorted(hosts)[:5]},
                reasoning=["Flag combinations that conforming TCP stacks do not normally send were observed."]
                + (["At least one kind (NULL/XMAS/SYN+FIN/SYN+RST) is typical of stealth scan tools."] if high else []),
                caveats=["Middleboxes, packet corruption or capture offload artifacts can produce odd flags.",
                         "Authorized scanners deliberately send these packets."],
                recommendation=f"Review packets from {src} (Wireshark filter: ip.src == {src} && tcp) and confirm whether it is an authorized scanner.",
                source_ip=src, destination_ip=next(iter(hosts)) if len(hosts) == 1 else None,
                key=src, first_seen=first, last_seen=last,
            ))
        return out

    # ------------------------------------------------------------------ retransmissions
    def _retrans(self, result: AnalysisResult) -> Finding | None:
        cfg = self.config.tcp_anomaly
        r = result.tcp_statistics.retransmissions
        if r.sequence_bearing_segments < cfg.retrans_min_segments or r.retransmission_rate < cfg.retrans_min_rate:
            return None
        w = cfg.retrans_weights
        factors = [
            ("rate", ramp(r.retransmission_rate, cfg.retrans_min_rate, cfg.retrans_strong_rate), w["rate"],
             f"{r.retransmission_rate:.1%} of segments"),
            ("volume", ramp(r.sequence_bearing_segments, cfg.retrans_min_segments, cfg.retrans_strong_segments),
             w["volume"], f"{r.sequence_bearing_segments} segments observed"),
        ]
        worst = r.top_flows[0] if r.top_flows else None
        dominant = worst is not None and r.retransmitted_segments and \
            worst.retransmissions / r.retransmitted_segments >= cfg.retrans_dominant_share
        return self.build(
            type=FindingType.TCP_HIGH_RETRANSMISSION, factors=factors, max_severity=cfg.max_severity,
            title="High TCP retransmission rate",
            description=(
                f"{r.retransmitted_segments} of {r.sequence_bearing_segments} sequence-bearing TCP segments "
                f"({r.retransmission_rate:.1%}) repeated an already-seen sequence number"
                + (f", mostly on {worst.src_ip}:{worst.src_port} -> {worst.dst_ip}:{worst.dst_port}" if dominant and worst else "")
                + ". This is consistent with packet loss, congestion or an unresponsive peer (a network health "
                  "indicator rather than evidence of an attack) and requires investigation."
            ),
            evidence={"retransmitted_segments": r.retransmitted_segments, "segments": r.sequence_bearing_segments,
                      "rate": r.retransmission_rate, "syn_retransmissions": r.syn_retransmissions,
                      "duplicate_acks": r.duplicate_acks,
                      "top_flows": [f.model_dump() for f in r.top_flows[:5]]},
            reasoning=[f"Retransmission rate {r.retransmission_rate:.1%} (threshold {cfg.retrans_min_rate:.0%}) over at least "
                       f"{cfg.retrans_min_segments} segments."],
            caveats=["Capture-side packet loss or duplicated packets (SPAN/mirror ports) inflate this metric.",
                     "SYN retransmissions often mean a host or port is unreachable/filtered."],
            recommendation="Check path quality (loss, duplex mismatches, congestion) for the top flows and verify that the capture point does not duplicate packets.",
            source_ip=worst.src_ip if dominant and worst else None,
            destination_ip=worst.dst_ip if dominant and worst else None, key="global",
        )

    # ------------------------------------------------------------------ resets
    def _resets(self, result: AnalysisResult) -> Finding | None:
        cfg = self.config.tcp_anomaly
        t = result.tcp_statistics
        if t.total_packets == 0 or t.rst_packets < cfg.rst_min_packets:
            return None
        ratio = t.rst_packets / t.total_packets
        if ratio < cfg.rst_min_ratio:
            return None
        w = cfg.rst_weights
        factors = [
            ("rst_ratio", ramp(ratio, cfg.rst_min_ratio, cfg.rst_strong_ratio), w["ratio"],
             f"{ratio:.0%} of TCP packets are RST"),
            ("volume", ramp(t.rst_packets, cfg.rst_min_packets, cfg.rst_strong_packets), w["volume"],
             f"{t.rst_packets} RST packets"),
        ]
        cs = result.connection_summary
        return self.build(
            type=FindingType.TCP_EXCESSIVE_RESETS, factors=factors, max_severity=cfg.max_severity,
            title="Unusually high share of TCP resets",
            description=(
                f"{t.rst_packets} of {t.total_packets} TCP packets ({ratio:.0%}) were RSTs. This is consistent with "
                f"refused connections to closed ports (for example during scanning), aborted sessions or middlebox "
                f"interference, and requires investigation."
            ),
            evidence={"rst_packets": t.rst_packets, "tcp_packets": t.total_packets, "rst_ratio": round(ratio, 4),
                      "tcp_connections_with_rst": cs.tcp_with_rst, "total_connections": cs.total_connections},
            reasoning=[f"RST ratio {ratio:.0%} (threshold {cfg.rst_min_ratio:.0%}) over at least {cfg.rst_min_packets} RSTs."],
            caveats=["Applications that close sockets abruptly (some browsers, load balancers) generate many RSTs.",
                     "Firewalls rejecting traffic with RST show the same pattern."],
            recommendation="Find which hosts send the RSTs (Wireshark filter: tcp.flags.reset == 1) and whether they correspond to refused ports or policy rejections.",
            key="global",
        )
