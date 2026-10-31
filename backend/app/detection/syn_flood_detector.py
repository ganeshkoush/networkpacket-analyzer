"""Possible SYN flood behaviour."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector, fmt_ts, span
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, SynTarget


class SynFloodDetector(BaseDetector):
    """Flags a destination ip:port receiving a burst of SYNs that are not being completed.

    Evidence (``tcp_statistics.syn_targets``): total SYNs, peak SYNs in one second, unique
    sources, and ``ack_packets_in`` - ACK-bearing non-SYN packets sent *to* the target. A
    completed handshake produces at least one such packet per SYN, so
    ``completion_ratio = ack_packets_in / syn_packets`` near or above 1 means connections
    are being finished (busy server), while a ratio near 0 with a high SYN rate is
    consistent with half-open connection exhaustion.
    """

    name = "syn_flood"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.syn_flood
        if not cfg.enabled:
            return []
        findings = []
        for t in result.tcp_statistics.syn_targets:
            completion = t.ack_packets_in / t.syn_packets if t.syn_packets else 0.0
            if (t.syn_packets >= cfg.min_syn_packets
                    and t.peak_syn_per_second >= cfg.min_peak_syn_per_second
                    and completion <= cfg.max_completion_ratio):
                findings.append(self._finding(t, completion))
        return findings

    def _finding(self, t: SynTarget, completion: float) -> Finding:
        cfg = self.config.syn_flood
        w = cfg.weights
        duration = span(t.first_syn_time, t.last_syn_time)
        factors = [
            ("volume", ramp(t.syn_packets, cfg.min_syn_packets, cfg.strong_syn_packets), w["volume"],
             f"{t.syn_packets} SYNs (full score at {cfg.strong_syn_packets})"),
            ("peak_rate", ramp(t.peak_syn_per_second, cfg.min_peak_syn_per_second, cfg.strong_peak_syn_per_second),
             w["peak_rate"], f"peak {t.peak_syn_per_second} SYN/s"),
            ("incomplete_handshakes", 1 - ramp(completion, cfg.low_completion_ratio, cfg.max_completion_ratio),
             w["incomplete_handshakes"], f"{t.ack_packets_in} ACK-bearing packets for {t.syn_packets} SYNs"),
            ("source_diversity", ramp(t.unique_sources, 1, cfg.strong_unique_sources), w["source_diversity"],
             f"{t.unique_sources}{'+' if t.sources_capped else ''} distinct source IPs"),
        ]
        dominant = t.syn_packets and t.top_source_syns / t.syn_packets >= cfg.dominant_source_share
        source_ip = t.top_source_ip if dominant else None
        origin = (f"mostly from {t.top_source_ip}" if dominant
                  else f"from {t.unique_sources}{'+' if t.sources_capped else ''} distinct source IPs")
        return self.build(
            type=FindingType.SYN_FLOOD,
            factors=factors,
            max_severity=cfg.max_severity,
            title=f"Possible SYN flood against {t.dst_ip}:{t.dst_port}",
            description=(
                f"{t.dst_ip}:{t.dst_port} received {t.syn_packets} SYN packets ({origin}), peaking at "
                f"{t.peak_syn_per_second} SYN/s, with only {t.ack_packets_in} ACK-bearing packets following. "
                f"This is consistent with possible SYN flood behaviour (half-open connection pressure) and "
                f"requires investigation."
            ),
            evidence={
                "target": f"{t.dst_ip}:{t.dst_port}",
                "syn_packets": t.syn_packets,
                "peak_syn_per_second": t.peak_syn_per_second,
                "unique_sources": t.unique_sources,
                "unique_sources_is_lower_bound": t.sources_capped,
                "top_source_ip": t.top_source_ip,
                "top_source_share": round(t.top_source_syns / t.syn_packets, 3) if t.syn_packets else 0,
                "syn_ack_packets_sent_by_target": t.syn_ack_sent,
                "ack_packets_in": t.ack_packets_in,
                "completion_ratio": round(completion, 4),
                "duration_seconds": round(duration, 3),
            },
            reasoning=[
                f"{t.syn_packets} SYNs to one service (threshold {cfg.min_syn_packets}).",
                f"Peak of {t.peak_syn_per_second} SYN/s (threshold {cfg.min_peak_syn_per_second}).",
                f"Completion ratio {completion:.2f}: far fewer ACK-bearing packets than SYNs suggests handshakes "
                f"are not being completed (a completing server shows >= 1 per SYN).",
            ],
            caveats=[
                "A flash crowd, retry storm after an outage, or load test can send many SYNs quickly.",
                "If the capture point is before the server (or only sees one direction), ACKs may be missing from the capture.",
                "Spoofed source addresses cannot be confirmed from the capture alone.",
            ],
            recommendation=(
                f"Verify service health on {t.dst_ip}:{t.dst_port} (half-open connection count, SYN backlog drops) and "
                f"compare against the traffic baseline. Review the sources in Wireshark (filter: ip.dst == {t.dst_ip} && "
                f"tcp.dstport == {t.dst_port} && tcp.flags.syn == 1 && tcp.flags.ack == 0). Consider SYN cookies or "
                f"rate limiting at the network edge only after confirming the traffic is not legitimate."
            ),
            source_ip=source_ip,
            destination_ip=t.dst_ip,
            key=f"{t.dst_ip}:{t.dst_port}",
            first_seen=t.first_syn_time,
            last_seen=t.last_syn_time,
        )
