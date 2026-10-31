"""TCP statistics: flags, handshake/SYN profiles, abnormal flags, retransmission indicators."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.analysis.pcap_parser import PacketRecord
from app.models.analysis import (
    FlagAnomaly,
    FlagCombination,
    RetransmissionFlow,
    RetransmissionStatistics,
    SynPair,
    SynSource,
    SynTarget,
    TcpStatistics,
)

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
_FLAG_NAMES = (("FIN", FIN), ("SYN", SYN), ("RST", RST), ("PSH", PSH),
               ("ACK", ACK), ("URG", URG), ("ECE", ECE), ("CWR", CWR))
_COMBO_ORDER = ("SYN", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "ACK")

_MAX_TRACKED_FLOWS = 100_000
_MAX_SEQS_PER_FLOW = 2048
_MAX_SYN_SOURCES = 50_000
_MAX_SYN_PAIRS = 100_000
_MAX_SYN_TARGETS = 50_000
_MAX_SOURCES_PER_TARGET = 5_000
_MAX_SET = 100_000
_MAX_FLAG_ANOMALIES = 50_000
_SAMPLE_PORTS = 20


def flag_names(flags: int) -> list[str]:
    """Names of the TCP flags set in ``flags`` (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)."""
    return [name for name, bit in _FLAG_NAMES if flags & bit]


def flag_combination(flags: int) -> str:
    """Canonical label such as ``"SYN,ACK"``; ``"NONE"`` when no flag is set."""
    names = set(flag_names(flags))
    return ",".join(n for n in _COMBO_ORDER if n in names) or "NONE"


def abnormal_flag_label(flags: int) -> str | None:
    """Name the abnormal flag combination, or ``None`` for a normal-looking one.

    Rules (each is a combination that normal TCP stacks do not send):
    NULL (no FIN/SYN/RST/PSH/ACK/URG), SYN+FIN, SYN+RST, FIN+RST, XMAS (FIN+PSH+URG),
    FIN without ACK, and data/URG flags without ACK on a non-SYN, non-RST packet.
    """
    core = flags & 0x3F
    syn, fin, rst = bool(flags & SYN), bool(flags & FIN), bool(flags & RST)
    ack, psh, urg = bool(flags & ACK), bool(flags & PSH), bool(flags & URG)
    if core == 0:
        return "NULL"
    if syn and fin:
        return "SYN+FIN"
    if syn and rst:
        return "SYN+RST"
    if fin and rst:
        return "FIN+RST"
    if fin and psh and urg:
        return "XMAS"
    if fin and not ack:
        return "FIN_NO_ACK"
    if not (syn or rst or ack):
        return "NO_ACK"
    return None


@dataclass(slots=True)
class _FlowState:
    seen: dict[int, int] = field(default_factory=dict)  # seq -> longest segment length seen
    last_ack: int | None = None
    last_ack_seq: int | None = None
    retransmissions: int = 0
    segments: int = 0


@dataclass(slots=True)
class _SrcSyn:
    syn: int = 0
    synack_received: int = 0
    rst_received: int = 0
    hosts: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0


@dataclass(slots=True)
class _PairSyn:
    syn: int = 0
    synack: int = 0
    rst: int = 0
    ports: set[int] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0


@dataclass(slots=True)
class _TargetSyn:
    syn: int = 0
    synack_sent: int = 0
    ack_in: int = 0
    sources: dict[str, int] = field(default_factory=dict)
    sources_capped: bool = False
    first: float = 0.0
    last: float = 0.0
    cur_sec: int = -1
    cur_count: int = 0
    peak: int = 0


class TcpAnalyzer:
    """Per-packet TCP counters, SYN profiles and heuristic retransmission detection.

    A segment is flagged as a *retransmission indicator* when its sequence number was
    already seen in the same direction of the same flow with at least the same length
    (segments occupying sequence space: payload bytes, SYN, FIN). Duplicate ACKs are
    repeated identical pure ACKs. Both are heuristics and can be fooled by packet loss
    in the capture itself.

    SYN profiles (per source, per source/destination pair and per destination ip:port)
    are raw aggregates; deciding what is suspicious is left to the detection layer.
    """

    def __init__(self, top_n: int = 20, max_profiles: int = 100) -> None:
        self.top_n = top_n
        self.max_profiles = max_profiles
        self._total = 0
        self._flags: Counter[str] = Counter()
        self._combos: Counter[str] = Counter()
        self._syn = self._synack = self._ack_only = self._rst = self._fin = 0
        self._srcs: dict[str, _SrcSyn] = {}
        self._pairs: dict[tuple[str, str], _PairSyn] = {}
        self._targets: dict[tuple[str, int], _TargetSyn] = {}
        self._anomalies: dict[tuple[str, str, str], list] = {}  # key -> [packets, first, last, flags]
        self._profiles_dropped = 0
        self._flows: dict[tuple[str, int, str, int], _FlowState] = {}
        self._flows_dropped = 0
        self._seq_segments = 0
        self._retrans = 0
        self._syn_retrans = 0
        self._dup_acks = 0

    def flow_retransmissions(self, a: tuple[str, int | None], b: tuple[str, int | None]) -> int:
        """Retransmission indicators seen in both directions between endpoints ``a`` and ``b``."""
        total = 0
        for (sip, sport), (dip, dport) in ((a, b), (b, a)):
            state = self._flows.get((sip, sport, dip, dport))  # type: ignore[arg-type]
            if state is not None:
                total += state.retransmissions
        return total

    # ------------------------------------------------------------------ ingest
    def add(self, pkt: PacketRecord) -> None:
        if pkt.transport != "TCP" or pkt.tcp_flags is None:
            return
        flags = pkt.tcp_flags
        self._total += 1
        for name in flag_names(flags):
            self._flags[name] += 1
        self._combos[flag_combination(flags)] += 1

        is_syn = bool(flags & SYN)
        is_ack = bool(flags & ACK)
        if is_syn and not is_ack:
            self._syn += 1
            self._on_syn(pkt)
        elif is_syn and is_ack:
            self._synack += 1
            self._on_synack(pkt)
        if flags & (SYN | FIN | RST | PSH | URG) == 0 and is_ack:
            self._ack_only += 1
        if flags & RST:
            self._rst += 1
            self._on_rst(pkt)
        if flags & FIN:
            self._fin += 1
        if is_ack and not is_syn and not flags & RST:
            self._on_ack_in(pkt)

        label = abnormal_flag_label(flags)
        if label and pkt.src_ip and pkt.dst_ip:
            self._on_anomaly(pkt, label)

        self._track_flow(pkt, flags)

    def _on_syn(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip or pkt.dst_port is None:
            return
        ts = pkt.timestamp
        src = self._srcs.get(pkt.src_ip)
        if src is None and len(self._srcs) < _MAX_SYN_SOURCES:
            src = self._srcs[pkt.src_ip] = _SrcSyn(first=ts, last=ts)
        if src is not None:
            src.syn += 1
            src.first, src.last = min(src.first, ts), max(src.last, ts)
            if len(src.hosts) < _MAX_SET:
                src.hosts.add(pkt.dst_ip)
            if len(src.ports) < _MAX_SET:
                src.ports.add(pkt.dst_port)
        else:
            self._profiles_dropped += 1

        pair = self._pairs.get((pkt.src_ip, pkt.dst_ip))
        if pair is None and len(self._pairs) < _MAX_SYN_PAIRS:
            pair = self._pairs[(pkt.src_ip, pkt.dst_ip)] = _PairSyn(first=ts, last=ts)
        if pair is not None:
            pair.syn += 1
            pair.first, pair.last = min(pair.first, ts), max(pair.last, ts)
            pair.ports.add(pkt.dst_port)

        key = (pkt.dst_ip, pkt.dst_port)
        tgt = self._targets.get(key)
        if tgt is None and len(self._targets) < _MAX_SYN_TARGETS:
            tgt = self._targets[key] = _TargetSyn(first=ts, last=ts)
        if tgt is not None:
            tgt.syn += 1
            tgt.first, tgt.last = min(tgt.first, ts), max(tgt.last, ts)
            if pkt.src_ip in tgt.sources:
                tgt.sources[pkt.src_ip] += 1
            elif len(tgt.sources) < _MAX_SOURCES_PER_TARGET:
                tgt.sources[pkt.src_ip] = 1
            else:
                tgt.sources_capped = True
            sec = int(ts)
            if sec != tgt.cur_sec:
                tgt.cur_sec, tgt.cur_count = sec, 0
            tgt.cur_count += 1
            tgt.peak = max(tgt.peak, tgt.cur_count)

    def _on_synack(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip:
            return
        src = self._srcs.get(pkt.dst_ip)
        if src is not None:
            src.synack_received += 1
        pair = self._pairs.get((pkt.dst_ip, pkt.src_ip))
        if pair is not None:
            pair.synack += 1
        if pkt.src_port is not None:
            tgt = self._targets.get((pkt.src_ip, pkt.src_port))
            if tgt is not None:
                tgt.synack_sent += 1

    def _on_rst(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip:
            return
        src = self._srcs.get(pkt.dst_ip)
        if src is not None:
            src.rst_received += 1
        pair = self._pairs.get((pkt.dst_ip, pkt.src_ip))
        if pair is not None:
            pair.rst += 1

    def _on_ack_in(self, pkt: PacketRecord) -> None:
        if pkt.dst_ip and pkt.dst_port is not None:
            tgt = self._targets.get((pkt.dst_ip, pkt.dst_port))
            if tgt is not None:
                tgt.ack_in += 1

    def _on_anomaly(self, pkt: PacketRecord, label: str) -> None:
        key = (pkt.src_ip, pkt.dst_ip, label)  # type: ignore[assignment]
        entry = self._anomalies.get(key)
        if entry is None:
            if len(self._anomalies) >= _MAX_FLAG_ANOMALIES:
                return
            self._anomalies[key] = [1, pkt.timestamp, pkt.timestamp, flag_combination(pkt.tcp_flags or 0)]
        else:
            entry[0] += 1
            entry[1], entry[2] = min(entry[1], pkt.timestamp), max(entry[2], pkt.timestamp)

    def _track_flow(self, pkt: PacketRecord, flags: int) -> None:
        if None in (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.tcp_seq):
            return
        payload = pkt.payload_len or 0
        seg_len = payload + (1 if flags & SYN else 0) + (1 if flags & FIN else 0)
        is_pure_ack = flags & (SYN | FIN | RST) == 0 and flags & ACK and payload == 0
        if seg_len == 0 and not is_pure_ack:
            return  # e.g. bare RST: nothing to track

        key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)  # type: ignore[assignment]
        state = self._flows.get(key)
        if state is None:
            if len(self._flows) >= _MAX_TRACKED_FLOWS:
                self._flows_dropped += 1
                return
            state = self._flows[key] = _FlowState()

        if seg_len > 0 and not flags & RST:
            self._seq_segments += 1
            state.segments += 1
            previous = state.seen.get(pkt.tcp_seq)  # type: ignore[arg-type]
            if previous is not None and previous >= seg_len:
                self._retrans += 1
                state.retransmissions += 1
                if flags & SYN:
                    self._syn_retrans += 1
            else:
                if len(state.seen) >= _MAX_SEQS_PER_FLOW:
                    state.seen.pop(next(iter(state.seen)))
                state.seen[pkt.tcp_seq] = seg_len  # type: ignore[index]
        elif is_pure_ack:
            if state.last_ack == pkt.tcp_ack and state.last_ack_seq == pkt.tcp_seq:
                self._dup_acks += 1
            state.last_ack, state.last_ack_seq = pkt.tcp_ack, pkt.tcp_seq

    # ------------------------------------------------------------------ output
    def result(self) -> TcpStatistics:
        n = self.max_profiles
        sources = sorted(self._srcs.items(), key=lambda kv: kv[1].syn, reverse=True)[:n]
        syn_sources = [
            SynSource(
                ip=ip, syn_sent=s.syn, syn_ack_received=s.synack_received,
                unanswered_ratio=round(max(0.0, 1 - s.synack_received / s.syn), 4),
                rst_received=s.rst_received,
                unique_destination_hosts=len(s.hosts), unique_destination_ports=len(s.ports),
                first_syn_time=s.first, last_syn_time=s.last,
            )
            for ip, s in sources
        ]
        pairs = sorted(self._pairs.items(), key=lambda kv: (len(kv[1].ports), kv[1].syn), reverse=True)[:n]
        syn_pairs = [
            SynPair(
                src_ip=k[0], dst_ip=k[1], syn_packets=p.syn, unique_destination_ports=len(p.ports),
                syn_ack_received=p.synack, rst_received=p.rst, first_syn_time=p.first,
                last_syn_time=p.last, sample_ports=sorted(p.ports)[:_SAMPLE_PORTS],
            )
            for k, p in pairs
        ]
        targets = sorted(self._targets.items(), key=lambda kv: kv[1].syn, reverse=True)[:n]
        syn_targets = []
        for (ip, port), t in targets:
            top_ip, top_n = max(t.sources.items(), key=lambda kv: kv[1]) if t.sources else (None, 0)
            syn_targets.append(SynTarget(
                dst_ip=ip, dst_port=port, syn_packets=t.syn, unique_sources=len(t.sources),
                sources_capped=t.sources_capped, top_source_ip=top_ip, top_source_syns=top_n,
                syn_ack_sent=t.synack_sent, ack_packets_in=t.ack_in, first_syn_time=t.first,
                last_syn_time=t.last, peak_syn_per_second=t.peak,
            ))
        anomalies = sorted(self._anomalies.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
        flag_anomalies = [
            FlagAnomaly(src_ip=k[0], dst_ip=k[1], anomaly=k[2], flags=v[3], packets=v[0],
                        first_time=v[1], last_time=v[2])
            for k, v in anomalies
        ]

        worst = sorted(
            ((k, s) for k, s in self._flows.items() if s.retransmissions),
            key=lambda kv: kv[1].retransmissions, reverse=True,
        )[: self.top_n]
        retrans = RetransmissionStatistics(
            retransmitted_segments=self._retrans,
            syn_retransmissions=self._syn_retrans,
            sequence_bearing_segments=self._seq_segments,
            retransmission_rate=round(self._retrans / self._seq_segments, 4) if self._seq_segments else 0.0,
            duplicate_acks=self._dup_acks,
            top_flows=[
                RetransmissionFlow(src_ip=k[0], src_port=k[1], dst_ip=k[2], dst_port=k[3],
                                   retransmissions=s.retransmissions, segments=s.segments)
                for k, s in worst
            ],
            flows_not_tracked=self._flows_dropped,
        )
        total_synack = self._synack
        return TcpStatistics(
            total_packets=self._total,
            flag_counts=dict(self._flags),
            flag_combinations=[FlagCombination(flags=f, packets=c) for f, c in self._combos.most_common()],
            syn_packets=self._syn,
            syn_ack_packets=total_synack,
            ack_only_packets=self._ack_only,
            rst_packets=self._rst,
            fin_packets=self._fin,
            syn_to_syn_ack_ratio=round(self._syn / total_synack, 3) if total_synack else None,
            top_syn_sources=syn_sources,
            syn_pairs=syn_pairs,
            syn_targets=syn_targets,
            flag_anomalies=flag_anomalies,
            syn_profiles_not_tracked=self._profiles_dropped,
            retransmissions=retrans,
        )
