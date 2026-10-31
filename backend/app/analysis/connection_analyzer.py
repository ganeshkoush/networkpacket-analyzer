"""Connection (flow) tracking for TCP, UDP and ICMP."""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from app.analysis.connection_tracker import (
    HANDSHAKE_COMPLETED, HANDSHAKE_INCOMPLETE, FlowKey, Handshake, connection_id, flow_key, resolve_handshake, tcp_state,
)
from app.analysis.pcap_parser import PacketRecord
from app.analysis.tcp_analyzer import ACK, FIN, RST, SYN, flag_names
from app.models.analysis import Connection, ConnectionSummary, DomainHandshakeTime

_MAX_TRACKED_CONNECTIONS = 200_000
_MAX_SYNS = _MAX_SYNACKS = 16  # per connection: enough to see retransmissions without unbounded growth
_MAX_EARLY_ACKS = 8


@dataclass(frozen=True, slots=True)
class TrackedFlow:
    """Read-only view of one tracked connection, used by the performance builder (all flows, not only the reported ones)."""

    key: FlowKey
    id: str
    protocol: str
    client: tuple[str, int | None]
    server: tuple[str, int | None]
    bytes: int
    start: float
    end: float
    handshake_ms: float | None  # completed handshakes only
    packets: int = 0
    resets: int = 0  # RST packets (TCP)
    handshake_status: str | None = None
    handshake_reason: str | None = None  # why an incomplete handshake is incomplete (see resolve_handshake)


@dataclass(slots=True)
class _Conn:
    protocol: str
    client: tuple[str, int | None]
    server: tuple[str, int | None]
    start: float
    end: float
    pkts: list[int] = field(default_factory=lambda: [0, 0])  # [c->s, s->c]
    size: list[int] = field(default_factory=lambda: [0, 0])
    flags: int = 0
    syn: bool = False
    synack: bool = False
    established: bool = False
    fin: bool = False
    fin_dir: list[bool] = field(default_factory=lambda: [False, False])  # FIN seen from [client, server]
    rst: bool = False
    rsts: int = 0
    # Handshake packets, kept as small tuples and paired at result() time (see resolve_handshake).
    syns: list = field(default_factory=list)      # (ts, seq, direction)
    synacks: list = field(default_factory=list)   # (ts, seq, ack, direction)
    acks: list = field(default_factory=list)      # (ts, seq, ack, direction)


class ConnectionAnalyzer:
    """Groups packets into bidirectional flows keyed by protocol and endpoint pair.

    The first sender seen for a flow is labelled the *client*. Flows are never closed
    or timed out, so port reuse within one capture merges into one flow.

    ``result()`` can enrich connections with data other analyzers own (retransmission indicators,
    DNS-inferred domains) through optional lookups, so no analysis logic is duplicated here.
    """

    def __init__(self, max_connections: int = 200, max_domains: int = 500) -> None:
        self.max_connections = max_connections
        self.max_domains = max_domains
        self._conns: dict[tuple, _Conn] = {}
        self._dropped = 0
        self._handshake_cache: dict[FlowKey, Handshake] | None = None

    def add(self, pkt: PacketRecord) -> None:
        if not pkt.src_ip or not pkt.dst_ip or pkt.transport is None:
            return
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        key = flow_key(pkt.transport, a, b)
        conn = self._conns.get(key)
        if conn is None:
            if len(self._conns) >= _MAX_TRACKED_CONNECTIONS:
                self._dropped += 1
                return
            conn = self._conns[key] = _Conn(pkt.transport, a, b, pkt.timestamp, pkt.timestamp)
        self._handshake_cache = None
        direction = 0 if a == conn.client else 1
        conn.pkts[direction] += 1
        conn.size[direction] += pkt.size
        conn.start = min(conn.start, pkt.timestamp)
        conn.end = max(conn.end, pkt.timestamp)
        if pkt.transport == "TCP" and pkt.tcp_flags is not None:
            self._update_tcp(conn, direction, pkt)

    @staticmethod
    def _update_tcp(conn: _Conn, direction: int, pkt: PacketRecord) -> None:
        flags = pkt.tcp_flags or 0
        conn.flags |= flags
        if pkt.tcp_seq is not None:
            ts, seq, ack = pkt.timestamp, pkt.tcp_seq, pkt.tcp_ack
            if flags & SYN and not flags & (ACK | RST):
                if len(conn.syns) < _MAX_SYNS:
                    conn.syns.append((ts, seq, direction))
            elif flags & SYN and flags & ACK and not flags & RST:
                if ack is not None and len(conn.synacks) < _MAX_SYNACKS:
                    conn.synacks.append((ts, seq, ack, direction))
            elif flags & ACK and not flags & (SYN | FIN | RST):
                if ack is not None and len(conn.acks) < _MAX_EARLY_ACKS:
                    conn.acks.append((ts, seq, ack, direction))
        if flags & RST:
            conn.rst = True
            conn.rsts += 1
        if flags & FIN:
            conn.fin = True
            conn.fin_dir[direction] = True
        if direction == 0 and flags & SYN and not flags & ACK:
            conn.syn = True
        elif direction == 1 and flags & SYN and flags & ACK and conn.syn:
            conn.synack = True
        elif direction == 0 and flags & ACK and not flags & SYN and conn.synack:
            conn.established = True

    def result(
        self,
        *,
        retransmissions: Callable[[tuple[str, int | None], tuple[str, int | None]], int] | None = None,
        domain_for_flow: Callable[[FlowKey], tuple[str, bool] | None] | None = None,
    ) -> tuple[list[Connection], ConnectionSummary]:
        """Top connections by bytes plus a summary.

        Args:
            retransmissions: ``f(endpoint_a, endpoint_b) -> int`` for TCP retransmission indicators.
            domain_for_flow: ``f(flow_key) -> (domain, ambiguous) | None`` for DNS-inferred domains.
        """
        ranked = sorted(self._conns.items(), key=lambda kv: sum(kv[1].size), reverse=True)
        by_proto = Counter(c.protocol for c in self._conns.values())
        tcp = {k: c for k, c in self._conns.items() if c.protocol == "TCP"}
        handshakes = self._handshakes()
        # An order-independent handshake match is stronger evidence than the first-sender heuristic.
        completed = {k for k, h in handshakes.items() if h.status == HANDSHAKE_COMPLETED}
        out = [self._to_model(key, c, handshakes.get(key), key in completed, retransmissions, domain_for_flow)
               for key, c in ranked[: self.max_connections]]
        summary = ConnectionSummary(
            total_connections=len(self._conns) + self._dropped,
            reported_connections=len(out),
            by_protocol=dict(by_proto),
            tcp_handshakes_complete=sum(1 for k, c in tcp.items() if c.established or k in completed),
            tcp_with_rst=sum(1 for c in tcp.values() if c.rst),
            by_state=dict(Counter(self._state(c, k in completed) for k, c in tcp.items())),
            connections_not_tracked=self._dropped,
            handshakes_timed=len(completed),
            handshakes_incomplete=len(tcp) - len(completed),
            **self._handshake_aggregates(handshakes, domain_for_flow),
        )
        return out, summary

    def _handshakes(self) -> dict[FlowKey, Handshake]:
        if self._handshake_cache is None:
            self._handshake_cache = {k: resolve_handshake(c.syns, c.synacks, c.acks, c.rst)
                                     for k, c in self._conns.items() if c.protocol == "TCP"}
        return self._handshake_cache

    def tracked(self) -> list[TrackedFlow]:
        """Every tracked connection, largest first (same order as ``result()`` ranks them)."""
        handshakes = self._handshakes()
        ranked = sorted(self._conns.items(), key=lambda kv: sum(kv[1].size), reverse=True)
        out = []
        for key, c in ranked:
            h = handshakes.get(key)
            out.append(TrackedFlow(
                key=key, id=connection_id(key), protocol=c.protocol, client=c.client, server=c.server,
                bytes=sum(c.size), start=c.start, end=c.end,
                handshake_ms=h.handshake_time_ms if h and h.status == HANDSHAKE_COMPLETED else None,
                packets=sum(c.pkts), resets=c.rsts,
                handshake_status=h.status if h else None, handshake_reason=h.incomplete_reason if h else None))
        return out

    def _handshake_aggregates(self, handshakes: dict[FlowKey, Handshake], domain_for_flow) -> dict:
        times = [(k, h.handshake_time_ms) for k, h in handshakes.items()
                 if h.status == HANDSHAKE_COMPLETED and h.handshake_time_ms is not None]
        by_domain: dict[str, list[float]] = {}
        if domain_for_flow:
            for key, ms in times:
                hit = domain_for_flow(key)
                if hit:
                    by_domain.setdefault(hit[0], []).append(ms)
        stats = [DomainHandshakeTime(domain=d, samples=len(v), avg_handshake_ms=round(sum(v) / len(v), 3),
                                     min_handshake_ms=min(v), max_handshake_ms=max(v)) for d, v in by_domain.items()]
        stats.sort(key=lambda s: (-s.avg_handshake_ms, s.domain))
        return {"avg_handshake_ms": round(sum(ms for _, ms in times) / len(times), 3) if times else None,
                "handshake_by_domain": stats[: self.max_domains]}

    @staticmethod
    def _state(c: _Conn, handshake_matched: bool = False) -> str:
        return tcp_state(syn=c.syn or handshake_matched, synack=c.synack or handshake_matched,
                         established=c.established or handshake_matched,
                         fin_client=c.fin_dir[0], fin_server=c.fin_dir[1], rst=c.rst)

    @classmethod
    def _to_model(cls, key: FlowKey, c: _Conn, hs: Handshake | None, matched: bool,
                  retransmissions, domain_for_flow) -> Connection:
        is_tcp = c.protocol == "TCP"
        domain = domain_for_flow(key) if domain_for_flow else None
        return Connection(
            id=connection_id(key),
            protocol=c.protocol,
            client_ip=c.client[0],
            client_port=c.client[1],
            server_ip=c.server[0],
            server_port=c.server[1],
            packets=sum(c.pkts),
            bytes=sum(c.size),
            packets_client_to_server=c.pkts[0],
            packets_server_to_client=c.pkts[1],
            bytes_client_to_server=c.size[0],
            bytes_server_to_client=c.size[1],
            start_time=c.start,
            end_time=c.end,
            duration_seconds=round(c.end - c.start, 6),
            handshake_complete=(c.established or matched) if is_tcp else None,
            syn_seen=(c.syn or matched) if is_tcp else None,
            synack_seen=(c.synack or matched) if is_tcp else None,
            fin_seen=c.fin if is_tcp else None,
            rst_seen=c.rst if is_tcp else None,
            tcp_flags_seen=flag_names(c.flags) if is_tcp else None,
            state=cls._state(c, matched) if is_tcp else None,
            resets=c.rsts if is_tcp else None,
            retransmissions=retransmissions(c.client, c.server) if is_tcp and retransmissions else None,
            domain=domain[0] if domain else None,
            domain_ambiguous=domain[1] if domain else False,
            handshake_status=hs.status if hs else None,
            handshake_incomplete_reason=hs.incomplete_reason if hs else None,
            tcp_syn_timestamp=hs.syn_timestamp if hs else None,
            tcp_syn_ack_timestamp=hs.syn_ack_timestamp if hs else None,
            tcp_ack_timestamp=hs.ack_timestamp if hs else None,
            tcp_syn_ack_latency_ms=hs.syn_ack_latency_ms if hs else None,
            tcp_ack_latency_ms=hs.ack_latency_ms if hs else None,
            tcp_handshake_time_ms=hs.handshake_time_ms if hs else None,
            tcp_syn_retransmissions=hs.syn_retransmissions if hs else None,
            tcp_syn_ack_retransmissions=hs.syn_ack_retransmissions if hs else None,
        )
