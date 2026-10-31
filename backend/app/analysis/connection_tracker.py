"""Connection-tracking helpers: flow identity, TCP state derivation and query filtering.

Pure functions only (no packets, no I/O). ``ConnectionAnalyzer`` feeds packets into flows and uses
these helpers; the API uses :func:`filter_connections` to answer queries over a finished result.

A connection is the bidirectional traffic between two (IP, port) endpoints over one protocol. The
TCP *state* is derived from the packets that were captured, so it describes what the capture shows
(a capture that starts mid-connection or drops packets can look "incomplete") - it is not the
state the endpoints' kernels held.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

# TCP states derived from a capture (a simplified view of the RFC 793 diagram).
SYN_SENT = "SYN_SENT"          # SYN seen, no SYN-ACK
SYN_RECEIVED = "SYN_RECEIVED"  # SYN and SYN-ACK seen, final ACK not seen
ESTABLISHED = "ESTABLISHED"    # three-way handshake completed, no FIN/RST yet
CLOSING = "CLOSING"            # FIN from one side only
CLOSED = "CLOSED"              # FIN from both sides
RESET = "RESET"                # an RST was seen
UNKNOWN = "UNKNOWN"            # no handshake/teardown seen (e.g. capture began mid-connection)

TCP_STATES = (SYN_SENT, SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED, RESET, UNKNOWN)

FlowKey = tuple  # (protocol, endpoint_a, endpoint_b) with endpoints in canonical order


def flow_key(protocol: str, src: tuple[str, int | None], dst: tuple[str, int | None]) -> FlowKey:
    """Direction-independent key: both directions of a connection map to the same key."""
    ends = sorted((src, dst), key=lambda e: (e[0], e[1] if e[1] is not None else -1))
    return (protocol, *ends)


def connection_id(key: FlowKey) -> str:
    """Stable short id for a flow key (same capture -> same ids, whichever side spoke first)."""
    protocol, a, b = key
    text = f"{protocol}|{a[0]}|{a[1]}|{b[0]}|{b[1]}"
    return hashlib.sha1(text.encode()).hexdigest()[:12]


def tcp_state(*, syn: bool, synack: bool, established: bool, fin_client: bool, fin_server: bool,
              rst: bool) -> str:
    """Derive the capture-visible TCP state from which handshake/teardown packets were seen."""
    if rst:
        return RESET
    if fin_client and fin_server:
        return CLOSED
    if fin_client or fin_server:
        return CLOSING
    if established:
        return ESTABLISHED
    if synack:
        return SYN_RECEIVED
    if syn:
        return SYN_SENT
    return UNKNOWN


# --------------------------------------------------------------------- querying
def normalize_ip(text: str) -> str:
    """Canonical text form of an IPv4/IPv6 address (raises ValueError if it is not one)."""
    return str(ipaddress.ip_address(text.strip()))


def _same_ip(candidate: str, wanted: str) -> bool:
    try:
        return normalize_ip(candidate) == wanted
    except ValueError:
        return candidate == wanted


@dataclass(frozen=True, slots=True)
class ConnectionFilter:
    """All criteria are optional and combined with AND.

    ``domain`` is a case-insensitive substring match; ``src_ip``/``dst_ip`` match the connection's
    initiator (first sender seen) and responder; ``port`` matches either endpoint's port.
    """

    domain: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    port: int | None = None
    state: str | None = None


def filter_connections(connections: Iterable, flt: ConnectionFilter) -> list:
    """Connections (``app.models.analysis.Connection``) matching every criterion in ``flt``.

    Raises:
        ValueError: ``src_ip``/``dst_ip`` is not a valid IP address.
    """
    src = normalize_ip(flt.src_ip) if flt.src_ip else None
    dst = normalize_ip(flt.dst_ip) if flt.dst_ip else None
    needle = flt.domain.strip().lower().rstrip(".") if flt.domain else None
    proto = flt.protocol.strip().upper() if flt.protocol else None
    state = flt.state.strip().upper() if flt.state else None
    out = []
    for c in connections:
        if needle and needle not in (c.domain or ""):
            continue
        if src and not _same_ip(c.client_ip, src):
            continue
        if dst and not _same_ip(c.server_ip, dst):
            continue
        if proto and c.protocol.upper() != proto:
            continue
        if flt.port is not None and flt.port not in (c.client_port, c.server_port):
            continue
        if state and (c.state or "") != state:
            continue
        out.append(c)
    return out


# --------------------------------------------------------------------- TCP handshake timing
HANDSHAKE_COMPLETED = "completed"
HANDSHAKE_INCOMPLETE = "incomplete"

# Why a handshake is incomplete (None when completed).
NO_SYN_SEEN = "no_syn_seen"          # capture began after the SYN (mid-connection) or the SYN was lost
NO_SYNACK = "no_synack"              # SYN seen, no SYN-ACK that acknowledges it
NO_FINAL_ACK = "no_final_ack"        # SYN-ACK seen, no ACK that completes it
RESET_IN_HANDSHAKE = "reset"         # an RST arrived before the handshake completed
SIMULTANEOUS_OPEN = "simultaneous_open"  # both sides sent a SYN: packets cannot be paired confidently

_SEQ_MASK = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class Handshake:
    """Timing of one TCP three-way handshake. Latencies are only set when the packets involved
    were matched by sequence/acknowledgement numbers, never inferred from arbitrary packets."""

    status: str
    incomplete_reason: str | None = None
    syn_timestamp: float | None = None
    syn_ack_timestamp: float | None = None
    ack_timestamp: float | None = None
    syn_retransmissions: int = 0
    syn_ack_retransmissions: int = 0
    syn_ack_latency_ms: float | None = None  # SYN -> SYN-ACK
    ack_latency_ms: float | None = None      # SYN-ACK -> ACK
    handshake_time_ms: float | None = None   # SYN -> ACK


def _ms(later: float, earlier: float) -> float:
    return round((later - earlier) * 1000, 3)


def resolve_handshake(syns: list, synacks: list, acks: list, rst: bool) -> Handshake:
    """Pair handshake packets of one connection and time them.

    Args:
        syns: ``(timestamp, seq, direction)`` of SYN packets (SYN set, ACK clear).
        synacks: ``(timestamp, seq, ack, direction)`` of SYN-ACK packets.
        acks: ``(timestamp, seq, ack, direction)`` of early ACK-flagged packets without SYN/FIN/RST.
        rst: an RST was seen on the connection.

    ``direction`` only has to distinguish the two endpoints, so the result does not depend on which
    side the capture happened to show first, nor on the order packets appear in the file.

    Matching rules (all must hold): the SYN-ACK comes from the other endpoint and acknowledges
    ``SYN.seq + 1``; the final ACK comes from the SYN's sender with ``seq = SYN.seq + 1`` and
    ``ack = SYN-ACK.seq + 1``; each packet is not earlier than the one it answers. With a
    retransmitted SYN or SYN-ACK the earliest copy is used, so the latencies include the
    retransmission delay (the retransmission counts say so). Otherwise the handshake is reported
    as incomplete, with the packets that could be paired and no invented latency.
    """
    if not syns:
        return Handshake(HANDSHAKE_INCOMPLETE, NO_SYN_SEEN)
    if len({d for _, _, d in syns}) > 1:
        return Handshake(HANDSHAKE_INCOMPLETE, SIMULTANEOUS_OPEN, syn_timestamp=min(t for t, _, _ in syns))

    client_dir = syns[0][2]
    syn_times: dict[int, list[float]] = {}
    for ts, seq, _ in syns:
        syn_times.setdefault(seq, []).append(ts)
    ordered = sorted(syn_times.items(), key=lambda kv: min(kv[1]))  # earliest attempt first

    for seq, times in ordered:
        syn_ts = min(times)
        replies = [(ts, s) for ts, s, ack, d in synacks
                   if d != client_dir and ack == (seq + 1) & _SEQ_MASK and ts >= syn_ts]
        if not replies:
            continue
        synack_ts, synack_seq = min(replies)
        synack_copies = sum(1 for _, s in replies if s == synack_seq)
        finals = [ts for ts, s, ack, d in acks
                  if d == client_dir and s == (seq + 1) & _SEQ_MASK
                  and ack == (synack_seq + 1) & _SEQ_MASK and ts >= synack_ts]
        common = dict(syn_timestamp=syn_ts, syn_ack_timestamp=synack_ts,
                      syn_retransmissions=len(times) - 1, syn_ack_retransmissions=synack_copies - 1,
                      syn_ack_latency_ms=_ms(synack_ts, syn_ts))
        if finals:
            ack_ts = min(finals)
            return Handshake(HANDSHAKE_COMPLETED, None, ack_timestamp=ack_ts, ack_latency_ms=_ms(ack_ts, synack_ts),
                             handshake_time_ms=_ms(ack_ts, syn_ts), **common)
        return Handshake(HANDSHAKE_INCOMPLETE, RESET_IN_HANDSHAKE if rst else NO_FINAL_ACK, **common)

    seq, times = ordered[0]
    return Handshake(HANDSHAKE_INCOMPLETE, RESET_IN_HANDSHAKE if rst else NO_SYNACK,
                     syn_timestamp=min(times), syn_retransmissions=len(times) - 1)
