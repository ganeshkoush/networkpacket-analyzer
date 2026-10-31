"""API models for the interactive Network Map: local host -> (applications) -> domains -> IP addresses -> ports.

The map is *derived* from analysis results that already exist (connections, performance, findings, optional OS process
snapshots); filtering, the node budget and the health states are computed here so the UI only draws and handles clicks.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

NodeKind = Literal["local", "application", "domain", "group", "ip", "port", "other"]  # group: addresses with no DNS name
MapState = Literal["healthy", "degraded", "suspicious", "unknown"]  # unknown: nothing measurable to judge by


class MapNode(BaseModel):
    id: str
    kind: NodeKind
    label: str
    sublabel: str | None = None
    tier: int  # 0 local, 1 applications (when shown), 2 domains, 3 IP addresses, 4 ports
    state: MapState = "unknown"
    state_reasons: list[str] = Field(default_factory=list)
    connections: int = 0
    bytes: int = 0
    latency_ms: float | None = None  # typical RTT of the node's connections, else handshake time (never both mixed)
    latency_kind: Literal["rtt", "handshake"] | None = None
    domain: str | None = None  # click-through: the domain's details
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    finding_ids: list[str] = Field(default_factory=list)  # security findings that mention this address
    connection_ids: list[str] = Field(default_factory=list)  # connections behind this node (bounded)
    members: int | None = None  # for "other": how many destinations were folded in
    detail_available: bool = True  # False: known only from a finding (no connection detail was kept for it)


class MapEdge(BaseModel):
    id: str
    source: str
    target: str
    connections: int
    bytes: int
    protocol: str | None = None  # "TCP", "UDP" or "TCP+UDP"
    ports: list[int] = Field(default_factory=list)  # bounded
    latency_ms: float | None = None
    latency_kind: Literal["rtt", "handshake"] | None = None
    state: MapState = "unknown"
    connection_ids: list[str] = Field(default_factory=list)


class MapConnection(BaseModel):
    """One connection behind the map, for the connection detail panel."""

    id: str
    protocol: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    domain: str | None = None
    application: str | None = None  # OS-reported (never from packets); only when process information matched
    process_name: str | None = None
    start_time: float
    end_time: float
    duration_seconds: float
    bytes: int
    packets: int
    state: str | None = None
    handshake_ms: float | None = None
    rtt_ms: float | None = None
    retransmissions: int | None = None
    health: MapState = "unknown"
    health_reasons: list[str] = Field(default_factory=list)


class MapFinding(BaseModel):
    id: str
    type: str
    severity: str
    confidence: float
    title: str
    source_ip: str | None = None
    destination_ip: str | None = None


class LocalHostOption(BaseModel):
    ip: str
    connections: int


class HiddenSummary(BaseModel):
    destinations: int = 0
    connections: int = 0
    bytes: int = 0


class NetworkMap(BaseModel):
    nodes: list[MapNode]
    edges: list[MapEdge]
    connections: list[MapConnection]
    findings: list[MapFinding]
    local: str  # the selected local host's IP, or "all"
    local_hosts: list[LocalHostOption]
    capture_start: float | None = None
    capture_end: float | None = None
    applied_start: float | None = None
    applied_end: float | None = None
    total_connections: int = 0  # connections the analysis keeps detail for
    shown_connections: int = 0
    hidden: HiddenSummary = Field(default_factory=HiddenSummary)  # folded into the "more destinations" node by the node budget
    applications_status: str | None = None  # why applications are not shown, when they were requested
    notes: list[str] = Field(default_factory=list)
