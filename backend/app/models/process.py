"""Models for local process <-> network connection mapping.

Everything here comes from the *operating system's socket table*, read at the moment a snapshot was taken. It is never
derived from packets: a packet capture does not say which application sent a packet. A mapping only describes a socket
that was open when the snapshot was taken, so it can only be matched to a connection that was active at that moment.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MappingConfidence = Literal["HIGH", "MEDIUM", "LOW"]

UNAVAILABLE = "Process information unavailable"


class ProcessConnectionMapping(BaseModel):
    """One socket the OS reported as belonging to one process at ``timestamp``."""

    process_name: str  # as reported by the OS (e.g. "Code Helper (Plugin)")
    pid: int
    application: str | None = None  # outermost .app bundle in the executable's path (e.g. "Visual Studio Code"); None if not an app
    local_ip: str | None  # None = bound to all addresses
    local_port: int | None
    remote_ip: str | None  # None = not connected (listening / unconnected UDP)
    remote_port: int | None
    protocol: Literal["TCP", "UDP"]
    timestamp: float  # when the OS was asked (epoch seconds)
    # HIGH: full local+remote endpoint pair. MEDIUM: connected UDP is also a full pair but UDP flows are less stable.
    # LOW: bound to a local port only, so it does not prove this process owns a given flow on that port.
    confidence: MappingConfidence


class ProcessSnapshot(BaseModel):
    timestamp: float
    platform: str
    mappings: list[ProcessConnectionMapping] = Field(default_factory=list)
    processes: int = 0
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


class ProcessSourceStatus(BaseModel):
    platform: str
    supported: bool  # a process mapping mechanism exists for this OS
    mechanism: str | None = None  # e.g. "lsof (read-only)"
    permission_note: str  # what access is needed, and what is not visible without more
    snapshots: int = 0
    first_snapshot_at: float | None = None
    last_snapshot_at: float | None = None
    watching: bool = False
    watch_interval_seconds: float | None = None
    last_error: str | None = None
    notes: list[str] = Field(default_factory=list)


class ConnectionProcessMatch(BaseModel):
    """How one observed connection was matched to an OS-reported process (never for connections without a match)."""

    connection_id: str
    process_name: str
    pid: int
    application: str | None = None
    confidence: MappingConfidence
    snapshots_matched: int  # snapshots in which the OS reported this socket for this process
    reason: str  # why this match was made
    ambiguous: bool = False  # more than one process claimed the same endpoints in different snapshots


class ApplicationUsage(BaseModel):
    """Connections of one application (or, for non-app executables, one process name) to a domain."""

    name: str  # application bundle name, else the process name
    kind: Literal["application", "process"]
    process_names: list[str]
    pids: list[int]
    connections: int
    confidence_counts: dict[str, int] = Field(default_factory=dict)  # HIGH/MEDIUM/LOW -> connections


class DomainApplications(BaseModel):
    domain: str
    status: Literal["available", "partial", "unsupported", "no_snapshots", "no_overlap", "no_matches"]
    message: str  # always starts with "Process information unavailable" unless some connections were matched
    applications: list[ApplicationUsage] = Field(default_factory=list)
    connections_considered: int = 0  # the domain's connections the analysis keeps detail for
    connections_matched: int = 0
    connections_unmatched: int = 0
    snapshots_used: int = 0
    permission_note: str = ""
    source_note: str = (
        "Application names come from the operating system's process list on this computer at the moment each snapshot was taken, "
        "not from the captured packets.")
