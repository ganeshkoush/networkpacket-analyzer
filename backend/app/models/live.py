"""Pydantic models for live capture (API request/response contract)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.ai.schemas import InvestigationReport
from app.detection.models import Finding
from app.models.analysis import PortCount, ProtocolStat, Talker

InterfaceKind = Literal["wifi", "ethernet", "vpn", "loopback", "other"]
LiveState = Literal["stopped", "capturing", "permission_error", "error"]


class InterfaceInfo(BaseModel):
    name: str
    description: str
    kind: InterfaceKind
    addresses: list[str] = Field(default_factory=list)
    is_up: bool | None = None


class StartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=256)
    confirm: bool = Field(False, description="Must be true: capture only starts on an explicit user action")
    auto_investigate: bool = Field(
        False, description="Opt in to sending structured evidence of suspicious events to the AI provider")
    save: bool | None = Field(None, description="Record the packets to a standard capture file in the managed capture folder; None = the 'Automatically save captures' setting")
    format: Literal["pcap", "pcapng"] | None = Field(None, description="None = the default capture format setting")


class LiveError(BaseModel):
    code: str
    message: str
    hint: str | None = None


class LiveInvestigation(BaseModel):
    status: Literal["pending", "completed", "failed"]
    requested_at: float
    report: InvestigationReport | None = None
    error: LiveError | None = None


class LiveFindingEvent(BaseModel):
    """A suspicious event: the latest detector finding plus bookkeeping across windows."""

    finding: Finding
    first_detected_at: float
    last_detected_at: float
    detections: int  # analysis windows in which the detector fired
    active: bool  # still present in the most recent window
    investigation: LiveInvestigation | None = None


class LiveCaptureFile(BaseModel):
    """The file this capture is being (or was) saved to. Names only: no filesystem paths are exposed."""

    id: str
    filename: str
    format: Literal["pcap", "pcapng"]
    status: Literal["CAPTURING", "COMPLETED", "ANALYZING", "ANALYZED", "FAILED"]
    packets: int = 0  # packets written to the file so far
    bytes: int = 0  # captured bytes written so far
    file_size: int = 0
    error: str | None = None
    rotated: int = 0  # earlier files this capture was split into (capture file rotation)


class LiveStatus(BaseModel):
    state: LiveState
    interface: str | None = None
    started_at: float | None = None
    elapsed_seconds: float = 0.0
    packets_total: int = 0
    bytes_total: int = 0
    packets_per_second: float = 0.0  # over the recent rate window
    bits_per_second: float = 0.0
    window_seconds: float = 0.0  # span of traffic currently in the rolling window
    window_packets: int = 0
    window_truncated: bool = False  # packet cap forced the window shorter than configured
    last_analysis_at: float | None = None
    protocols: list[ProtocolStat] = Field(default_factory=list)
    top_talkers: list[Talker] = Field(default_factory=list)
    top_ports: list[PortCount] = Field(default_factory=list)
    findings: list[LiveFindingEvent] = Field(default_factory=list)
    capture: LiveCaptureFile | None = None
    notice: str | None = None  # e.g. why PacketMind stopped the capture by itself (size/duration limit)
    auto_investigate: bool = False
    parse_errors: int = 0
    error: LiveError | None = None
