"""Capture library models: one ``CaptureSession`` per saved capture file (a live recording or an imported PCAP).

The API never exposes filesystem paths: ``filename`` is the generated name inside the managed capture folder and
``original_filename`` is the sanitised name the user knows the file by.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SourceType = Literal["LIVE_CAPTURE", "UPLOADED_PCAP"]
CaptureStatus = Literal["CAPTURING", "COMPLETED", "ANALYZING", "ANALYZED", "FAILED"]
CaptureFormat = Literal["pcap", "pcapng"]


class ProtocolShare(BaseModel):
    protocol: str
    packets: int
    percent: float


class CaptureSummary(BaseModel):
    """What the analysis found, kept so the library and the 'Capture Completed' screen need not re-analyze."""

    protocols: list[ProtocolShare] = Field(default_factory=list)
    domains: int = 0
    findings: int = 0
    connections: int = 0


class CaptureSession(BaseModel):
    id: str
    filename: str
    original_filename: str
    source_type: SourceType
    capture_format: CaptureFormat = "pcap"
    interface: str | None = None
    start_time: float | None = None
    end_time: float | None = None
    duration_seconds: float | None = None
    packet_count: int = 0
    byte_count: int = 0  # captured packet bytes (live) / bytes on the wire (analysed import)
    file_size: int = 0  # size of the file on disk
    status: CaptureStatus
    error_message: str | None = None
    created_at: str
    analyzed_at: str | None = None
    summary: CaptureSummary | None = None


class ExportRequest(BaseModel):
    destination: str = Field(min_length=1, max_length=4096, description="Absolute path chosen in the save dialog")
    overwrite: bool = Field(False, description="True only after the user confirmed replacing an existing file")


class ExportResult(BaseModel):
    filename: str  # the final file name only
    directory: str  # where it was saved (the folder the user chose)
    size_bytes: int
