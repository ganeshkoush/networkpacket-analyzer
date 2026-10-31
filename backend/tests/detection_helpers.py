"""Build AnalysisResult objects directly (no pcap) for detector unit tests."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.analysis import (
    AnalysisResult,
    CaptureMetadata,
    ConnectionSummary,
    DnsStatistics,
    IpStatistics,
    PacketStatistics,
    PortStatistics,
    ProtocolStatistics,
    TcpStatistics,
)

T0 = 1_700_000_000.0


def blank_result(**sections) -> AnalysisResult:
    """An empty, valid AnalysisResult; pass section models to override (e.g. tcp_statistics=...)."""
    base = dict(
        metadata=CaptureMetadata(
            file_name="x.pcap", file_path="/x.pcap", file_size_bytes=0, sha256="0" * 64,
            capture_format="pcap", packets_read=0, analyzed_at=datetime.now(timezone.utc)),
        packet_statistics=PacketStatistics(),
        protocol_statistics=ProtocolStatistics(),
        ip_statistics=IpStatistics(),
        port_statistics=PortStatistics(),
        tcp_statistics=TcpStatistics(),
        dns_statistics=DnsStatistics(),
        connections=[],
        connection_summary=ConnectionSummary(),
        timeline=[],
    )
    base.update(sections)
    return AnalysisResult(**base)


HEDGES = ("possible", "consistent with", "suspicious", "likely", "requires investigation")
OVERCLAIMS = ("definitely", "confirmed attack", "is malicious", "proves", "certainly")


def assert_well_formed(finding, ceiling=0.95):
    """Properties every finding must satisfy: evidence, hedged wording, bounded confidence."""
    assert finding.evidence, "finding has no evidence"
    assert finding.recommendation and finding.reasoning and finding.caveats
    assert 0 < finding.confidence <= ceiling
    text = f"{finding.title} {finding.description}".lower()
    assert any(h in text for h in HEDGES), f"no hedged wording: {finding.description}"
    assert not any(o in text for o in OVERCLAIMS)
    assert sum(f.weight for f in finding.confidence_factors) > 0
