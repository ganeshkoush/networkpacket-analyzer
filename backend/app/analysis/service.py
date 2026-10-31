"""Central analysis service: ``analyze_pcap(file_path)``."""
from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path

from app.analysis.arp_analyzer import ArpAnalyzer
from app.analysis.connection_analyzer import ConnectionAnalyzer
from app.analysis.dns_analyzer import DnsAnalyzer
from app.analysis.domain_analyzer import DomainAnalyzer
from app.analysis.ip_analyzer import IpAnalyzer
from app.analysis.latency_analyzer import LatencyAnalyzer
from app.analysis.performance import build_performance
from app.analysis.pcap_parser import PacketRecord, PcapParser
from app.analysis.port_analyzer import PortAnalyzer
from app.analysis.protocol_analyzer import ProtocolAnalyzer
from app.analysis.statistics import StatisticsAnalyzer, iso_time
from app.analysis.tcp_analyzer import TcpAnalyzer
from app.analysis.timeline_analyzer import TimelineAnalyzer
from app.models.analysis import AnalysisOptions, AnalysisResult, CaptureMetadata, PerformanceStatistics
from app.services.effective_config import analysis_options, apply_performance_settings, max_packets, skipped_analyzers

logger = logging.getLogger(__name__)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_analyzers(opts: AnalysisOptions) -> dict:
    stats = StatisticsAnalyzer()
    protocols = ProtocolAnalyzer()
    ips = IpAnalyzer(opts.top_n, opts.max_conversations)
    ports = PortAnalyzer(opts.top_n)
    tcp = TcpAnalyzer(opts.top_n, opts.max_profiles)
    dns = DnsAnalyzer(opts.top_n, opts.max_dns_log, opts.max_profiles,
                      opts.dns_entropy_threshold, opts.dns_entropy_min_label_length,
                      opts.dns_random_digit_share, opts.dns_random_consonant_run)
    arp = ArpAnalyzer(opts.max_profiles)
    timeline = TimelineAnalyzer(opts.timeline_max_points)
    connections = ConnectionAnalyzer(opts.max_connections, opts.max_domains)
    domains = DomainAnalyzer(opts.max_domains, opts.timeline_max_points)
    latency = LatencyAnalyzer()
    return {
        "statistics": stats, "protocols": protocols, "ip": ips, "ports": ports,
        "tcp": tcp, "dns": dns, "arp": arp, "timeline": timeline, "connections": connections, "domains": domains,
        "latency": latency,
    }



def _connection_results(analyzers: dict, failed: dict[str, str]):
    """Connections enriched with TCP retransmission indicators and DNS-inferred domains.

    Enrichment is skipped for an analyzer that failed, so a broken one never hides connections.
    """
    return analyzers["connections"].result(
        retransmissions=None if "tcp" in failed else analyzers["tcp"].flow_retransmissions,
        domain_for_flow=None if "domains" in failed else analyzers["domains"].domain_for_flow,
    )


def _performance(analyzers: dict, failed: dict[str, str], opts: AnalysisOptions, domain_stats) -> PerformanceStatistics:
    """Latency metrics; empty if a source analyzer failed (the failure is listed in ``metadata.warnings``)."""
    if {"latency", "dns", "connections"} & failed.keys():
        return PerformanceStatistics()
    domains = analyzers["domains"] if "domains" not in failed else None
    tcp = analyzers["tcp"] if "tcp" not in failed else None
    return build_performance(
        analyzers["connections"].tracked(), analyzers["latency"], analyzers["dns"],
        domains.domain_for_flow if domains else None, opts.max_connections, opts.max_domains,
        retransmissions=tcp.flow_retransmissions if tcp else None,
        traffic_series=domains.traffic_series if domains else None,
        series_domains=[d.domain for d in domain_stats.domains],
        lookup_samples=analyzers["dns"].lookup_samples())


PROGRESS_EVERY = 2000  # packets between progress callbacks


def analyze_pcap(
    file_path: str | Path,
    options: AnalysisOptions | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> AnalysisResult:
    """Analyze a PCAP/PCAPNG file locally and return structured, aggregated results.

    The capture is streamed once; every analyzer sees each packet and retains only
    aggregates, so raw packets are never held in memory or returned.

    Args:
        file_path: Path to a ``.pcap`` or ``.pcapng`` file.
        options: Output/memory limits; defaults are used when omitted.
        on_progress: Optional ``callback(packets_read, bytes_read)`` invoked every
            ``PROGRESS_EVERY`` packets and once at the end. Exceptions it raises are ignored.

    Raises:
        FileNotFoundError: the file does not exist.
        InvalidCaptureError: the file is not a readable capture.

    A capture that becomes unreadable part-way (truncated/corrupt) does *not* raise:
    the packets read so far are analyzed and the problem is reported in
    ``metadata.read_error`` / ``metadata.warnings``.
    """
    started = time.perf_counter()
    opts = options or analysis_options()  # the user's Analysis/Privacy settings (code defaults when unchanged)
    skipped, limit = skipped_analyzers(), max_packets()
    path = Path(file_path)
    parser = PcapParser(path)  # validates the file before any work is done

    analyzers = _build_analyzers(opts)
    stats, protocols, ips, ports = analyzers["statistics"], analyzers["protocols"], analyzers["ip"], analyzers["ports"]
    tcp, dns, arp = analyzers["tcp"], analyzers["dns"], analyzers["arp"]
    timeline, connections = analyzers["timeline"], analyzers["connections"]
    failed: dict[str, str] = {}

    def report() -> None:
        if on_progress is not None:
            try:
                on_progress(parser.packets_read, parser.bytes_read)
            except Exception:  # progress is best-effort and must never break analysis
                logger.debug("progress callback failed", exc_info=True)

    stopped_early = False
    for record in parser:
        if limit and record.index > limit:
            stopped_early = True
            break
        if record.index % PROGRESS_EVERY == 0:
            report()
        for name, analyzer in analyzers.items():
            if name in failed or name in skipped:
                continue
            try:
                analyzer.add(record)
            except Exception as exc:  # one broken analyzer must not sink the analysis
                failed[name] = f"{type(exc).__name__}: {exc}"
                logger.exception("Analyzer '%s' failed on packet #%d; disabling it", name, record.index)

    report()
    warnings: list[str] = []
    if parser.read_error:
        warnings.append(f"Capture ended unexpectedly ({parser.read_error}); results cover {parser.packets_read} packets.")
    if parser.malformed_packets:
        warnings.append(f"{parser.malformed_packets} malformed packet(s) were counted by size/time only.")
    if parser.snaplen_truncated_packets:
        warnings.append(f"{parser.snaplen_truncated_packets} packet(s) were truncated by the capture snap length.")
    for name, err in failed.items():
        warnings.append(f"Analyzer '{name}' failed and its results are incomplete: {err}")
    if stopped_early:
        warnings.append(f"Analysis stopped after {limit:,} packets because of the 'Maximum packets analyzed' setting; the rest of the capture was not analysed.")
    if skipped:
        warnings.append("Turned off in Settings → Analysis: " + ", ".join(sorted(skipped)) + ". Their results are empty.")
    if parser.packets_read == 0:
        warnings.append("Capture contains no packets.")

    conn_list, conn_summary = _connection_results(analyzers, failed | {n: "off" for n in skipped})
    metadata = CaptureMetadata(
        file_name=path.name,
        file_path=str(path.resolve()),
        file_size_bytes=path.stat().st_size,
        sha256=_sha256(path),
        capture_format=parser.format,
        packets_read=parser.packets_read,
        malformed_packets=parser.malformed_packets,
        snaplen_truncated_packets=parser.snaplen_truncated_packets,
        read_error=parser.read_error,
        warnings=warnings,
        first_packet_time=stats.first_time,
        last_packet_time=stats.last_time,
        first_packet_time_iso=iso_time(stats.first_time),
        last_packet_time_iso=iso_time(stats.last_time),
        duration_seconds=round(stats.duration, 6),
        analyzed_at=datetime.now(timezone.utc),
        analysis_seconds=round(time.perf_counter() - started, 3),
    )
    domain_stats = analyzers["domains"].result()
    return apply_performance_settings(AnalysisResult(
        metadata=metadata,
        packet_statistics=stats.result(timeline.peak_packets_per_second),
        protocol_statistics=protocols.result(),
        ip_statistics=ips.result(),
        port_statistics=ports.result(),
        tcp_statistics=tcp.result(),
        dns_statistics=dns.result(),
        arp_statistics=arp.result(),
        connections=conn_list,
        connection_summary=conn_summary,
        timeline=timeline.result(),
        domain_statistics=domain_stats,
        performance_statistics=_performance(analyzers, failed | {n: "off" for n in skipped if n in ("latency", "connections")}, opts, domain_stats),
    ))


def analyze_records(
    records: Iterable[PacketRecord],
    *,
    source_name: str,
    options: AnalysisOptions | None = None,
    capture_format: str = "live",
) -> AnalysisResult:
    """Analyze already-parsed packet records (e.g. a live rolling window) with the same analyzers.

    No file is involved: file-oriented metadata fields are left empty. The records are only
    iterated once and are not retained by the analyzers.
    """
    started = time.perf_counter()
    opts = options or analysis_options()
    skipped, limit = skipped_analyzers(), max_packets()
    analyzers = _build_analyzers(opts)
    failed: dict[str, str] = {}
    count = 0
    for record in records:
        if limit and count >= limit:
            break
        count += 1
        for name, analyzer in analyzers.items():
            if name in failed or name in skipped:
                continue
            try:
                analyzer.add(record)
            except Exception as exc:
                failed[name] = f"{type(exc).__name__}: {exc}"
                logger.exception("Analyzer '%s' failed on live packet; disabling it for this window", name)
    stats = analyzers["statistics"]
    warnings = [f"Analyzer '{n}' failed and its results are incomplete: {e}" for n, e in failed.items()]
    if skipped:
        warnings.append("Turned off in Settings → Analysis: " + ", ".join(sorted(skipped)) + ". Their results are empty.")
    conn_list, conn_summary = _connection_results(analyzers, failed | {n: "off" for n in skipped})
    metadata = CaptureMetadata(
        file_name=source_name, file_path="", file_size_bytes=0, sha256="", capture_format=capture_format,
        packets_read=count, warnings=warnings,
        first_packet_time=stats.first_time, last_packet_time=stats.last_time,
        first_packet_time_iso=iso_time(stats.first_time), last_packet_time_iso=iso_time(stats.last_time),
        duration_seconds=round(stats.duration, 6), analyzed_at=datetime.now(timezone.utc),
        analysis_seconds=round(time.perf_counter() - started, 3),
    )
    domain_stats = analyzers["domains"].result()
    return apply_performance_settings(AnalysisResult(
        metadata=metadata,
        packet_statistics=stats.result(analyzers["timeline"].peak_packets_per_second),
        protocol_statistics=analyzers["protocols"].result(),
        ip_statistics=analyzers["ip"].result(),
        port_statistics=analyzers["ports"].result(),
        tcp_statistics=analyzers["tcp"].result(),
        dns_statistics=analyzers["dns"].result(),
        arp_statistics=analyzers["arp"].result(),
        connections=conn_list, connection_summary=conn_summary, timeline=analyzers["timeline"].result(),
        domain_statistics=domain_stats,
        performance_statistics=_performance(analyzers, failed | {n: "off" for n in skipped if n in ("latency", "connections")}, opts, domain_stats),
    ))
