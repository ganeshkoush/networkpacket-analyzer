"""Command line interface: ``python -m app.analysis <file.pcap> [--json] [--top N]``."""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from app.analysis.pcap_parser import CaptureError
from app.analysis.service import analyze_pcap
from app.models.analysis import AnalysisOptions, AnalysisResult


def _bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _table(rows: list[list[str]], headers: list[str], indent: str = "  ") -> list[str]:
    if not rows:
        return [f"{indent}(none)"]
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    fmt = indent + "  ".join(f"{{:<{w}}}" for w in widths)
    return [fmt.format(*headers), indent + "  ".join("-" * w for w in widths),
            *(fmt.format(*map(str, r)) for r in rows)]


def format_summary(result: AnalysisResult, top: int = 10) -> str:
    """Render an :class:`AnalysisResult` as a human-readable text summary."""
    m, ps = result.metadata, result.packet_statistics
    out: list[str] = []

    def section(title: str) -> None:
        out.extend(["", title, "=" * len(title)])

    section(f"PacketMind analysis: {m.file_name}")
    out += [
        f"Format        : {m.capture_format}   Size: {_bytes(m.file_size_bytes)}",
        f"SHA-256       : {m.sha256}",
        f"Packets       : {ps.total_packets}   Bytes: {_bytes(ps.total_bytes)}",
        f"Time range    : {m.first_packet_time_iso or '-'}  ->  {m.last_packet_time_iso or '-'}",
        f"Duration      : {m.duration_seconds:.3f} s",
    ]
    if ps.total_packets:
        rate = f"{ps.avg_packets_per_second} pkt/s avg" if ps.avg_packets_per_second is not None else "n/a"
        out.append(f"Rate          : {rate}, peak {ps.peak_packets_per_second} pkt/s")
        out.append(f"Packet size   : min {ps.min_packet_size}  mean {ps.mean_packet_size}  max {ps.max_packet_size}")
    for w in m.warnings:
        out.append(f"WARNING       : {w}")

    section("Protocols")
    out += _table([[p.protocol, p.packets, _bytes(p.bytes), f"{p.percent_of_packets}%"]
                   for p in result.protocol_statistics.distribution[:top]],
                  ["protocol", "packets", "bytes", "share"])

    ip = result.ip_statistics
    section("IP addresses")
    out.append(f"  {ip.unique_source_ips} unique sources, {ip.unique_destination_ips} unique destinations, "
               f"{ip.total_conversations} conversations")
    out += _table([[t.ip, "private" if t.is_private else "public", t.total_packets,
                    _bytes(t.bytes_sent), _bytes(t.bytes_received)] for t in ip.top_talkers[:top]],
                  ["top talker", "scope", "packets", "sent", "received"])

    pt = result.port_statistics
    section("Ports")
    out += _table([[p.protocol, p.port, p.service_hint or "", p.packets] for p in pt.top_destination_ports[:top]],
                  ["proto", "dst port", "service hint", "packets"])
    out.append("")
    out += _table([[f.source_ip, f.unique_destination_ports, f.packets] for f in pt.destination_ports_per_source[:top]],
                  ["source", "unique dst ports", "packets"])

    t = result.tcp_statistics
    section("TCP")
    out.append(f"  {t.total_packets} packets | SYN {t.syn_packets} | SYN-ACK {t.syn_ack_packets} | "
               f"ACK-only {t.ack_only_packets} | FIN {t.fin_packets} | RST {t.rst_packets}")
    r = t.retransmissions
    out.append(f"  retransmission indicators: {r.retransmitted_segments} of {r.sequence_bearing_segments} segments "
               f"({r.retransmission_rate:.1%}), duplicate ACKs: {r.duplicate_acks}")
    out += _table([[f.flags, f.packets] for f in t.flag_combinations[:top]], ["flags", "packets"])

    d = result.dns_statistics
    section("DNS")
    out.append(f"  {d.total_queries} queries, {d.total_responses} responses, {d.unique_domains} unique names, "
               f"{d.nxdomain_responses} NXDOMAIN, {d.unanswered_queries} unanswered")
    if d.avg_response_ms is not None:
        out.append(f"  response time: avg {d.avg_response_ms} ms, max {d.max_response_ms} ms")
    out += _table([[x.name, x.count] for x in d.top_domains[:top]], ["top queried name", "count"])

    cs = result.connection_summary
    section("Connections")
    out.append(f"  {cs.total_connections} total ({', '.join(f'{k} {v}' for k, v in cs.by_protocol.items()) or 'none'}); "
               f"TCP handshakes complete: {cs.tcp_handshakes_complete}, with RST: {cs.tcp_with_rst}")
    out += _table([[c.protocol, f"{c.client_ip}:{c.client_port}", f"{c.server_ip}:{c.server_port}",
                    c.packets, _bytes(c.bytes), f"{c.duration_seconds:.2f}s"] for c in result.connections[:top]],
                  ["proto", "client", "server", "packets", "bytes", "duration"])

    section("Timeline")
    if result.timeline:
        peak = max(result.timeline, key=lambda p: p.packets_per_second)
        out.append(f"  {len(result.timeline)} points of {result.timeline[0].interval_seconds}s; busiest at "
                   f"+{peak.offset_seconds:.0f}s ({peak.packets_per_second} pkt/s)")
        out += _table([[f"+{p.offset_seconds:.0f}s", datetime.fromtimestamp(p.start_time).strftime("%H:%M:%S"),
                        p.packets, p.packets_per_second] for p in result.timeline[:top]],
                      ["offset", "local time", "packets", "pkt/s"])
    else:
        out.append("  (no data)")
    out.append(f"\nAnalyzed in {m.analysis_seconds}s. Counts are local observations, not verdicts.")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.analysis",
                                description="Analyze a PCAP/PCAPNG file locally and print a summary.")
    p.add_argument("file", type=Path, help="path to a .pcap or .pcapng file")
    p.add_argument("--json", action="store_true", help="print the full structured result as JSON")
    p.add_argument("-o", "--output", type=Path, help="write the full JSON result to this file")
    p.add_argument("--top", type=int, default=10, help="rows per table in the text summary (default 10)")
    p.add_argument("--detect", action="store_true", help="also run the threat detectors and print findings")
    p.add_argument("-v", "--verbose", action="store_true", help="show parser warnings/logs")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING if args.verbose else logging.CRITICAL, format="%(levelname)s %(message)s")
    try:
        result = analyze_pcap(args.file, AnalysisOptions(top_n=max(args.top, 20)))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.write_text(result.model_dump_json(indent=2))
        print(f"Full JSON written to {args.output}", file=sys.stderr)
    findings = None
    if args.detect:
        from app.detection import detect_threats  # local import: analysis works without detection

        findings = detect_threats(result)
    if args.json:
        if findings is None:
            print(result.model_dump_json(indent=2))
        else:
            import json

            print(json.dumps({"analysis": json.loads(result.model_dump_json()),
                              "findings": [json.loads(f.model_dump_json()) for f in findings]}, indent=2))
    else:
        print(format_summary(result, args.top))
        if findings is not None:
            from app.detection.report import format_findings

            print(format_findings(findings))
    return 0
