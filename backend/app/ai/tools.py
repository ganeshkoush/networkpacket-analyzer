"""Safe, read-only investigation tools over already-parsed analysis data.

These functions take an `AnalysisResult` (+ detector findings) and return small JSON-able
dicts. They never touch the filesystem, network, subprocesses or the original PCAP, and the
registry is a fixed allowlist: an unknown tool name is rejected, never executed. They are
called by the investigator (not by the model) to assemble bounded evidence.

All strings that originate from traffic are untrusted; `sanitize` neutralises control
characters, over-long values and instruction-like text before anything reaches the model.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.ai.schemas import EvidenceBundle
from app.detection.models import Finding
from app.models.analysis import AnalysisResult

MAX_STRING = 200
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
_INJECTION = re.compile(
    r"(ignore|disregard|forget|override)\b.{0,40}\b(instruction|prompt|rule|previous|above)"
    r"|system\s*prompt|you\s+are\s+now|</?\s*(evidence_json|analyst_question|system)\b|assistant\s*:",
    re.I | re.S)
INJECTION_PLACEHOLDER = "[redacted: instruction-like text in packet metadata]"


class UnknownToolError(ValueError):
    pass


def sanitize(value: Any) -> Any:
    """Recursively clean untrusted packet-derived strings (numbers/bools/None pass through)."""
    if isinstance(value, str):
        value = _CONTROL.sub("", value)
        if _INJECTION.search(value):
            return INJECTION_PLACEHOLDER
        return value if len(value) <= MAX_STRING else value[:MAX_STRING] + "…"
    if isinstance(value, dict):
        return {sanitize(str(k)): sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        raise ValueError("not a valid IP address") from None


class EvidenceTools:
    """Read-only views over one analysis. Every method is bounded in output size."""

    def __init__(self, analysis: AnalysisResult, findings: list[Finding]):
        self.a = analysis
        self.findings = findings

    # ---- capture-wide ----
    def get_capture_overview(self) -> dict[str, Any]:
        m, p = self.a.metadata, self.a.packet_statistics
        return {
            "file_name": m.file_name.replace("\\", "/").rsplit("/", 1)[-1],  # basename only; no local paths
            "capture_format": m.capture_format,
            "packets_read": m.packets_read, "malformed_packets": m.malformed_packets,
            "duration_seconds": m.duration_seconds,
            "first_packet_time_iso": m.first_packet_time_iso, "last_packet_time_iso": m.last_packet_time_iso,
            "total_bytes": p.total_bytes, "avg_packets_per_second": p.avg_packets_per_second,
            "peak_packets_per_second": p.peak_packets_per_second, "warnings": m.warnings[:5],
        }

    def get_protocol_summary(self, limit: int = 10) -> dict[str, Any]:
        d = self.a.protocol_statistics.distribution[:limit]
        return {"distribution": [s.model_dump(mode="json") for s in d]}

    def get_top_talkers(self, limit: int = 10) -> dict[str, Any]:
        ip = self.a.ip_statistics
        return {"unique_source_ips": ip.unique_source_ips, "unique_destination_ips": ip.unique_destination_ips,
                "top_talkers": [t.model_dump(mode="json") for t in ip.top_talkers[:limit]]}

    def get_port_summary(self, limit: int = 10) -> dict[str, Any]:
        ps = self.a.port_statistics
        return {"unique_destination_ports": ps.unique_destination_ports,
                "top_destination_ports": [p.model_dump(mode="json") for p in ps.top_destination_ports[:limit]],
                "destination_ports_per_source": [s.model_dump(mode="json") for s in ps.destination_ports_per_source[:limit]]}

    def get_tcp_summary(self, limit: int = 10) -> dict[str, Any]:
        t = self.a.tcp_statistics
        return {"syn_packets": t.syn_packets, "syn_ack_packets": t.syn_ack_packets, "rst_packets": t.rst_packets,
                "fin_packets": t.fin_packets, "syn_to_syn_ack_ratio": t.syn_to_syn_ack_ratio,
                "retransmission_rate": t.retransmissions.retransmission_rate,
                "top_syn_sources": [s.model_dump(mode="json") for s in t.top_syn_sources[:limit]]}

    def get_dns_summary(self, limit: int = 10) -> dict[str, Any]:
        d = self.a.dns_statistics
        return {"total_queries": d.total_queries, "total_responses": d.total_responses,
                "unique_domains": d.unique_domains, "nxdomain_responses": d.nxdomain_responses,
                "unanswered_queries": d.unanswered_queries,
                "top_domains": [x.model_dump(mode="json") for x in d.top_domains[:limit]],
                "clients": [c.model_dump(mode="json") for c in d.clients[:limit]]}

    def get_timeline(self, limit: int = 30) -> list[dict[str, Any]]:
        pts = self.a.timeline
        if len(pts) > limit:
            step = len(pts) / limit
            pts = [pts[int(i * step)] for i in range(limit)]
        return [{"offset_seconds": p.offset_seconds, "packets": p.packets, "bytes": p.bytes,
                 "packets_per_second": p.packets_per_second} for p in pts]

    def get_findings(self) -> list[dict[str, Any]]:
        return [self._digest(f) for f in self.findings]

    def get_finding_detail(self, finding_id: str) -> dict[str, Any]:
        for f in self.findings:
            if f.id == finding_id:
                return self._digest(f)
        raise ValueError("unknown finding id")

    # ---- per-host ----
    def get_connections(self, ip: str, limit: int = 15) -> list[dict[str, Any]]:
        ip = _valid_ip(ip)
        rows = [c for c in self.a.connections if ip in (c.client_ip, c.server_ip)]
        return [c.model_dump(mode="json", exclude={"tcp_flags_seen"}) for c in rows[:limit]]

    def get_host_profile(self, ip: str) -> dict[str, Any]:
        ip = _valid_ip(ip)
        a = self.a
        return {
            "ip": ip,
            "talker": next((t.model_dump(mode="json") for t in a.ip_statistics.top_talkers if t.ip == ip), None),
            "port_fanout": next((s.model_dump(mode="json") for s in a.port_statistics.destination_ports_per_source
                                 if s.source_ip == ip), None),
            "syn_activity": next((s.model_dump(mode="json") for s in a.tcp_statistics.top_syn_sources
                                  if s.ip == ip), None),
            "dns_client": next((c.model_dump(mode="json") for c in a.dns_statistics.clients if c.client_ip == ip), None),
            "syn_pairs": [p.model_dump(mode="json") for p in a.tcp_statistics.syn_pairs
                          if ip in (p.src_ip, p.dst_ip)][:10],
        }

    @staticmethod
    def _digest(f: Finding) -> dict[str, Any]:
        d = f.model_dump(mode="json", exclude={"confidence_factors"})
        d["first_seen_iso"], d["last_seen_iso"] = _iso(f.first_seen), _iso(f.last_seen)
        return d


# Fixed allowlist: name -> callable. Anything not listed cannot be invoked.
TOOL_NAMES = ("get_capture_overview", "get_protocol_summary", "get_top_talkers", "get_port_summary",
              "get_tcp_summary", "get_dns_summary", "get_timeline", "get_findings", "get_finding_detail",
              "get_connections", "get_host_profile")


def call_tool(tools: EvidenceTools, name: str, **kwargs: Any) -> Any:
    if name not in TOOL_NAMES:
        raise UnknownToolError(f"tool {name!r} is not in the allowlist")
    fn: Callable[..., Any] = getattr(tools, name)
    return sanitize(fn(**kwargs))


def build_evidence_bundle(
    analysis: AnalysisResult, findings: list[Finding], finding_id: str | None = None, max_hosts: int = 4
) -> EvidenceBundle:
    """Assemble bounded structured evidence for the model from local results only."""
    tools = EvidenceTools(analysis, findings)
    focus = [f for f in findings if f.id == finding_id] if finding_id else findings
    if finding_id and not focus:
        raise ValueError("unknown finding id")
    hosts: list[str] = []
    for f in focus:
        for ip in (f.source_ip, f.destination_ip):
            if ip and ip not in hosts:
                hosts.append(ip)
    hosts = hosts[:max_hosts]

    def run(name: str, **kw: Any) -> Any:
        return call_tool(tools, name, **kw)

    data: dict[str, Any] = {
        "capture_overview": run("get_capture_overview"),
        "protocol_summary": run("get_protocol_summary"),
        "top_talkers": run("get_top_talkers"),
        "port_summary": run("get_port_summary"),
        "tcp_summary": run("get_tcp_summary"),
        "dns_summary": run("get_dns_summary"),
        "timeline": run("get_timeline"),
        "host_profiles": [run("get_host_profile", ip=ip) for ip in hosts],
        "connections_by_host": {ip: run("get_connections", ip=ip) for ip in hosts},
    }
    bundle_findings = [Finding.model_validate(sanitize(f.model_dump(mode="json"))) for f in focus]
    return EvidenceBundle(data=data, findings=bundle_findings)
