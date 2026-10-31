"""Turns the user's settings into the configuration objects the existing engines already consume.

Nothing here re-implements detection or analysis: it only fills ``DetectionConfig``, ``AnalysisOptions``,
``HealthThresholds`` and ``BaselineConfig`` (and trims results for the "track ..." switches). With default settings every
builder returns exactly what the code defaults were, so behaviour only changes when the user changes a setting.
"""
from __future__ import annotations

import logging
from dataclasses import replace

from app.analysis.baseline import DEFAULT_CONFIG, BaselineConfig
from app.analysis.web_activity import HealthThresholds
from app.detection.config import DetectionConfig
from app.models.analysis import AnalysisOptions, AnalysisResult
from app.models.app_settings import AppSettings
from app.services.app_settings import current_settings

logger = logging.getLogger(__name__)

# Detection sensitivity: how far the user's thresholds are stretched. Low needs more evidence, high needs less.
_SENSITIVITY = {"low": 1.5, "medium": 1.0, "high": 0.67}
_ANOMALY_Z = {"low": 4.5, "medium": 3.5, "high": 2.5}  # baseline.BaselineConfig.z_threshold
_ANOMALY_REL = {"low": 0.40, "medium": 0.25, "high": 0.15}
_DEPTH = {"basic": 0.25, "standard": 1.0, "deep": 2.0}  # multiplies the "keep at most N" caps of AnalysisOptions
_LEVELS = {"error": "ERROR", "warning": "WARNING", "info": "INFO", "debug": "DEBUG"}


def _count(v: float, f: float) -> int:
    return max(1, round(v * f))


def _ratio(v: float, f: float) -> float:
    return min(0.99, v * f)


def detection_config(s: AppSettings | None = None) -> DetectionConfig:
    s = s or current_settings()
    d, f = s.detection, _SENSITIVITY[s.detection.sensitivity]
    cfg = DetectionConfig()

    ps = cfg.port_scan
    ps.enabled = d.port_scan.enabled
    ps.min_unique_ports = _count(d.port_scan.min_ports, f)
    ps.strong_unique_ports = max(ps.strong_unique_ports, ps.min_unique_ports * 2)

    sf = cfg.syn_flood
    sf.enabled = d.syn_flood.enabled
    sf.min_syn_packets = _count(d.syn_flood.min_syn_packets, f)
    sf.strong_syn_packets = max(sf.strong_syn_packets, sf.min_syn_packets * 2)
    sf.min_peak_syn_per_second = _count(d.syn_flood.min_peak_syn_per_second, f)
    sf.strong_peak_syn_per_second = max(sf.strong_peak_syn_per_second, sf.min_peak_syn_per_second * 2)

    dns = cfg.dns
    dns.enabled = d.dns.enabled
    dns.excessive_min_qps = d.dns.query_rate_per_second * f
    dns.excessive_strong_qps = max(dns.excessive_strong_qps, dns.excessive_min_qps * 2)
    dns.nxdomain_min_ratio = _ratio(d.dns.nxdomain_ratio, f)
    dns.nxdomain_strong_ratio = max(dns.nxdomain_strong_ratio, min(0.99, dns.nxdomain_min_ratio + 0.05))

    arp = cfg.arp
    arp.enabled = d.arp.enabled
    arp.min_macs_per_ip = d.arp.min_macs_per_ip
    arp.strong_macs_per_ip = max(arp.strong_macs_per_ip, arp.min_macs_per_ip + 2)

    t = cfg.tcp_anomaly
    t.enabled = d.tcp.enabled
    t.retrans_min_rate = _ratio(d.tcp.retransmission_rate, f)
    t.retrans_strong_rate = max(t.retrans_strong_rate, min(0.99, t.retrans_min_rate * 2))
    t.rst_min_ratio = _ratio(d.tcp.reset_ratio, f)
    t.rst_strong_ratio = max(t.rst_strong_ratio, min(0.99, t.rst_min_ratio * 2))

    c = cfg.connection_behavior
    c.enabled = d.connection.enabled
    c.min_upload_bytes = _count(d.connection.min_upload_mb, f) * 1024 * 1024
    c.strong_upload_bytes = max(c.strong_upload_bytes, c.min_upload_bytes * 5)

    by_detector = {"port_scan": d.port_scan.min_confidence, "syn_flood": d.syn_flood.min_confidence, "dns_anomaly": d.dns.min_confidence,
                   "arp_spoof": d.arp.min_confidence, "tcp_anomaly": d.tcp.min_confidence, "connection_behavior": d.connection.min_confidence}
    cfg.min_confidence_by_detector = {k: v for k, v in by_detector.items() if v > 0}
    return cfg


def analysis_options(s: AppSettings | None = None) -> AnalysisOptions:
    s = s or current_settings()
    base, f = AnalysisOptions(), _DEPTH[s.analysis.depth]
    scaled = {name: max(1, round(getattr(base, name) * f)) for name in
              ("top_n", "max_connections", "max_conversations", "timeline_max_points", "max_profiles", "max_domains")}
    scaled["max_dns_log"] = 0 if not s.privacy.store_dns_queries else max(1, round(base.max_dns_log * f))
    return base.model_copy(update=scaled)


def skipped_analyzers(s: AppSettings | None = None) -> set[str]:
    """Analyzers that must not run. Their results stay empty, like an analysis of a capture without that traffic."""
    a = (s or current_settings()).analysis
    skip: set[str] = set()
    if not a.dns:
        skip.add("dns")
    if not a.tcp:
        skip.add("tcp")
    if not a.connection_tracking:
        skip.add("connections")
    if not a.domain_tracking:
        skip.add("domains")
    if not a.performance:
        skip.add("latency")
    return skip


def max_packets(s: AppSettings | None = None) -> int:
    return (s or current_settings()).analysis.max_packets


def health_thresholds(s: AppSettings | None = None) -> HealthThresholds:
    """'Slow' limits for the domain health rating. The user sets the 'slow' (fair) limit; 'poor' keeps the original ratio."""
    p = (s or current_settings()).performance
    return HealthThresholds(handshake_ms=(p.slow_handshake_ms, p.slow_handshake_ms * 3), avg_rtt_ms=(p.slow_rtt_ms, p.slow_rtt_ms * 3),
                            p95_rtt_ms=(p.slow_rtt_ms * 2.5, p.slow_rtt_ms * 6), dns_ms=(p.slow_dns_ms, p.slow_dns_ms * 5))


def baseline_config(s: AppSettings | None = None) -> BaselineConfig:
    p = (s or current_settings()).performance
    return replace(DEFAULT_CONFIG, window=p.baseline_window, min_observations=p.baseline_min_samples,
                   z_threshold=_ANOMALY_Z[p.anomaly_sensitivity], min_rel_increase=_ANOMALY_REL[p.anomaly_sensitivity])


def history_enabled(s: AppSettings | None = None) -> bool:
    """Whether per-domain performance may be remembered: needs baselines on, domain history on and performance analysis on."""
    s = s or current_settings()
    return s.performance.baseline_enabled and s.domains.track_history and s.analysis.performance


def log_level(s: AppSettings | None = None) -> str:
    s = s or current_settings()
    return "DEBUG" if s.advanced.debug_mode else _LEVELS[s.diagnostics.log_level]


# ---------------------------------------------------------------------------------------------- performance switches
def apply_performance_settings(result: AnalysisResult, s: AppSettings | None = None) -> AnalysisResult:
    """Blank the measurements the user chose not to track. Done on the finished result so one code path serves files and live."""
    s = s or current_settings()
    a, p = s.analysis, s.performance
    perf = result.performance_statistics
    if not a.performance:
        result.performance_statistics = type(perf)()
        perf = result.performance_statistics
    if a.performance and not a.rtt:
        for d in perf.domains:
            d.avg_rtt_ms = d.p95_rtt_ms = d.max_rtt_ms = None
            d.rtt_samples = 0
        for m in perf.metrics:
            m.min_rtt_ms = m.avg_rtt_ms = m.median_rtt_ms = m.p95_rtt_ms = m.max_rtt_ms = None
            m.rtt_samples, m.rtt_basis = 0, None
        for fs in perf.flow_samples:
            fs.rtt_ms, fs.rtt_samples = None, 0
        for series in perf.series.values():
            series.rtt = []
    if not a.handshake:
        for d in perf.domains:
            d.tcp_handshake_ms, d.handshake_samples = None, 0
        for m in perf.metrics:
            m.tcp_handshake_ms = None
        for fs in perf.flow_samples:
            fs.handshake_ms = None
        for series in perf.series.values():
            series.handshake = []
        for c in result.connections:
            c.tcp_handshake_time_ms = c.tcp_syn_ack_latency_ms = c.tcp_ack_latency_ms = None
        cs = result.connection_summary
        cs.avg_handshake_ms, cs.handshakes_timed, cs.handshake_by_domain = None, 0, []
    if not p.track_dns_latency:
        for d in perf.domains:
            d.dns_latency_ms, d.dns_lookups = None, 0
        for m in perf.metrics:
            m.dns_latency_ms, m.dns_lookups = None, 0
        perf.lookup_samples = []
        result.dns_statistics.avg_response_ms = result.dns_statistics.max_response_ms = None
    if not p.track_retransmissions:
        for d in perf.domains:
            d.retransmissions = 0
        for fs in perf.flow_samples:
            fs.retransmissions = 0
        for c in result.connections:
            c.retransmissions = None
    if not p.track_failures:
        for d in perf.domains:
            d.tcp_connections_attempted = d.tcp_connections_failed = 0
        for fs in perf.flow_samples:
            fs.attempted = fs.failed = False
    return result
