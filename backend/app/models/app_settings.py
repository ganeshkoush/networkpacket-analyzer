"""The one typed configuration model for user-changeable PacketMind settings.

Rules that keep this honest:

* Every field here is *consumed by the backend* (see ``app/services/effective_config.py`` and the places that call it). A
  control that PacketMind cannot honour is not a field: it is listed in ``UNAVAILABLE`` with the reason, and the UI shows
  it disabled.
* Validation lives here (pydantic ``Field`` bounds), is returned to the UI as JSON schema, and is enforced again on every
  write. Unknown keys are rejected (``extra="forbid"``), so an imported file cannot smuggle anything in.
* Nothing here is a secret or a filesystem path. API keys go to the OS keychain (``secret_store.py``); folders are fixed
  by the deployment (env vars), so a settings file can never redirect where PacketMind reads or writes.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Sensitivity = Literal["low", "medium", "high"]


class Section(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class GeneralSettings(Section):
    theme: Literal["system", "light", "dark"] = "system"
    time_format: Literal["utc", "local", "local_24h"] = "utc"


class CaptureSettings(Section):
    default_interface: str = Field("", max_length=256)  # "" = none chosen
    format: Literal["pcap", "pcapng"] = "pcap"
    max_size_mb: int = Field(0, ge=0, le=1_000_000)  # 0 = unlimited; the capture stops when the file reaches it
    max_duration_minutes: int = Field(0, ge=0, le=100_000)  # 0 = unlimited
    auto_save: bool = True
    auto_analyze: bool = True
    rotation_enabled: bool = False
    rotation_size_mb: int = Field(500, ge=1, le=1_000_000)
    rotation_minutes: int = Field(60, ge=1, le=100_000)


class NetworkSettings(Section):
    auto_select_interface: bool = False
    show_inactive_interfaces: bool = True


class AnalysisSettings(Section):
    dns: bool = True
    tcp: bool = True
    connection_tracking: bool = True
    domain_tracking: bool = True
    rtt: bool = True
    handshake: bool = True
    performance: bool = True
    depth: Literal["basic", "standard", "deep"] = "standard"
    max_packets: int = Field(0, ge=0, le=10_000_000_000)  # 0 = analyse everything


class PortScanSettings(Section):
    enabled: bool = True
    min_ports: int = Field(15, ge=1, le=65_535)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class SynFloodSettings(Section):
    enabled: bool = True
    min_syn_packets: int = Field(200, ge=1, le=100_000_000)
    min_peak_syn_per_second: int = Field(100, ge=1, le=100_000_000)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class DnsDetectorSettings(Section):
    enabled: bool = True
    query_rate_per_second: float = Field(50.0, ge=0.0, le=1_000_000)
    nxdomain_ratio: float = Field(0.5, ge=0.0, le=1.0)  # share of failed lookups that is worth reporting
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class ArpSettings(Section):
    enabled: bool = True
    min_macs_per_ip: int = Field(2, ge=2, le=1000)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class TcpDetectorSettings(Section):
    enabled: bool = True
    retransmission_rate: float = Field(0.05, ge=0.0, le=1.0)
    reset_ratio: float = Field(0.2, ge=0.0, le=1.0)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class ConnectionBehaviorSettings(Section):
    enabled: bool = True
    min_upload_mb: int = Field(10, ge=1, le=1_000_000)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)


class DetectionSettings(Section):
    sensitivity: Sensitivity = "medium"
    port_scan: PortScanSettings = PortScanSettings()
    syn_flood: SynFloodSettings = SynFloodSettings()
    dns: DnsDetectorSettings = DnsDetectorSettings()
    arp: ArpSettings = ArpSettings()
    tcp: TcpDetectorSettings = TcpDetectorSettings()
    connection: ConnectionBehaviorSettings = ConnectionBehaviorSettings()


class PerformanceSettings(Section):
    track_dns_latency: bool = True
    track_retransmissions: bool = True
    track_failures: bool = True
    baseline_enabled: bool = True
    baseline_window: int = Field(30, ge=5, le=365)  # earlier captures that form the baseline
    baseline_min_samples: int = Field(5, ge=2, le=100)
    anomaly_sensitivity: Sensitivity = "medium"
    slow_dns_ms: float = Field(100.0, gt=0, le=60_000)
    slow_handshake_ms: float = Field(100.0, gt=0, le=60_000)  # TCP connection set-up time; never application response time
    slow_rtt_ms: float = Field(100.0, gt=0, le=60_000)


class DomainSettings(Section):
    track_history: bool = True
    retention_days: int = Field(0, ge=0, le=36_500)  # 0 = keep (bounded per domain)
    hide_localhost: bool = False
    hide_private_ips: bool = False
    hide_local_domains: bool = False


class PrivacySettings(Section):
    store_payloads: bool = True  # False = headers-only capture files (application payload bytes are cut off)
    store_dns_queries: bool = True
    anonymize_ips: bool = False  # in saved reports
    clear_temp_on_exit: bool = True
    data_retention_days: int = Field(0, ge=0, le=36_500)  # saved reports; 0 = keep


class AiSettingsModel(Section):
    model: str = Field("", max_length=100, pattern=r"^[A-Za-z0-9._\-/:]*$")  # "" = GEMINI_MODEL / default
    timeout_seconds: int | None = Field(None, ge=5, le=600)  # None = GEMINI_TIMEOUT_SECONDS / default
    auto_critical: bool = True
    auto_high: bool = True
    auto_medium: bool = True
    auto_low: bool = False
    auto_min_confidence: float = Field(0.6, ge=0.0, le=1.0)


class AiUsageSettings(Section):
    daily_limit: int = Field(50, ge=0, le=100_000)  # 0 = no limit
    max_auto_per_day: int = Field(20, ge=0, le=100_000)
    cache_enabled: bool = True
    cache_minutes: int = Field(60, ge=1, le=10_080)


class NotificationSettings(Section):
    enabled: bool = True
    critical_finding: bool = True
    high_finding: bool = True
    medium_finding: bool = False
    performance_anomaly: bool = False
    capture_completed: bool = True
    analysis_completed: bool = True
    ai_completed: bool = True
    capture_error: bool = True
    analysis_error: bool = True
    sound: bool = False
    only_in_background: bool = False


class StorageSettings(Section):
    max_capture_storage_gb: float = Field(50.0, gt=0, le=1_000_000)
    auto_delete_old: bool = False
    capture_retention_days: int = Field(30, ge=1, le=36_500)
    keep_analyzed: bool = True
    keep_failed: bool = False


class DiagnosticsSettings(Section):
    log_level: Literal["error", "warning", "info", "debug"] = "info"
    save_logs: bool = True
    max_log_mb: int = Field(2, ge=1, le=1024)
    rotation: bool = True


class SecuritySettings(Section):
    confirm_delete_captures: bool = True
    confirm_clear_history: bool = True
    allow_ai: bool = True  # master switch for every AI feature; AI is read-only analysis either way


class AdvancedSettings(Section):
    backend_timeout_seconds: int = Field(30, ge=5, le=600)
    max_concurrent_analyses: int = Field(2, ge=1, le=8)  # applied when the backend starts
    debug_mode: bool = False
    show_internal_ids: bool = False


class AppSettings(Section):
    general: GeneralSettings = GeneralSettings()
    capture: CaptureSettings = CaptureSettings()
    network: NetworkSettings = NetworkSettings()
    analysis: AnalysisSettings = AnalysisSettings()
    detection: DetectionSettings = DetectionSettings()
    performance: PerformanceSettings = PerformanceSettings()
    domains: DomainSettings = DomainSettings()
    privacy: PrivacySettings = PrivacySettings()
    ai: AiSettingsModel = AiSettingsModel()
    ai_usage: AiUsageSettings = AiUsageSettings()
    notifications: NotificationSettings = NotificationSettings()
    storage: StorageSettings = StorageSettings()
    diagnostics: DiagnosticsSettings = DiagnosticsSettings()
    security: SecuritySettings = SecuritySettings()
    advanced: AdvancedSettings = AdvancedSettings()

    @model_validator(mode="after")
    def _consistent(self) -> "AppSettings":
        if self.capture.rotation_enabled and self.capture.max_size_mb and self.capture.rotation_size_mb > self.capture.max_size_mb:
            raise ValueError("capture.rotation_size_mb: the rotation size cannot be larger than the maximum capture size")
        return self


SECTIONS: tuple[str, ...] = tuple(AppSettings.model_fields)

# Controls PacketMind cannot honour today. They are shown disabled with this explanation and are never stored.
UNAVAILABLE: dict[str, list[dict[str, str]]] = {
    "general": [
        {"key": "start_on_login", "label": "Start application on login", "reason": "Not available yet: the desktop shell has no login-item support."},
        {"key": "minimize_to_tray", "label": "Minimize to system tray", "reason": "Not available yet: the desktop shell has no system-tray support."},
    ],
    "capture": [
        {"key": "buffer_size", "label": "Capture buffer size", "reason": "The capture library (Scapy/libpcap) is opened with its default buffer; PacketMind cannot change it."},
    ],
    "analysis": [
        {"key": "udp", "label": "Enable UDP analysis", "reason": "There is no separate UDP analyzer: UDP is part of the protocol, port, connection and DNS analysis."},
        {"key": "tls_metadata", "label": "Enable TLS metadata analysis", "reason": "PacketMind only recognises TLS to tell encrypted from cleartext traffic; it does not read certificates or server names."},
        {"key": "store_packet_metadata", "label": "Store packet metadata", "reason": "PacketMind never keeps per-packet metadata: results are aggregates only."},
        {"key": "max_memory", "label": "Maximum analysis memory", "reason": "Memory is bounded by fixed caps (see Analysis depth), not by a byte limit."},
    ],
    "detection": [
        {"key": "time_window", "label": "Port scan / SYN flood time window", "reason": "Detectors work on whole-capture aggregates, so they have no sliding time window to configure."},
    ],
    "domains": [
        {"key": "group_subdomains", "label": "Group subdomains", "reason": "Grouping needs a public-suffix list that PacketMind does not ship; grouping by the last two labels would be wrong for names like example.co.uk."},
        {"key": "track_destination_ips", "label": "Track destination IPs", "reason": "Destination IPs are always part of the analysis; they cannot be turned off without breaking connections and findings."},
    ],
    "ai": [
        {"key": "max_tool_calls", "label": "Maximum tool calls", "reason": "The model cannot call tools. PacketMind runs a fixed read-only set of local analysis functions itself, so there is nothing to cap."},
        {"key": "auto_anomalies", "label": "Automatically investigate performance anomalies", "reason": "Automatic investigation only runs for live-capture security findings."},
    ],
    "ai_usage": [
        {"key": "per_capture_limit", "label": "Maximum investigations per capture", "reason": "Requests are counted per day, not per capture."},
    ],
    "security": [
        {"key": "external_integrations", "label": "Allow external integrations", "reason": "PacketMind has no external integrations, so there is nothing to allow."},
    ],
    "advanced": [
        {"key": "max_concurrent_captures", "label": "Maximum concurrent captures", "reason": "PacketMind supports one live capture at a time."},
        {"key": "developer_tools", "label": "Developer tools", "reason": "Not exposed in release builds."},
        {"key": "experimental", "label": "Experimental features", "reason": "There are no experimental features in this version."},
    ],
}

# Settings whose change only applies after the backend restarts.
RESTART_REQUIRED: tuple[str, ...] = ("advanced.max_concurrent_analyses",)

# What the AI may and may not do. Fixed on purpose: none of this is user-configurable.
AI_PERMISSIONS: dict[str, list[str]] = {
    "allowed": ["Read network statistics", "Read findings", "Read performance metrics", "Read domain statistics"],
    "never": ["Execute commands", "Modify firewall", "Modify routing", "Modify network configuration", "Delete files", "Block IP addresses", "Execute code"],
}
AI_DATA_POLICY: list[dict[str, str]] = [
    {"item": "Raw PCAP files", "policy": "NEVER SENT"},
    {"item": "Raw packet payloads", "policy": "NEVER SENT"},
    {"item": "Structured analysis", "policy": "ALLOWED"},
    {"item": "Aggregated statistics", "policy": "ALLOWED"},
]
