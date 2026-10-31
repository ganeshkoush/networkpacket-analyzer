"""Detection thresholds and weights. Every number a detector uses lives here.

Defaults are conservative starting points for typical enterprise/home captures, not
universal truths - tune them per environment (e.g. raise `min_bytes` on backup servers).
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.detection.severity import ConfidenceBounds, Severity, SeverityThresholds


class PortScanConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.HIGH
    # Vertical scan: one source probing many ports on one host.
    min_unique_ports: int = 15
    strong_unique_ports: int = 100
    min_failure_ratio: float = 0.5  # share of SYNs that did NOT get a SYN-ACK
    strong_failure_ratio: float = 0.95
    min_syn_per_second: float = 1.0
    strong_syn_per_second: float = 50.0
    min_ports_per_syn: float = 0.3  # ports/SYNs: ~1.0 means each port probed about once
    strong_ports_per_syn: float = 0.9
    min_duration_seconds: float = 1.0  # floor used when computing rates
    weights: dict[str, float] = {"port_breadth": 0.40, "failure_ratio": 0.25, "probe_rate": 0.15, "one_probe_per_port": 0.20}
    # Horizontal sweep: one source probing many hosts.
    min_unique_hosts: int = 10
    strong_unique_hosts: int = 100
    focused_ports_max: int = 3  # few distinct ports across many hosts = focused sweep
    unfocused_ports_full: int = 50
    sweep_weights: dict[str, float] = {"host_breadth": 0.45, "failure_ratio": 0.30, "probe_rate": 0.10, "port_focus": 0.15}


class SynFloodConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.CRITICAL
    min_syn_packets: int = 200
    strong_syn_packets: int = 2000
    min_peak_syn_per_second: int = 100
    strong_peak_syn_per_second: int = 500
    # ack_packets_in / syn_packets. Completed handshakes send >= 1 ACK-bearing packet per SYN.
    max_completion_ratio: float = 1.0  # above this the target is completing connections: not flagged
    low_completion_ratio: float = 0.05
    strong_unique_sources: int = 50
    dominant_source_share: float = 0.8  # one source sending >= this share is reported as source_ip
    weights: dict[str, float] = {"volume": 0.25, "peak_rate": 0.25, "incomplete_handshakes": 0.35, "source_diversity": 0.15}


class DnsConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.HIGH
    # NXDOMAIN-heavy client
    nxdomain_max_severity: Severity = Severity.MEDIUM
    nxdomain_min_responses: int = 20
    nxdomain_min_ratio: float = 0.5
    nxdomain_strong_ratio: float = 0.9
    nxdomain_strong_responses: int = 200
    nxdomain_weights: dict[str, float] = {"ratio": 0.6, "volume": 0.4}
    # DGA-like (many random-looking registered domains per client)
    dga_min_domains: int = 5
    dga_strong_domains: int = 50
    dga_nxdomain_start: float = 0.3
    dga_nxdomain_full: float = 0.9
    dga_share_start: float = 0.1  # high-entropy domains / unique names queried
    dga_share_full: float = 0.8
    dga_weights: dict[str, float] = {"domain_count": 0.5, "nxdomain_ratio": 0.3, "random_share": 0.2}
    # Tunneling-like (many long unique subdomains under one base domain)
    tunnel_min_unique_names: int = 50
    tunnel_strong_unique_names: int = 500
    tunnel_label_start: float = 16.0
    tunnel_label_full: float = 40.0
    tunnel_name_len_start: int = 60
    tunnel_name_len_full: int = 180
    tunnel_txt_null_share_full: float = 0.5
    tunnel_weights: dict[str, float] = {"unique_names": 0.35, "label_length": 0.30, "name_length": 0.15, "txt_null_share": 0.20}
    ignored_base_suffixes: list[str] = ["in-addr.arpa", "ip6.arpa"]  # reverse lookups legitimately fan out
    allowlisted_base_domains: list[str] = []  # e.g. CDN/AV vendors that use long random labels
    # Excessive query rate
    excessive_max_severity: Severity = Severity.MEDIUM
    excessive_min_queries: int = 500
    excessive_min_qps: float = 50.0
    excessive_strong_qps: float = 500.0
    excessive_strong_queries: int = 10_000
    excessive_weights: dict[str, float] = {"rate": 0.6, "volume": 0.4}
    # Responses without a captured query
    unsolicited_max_severity: Severity = Severity.MEDIUM
    unsolicited_min_responses: int = 20
    unsolicited_min_share: float = 0.5
    unsolicited_strong_responses: int = 500
    unsolicited_weights: dict[str, float] = {"share": 0.5, "volume": 0.5}
    min_duration_seconds: float = 1.0


class ArpConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.HIGH
    min_macs_per_ip: int = 2
    strong_macs_per_ip: int = 4
    changes_full: int = 6  # binding flip-flops for full score (1 change scores 0)
    unrequested_full: int = 10  # unsolicited + gratuitous packets for full score
    mismatch_full: int = 3  # ARP sender MAC != Ethernet source MAC
    weights: dict[str, float] = {
        "multiple_macs": 0.10, "binding_changes": 0.30, "unrequested_announcements": 0.25,
        "eth_mac_mismatch": 0.25, "mac_count": 0.10,
    }
    # One MAC claiming many IPs
    multi_ip_max_severity: Severity = Severity.MEDIUM
    multi_ip_min_ips: int = 5
    multi_ip_strong_ips: int = 30
    multi_ip_unsolicited_full: int = 20
    multi_ip_weights: dict[str, float] = {"ip_count": 0.6, "unsolicited": 0.4}


class TcpAnomalyConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.MEDIUM
    # Abnormal flag combinations
    flags_min_packets: int = 3
    flags_strong_packets: int = 50
    flags_high_signal: list[str] = ["NULL", "XMAS", "SYN+FIN", "SYN+RST"]
    flags_low_signal_score: float = 0.4  # score for kinds not in flags_high_signal
    flags_strong_hosts: int = 10
    flags_weights: dict[str, float] = {"packet_count": 0.40, "anomaly_kind": 0.35, "destination_breadth": 0.25}
    # Retransmissions
    retrans_min_segments: int = 100
    retrans_min_rate: float = 0.05
    retrans_strong_rate: float = 0.30
    retrans_strong_segments: int = 5000
    retrans_dominant_share: float = 0.5  # one flow causing >= this share is reported as source/destination
    retrans_weights: dict[str, float] = {"rate": 0.7, "volume": 0.3}
    # Resets
    rst_min_packets: int = 50
    rst_min_ratio: float = 0.2
    rst_strong_ratio: float = 0.6
    rst_strong_packets: int = 1000
    rst_weights: dict[str, float] = {"ratio": 0.6, "volume": 0.4}


class ConnectionBehaviorConfig(BaseModel):
    enabled: bool = True
    max_severity: Severity = Severity.MEDIUM
    # Large asymmetric outbound transfer (private client -> public server)
    min_upload_bytes: int = 10 * 1024 * 1024
    strong_upload_bytes: int = 500 * 1024 * 1024
    min_asymmetry: float = 10.0  # bytes client->server / bytes server->client
    strong_asymmetry: float = 100.0
    weights: dict[str, float] = {"volume": 0.35, "asymmetry": 0.35, "uncommon_port": 0.30}
    # Cleartext management/mail protocols
    cleartext_max_severity: Severity = Severity.LOW
    cleartext_ports: dict[int, str] = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 513: "rlogin"}
    cleartext_min_packets: int = 10
    cleartext_strong_packets: int = 200
    cleartext_weights: dict[str, float] = {"traffic": 0.5, "public_server": 0.5}


class DetectionConfig(BaseModel):
    confidence: ConfidenceBounds = Field(default_factory=ConfidenceBounds)
    severity: SeverityThresholds = Field(default_factory=SeverityThresholds)
    min_confidence_to_report: float = 0.0
    min_confidence_by_detector: dict[str, float] = Field(default_factory=dict)  # detector name -> minimum confidence to report
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    syn_flood: SynFloodConfig = Field(default_factory=SynFloodConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    arp: ArpConfig = Field(default_factory=ArpConfig)
    tcp_anomaly: TcpAnomalyConfig = Field(default_factory=TcpAnomalyConfig)
    connection_behavior: ConnectionBehaviorConfig = Field(default_factory=ConnectionBehaviorConfig)


def default_detection_config() -> DetectionConfig:
    """The detection config the user's settings describe (the code defaults when nothing was changed or settings are unavailable)."""
    try:
        from app.services.effective_config import detection_config

        return detection_config()
    except Exception:
        return DetectionConfig()
