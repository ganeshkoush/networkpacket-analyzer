"""Pydantic data models for PCAP analysis results.

These models are the contract between the local analysis engine and everything
that consumes it (API, reports, and later the AI layer). They contain only
aggregated, JSON-serialisable data - never raw packets.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AnalysisOptions(BaseModel):
    """Limits that keep analysis output (and memory use) bounded."""

    top_n: int = Field(20, ge=1, description="Entries in each 'top X' list")
    max_connections: int = Field(200, ge=1, description="Connections reported (by bytes)")
    max_conversations: int = Field(100, ge=1)
    timeline_max_points: int = Field(300, ge=1)
    max_dns_log: int = Field(500, ge=0, description="DNS queries kept in the query log")
    max_profiles: int = Field(100, ge=1, description="Per-source/target/client profiles reported")
    max_domains: int = Field(500, ge=1, description="Domains reported in domain activity (by traffic)")
    dns_entropy_threshold: float = Field(3.2, description="Shannon entropy (bits/char) a domain label needs to look random")
    dns_entropy_min_label_length: int = Field(12, ge=1, description="Minimum label length for the randomness feature")
    dns_random_digit_share: float = Field(0.2, ge=0, le=1, description="Digit share that (with entropy) marks a label random")
    dns_random_consonant_run: int = Field(5, ge=1, description="Consonant run length that (with entropy) marks a label random")


# --------------------------------------------------------------------- metadata
class CaptureMetadata(BaseModel):
    file_name: str
    file_path: str
    file_size_bytes: int
    sha256: str
    capture_format: str  # "pcap" | "pcapng"
    packets_read: int
    malformed_packets: int = 0
    snaplen_truncated_packets: int = 0
    read_error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    first_packet_time: float | None = None
    last_packet_time: float | None = None
    first_packet_time_iso: str | None = None
    last_packet_time_iso: str | None = None
    duration_seconds: float = 0.0
    analyzed_at: datetime
    analysis_seconds: float = 0.0


class SizeBucket(BaseModel):
    label: str
    packets: int


class PacketStatistics(BaseModel):
    total_packets: int = 0
    total_bytes: int = 0
    min_packet_size: int | None = None
    max_packet_size: int | None = None
    mean_packet_size: float | None = None
    avg_packets_per_second: float | None = None
    avg_bits_per_second: float | None = None
    peak_packets_per_second: int | None = None
    size_distribution: list[SizeBucket] = Field(default_factory=list)


# --------------------------------------------------------------------- protocols
class ProtocolStat(BaseModel):
    protocol: str
    packets: int
    bytes: int
    percent_of_packets: float


class ProtocolStatistics(BaseModel):
    """`distribution` classifies each packet by its most specific protocol;
    `layer_packet_counts` counts packets *containing* each layer."""

    distribution: list[ProtocolStat] = Field(default_factory=list)
    layer_packet_counts: dict[str, int] = Field(default_factory=dict)


# --------------------------------------------------------------------- IPs
class IpCount(BaseModel):
    ip: str
    packets: int
    bytes: int
    is_private: bool


class Talker(BaseModel):
    ip: str
    is_private: bool
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    total_packets: int
    total_bytes: int


class Conversation(BaseModel):
    """Bidirectional traffic between two IP addresses (all ports/protocols)."""

    ip_a: str
    ip_b: str
    packets: int
    bytes: int
    packets_a_to_b: int
    packets_b_to_a: int
    bytes_a_to_b: int
    bytes_b_to_a: int


class IpStatistics(BaseModel):
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    ip_version_packets: dict[str, int] = Field(default_factory=dict)
    top_sources: list[IpCount] = Field(default_factory=list)
    top_destinations: list[IpCount] = Field(default_factory=list)
    top_talkers: list[Talker] = Field(default_factory=list)
    conversations: list[Conversation] = Field(default_factory=list)
    total_conversations: int = 0


# --------------------------------------------------------------------- ports
class PortCount(BaseModel):
    protocol: str  # "TCP" | "UDP"
    port: int
    packets: int
    bytes: int
    service_hint: str | None = None  # IANA-style name for the port; not a claim about content


class SourcePortFanout(BaseModel):
    """How many distinct destination ports one source IP contacted."""

    source_ip: str
    unique_destination_ports: int
    packets: int
    sample_ports: list[int] = Field(default_factory=list)  # lowest ports, capped


class PortStatistics(BaseModel):
    top_source_ports: list[PortCount] = Field(default_factory=list)
    top_destination_ports: list[PortCount] = Field(default_factory=list)
    unique_source_ports: int = 0
    unique_destination_ports: int = 0
    destination_ports_per_source: list[SourcePortFanout] = Field(default_factory=list)
    sources_not_tracked: int = 0  # sources dropped once the tracking cap was hit


# --------------------------------------------------------------------- TCP
class FlagCombination(BaseModel):
    flags: str  # e.g. "SYN,ACK"; "NONE" when no flag is set
    packets: int


class SynSource(BaseModel):
    """SYN activity of one source IP (SYN without ACK)."""

    ip: str
    syn_sent: int
    syn_ack_received: int
    unanswered_ratio: float  # max(0, 1 - syn_ack_received / syn_sent)
    rst_received: int = 0  # RST packets sent back to this source
    unique_destination_hosts: int = 0
    unique_destination_ports: int = 0
    first_syn_time: float | None = None
    last_syn_time: float | None = None


class SynPair(BaseModel):
    """SYN activity from one source to one destination host."""

    src_ip: str
    dst_ip: str
    syn_packets: int
    unique_destination_ports: int
    syn_ack_received: int
    rst_received: int
    first_syn_time: float
    last_syn_time: float
    sample_ports: list[int] = Field(default_factory=list)


class SynTarget(BaseModel):
    """SYN activity aimed at one destination ip:port."""

    dst_ip: str
    dst_port: int
    syn_packets: int
    unique_sources: int
    sources_capped: bool = False  # True if unique_sources is a lower bound
    top_source_ip: str | None = None
    top_source_syns: int = 0
    syn_ack_sent: int = 0  # SYN-ACKs sent *by* this ip:port
    ack_packets_in: int = 0  # ACK-bearing, non-SYN, non-RST packets sent *to* this ip:port
    first_syn_time: float
    last_syn_time: float
    peak_syn_per_second: int = 0


class FlagAnomaly(BaseModel):
    """Packets with an abnormal TCP flag combination, per (source, destination, kind)."""

    src_ip: str
    dst_ip: str
    anomaly: str  # NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST, FIN_NO_ACK, NO_ACK
    flags: str
    packets: int
    first_time: float
    last_time: float


class RetransmissionFlow(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    retransmissions: int
    segments: int = 0  # sequence-bearing segments seen in this direction


class RetransmissionStatistics(BaseModel):
    """Heuristic indicators: a repeated sequence number carrying data (or SYN/FIN)."""

    retransmitted_segments: int = 0
    syn_retransmissions: int = 0
    sequence_bearing_segments: int = 0
    retransmission_rate: float = 0.0
    duplicate_acks: int = 0
    top_flows: list[RetransmissionFlow] = Field(default_factory=list)
    flows_not_tracked: int = 0


class TcpStatistics(BaseModel):
    total_packets: int = 0
    flag_counts: dict[str, int] = Field(default_factory=dict)
    flag_combinations: list[FlagCombination] = Field(default_factory=list)
    syn_packets: int = 0  # SYN without ACK
    syn_ack_packets: int = 0
    ack_only_packets: int = 0
    rst_packets: int = 0
    fin_packets: int = 0
    syn_to_syn_ack_ratio: float | None = None
    top_syn_sources: list[SynSource] = Field(default_factory=list)
    syn_pairs: list[SynPair] = Field(default_factory=list)
    syn_targets: list[SynTarget] = Field(default_factory=list)
    flag_anomalies: list[FlagAnomaly] = Field(default_factory=list)
    syn_profiles_not_tracked: int = 0
    retransmissions: RetransmissionStatistics = Field(default_factory=RetransmissionStatistics)


# --------------------------------------------------------------------- DNS
class DnsCount(BaseModel):
    name: str
    count: int


class DnsQueryLogEntry(BaseModel):
    timestamp: float
    client_ip: str
    server_ip: str
    qname: str
    qtype: str


class DnsClientStat(BaseModel):
    client_ip: str
    queries: int
    responses: int  # responses received by this client
    nxdomain: int
    unique_domains: int  # distinct query names (capped)
    first_time: float
    last_time: float
    random_looking_domains: int = 0  # distinct registered domains whose name label looks random (see looks_random)
    random_looking_samples: list[str] = Field(default_factory=list)


class DnsDomainGroup(BaseModel):
    """Queries grouped by registered-style base domain (last 2 labels, or 3 for known 2-part suffixes)."""

    base_domain: str
    queries: int
    unique_names: int  # capped
    max_name_length: int
    mean_subdomain_label_length: float  # leftmost label of names below the base domain
    txt_null_queries: int
    top_client: str | None = None
    sample_names: list[str] = Field(default_factory=list)


class DnsStatistics(BaseModel):
    total_queries: int = 0
    total_responses: int = 0
    unique_domains: int = 0
    query_types: dict[str, int] = Field(default_factory=dict)
    response_codes: dict[str, int] = Field(default_factory=dict)
    nxdomain_responses: int = 0
    empty_responses: int = 0  # responses with zero answer records
    answered_queries: int = 0
    unanswered_queries: int = 0
    responses_without_query: int = 0
    avg_response_ms: float | None = None
    max_response_ms: float | None = None
    top_domains: list[DnsCount] = Field(default_factory=list)
    top_clients: list[DnsCount] = Field(default_factory=list)
    top_servers: list[DnsCount] = Field(default_factory=list)
    query_log: list[DnsQueryLogEntry] = Field(default_factory=list)
    query_log_truncated: bool = False
    clients: list[DnsClientStat] = Field(default_factory=list)
    domain_groups: list[DnsDomainGroup] = Field(default_factory=list)


# --------------------------------------------------------------------- ARP
class ArpMacUse(BaseModel):
    mac: str
    packets: int
    first_time: float
    last_time: float


class ArpBinding(BaseModel):
    """Sender MAC address(es) observed claiming one IP address."""

    ip: str
    macs: list[ArpMacUse]
    binding_changes: int  # times the claimed MAC differed from the previous claim
    unsolicited_replies: int  # replies with no matching earlier request (excluding gratuitous)
    gratuitous_packets: int  # sender IP == target IP
    eth_mismatch_packets: int  # ARP sender MAC != Ethernet source MAC


class ArpMacBinding(BaseModel):
    """IP addresses claimed by one sender MAC."""

    mac: str
    ip_count: int
    ips: list[str] = Field(default_factory=list)  # capped
    packets: int
    unsolicited_replies: int


class ArpStatistics(BaseModel):
    total_packets: int = 0
    requests: int = 0
    replies: int = 0
    gratuitous_packets: int = 0
    unsolicited_replies: int = 0
    unique_ips: int = 0
    multi_mac_ips: list[ArpBinding] = Field(default_factory=list)  # IPs claimed by >1 MAC
    multi_ip_macs: list[ArpMacBinding] = Field(default_factory=list)  # MACs claiming >1 IP
    ips_not_tracked: int = 0


# --------------------------------------------------------------------- connections
class Connection(BaseModel):
    """A flow keyed by protocol + endpoint pair. 'Client' is the first sender seen."""

    id: str = ""  # stable per flow within a capture; used by the connection detail API
    protocol: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    packets: int
    bytes: int
    packets_client_to_server: int
    packets_server_to_client: int
    bytes_client_to_server: int
    bytes_server_to_client: int
    start_time: float
    end_time: float
    duration_seconds: float
    # TCP only (None for other protocols)
    handshake_complete: bool | None = None
    syn_seen: bool | None = None
    fin_seen: bool | None = None
    rst_seen: bool | None = None
    tcp_flags_seen: list[str] | None = None
    synack_seen: bool | None = None
    # Capture-visible TCP state: SYN_SENT, SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED, RESET, UNKNOWN.
    state: str | None = None
    resets: int | None = None  # RST packets seen (either direction)
    retransmissions: int | None = None  # heuristic indicator from the TCP analyzer, not a verdict
    # Inferred from DNS (see DomainAnalyzer); None when no lookup preceded the connection.
    domain: str | None = None
    domain_ambiguous: bool = False  # server IP was also resolved for other domains
    # TCP three-way handshake timing (epoch seconds / milliseconds). Set only for packets that could be
    # paired by sequence numbers; None otherwise. "incomplete" never carries an invented latency.
    handshake_status: str | None = None  # "completed" | "incomplete" (None for non-TCP)
    handshake_incomplete_reason: str | None = None  # no_syn_seen | no_synack | no_final_ack | reset | simultaneous_open
    tcp_syn_timestamp: float | None = None
    tcp_syn_ack_timestamp: float | None = None
    tcp_ack_timestamp: float | None = None
    tcp_syn_ack_latency_ms: float | None = None  # SYN -> SYN-ACK
    tcp_ack_latency_ms: float | None = None  # SYN-ACK -> ACK
    tcp_handshake_time_ms: float | None = None  # SYN -> ACK
    tcp_syn_retransmissions: int | None = None  # latencies include this delay when > 0
    tcp_syn_ack_retransmissions: int | None = None


class DomainHandshakeTime(BaseModel):
    """Completed TCP handshakes to one (DNS-inferred) domain. Averages are over completed handshakes only."""

    domain: str
    samples: int
    avg_handshake_ms: float
    min_handshake_ms: float
    max_handshake_ms: float


class ConnectionSummary(BaseModel):
    total_connections: int = 0
    reported_connections: int = 0
    by_protocol: dict[str, int] = Field(default_factory=dict)
    tcp_handshakes_complete: int = 0
    tcp_with_rst: int = 0
    by_state: dict[str, int] = Field(default_factory=dict)  # TCP connections by derived state
    handshakes_timed: int = 0  # TCP connections with a completed, timed handshake
    handshakes_incomplete: int = 0
    avg_handshake_ms: float | None = None
    handshake_by_domain: list[DomainHandshakeTime] = Field(default_factory=list)  # slowest average first
    connections_not_tracked: int = 0


# --------------------------------------------------------------------- domain activity
class DomainActivity(BaseModel):
    """Traffic attributed to one DNS name. Attribution is inferred from DNS, not observed in the
    connection itself: it says "this host resolved <domain> to this IP and then connected to it"."""

    domain: str
    resolved_ips: list[str] = Field(default_factory=list)
    clients: list[str] = Field(default_factory=list)  # hosts that queried or connected (bounded)
    first_seen: float
    last_seen: float
    dns_queries: int = 0
    dns_responses: int = 0
    connection_count: int = 0
    tcp_connection_count: int = 0
    udp_connection_count: int = 0
    total_bytes_sent: int = 0  # client -> server
    total_bytes_received: int = 0  # server -> client
    min_ttl: int | None = None
    max_ttl: int | None = None
    # Connections whose server IP was also resolved for another domain; the most recent
    # resolution before the connection was chosen, so these are less certain.
    ambiguous_connection_count: int = 0
    shared_ips: list[str] = Field(default_factory=list)
    server_ports: list[int] = Field(default_factory=list)
    packets_sent: int = 0  # client -> server, attributed connections only
    packets_received: int = 0


class DomainSummary(BaseModel):
    total_domains: int = 0
    reported_domains: int = 0
    domains_with_connections: int = 0
    attributed_connections: int = 0
    unattributed_connections: int = 0  # TCP/UDP flows (excluding DNS itself) with no DNS match
    ambiguous_connections: int = 0
    dns_only_domains: int = 0  # queried but never connected to (or no answer captured)
    encrypted_dns_flows: int = 0  # TCP/853 (DNS over TLS)
    domains_not_tracked: int = 0
    notes: list[str] = Field(default_factory=list)


class DomainStatistics(BaseModel):
    domains: list[DomainActivity] = Field(default_factory=list)
    summary: DomainSummary = Field(default_factory=DomainSummary)


# --------------------------------------------------------------------- timeline
class TimelinePoint(BaseModel):
    start_time: float  # epoch seconds, start of the interval
    offset_seconds: float  # from first packet
    interval_seconds: int
    packets: int
    bytes: int
    packets_per_second: float


# --------------------------------------------------------------------- result
# --------------------------------------------------------------------- performance / latency
MeasurementConfidence = Literal["HIGH", "MEDIUM", "LOW", "UNAVAILABLE"]


class PerformanceMetrics(BaseModel):
    """Latency measurements of one tracked connection.

    The timings are different things and are deliberately separate fields; ``tcp_handshake_ms`` is
    connection set-up time and is never a website/application response time. A field is None when it
    could not be measured from the captured packets (nothing is estimated).

    ``measurement_confidence`` is the confidence of the round-trip estimate for TCP connections, and of
    the lookup time for DNS flows: HIGH >= 10 clean RTT samples, MEDIUM 3-9, LOW 1-2, UNAVAILABLE none
    (lowered one step when more than 10% of segments were retransmitted/reordered). Other timings
    in the row do not raise it.
    """

    connection_id: str
    domain: str | None = None  # inferred from DNS; None when no lookup preceded the connection
    protocol: str  # transport: TCP / UDP / ...
    application_protocol: str | None = None  # "DNS", "HTTP" (cleartext) or "TLS" (encrypted) when recognised
    encrypted: bool = False  # TLS seen: HTTP request/response timing is not visible
    dns_latency_ms: float | None = None  # DNS lookup of the domain (web rows) or this DNS flow's own lookups
    dns_lookups: int = 0
    tcp_handshake_ms: float | None = None  # SYN -> final ACK; set-up time only
    tls_server_hello_ms: float | None = None  # ClientHello -> ServerHello (not a response time)
    min_rtt_ms: float | None = None
    avg_rtt_ms: float | None = None
    median_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None  # None below 5 RTT samples
    max_rtt_ms: float | None = None
    rtt_samples: int = 0
    rtt_basis: Literal["client_to_server", "server_to_client"] | None = None  # which side's data the RTT came from
    application_response_ms: float | None = None  # cleartext HTTP only: last request packet -> first response packet
    application_response_samples: int = 0
    connection_duration_ms: float = 0.0
    measurement_confidence: MeasurementConfidence = "UNAVAILABLE"
    notes: list[str] = Field(default_factory=list)


class DomainPerformance(BaseModel):
    """Latency of the connections attributed (via DNS) to one domain, over all tracked connections."""

    domain: str
    connections: int
    dns_latency_ms: float | None = None  # median clean lookup
    dns_lookups: int = 0
    tcp_handshake_ms: float | None = None  # average over completed handshakes
    handshake_samples: int = 0
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    rtt_samples: int = 0
    application_response_ms: float | None = None  # median of visible cleartext HTTP responses only
    application_response_samples: int = 0
    http_connections: int = 0
    encrypted_connections: int = 0
    measurement_confidence: MeasurementConfidence = "UNAVAILABLE"
    max_rtt_ms: float | None = None
    # Heuristic indicators from TCP analysis (retransmitted segments / RST packets), summed over the domain's TCP connections.
    retransmissions: int = 0
    resets: int = 0  # RST packets
    connections_reset: int = 0  # connections that saw an RST
    tcp_packets: int = 0
    # Connection attempts (a SYN was captured) and the ones that failed: SYN never answered, or reset before the
    # handshake finished. A capture that ends mid-handshake can look like an unanswered SYN.
    tcp_connections_attempted: int = 0
    tcp_connections_failed: int = 0


class RttPoint(BaseModel):
    """One TCP connection with a measurable RTT, placed at its first packet."""

    t: float
    avg_rtt_ms: float | None = None
    p95_rtt_ms: float | None = None
    response_ms: float | None = None  # cleartext HTTP only


class HandshakePoint(BaseModel):
    t: float
    handshake_ms: float


class TrafficPoint(BaseModel):
    """Bytes of the domain's attributed connections seen in one time bin (exact, counted per packet)."""

    t: float  # bin start (epoch seconds)
    bytes_sent: int
    bytes_received: int


@dataclass(slots=True)
class FlowSample:
    """One TCP connection's timing facts, for time-window comparisons by the correlation engine (never serialised)."""

    t: float  # first packet
    client_ip: str
    server_ip: str
    server_port: int | None
    domain: str | None = None
    attempted: bool = False  # a SYN was captured and the handshake could be judged
    failed: bool = False  # SYN never answered, or reset during the handshake
    reset: bool = False  # saw an RST
    handshake_ms: float | None = None
    rtt_ms: float | None = None  # average RTT of the connection
    rtt_samples: int = 0
    response_ms: float | None = None  # cleartext HTTP only
    retransmissions: int = 0
    packets: int = 0


@dataclass(slots=True)
class LookupSample:
    """One answered DNS lookup (query time, latency, who asked whom)."""

    t: float
    ms: float
    client_ip: str
    server_ip: str


class DomainSeries(BaseModel):
    bin_seconds: float = 1.0
    rtt: list[RttPoint] = Field(default_factory=list)
    handshake: list[HandshakePoint] = Field(default_factory=list)
    traffic: list[TrafficPoint] = Field(default_factory=list)


class PerformanceSummary(BaseModel):
    tracked_connections: int = 0
    connections_with_rtt: int = 0
    http_responses_timed: int = 0
    encrypted_connections: int = 0
    dns_lookups_timed: int = 0
    notes: list[str] = Field(default_factory=list)


class PerformanceStatistics(BaseModel):
    summary: PerformanceSummary = Field(default_factory=PerformanceSummary)
    metrics: list[PerformanceMetrics] = Field(default_factory=list)  # same connections as AnalysisResult.connections
    domains: list[DomainPerformance] = Field(default_factory=list)
    # Per-domain time series for the web-activity dashboard. Held in memory with the result but never serialised into
    # it (it is large); served per domain by the web-activity API.
    series: dict[str, DomainSeries] = Field(default_factory=dict, exclude=True)
    # Per-connection and per-lookup samples for the correlation engine: bounded, in memory only, never serialised.
    # ``flow_sample_stride`` > 1 means only every n-th connection was kept (counts are then a uniform 1/n sample).
    flow_samples: list[Any] = Field(default_factory=list, exclude=True)
    flow_sample_stride: int = Field(1, exclude=True)
    lookup_samples: list[Any] = Field(default_factory=list, exclude=True)


class AnalysisResult(BaseModel):
    metadata: CaptureMetadata
    packet_statistics: PacketStatistics
    protocol_statistics: ProtocolStatistics
    ip_statistics: IpStatistics
    port_statistics: PortStatistics
    tcp_statistics: TcpStatistics
    dns_statistics: DnsStatistics
    arp_statistics: ArpStatistics = Field(default_factory=ArpStatistics)
    connections: list[Connection]
    connection_summary: ConnectionSummary
    timeline: list[TimelinePoint]
    domain_statistics: DomainStatistics = Field(default_factory=DomainStatistics)
    performance_statistics: PerformanceStatistics = Field(default_factory=PerformanceStatistics)
