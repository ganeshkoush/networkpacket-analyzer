import settingsPayload from "./settingsPayload.json";
import type {
  SettingsPayload, CaptureSession, DashboardData, NetworkInvestigation, NetworkMetric,
  AnalysisBundle, AnalysisResult, AnomalyList, Correlation, CorrelationList, DomainBaselineView, Finding, MapConnection, MapEdge, MapNode, NetworkMapData, HistoryPoint, JobStatus, PerformanceAnomaly, WebActivityList, WebDomainDetail, WebDomainRow,
} from "../api/types";

export function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "PORT_SCAN-abc123", type: "PORT_SCAN", severity: "HIGH", confidence: 0.91,
    source_ip: "10.0.0.99", destination_ip: "10.0.0.9",
    title: "Possible TCP port scan from 10.0.0.99",
    description: "10.0.0.99 sent 119 SYN packets to 119 distinct ports. This is consistent with possible TCP port scanning and requires investigation.",
    evidence: { unique_ports: 119, syn_packets: 119, syn_ack_packets: 0, failure_ratio: 1, sample_ports: [1, 2, 3], top_targets: [{ ip: "10.0.0.9", unique_ports: 119 }] },
    reasoning: ["Probed 119 distinct ports (threshold 15).", "100% of SYNs were unanswered (threshold 50%)."],
    caveats: ["Authorized vulnerability scanners produce this pattern."],
    confidence_factors: [{ name: "port_breadth", score: 1, weight: 0.4, detail: "119 distinct ports" }, { name: "failure_ratio", score: 0.9, weight: 0.25, detail: "100% unanswered" }],
    recommendation: "Check whether 10.0.0.99 is an authorized scanner.",
    detector: "port_scan", first_seen: 1_700_000_000, last_seen: 1_700_000_001, ...over,
  };
}

export function makeAnalysis(over: Partial<AnalysisResult> = {}): AnalysisResult {
  const base: AnalysisResult = {
    metadata: { file_name: "demo.pcap", file_size_bytes: 150_000, sha256: "ab".repeat(32), capture_format: "pcap", packets_read: 1200,
      malformed_packets: 0, snaplen_truncated_packets: 0, read_error: null, warnings: [], first_packet_time: 1_700_000_000,
      last_packet_time: 1_700_000_030, duration_seconds: 30, analysis_seconds: 0.4 },
    packet_statistics: { total_packets: 1200, total_bytes: 150_000, min_packet_size: 42, max_packet_size: 1500, mean_packet_size: 125, avg_packets_per_second: 40, avg_bits_per_second: 40_000, peak_packets_per_second: 300,
      size_distribution: [{ label: "0-63", packets: 1000 }, { label: "64-127", packets: 200 }] },
    protocol_statistics: { distribution: [
      { protocol: "TCP", packets: 900, bytes: 100_000, percent_of_packets: 75 },
      { protocol: "DNS", packets: 200, bytes: 30_000, percent_of_packets: 16.67 },
      { protocol: "ARP", packets: 100, bytes: 20_000, percent_of_packets: 8.33 }], layer_packet_counts: {} },
    ip_statistics: { unique_source_ips: 12, unique_destination_ips: 9, total_conversations: 14,
      top_sources: [{ ip: "10.0.0.99", packets: 500, bytes: 40_000, is_private: true }, { ip: "93.184.216.34", packets: 100, bytes: 9000, is_private: false }],
      top_destinations: [{ ip: "10.0.0.9", packets: 600, bytes: 50_000, is_private: true }],
      top_talkers: [{ ip: "10.0.0.99", is_private: true, packets_sent: 500, packets_received: 50, bytes_sent: 40_000, bytes_received: 3000, total_packets: 550, total_bytes: 43_000 }],
      conversations: [{ ip_a: "10.0.0.9", ip_b: "10.0.0.99", packets: 550, bytes: 43_000, packets_a_to_b: 50, packets_b_to_a: 500 }] },
    port_statistics: { top_source_ports: [], top_destination_ports: [{ protocol: "TCP", port: 443, packets: 300, bytes: 20_000, service_hint: "https" }, { protocol: "UDP", port: 53, packets: 200, bytes: 20_000, service_hint: "dns" }],
      unique_source_ports: 50, unique_destination_ports: 130,
      destination_ports_per_source: [{ source_ip: "10.0.0.99", unique_destination_ports: 119, packets: 500, sample_ports: [1, 2, 3] }] },
    tcp_statistics: { total_packets: 900, flag_counts: {}, flag_combinations: [{ flags: "SYN", packets: 300 }], syn_packets: 300, syn_ack_packets: 20, ack_only_packets: 100, rst_packets: 280, fin_packets: 10, syn_to_syn_ack_ratio: 15,
      retransmissions: { retransmitted_segments: 2, sequence_bearing_segments: 400, retransmission_rate: 0.005, duplicate_acks: 1, syn_retransmissions: 0 } },
    dns_statistics: { total_queries: 100, total_responses: 100, unique_domains: 40, query_types: { A: 100 }, response_codes: { NOERROR: 100 }, nxdomain_responses: 0, unanswered_queries: 0, avg_response_ms: 12, max_response_ms: 40,
      top_domains: [{ name: "example.com", count: 30 }], top_clients: [{ name: "10.0.0.5", count: 100 }], top_servers: [{ name: "8.8.8.8", count: 100 }] },
    connections: [
      { id: "aaaaaaaaaaaa", protocol: "TCP", client_ip: "10.0.0.5", client_port: 50000, server_ip: "93.184.216.34", server_port: 443, packets: 20, bytes: 5000,
        packets_client_to_server: 8, packets_server_to_client: 12, bytes_client_to_server: 1000, bytes_server_to_client: 4000,
        start_time: 1_700_000_000.12, end_time: 1_700_000_001.831, duration_seconds: 1.711, handshake_complete: true, syn_seen: true, synack_seen: true, fin_seen: true, rst_seen: false,
        tcp_flags_seen: ["SYN", "ACK", "FIN"], state: "CLOSING", resets: 0, retransmissions: 2, domain: "cdn.example.net", domain_ambiguous: true,
        handshake_status: "completed", handshake_incomplete_reason: null, tcp_syn_timestamp: 1_700_000_000.12, tcp_syn_ack_timestamp: 1_700_000_000.165, tcp_ack_timestamp: 1_700_000_000.172,
        tcp_syn_ack_latency_ms: 45, tcp_ack_latency_ms: 7, tcp_handshake_time_ms: 52, tcp_syn_retransmissions: 0, tcp_syn_ack_retransmissions: 0 },
      { id: "bbbbbbbbbbbb", protocol: "UDP", client_ip: "2001:db8::10", client_port: 41000, server_ip: "2606:4700:4700::1111", server_port: 53, packets: 2, bytes: 180,
        packets_client_to_server: 1, packets_server_to_client: 1, bytes_client_to_server: 80, bytes_server_to_client: 100,
        start_time: 1_700_000_010, end_time: 1_700_000_010.05, duration_seconds: 0.05, handshake_complete: null, rst_seen: null, state: null, domain: null },
      { id: "cccccccccccc", protocol: "TCP", client_ip: "10.0.0.5", client_port: 50001, server_ip: "203.0.113.9", server_port: 8443, packets: 1, bytes: 60,
        packets_client_to_server: 1, packets_server_to_client: 0, bytes_client_to_server: 60, bytes_server_to_client: 0,
        start_time: 1_700_000_020, end_time: 1_700_000_020, duration_seconds: 0, handshake_complete: false, syn_seen: true, synack_seen: false, fin_seen: false, rst_seen: false,
        state: "SYN_SENT", resets: 0, retransmissions: 0, domain: null,
        handshake_status: "incomplete", handshake_incomplete_reason: "no_synack", tcp_syn_timestamp: 1_700_000_020, tcp_syn_ack_timestamp: null, tcp_ack_timestamp: null,
        tcp_syn_ack_latency_ms: null, tcp_ack_latency_ms: null, tcp_handshake_time_ms: null, tcp_syn_retransmissions: 2, tcp_syn_ack_retransmissions: 0 },
    ],
    connection_summary: { total_connections: 120, by_protocol: { TCP: 100, UDP: 20 }, tcp_handshakes_complete: 12, tcp_with_rst: 80, by_state: { CLOSING: 1, SYN_SENT: 1 },
      handshakes_timed: 3, handshakes_incomplete: 1, avg_handshake_ms: 55.3,
      handshake_by_domain: [
        { domain: "youtube.com", samples: 1, avg_handshake_ms: 73, min_handshake_ms: 73, max_handshake_ms: 73 },
        { domain: "github.com", samples: 1, avg_handshake_ms: 51, min_handshake_ms: 51, max_handshake_ms: 51 },
        { domain: "google.com", samples: 2, avg_handshake_ms: 42, min_handshake_ms: 40, max_handshake_ms: 44 },
      ] },
    performance_statistics: {
      summary: { tracked_connections: 3, connections_with_rtt: 2, http_responses_timed: 1, encrypted_connections: 1, dns_lookups_timed: 4,
        notes: ["TCP handshake time is connection set-up time (SYN to final ACK). It is not website or application response time."] },
      domains: [
        { domain: "github.com", connections: 4, dns_latency_ms: 19, dns_lookups: 2, tcp_handshake_ms: 42, handshake_samples: 4, avg_rtt_ms: 36, p95_rtt_ms: 71, rtt_samples: 40,
          application_response_ms: null, application_response_samples: 0, http_connections: 0, encrypted_connections: 4, measurement_confidence: "HIGH" },
        { domain: "plain.example.org", connections: 1, dns_latency_ms: 8, dns_lookups: 1, tcp_handshake_ms: 12, handshake_samples: 1, avg_rtt_ms: null, p95_rtt_ms: null, rtt_samples: 0,
          application_response_ms: 80, application_response_samples: 1, http_connections: 1, encrypted_connections: 0, measurement_confidence: "UNAVAILABLE" },
        { domain: "slow.example.net", connections: 2, dns_latency_ms: 90, dns_lookups: 1, tcp_handshake_ms: 150, handshake_samples: 2, avg_rtt_ms: 140, p95_rtt_ms: 210, rtt_samples: 6,
          application_response_ms: null, application_response_samples: 0, http_connections: 0, encrypted_connections: 0, measurement_confidence: "MEDIUM" },
      ],
      metrics: [
        { connection_id: "aaaaaaaaaaaa", domain: "github.com", protocol: "TCP", application_protocol: "TLS", encrypted: true, dns_latency_ms: 19, dns_lookups: 2, tcp_handshake_ms: 42, tls_server_hello_ms: 65,
          min_rtt_ms: 30, avg_rtt_ms: 36, median_rtt_ms: 35, p95_rtt_ms: 71, max_rtt_ms: 80, rtt_samples: 40, rtt_basis: "server_to_client", application_response_ms: null, application_response_samples: 0,
          connection_duration_ms: 1711, measurement_confidence: "HIGH", notes: ["Encrypted (TLS): HTTP request/response timing is not visible, so no response time is reported."] },
        { connection_id: "bbbbbbbbbbbb", domain: null, protocol: "UDP", application_protocol: "DNS", encrypted: false, dns_latency_ms: 21, dns_lookups: 1, tcp_handshake_ms: null, tls_server_hello_ms: null,
          min_rtt_ms: null, avg_rtt_ms: null, median_rtt_ms: null, p95_rtt_ms: null, max_rtt_ms: null, rtt_samples: 0, rtt_basis: null, application_response_ms: null, application_response_samples: 0,
          connection_duration_ms: 21, measurement_confidence: "HIGH", notes: [] },
        { connection_id: "cccccccccccc", domain: null, protocol: "TCP", application_protocol: "HTTP", encrypted: false, dns_latency_ms: null, dns_lookups: 0, tcp_handshake_ms: null, tls_server_hello_ms: null,
          min_rtt_ms: null, avg_rtt_ms: null, median_rtt_ms: null, p95_rtt_ms: null, max_rtt_ms: null, rtt_samples: 0, rtt_basis: null, application_response_ms: 80, application_response_samples: 1,
          connection_duration_ms: 90, measurement_confidence: "UNAVAILABLE", notes: ["Not enough data segments acknowledged by pure ACKs to derive an RTT."] },
      ],
    },
    domain_statistics: {
      domains: [
        { domain: "github.com", resolved_ips: ["140.82.112.3"], clients: ["10.0.0.5"], first_seen: 1_700_000_000, last_seen: 1_700_000_050, dns_queries: 2, dns_responses: 2, connection_count: 18, tcp_connection_count: 18, udp_connection_count: 0, total_bytes_sent: 1_200_000, total_bytes_received: 3_800_000, min_ttl: 60, max_ttl: 60, ambiguous_connection_count: 0, shared_ips: [], server_ports: [443] },
        { domain: "cdn.example.net", resolved_ips: ["93.184.216.34"], clients: ["10.0.0.5"], first_seen: 1_700_000_010, last_seen: 1_700_000_090, dns_queries: 1, dns_responses: 1, connection_count: 40, tcp_connection_count: 30, udp_connection_count: 10, total_bytes_sent: 50_000, total_bytes_received: 200_000, min_ttl: 30, max_ttl: 300, ambiguous_connection_count: 5, shared_ips: ["93.184.216.34"], server_ports: [443, 80] },
        { domain: "quiet.example.org", resolved_ips: [], clients: ["10.0.0.5"], first_seen: 1_700_000_020, last_seen: 1_700_000_020, dns_queries: 1, dns_responses: 0, connection_count: 0, tcp_connection_count: 0, udp_connection_count: 0, total_bytes_sent: 0, total_bytes_received: 0, min_ttl: null, max_ttl: null, ambiguous_connection_count: 0, shared_ips: [], server_ports: [] },
      ],
      summary: { total_domains: 3, reported_domains: 3, domains_with_connections: 2, attributed_connections: 58, unattributed_connections: 7, ambiguous_connections: 5, dns_only_domains: 1, encrypted_dns_flows: 0, domains_not_tracked: 0,
        notes: ["Domains are inferred by matching DNS answers to later connections. HTTPS URLs, paths and page content are encrypted and not visible; only the hostname a client resolved is known."] },
    },
    timeline: Array.from({ length: 10 }, (_, i) => ({ start_time: 1_700_000_000 + i * 3, offset_seconds: i * 3, interval_seconds: 3, packets: 100 + i * 20, bytes: 10_000, packets_per_second: 33 + i * 6 })),
  };
  return { ...base, ...over };
}

export function makeJob(over: Partial<JobStatus> = {}): JobStatus {
  return { id: "job1", filename: "demo.pcap", size_bytes: 150_000, status: "completed", progress_percent: 100, packets_read: 1200, elapsed_seconds: 0.4, error: null, ...over };
}

export function makeBundle(opts: { findings?: Finding[]; analysis?: AnalysisResult } = {}): AnalysisBundle {
  return {
    job: makeJob(),
    analysis: opts.analysis ?? makeAnalysis(),
    findings: opts.findings ?? [
      makeFinding(),
      makeFinding({ id: "DNS_DGA_LIKE-1", type: "DNS_DGA_LIKE", severity: "MEDIUM", confidence: 0.62, source_ip: "10.0.0.7", destination_ip: null, title: "Possible DGA domains", description: "Random-looking names.", evidence: { random_looking_domains: 12 } }),
      makeFinding({ id: "ARP_SPOOFING-1", type: "ARP_SPOOFING", severity: "INFO", confidence: 0.37, source_ip: "10.0.0.1", destination_ip: null, title: "Multiple MACs for 10.0.0.1", description: "Two MACs claimed one IP." }),
    ],
    detector_errors: {},
  };
}

export const emptyAnalysis = (): AnalysisResult => {
  const a = makeAnalysis();
  return {
    ...a,
    metadata: { ...a.metadata, packets_read: 0, duration_seconds: 0, first_packet_time: null, last_packet_time: null, warnings: ["Capture contains no packets."] },
    packet_statistics: { ...a.packet_statistics, total_packets: 0, total_bytes: 0, size_distribution: [] },
    protocol_statistics: { distribution: [], layer_packet_counts: {} }, timeline: [], connections: [],
  };
};

// ---- Domain / Web Activity dashboard
export function makeWebRow(over: Partial<WebDomainRow> = {}): WebDomainRow {
  return {
    domain: "github.com", connections: 18, total_bytes: 3_250_000, bytes_sent: 650_000, bytes_received: 2_600_000,
    first_seen: 1_700_000_000, last_seen: 1_700_000_030, dns_latency_ms: 18, tcp_handshake_ms: 51, avg_rtt_ms: 72, p95_rtt_ms: 104,
    rtt_samples: 40, health: "good", health_reasons: [], ...over,
  };
}

export function makeWebList(domains: WebDomainRow[] = [
  makeWebRow(),
  makeWebRow({ domain: "youtube.com", connections: 31, total_bytes: 25_900_000, dns_latency_ms: 29, tcp_handshake_ms: 73, avg_rtt_ms: 410, p95_rtt_ms: 650, health: "poor",
    health_reasons: ["Average RTT 410 ms is high (threshold 300 ms)"] }),
  makeWebRow({ domain: "quic.example.org", connections: 2, total_bytes: 9000, dns_latency_ms: null, tcp_handshake_ms: null, avg_rtt_ms: null, p95_rtt_ms: null, rtt_samples: 0, health: "unknown" }),
], over: Partial<WebActivityList> = {}): WebActivityList {
  return {
    summary: { total_domains: domains.length, domains_with_connections: domains.filter((d) => d.connections > 0).length,
      health_counts: { good: 1, poor: 1, unknown: 1 },
      notes: ["Domains are inferred from DNS lookups that preceded each connection, not read from the traffic itself.",
        "Health is a heuristic summary of measured latency and loss indicators. It is not a verdict on a site; connection set-up time is never treated as response time."] },
    total_matching: domains.length, offset: 0, limit: 25, domains, ...over,
  };
}

export function makeWebDetail(over: Partial<WebDomainDetail> = {}): WebDomainDetail {
  const github = makeAnalysis().domain_statistics!.domains[0];
  return {
    domain: "github.com", health: "fair", health_reasons: ["TCP handshake (average) 150 ms is elevated (threshold 100 ms)"],
    overview: { ...github, packets_sent: 400, packets_received: 900 },
    performance: {
      domain: "github.com", connections: 18, dns_latency_ms: 19, dns_lookups: 2, tcp_handshake_ms: 51, handshake_samples: 18, avg_rtt_ms: 72, p95_rtt_ms: 104, rtt_samples: 40,
      application_response_ms: null, application_response_samples: 0, http_connections: 0, encrypted_connections: 18, measurement_confidence: "HIGH",
      max_rtt_ms: 180, retransmissions: 3, resets: 2, connections_reset: 1, tcp_packets: 600,
    },
    connections: [{
      id: "aaaaaaaaaaaa", protocol: "TCP", application_protocol: "TLS", client_ip: "10.0.0.5", client_port: 50000, server_ip: "140.82.112.3", server_port: 443, state: "ESTABLISHED",
      start_time: 1_700_000_001, duration_seconds: 1.711, bytes: 52_000, packets: 80, handshake_ms: 51, avg_rtt_ms: 72, p95_rtt_ms: 104, application_response_ms: null,
      retransmissions: 1, resets: 0, measurement_confidence: "HIGH",
    }],
    connections_total: 18,
    series: {
      bin_seconds: 1,
      rtt: [{ t: 1_700_000_001, avg_rtt_ms: 60, p95_rtt_ms: 90, response_ms: null }, { t: 1_700_000_011, avg_rtt_ms: 80, p95_rtt_ms: 120, response_ms: null }, { t: 1_700_000_021, avg_rtt_ms: 70, p95_rtt_ms: null, response_ms: null }],
      handshake: [{ t: 1_700_000_001, handshake_ms: 40 }, { t: 1_700_000_011, handshake_ms: 60 }],
      traffic: [{ t: 1_700_000_001, bytes_sent: 1000, bytes_received: 9000 }, { t: 1_700_000_002, bytes_sent: 500, bytes_received: 4000 }, { t: 1_700_000_005, bytes_sent: 200, bytes_received: 800 }],
    },
    notes: ["Domains are inferred from DNS lookups that preceded each connection, not read from the traffic itself."],
    ...over,
  };
}

// ---- Historical baselines
export function makeAnomaly(over: Partial<PerformanceAnomaly> = {}): PerformanceAnomaly {
  return {
    id: "anom1", domain: "github.com", metric: "tcp_handshake_ms", label: "TCP handshake", unit: "ms",
    baseline: 45, baseline_mean: 46, baseline_std: 3, baseline_observations: 14, current_value: 131, deviation: 1.91, absolute_change: 86, z_score: 9.2,
    severity: "MEDIUM", confidence: 0.62, confidence_label: "Medium", first_seen: 1_700_000_000, last_seen: 1_700_003_600, observations_in_run: 2,
    evidence: ["TCP handshake was 131 ms in this capture (12 samples), against a typical 45 ms over the previous 14 observations (mean 46 ms, range 41–49 ms).",
      "Robust z-score 9.2 (log scale, median/MAD); significance threshold 3.5."],
    caveats: ["This is a possible performance change relative to this domain's own earlier captures, not a diagnosis."], ...over,
  };
}

export function makeAnomalyList(over: Partial<AnomalyList> = {}): AnomalyList {
  return {
    history_enabled: true, domains_evaluated: 2, domains_with_baseline: 1,
    anomalies: [makeAnomaly(), makeAnomaly({ id: "anom2", metric: "retransmission_rate", label: "Retransmission rate", unit: "%", baseline: 0.008, baseline_mean: 0.009,
      current_value: 0.062, deviation: 6.75, absolute_change: 0.054, severity: "HIGH", confidence: 0.81, confidence_label: "High" })],
    notes: ["Baselines are learned from this computer's earlier captures and stay in the local database (domain names and aggregate numbers only)."], ...over,
  };
}

const point = (i: number, over: Partial<HistoryPoint> = {}): HistoryPoint => ({
  t: 1_700_000_000 + i * 3600, source_name: `cap${i}.pcap`, current: false, tcp_handshake_ms: 45 + (i % 3), avg_rtt_ms: 38 + (i % 3), p95_rtt_ms: 72,
  dns_latency_ms: 20, response_ms: null, retransmission_rate: 0.008, failure_rate: 0, ...over,
});

export function makeBaselineView(over: Partial<DomainBaselineView> = {}): DomainBaselineView {
  const base = { observations: 14, excluded_outliers: 0, mean: 46, std: 3, median: 45, p95: 49, min: 41, max: 50 };
  return {
    domain: "github.com", history_enabled: true, prior_observations: 14,
    comparisons: [
      { metric: "tcp_handshake_ms", label: "TCP handshake", unit: "ms", status: "anomalous", current: 131, current_samples: 12, baseline: base, relative_change: 1.91, z_score: 9.2, note: null },
      { metric: "avg_rtt_ms", label: "Average RTT", unit: "ms", status: "normal", current: 40, current_samples: 40, baseline: { ...base, median: 38 }, relative_change: 0.05, z_score: 0.6, note: null },
      { metric: "p95_rtt_ms", label: "P95 RTT", unit: "ms", status: "insufficient_current", current: 75, current_samples: 8, baseline: { ...base, median: 72 }, relative_change: 0.04, z_score: 0.3,
        note: "This capture has 8 samples for this metric; at least 20 are needed to judge it." },
      { metric: "dns_latency_ms", label: "DNS latency", unit: "ms", status: "insufficient_baseline", current: 22, current_samples: 3, baseline: { ...base, observations: 3, median: 20 }, relative_change: null, z_score: null,
        note: "Baseline needs 5 earlier observations with this metric; 3 so far." },
      { metric: "response_ms", label: "Response time", unit: "ms", status: "no_data", current: null, current_samples: 0, baseline: null, relative_change: null, z_score: null, note: "Not measurable in this capture." },
      { metric: "retransmission_rate", label: "Retransmission rate", unit: "%", status: "anomalous", current: 0.062, current_samples: 2000, baseline: { ...base, median: 0.008, mean: 0.009, std: 0.002, p95: 0.012, min: 0.005, max: 0.013 },
        relative_change: 6.75, z_score: 12.1, note: null },
    ],
    anomalies: makeAnomalyList().anomalies,
    history: [...Array.from({ length: 14 }, (_, i) => point(i)), point(14, { current: true, tcp_handshake_ms: 131, avg_rtt_ms: 102, p95_rtt_ms: 211, retransmission_rate: 0.062 })],
    notes: [], ...over,
  };
}

// ---- Correlations (potentially related events)
export function makeCorrelation(over: Partial<Correlation> = {}): Correlation {
  return {
    id: "corr1", type: "SYN_FLOOD_HANDSHAKE_LATENCY", relationship: "Potentially related",
    finding_id: "PORT_SCAN-abc123", finding_type: "SYN_FLOOD", finding_title: "Possible SYN flood against 10.0.0.9:80", finding_severity: "HIGH", finding_confidence: 0.87,
    finding_first_seen: 1_700_000_060, finding_last_seen: 1_700_000_070,
    performance: makeAnomaly({ id: "perf1", domain: "10.0.0.9", baseline: 40, current_value: 180, deviation: 3.5, ratio: 4.5, basis: "capture", scope_ips: ["10.0.0.9"] }),
    headline: "TCP handshake latency increased 4.5x (40 ms → 180 ms)",
    summary: "Possible SYN flood against 10.0.0.9:80: potentially related to TCP handshake latency increased 4.5x (40 ms → 180 ms).",
    time_difference_seconds: 0.5, temporal_relation: "overlapping", shared_ips: ["10.0.0.9"], shared_domains: ["shop.example.com"], scope: "host",
    evidence: ["TCP handshakes to 10.0.0.9 had a median of 180 ms across 11 consecutive slow handshakes between 12:01:00 and 12:01:10 UTC, against 40 ms over 150 handshakes in the rest of the capture: 4.5x.",
      "Handshakes from 203.0.113.50, the source named in the finding, were left out of both sides."],
    caveats: ["Correlation is not proof of causation: the two events share a time window and scope, which can also happen by coincidence or through a common underlying cause.",
      "Legitimate load spikes, a busy or restarting server, or path congestion can also slow handshakes."],
    confidence: 0.78, confidence_label: "High", ...over,
  };
}

export function makeCorrelationList(over: Partial<CorrelationList> = {}): CorrelationList {
  return { finding_id: "PORT_SCAN-abc123", correlations: [makeCorrelation()], not_evaluated: [], no_related_change: [], flow_data_thinned: false,
    notes: ["Correlation is not proof of causation."], ...over };
}

// ---- Network map
const T = 1_700_000_000;
export const mapNode = (id: string, kind: MapNode["kind"], label: string, tier: number, over: Partial<MapNode> = {}): MapNode => ({
  id, kind, label, sublabel: null, tier, state: "healthy", state_reasons: [], connections: 3, bytes: 12_000, latency_ms: null, latency_kind: null,
  domain: null, ip: null, port: null, protocol: null, finding_ids: [], connection_ids: [], members: null, detail_available: true, ...over,
});
export const mapEdge = (source: string, target: string, over: Partial<MapEdge> = {}): MapEdge => ({
  id: `${source}>${target}`, source, target, connections: 3, bytes: 12_000, protocol: "TCP", ports: [], latency_ms: null, latency_kind: null, state: "healthy", connection_ids: [], ...over,
});
export const mapConnection = (id: string, over: Partial<MapConnection> = {}): MapConnection => ({
  id, protocol: "TCP", local_ip: "192.168.1.10", local_port: 50000, remote_ip: "140.82.112.3", remote_port: 443, domain: "github.com", application: null, process_name: null,
  start_time: T + 1, end_time: T + 31, duration_seconds: 30, bytes: 4000, packets: 40, state: "ESTABLISHED", handshake_ms: 45, rtt_ms: 72, retransmissions: 0, health: "healthy", health_reasons: [], ...over,
});

/** local -> github.com / youtube.com / google.com -> two addresses (one shared by two domains) -> ports, plus a flagged address. */
export function makeNetworkMap(over: Partial<NetworkMapData> = {}): NetworkMapData {
  const GH = "140.82.112.3", CDN = "142.250.80.46", BAD = "45.33.32.156";
  const nodes = [
    mapNode("local", "local", "192.168.1.10", 0, { connections: 9, bytes: 40_000, ip: "192.168.1.10", state: "unknown" }),
    mapNode("domain:github.com", "domain", "github.com", 2, { domain: "github.com", latency_ms: 72, latency_kind: "rtt", sublabel: "1 address", connection_ids: ["c1", "c2", "c3"] }),
    mapNode("domain:youtube.com", "domain", "youtube.com", 2, { domain: "youtube.com", latency_ms: 126, latency_kind: "rtt", state: "degraded", state_reasons: ["Average RTT 410 ms is high (threshold 300 ms)"], connection_ids: ["c4"], connections: 1 }),
    mapNode("domain:google.com", "domain", "google.com", 2, { domain: "google.com", latency_ms: 84, latency_kind: "rtt", connection_ids: ["c5"], connections: 1 }),
    mapNode(`ip:${GH}`, "ip", GH, 3, { ip: GH, connection_ids: ["c1", "c2", "c3"] }),
    mapNode(`ip:${CDN}`, "ip", CDN, 3, { ip: CDN, connections: 2, connection_ids: ["c4", "c5"], state: "degraded" }),
    mapNode(`ip:${BAD}`, "ip", BAD, 3, { ip: BAD, connections: 0, bytes: 0, state: "suspicious", detail_available: false, finding_ids: ["PORT_SCAN-abc123"],
      state_reasons: ["Security finding: Possible TCP port scan from 10.0.0.99"], sublabel: "no connection detail kept" }),
    mapNode(`port:${GH}:TCP:443`, "port", "TCP/443", 4, { ip: GH, port: 443, protocol: "TCP", latency_ms: 70, latency_kind: "rtt", connection_ids: ["c1", "c2", "c3"] }),
    mapNode(`port:${CDN}:UDP:443`, "port", "UDP/443", 4, { ip: CDN, port: 443, protocol: "UDP", connections: 2, connection_ids: ["c4", "c5"], state: "unknown" }),
  ];
  const edges = [
    mapEdge("local", "domain:github.com", { ports: [443], latency_ms: 72, latency_kind: "rtt", connection_ids: ["c1", "c2", "c3"] }),
    mapEdge("local", "domain:youtube.com", { connections: 1, protocol: "UDP", ports: [443], latency_ms: 126, latency_kind: "rtt", state: "degraded", connection_ids: ["c4"], bytes: 900_000 }),
    mapEdge("local", "domain:google.com", { connections: 1, protocol: "UDP", ports: [443], latency_ms: 84, latency_kind: "rtt", connection_ids: ["c5"] }),
    mapEdge("domain:github.com", `ip:${GH}`, { ports: [443] }),
    mapEdge("domain:youtube.com", `ip:${CDN}`, { connections: 1, protocol: "UDP", state: "degraded" }),
    mapEdge("domain:google.com", `ip:${CDN}`, { connections: 1, protocol: "UDP", state: "degraded" }),
    mapEdge("local", `ip:${BAD}`, { connections: 0, bytes: 0, protocol: null, state: "suspicious" }),
    mapEdge(`ip:${GH}`, `port:${GH}:TCP:443`, { ports: [443], latency_ms: 70, latency_kind: "rtt", connection_ids: ["c1", "c2", "c3"] }),
    mapEdge(`ip:${CDN}`, `port:${CDN}:UDP:443`, { connections: 2, protocol: "UDP", ports: [443], connection_ids: ["c4", "c5"], state: "unknown" }),
  ];
  return {
    nodes, edges, local: "192.168.1.10", local_hosts: [{ ip: "192.168.1.10", connections: 5 }, { ip: "192.168.1.20", connections: 2 }],
    connections: [mapConnection("c1"), mapConnection("c2", { local_port: 50001 }), mapConnection("c3", { local_port: 50002, retransmissions: 4, health: "degraded", health_reasons: ["4 retransmitted segments (a heuristic loss indicator)"] }),
      mapConnection("c4", { protocol: "UDP", remote_ip: CDN, domain: "youtube.com", state: null, handshake_ms: null, rtt_ms: null, health: "degraded" }),
      mapConnection("c5", { protocol: "UDP", remote_ip: CDN, domain: "google.com", state: null, handshake_ms: null, rtt_ms: 84, application: "Google Chrome", process_name: "Google Chrome Helper" })],
    findings: [{ id: "PORT_SCAN-abc123", type: "PORT_SCAN", severity: "HIGH", confidence: 0.91, title: "Possible TCP port scan from 10.0.0.99", source_ip: BAD, destination_ip: "192.168.1.10" }],
    capture_start: T, capture_end: T + 100, applied_start: null, applied_end: null, total_connections: 5, shown_connections: 5, hidden: { destinations: 0, connections: 0, bytes: 0 },
    applications_status: null, notes: ["Domains are inferred from DNS lookups, not read from the traffic."], ...over,
  };
}


export const makeMetric = (over: Partial<NetworkMetric> = {}): NetworkMetric => ({
  id: "retrans.rate", category: "retransmissions", label: "Retransmission rate", unit: "%", current: 0.062, normal: 0.008, change: 6.75, status: "high", samples: 4000, note: null, ...over,
});

export function makeInvestigation(over: Partial<NetworkInvestigation> = {}): NetworkInvestigation {
  const retrans = makeMetric();
  const rtt = makeMetric({ id: "rtt.avg", category: "rtt", label: "Average RTT", unit: "ms", current: 102, normal: 38, change: 1.68, status: "elevated", samples: 300 });
  const dns = makeMetric({ id: "dns.avg", category: "dns", label: "Average DNS latency", unit: "ms", current: 22, normal: 24, change: -0.08, status: "ok", samples: 40 });
  return {
    status: "completed", generated_at: "2026-10-07T10:00:00Z",
    local: { health: "Degraded", reasons: ["Retransmission rate is well above this computer's usual."], strength: "Medium", strength_reason: "7 earlier captures were used as normal.", earlier_captures: 7, metrics: [retrans, rtt, dns] },
    report: {
      overall_health: "Degraded", summary: "Packet retransmissions are higher than usual and round-trip time has increased.", main_issue: "Elevated packet retransmissions are affecting network latency",
      top_problems: [{ title: "High retransmission rate", detail: "Retransmissions are far above this computer's usual.", evidence_ids: ["retrans.rate"] }, { title: "Slower round trips", detail: "Average RTT rose.", evidence_ids: ["rtt.avg"] }],
      evidence: [{ evidence_id: "retrans.rate", statement: "Retransmission rate was elevated." }, { evidence_id: "rtt.avg", statement: "Average RTT increased." }],
      potential_explanations: ["Wi-Fi interference", "Network congestion", "An unstable route", "Remote service issues"],
      recommended_next_steps: ["Compare latency to multiple independent services."], confidence: "Medium", limitations: ["Only one capture point was available."],
    },
    evidence: [retrans, rtt], health: "Degraded", health_note: null, confidence: "Medium",
    ai: { requested: true, provider: "Google Gemini", model: "gemini-2.5-flash", error_code: null, error_message: null }, notes: [],
    disclosure: "To analyse this, PacketMind sends Google Gemini a summary of the measurements, never the capture. PacketMind never runs anything it suggests.", ...over,
  };
}


export function makeDashboard(over: Partial<DashboardData> = {}): DashboardData {
  return {
    source: "capture", empty: false,
    window: { key: "all", label: "Capture duration", start: 1_700_000_000, end: 1_700_000_030, capture_start: 1_700_000_000, capture_end: 1_700_000_030, covers_whole_capture: true, note: null },
    health: { score: 72, label: "Degraded", deductions: [{ reason: "Retransmission rate 6.2% is elevated (>= 2%)", points: 10 }, { reason: "1 security finding(s) in this range", points: 12 }], basis: "Measured: TCP handshake, Average RTT, DNS latency, Retransmission rate." },
    kpis: { active_connections: 4, connections_in_window: 9, domains_contacted: 3, total_bytes: 2_500_000, total_packets: 1200, avg_handshake_ms: 48, handshake_samples: 8, avg_rtt_ms: 102, rtt_samples: 60,
      dns_latency_ms: 22, dns_samples: 6, retransmission_rate: 0.062, tcp_packets: 900, findings: 1, anomalies: 1 },
    top_domains: [
      makeWebRow({ domain: "github.com", connections: 5, total_bytes: 1_800_000, avg_rtt_ms: 38, health: "good" }),
      makeWebRow({ domain: "slow.example.com", connections: 2, total_bytes: 400_000, avg_rtt_ms: 420, tcp_handshake_ms: 350, health: "poor", health_reasons: ["Average RTT 420 ms is high"] }),
    ],
    slowest_domains: [{ domain: "slow.example.com", avg_rtt_ms: 420, p95_rtt_ms: 610, tcp_handshake_ms: 350, rtt_samples: 12, status: "poor", reasons: ["Average RTT 420 ms is high"] },
                      { domain: "github.com", avg_rtt_ms: 38, p95_rtt_ms: 70, tcp_handshake_ms: 45, rtt_samples: 40, status: "good", reasons: [] }],
    findings: [{ id: "PORT_SCAN-1", type: "PORT_SCAN", title: "Possible port scan from 10.0.0.99", severity: "HIGH", confidence: 0.86, evidence: ["distinct_ports: 220", "rate_per_second: 28"], source_ip: "10.0.0.99", destination_ip: "10.0.0.9", first_seen: 1_700_000_010, last_seen: 1_700_000_020 }],
    anomalies: [makeAnomaly()],
    suspicious_connections: [{ id: "c1", protocol: "TCP", client_ip: "10.0.0.99", client_port: 50000, server_ip: "10.0.0.9", server_port: 22, domain: null, state: "RESET", bytes: 120, start_time: 1_700_000_010, end_time: 1_700_000_011,
      handshake_ms: null, retransmissions: 0, finding_ids: ["PORT_SCAN-1"], reasons: ["An endpoint is named by 1 finding(s): possible, requires investigation"] }],
    active_connections: [{ id: "c2", protocol: "TCP", client_ip: "192.168.1.10", client_port: 40000, server_ip: "140.82.112.3", server_port: 443, domain: "github.com", state: "ESTABLISHED", bytes: 900_000, start_time: 1_700_000_001,
      end_time: 1_700_000_029, handshake_ms: 45, retransmissions: 2, finding_ids: [], reasons: [] }],
    recent_activity: [{ time: 1_700_000_020, kind: "finding", text: "Possible port scan from 10.0.0.99", severity: "HIGH", ref: "PORT_SCAN-1" },
                      { time: 1_700_000_009, kind: "anomaly", text: "github.com: Average RTT is +168% against its usual", severity: "MEDIUM", ref: "github.com" },
                      { time: 1_700_000_001, kind: "domain", text: "First contact with github.com", severity: null, ref: "github.com" }],
    timeline: Array.from({ length: 6 }, (_, i) => ({ start_time: 1_700_000_000 + i * 5, interval_seconds: 5, packets: 200, bytes: 400_000 })),
    markers: [{ time: 1_700_000_010, kind: "finding", label: "Possible port scan from 10.0.0.99", severity: "HIGH" }],
    notes: ["Domains are inferred from DNS lookups, not read from traffic."], ...over,
  };
}

export const emptyDashboard = (over: Partial<DashboardData> = {}): DashboardData => makeDashboard({
  empty: true, window: { key: "all", label: "Capture duration", start: null, end: null, capture_start: null, capture_end: null, covers_whole_capture: true, note: null },
  health: { score: null, label: "Unknown", deductions: [], basis: "This capture contains no packets." },
  kpis: { active_connections: 0, connections_in_window: 0, domains_contacted: 0, total_bytes: 0, total_packets: 0, avg_handshake_ms: null, handshake_samples: 0, avg_rtt_ms: null, rtt_samples: 0,
    dns_latency_ms: null, dns_samples: 0, retransmission_rate: null, tcp_packets: 0, findings: 0, anomalies: 0 },
  top_domains: [], slowest_domains: [], findings: [], anomalies: [], suspicious_connections: [], active_connections: [], recent_activity: [], timeline: [], markers: [], notes: ["No packets to summarise."], ...over,
});


export function makeCapture(over: Partial<CaptureSession> = {}): CaptureSession {
  return {
    id: "a".repeat(32), filename: "packetmind_capture_2026-10-07_23-30-15_ab12cd.pcap", original_filename: "packetmind_capture_2026-10-07_23-30-15_ab12cd.pcap",
    source_type: "LIVE_CAPTURE", capture_format: "pcap", interface: "Wi-Fi", start_time: 1_700_000_000, end_time: 1_700_000_272, duration_seconds: 272,
    packet_count: 12_483, byte_count: 19_300_000, file_size: 19_300_000, status: "ANALYZED", error_message: null, created_at: "2026-10-07T23:30:15+00:00",
    analyzed_at: "2026-10-07T23:35:00+00:00",
    summary: { protocols: [{ protocol: "TCP", packets: 8988, percent: 72 }, { protocol: "UDP", packets: 2372, percent: 19 }, { protocol: "DNS", packets: 874, percent: 7 }, { protocol: "ARP", packets: 249, percent: 2 }],
      domains: 42, findings: 3, connections: 310 }, ...over,
  };
}


/** The settings payload exactly as the backend produces it (generated from the Python model: defaults, limits, unavailable controls). */
export function makeSettingsPayload(over: Partial<SettingsPayload> = {}, settings: Record<string, unknown> = {}): SettingsPayload {
  const base = JSON.parse(JSON.stringify(settingsPayload)) as SettingsPayload;
  for (const [section, values] of Object.entries(settings)) Object.assign((base.settings as unknown as Record<string, object>)[section], values);
  return { ...base, ...over };
}
