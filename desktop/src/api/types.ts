// Types mirroring the backend's pydantic models (backend/app/models/analysis.py, app/detection/models.py,
// app/api/analyses.py). Only fields the UI uses are listed; extra backend fields are ignored.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Health {
  status: string;
  app: string;
  version: string;
  max_upload_bytes?: number;
}

export interface SystemInfo {
  app: string; version: string;
  ai: { configured: boolean; provider: string; model: string };
  live: { platform: string; capture_library: boolean; privileges: "likely" | "unlikely" | "unknown"; note: string };
  max_upload_bytes: number; max_retained_analyses: number; log_level: string;
  data_dir: string; captures_dir: string; reports_dir: string;
}

export type JobState = "queued" | "running" | "completed" | "failed";

export interface JobStatus {
  id: string;
  filename: string;
  size_bytes: number;
  status: JobState;
  progress_percent: number | null;
  packets_read: number;
  elapsed_seconds: number | null;
  error: { code: string; message: string } | null;
  capture_id?: string | null; // the capture-library entry (saved copy) of this analysis
}

export interface CaptureMetadata {
  file_name: string;
  file_size_bytes: number;
  sha256: string;
  capture_format: string;
  packets_read: number;
  malformed_packets: number;
  snaplen_truncated_packets: number;
  read_error: string | null;
  warnings: string[];
  first_packet_time: number | null;
  last_packet_time: number | null;
  duration_seconds: number;
  analysis_seconds: number;
}

export interface PacketStatistics {
  total_packets: number;
  total_bytes: number;
  min_packet_size: number | null;
  max_packet_size: number | null;
  mean_packet_size: number | null;
  avg_packets_per_second: number | null;
  avg_bits_per_second: number | null;
  peak_packets_per_second: number | null;
  size_distribution: { label: string; packets: number }[];
}

export interface ProtocolStat { protocol: string; packets: number; bytes: number; percent_of_packets: number }
export interface IpCount { ip: string; packets: number; bytes: number; is_private: boolean }
export interface Talker {
  ip: string; is_private: boolean; packets_sent: number; packets_received: number;
  bytes_sent: number; bytes_received: number; total_packets: number; total_bytes: number;
}
export interface Conversation {
  ip_a: string; ip_b: string; packets: number; bytes: number;
  packets_a_to_b: number; packets_b_to_a: number;
}
export interface PortCount { protocol: string; port: number; packets: number; bytes: number; service_hint: string | null }
export interface SourcePortFanout { source_ip: string; unique_destination_ports: number; packets: number; sample_ports: number[] }

export interface TcpStatistics {
  total_packets: number;
  flag_counts: Record<string, number>;
  flag_combinations: { flags: string; packets: number }[];
  syn_packets: number;
  syn_ack_packets: number;
  ack_only_packets: number;
  rst_packets: number;
  fin_packets: number;
  syn_to_syn_ack_ratio: number | null;
  retransmissions: {
    retransmitted_segments: number;
    sequence_bearing_segments: number;
    retransmission_rate: number;
    duplicate_acks: number;
    syn_retransmissions: number;
  };
}

export interface DnsStatistics {
  total_queries: number;
  total_responses: number;
  unique_domains: number;
  query_types: Record<string, number>;
  response_codes: Record<string, number>;
  nxdomain_responses: number;
  unanswered_queries: number;
  avg_response_ms: number | null;
  max_response_ms: number | null;
  top_domains: { name: string; count: number }[];
  top_clients: { name: string; count: number }[];
  top_servers: { name: string; count: number }[];
}

export type TcpState = "SYN_SENT" | "SYN_RECEIVED" | "ESTABLISHED" | "CLOSING" | "CLOSED" | "RESET" | "UNKNOWN";

export interface Connection {
  id?: string; // absent from results produced before connection tracking
  protocol: string;
  client_ip: string; client_port: number | null;
  server_ip: string; server_port: number | null;
  packets: number; bytes: number;
  packets_client_to_server?: number; packets_server_to_client?: number;
  bytes_client_to_server: number; bytes_server_to_client: number;
  start_time?: number; end_time?: number;
  duration_seconds: number;
  // TCP only (null for other protocols)
  handshake_complete: boolean | null;
  syn_seen?: boolean | null; synack_seen?: boolean | null; fin_seen?: boolean | null;
  rst_seen: boolean | null;
  tcp_flags_seen?: string[] | null;
  state?: TcpState | null;
  resets?: number | null;
  retransmissions?: number | null; // heuristic indicator, not a verdict
  domain?: string | null; // inferred from DNS; null when no lookup preceded the connection
  domain_ambiguous?: boolean;
  // TCP handshake timing: set only for packets matched by sequence numbers (null otherwise, never estimated)
  handshake_status?: "completed" | "incomplete" | null;
  handshake_incomplete_reason?: "no_syn_seen" | "no_synack" | "no_final_ack" | "reset" | "simultaneous_open" | null;
  tcp_syn_timestamp?: number | null; tcp_syn_ack_timestamp?: number | null; tcp_ack_timestamp?: number | null;
  tcp_syn_ack_latency_ms?: number | null; tcp_ack_latency_ms?: number | null; tcp_handshake_time_ms?: number | null;
  tcp_syn_retransmissions?: number | null; tcp_syn_ack_retransmissions?: number | null;
}

export interface DomainHandshakeTime {
  domain: string; samples: number; avg_handshake_ms: number; min_handshake_ms: number; max_handshake_ms: number;
}

export interface DomainActivity {
  domain: string; resolved_ips: string[]; clients: string[]; first_seen: number; last_seen: number;
  dns_queries: number; dns_responses: number; connection_count: number; tcp_connection_count: number; udp_connection_count: number;
  total_bytes_sent: number; total_bytes_received: number; min_ttl: number | null; max_ttl: number | null;
  ambiguous_connection_count: number; shared_ips: string[]; server_ports: number[];
  packets_sent?: number; packets_received?: number; // absent from results produced before the web-activity dashboard
}
export interface DomainSummary {
  total_domains: number; reported_domains: number; domains_with_connections: number; attributed_connections: number;
  unattributed_connections: number; ambiguous_connections: number; dns_only_domains: number; encrypted_dns_flows: number;
  domains_not_tracked: number; notes: string[];
}
export interface DomainStatistics { domains: DomainActivity[]; summary: DomainSummary }

export type MeasurementConfidence = "HIGH" | "MEDIUM" | "LOW" | "UNAVAILABLE";

/** Latency of one connection. Handshake, RTT, TLS hello and HTTP response time are separate, never interchangeable. */
export interface PerformanceMetrics {
  connection_id: string; domain: string | null; protocol: string;
  application_protocol: "DNS" | "HTTP" | "TLS" | null; encrypted: boolean;
  dns_latency_ms: number | null; dns_lookups: number;
  tcp_handshake_ms: number | null; tls_server_hello_ms: number | null;
  min_rtt_ms: number | null; avg_rtt_ms: number | null; median_rtt_ms: number | null; p95_rtt_ms: number | null; max_rtt_ms: number | null;
  rtt_samples: number; rtt_basis: "client_to_server" | "server_to_client" | null;
  application_response_ms: number | null; application_response_samples: number; // cleartext HTTP only
  connection_duration_ms: number; measurement_confidence: MeasurementConfidence; notes: string[];
}
export interface DomainPerformance {
  domain: string; connections: number; dns_latency_ms: number | null; dns_lookups: number;
  tcp_handshake_ms: number | null; handshake_samples: number; avg_rtt_ms: number | null; p95_rtt_ms: number | null; rtt_samples: number;
  application_response_ms: number | null; application_response_samples: number; http_connections: number; encrypted_connections: number;
  measurement_confidence: MeasurementConfidence;
  max_rtt_ms?: number | null; retransmissions?: number; resets?: number; connections_reset?: number; tcp_packets?: number;
}
export interface PerformanceStatistics {
  summary: { tracked_connections: number; connections_with_rtt: number; http_responses_timed: number; encrypted_connections: number; dns_lookups_timed: number; notes: string[] };
  metrics: PerformanceMetrics[]; domains: DomainPerformance[];
}

export interface ConnectionSummary {
  total_connections: number;
  by_protocol: Record<string, number>;
  tcp_handshakes_complete: number;
  tcp_with_rst: number;
  by_state?: Record<string, number>;
  handshakes_timed?: number; handshakes_incomplete?: number;
  avg_handshake_ms?: number | null;
  handshake_by_domain?: DomainHandshakeTime[]; // slowest average first
}

export interface TimelinePoint {
  start_time: number; offset_seconds: number; interval_seconds: number;
  packets: number; bytes: number; packets_per_second: number;
}

export interface AnalysisResult {
  metadata: CaptureMetadata;
  packet_statistics: PacketStatistics;
  protocol_statistics: { distribution: ProtocolStat[]; layer_packet_counts: Record<string, number> };
  ip_statistics: {
    unique_source_ips: number; unique_destination_ips: number;
    top_sources: IpCount[]; top_destinations: IpCount[]; top_talkers: Talker[];
    conversations: Conversation[]; total_conversations: number;
  };
  port_statistics: {
    top_source_ports: PortCount[]; top_destination_ports: PortCount[];
    unique_source_ports: number; unique_destination_ports: number;
    destination_ports_per_source: SourcePortFanout[];
  };
  tcp_statistics: TcpStatistics;
  dns_statistics: DnsStatistics;
  connections: Connection[];
  connection_summary: ConnectionSummary;
  domain_statistics?: DomainStatistics; // absent from results produced before this feature
  performance_statistics?: PerformanceStatistics; // absent from results produced before latency analysis
  timeline: TimelinePoint[];
}

export interface ConfidenceFactor { name: string; score: number; weight: number; detail: string }

export interface Finding {
  id: string;
  type: string;
  severity: Severity;
  confidence: number;
  source_ip: string | null;
  destination_ip: string | null;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  reasoning: string[];
  caveats: string[];
  confidence_factors: ConfidenceFactor[];
  recommendation: string;
  detector: string;
  first_seen: number | null;
  last_seen: number | null;
}

export interface AnalysisBundle {
  job: JobStatus;
  analysis: AnalysisResult;
  findings: Finding[];
  detector_errors: Record<string, string>;
}

// ---- live capture (backend/app/models/live.py)
export type InterfaceKind = "wifi" | "ethernet" | "vpn" | "loopback" | "other";
export type LiveState = "stopped" | "capturing" | "permission_error" | "error";

export interface InterfaceInfo { name: string; description: string; kind: InterfaceKind; addresses: string[]; is_up: boolean | null }
export interface LiveError { code: string; message: string; hint: string | null }

export interface InvestigationResult {
  investigation_summary: string; finding_type: string; severity: Severity; confidence: number;
  evidence: string[]; interpretation: string; possible_explanations: string[];
  recommended_next_steps: string[]; additional_evidence_needed: string[]; limitations: string[];
}
export interface InvestigationReport { result: InvestigationResult; model: string; provider: string; notes: string[] }
export interface LiveInvestigation {
  status: "pending" | "completed" | "failed"; requested_at: number;
  report: InvestigationReport | null; error: LiveError | null;
}
export interface LiveFindingEvent {
  finding: Finding; first_detected_at: number; last_detected_at: number; detections: number; active: boolean;
  investigation: LiveInvestigation | null;
}
export interface LiveStatus {
  state: LiveState; interface: string | null; started_at: number | null; elapsed_seconds: number;
  packets_total: number; bytes_total: number; packets_per_second: number; bits_per_second: number;
  window_seconds: number; window_packets: number; window_truncated: boolean; last_analysis_at: number | null;
  protocols: ProtocolStat[]; top_talkers: Talker[]; top_ports: PortCount[];
  findings: LiveFindingEvent[]; capture: LiveCaptureFile | null; notice: string | null; auto_investigate: boolean; parse_errors: number; error: LiveError | null;
}
export interface StartLiveRequest { interface: string; auto_investigate: boolean; save?: boolean; format?: CaptureFormat }

// ---- reports (backend/app/models/report.py)
export type AiStatus = "completed" | "failed" | "not_run";
export interface ReportListItem {
  id: string; title: string; created_at: string; source_kind: "pcap" | "live"; capture_name: string;
  highest_severity: Severity | null; finding_count: number; total_packets: number; ai_status: AiStatus;
}
export interface ReportFinding {
  id: string; type: string; severity: Severity; confidence: number; title: string; description: string;
  source_ip: string | null; destination_ip: string | null; evidence: Record<string, unknown>;
  investigation_steps: string[]; caveats: string[]; recommendation: string;
  first_seen_iso: string | null; last_seen_iso: string | null; ai_assessment: InvestigationResult | null;
}
export interface ReportContent {
  schema_version: number; title: string; investigation_timestamp: string; app_version: string;
  capture: {
    source_kind: "pcap" | "live"; name: string; capture_format: string; size_bytes: number; sha256: string;
    packets: number; duration_seconds: number; first_packet_time_iso: string | null; last_packet_time_iso: string | null;
    interface: string | null; warnings: string[];
  };
  summary: {
    total_packets: number; total_bytes: number; duration_seconds: number; avg_packets_per_second: number | null;
    peak_packets_per_second: number | null; unique_source_ips: number; unique_destination_ips: number;
    finding_count: number; severity_counts: Record<string, number>; highest_severity: Severity | null; headline: string;
  };
  protocols: ProtocolStat[]; top_talkers: Talker[]; top_ports: PortCount[]; domains?: { domain: string; connections: number; bytes_sent: number; bytes_received: number }[]; findings: ReportFinding[];
  ai_investigation: { status: AiStatus; provider: string | null; model: string | null; result: InvestigationResult | null; notes: string[]; message: string | null };
  recommended_actions: { action: string; priority: Severity | null; source: "detector" | "ai"; related_finding: string | null }[];
  limitations: string[]; analyst_notes: string | null;
}
export interface SavedReport { id: string; content: ReportContent }
export interface CreateReportRequest { source: "analysis" | "live"; analysis_id?: string; title?: string; notes?: string; run_ai: boolean }
export type ExportFormat = "html" | "md" | "json";
export interface ExportResult { path: string; filename: string; format: ExportFormat }

// ---- Domain / Web Activity dashboard (GET /api/analyses/{id}/web-activity). All values are computed by the backend.
export type DomainHealth = "good" | "fair" | "poor" | "unknown";

export interface WebDomainRow {
  domain: string; connections: number; total_bytes: number; bytes_sent: number; bytes_received: number;
  first_seen: number; last_seen: number;
  dns_latency_ms: number | null; tcp_handshake_ms: number | null; avg_rtt_ms: number | null; p95_rtt_ms: number | null; rtt_samples: number;
  health: DomainHealth; health_reasons: string[];
  anomalies?: number; // performance anomalies vs the domain's own history in this capture
}
export interface WebActivityList {
  summary: { total_domains: number; domains_with_connections: number; health_counts: Record<string, number>; notes: string[] };
  total_matching: number; offset: number; limit: number; domains: WebDomainRow[];
}
export type WebSort = "traffic" | "connections" | "dns" | "handshake" | "rtt" | "p95" | "health" | "recent" | "name";
export interface WebActivityQuery { search?: string; sort?: WebSort; health?: DomainHealth; includeDnsOnly?: boolean; limit?: number; offset?: number }

export interface DomainConnection {
  id: string; protocol: string; application_protocol: string | null;
  client_ip: string; client_port: number | null; server_ip: string; server_port: number | null;
  state: string | null; start_time: number; duration_seconds: number; bytes: number; packets: number;
  handshake_ms: number | null; avg_rtt_ms: number | null; p95_rtt_ms: number | null; application_response_ms: number | null;
  retransmissions: number | null; resets: number | null; measurement_confidence: MeasurementConfidence;
}
export interface DomainSeries {
  bin_seconds: number;
  rtt: { t: number; avg_rtt_ms: number | null; p95_rtt_ms: number | null; response_ms: number | null }[];
  handshake: { t: number; handshake_ms: number }[];
  traffic: { t: number; bytes_sent: number; bytes_received: number }[];
}
export interface WebDomainDetail {
  domain: string; health: DomainHealth; health_reasons: string[];
  overview: DomainActivity; performance: DomainPerformance | null;
  connections: DomainConnection[]; connections_total: number; series: DomainSeries; notes: string[];
}

// ---- Historical baselines and performance anomalies (stored locally; GET /api/analyses/{id}/anomalies etc.)
export type BaselineMetric = "tcp_handshake_ms" | "avg_rtt_ms" | "p95_rtt_ms" | "dns_latency_ms" | "response_ms" | "retransmission_rate" | "failure_rate" | "connection_attempts_per_s";
export interface MetricBaseline { observations: number; excluded_outliers: number; mean: number; std: number; median: number; p95: number; min: number; max: number }
export interface MetricComparison {
  metric: BaselineMetric; label: string; unit: "ms" | "%";
  status: "normal" | "anomalous" | "insufficient_baseline" | "insufficient_current" | "no_data";
  current: number | null; current_samples: number; baseline: MetricBaseline | null;
  relative_change: number | null; z_score: number | null; note: string | null;
}
export interface PerformanceAnomaly {
  id: string; domain: string; metric: BaselineMetric; label: string; unit: "ms" | "%" | "/s";
  baseline: number; baseline_mean: number; baseline_std: number; baseline_observations: number;
  current_value: number; deviation: number; absolute_change: number; z_score: number;
  severity: Severity; confidence: number; confidence_label: "Low" | "Medium" | "High";
  first_seen: number; last_seen: number; observations_in_run: number; evidence: string[]; caveats: string[];
  basis?: "history" | "capture"; // "capture": a time window against the rest of the same capture (correlation engine)
  scope_ips?: string[]; ratio?: number | null; // current / baseline
}
export interface HistoryPoint {
  t: number; source_name: string; current: boolean;
  tcp_handshake_ms: number | null; avg_rtt_ms: number | null; p95_rtt_ms: number | null; dns_latency_ms: number | null;
  response_ms: number | null; retransmission_rate: number | null; failure_rate: number | null; // rates are fractions
}
export interface AnomalyList { history_enabled: boolean; domains_evaluated: number; domains_with_baseline: number; anomalies: PerformanceAnomaly[]; notes: string[] }
export interface DomainBaselineView {
  domain: string; history_enabled: boolean; prior_observations: number;
  comparisons: MetricComparison[]; anomalies: PerformanceAnomaly[]; history: HistoryPoint[]; notes: string[];
}
export interface HistoryStatus { enabled: boolean; sources: number; observations: number; domains: number; oldest: number | null; newest: number | null; notes: string[] }

// ---- Correlation of security findings with performance changes ("potentially related", never "caused by")
export type CorrelationType = "SYN_FLOOD_HANDSHAKE_LATENCY" | "PORT_SCAN_CONNECTION_ATTEMPTS" | "DNS_ANOMALY_DNS_LATENCY"
  | "PACKET_LOSS_RTT" | "RETRANSMISSIONS_RESPONSE_TIME" | "RESETS_FAILED_CONNECTIONS";
export type TemporalRelation = "overlapping" | "performance_follows_finding" | "performance_precedes_finding" | "same_connections" | "capture_level";
export interface Correlation {
  id: string; type: CorrelationType; relationship: "Potentially related";
  finding_id: string; finding_type: string; finding_title: string; finding_severity: Severity; finding_confidence: number;
  finding_first_seen: number | null; finding_last_seen: number | null;
  performance: PerformanceAnomaly; headline: string; summary: string;
  time_difference_seconds: number; temporal_relation: TemporalRelation;
  shared_ips: string[]; shared_domains: string[]; scope: "host" | "network";
  evidence: string[]; caveats: string[]; confidence: number; confidence_label: "Low" | "Medium" | "High";
}
export interface CorrelationList {
  finding_id: string | null; correlations: Correlation[]; not_evaluated: string[]; no_related_change: string[]; flow_data_thinned: boolean; notes: string[];
}

// ---- Local process <-> connection mapping. Comes from the operating system's socket table at the moment a snapshot was
// taken (explicitly requested), never from the packets.
export interface ProcessSourceStatus {
  platform: string; supported: boolean; mechanism: string | null; permission_note: string;
  snapshots: number; first_snapshot_at: number | null; last_snapshot_at: number | null;
  watching: boolean; watch_interval_seconds: number | null; last_error: string | null; notes: string[];
}
export interface ProcessSnapshotSummary { timestamp: number; platform: string; sockets: number; processes: number; applications: number; truncated: boolean; notes: string[] }
export interface ApplicationUsage {
  name: string; kind: "application" | "process"; process_names: string[]; pids: number[]; connections: number; confidence_counts: Record<string, number>;
}
export interface DomainApplications {
  domain: string; status: "available" | "partial" | "unsupported" | "no_snapshots" | "no_overlap" | "no_matches"; message: string;
  applications: ApplicationUsage[]; connections_considered: number; connections_matched: number; connections_unmatched: number;
  snapshots_used: number; permission_note: string; source_note: string;
}

// ---- Network map (GET /api/analyses/{id}/network-map): built and filtered by the backend, drawn here.
export type MapState = "healthy" | "degraded" | "suspicious" | "unknown";
export type MapNodeKind = "local" | "application" | "domain" | "group" | "ip" | "port" | "other";
export interface MapNode {
  id: string; kind: MapNodeKind; label: string; sublabel: string | null; tier: number; state: MapState; state_reasons: string[];
  connections: number; bytes: number; latency_ms: number | null; latency_kind: "rtt" | "handshake" | null;
  domain: string | null; ip: string | null; port: number | null; protocol: string | null;
  finding_ids: string[]; connection_ids: string[]; members: number | null; detail_available: boolean;
}
export interface MapEdge {
  id: string; source: string; target: string; connections: number; bytes: number; protocol: string | null; ports: number[];
  latency_ms: number | null; latency_kind: "rtt" | "handshake" | null; state: MapState; connection_ids: string[];
}
export interface MapConnection {
  id: string; protocol: string; local_ip: string; local_port: number | null; remote_ip: string; remote_port: number | null; domain: string | null;
  application: string | null; process_name: string | null; start_time: number; end_time: number; duration_seconds: number; bytes: number; packets: number;
  state: string | null; handshake_ms: number | null; rtt_ms: number | null; retransmissions: number | null; health: MapState; health_reasons: string[];
}
export interface MapFinding { id: string; type: string; severity: Severity; confidence: number; title: string; source_ip: string | null; destination_ip: string | null }
export interface NetworkMapData {
  nodes: MapNode[]; edges: MapEdge[]; connections: MapConnection[]; findings: MapFinding[];
  local: string; local_hosts: { ip: string; connections: number }[];
  capture_start: number | null; capture_end: number | null; applied_start: number | null; applied_end: number | null;
  total_connections: number; shown_connections: number; hidden: { destinations: number; connections: number; bytes: number };
  applications_status: string | null; notes: string[];
}
export interface NetworkMapQuery {
  local?: string; search?: string; protocol?: "TCP" | "UDP"; health?: MapState; start?: number; end?: number; maxNodes?: number; includeApplications?: boolean;
}

// ---- Investigate Network (POST /api/analyses/{id}/investigate-network). Every number comes from `NetworkMetric`s PacketMind
// measured locally; the model's report can only cite them by id. There is deliberately no model reasoning in this payload.
export type NetworkHealth = "Healthy" | "Degraded" | "Poor" | "Unknown";
export type ConfidenceLevel = "High" | "Medium" | "Low";
export type NetworkMetricStatus = "ok" | "elevated" | "high" | "info" | "unmeasured";
export type NetworkMetricCategory =
  | "traffic" | "dns" | "handshake" | "rtt" | "retransmissions" | "resets" | "failures" | "response" | "domains" | "anomalies" | "findings" | "baseline";
export interface NetworkMetric {
  id: string; category: NetworkMetricCategory; label: string; unit: "ms" | "%" | "count" | "packets" | "bytes" | "seconds" | "packets/s";
  current: number | null; normal: number | null; change: number | null; status: NetworkMetricStatus; samples: number; note: string | null;
}
export interface LocalAssessment {
  health: NetworkHealth; reasons: string[]; strength: ConfidenceLevel; strength_reason: string; earlier_captures: number; metrics: NetworkMetric[];
}
export interface NetworkProblem { title: string; detail: string; evidence_ids: string[] }
export interface NetworkEvidenceItem { evidence_id: string; statement: string }
export interface NetworkHealthReport {
  overall_health: NetworkHealth; summary: string; main_issue: string; top_problems: NetworkProblem[]; evidence: NetworkEvidenceItem[];
  potential_explanations: string[]; recommended_next_steps: string[]; confidence: ConfidenceLevel; limitations: string[];
}
export interface NetworkInvestigation {
  status: "completed" | "local_only" | "ai_failed"; generated_at: string; local: LocalAssessment; report: NetworkHealthReport | null;
  evidence: NetworkMetric[]; health: NetworkHealth; health_note: string | null; confidence: ConfidenceLevel;
  ai: { requested: boolean; provider: string | null; model: string | null; error_code: string | null; error_message: string | null };
  notes: string[]; disclosure: string;
}

// ---- Network Intelligence Dashboard (GET /api/analyses/{id}/dashboard, GET /api/live/dashboard). Aggregated and capped by the
// backend; the UI only renders it. The range is measured back from the last packet of the capture.
export type DashboardRange = "5m" | "15m" | "1h" | "all";
export const DASHBOARD_RANGES: { key: DashboardRange; label: string }[] = [
  { key: "5m", label: "Last 5 minutes" }, { key: "15m", label: "Last 15 minutes" }, { key: "1h", label: "Last hour" }, { key: "all", label: "Capture duration" },
];
export interface DashboardWindow {
  key: DashboardRange; label: string; start: number | null; end: number | null; capture_start: number | null; capture_end: number | null;
  covers_whole_capture: boolean; note: string | null;
}
export interface HealthScoreView {
  score: number | null; label: "Healthy" | "Degraded" | "Poor" | "Unknown"; deductions: { reason: string; points: number }[]; basis: string;
}
export interface DashboardKpis {
  active_connections: number; connections_in_window: number; domains_contacted: number; total_bytes: number; total_packets: number;
  avg_handshake_ms: number | null; handshake_samples: number; avg_rtt_ms: number | null; rtt_samples: number; dns_latency_ms: number | null; dns_samples: number;
  retransmission_rate: number | null; tcp_packets: number; findings: number; anomalies: number;
}
export interface SlowDomainRow {
  domain: string; avg_rtt_ms: number | null; p95_rtt_ms: number | null; tcp_handshake_ms: number | null; rtt_samples: number; status: DomainHealth; reasons: string[];
}
export interface DashboardFinding {
  id: string; type: string; title: string; severity: Severity; confidence: number; evidence: string[];
  source_ip: string | null; destination_ip: string | null; first_seen: number | null; last_seen: number | null;
}
export interface DashboardConnection {
  id: string; protocol: string; client_ip: string; client_port: number | null; server_ip: string; server_port: number | null; domain: string | null;
  state: string | null; bytes: number; start_time: number; end_time: number; handshake_ms: number | null; retransmissions: number | null;
  finding_ids: string[]; reasons: string[];
}
export interface ActivityItem { time: number; kind: "finding" | "anomaly" | "domain" | "connection"; text: string; severity: Severity | null; ref: string | null }
export interface DashboardData {
  source: "capture" | "live"; empty: boolean; window: DashboardWindow; health: HealthScoreView; kpis: DashboardKpis;
  top_domains: WebDomainRow[]; slowest_domains: SlowDomainRow[]; findings: DashboardFinding[]; anomalies: PerformanceAnomaly[];
  suspicious_connections: DashboardConnection[]; active_connections: DashboardConnection[]; recent_activity: ActivityItem[];
  timeline: { start_time: number; interval_seconds: number; packets: number; bytes: number }[];
  markers: { time: number; kind: "finding" | "anomaly"; label: string; severity: Severity | null }[]; notes: string[];
}

// ---- Capture library (backend/app/models/capture.py). Names only: the backend never exposes filesystem paths.
export type CaptureFormat = "pcap" | "pcapng";
export type CaptureStatus = "CAPTURING" | "COMPLETED" | "ANALYZING" | "ANALYZED" | "FAILED";
export type CaptureSource = "LIVE_CAPTURE" | "UPLOADED_PCAP";
export interface LiveCaptureFile { id: string; filename: string; format: CaptureFormat; status: CaptureStatus; packets: number; bytes: number; file_size: number; error: string | null; rotated?: number }
export interface CaptureSummary { protocols: { protocol: string; packets: number; percent: number }[]; domains: number; findings: number; connections: number }
export interface CaptureSession {
  id: string; filename: string; original_filename: string; source_type: CaptureSource; capture_format: CaptureFormat; interface: string | null;
  start_time: number | null; end_time: number | null; duration_seconds: number | null; packet_count: number; byte_count: number; file_size: number;
  status: CaptureStatus; error_message: string | null; created_at: string; analyzed_at: string | null; summary: CaptureSummary | null;
}
export interface CaptureExportResult { filename: string; directory: string; size_bytes: number }

// ---- Settings (backend/app/models/app_settings.py). One typed document; the backend validates and applies it.
export type Sensitivity = "low" | "medium" | "high";
export interface DetectorBase { enabled: boolean; min_confidence: number }
export interface AppSettings {
  general: { theme: "system" | "light" | "dark"; time_format: "utc" | "local" | "local_24h" };
  capture: { default_interface: string; format: CaptureFormat; max_size_mb: number; max_duration_minutes: number; auto_save: boolean; auto_analyze: boolean;
    rotation_enabled: boolean; rotation_size_mb: number; rotation_minutes: number };
  network: { auto_select_interface: boolean; show_inactive_interfaces: boolean };
  analysis: { dns: boolean; tcp: boolean; connection_tracking: boolean; domain_tracking: boolean; rtt: boolean; handshake: boolean; performance: boolean;
    depth: "basic" | "standard" | "deep"; max_packets: number };
  detection: { sensitivity: Sensitivity;
    port_scan: DetectorBase & { min_ports: number }; syn_flood: DetectorBase & { min_syn_packets: number; min_peak_syn_per_second: number };
    dns: DetectorBase & { query_rate_per_second: number; nxdomain_ratio: number }; arp: DetectorBase & { min_macs_per_ip: number };
    tcp: DetectorBase & { retransmission_rate: number; reset_ratio: number }; connection: DetectorBase & { min_upload_mb: number } };
  performance: { track_dns_latency: boolean; track_retransmissions: boolean; track_failures: boolean; baseline_enabled: boolean; baseline_window: number;
    baseline_min_samples: number; anomaly_sensitivity: Sensitivity; slow_dns_ms: number; slow_handshake_ms: number; slow_rtt_ms: number };
  domains: { track_history: boolean; retention_days: number; hide_localhost: boolean; hide_private_ips: boolean; hide_local_domains: boolean };
  privacy: { store_payloads: boolean; store_dns_queries: boolean; anonymize_ips: boolean; clear_temp_on_exit: boolean; data_retention_days: number };
  ai: { model: string; timeout_seconds: number | null; auto_critical: boolean; auto_high: boolean; auto_medium: boolean; auto_low: boolean; auto_min_confidence: number };
  ai_usage: { daily_limit: number; max_auto_per_day: number; cache_enabled: boolean; cache_minutes: number };
  notifications: { enabled: boolean; critical_finding: boolean; high_finding: boolean; medium_finding: boolean; performance_anomaly: boolean; capture_completed: boolean;
    analysis_completed: boolean; ai_completed: boolean; capture_error: boolean; analysis_error: boolean; sound: boolean; only_in_background: boolean };
  storage: { max_capture_storage_gb: number; auto_delete_old: boolean; capture_retention_days: number; keep_analyzed: boolean; keep_failed: boolean };
  diagnostics: { log_level: "error" | "warning" | "info" | "debug"; save_logs: boolean; max_log_mb: number; rotation: boolean };
  security: { confirm_delete_captures: boolean; confirm_clear_history: boolean; allow_ai: boolean };
  advanced: { backend_timeout_seconds: number; max_concurrent_analyses: number; debug_mode: boolean; show_internal_ids: boolean };
}
export type SettingsSection = keyof AppSettings;
export interface FieldConstraint { type?: "integer" | "number"; min?: number; exclusive_min?: number; max?: number; exclusive_max?: number; max_length?: number }
export interface UnavailableSetting { key: string; label: string; reason: string }
export interface AiKeyStatus {
  configured: boolean; source: "keychain" | "environment" | "none"; secure_storage_available: boolean; secure_storage: string | null; model: string;
  last_test: { ok: boolean; message: string; code: string | null; model: string | null; latency_ms: number | null; at: string } | null;
}
export interface SettingsPayload {
  settings: AppSettings; defaults: AppSettings; constraints: Record<string, FieldConstraint>; unavailable: Record<string, UnavailableSetting[]>;
  restart_required: string[]; sections: string[]; version: number; ai: AiKeyStatus;
  ai_permissions: { allowed: string[]; never: string[] }; ai_data_policy: { item: string; policy: string }[];
}
export interface AiUsageToday { day: string; requests: number; cached: number; automatic: number; blocked: number; daily_limit: number; max_automatic_per_day: number; cache_enabled: boolean; note: string }
export interface StorageInfo { usage: { captures: number; reports: number; database: number; logs: number; total: number; temporary_uploads: number };
  locations: Record<string, string | null>; limits: { max_capture_storage_gb: number }; note: string }
export interface CleanupPreview { dry_run: boolean; candidates: { id: string; name: string; size: number; reason: string }[]; deleted: number; freed_bytes: number; would_free_bytes: number }
export interface DatabaseInfo { type: string; path: string | null; size_bytes: number; schema_version: number; captures: number; reports: number; findings_in_reports: number;
  history_domains_observations: number; retention_days: number; notes: string[] }
export interface AboutInfo {
  app: string; tagline: string; backend_version: string; python: string; analysis_engine: string; database_engine: string; ai_provider: string; os: string; architecture: string;
  capture: { library_available: boolean; privileges: "likely" | "unlikely" | "unknown"; note: string }; tshark: boolean; ai: AiKeyStatus;
}
export interface SavedFile { filename: string; directory: string; size_bytes?: number }
