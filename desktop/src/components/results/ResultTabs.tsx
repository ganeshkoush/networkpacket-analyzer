import { useState, type ReactNode } from "react";
import type { AnalysisResult } from "../../api/types";
import { BarList } from "../charts/BarList";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { ConnectionsTab } from "./ConnectionsTab";
import { DomainsTab } from "./DomainsTab";
import { PerformanceTab } from "./PerformanceTab";
import { formatBytes, formatDuration, formatNumber, formatPercent, formatTime } from "../../lib/format";

const TABS = ["Summary", "Hosts", "Domains", "Ports", "TCP", "DNS", "Connections", "Performance"] as const;
type Tab = (typeof TABS)[number];

function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
      {rows.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-all font-mono text-ink">{v}</dd></div>))}
    </dl>
  );
}

export function ResultTabs({ a }: { a: AnalysisResult }) {
  const [tab, setTab] = useState<Tab>("Summary");
  return (
    <div>
      <div role="tablist" aria-label="Analysis results" className="mb-4 flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button key={t} role="tab" type="button" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 py-2 text-[13.5px] ${tab === t ? "border-accent text-ink" : "border-transparent text-ink-2 hover:text-ink"}`}>{t}</button>
        ))}
      </div>
      <div role="tabpanel" className="space-y-4">
        {tab === "Summary" && <Summary a={a} />}
        {tab === "Hosts" && <Hosts a={a} />}
        {tab === "Domains" && <DomainsTab stats={a.domain_statistics} />}
        {tab === "Ports" && <Ports a={a} />}
        {tab === "TCP" && <Tcp a={a} />}
        {tab === "DNS" && <Dns a={a} />}
        {tab === "Connections" && <ConnectionsTab connections={a.connections} summary={a.connection_summary} />}
        {tab === "Performance" && <PerformanceTab stats={a.performance_statistics} connections={a.connections} />}
      </div>
    </div>
  );
}

function Summary({ a }: { a: AnalysisResult }) {
  const m = a.metadata, p = a.packet_statistics;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Capture">
        <KV rows={[
          ["File", m.file_name], ["Format", m.capture_format], ["File size", formatBytes(m.file_size_bytes)], ["SHA-256", m.sha256],
          ["First packet", formatTime(m.first_packet_time)], ["Last packet", formatTime(m.last_packet_time)],
          ["Duration", formatDuration(m.duration_seconds)], ["Analysis time", formatDuration(m.analysis_seconds)],
        ]} />
      </Card>
      <Card title="Packets">
        <KV rows={[
          ["Packets", formatNumber(p.total_packets)], ["Bytes", `${formatNumber(p.total_bytes)} (${formatBytes(p.total_bytes)})`],
          ["Size min / mean / max", `${p.min_packet_size ?? "–"} / ${p.mean_packet_size ?? "–"} / ${p.max_packet_size ?? "–"} B`],
          ["Average rate", p.avg_packets_per_second != null ? `${p.avg_packets_per_second} pkt/s` : "–"],
          ["Peak rate", p.peak_packets_per_second != null ? `${formatNumber(p.peak_packets_per_second)} pkt/s` : "–"],
          ["Average throughput", p.avg_bits_per_second != null ? `${formatBytes(p.avg_bits_per_second / 8)}/s` : "–"],
          ["Malformed packets", formatNumber(m.malformed_packets)], ["Snap-length truncated", formatNumber(m.snaplen_truncated_packets)],
        ]} />
      </Card>
      <Card title="Packet size distribution" className="lg:col-span-2">
        <BarList ariaLabel="Packet size distribution" items={p.size_distribution.map((b) => ({ key: b.label, label: <span className="font-mono">{b.label} B</span>, value: b.packets, valueLabel: formatNumber(b.packets) }))} />
      </Card>
    </div>
  );
}

function Hosts({ a }: { a: AnalysisResult }) {
  return (
    <>
      <Card title="Top talkers" subtitle="Ranked by total bytes" padded={false}>
        <DataTable rowKey={(r) => r.ip} caption="Top talkers" rows={a.ip_statistics.top_talkers.slice(0, 15)} empty="No IP traffic."
          columns={[
            { header: "Host", cell: (r) => <Mono>{r.ip}</Mono> },
            { header: "Scope", cell: (r) => <span className="text-ink-2">{r.is_private ? "private" : "public"}</span> },
            { header: "Packets sent", align: "right", cell: (r) => formatNumber(r.packets_sent) },
            { header: "Packets recv", align: "right", cell: (r) => formatNumber(r.packets_received) },
            { header: "Bytes sent", align: "right", cell: (r) => formatBytes(r.bytes_sent) },
            { header: "Bytes recv", align: "right", cell: (r) => formatBytes(r.bytes_received) },
          ]} />
      </Card>
      <Card title="Conversations" subtitle={`${formatNumber(a.ip_statistics.total_conversations)} total · top 15 by bytes`} padded={false}>
        <DataTable rowKey={(r) => `${r.ip_a}-${r.ip_b}`} caption="Conversations" rows={a.ip_statistics.conversations.slice(0, 15)} empty="No conversations."
          columns={[
            { header: "Endpoint A", cell: (r) => <Mono>{r.ip_a}</Mono> },
            { header: "Endpoint B", cell: (r) => <Mono>{r.ip_b}</Mono> },
            { header: "Packets", align: "right", cell: (r) => `${formatNumber(r.packets)} (${formatNumber(r.packets_a_to_b)} / ${formatNumber(r.packets_b_to_a)})` },
            { header: "Bytes", align: "right", cell: (r) => formatBytes(r.bytes) },
          ]} />
      </Card>
    </>
  );
}

function Ports({ a }: { a: AnalysisResult }) {
  const p = a.port_statistics;
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Destination ports" subtitle={`${formatNumber(p.unique_destination_ports)} distinct`}>
          <BarList ariaLabel="Destination ports" empty="No TCP/UDP traffic." items={p.top_destination_ports.slice(0, 10).map((x) => ({
            key: `${x.protocol}${x.port}`, value: x.packets, valueLabel: formatNumber(x.packets),
            label: <span><span className="font-mono">{x.port}</span> <span className="text-ink-3">{x.protocol}{x.service_hint ? ` · ${x.service_hint}` : ""}</span></span> }))} />
        </Card>
        <Card title="Source ports" subtitle={`${formatNumber(p.unique_source_ports)} distinct`}>
          <BarList ariaLabel="Source ports" empty="No TCP/UDP traffic." items={p.top_source_ports.slice(0, 10).map((x) => ({
            key: `${x.protocol}${x.port}`, value: x.packets, valueLabel: formatNumber(x.packets),
            label: <span><span className="font-mono">{x.port}</span> <span className="text-ink-3">{x.protocol}{x.service_hint ? ` · ${x.service_hint}` : ""}</span></span> }))} />
        </Card>
      </div>
      <Card title="Distinct destination ports per source" subtitle="Many ports from one source can indicate scanning — see Findings" padded={false}>
        <DataTable rowKey={(r) => r.source_ip} caption="Destination ports per source" rows={p.destination_ports_per_source.slice(0, 15)} empty="No TCP/UDP traffic."
          columns={[
            { header: "Source", cell: (r) => <Mono>{r.source_ip}</Mono> },
            { header: "Distinct dst ports", align: "right", cell: (r) => formatNumber(r.unique_destination_ports) },
            { header: "Packets", align: "right", cell: (r) => formatNumber(r.packets) },
            { header: "Lowest ports", cell: (r) => <Mono className="text-ink-2">{r.sample_ports.slice(0, 8).join(", ")}{r.sample_ports.length > 8 ? " …" : ""}</Mono> },
          ]} />
      </Card>
    </>
  );
}

function Tcp({ a }: { a: AnalysisResult }) {
  const t = a.tcp_statistics, r = t.retransmissions;
  if (t.total_packets === 0) return <Card><p className="text-sm text-ink-3">No TCP traffic in this capture.</p></Card>;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Handshake & flags">
        <KV rows={[
          ["TCP packets", formatNumber(t.total_packets)], ["SYN", formatNumber(t.syn_packets)], ["SYN-ACK", formatNumber(t.syn_ack_packets)],
          ["ACK only", formatNumber(t.ack_only_packets)], ["FIN", formatNumber(t.fin_packets)], ["RST", formatNumber(t.rst_packets)],
          ["SYN : SYN-ACK", t.syn_to_syn_ack_ratio != null ? t.syn_to_syn_ack_ratio.toString() : "–"],
        ]} />
      </Card>
      <Card title="Retransmission indicators" subtitle="Heuristic: repeated sequence numbers">
        <KV rows={[
          ["Retransmitted segments", `${formatNumber(r.retransmitted_segments)} of ${formatNumber(r.sequence_bearing_segments)}`],
          ["Rate", formatPercent(r.retransmission_rate)], ["SYN retransmissions", formatNumber(r.syn_retransmissions)], ["Duplicate ACKs", formatNumber(r.duplicate_acks)],
        ]} />
      </Card>
      <Card title="Flag combinations" className="lg:col-span-2" padded={false}>
        <DataTable rowKey={(r) => r.flags} caption="TCP flag combinations" rows={t.flag_combinations.slice(0, 12)}
          columns={[{ header: "Flags", cell: (r) => <Mono>{r.flags}</Mono> }, { header: "Packets", align: "right", cell: (r) => formatNumber(r.packets) }]} />
      </Card>
    </div>
  );
}

function Dns({ a }: { a: AnalysisResult }) {
  const d = a.dns_statistics;
  if (d.total_queries === 0 && d.total_responses === 0) return <Card><p className="text-sm text-ink-3">No DNS traffic in this capture.</p></Card>;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Summary">
        <KV rows={[
          ["Queries", formatNumber(d.total_queries)], ["Responses", formatNumber(d.total_responses)], ["Unique names", formatNumber(d.unique_domains)],
          ["NXDOMAIN", formatNumber(d.nxdomain_responses)], ["Unanswered queries", formatNumber(d.unanswered_queries)],
          ["Response time", d.avg_response_ms != null ? `${d.avg_response_ms} ms avg · ${d.max_response_ms} ms max` : "–"],
          ["Query types", Object.entries(d.query_types).map(([k, v]) => `${k} ${v}`).join(", ") || "–"],
          ["Response codes", Object.entries(d.response_codes).map(([k, v]) => `${k} ${v}`).join(", ") || "–"],
        ]} />
      </Card>
      <Card title="Top queried names">
        <BarList ariaLabel="Top queried names" items={d.top_domains.slice(0, 10).map((x) => ({ key: x.name, label: <Mono>{x.name}</Mono>, value: x.count, valueLabel: formatNumber(x.count) }))} />
      </Card>
      <Card title="Top DNS clients">
        <BarList ariaLabel="Top DNS clients" items={d.top_clients.slice(0, 8).map((x) => ({ key: x.name, label: <Mono>{x.name}</Mono>, value: x.count, valueLabel: formatNumber(x.count) }))} />
      </Card>
      <Card title="DNS servers">
        <BarList ariaLabel="DNS servers" items={d.top_servers.slice(0, 8).map((x) => ({ key: x.name, label: <Mono>{x.name}</Mono>, value: x.count, valueLabel: formatNumber(x.count) }))} />
      </Card>
    </div>
  );
}
