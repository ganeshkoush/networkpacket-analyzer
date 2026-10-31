import { useMemo, useState } from "react";
import type { Connection, DomainPerformance, MeasurementConfidence, PerformanceMetrics, PerformanceStatistics } from "../../api/types";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { Notice } from "../ui/feedback";
import { endpoint, formatMs, formatNumber } from "../../lib/format";

export type PerformanceSort = "connections" | "rtt" | "handshake" | "dns" | "response" | "name";
const SORTS: { value: PerformanceSort; label: string }[] = [
  { value: "connections", label: "Connections" }, { value: "rtt", label: "Average RTT" }, { value: "handshake", label: "TCP handshake" },
  { value: "dns", label: "DNS" }, { value: "response", label: "Response time" }, { value: "name", label: "Domain name" },
];
const KEY: Record<Exclude<PerformanceSort, "connections" | "name">, (d: DomainPerformance) => number | null> = {
  rtt: (d) => d.avg_rtt_ms, handshake: (d) => d.tcp_handshake_ms, dns: (d) => d.dns_latency_ms, response: (d) => d.application_response_ms,
};

/** Same ordering as GET /api/analyses/{id}/performance: slowest first, domains without that measurement last. */
export function filterAndSortDomains(domains: DomainPerformance[], search: string, sort: PerformanceSort): DomainPerformance[] {
  const needle = search.trim().toLowerCase();
  const rows = needle ? domains.filter((d) => d.domain.includes(needle)) : [...domains];
  if (sort === "name") return rows.sort((a, b) => a.domain.localeCompare(b.domain));
  if (sort === "connections") return rows.sort((a, b) => b.connections - a.connections || a.domain.localeCompare(b.domain));
  const key = KEY[sort];
  return rows.sort((a, b) => {
    const x = key(a), y = key(b);
    if ((x === null) !== (y === null)) return x === null ? 1 : -1;
    return (y ?? 0) - (x ?? 0) || a.domain.localeCompare(b.domain);
  });
}

/** "Response Time" is only ever a visible cleartext-HTTP measurement. Handshake time is never shown here. */
function responseCell(ms: number | null, encrypted: boolean) {
  if (ms !== null) return formatMs(ms);
  return encrypted ? <span className="text-ink-3" title="HTTPS request/response timing is encrypted">not visible (HTTPS)</span> : <span className="text-ink-3">–</span>;
}

const CONF_STYLE: Record<MeasurementConfidence, string> = {
  HIGH: "text-ink", MEDIUM: "text-ink-2", LOW: "text-sev-medium", UNAVAILABLE: "text-ink-3",
};
const Confidence = ({ level }: { level: MeasurementConfidence }) => (
  <span className={`text-xs uppercase tracking-wide ${CONF_STYLE[level]}`} title="Confidence in the round-trip estimate">{level.toLowerCase()}</span>
);
const input = "rounded-md border border-line bg-bg px-2.5 py-1 text-sm text-ink placeholder:text-ink-3";

export function PerformanceTab({ stats, connections }: { stats: PerformanceStatistics | undefined; connections: Connection[] }) {
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<PerformanceSort>("connections");
  const [openId, setOpenId] = useState<string | null>(null);
  const domains = useMemo(() => filterAndSortDomains(stats?.domains ?? [], search, sort), [stats, search, sort]);
  const byId = useMemo(() => new Map(connections.map((c) => [c.id, c])), [connections]);

  if (!stats || stats.summary.tracked_connections === 0) {
    return <Card><p className="text-sm text-ink-3">No latency measurements: this capture has no tracked connections (or was analysed before latency analysis existed).</p></Card>;
  }
  const s = stats.summary;
  const selected = stats.metrics.find((m) => m.connection_id === openId);
  const destination = (m: PerformanceMetrics) => {
    const c = byId.get(m.connection_id);
    return m.domain ?? (c ? endpoint(c.server_ip, c.server_port) : m.connection_id);
  };

  return (
    <>
      {s.notes.map((n) => <Notice key={n} tone="info">{n}</Notice>)}
      <Card padded={false} title="Performance by domain"
        subtitle={`${formatNumber(s.connections_with_rtt)} of ${formatNumber(s.tracked_connections)} connections have an RTT · ${formatNumber(s.http_responses_timed)} cleartext HTTP responses timed · ${formatNumber(s.encrypted_connections)} encrypted · ${formatNumber(s.dns_lookups_timed)} DNS lookups timed · domains are inferred from DNS`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input type="search" aria-label="Search performance domains" placeholder="Search domain" value={search} onChange={(e) => setSearch(e.target.value)} className={`w-44 ${input}`} />
            <select aria-label="Sort performance" value={sort} onChange={(e) => setSort(e.target.value as PerformanceSort)} className={input}>
              {SORTS.map((o) => <option key={o.value} value={o.value}>Sort: {o.label}</option>)}
            </select>
          </div>
        }>
        <DataTable rowKey={(d) => d.domain} caption="Performance by domain" rows={domains.slice(0, 200)}
          empty={search ? `No domain matches “${search}”.` : "No connection could be attributed to a domain (no matching DNS lookups were captured)."}
          columns={[
            { header: "Domain", cell: (d) => <Mono>{d.domain}</Mono> },
            { header: "DNS", align: "right", cell: (d) => formatMs(d.dns_latency_ms) },
            { header: "TCP Handshake", align: "right", cell: (d) => formatMs(d.tcp_handshake_ms) },
            { header: "Avg RTT", align: "right", cell: (d) => formatMs(d.avg_rtt_ms) },
            { header: "P95 RTT", align: "right", cell: (d) => formatMs(d.p95_rtt_ms) },
            { header: "Response Time", align: "right", cell: (d) => responseCell(d.application_response_ms, d.encrypted_connections > 0 && d.http_connections === 0) },
            { header: "Confidence", cell: (d) => <Confidence level={d.measurement_confidence} /> },
          ]} />
      </Card>

      {selected && <MetricsDetail m={selected} destination={destination(selected)} onClose={() => setOpenId(null)} />}
      <Card padded={false} title="Connections" subtitle="Largest connections first. Click a row for the full measurements.">
        <DataTable rowKey={(m) => m.connection_id} caption="Connection performance" rows={stats.metrics.slice(0, 100)} empty="No connections."
          onRowClick={(m) => setOpenId(openId === m.connection_id ? null : m.connection_id)}
          columns={[
            { header: "Destination", cell: (m) => <Mono>{destination(m)}</Mono> },
            { header: "Protocol", cell: (m) => m.application_protocol ? `${m.protocol} · ${m.application_protocol}` : m.protocol },
            { header: "DNS", align: "right", cell: (m) => formatMs(m.dns_latency_ms) },
            { header: "TCP Handshake", align: "right", cell: (m) => formatMs(m.tcp_handshake_ms) },
            { header: "Avg RTT", align: "right", cell: (m) => formatMs(m.avg_rtt_ms) },
            { header: "P95 RTT", align: "right", cell: (m) => formatMs(m.p95_rtt_ms) },
            { header: "Response Time", align: "right", cell: (m) => responseCell(m.application_response_ms, m.encrypted) },
            { header: "Confidence", cell: (m) => <Confidence level={m.measurement_confidence} /> },
          ]} />
      </Card>
    </>
  );
}

function MetricsDetail({ m, destination, onClose }: { m: PerformanceMetrics; destination: string; onClose: () => void }) {
  const rows: [string, string][] = [
    ["Destination", destination], ["Protocol", m.application_protocol ? `${m.protocol} · ${m.application_protocol}` : m.protocol],
    ["Connection duration", formatMs(m.connection_duration_ms)],
  ];
  if (m.dns_latency_ms !== null) rows.push(["DNS lookup", `${formatMs(m.dns_latency_ms)} (${m.dns_lookups} lookup${m.dns_lookups === 1 ? "" : "s"}, median)`]);
  if (m.protocol === "TCP") {
    rows.push(["TCP handshake (set-up time)", formatMs(m.tcp_handshake_ms)]);
    if (m.encrypted) rows.push(["TLS ClientHello → ServerHello", formatMs(m.tls_server_hello_ms)]);
    rows.push(
      ["RTT samples", formatNumber(m.rtt_samples)],
      ["RTT min / avg / median", m.rtt_samples ? `${formatMs(m.min_rtt_ms)} / ${formatMs(m.avg_rtt_ms)} / ${formatMs(m.median_rtt_ms)}` : "–"],
      ["RTT P95 / max", m.rtt_samples ? `${formatMs(m.p95_rtt_ms)} / ${formatMs(m.max_rtt_ms)}` : "–"],
      ["RTT measured from", m.rtt_basis === "client_to_server" ? "data sent by the source, acknowledged by the destination" : m.rtt_basis === "server_to_client" ? "data sent by the destination, acknowledged by the source" : "–"],
    );
    if (m.application_protocol === "HTTP") rows.push(["HTTP response time", m.application_response_ms !== null ? `${formatMs(m.application_response_ms)} (${m.application_response_samples} exchange${m.application_response_samples === 1 ? "" : "s"}, median)` : "not measurable"]);
    if (m.encrypted) rows.push(["Response time", "not visible (HTTPS)"]);
  }
  rows.push(["Confidence", m.measurement_confidence.toLowerCase()]);
  return (
    <Card title="Connection measurements" subtitle={`ID ${m.connection_id}`}
      actions={<button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-ink-2 hover:text-ink">Close</button>}>
      <dl aria-label="Connection measurements" className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
        {rows.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-all font-mono text-ink">{v}</dd></div>))}
      </dl>
      {m.notes.length > 0 && <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-ink-2">{m.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
    </Card>
  );
}
