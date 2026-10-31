import { useMemo, useState } from "react";
import type { DomainActivity, DomainStatistics } from "../../api/types";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { Notice } from "../ui/feedback";
import { formatBytes, formatNumber, formatTime } from "../../lib/format";

export type DomainSort = "traffic" | "connections" | "recent" | "name";
const SORTS: { value: DomainSort; label: string }[] = [
  { value: "traffic", label: "Traffic (sent + received)" },
  { value: "connections", label: "Connections" },
  { value: "recent", label: "Latest activity" },
  { value: "name", label: "Domain name" },
];

const traffic = (d: DomainActivity) => d.total_bytes_sent + d.total_bytes_received;

/** Same ordering as GET /api/analyses/{id}/domains, applied locally to the already-loaded result. */
export function filterAndSortDomains(domains: DomainActivity[], search: string, sort: DomainSort): DomainActivity[] {
  const needle = search.trim().toLowerCase();
  const rows = needle ? domains.filter((d) => d.domain.includes(needle)) : [...domains];
  const by: Record<DomainSort, (a: DomainActivity, b: DomainActivity) => number> = {
    traffic: (a, b) => traffic(b) - traffic(a) || b.connection_count - a.connection_count,
    connections: (a, b) => b.connection_count - a.connection_count || traffic(b) - traffic(a),
    recent: (a, b) => b.last_seen - a.last_seen || b.connection_count - a.connection_count,
    name: (a, b) => a.domain.localeCompare(b.domain),
  };
  return rows.sort(by[sort]);
}

export function DomainsTab({ stats }: { stats: DomainStatistics | undefined }) {
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<DomainSort>("traffic");
  const [open, setOpen] = useState<string | null>(null);
  const rows = useMemo(() => filterAndSortDomains(stats?.domains ?? [], search, sort), [stats, search, sort]);

  if (!stats || stats.summary.total_domains === 0) {
    return (
      <Card>
        <p className="text-sm text-ink-3">No domains could be identified: this capture has no DNS lookups with usable answers.</p>
        {stats?.summary.notes.slice(1).map((n) => <p key={n} className="mt-2 text-sm text-ink-2">{n}</p>)}
      </Card>
    );
  }
  const s = stats.summary;
  return (
    <>
      <Notice tone="info">{s.notes[0]}</Notice>
      <Card padded={false}
        title="Domain activity"
        subtitle={`${formatNumber(s.total_domains)} domains · ${formatNumber(s.attributed_connections)} connections matched to a DNS lookup · ${formatNumber(s.unattributed_connections)} with no matching lookup`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input type="search" aria-label="Search domains" placeholder="Search domain" value={search} onChange={(e) => setSearch(e.target.value)}
              className="w-44 rounded-md border border-line bg-bg px-2.5 py-1 text-sm text-ink placeholder:text-ink-3" />
            <select aria-label="Sort domains" value={sort} onChange={(e) => setSort(e.target.value as DomainSort)}
              className="rounded-md border border-line bg-bg px-2 py-1 text-sm text-ink">
              {SORTS.map((o) => <option key={o.value} value={o.value}>Sort: {o.label}</option>)}
            </select>
          </div>
        }>
        <DataTable rowKey={(d) => d.domain} caption="Domain activity" rows={rows.slice(0, 200)}
          empty={search ? `No domain matches “${search}”.` : "No domains."}
          onRowClick={(d) => setOpen(open === d.domain ? null : d.domain)}
          columns={[
            { header: "Domain", cell: (d) => (
              <div>
                <Mono>{d.domain}</Mono>
                {open === d.domain && <DomainDetail d={d} />}
              </div>) },
            { header: "Connections", align: "right", cell: (d) => formatNumber(d.connection_count) },
            { header: "Data sent", align: "right", cell: (d) => formatBytes(d.total_bytes_sent) },
            { header: "Data received", align: "right", cell: (d) => formatBytes(d.total_bytes_received) },
            { header: "First seen", cell: (d) => <span className="text-ink-2">{formatTime(d.first_seen)}</span> },
            { header: "Last seen", cell: (d) => <span className="text-ink-2">{formatTime(d.last_seen)}</span> },
          ]} />
        {rows.length > 200 && <p className="px-4 py-2 text-xs text-ink-3">Showing the first 200 of {formatNumber(rows.length)}. Use search to narrow.</p>}
      </Card>
      {s.notes.slice(1).map((n) => <Notice key={n} tone="warn">{n}</Notice>)}
    </>
  );
}

function DomainDetail({ d }: { d: DomainActivity }) {
  const kv: [string, string][] = [
    ["Destination IPs", d.resolved_ips.join(", ") || "none captured (query had no usable answer)"],
    ["Clients", d.clients.join(", ") || "–"],
    ["Connections", `${d.tcp_connection_count} TCP · ${d.udp_connection_count} UDP`],
    ["Server ports", d.server_ports.join(", ") || "–"],
    ["DNS", `${d.dns_queries} queries · ${d.dns_responses} responses${d.min_ttl != null ? ` · TTL ${d.min_ttl === d.max_ttl ? d.min_ttl : `${d.min_ttl}–${d.max_ttl}`} s` : ""}`],
  ];
  if (d.shared_ips.length) kv.push(["Shared IPs", `${d.shared_ips.join(", ")}: also resolved for other domains${d.ambiguous_connection_count ? `; ${d.ambiguous_connection_count} connection(s) are less certain` : ""}`]);
  return (
    <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 text-xs text-ink-2">
      {kv.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="break-all font-mono">{v}</dd></div>))}
    </dl>
  );
}
