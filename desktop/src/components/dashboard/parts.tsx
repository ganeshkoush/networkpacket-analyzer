import { Link } from "react-router-dom";
import type { ActivityItem, DashboardConnection, DashboardData, DashboardFinding, DashboardRange, HealthScoreView, SlowDomainRow, WebDomainRow } from "../../api/types";
import { DASHBOARD_RANGES } from "../../api/types";
import { endpoint, formatBytes, formatMs, formatNumber, formatPercent, formatTime } from "../../lib/format";
import { typeLabel } from "../../lib/severity";
import { Card, StatTile } from "../ui/Card";
import { type Column, DataTable } from "../ui/DataTable";
import { ConfidenceMeter } from "../ui/ConfidenceMeter";
import { SeverityBadge } from "../ui/SeverityBadge";
import { HealthBadge } from "../web/HealthBadge";

// ---------------------------------------------------------------- controls
export function RangeControl({ value, onChange, disabled }: { value: DashboardRange; onChange: (r: DashboardRange) => void; disabled?: boolean }) {
  return (
    <div role="radiogroup" aria-label="Time range" className="inline-flex overflow-hidden rounded-md border border-line">
      {DASHBOARD_RANGES.map((r) => (
        <button key={r.key} type="button" role="radio" aria-checked={value === r.key} disabled={disabled} onClick={() => onChange(r.key)}
          className={`px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-wait ${value === r.key ? "bg-accent text-bg" : "bg-surface-2 text-ink-2 hover:text-ink"}`}>
          {r.label}
        </button>
      ))}
    </div>
  );
}

export const SECTIONS = ["Overview", "Domains", "Connections", "Performance", "Security", "AI Investigation", "Network Map", "Reports"] as const;
export type Section = (typeof SECTIONS)[number];

export function SectionTabs({ value, onChange }: { value: Section; onChange: (s: Section) => void }) {
  return (
    <div role="tablist" aria-label="Dashboard sections" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
      {SECTIONS.map((s) => (
        <button key={s} type="button" role="tab" id={`tab-${s}`} aria-selected={value === s} aria-controls="dashboard-panel" onClick={() => onChange(s)}
          className={`-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium ${value === s ? "border-accent text-ink" : "border-transparent text-ink-2 hover:text-ink"}`}>{s}</button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------- health score
const SCORE_STYLE = {
  Healthy: { text: "text-series-3", border: "border-series-3/50", bg: "bg-series-3/10" },
  Degraded: { text: "text-sev-medium", border: "border-sev-medium/50", bg: "bg-sev-medium/10" },
  Poor: { text: "text-sev-critical", border: "border-sev-critical/50", bg: "bg-sev-critical/10" },
  Unknown: { text: "text-ink-2", border: "border-line", bg: "bg-surface-2" },
} as const;

export function HealthScoreCard({ health }: { health: HealthScoreView }) {
  const s = SCORE_STYLE[health.label];
  return (
    <section aria-label="Network health score" className={`rounded-lg border-2 p-4 ${s.border} ${s.bg}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-ink-3">Network health score</div>
      <div className="mt-1 flex items-baseline gap-3">
        <span className={`font-mono text-4xl font-bold tabular-nums ${s.text}`} data-testid="health-score">{health.score ?? "–"}</span>
        {health.score != null && <span className="text-sm text-ink-3">/ 100</span>}
        <span className={`text-lg font-semibold uppercase ${s.text}`} data-testid="health-label">{health.label}</span>
      </div>
      <p className="mt-2 text-xs text-ink-2">{health.basis}</p>
      {health.deductions.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-xs text-ink-2" aria-label="Score deductions">
          {health.deductions.map((d) => <li key={d.reason}><span className="font-mono text-ink">−{d.points}</span> {d.reason}</li>)}
        </ul>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- KPIs
const unmeasured = "not measurable here";

export function KpiGrid({ k, onOpen }: { k: DashboardData["kpis"]; onOpen: (s: Section) => void }) {
  const n = (v: number) => `${formatNumber(v)} sample${v === 1 ? "" : "s"}`;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-3" aria-label="Key metrics" role="group">
      <StatTile label="Active connections" value={formatNumber(k.active_connections)} sub={`${formatNumber(k.connections_in_window)} in this range`} />
      <StatTile label="Domains contacted" value={formatNumber(k.domains_contacted)} sub="inferred from DNS" />
      <StatTile label="Total traffic" value={formatBytes(k.total_bytes)} sub={`${formatNumber(k.total_packets)} packets`} />
      <StatTile label="Avg TCP handshake" value={formatMs(k.avg_handshake_ms)} sub={k.avg_handshake_ms == null ? unmeasured : n(k.handshake_samples)} />
      <StatTile label="Avg RTT" value={formatMs(k.avg_rtt_ms)} sub={k.avg_rtt_ms == null ? unmeasured : n(k.rtt_samples)} />
      <StatTile label="DNS latency" value={formatMs(k.dns_latency_ms)} sub={k.dns_latency_ms == null ? unmeasured : n(k.dns_samples)} />
      <StatTile label="Retransmission rate" value={formatPercent(k.retransmission_rate)} sub={k.retransmission_rate == null ? unmeasured : `${formatNumber(k.tcp_packets)} TCP packets · heuristic`} />
      <button type="button" onClick={() => onOpen("Security")} className="rounded-lg text-left focus-visible:outline-offset-0" aria-label={`Security findings ${k.findings}`}>
        <StatTile label="Security findings" value={formatNumber(k.findings)} sub={k.findings ? "see Security" : "no detector threshold exceeded"} />
      </button>
      <button type="button" onClick={() => onOpen("Performance")} className="rounded-lg text-left focus-visible:outline-offset-0" aria-label={`Performance anomalies ${k.anomalies}`}>
        <StatTile label="Performance anomalies" value={formatNumber(k.anomalies)} sub="against this computer's history" />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------- tables
const latency = (r: WebDomainRow) => (r.avg_rtt_ms != null ? `${formatMs(r.avg_rtt_ms)} RTT` : r.tcp_handshake_ms != null ? `${formatMs(r.tcp_handshake_ms)} handshake` : "–");

export function TopDomainsTable({ rows }: { rows: WebDomainRow[] }) {
  const cols: Column<WebDomainRow>[] = [
    { header: "Domain", cell: (r) => <span className="break-all font-mono">{r.domain}</span> },
    { header: "Connections", align: "right", cell: (r) => formatNumber(r.connections) },
    { header: "Traffic", align: "right", cell: (r) => formatBytes(r.total_bytes) },
    { header: "Latency", align: "right", cell: latency },
    { header: "Health", cell: (r) => <HealthBadge health={r.health} reasons={r.health_reasons} /> },
  ];
  return <DataTable caption="Top domains" columns={cols} rows={rows} rowKey={(r) => r.domain} empty="No domains were attributed in this range: domains come from DNS lookups that preceded a connection." />;
}

export function SlowestTable({ rows }: { rows: SlowDomainRow[] }) {
  const cols: Column<SlowDomainRow>[] = [
    { header: "Domain", cell: (r) => <span className="break-all font-mono">{r.domain}</span> },
    { header: "Avg RTT", align: "right", cell: (r) => formatMs(r.avg_rtt_ms) },
    { header: "P95 RTT", align: "right", cell: (r) => formatMs(r.p95_rtt_ms) },
    { header: "TCP handshake", align: "right", cell: (r) => formatMs(r.tcp_handshake_ms) },
    { header: "Status", cell: (r) => <HealthBadge health={r.status} reasons={r.reasons} /> },
  ];
  return <DataTable caption="Slowest services" columns={cols} rows={rows} rowKey={(r) => r.domain} empty="No domain has timing data in this range." />;
}

export function FindingsTable({ rows }: { rows: DashboardFinding[] }) {
  const cols: Column<DashboardFinding>[] = [
    { header: "Finding", cell: (f) => <Link to={`/findings/${f.id}`} className="font-medium text-ink hover:text-accent">{f.title}<span className="block text-xs font-normal text-ink-3">{typeLabel(f.type)}</span></Link> },
    { header: "Severity", cell: (f) => <SeverityBadge severity={f.severity} /> },
    { header: "Confidence", cell: (f) => <ConfidenceMeter value={f.confidence} /> },
    { header: "Evidence", cell: (f) => <span className="font-mono text-xs text-ink-2">{f.evidence.length ? f.evidence.join(" · ") : "see finding"}</span> },
  ];
  return <DataTable caption="Recent findings" columns={cols} rows={rows} rowKey={(f) => f.id} empty="No detector exceeded its threshold in this range. That is not proof the traffic is safe." />;
}

export function ConnectionsTable({ rows, empty, caption, showReasons = false }: { rows: DashboardConnection[]; empty: string; caption: string; showReasons?: boolean }) {
  const cols: Column<DashboardConnection>[] = [
    { header: "Remote", cell: (c) => <span className="break-all font-mono">{c.domain ?? endpoint(c.server_ip, c.server_port)}{c.domain && <span className="block text-xs text-ink-3">{endpoint(c.server_ip, c.server_port)}</span>}</span> },
    { header: "Client", cell: (c) => <span className="font-mono text-xs">{endpoint(c.client_ip, c.client_port)}</span> },
    { header: "Proto", cell: (c) => c.protocol },
    { header: "State", cell: (c) => c.state ?? "–" },
    { header: "Traffic", align: "right", cell: (c) => formatBytes(c.bytes) },
    { header: "Handshake", align: "right", cell: (c) => formatMs(c.handshake_ms) },
    ...(showReasons ? [{ header: "Why listed", cell: (c: DashboardConnection) => <span className="text-xs text-ink-2">{c.reasons.join(" ")}{c.finding_ids.map((id) => <Link key={id} to={`/findings/${id}`} className="ml-1 text-accent hover:underline">{id}</Link>)}</span> }] : []),
  ];
  return <DataTable caption={caption} columns={cols} rows={rows} rowKey={(c) => c.id} empty={empty} />;
}

export function ActivityList({ items }: { items: ActivityItem[] }) {
  if (!items.length) return <p className="text-sm text-ink-3">Nothing notable happened in this range.</p>;
  const icon = { finding: "🛡", anomaly: "⚠", domain: "◦", connection: "→" } as const;
  return (
    <ul className="divide-y divide-line/60" aria-label="Recent activity">
      {items.map((i, n) => (
        <li key={`${i.kind}-${i.ref}-${n}`} className="flex items-start gap-3 py-2 text-[13px]">
          <span aria-hidden className="mt-0.5 w-4 text-center text-ink-3">{icon[i.kind]}</span>
          <span className="min-w-0 flex-1">{i.kind === "finding" && i.ref ? <Link to={`/findings/${i.ref}`} className="hover:text-accent">{i.text}</Link> : i.text}</span>
          {i.severity && <SeverityBadge severity={i.severity} />}
          <time className="shrink-0 font-mono text-xs text-ink-3">{formatTime(i.time).slice(11, 19)}</time>
        </li>
      ))}
    </ul>
  );
}

export function SectionCard({ title, subtitle, actions, children }: { title: string; subtitle?: string; actions?: React.ReactNode; children: React.ReactNode }) {
  return <Card title={title} subtitle={subtitle} actions={actions}>{children}</Card>;
}
