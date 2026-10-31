import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { WebDomainDetail } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { SeriesChart } from "../charts/SeriesChart";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { Button, ErrorPanel, Notice, Spinner } from "../ui/feedback";
import { endpoint, formatBytes, formatClock, formatDuration, formatMs, formatNumber, formatTime } from "../../lib/format";
import { ApplicationsSection } from "./ApplicationsSection";
import { BaselineSection } from "./BaselineSection";
import { HealthBadge } from "./HealthBadge";

function KV({ label, rows }: { label: string; rows: [string, ReactNode][] }) {
  return (
    <dl aria-label={label} className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
      {rows.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-words font-mono text-ink">{v}</dd></div>))}
    </dl>
  );
}
const Missing = ({ children }: { children: ReactNode }) => <span className="font-sans text-ink-3">{children}</span>;
const ms = (v: number | null | undefined) => (v == null ? <Missing>–</Missing> : formatMs(v));

export function DomainDetail({ analysisId, domain, onBack }: { analysisId: string; domain: string; onBack: () => void }) {
  const api = useApi();
  const [detail, setDetail] = useState<WebDomainDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setDetail(null); setError(null);
    api.getWebDomain(analysisId, domain, signal).then(setDetail).catch((e) => {
      if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not load this domain.");
    });
  }, [api, analysisId, domain]);

  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  const back = <Button variant="ghost" onClick={onBack}>← Back to domains</Button>;
  if (error) return <div className="space-y-3">{back}<ErrorPanel title="Domain details unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel></div>;
  if (!detail) return <div className="space-y-3">{back}<Spinner label={`Loading ${domain}…`} /></div>;

  const { overview: o, performance: p, series: s } = detail;
  const encryptedOnly = !!p && p.encrypted_connections > 0 && p.http_connections === 0;
  const first = (v: number | null | undefined) => (v == null ? "–" : formatNumber(v));
  const pairs = <T extends number | null>(pts: { t: number }[], get: (i: number) => T) =>
    pts.flatMap((pt, i) => { const v = get(i); return v == null ? [] : [{ t: pt.t, v }]; });

  return (
    <div className="space-y-4">
      {back}
      <Card title="Domain details" subtitle="Domains are inferred from DNS lookups that preceded each connection, not read from the traffic."
        actions={<HealthBadge health={detail.health} reasons={detail.health_reasons} />}>
        <h2 className="mb-3 break-all font-mono text-lg font-semibold">{detail.domain}</h2>
        {detail.health_reasons.length > 0 && (
          <ul aria-label="Health observations" className="mb-3 list-disc space-y-0.5 pl-5 text-xs text-ink-2">{detail.health_reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        )}
        <h3 className="mb-1.5 text-[13px] font-medium">Overview</h3>
        <KV label="Overview" rows={[
          ["Connections", `${formatNumber(o.connection_count)} (${o.tcp_connection_count} TCP · ${o.udp_connection_count} UDP)`],
          ["First seen", formatTime(o.first_seen)], ["Last seen", formatTime(o.last_seen)],
          ["Total traffic", formatBytes(o.total_bytes_sent + o.total_bytes_received)],
          ["Destination IPs", o.resolved_ips.join(", ") || <Missing>none captured</Missing>],
          ["Server ports", o.server_ports.join(", ") || <Missing>–</Missing>],
        ]} />
      </Card>

      <Card title="Performance" subtitle="Connection set-up time and round-trip time are different from response time and are never mixed.">
        <KV label="Performance" rows={[
          ["DNS latency", p?.dns_latency_ms != null ? `${formatMs(p.dns_latency_ms)} (median of ${p.dns_lookups} lookup${p.dns_lookups === 1 ? "" : "s"})` : <Missing>No DNS information available</Missing>],
          ["TCP handshake", p?.tcp_handshake_ms != null ? `${formatMs(p.tcp_handshake_ms)} (average of ${p.handshake_samples}; connection set-up time)` : <Missing>–</Missing>],
          ["Average RTT", ms(p?.avg_rtt_ms)], ["P95 RTT", ms(p?.p95_rtt_ms)], ["Maximum RTT", ms(p?.max_rtt_ms)],
          ["RTT samples", p ? formatNumber(p.rtt_samples) : <Missing>–</Missing>],
          ["Retransmissions", p ? `${formatNumber(p.retransmissions ?? 0)} (heuristic indicator)` : <Missing>–</Missing>],
          ["Resets", p ? `${formatNumber(p.resets ?? 0)} RST packet${p.resets === 1 ? "" : "s"} in ${p.connections_reset ?? 0} connection${p.connections_reset === 1 ? "" : "s"}` : <Missing>–</Missing>],
          ["Response time", p?.application_response_ms != null ? `${formatMs(p.application_response_ms)} (cleartext HTTP, ${p.application_response_samples} exchange${p.application_response_samples === 1 ? "" : "s"})`
            : encryptedOnly ? <Missing>not visible (HTTPS)</Missing> : <Missing>No measurable response-time data</Missing>],
        ]} />
      </Card>

      <ApplicationsSection analysisId={analysisId} domain={detail.domain} />

      <Card title="Traffic">
        <KV label="Traffic" rows={[
          ["Bytes sent", formatBytes(o.total_bytes_sent)], ["Bytes received", formatBytes(o.total_bytes_received)],
          ["Packets sent", first(o.packets_sent)], ["Packets received", first(o.packets_received)],
        ]} />
      </Card>

      <Card padded={false} title="Connections"
        subtitle={detail.connections_total > detail.connections.length ? `The ${detail.connections.length} largest of ${formatNumber(detail.connections_total)}` : `${formatNumber(detail.connections_total)} total`}>
        <DataTable rowKey={(c) => c.id} caption="Connections to this domain" rows={detail.connections} empty="No connections found"
          columns={[
            { header: "Source", cell: (c) => <Mono>{endpoint(c.client_ip, c.client_port)}</Mono> },
            { header: "Destination", cell: (c) => <Mono>{endpoint(c.server_ip, c.server_port)}</Mono> },
            { header: "Protocol", cell: (c) => c.application_protocol ? `${c.protocol} · ${c.application_protocol}` : c.protocol },
            { header: "State", cell: (c) => c.state ? c.state.replace("_", " ").toLowerCase() : <span className="text-ink-3">–</span> },
            { header: "Started", cell: (c) => <span className="text-ink-2">{formatClock(c.start_time)}</span> },
            { header: "Duration", align: "right", cell: (c) => formatDuration(c.duration_seconds) },
            { header: "Bytes", align: "right", cell: (c) => formatBytes(c.bytes) },
            { header: "TCP Handshake", align: "right", cell: (c) => formatMs(c.handshake_ms) },
            { header: "Avg RTT", align: "right", cell: (c) => formatMs(c.avg_rtt_ms) },
            { header: "Retrans.", align: "right", cell: (c) => c.retransmissions == null ? "–" : formatNumber(c.retransmissions) },
          ]} />
      </Card>

      <BaselineSection analysisId={analysisId} domain={detail.domain} />

      <Card title="Over time">
        <div className="space-y-6">
          <SeriesChart title="Response / RTT over time (one point per connection)" kind="line" formatValue={formatMs}
            empty="No measurable response-time data"
            series={[
              { key: "avg", label: "Average RTT", color: "var(--color-series-1)", points: pairs(s.rtt, (i) => s.rtt[i].avg_rtt_ms) },
              { key: "p95", label: "P95 RTT", color: "var(--color-series-2)", points: pairs(s.rtt, (i) => s.rtt[i].p95_rtt_ms) },
              { key: "resp", label: "HTTP response", color: "var(--color-series-4)", points: pairs(s.rtt, (i) => s.rtt[i].response_ms) },
            ]} />
          <SeriesChart title="TCP handshake over time (one point per connection)" kind="line" formatValue={formatMs}
            empty="No completed TCP handshakes to chart"
            series={[{ key: "hs", label: "TCP handshake", color: "var(--color-series-3)", points: s.handshake.map((h) => ({ t: h.t, v: h.handshake_ms })) }]} />
          <SeriesChart title="Traffic volume over time" kind="bars" formatValue={formatBytes} binSeconds={s.bin_seconds} empty="No traffic recorded"
            series={[
              { key: "sent", label: "Sent", color: "var(--color-series-1)", points: s.traffic.map((b) => ({ t: b.t, v: b.bytes_sent })) },
              { key: "recv", label: "Received", color: "var(--color-series-6)", points: s.traffic.map((b) => ({ t: b.t, v: b.bytes_received })) },
            ]} />
        </div>
      </Card>
      {detail.notes.map((n) => <p key={n} className="text-xs text-ink-3">{n}</p>)}
      {detail.connections_total > detail.connections.length && <Notice tone="info">Per-connection detail is kept for the largest connections only; the totals above cover all {formatNumber(detail.connections_total)}.</Notice>}
    </div>
  );
}
