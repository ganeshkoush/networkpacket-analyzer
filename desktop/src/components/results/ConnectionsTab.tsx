import { useMemo, useState } from "react";
import type { Connection, ConnectionSummary } from "../../api/types";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { Button, Notice } from "../ui/feedback";
import { endpoint, formatBytes, formatDuration, formatMs, formatNumber, formatTimeMs } from "../../lib/format";

export interface ConnectionFilters { domain: string; src: string; dst: string; protocol: string; port: string; state: string }
export const NO_FILTERS: ConnectionFilters = { domain: "", src: "", dst: "", protocol: "", port: "", state: "" };

const STATES = ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSING", "CLOSED", "RESET", "UNKNOWN"];
const STATE_LABEL: Record<string, string> = {
  SYN_SENT: "SYN sent", SYN_RECEIVED: "SYN received", ESTABLISHED: "Established", CLOSING: "Closing", CLOSED: "Closed", RESET: "Reset", UNKNOWN: "Unknown",
};

/** Same criteria as GET /api/analyses/{id}/connections, applied to the already-loaded result (IP fields match as substrings here). */
export function filterConnections(rows: Connection[], f: ConnectionFilters): Connection[] {
  const domain = f.domain.trim().toLowerCase();
  const src = f.src.trim().toLowerCase();
  const dst = f.dst.trim().toLowerCase();
  const port = f.port.trim() === "" ? null : Number(f.port);
  return rows.filter((c) =>
    (!domain || (c.domain ?? "").includes(domain)) &&
    (!src || c.client_ip.toLowerCase().includes(src)) &&
    (!dst || c.server_ip.toLowerCase().includes(dst)) &&
    (!f.protocol || c.protocol === f.protocol) &&
    (port === null || Number.isNaN(port) || c.client_port === port || c.server_port === port) &&
    (!f.state || c.state === f.state));
}

/** "ESTABLISHED" etc. for TCP; older results without `state` fall back to the handshake/reset flags. */
export function stateOf(c: Connection): string | null {
  if (c.protocol !== "TCP") return null;
  if (c.state) return c.state;
  return c.rst_seen ? "RESET" : c.handshake_complete ? "ESTABLISHED" : "UNKNOWN";
}

const idOf = (c: Connection, i: number) => c.id || `${c.protocol}-${c.client_ip}-${c.client_port}-${c.server_ip}-${c.server_port}-${i}`;
const input = "rounded-md border border-line bg-bg px-2.5 py-1 text-sm text-ink placeholder:text-ink-3";

export function ConnectionsTab({ connections, summary }: { connections: Connection[]; summary: ConnectionSummary }) {
  const [filters, setFilters] = useState<ConnectionFilters>(NO_FILTERS);
  const [openId, setOpenId] = useState<string | null>(null);
  const set = (k: keyof ConnectionFilters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const protocols = useMemo(() => [...new Set(connections.map((c) => c.protocol))].sort(), [connections]);
  const rows = useMemo(() => filterConnections(connections, filters), [connections, filters]);
  const selected = openId === null ? undefined : connections.find((c, i) => idOf(c, i) === openId);
  const filtered = JSON.stringify(filters) !== JSON.stringify(NO_FILTERS);

  return (
    <>
      {selected && <ConnectionDetail c={selected} onClose={() => setOpenId(null)} />}
      <HandshakeByDomain summary={summary} />
      <Card padded={false} title="Connections"
        subtitle={`${formatNumber(summary.total_connections)} total (${Object.entries(summary.by_protocol).map(([k, v]) => `${k} ${formatNumber(v)}`).join(", ") || "none"}) · ${formatNumber(summary.tcp_handshakes_complete)} TCP handshakes completed · showing the top ${formatNumber(connections.length)} by bytes`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input type="search" aria-label="Filter by domain" placeholder="Domain" value={filters.domain} onChange={set("domain")} className={`w-32 ${input}`} />
            <input type="search" aria-label="Filter by source IP" placeholder="Source IP" value={filters.src} onChange={set("src")} className={`w-32 ${input}`} />
            <input type="search" aria-label="Filter by destination IP" placeholder="Destination IP" value={filters.dst} onChange={set("dst")} className={`w-32 ${input}`} />
            <select aria-label="Filter by protocol" value={filters.protocol} onChange={set("protocol")} className={input}>
              <option value="">Any protocol</option>
              {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
            <input type="number" min={0} max={65535} aria-label="Filter by port" placeholder="Port" value={filters.port} onChange={set("port")} className={`w-20 ${input}`} />
            <select aria-label="Filter by state" value={filters.state} onChange={set("state")} className={input}>
              <option value="">Any state</option>
              {STATES.map((s) => <option key={s} value={s}>{STATE_LABEL[s]}</option>)}
            </select>
            {filtered && <Button variant="ghost" onClick={() => setFilters(NO_FILTERS)}>Clear</Button>}
          </div>
        }>
        <DataTable rowKey={idOf} caption="Connections" rows={rows.slice(0, 200)}
          empty={filtered ? "No connection matches these filters." : "No connections."}
          onRowClick={(c) => { const id = idOf(c, connections.indexOf(c)); setOpenId(openId === id ? null : id); }}
          columns={[
            { header: "Domain / Destination", cell: (c) => c.domain ? <Mono>{c.domain}</Mono> : <Mono className="text-ink-2">{c.server_ip}</Mono> },
            { header: "Source", cell: (c) => <Mono>{endpoint(c.client_ip, c.client_port)}</Mono> },
            { header: "Destination", cell: (c) => <Mono>{endpoint(c.server_ip, c.server_port)}</Mono> },
            { header: "Protocol", cell: (c) => c.protocol },
            { header: "Port", align: "right", cell: (c) => c.server_port ?? "–" },
            { header: "Duration", align: "right", cell: (c) => formatDuration(c.duration_seconds) },
            { header: "Bytes", align: "right", cell: (c) => formatBytes(c.bytes) },
            { header: "Packets", align: "right", cell: (c) => formatNumber(c.packets) },
            { header: "State", cell: (c) => { const s = stateOf(c); return s ? STATE_LABEL[s] ?? s : <span className="text-ink-3">–</span>; } },
          ]} />
        {rows.length > 200 && <p className="px-4 py-2 text-xs text-ink-3">Showing the first 200 of {formatNumber(rows.length)}. Use the filters to narrow.</p>}
      </Card>
      <p className="text-xs text-ink-3">
        “Source” is the side that sent the first packet in the capture. State is derived from the packets captured, so a capture that starts or ends mid-connection can look incomplete.
        Domains are inferred from DNS lookups and are blank when none was seen.
      </p>
    </>
  );
}

function ConnectionDetail({ c, onClose }: { c: Connection; onClose: () => void }) {
  const isTcp = c.protocol === "TCP";
  const yn = (v: boolean | null | undefined) => (v == null ? "–" : v ? "yes" : "no");
  const rows: [string, string][] = [
    ["Protocol", c.protocol],
    ["Source (initiator)", endpoint(c.client_ip, c.client_port)],
    ["Destination (responder)", endpoint(c.server_ip, c.server_port)],
    ["Domain", c.domain ? `${c.domain} (inferred from DNS)` : "none: no preceding DNS lookup was captured"],
    ["Started", formatTimeMs(c.start_time)],
    ["Ended", formatTimeMs(c.end_time)],
    ["Duration", c.duration_seconds < 1 ? `${Math.round(c.duration_seconds * 1000)} ms` : formatDuration(c.duration_seconds)],
    ["Sent (source → destination)", `${formatNumber(c.packets_client_to_server)} packets · ${formatBytes(c.bytes_client_to_server)}`],
    ["Received (destination → source)", `${formatNumber(c.packets_server_to_client)} packets · ${formatBytes(c.bytes_server_to_client)}`],
    ["Total", `${formatNumber(c.packets)} packets · ${formatBytes(c.bytes)}`],
  ];
  if (isTcp) {
    const s = stateOf(c);
    rows.push(
      ["State", s ? STATE_LABEL[s] ?? s : "–"],
      ["Teardown", `FIN ${yn(c.fin_seen)} · RST ${yn(c.rst_seen)}${c.resets ? ` (${c.resets} reset packet${c.resets === 1 ? "" : "s"})` : ""}`],
      ["Retransmissions", c.retransmissions == null ? "–" : `${formatNumber(c.retransmissions)} (heuristic indicator)`],
      ["Flags seen", c.tcp_flags_seen?.join(", ") || "–"],
    );
  }
  return (
    <Card title="Connection detail" subtitle={c.id ? `ID ${c.id}` : undefined}
      actions={<Button variant="ghost" onClick={onClose}>Close</Button>}>
      <dl aria-label="Connection detail" className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
        {rows.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-all font-mono text-ink">{v}</dd></div>))}
      </dl>
      {isTcp && <TcpHandshake c={c} />}
      {c.domain_ambiguous && <div className="mt-3"><Notice tone="warn">This destination IP was also resolved for other domains; the most recent lookup was chosen, so the domain is less certain.</Notice></div>}
      {isTcp && c.state === "UNKNOWN" && <div className="mt-3"><Notice tone="info">No handshake or teardown was captured: the capture likely began mid-connection.</Notice></div>}
    </Card>
  );
}

const INCOMPLETE_REASON: Record<string, string> = {
  no_syn_seen: "No SYN was captured (the capture likely began mid-connection).",
  no_synack: "A SYN was seen but no SYN-ACK that answers it.",
  no_final_ack: "A SYN-ACK was seen but no ACK that completes the handshake.",
  reset: "The connection was reset (RST) before the handshake completed.",
  simultaneous_open: "Both sides sent a SYN (simultaneous open), so the packets cannot be paired reliably.",
};

/** TCP three-way handshake timing. Latencies are shown only when the backend could pair the packets; otherwise "–". */
function TcpHandshake({ c }: { c: Connection }) {
  const status = c.handshake_status;
  const rows: [string, string][] = [
    ["SYN → SYN-ACK", formatMs(c.tcp_syn_ack_latency_ms)],
    ["SYN-ACK → ACK", formatMs(c.tcp_ack_latency_ms)],
    ["Total", formatMs(c.tcp_handshake_time_ms)],
  ];
  const retx = (c.tcp_syn_retransmissions ?? 0) + (c.tcp_syn_ack_retransmissions ?? 0);
  return (
    <section aria-label="TCP Handshake" className="mt-4 border-t border-line pt-3">
      <h4 className="mb-1.5 text-[13px] font-medium text-ink">TCP Handshake</h4>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
        <div className="contents"><dt className="text-ink-3">Handshake status</dt>
          <dd className="font-mono text-ink">{status === "completed" ? "Completed" : status === "incomplete" ? "Incomplete" : "–"}</dd></div>
        {rows.map(([k, v]) => (<div key={k} className="contents"><dt className="text-ink-3">{k}</dt><dd className="font-mono text-ink">{v}</dd></div>))}
      </dl>
      {status === "incomplete" && c.handshake_incomplete_reason && (
        <p className="mt-2 text-xs text-ink-2">{INCOMPLETE_REASON[c.handshake_incomplete_reason] ?? "The handshake could not be matched."} No latency is estimated for missing steps.</p>
      )}
      {retx > 0 && (
        <p className="mt-2 text-xs text-ink-2">
          {c.tcp_syn_retransmissions ? `${c.tcp_syn_retransmissions} SYN retransmission(s)` : ""}{c.tcp_syn_retransmissions && c.tcp_syn_ack_retransmissions ? " and " : ""}
          {c.tcp_syn_ack_retransmissions ? `${c.tcp_syn_ack_retransmissions} SYN-ACK retransmission(s)` : ""} were seen, so the times above include the retransmission delay and are not a clean round-trip measurement.
        </p>
      )}
    </section>
  );
}

function HandshakeByDomain({ summary }: { summary: ConnectionSummary }) {
  const rows = summary.handshake_by_domain ?? [];
  if (rows.length === 0) return null;
  return (
    <Card padded={false} title="Average TCP handshake by domain"
      subtitle={`${formatNumber(summary.handshakes_timed)} completed handshakes timed${summary.avg_handshake_ms != null ? ` · ${formatMs(summary.avg_handshake_ms)} average` : ""} · ${formatNumber(summary.handshakes_incomplete)} incomplete (not timed) · domains are inferred from DNS`}>
      <DataTable rowKey={(d) => d.domain} caption="Average TCP handshake by domain" rows={rows.slice(0, 10)}
        columns={[
          { header: "Domain", cell: (d) => <Mono>{d.domain}</Mono> },
          { header: "Average handshake", align: "right", cell: (d) => formatMs(d.avg_handshake_ms) },
          { header: "Min – max", align: "right", cell: (d) => `${formatMs(d.min_handshake_ms)} – ${formatMs(d.max_handshake_ms)}` },
          { header: "Handshakes", align: "right", cell: (d) => formatNumber(d.samples) },
        ]} />
    </Card>
  );
}
