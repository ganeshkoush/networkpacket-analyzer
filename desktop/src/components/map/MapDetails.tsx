import type { MapConnection, MapEdge, MapFinding, MapNode, NetworkMapData } from "../../api/types";
import { STATE_STYLE, kindLabelFor, latencyText } from "../../lib/mapState";
import { endpoint, formatBytes, formatDuration, formatMs, formatNumber, formatTime } from "../../lib/format";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Button } from "../ui/feedback";

export type MapSelection =
  | { type: "node"; id: string } | { type: "edge"; id: string } | { type: "connection"; id: string } | { type: "finding"; id: string };

const MAX_LISTED = 25;
const Row = ({ k, children }: { k: string; children: React.ReactNode }) => (<div className="contents"><dt className="text-ink-3">{k}</dt><dd className="min-w-0 break-words font-mono text-ink">{children}</dd></div>);
const State = ({ state }: { state: keyof typeof STATE_STYLE }) => <span className={`font-medium ${STATE_STYLE[state].text}`}>{STATE_STYLE[state].label}</span>;

function ConnectionList({ ids, data, onSelect }: { ids: string[]; data: NetworkMapData; onSelect: (s: MapSelection) => void }) {
  const byId = new Map(data.connections.map((c) => [c.id, c]));
  const rows = ids.map((i) => byId.get(i)).filter((c): c is MapConnection => !!c);
  if (!rows.length) return <p className="text-xs text-ink-3">No connection detail is kept for this.</p>;
  return (
    <ul aria-label="Connections" className="space-y-1">
      {rows.slice(0, MAX_LISTED).map((c) => (
        <li key={c.id}>
          <button type="button" onClick={() => onSelect({ type: "connection", id: c.id })}
            className="w-full rounded border border-line px-2 py-1 text-left text-[12px] hover:bg-surface-2">
            <span className="font-mono">{c.protocol} {endpoint(c.local_ip, c.local_port)} → {endpoint(c.remote_ip, c.remote_port)}</span>
            <span className="block text-ink-3">{formatBytes(c.bytes)} · {formatDuration(c.duration_seconds)} · <span className={STATE_STYLE[c.health].text}>{STATE_STYLE[c.health].label}</span></span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function FindingList({ ids, data, onSelect }: { ids: string[]; data: NetworkMapData; onSelect: (s: MapSelection) => void }) {
  const found = ids.map((i) => data.findings.find((f) => f.id === i)).filter((f): f is MapFinding => !!f);
  if (!found.length) return null;
  return (
    <div className="mt-3">
      <h4 className="text-xs font-semibold uppercase tracking-wide text-ink-2">Security findings</h4>
      <ul aria-label="Security findings" className="mt-1 space-y-1">
        {found.map((f) => (
          <li key={f.id}>
            <button type="button" onClick={() => onSelect({ type: "finding", id: f.id })} className="flex w-full items-center gap-2 rounded border border-sev-critical/40 px-2 py-1 text-left text-[12px] hover:bg-surface-2">
              <SeverityBadge severity={f.severity} /><span className="min-w-0 truncate">{f.title}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NodeDetails({ n, data, onSelect, onOpenDomain }: { n: MapNode; data: NetworkMapData; onSelect: (s: MapSelection) => void; onOpenDomain: (d: string) => void }) {
  const lat = latencyText(n.latency_ms, n.latency_kind, formatMs);
  return (
    <>
      <p className="text-[11px] uppercase tracking-wide text-ink-3">{kindLabelFor(n)}</p>
      <h3 className="break-all font-mono text-[15px] font-semibold">{n.label}</h3>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        <Row k="State"><State state={n.state} /></Row>
        {n.connections > 0 && <Row k="Connections">{formatNumber(n.connections)}</Row>}
        {n.bytes > 0 && <Row k="Traffic">{formatBytes(n.bytes)}</Row>}
        {lat && <Row k="Latency">{lat}</Row>}
        {n.ip && n.kind !== "ip" && <Row k="Address">{n.ip}</Row>}
        {n.port != null && <Row k="Port">{n.protocol}/{n.port}</Row>}
        {n.members != null && <Row k="Folded in">{n.members} {n.tier === 4 ? "ports" : "destinations"}</Row>}
      </dl>
      {n.state_reasons.length > 0 && <ul aria-label="Why this state" className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-ink-2">{n.state_reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
      {n.kind === "domain" && n.domain && <Button className="mt-3" variant="secondary" onClick={() => onOpenDomain(n.domain!)}>Open domain details</Button>}
      {n.kind === "domain" && <p className="mt-2 text-xs text-ink-3">Domains are inferred from DNS lookups, not read from the traffic.</p>}
      {n.kind === "group" && <p className="mt-2 text-xs text-ink-3">These addresses were contacted without a DNS lookup in this capture (cached, hard-coded, or encrypted DNS), so no domain name can be inferred for them.</p>}
      {n.kind === "application" && <p className="mt-2 text-xs text-ink-3">Application names come from this computer's operating system at the moment snapshots were taken, not from the captured packets.</p>}
      {n.kind === "other" && <p className="mt-2 text-xs text-ink-3">{n.tier === 4 ? "Less-used ports of this address are folded into this node to keep the map readable. Their connections are listed below." : "Lower-traffic destinations are folded into this node to keep the map readable. Narrow the filters to see them individually."}</p>}
      {!n.detail_available && <p className="mt-2 text-xs text-ink-3">Only known from a security finding: no connection detail is kept for this address.</p>}
      <FindingList ids={n.finding_ids} data={data} onSelect={onSelect} />
      {n.connection_ids.length > 0 && <div className="mt-3"><h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-2">Connections ({formatNumber(n.connections)})</h4>
        <ConnectionList ids={n.connection_ids} data={data} onSelect={onSelect} />{n.connections > n.connection_ids.length && <p className="mt-1 text-xs text-ink-3">Showing {n.connection_ids.length} of {formatNumber(n.connections)}.</p>}</div>}
    </>
  );
}

function EdgeDetails({ e, data, onSelect }: { e: MapEdge; data: NetworkMapData; onSelect: (s: MapSelection) => void }) {
  const label = (id: string) => data.nodes.find((n) => n.id === id)?.label ?? id;
  const lat = latencyText(e.latency_ms, e.latency_kind, formatMs);
  return (
    <>
      <p className="text-[11px] uppercase tracking-wide text-ink-3">Connections</p>
      <h3 className="break-all font-mono text-[14px] font-semibold">{label(e.source)} → {label(e.target)}</h3>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        <Row k="State"><State state={e.state} /></Row>
        <Row k="Connections">{formatNumber(e.connections)}</Row>
        {e.protocol && <Row k="Protocol">{e.protocol}</Row>}
        {e.ports.length > 0 && <Row k="Ports">{e.ports.join(", ")}</Row>}
        {lat && <Row k="Latency">{lat}</Row>}
        <Row k="Traffic">{formatBytes(e.bytes)}</Row>
      </dl>
      <div className="mt-3"><h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-2">Connections</h4><ConnectionList ids={e.connection_ids} data={data} onSelect={onSelect} /></div>
    </>
  );
}

function ConnectionDetails({ c }: { c: MapConnection }) {
  return (
    <>
      <p className="text-[11px] uppercase tracking-wide text-ink-3">Connection</p>
      <h3 className="break-all font-mono text-[14px] font-semibold">{c.protocol} {endpoint(c.local_ip, c.local_port)} → {endpoint(c.remote_ip, c.remote_port)}</h3>
      <dl aria-label="Connection details" className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        <Row k="State"><State state={c.health} /></Row>
        {c.domain && <Row k="Domain">{c.domain} <span className="font-sans text-ink-3">(inferred from DNS)</span></Row>}
        <Row k="Started">{formatTime(c.start_time)}</Row><Row k="Ended">{formatTime(c.end_time)}</Row>
        <Row k="Duration">{formatDuration(c.duration_seconds)}</Row>
        <Row k="Traffic">{formatBytes(c.bytes)} · {formatNumber(c.packets)} packets</Row>
        {c.state && <Row k="TCP state">{c.state.replace("_", " ").toLowerCase()}</Row>}
        {c.handshake_ms != null && <Row k="TCP handshake">{formatMs(c.handshake_ms)} <span className="font-sans text-ink-3">(set-up time)</span></Row>}
        {c.rtt_ms != null && <Row k="Round-trip time">{formatMs(c.rtt_ms)}</Row>}
        {c.retransmissions != null && c.retransmissions > 0 && <Row k="Retransmissions">{c.retransmissions} <span className="font-sans text-ink-3">(heuristic)</span></Row>}
        {(c.application || c.process_name) && <Row k="Application">{c.application ?? c.process_name} <span className="font-sans text-ink-3">(from the operating system)</span></Row>}
      </dl>
      {c.health_reasons.length > 0 && <ul aria-label="Why this state" className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-ink-2">{c.health_reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
    </>
  );
}

function FindingDetails({ f, onOpenFinding }: { f: MapFinding; onOpenFinding: (id: string) => void }) {
  return (
    <>
      <p className="text-[11px] uppercase tracking-wide text-ink-3">Security finding</p>
      <div className="mt-1 flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-[12px] text-ink-3">confidence {Math.round(f.confidence * 100)}%</span></div>
      <h3 className="mt-1 text-[14px] font-semibold">{f.title}</h3>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        {f.source_ip && <Row k="Source">{f.source_ip}</Row>}{f.destination_ip && <Row k="Destination">{f.destination_ip}</Row>}
      </dl>
      <p className="mt-2 text-xs text-ink-3">A finding is a possibility for a person to check, not a verdict.</p>
      <Button className="mt-3" variant="secondary" onClick={() => onOpenFinding(f.id)}>Open finding</Button>
    </>
  );
}

/** Side panel for whatever was clicked on the map: a node, a group of connections, one connection, or a finding. */
export function MapDetails({ data, selection, onSelect, onOpenDomain, onOpenFinding }: {
  data: NetworkMapData; selection: MapSelection | null; onSelect: (s: MapSelection | null) => void; onOpenDomain: (d: string) => void; onOpenFinding: (id: string) => void;
}) {
  const node = selection?.type === "node" ? data.nodes.find((n) => n.id === selection.id) : undefined;
  const edge = selection?.type === "edge" ? data.edges.find((e) => e.id === selection.id) : undefined;
  const conn = selection?.type === "connection" ? data.connections.find((c) => c.id === selection.id) : undefined;
  const finding = selection?.type === "finding" ? data.findings.find((f) => f.id === selection.id) : undefined;
  return (
    <aside aria-label="Map details" className="rounded-lg border border-line bg-surface p-4">
      {!node && !edge && !conn && !finding && (
        <p className="text-sm text-ink-3">Click a node to see its details, a line to see its connections, or a ⚠ finding badge. Scroll to zoom and drag to pan.</p>
      )}
      {node && <NodeDetails n={node} data={data} onSelect={onSelect} onOpenDomain={onOpenDomain} />}
      {edge && <EdgeDetails e={edge} data={data} onSelect={onSelect} />}
      {conn && <ConnectionDetails c={conn} />}
      {finding && <FindingDetails f={finding} onOpenFinding={onOpenFinding} />}
      {(node || edge || conn || finding) && <Button className="mt-4" variant="ghost" onClick={() => onSelect(null)}>Clear selection</Button>}
    </aside>
  );
}
