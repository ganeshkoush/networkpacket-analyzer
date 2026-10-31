import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, isAbort } from "../api/client";
import type { NetworkMapData } from "../api/types";
import { MapDetails, type MapSelection } from "../components/map/MapDetails";
import { DEFAULT_FILTERS, FULL_RANGE, MapFilters, isFiltered, rangeToTime, type MapFilterState } from "../components/map/MapFilters";
import { NetworkMapGraph } from "../components/map/NetworkMapGraph";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { STATE_STYLE } from "../lib/mapState";
import { formatBytes, formatNumber } from "../lib/format";
import { useApi } from "../state/ApiContext";
import { useAnalysis } from "../state/AnalysisContext";
import { PageHeader } from "./Placeholder";

const DEBOUNCE_MS = 300;

function Legend() {
  return (
    <ul aria-label="Legend" className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
      {(["healthy", "degraded", "suspicious", "unknown"] as const).map((s) => (
        <li key={s} className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: STATE_STYLE[s].color }} aria-hidden />{STATE_STYLE[s].label}</li>
      ))}
      <li className="text-ink-3">Line thickness follows traffic · dashed: known only from a finding</li>
    </ul>
  );
}

function MapBody({ analysisId }: { analysisId: string }) {
  const api = useApi();
  const navigate = useNavigate();
  const [filters, setFilters] = useState<MapFilterState>(DEFAULT_FILTERS);
  const [applied, setApplied] = useState<MapFilterState>(DEFAULT_FILTERS);   // filters after the debounce: what is actually requested
  const [data, setData] = useState<NetworkMapData | null>(null);
  const [span, setSpan] = useState<[number, number] | null>(null);          // the capture's time span, from the first answer
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<MapSelection | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => { const t = setTimeout(() => setApplied(filters), DEBOUNCE_MS); return () => clearTimeout(t); }, [filters]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    const f = applied;
    const sliced = span != null && (f.range[0] > FULL_RANGE[0] || f.range[1] < FULL_RANGE[1]);
    api.getNetworkMap(analysisId, {
      local: f.local, search: f.search, protocol: f.protocol || undefined, health: f.health || undefined, maxNodes: f.maxNodes, includeApplications: f.includeApplications,
      start: sliced ? rangeToTime(f.range[0], span![0], span![1]) : undefined, end: sliced ? rangeToTime(f.range[1], span![0], span![1]) : undefined,
    }, controller.signal).then((d) => {
      setData(d); setError(null); setLoading(false);
      if (d.capture_start != null && d.capture_end != null) setSpan((s) => s ?? [d.capture_start!, d.capture_end!]);
    }).catch((e) => { if (!isAbort(e)) { setError(e instanceof ApiError ? e.message : "Could not load the network map."); setLoading(false); } });
    return () => controller.abort();
  }, [api, analysisId, applied, span, attempt]);

  const select = useCallback((s: MapSelection | null) => setSelection(s), []);
  const clear = () => setFilters((f) => ({ ...DEFAULT_FILTERS, local: f.local, includeApplications: f.includeApplications, maxNodes: f.maxNodes }));
  const stillThere = useMemo(() => !selection || !data ? true
    : selection.type === "node" ? data.nodes.some((n) => n.id === selection.id) : selection.type === "edge" ? data.edges.some((e) => e.id === selection.id)
    : selection.type === "connection" ? data.connections.some((c) => c.id === selection.id) : data.findings.some((f) => f.id === selection.id), [selection, data]);

  if (error && !data) return <ErrorPanel title="Network map unavailable" actions={<Button onClick={() => setAttempt((n) => n + 1)}>Retry</Button>}>{error}</ErrorPanel>;
  if (!data) return <Spinner label="Building the network map…" />;

  const empty = data.nodes.length === 0;
  return (
    <div className="space-y-3">
      {error && <ErrorPanel title="Could not refresh the map" actions={<Button onClick={() => setAttempt((n) => n + 1)}>Retry</Button>}>{error}</ErrorPanel>}
      <MapFilters filters={filters} onChange={setFilters} localHosts={data.local_hosts} selectedLocal={data.local} captureStart={span?.[0] ?? data.capture_start} captureEnd={span?.[1] ?? data.capture_end} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Legend />
        <span className="text-xs text-ink-3" aria-live="polite">
          {loading ? <Spinner label="Updating…" /> : `${formatNumber(data.shown_connections)} of ${formatNumber(data.total_connections)} connections shown · ${formatNumber(data.nodes.length)} nodes`}
        </span>
      </div>
      {data.findings.length > 0 && !empty && (
        <Notice tone="warn">
          {data.findings.length} security finding{data.findings.length === 1 ? "" : "s"} involve addresses on this map (⚠). Click a marked node to see them.
        </Notice>
      )}
      {data.applications_status && filters.includeApplications && <Notice tone="info">{data.applications_status}</Notice>}
      {empty ? (
        <EmptyState title={isFiltered(filters) ? "No connections match these filters" : "No connections to show"}>
          {isFiltered(filters) ? <Button onClick={clear}>Clear filters</Button> : "This capture has no TCP or UDP connections with detail to draw."}
        </EmptyState>
      ) : (
        <div className="grid gap-3 lg:grid-cols-[1fr_340px]">
          <NetworkMapGraph data={data} selection={stillThere ? selection : null} onSelect={select} />
          <MapDetails data={data} selection={stillThere ? selection : null} onSelect={select}
            onOpenDomain={(d) => navigate(`/web?domain=${encodeURIComponent(d)}`)} onOpenFinding={(id) => navigate(`/findings/${encodeURIComponent(id)}`)} />
        </div>
      )}
      {data.hidden.destinations > 0 && !empty && (
        <p className="text-xs text-ink-3">{formatNumber(data.hidden.destinations)} lower-traffic destination(s) ({formatNumber(data.hidden.connections)} connections, {formatBytes(data.hidden.bytes)}) are folded into one node. Use search, protocol or the time range to look at them.</p>
      )}
      <ul className="space-y-0.5 text-xs text-ink-3">{data.notes.filter((n) => !n.includes("folded into one node")).map((n) => <li key={n}>{n}</li>)}</ul>
    </div>
  );
}

/** Network Map: this computer -> domains -> IP addresses -> ports for the capture that is loaded. */
export function NetworkMap() {
  const { session } = useAnalysis();
  return (
    <>
      <PageHeader title="Network Map" subtitle="Who this computer talked to: domains, the addresses behind them, and the ports used, coloured by how healthy each looks." />
      {session.phase === "idle" && (
        <EmptyState title="No capture loaded" action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>Analyze a capture to see its network map.</EmptyState>
      )}
      {(session.phase === "uploading" || session.phase === "analyzing") && <Spinner label="Analyzing the capture…" />}
      {session.phase === "error" && <ErrorPanel title="The analysis failed" actions={<Link to="/analysis" className={linkButtonClass()}>Back to PCAP Analysis</Link>}>{session.problem.message}</ErrorPanel>}
      {session.phase === "ready" && (session.bundle.analysis.packet_statistics.total_packets === 0
        ? <EmptyState title="This capture contains no packets">There is nothing to map.</EmptyState>
        : <MapBody analysisId={session.bundle.job.id} />)}
    </>
  );
}
