import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, isAbort } from "../../api/client";
import type { DomainHealth, WebActivityList, WebDomainRow, WebSort } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { Card } from "../ui/Card";
import { DataTable, Mono } from "../ui/DataTable";
import { Button, EmptyState, ErrorPanel, Notice, Spinner } from "../ui/feedback";
import { formatBytes, formatMs, formatNumber } from "../../lib/format";
import { AnomaliesPanel } from "./AnomaliesPanel";
import { DomainDetail } from "./DomainDetail";
import { HistoryControls } from "./HistoryControls";
import { ProcessControls } from "./ProcessControls";
import { HealthBadge } from "./HealthBadge";

export const PAGE_SIZE = 25;
const SORTS: { value: WebSort; label: string }[] = [
  { value: "traffic", label: "Traffic" }, { value: "connections", label: "Connections" }, { value: "dns", label: "DNS latency" },
  { value: "handshake", label: "TCP handshake" }, { value: "rtt", label: "Average RTT" }, { value: "p95", label: "P95 RTT" },
  { value: "health", label: "Health (worst first)" }, { value: "recent", label: "Latest activity" }, { value: "name", label: "Domain name" },
];
const HEALTHS: DomainHealth[] = ["good", "fair", "poor", "unknown"];
const input = "rounded-md border border-line bg-bg px-2.5 py-1 text-sm text-ink placeholder:text-ink-3";

/** Domain / web activity table. Searching, sorting, filtering and paging are done by the backend; this only renders. */
export function WebActivityDashboard({ analysisId }: { analysisId: string }) {
  const api = useApi();
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<WebSort>("traffic");
  const [health, setHealth] = useState<DomainHealth | "">("");
  const [includeDnsOnly, setIncludeDnsOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<WebActivityList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(params.get("domain"));   // e.g. from the network map
  const [attempt, setAttempt] = useState(0);
  const [historyVersion, setHistoryVersion] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(0); }, 250);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api.listWebActivity(analysisId, { search, sort, health: health || undefined, includeDnsOnly, limit: PAGE_SIZE, offset: page * PAGE_SIZE }, controller.signal)
      .then((d) => { setData(d); setError(null); setLoading(false); })
      .catch((e) => { if (!isAbort(e)) { setError(e instanceof ApiError ? e.message : "Could not load web activity."); setLoading(false); } });
    return () => controller.abort();
  }, [api, analysisId, search, sort, health, includeDnsOnly, page, attempt]);

  const filtered = search.trim() !== "" || health !== "";
  const clearFilters = useCallback(() => { setSearchInput(""); setSearch(""); setHealth(""); setPage(0); }, []);

  if (selected) return <DomainDetail analysisId={analysisId} domain={selected} onBack={() => setSelected(null)} />;

  if (error && !data) {
    return <ErrorPanel title="Web activity unavailable" actions={<Button onClick={() => setAttempt((n) => n + 1)}>Retry</Button>}>{error}</ErrorPanel>;
  }
  if (!data) return <Spinner label="Loading web activity…" />;

  const s = data.summary;
  if (s.total_domains === 0) {
    return (
      <EmptyState title="No DNS information available">
        No DNS lookups with usable answers were captured, so connections can't be mapped to domains. DNS may be cached on the host, encrypted (DoH/DoT) or not visible from where this was captured.
      </EmptyState>
    );
  }

  const from = data.total_matching === 0 ? 0 : data.offset + 1;
  const to = data.offset + data.domains.length;
  const counts = HEALTHS.map((h) => `${h[0].toUpperCase()}${h.slice(1)} ${s.health_counts[h] ?? 0}`).join(" · ");
  const noConnections = data.total_matching === 0 && !filtered && s.domains_with_connections === 0;

  return (
    <div className="space-y-4">
      {error && <ErrorPanel title="Could not refresh" actions={<Button onClick={() => setAttempt((n) => n + 1)}>Retry</Button>}>{error}</ErrorPanel>}
      <AnomaliesPanel analysisId={analysisId} reloadKey={historyVersion} onOpenDomain={setSelected} />
      {s.notes.map((n) => <Notice key={n} tone="info">{n}</Notice>)}
      <Card padded={false} title="Domains"
        subtitle={`${formatNumber(s.domains_with_connections)} domains with connections · ${counts}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input type="search" aria-label="Search domains" placeholder="Search domain" value={searchInput} onChange={(e) => setSearchInput(e.target.value)} className={`w-44 ${input}`} />
            <select aria-label="Sort domains" value={sort} onChange={(e) => { setSort(e.target.value as WebSort); setPage(0); }} className={input}>
              {SORTS.map((o) => <option key={o.value} value={o.value}>Sort: {o.label}</option>)}
            </select>
            <select aria-label="Filter by health" value={health} onChange={(e) => { setHealth(e.target.value as DomainHealth | ""); setPage(0); }} className={input}>
              <option value="">Any health</option>
              {HEALTHS.map((h) => <option key={h} value={h}>{h[0].toUpperCase() + h.slice(1)}</option>)}
            </select>
            <label className="flex items-center gap-1.5 text-sm text-ink-2">
              <input type="checkbox" checked={includeDnsOnly} onChange={(e) => { setIncludeDnsOnly(e.target.checked); setPage(0); }} />
              Include DNS-only domains
            </label>
          </div>
        }>
        {loading && <div className="px-4 py-2"><Spinner label="Loading…" /></div>}
        {data.total_matching === 0 ? (
          <div className="p-4">
            {noConnections ? (
              <EmptyState title="No connections found">
                Domains were looked up in this capture, but no connection to them was captured.
                <div className="mt-3"><Button onClick={() => setIncludeDnsOnly(true)}>Show DNS-only domains</Button></div>
              </EmptyState>
            ) : (
              <EmptyState title={filtered ? "No domains match these filters" : "No connections found"}>
                {filtered && <Button onClick={clearFilters}>Clear filters</Button>}
              </EmptyState>
            )}
          </div>
        ) : (
          <>
            <DataTable<WebDomainRow> rowKey={(d) => d.domain} caption="Domain web activity" rows={data.domains}
              onRowClick={(d) => setSelected(d.domain)}
              columns={[
                { header: "Domain", cell: (d) => (
                  <span className="inline-flex items-center gap-2">
                    <Mono>{d.domain}</Mono>
                    {!!d.anomalies && <span className="text-sev-medium" title="Performance differs from this domain's history" aria-label={`${d.anomalies} performance ${d.anomalies === 1 ? "anomaly" : "anomalies"}`}>⚠ {d.anomalies}</span>}
                  </span>) },
                { header: "Connections", align: "right", cell: (d) => formatNumber(d.connections) },
                { header: "Traffic", align: "right", cell: (d) => formatBytes(d.total_bytes) },
                { header: "DNS Latency", align: "right", cell: (d) => formatMs(d.dns_latency_ms) },
                { header: "TCP Handshake", align: "right", cell: (d) => formatMs(d.tcp_handshake_ms) },
                { header: "Avg RTT", align: "right", cell: (d) => formatMs(d.avg_rtt_ms) },
                { header: "P95 RTT", align: "right", cell: (d) => formatMs(d.p95_rtt_ms) },
                { header: "Health", cell: (d) => <HealthBadge health={d.health} reasons={d.health_reasons} /> },
              ]} />
            <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-2 text-xs text-ink-2">
              <span>Showing {formatNumber(from)}–{formatNumber(to)} of {formatNumber(data.total_matching)}</span>
              <span className="flex gap-2">
                <Button variant="secondary" disabled={page === 0 || loading} onClick={() => setPage((p) => p - 1)}>Previous</Button>
                <Button variant="secondary" disabled={to >= data.total_matching || loading} onClick={() => setPage((p) => p + 1)}>Next</Button>
              </span>
            </div>
          </>
        )}
      </Card>
      <ProcessControls />
      <HistoryControls onCleared={() => { setHistoryVersion((v) => v + 1); setAttempt((n) => n + 1); }} />
    </div>
  );
}
