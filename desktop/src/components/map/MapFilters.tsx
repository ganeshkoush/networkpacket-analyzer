import type { MapState } from "../../api/types";
import { formatTime } from "../../lib/format";
import { STATE_STYLE } from "../../lib/mapState";
import { Button } from "../ui/feedback";

export interface MapFilterState {
  search: string; protocol: "" | "TCP" | "UDP"; health: "" | MapState; local: string | undefined;
  range: [number, number];  // 0..1000 along the capture's time span
  includeApplications: boolean; maxNodes: number;
}
export const FULL_RANGE: [number, number] = [0, 1000];
export const DEFAULT_FILTERS: MapFilterState = { search: "", protocol: "", health: "", local: undefined, range: FULL_RANGE, includeApplications: false, maxNodes: 60 };
export const isFiltered = (f: MapFilterState) => !!(f.search.trim() || f.protocol || f.health || f.range[0] > 0 || f.range[1] < 1000);

/** Epoch seconds at a slider position (0..1000) of the capture's time span. */
export const rangeToTime = (pos: number, start: number, end: number) => start + ((end - start) * pos) / 1000;

const field = "rounded-md border border-line bg-bg px-2.5 py-1 text-sm text-ink placeholder:text-ink-3";

export function MapFilters({ filters, onChange, localHosts, selectedLocal, captureStart, captureEnd }: {
  filters: MapFilterState; onChange: (f: MapFilterState) => void; localHosts: { ip: string; connections: number }[]; selectedLocal: string;
  captureStart: number | null; captureEnd: number | null;
}) {
  const set = <K extends keyof MapFilterState>(k: K, v: MapFilterState[K]) => onChange({ ...filters, [k]: v });
  const canSlice = captureStart != null && captureEnd != null && captureEnd > captureStart;
  const from = canSlice ? formatTime(rangeToTime(filters.range[0], captureStart!, captureEnd!)) : null;
  const to = canSlice ? formatTime(rangeToTime(filters.range[1], captureStart!, captureEnd!)) : null;
  return (
    <div className="space-y-3 rounded-lg border border-line bg-surface p-3">
      <div className="flex flex-wrap items-center gap-2">
        <input type="search" aria-label="Search the map" placeholder="Search domain, IP, port…" value={filters.search} onChange={(e) => set("search", e.target.value)} className={`w-56 ${field}`} />
        <select aria-label="Protocol" value={filters.protocol} onChange={(e) => set("protocol", e.target.value as MapFilterState["protocol"])} className={field}>
          <option value="">Any protocol</option><option value="TCP">TCP</option><option value="UDP">UDP</option>
        </select>
        <select aria-label="Health" value={filters.health} onChange={(e) => set("health", e.target.value as MapFilterState["health"])} className={field}>
          <option value="">Any health</option>
          {(["healthy", "degraded", "suspicious", "unknown"] as const).map((s) => <option key={s} value={s}>{STATE_STYLE[s].label}</option>)}
        </select>
        <select aria-label="Local host" value={filters.local ?? selectedLocal} onChange={(e) => set("local", e.target.value)} className={field}>
          {localHosts.map((h) => <option key={h.ip} value={h.ip}>{h.ip} ({h.connections})</option>)}
          <option value="all">All local hosts</option>
        </select>
        <select aria-label="Node budget" value={filters.maxNodes} onChange={(e) => set("maxNodes", Number(e.target.value))} className={field}>
          {[30, 60, 100, 150].map((n) => <option key={n} value={n}>Up to {n} nodes</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-sm text-ink-2">
          <input type="checkbox" checked={filters.includeApplications} onChange={(e) => set("includeApplications", e.target.checked)} />
          Show applications
        </label>
        {isFiltered(filters) && <Button variant="ghost" onClick={() => onChange({ ...DEFAULT_FILTERS, local: filters.local, includeApplications: filters.includeApplications, maxNodes: filters.maxNodes })}>Clear filters</Button>}
      </div>
      {canSlice && (
        <div className="flex flex-wrap items-center gap-3 text-xs text-ink-2">
          <span className="text-ink-3">Time range</span>
          <input type="range" min={0} max={1000} step={1} aria-label="Time range start" value={filters.range[0]}
            onChange={(e) => set("range", [Math.min(Number(e.target.value), filters.range[1]), filters.range[1]])} className="w-40" />
          <input type="range" min={0} max={1000} step={1} aria-label="Time range end" value={filters.range[1]}
            onChange={(e) => set("range", [filters.range[0], Math.max(Number(e.target.value), filters.range[0])])} className="w-40" />
          <span className="font-mono" aria-live="polite">{from} → {to}</span>
        </div>
      )}
    </div>
  );
}
