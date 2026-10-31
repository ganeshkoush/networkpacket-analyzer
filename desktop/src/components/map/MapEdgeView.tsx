import { BaseEdge, EdgeLabelRenderer, getBezierPath, useStore, type Edge, type EdgeProps } from "@xyflow/react";
import type { MapEdge } from "../../api/types";
import { STATE_STYLE, latencyText } from "../../lib/mapState";
import { formatBytes, formatMs } from "../../lib/format";

export type MapEdgeData = {
  edge: MapEdge; sourceLabel: string; targetLabel: string; selected: boolean; onSelect: (id: string) => void;
  labelShiftX: number;  // sideways shift when several lines arrive at the same node, so their labels do not stack
} & Record<string, unknown>;
export type MapFlowEdge = Edge<MapEdgeData, "map">;

export const LABEL_MIN_ZOOM = 0.45;  // below this the labels would be an unreadable smear: the numbers stay in the detail panel
const LABEL_LIFT = 34;               // the label sits just above the node the line points to, inside the gap between rows

/** A group of connections between two nodes: thickness follows traffic, colour follows state, the label carries the facts. */
export function MapEdgeView({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps<MapFlowEdge>) {
  const zoom = useStore((s) => s.transform[2]);
  const [path] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  if (!data) return null;
  // Anchored above the target, not at the curve's midpoint: midpoints of neighbouring lines bunch together and collide.
  const lx = targetX + data.labelShiftX, ly = targetY - LABEL_LIFT;
  const { edge: e, selected, onSelect } = data;
  const color = STATE_STYLE[e.state].color;
  const width = 1.5 + Math.min(4, Math.log10(e.bytes / 1000 + 1));
  const facts = [`${e.connections} conn`, e.protocol, e.ports.length ? e.ports.slice(0, 3).map((p) => `:${p}`).join(" ") : null].filter(Boolean).join(" · ");
  const more = [latencyText(e.latency_ms, e.latency_kind, formatMs), e.bytes ? formatBytes(e.bytes) : null].filter(Boolean).join(" · ");
  return (
    <>
      <BaseEdge id={id} path={path} style={{ stroke: color, strokeWidth: selected ? width + 1.5 : width, strokeDasharray: e.connections === 0 ? "5 4" : undefined, opacity: selected ? 1 : 0.75 }} />
      {zoom >= LABEL_MIN_ZOOM && e.connections > 0 && (
        <EdgeLabelRenderer>
          <button type="button" onClick={() => onSelect(e.id)} aria-pressed={selected}
            aria-label={`Connections from ${data.sourceLabel} to ${data.targetLabel}: ${e.connections}${e.protocol ? `, ${e.protocol}` : ""}`}
            style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly}px)`, pointerEvents: "all", borderColor: color }}
            className="nodrag nopan absolute w-[150px] rounded border bg-bg/95 px-1.5 py-0.5 text-center text-[10px] leading-tight text-ink-2 hover:bg-surface-2">
            <span className="block truncate font-mono text-ink" title={facts}>{facts}</span>
            {more && <span className="block truncate" title={more}>{more}</span>}
          </button>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
