import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import type { MapNode } from "../../api/types";
import { STATE_STYLE, kindLabelFor, latencyText } from "../../lib/mapState";
import { NODE_H, NODE_W } from "../../lib/mapLayout";
import { formatBytes, formatMs, formatNumber } from "../../lib/format";

export type MapNodeData = { node: MapNode; selected: boolean; onSelect: (id: string) => void } & Record<string, unknown>;
export type MapFlowNode = Node<MapNodeData, "map">;

/** One node of the network map: what it is, how it is doing (as text and colour), and its headline numbers. */
export function MapNodeView({ data }: NodeProps<MapFlowNode>) {
  const { node: n, selected, onSelect } = data;
  const s = STATE_STYLE[n.state];
  const lat = latencyText(n.latency_ms, n.latency_kind, formatMs);
  const findings = n.finding_ids.length;
  const summary = [
    n.connections ? `${formatNumber(n.connections)} connection${n.connections === 1 ? "" : "s"}` : null, lat, n.bytes ? formatBytes(n.bytes) : null,
  ].filter(Boolean).join(" · ");
  return (
    <>
      <Handle type="target" position={Position.Top} isConnectable={false} style={{ opacity: 0 }} />
      <button type="button" onClick={() => onSelect(n.id)} aria-pressed={selected}
        aria-label={`${kindLabelFor(n)} ${n.label}, ${s.label}${findings ? `, ${findings} security finding${findings === 1 ? "" : "s"}` : ""}`}
        style={{ width: NODE_W, height: NODE_H, borderColor: s.color, outlineColor: s.color }}
        className={`flex flex-col justify-between rounded-md border-2 bg-surface px-2.5 py-1.5 text-left shadow-sm hover:bg-surface-2 ${selected ? "outline outline-2 outline-offset-2" : ""} ${n.detail_available ? "" : "border-dashed"}`}>
        <span className="flex items-center justify-between gap-2">
          <span className="truncate font-mono text-[12.5px] font-semibold text-ink" title={n.label}>{n.label}</span>
          <span className="shrink-0 text-[9px] uppercase tracking-wide text-ink-3">{kindLabelFor(n)}</span>
        </span>
        <span className="truncate text-[11px] text-ink-2" title={[n.sublabel, summary].filter(Boolean).join(" · ")}>{n.sublabel && !summary ? n.sublabel : summary || n.sublabel || " "}</span>
        <span className="flex items-center justify-between gap-2 text-[10px]">
          <span className={`inline-flex items-center gap-1 font-medium ${s.text}`}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} aria-hidden />{s.label}
          </span>
          {findings > 0 && <span className="font-semibold text-sev-critical">⚠ {findings} finding{findings === 1 ? "" : "s"}</span>}
        </span>
      </button>
      <Handle type="source" position={Position.Bottom} isConnectable={false} style={{ opacity: 0 }} />
    </>
  );
}
