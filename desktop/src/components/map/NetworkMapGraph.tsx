import { useMemo } from "react";
import { Background, Controls, MiniMap, Panel, Position, ReactFlow, useStore, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { NetworkMapData } from "../../api/types";
import { NODE_H, NODE_W, layoutMap } from "../../lib/mapLayout";
import { STATE_STYLE } from "../../lib/mapState";
import { LABEL_MIN_ZOOM, MapEdgeView, type MapFlowEdge } from "./MapEdgeView";
import { MapNodeView, type MapFlowNode } from "./MapNodeView";
import type { MapSelection } from "./MapDetails";

// Node size and handle positions are known up front (fixed-size nodes), so edges can be drawn on the first paint
// instead of waiting for the library to measure the DOM.
const HANDLES = [
  { id: null, type: "target" as const, position: Position.Top, x: NODE_W / 2, y: 0, width: 1, height: 1 },
  { id: null, type: "source" as const, position: Position.Bottom, x: NODE_W / 2, y: NODE_H, width: 1, height: 1 },
];
const LABEL_STEP = 160;   // label width (150) + margin, so labels of lines into the same node never touch; node pitch is 236
const nodeTypes = { map: MapNodeView };
const edgeTypes = { map: MapEdgeView };

/** Tells the user why the lines have no labels when the map is zoomed far out. */
function ZoomHint() {
  const zoom = useStore((s) => s.transform[2]);
  if (zoom >= LABEL_MIN_ZOOM) return null;
  return <Panel position="bottom-center"><span className="rounded bg-surface px-2 py-1 text-xs text-ink-2">Zoom in to see connection details on the lines</span></Panel>;
}

/** The zoomable, pannable graph (React Flow). Layout is the deterministic layered one from lib/mapLayout. */
export function NetworkMapGraph({ data, selection, onSelect }: { data: NetworkMapData; selection: MapSelection | null; onSelect: (s: MapSelection | null) => void }) {
  const { nodes, edges, fitKey } = useMemo(() => {
    const pos = layoutMap(data.nodes, data.edges);
    const labels = new Map(data.nodes.map((n) => [n.id, n.label]));
    const ns: MapFlowNode[] = data.nodes.map((n) => ({
      id: n.id, type: "map", position: pos.get(n.id) ?? { x: 0, y: 0 }, width: NODE_W, height: NODE_H, handles: HANDLES, draggable: false, connectable: false,
      data: { node: n, selected: selection?.type === "node" && selection.id === n.id, onSelect: (id: string) => onSelect({ type: "node", id }) },
    }));
    // Lines that arrive at the same node get their labels spread sideways (ordered by where they come from).
    const incoming = new Map<string, string[]>();
    for (const e of [...data.edges].sort((a, b) => (pos.get(a.source)?.x ?? 0) - (pos.get(b.source)?.x ?? 0) || a.id.localeCompare(b.id))) {
      incoming.set(e.target, [...(incoming.get(e.target) ?? []), e.id]);
    }
    const es: MapFlowEdge[] = data.edges.map((e) => {
      const group = incoming.get(e.target) ?? [e.id];
      return {
        id: e.id, type: "map", source: e.source, target: e.target, selectable: false, focusable: false,
        data: { edge: e, sourceLabel: labels.get(e.source) ?? e.source, targetLabel: labels.get(e.target) ?? e.target, selected: selection?.type === "edge" && selection.id === e.id,
          onSelect: (id: string) => onSelect({ type: "edge", id }), labelShiftX: (group.indexOf(e.id) - (group.length - 1) / 2) * LABEL_STEP },
      };
    });
    return { nodes: ns, edges: es, fitKey: data.nodes.map((n) => n.id).join("|") };
  }, [data, selection, onSelect]);

  return (
    <div className="h-[max(560px,calc(100vh-340px))] w-full overflow-hidden rounded-lg border border-line bg-bg" role="region" aria-label="Network map">
      <ReactFlow<Node & MapFlowNode, Edge & MapFlowEdge> key={fitKey} nodes={nodes as MapFlowNode[]} edges={edges as MapFlowEdge[]} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
        fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.1} maxZoom={2} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false}
        // A click handler is what makes the library give nodes pointer events: without one (dragging and selecting are
        // off) its nodes are pointer-events:none and real mouse clicks fall through to the background pane.
        onNodeClick={(_, n) => onSelect({ type: "node", id: n.id })}
        onPaneClick={() => onSelect(null)} colorMode="dark" aria-label="Interactive network map: scroll to zoom, drag to pan">
        <Background gap={24} />
        <Controls showInteractive={false} />
        <ZoomHint />
        <MiniMap style={{ width: 150, height: 100 }} pannable zoomable nodeColor={(n) => STATE_STYLE[(n.data as { node: { state: keyof typeof STATE_STYLE } }).node.state].color} maskColor="rgba(0,0,0,0.5)" />
      </ReactFlow>
    </div>
  );
}
