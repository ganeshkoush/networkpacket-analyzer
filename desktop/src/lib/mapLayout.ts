import type { MapEdge, MapNode } from "../api/types";

export const NODE_W = 196;
export const NODE_H = 72;
export const GAP_X = 40;
export const GAP_Y = 110;      // between rows: holds the edge labels that sit just above each node
export const SUBROW_GAP = 70;  // between the stacked sub-rows of a wide row: also holds those labels
export const MAX_PER_ROW = 7;  // wider rows wrap into sub-rows, so the graph stays roughly square and fit-to-view can zoom in

export interface Placement { x: number; y: number }

/** Row of each node: its longest distance from a root, so every edge goes down by at least one row and never cuts across an unrelated row. */
export function rankNodes(nodes: MapNode[], edges: MapEdge[]): Map<string, number> {
  const rank = new Map(nodes.map((n) => [n.id, 0]));
  const known = new Set(rank.keys());
  const live = edges.filter((e) => known.has(e.source) && known.has(e.target) && e.source !== e.target);
  for (let pass = 0; pass < nodes.length; pass++) {            // longest-path relaxation; a DAG settles in at most `nodes` passes
    let changed = false;
    for (const e of live) {
      const want = rank.get(e.source)! + 1;
      if (want > rank.get(e.target)!) { rank.set(e.target, want); changed = true; }
    }
    if (!changed) break;
  }
  return rank;
}

/**
 * Deterministic layered layout (local host at the top). Within a row nodes are ordered by where their parents sit
 * (barycentre), then by traffic. A row wider than MAX_PER_ROW is dealt out round-robin into stacked sub-rows, so each
 * sub-row spans the whole width and children stay near their parents. Each sub-row is packed left to right and
 * re-centred on its parents. Returns top-left coordinates, which is what the graph library expects.
 */
export function layoutMap(nodes: MapNode[], edges: MapEdge[]): Map<string, Placement> {
  const placed = new Map<string, Placement>();
  const centreX = new Map<string, number>();
  const parents = new Map<string, string[]>();
  for (const e of edges) parents.set(e.target, [...(parents.get(e.target) ?? []), e.source]);

  const rank = rankNodes(nodes, edges);
  const rows = [...new Set(rank.values())].sort((a, b) => a - b);
  const step = NODE_W + GAP_X;
  let y = 0;
  for (const r of rows) {
    const rowNodes = nodes.filter((n) => rank.get(n.id) === r);
    const ideal = new Map<string, number>();
    for (const n of rowNodes) {
      const known = (parents.get(n.id) ?? []).map((p) => centreX.get(p)).filter((v): v is number => v !== undefined);
      ideal.set(n.id, known.length ? known.reduce((s, v) => s + v, 0) / known.length : 0);
    }
    const ordered = [...rowNodes].sort((a, b) => ideal.get(a.id)! - ideal.get(b.id)! || b.bytes - a.bytes || a.label.localeCompare(b.label));
    const subRows = Math.max(1, Math.ceil(ordered.length / MAX_PER_ROW));
    for (let s = 0; s < subRows; s++) {
      const line = ordered.filter((_, i) => i % subRows === s);
      const xs: number[] = [];
      line.forEach((n, i) => { xs.push(i === 0 ? ideal.get(n.id)! : Math.max(ideal.get(n.id)!, xs[i - 1] + step)); });
      const shift = xs.length ? line.reduce((sum, n, i) => sum + (ideal.get(n.id)! - xs[i]), 0) / xs.length : 0;
      line.forEach((n, i) => {
        const cx = xs[i] + shift;
        centreX.set(n.id, cx);
        placed.set(n.id, { x: Math.round(cx - NODE_W / 2), y: y + s * (NODE_H + SUBROW_GAP) });
      });
    }
    y += subRows * NODE_H + (subRows - 1) * SUBROW_GAP + GAP_Y;
  }
  return placed;
}
