import { describe, expect, it } from "vitest";
import type { MapEdge, MapNode } from "../api/types";
import { GAP_X, GAP_Y, NODE_H, NODE_W, layoutMap } from "./mapLayout";

const node = (id: string, tier: number, bytes = 1000, label = id): MapNode => ({
  id, kind: "domain", label, sublabel: null, tier, state: "healthy", state_reasons: [], connections: 1, bytes, latency_ms: null, latency_kind: null,
  domain: null, ip: null, port: null, protocol: null, finding_ids: [], connection_ids: [], members: null, detail_available: true,
});
const edge = (source: string, target: string): MapEdge => ({ id: `${source}>${target}`, source, target, connections: 1, bytes: 1, protocol: "TCP", ports: [], latency_ms: null, latency_kind: null, state: "healthy", connection_ids: [] });

describe("layoutMap", () => {
  it("puts each tier in its own row, top to bottom", () => {
    const p = layoutMap([node("l", 0), node("d", 2), node("i", 3), node("p", 4)], [edge("l", "d"), edge("d", "i"), edge("i", "p")]);
    expect([p.get("l")!.y, p.get("d")!.y, p.get("i")!.y, p.get("p")!.y]).toEqual([0, 1, 2, 3].map((r) => r * (NODE_H + GAP_Y)));
  });

  it("skips tiers that are not present, so there is no empty band", () => {
    const p = layoutMap([node("l", 0), node("ip", 3)], [edge("l", "ip")]);
    expect(p.get("ip")!.y).toBe(NODE_H + GAP_Y);
  });

  it("never overlaps nodes in a row and keeps the gap", () => {
    const kids = ["a", "b", "c", "d", "e"].map((id) => node(id, 2));
    const p = layoutMap([node("l", 0), ...kids], kids.map((k) => edge("l", k.id)));
    const xs = kids.map((k) => p.get(k.id)!.x).sort((a, b) => a - b);
    for (let i = 1; i < xs.length; i++) expect(xs[i] - xs[i - 1]).toBeGreaterThanOrEqual(NODE_W + GAP_X);
  });

  it("centres children under their parent", () => {
    const kids = [node("a", 2), node("b", 2), node("c", 2)];
    const p = layoutMap([node("l", 0), ...kids], kids.map((k) => edge("l", k.id)));
    const parentCentre = p.get("l")!.x + NODE_W / 2;
    const mean = kids.map((k) => p.get(k.id)!.x + NODE_W / 2).reduce((s, v) => s + v, 0) / 3;
    expect(mean).toBeCloseTo(parentCentre, 0);
  });

  it("orders a row by where the parents are, so edges do not cross needlessly", () => {
    // two domains, each with one address; the address of the left domain must sit left of the other's
    const nodes = [node("l", 0), node("dA", 2, 9000), node("dB", 2, 1000), node("ipB", 3, 5), node("ipA", 3, 1)];
    const p = layoutMap(nodes, [edge("l", "dA"), edge("l", "dB"), edge("dA", "ipA"), edge("dB", "ipB")]);
    const left = p.get("dA")!.x < p.get("dB")!.x ? "A" : "B";
    expect(p.get(`ip${left}`)!.x).toBeLessThan(p.get(`ip${left === "A" ? "B" : "A"}`)!.x);
  });

  it("places higher-traffic siblings first when parents do not decide", () => {
    const p = layoutMap([node("l", 0), node("small", 2, 10), node("big", 2, 9999)], [edge("l", "small"), edge("l", "big")]);
    expect(p.get("big")!.x).toBeLessThan(p.get("small")!.x);
  });

  it("handles a node reachable from two parents (a shared address) once", () => {
    const p = layoutMap([node("l", 0), node("a", 2), node("b", 2), node("ip", 3)], [edge("l", "a"), edge("l", "b"), edge("a", "ip"), edge("b", "ip")]);
    expect(p.size).toBe(4);
    const mid = (p.get("a")!.x + p.get("b")!.x) / 2;
    expect(p.get("ip")!.x).toBeCloseTo(mid, 0);
  });

  it("is deterministic whatever order the nodes arrive in, and copes with an empty map", () => {
    const nodes = [node("l", 0), node("x", 2), node("y", 2), node("z", 3)];
    const edges = [edge("l", "x"), edge("l", "y"), edge("x", "z")];
    expect(Object.fromEntries(layoutMap([...nodes].reverse(), edges))).toEqual(Object.fromEntries(layoutMap(nodes, edges)));
    expect(layoutMap([], []).size).toBe(0);
  });

  it("treats a node with no edges as a root, so it shares the top row instead of floating below", () => {
    const p = layoutMap([node("l", 0), node("x", 2), node("bare", 3)], [edge("l", "x")]);
    expect(p.get("bare")!.y).toBe(0);
  });
});

import { MAX_PER_ROW, SUBROW_GAP, rankNodes } from "./mapLayout";

describe("rankNodes", () => {
  it("ranks by the longest path from a root, so an edge never skips a row it could use", () => {
    const nodes = [node("l", 0), node("d", 2), node("ip", 3), node("direct", 3)];
    const r = rankNodes(nodes, [edge("l", "d"), edge("d", "ip"), edge("l", "direct")]);
    expect([r.get("l"), r.get("d"), r.get("ip"), r.get("direct")]).toEqual([0, 1, 2, 1]);
  });

  it("puts a node reachable by two paths below the deeper one", () => {
    const r = rankNodes([node("a", 0), node("b", 2), node("c", 3)], [edge("a", "b"), edge("b", "c"), edge("a", "c")]);
    expect(r.get("c")).toBe(2);
  });

  it("ignores edges to unknown nodes and self-loops without hanging", () => {
    const r = rankNodes([node("a", 0), node("b", 1)], [edge("a", "b"), edge("a", "ghost"), edge("b", "b")]);
    expect([r.get("a"), r.get("b")]).toEqual([0, 1]);
  });
});

describe("layoutMap: wide rows", () => {
  const kids = Array.from({ length: 13 }, (_, i) => node(`k${i}`, 2, 1000 - i));
  const nodes = [node("l", 0), ...kids];
  const edges = kids.map((k) => edge("l", k.id));

  it("wraps a wide row into stacked sub-rows of at most MAX_PER_ROW", () => {
    const p = layoutMap(nodes, edges);
    const rows = new Map<number, number>();
    for (const k of kids) rows.set(p.get(k.id)!.y, (rows.get(p.get(k.id)!.y) ?? 0) + 1);
    expect([...rows.values()].every((n) => n <= MAX_PER_ROW)).toBe(true);
    expect(rows.size).toBe(Math.ceil(13 / MAX_PER_ROW));
  });

  it("leaves room between sub-rows (for the edge labels) and between ranks", () => {
    const p = layoutMap(nodes, edges);
    const ys = [...new Set(kids.map((k) => p.get(k.id)!.y))].sort((a, b) => a - b);
    expect(ys[1] - ys[0]).toBe(NODE_H + SUBROW_GAP);
    expect(ys[0] - p.get("l")!.y).toBe(NODE_H + GAP_Y);
  });

  it("never overlaps any two nodes, however many there are", () => {
    const many = Array.from({ length: 60 }, (_, i) => node(`n${i}`, i % 3 === 0 ? 2 : 3, 500 - i));
    const es = many.filter((n) => n.tier === 2).map((n) => edge("l", n.id)).concat(many.filter((n) => n.tier === 3).map((n, i) => edge(`n${(i * 3) % 60}`, n.id)));
    const p = layoutMap([node("l", 0), ...many], es);
    const boxes = [...p.values()];
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      const overlap = a.x < b.x + NODE_W && b.x < a.x + NODE_W && a.y < b.y + NODE_H && b.y < a.y + NODE_H;
      expect(overlap).toBe(false);
    }
  });

  it("keeps each sub-row centred on the parents instead of drifting sideways", () => {
    const p = layoutMap(nodes, edges);
    const centre = p.get("l")!.x + NODE_W / 2;
    for (const y of new Set(kids.map((k) => p.get(k.id)!.y))) {
      const xs = kids.filter((k) => p.get(k.id)!.y === y).map((k) => p.get(k.id)!.x + NODE_W / 2);
      expect(xs.reduce((s, v) => s + v, 0) / xs.length).toBeCloseTo(centre, 0);
    }
  });
});
