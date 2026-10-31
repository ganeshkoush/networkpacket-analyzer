import type { MapNodeKind, MapState } from "../api/types";

/** Colour and text for each health state. The text is always shown so colour is never the only signal. */
export const STATE_STYLE: Record<MapState, { label: string; color: string; text: string }> = {
  healthy: { label: "Healthy", color: "var(--color-series-3)", text: "text-series-3" },
  degraded: { label: "Degraded", color: "var(--color-sev-medium)", text: "text-sev-medium" },
  suspicious: { label: "Suspicious", color: "var(--color-sev-critical)", text: "text-sev-critical" },
  unknown: { label: "No health data", color: "var(--color-ink-3)", text: "text-ink-3" },
};

export const KIND_LABEL: Record<MapNodeKind, string> = {
  local: "This computer", application: "Application", domain: "Domain", group: "No DNS name", ip: "IP address", port: "Port", other: "More destinations",
};

/** "More destinations" folds whole destinations (tier 2); the same kind at the port tier folds ports. */
export const kindLabelFor = (n: { kind: MapNodeKind; tier: number }): string => (n.kind === "other" && n.tier === 4 ? "More ports" : KIND_LABEL[n.kind]);

export const latencyText = (ms: number | null, kind: "rtt" | "handshake" | null, fmt: (v: number) => string): string | null =>
  ms == null ? null : `${fmt(ms)} ${kind === "handshake" ? "handshake" : "RTT"}`;
