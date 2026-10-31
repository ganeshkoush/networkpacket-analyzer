import type { NetworkHealth, NetworkMetric, NetworkMetricStatus } from "../api/types";

export const HEALTH_STYLE: Record<NetworkHealth, { text: string; border: string; bg: string; label: string; blurb: string }> = {
  Healthy: { text: "text-series-3", border: "border-series-3/50", bg: "bg-series-3/10", label: "HEALTHY", blurb: "Measurements look in line with what is usual for this computer." },
  Degraded: { text: "text-sev-medium", border: "border-sev-medium/50", bg: "bg-sev-medium/10", label: "DEGRADED", blurb: "Some measurements are clearly worse than this computer's usual." },
  Poor: { text: "text-sev-critical", border: "border-sev-critical/50", bg: "bg-sev-critical/10", label: "POOR", blurb: "Measurements are clearly worse than usual and bad in absolute terms." },
  Unknown: { text: "text-ink-2", border: "border-line", bg: "bg-surface-2", label: "UNKNOWN", blurb: "This capture has too little measurable traffic to rate." },
};

export const STATUS_STYLE: Record<NetworkMetricStatus, { text: string; label: string }> = {
  ok: { text: "text-series-3", label: "Normal" },
  elevated: { text: "text-sev-medium", label: "Elevated" },
  high: { text: "text-sev-critical", label: "High" },
  info: { text: "text-ink-2", label: "Info" },
  unmeasured: { text: "text-ink-3", label: "Not measured" },
};

const fmt = (n: number, digits: number) => n.toLocaleString("en-US", { maximumFractionDigits: digits });

/** A measurement with its unit, e.g. 6.2%, 102 ms. */
export function formatMetric(value: number | null, unit: NetworkMetric["unit"]): string {
  if (value == null) return "—";
  switch (unit) {
    case "%": return `${fmt(value * 100, value < 0.1 ? 1 : 0)}%`;
    case "ms": return `${fmt(value, value < 10 ? 1 : 0)} ms`;
    case "seconds": return `${fmt(value, 1)} s`;
    case "bytes": return `${fmt(value, 0)} B`;
    case "packets/s": return `${fmt(value, 1)} packets/s`;
    default: return fmt(value, 0);
  }
}

/** "+163%" / "−12%" relative to normal, or an em dash. */
export function formatChange(change: number | null): string {
  if (change == null) return "—";
  const pct = Math.round(change * 100);
  return `${pct > 0 ? "+" : pct < 0 ? "−" : ""}${Math.abs(pct)}%`;
}

export const CATEGORY_TITLES: Record<NetworkMetric["category"], string> = {
  traffic: "Overall traffic", dns: "DNS latency", handshake: "TCP handshake latency", rtt: "Round-trip time (RTT)", retransmissions: "Retransmissions",
  resets: "TCP resets", failures: "Connection failures", response: "Response time", domains: "Domain performance", anomalies: "Performance anomalies",
  findings: "Security findings", baseline: "Historical baseline",
};
export const CATEGORY_ORDER = Object.keys(CATEGORY_TITLES) as NetworkMetric["category"][];
