import type { DomainHealth } from "../../api/types";

const STYLE: Record<DomainHealth, { label: string; cls: string; dot: string }> = {
  good: { label: "Good", cls: "text-series-3 border-series-3/40 bg-series-3/10", dot: "bg-series-3" },
  fair: { label: "Fair", cls: "text-sev-medium border-sev-medium/40 bg-sev-medium/10", dot: "bg-sev-medium" },
  poor: { label: "Poor", cls: "text-sev-critical border-sev-critical/40 bg-sev-critical/10", dot: "bg-sev-critical" },
  unknown: { label: "Unknown", cls: "text-ink-3 border-line bg-surface-2", dot: "bg-ink-3" },
};

/** Heuristic health rating from measured latency/loss indicators (text label always shown, not colour alone). */
export function HealthBadge({ health, reasons = [] }: { health: DomainHealth; reasons?: string[] }) {
  const s = STYLE[health];
  const title = reasons.length ? reasons.join("\n") : health === "unknown" ? "Nothing measurable to rate" : "No concerning indicators measured";
  return (
    <span title={title} aria-label={`Health ${s.label}`}
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${s.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden />{s.label}
    </span>
  );
}
