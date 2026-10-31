import type { PerformanceAnomaly } from "../../api/types";
import { formatMs, formatPercent, formatTime } from "../../lib/format";
import { SeverityBadge } from "../ui/SeverityBadge";

/** Value in the metric's own unit: milliseconds, or a rate stored as a fraction. */
export const formatMetric = (unit: "ms" | "%" | "/s", v: number) => (unit === "ms" ? formatMs(v) : unit === "%" ? formatPercent(v) : `${Number(v.toFixed(v < 10 ? 2 : 1))}/s`);
const increase = (a: PerformanceAnomaly) => `${a.deviation >= 0 ? "+" : ""}${Math.round(a.deviation * 100).toLocaleString()}%`;

/** ⚠ Performance anomaly: one domain, with each unusual metric against its own historical baseline. */
export function AnomalyCard({ domain, anomalies, onOpen }: { domain: string; anomalies: PerformanceAnomaly[]; onOpen?: (domain: string) => void }) {
  return (
    <article aria-label={`Performance anomaly ${domain}`} className="rounded-md border border-sev-medium/40 bg-sev-medium/5 p-3">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-sev-medium"><span aria-hidden>⚠</span> Performance anomaly</h3>
      {onOpen
        ? <button type="button" onClick={() => onOpen(domain)} className="mt-1 break-all font-mono text-[15px] font-semibold text-ink underline decoration-dotted underline-offset-2 hover:text-accent">{domain}</button>
        : <p className="mt-1 break-all font-mono text-[15px] font-semibold">{domain}</p>}
      <div className="mt-2 space-y-3">
        {anomalies.map((a) => (
          <section key={a.id} aria-label={a.label}>
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="text-[13px] font-medium">{a.label}:</h4>
              <SeverityBadge severity={a.severity} />
            </div>
            <dl className="mt-1 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 text-[13px]">
              <dt className="text-ink-3">Baseline:</dt><dd className="font-mono">{formatMetric(a.unit, a.baseline)}</dd>
              <dt className="text-ink-3">Current:</dt><dd className="font-mono">{formatMetric(a.unit, a.current_value)}</dd>
              <dt className="text-ink-3">Increase:</dt><dd className="font-mono">{increase(a)}</dd>
              <dt className="text-ink-3">Confidence:</dt><dd>{a.confidence_label}</dd>
            </dl>
            <p className="mt-1 text-xs text-ink-3">
              Typical value over the previous {a.baseline_observations} captures (mean {formatMetric(a.unit, a.baseline_mean)}).
              {a.observations_in_run > 1 ? ` Unusual in ${a.observations_in_run} consecutive captures, since ${formatTime(a.first_seen)}.` : ` Seen ${formatTime(a.last_seen)}.`}
            </p>
            <details className="mt-1 text-xs text-ink-2">
              <summary className="cursor-pointer text-ink-3 hover:text-ink">Evidence</summary>
              <ul className="mt-1 list-disc space-y-0.5 pl-5">{a.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-ink-3">{a.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
            </details>
          </section>
        ))}
      </div>
    </article>
  );
}
