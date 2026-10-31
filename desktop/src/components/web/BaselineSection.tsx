import { useCallback, useEffect, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { DomainBaselineView, HistoryPoint, MetricComparison } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { SeriesChart } from "../charts/SeriesChart";
import { Card } from "../ui/Card";
import { DataTable } from "../ui/DataTable";
import { Button, ErrorPanel, Spinner } from "../ui/feedback";
import { formatMs, formatNumber } from "../../lib/format";
import { AnomalyCard, formatMetric } from "./AnomalyCard";

const STATUS: Record<MetricComparison["status"], string> = {
  normal: "Normal", anomalous: "Unusual", insufficient_baseline: "Still learning", insufficient_current: "Too few samples", no_data: "Not measured",
};

function series(history: HistoryPoint[], key: keyof HistoryPoint, scale = 1) {
  return history.flatMap((p) => { const v = p[key]; return typeof v === "number" ? [{ t: p.t, v: v * scale }] : []; });
}

/** Historical baseline vs this capture for one domain, plus the stored history as charts. */
export function BaselineSection({ analysisId, domain }: { analysisId: string; domain: string }) {
  const api = useApi();
  const [view, setView] = useState<DomainBaselineView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setView(null); setError(null);
    api.getDomainBaseline(analysisId, domain, signal).then(setView).catch((e) => {
      if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not load the historical baseline.");
    });
  }, [api, analysisId, domain]);
  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  if (error) return <ErrorPanel title="Historical baseline unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel>;
  if (!view) return <Spinner label="Loading historical baseline…" />;
  if (!view.history_enabled) return <Card title="Historical baseline"><p className="text-sm text-ink-3">Performance history is turned off.</p></Card>;

  const compared = view.comparisons.filter((c) => c.status !== "no_data");
  const h = view.history;
  const learning = view.prior_observations < 5;
  return (
    <>
      {view.anomalies.length > 0 && <AnomalyCard domain={view.domain} anomalies={view.anomalies} />}
      <Card padded={false} title="Historical baseline"
        subtitle={view.prior_observations === 0
          ? "This is the first capture of this domain on this computer: baselines are still being learned."
          : `Compared with ${formatNumber(view.prior_observations)} earlier capture${view.prior_observations === 1 ? "" : "s"} of this domain${learning ? " (a judgement needs at least 5)" : ""}. Stored locally.`}>
        <DataTable rowKey={(c) => c.metric} caption="Baseline versus current" rows={compared} empty="Nothing measurable in this capture to compare."
          columns={[
            { header: "Metric", cell: (c) => c.label },
            { header: "Baseline", align: "right", cell: (c) => c.baseline ? <span title={`mean ${formatMetric(c.unit, c.baseline.mean)}, range ${formatMetric(c.unit, c.baseline.min)}–${formatMetric(c.unit, c.baseline.max)} over ${c.baseline.observations} captures`}>{formatMetric(c.unit, c.baseline.median)}</span> : <span className="text-ink-3">–</span> },
            { header: "Current", align: "right", cell: (c) => c.current == null ? "–" : formatMetric(c.unit, c.current) },
            { header: "Change", align: "right", cell: (c) => c.relative_change == null ? <span className="text-ink-3">–</span> : `${c.relative_change >= 0 ? "+" : ""}${Math.round(c.relative_change * 100)}%` },
            { header: "Status", cell: (c) => (
              <span className={c.status === "anomalous" ? "font-semibold text-sev-medium" : c.status === "normal" ? "" : "text-ink-3"} title={c.note ?? undefined}>
                {c.status === "anomalous" ? "⚠ " : ""}{STATUS[c.status]}{c.status === "insufficient_baseline" && c.baseline ? ` (${c.baseline.observations} of 5)` : ""}
              </span>) },
          ]} />
      </Card>
      <Card title="Historical performance" subtitle="One point per capture of this domain on this computer, oldest first.">
        {h.length < 2
          ? <p className="text-sm text-ink-3">Not enough history to chart yet: this is capture {h.length} of this domain.</p>
          : (
            <div className="space-y-6">
              <SeriesChart title="Latency history" kind="line" formatValue={formatMs} empty="No latency history"
                series={[
                  { key: "hs", label: "TCP handshake", color: "var(--color-series-3)", points: series(h, "tcp_handshake_ms") },
                  { key: "rtt", label: "Average RTT", color: "var(--color-series-1)", points: series(h, "avg_rtt_ms") },
                  { key: "p95", label: "P95 RTT", color: "var(--color-series-2)", points: series(h, "p95_rtt_ms") },
                ]} />
              <SeriesChart title="DNS and response-time history" kind="line" formatValue={formatMs} empty="No DNS or response-time history"
                series={[
                  { key: "dns", label: "DNS latency", color: "var(--color-series-6)", points: series(h, "dns_latency_ms") },
                  { key: "resp", label: "HTTP response", color: "var(--color-series-4)", points: series(h, "response_ms") },
                ]} />
              <SeriesChart title="Retransmission and failure rate history" kind="line" formatValue={(v) => `${v.toFixed(1)}%`} empty="No loss history"
                series={[
                  { key: "retx", label: "Retransmission rate", color: "var(--color-series-2)", points: series(h, "retransmission_rate", 100) },
                  { key: "fail", label: "Connection failure rate", color: "var(--color-series-5)", points: series(h, "failure_rate", 100) },
                ]} />
            </div>
          )}
        <p className="mt-3 text-xs text-ink-3">History points are aggregates only (domain, latency and rate figures); the capture itself is never stored.</p>
      </Card>
    </>
  );
}
