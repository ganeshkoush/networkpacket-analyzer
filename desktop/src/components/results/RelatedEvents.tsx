import { useCallback, useEffect, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { Correlation, CorrelationList, Finding } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { Card } from "../ui/Card";
import { Mono } from "../ui/DataTable";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Button, ErrorPanel, Spinner } from "../ui/feedback";

/** How the performance change lines up in time with the security event, in plain words (never causal). */
export function describeTiming(c: Correlation): string {
  const secs = `${Math.abs(c.time_difference_seconds).toFixed(1)} s`;
  switch (c.temporal_relation) {
    case "overlapping": return `The performance change began ${secs} ${c.time_difference_seconds >= 0 ? "after" : "before"} the security event started, while it was in progress.`;
    case "performance_follows_finding": return `The performance change began ${secs} after the security event started, once it had ended.`;
    case "performance_precedes_finding": return `The performance change began ${secs} before the security event started.`;
    case "same_connections": return "No time window is known for this finding; both were observed on the same connections in this capture.";
    case "capture_level": return "Only capture-level timing is known: both were seen in this capture, but their order within it is not.";
  }
}

const Arrow = ({ label }: { label: string }) => (
  <div className="flex flex-col items-center py-1 text-ink-3" aria-hidden>
    <span className="h-3 w-px bg-line" /><span className="text-lg leading-none">↓</span>
    <span className="sr-only">{label}</span>
  </div>
);

function RelatedEvent({ c }: { c: Correlation }) {
  const shared = [...c.shared_ips, ...c.shared_domains];
  return (
    <article aria-label={`Related event: ${c.headline}`} className="rounded-md border border-line bg-bg/40 p-4">
      <div className="mx-auto max-w-xl">
        <div className="rounded-md border border-line bg-surface p-3">
          <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={c.finding_severity} /><span className="text-[11px] uppercase tracking-wide text-ink-3">Security finding</span></div>
          <p className="mt-1 text-[14px] font-medium">{c.finding_title}</p>
        </div>
        <Arrow label="is" />
        <p className="text-center">
          <span className="inline-block rounded-full border border-sev-medium/40 bg-sev-medium/10 px-3 py-0.5 text-[13px] font-semibold text-sev-medium">{c.relationship}</span>
        </p>
        <Arrow label="to" />
        <div className="rounded-md border border-line bg-surface p-3">
          <div className="flex flex-wrap items-center gap-2"><span className="text-[11px] uppercase tracking-wide text-ink-3">Performance change</span>
            <span className="rounded border border-line px-1.5 py-0.5 text-[11px] text-ink-3">{c.performance.basis === "history" ? "vs. history" : "within this capture"}</span></div>
          <p className="mt-1 text-[14px] font-medium">{c.headline}</p>
        </div>
      </div>

      <dl className="mt-4 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-[13px]">
        <dt className="text-ink-3">Confidence</dt>
        <dd>{c.confidence_label} <span className="text-ink-3">({Math.round(c.confidence * 100)}% that the two are related; never certainty)</span></dd>
        <dt className="text-ink-3">Timing</dt><dd>{describeTiming(c)}</dd>
        <dt className="text-ink-3">Time difference</dt>
        <dd className="font-mono">{c.temporal_relation === "same_connections" || c.temporal_relation === "capture_level" ? "–" : `${c.time_difference_seconds >= 0 ? "+" : "−"}${Math.abs(c.time_difference_seconds).toFixed(1)} s`}</dd>
        <dt className="text-ink-3">Shared scope</dt>
        <dd>{shared.length ? shared.map((s) => <Mono key={s} className="mr-2">{s}</Mono>) : "–"}<span className="text-ink-3">{c.scope === "network" ? "network-wide" : "specific host"}</span></dd>
      </dl>

      <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-ink-2">Evidence</h4>
      <ul aria-label="Correlation evidence" className="mt-1 list-disc space-y-1 pl-5 text-[13px] text-ink-2">{c.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
      <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-2">Keep in mind</h4>
      <ul className="mt-1 list-disc space-y-1 pl-5 text-[13px] text-ink-3">{c.caveats.map((e) => <li key={e}>{e}</li>)}</ul>
    </article>
  );
}

/** Performance events that are potentially related to a finding. Correlation is not proof of causation. */
export function RelatedEvents({ analysisId, finding }: { analysisId: string; finding: Finding }) {
  const api = useApi();
  const [data, setData] = useState<CorrelationList | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setData(null); setError(null);
    api.getCorrelations(analysisId, finding.id, signal).then(setData).catch((e) => {
      if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not look for related events.");
    });
  }, [api, analysisId, finding.id]);
  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  const checked = data ? [...data.no_related_change, ...data.not_evaluated] : [];
  return (
    <Card title="Related Events" subtitle="Performance changes that share this finding's time window and scope. Correlation is not proof of causation.">
      {error && <ErrorPanel title="Related events unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel>}
      {!error && !data && <Spinner label="Looking for related performance events…" />}
      {data && data.correlations.length === 0 && <p className="text-sm text-ink-3">No potentially related performance events were found for this finding.</p>}
      {data && data.correlations.length > 0 && <div className="space-y-4">{data.correlations.map((c) => <RelatedEvent key={c.id} c={c} />)}</div>}
      {data?.flow_data_thinned && <p className="mt-3 text-xs text-ink-3">This is a very large capture: connection data was thinned to a uniform sample for this comparison.</p>}
      {checked.length > 0 && (
        <details className="mt-3 text-xs text-ink-3">
          <summary className="cursor-pointer hover:text-ink">What was checked ({checked.length})</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">{checked.map((n) => <li key={n}>{n}</li>)}</ul>
        </details>
      )}
    </Card>
  );
}
