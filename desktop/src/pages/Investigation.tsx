import { Link } from "react-router-dom";
import { Card } from "../components/ui/Card";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { InvestigateButton } from "../components/investigation/InvestigateButton";
import { CATEGORY_ORDER, CATEGORY_TITLES, formatChange, formatMetric, HEALTH_STYLE, STATUS_STYLE } from "../lib/investigation";
import type { ConfidenceLevel, NetworkInvestigation, NetworkMetric } from "../api/types";
import { useAnalysis } from "../state/AnalysisContext";
import { useInvestigation } from "../state/InvestigationContext";
import { PageHeader } from "./Placeholder";

function MetricRow({ m }: { m: NetworkMetric }) {
  const s = STATUS_STYLE[m.status];
  return (
    <tr className="border-t border-line">
      <td className="py-2 pr-3">{m.label}{m.note && <div className="text-xs text-ink-3">{m.note}</div>}</td>
      <td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">{formatMetric(m.normal, m.unit)}</td>
      <td className="px-3 py-2 text-right font-mono tabular-nums font-semibold">{formatMetric(m.current, m.unit)}</td>
      <td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">{formatChange(m.change)}</td>
      <td className={`py-2 pl-3 text-right text-xs font-medium ${s.text}`}>{s.label}</td>
    </tr>
  );
}

function MetricTable({ rows, caption }: { rows: NetworkMetric[]; caption: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="text-xs uppercase tracking-wide text-ink-3">
          <tr><th className="pb-1 pr-3 text-left font-medium">Metric</th><th className="px-3 pb-1 text-right font-medium">Normal</th><th className="px-3 pb-1 text-right font-medium">Current</th><th className="px-3 pb-1 text-right font-medium">Change</th><th className="pb-1 pl-3 text-right font-medium">Status</th></tr>
        </thead>
        <tbody>{rows.map((m) => <MetricRow key={m.id} m={m} />)}</tbody>
      </table>
    </div>
  );
}

const CONF_TEXT: Record<ConfidenceLevel, string> = { High: "text-series-3", Medium: "text-sev-medium", Low: "text-ink-2" };

function List({ items, ordered = false }: { items: string[]; ordered?: boolean }) {
  const Tag = ordered ? "ol" : "ul";
  return <Tag className={`space-y-1.5 pl-5 text-sm ${ordered ? "list-decimal" : "list-disc"}`}>{items.map((t, i) => <li key={i}>{t}</li>)}</Tag>;
}

function Result({ r, onAgain, running }: { r: NetworkInvestigation; onAgain: () => void; running: boolean }) {
  const h = HEALTH_STYLE[r.health];
  const rep = r.report;
  const byId = new Map(r.evidence.map((m) => [m.id, m]));
  const cited = rep ? rep.evidence.map((e) => ({ item: e, metric: byId.get(e.evidence_id) })) : [];
  const grouped = CATEGORY_ORDER.map((c) => ({ c, rows: r.local.metrics.filter((m) => m.category === c) })).filter((g) => g.rows.length);
  const mainIssue = rep?.main_issue || null;

  return (
    <div className="space-y-4">
      <section aria-label="Overall network health" className={`rounded-lg border-2 p-5 ${h.border} ${h.bg}`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-ink-3">Network health</div>
            <div className={`text-3xl font-bold tracking-tight ${h.text}`} data-testid="health">{h.label}</div>
          </div>
          <div className="text-right text-sm">
            <div className="text-xs uppercase tracking-wide text-ink-3">Confidence</div>
            <div className={`text-lg font-semibold ${CONF_TEXT[r.confidence]}`}>{r.confidence}</div>
          </div>
        </div>
        {mainIssue && <p className="mt-3 text-base"><span className="font-semibold">Main issue:</span> {mainIssue}</p>}
        <p className="mt-2 text-sm text-ink-2">{rep?.summary ?? h.blurb}</p>
        {r.health_note && <p className="mt-2 text-xs text-ink-3">{r.health_note}</p>}
        <p className="mt-2 text-xs text-ink-3">Confidence basis: {r.local.strength_reason}</p>
      </section>

      {r.status === "local_only" && (
        <Notice tone="info">{r.ai.requested ? <>Gemini analysis was not available{r.ai.error_message ? `: ${r.ai.error_message}` : "."} </> : <>Gemini was not asked. </>}This is PacketMind&apos;s own local assessment from measurements only.</Notice>
      )}
      {r.status === "ai_failed" && (
        <Notice>The AI analysis could not be used{r.ai.error_message ? `: ${r.ai.error_message}` : "."} The local measurements and rating below are unaffected.</Notice>
      )}

      {rep && rep.top_problems.length > 0 && (
        <Card title="Top problems">
          <ol className="space-y-3">
            {rep.top_problems.map((p, i) => (
              <li key={i} className="flex gap-3">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-2 font-mono text-xs">{i + 1}</span>
                <div><div className="font-medium">{p.title}</div><div className="text-sm text-ink-2">{p.detail}</div></div>
              </li>
            ))}
          </ol>
        </Card>
      )}

      {rep && cited.length > 0 && (
        <Card title="Evidence" subtitle="Measured by PacketMind on this computer. Numbers come from the measurement table, not from the AI.">
          <ul className="space-y-3">
            {cited.map(({ item, metric }) => (
              <li key={item.evidence_id} className="text-sm">
                {item.statement}
                {metric && <div className="mt-1 font-mono text-xs text-ink-2">{metric.label}: Normal {formatMetric(metric.normal, metric.unit)} · Current {formatMetric(metric.current, metric.unit)}</div>}
              </li>
            ))}
          </ul>
          {r.evidence.length > 0 && <div className="mt-4"><MetricTable rows={r.evidence} caption="Cited measurements" /></div>}
        </Card>
      )}

      {rep && rep.potential_explanations.length > 0 && (
        <Card title="Potential explanations" subtitle="Possibilities consistent with the measurements, not confirmed causes.">
          <List items={rep.potential_explanations} />
        </Card>
      )}

      {rep && rep.recommended_next_steps.length > 0 && (
        <Card title="Recommended next steps">
          <List items={rep.recommended_next_steps} ordered />
          <p className="mt-3 text-xs text-ink-3">Safe diagnostics only. PacketMind never runs, changes or blocks anything; these are suggestions for you to consider.</p>
        </Card>
      )}

      {rep && rep.limitations.length > 0 && (
        <Card title="Limitations" subtitle="What PacketMind could not measure.">
          <List items={rep.limitations} />
        </Card>
      )}

      <Card title="Local measurements" subtitle={`What PacketMind measured, by area. Normal = pooled over ${r.local.earlier_captures} earlier capture${r.local.earlier_captures === 1 ? "" : "s"} on this computer.`}>
        {r.local.reasons.length > 0 && (
          <div className="mb-4"><div className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">Why this rating</div><List items={r.local.reasons} /></div>
        )}
        <div className="space-y-5">
          {grouped.map(({ c, rows }) => (
            <div key={c}><h3 className="mb-1 text-sm font-semibold">{CATEGORY_TITLES[c]}</h3><MetricTable rows={rows} caption={CATEGORY_TITLES[c]} /></div>
          ))}
        </div>
      </Card>

      <Card title="About this investigation">
        <p className="text-sm text-ink-2">{r.disclosure}</p>
        {r.ai.model && <p className="mt-2 text-xs text-ink-3">Model: {r.ai.provider} {r.ai.model}. No hidden reasoning is shown or stored; only the conclusions above.</p>}
        {r.notes.length > 0 && <div className="mt-3"><div className="text-xs font-medium uppercase tracking-wide text-ink-3">Safeguards applied</div><List items={r.notes} /></div>}
        <div className="mt-4 flex flex-wrap gap-2">
          <Button onClick={onAgain} disabled={running}>Run again</Button>
        </div>
      </Card>
    </div>
  );
}

export function Investigation() {
  const { session } = useAnalysis();
  const { state, run } = useInvestigation();

  if (session.phase !== "ready") {
    return (
      <>
        <PageHeader title="Investigate Network" />
        <EmptyState title="No capture analyzed yet" action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>
          Analyze a capture first, then PacketMind can investigate it in one click.
        </EmptyState>
      </>
    );
  }
  const id = session.bundle.job.id;

  return (
    <>
      <PageHeader title="Investigate Network" subtitle={`${session.bundle.analysis.metadata.file_name} · analysis and recommendations only`}
        actions={<InvestigateButton analysisId={id} />} />
      {state.phase === "idle" && (
        <EmptyState title="Ready to investigate" action={<InvestigateButton analysisId={id} size="large" />}>
          PacketMind measures traffic, DNS and handshake latency, RTT, retransmissions, resets, failures, domains, anomalies, findings and your history locally, then asks Gemini to analyse that summary. Nothing is changed on your network.
        </EmptyState>
      )}
      {state.phase === "running" && (
        <Card><Spinner label={state.useAi ? "Measuring locally and asking Gemini to analyse the summary…" : "Measuring locally…"} /></Card>
      )}
      {state.phase === "error" && (
        <ErrorPanel title="The investigation could not be completed" actions={<Button onClick={() => void run(id, state.useAi)}>Try again</Button>}>{state.message}</ErrorPanel>
      )}
      {state.phase === "done" && <Result r={state.result} running={false} onAgain={() => void run(id, true)} />}
    </>
  );
}
