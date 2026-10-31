import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { EvidenceView } from "../components/results/EvidenceView";
import { RelatedEvents } from "../components/results/RelatedEvents";
import { Card } from "../components/ui/Card";
import { ConfidenceMeter } from "../components/ui/ConfidenceMeter";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Button, EmptyState, linkButtonClass } from "../components/ui/feedback";
import { Mono } from "../components/ui/DataTable";
import { formatTime, humanizeKey } from "../lib/format";
import { typeLabel } from "../lib/severity";
import { useBundle } from "../state/AnalysisContext";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <Card title={title}>{children}</Card>;
}

export function FindingDetail() {
  const { id } = useParams();
  const bundle = useBundle();
  const [copied, setCopied] = useState<"ok" | "fail" | null>(null);
  const finding = bundle?.findings.find((f) => f.id === id);

  if (!finding) {
    return (
      <EmptyState title="Finding not found" action={<Link to="/findings" className={linkButtonClass("primary")}>Back to findings</Link>}>
        {bundle ? "This finding is not part of the current analysis." : "No analysis is loaded. Findings are kept only for the current session."}
      </EmptyState>
    );
  }

  const copy = async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(finding.evidence, null, 2)); setCopied("ok"); } catch { setCopied("fail"); }
  };

  return (
    <div className="space-y-4">
      <Link to="/findings" className="inline-flex items-center gap-1 text-sm text-ink-2 hover:text-accent">← All findings</Link>

      <div className="rounded-lg border border-line bg-surface p-5">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={finding.severity} />
          <span className="text-xs font-medium uppercase tracking-wide text-ink-3">{typeLabel(finding.type)}</span>
          <span className="ml-auto"><ConfidenceMeter value={finding.confidence} wide /></span>
        </div>
        <h1 className="mt-3 text-xl font-semibold tracking-tight">{finding.title}</h1>
        <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-[13px] sm:grid-cols-[max-content_1fr_max-content_1fr]">
          <dt className="text-ink-3">Source</dt><dd>{finding.source_ip ? <Mono>{finding.source_ip}</Mono> : "–"}</dd>
          <dt className="text-ink-3">Destination</dt><dd>{finding.destination_ip ? <Mono>{finding.destination_ip}</Mono> : "–"}</dd>
          <dt className="text-ink-3">First seen</dt><dd><Mono>{formatTime(finding.first_seen)}</Mono></dd>
          <dt className="text-ink-3">Last seen</dt><dd><Mono>{formatTime(finding.last_seen)}</Mono></dd>
        </dl>
      </div>

      <Section title="What was detected">
        <p className="text-[14px] leading-relaxed">{finding.description}</p>
        <p className="mt-2 text-xs text-ink-3">Findings describe possibilities that need human review; they are not verdicts.</p>
      </Section>

      <Section title="Why it was detected">
        <ul className="list-disc space-y-1.5 pl-5 text-[14px] leading-relaxed">{finding.reasoning.map((r) => <li key={r}>{r}</li>)}</ul>
        {finding.caveats.length > 0 && (
          <div className="mt-4 rounded-md border border-line bg-bg/40 p-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-2">Could also be benign</h3>
            <ul className="mt-1.5 list-disc space-y-1 pl-5 text-[13px] text-ink-2">{finding.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
          </div>
        )}
      </Section>

      <Card title="Evidence" subtitle={`Measured by the ${humanizeKey(finding.detector)} detector`}
        actions={<div className="flex items-center gap-2">{copied && <span className="text-xs text-ink-3">{copied === "ok" ? "Copied" : "Copy not permitted"}</span>}<Button variant="ghost" onClick={copy}>Copy JSON</Button></div>}>
        <EvidenceView evidence={finding.evidence} />
      </Card>

      <RelatedEvents analysisId={bundle!.job.id} finding={finding} />

      <Section title="Confidence">
        <div className="flex items-center gap-3"><ConfidenceMeter value={finding.confidence} wide /><span className="text-xs text-ink-3">Evidence strength, never certainty — capped below 1.0 by design.</span></div>
        <table className="mt-4 w-full text-[13px]">
          <caption className="sr-only">Confidence factors</caption>
          <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wide text-ink-3"><th className="py-1.5 pr-3 font-medium">Factor</th><th className="py-1.5 pr-3 font-medium">Observed</th><th className="py-1.5 pr-3 text-right font-medium">Score</th><th className="py-1.5 text-right font-medium">Weight</th></tr></thead>
          <tbody>
            {finding.confidence_factors.map((f) => (
              <tr key={f.name} className="border-b border-line/60 last:border-0">
                <td className="py-1.5 pr-3">{humanizeKey(f.name)}</td>
                <td className="py-1.5 pr-3 text-ink-2">{f.detail || "–"}</td>
                <td className="py-1.5 pr-3 text-right"><span className="inline-flex items-center gap-2"><span className="h-1.5 w-14 rounded-full bg-surface-2"><span className="block h-full rounded-full bg-accent" style={{ width: `${f.score * 100}%` }} /></span><span className="w-9 font-mono tabular-nums">{f.score.toFixed(2)}</span></span></td>
                <td className="py-1.5 text-right font-mono tabular-nums text-ink-2">{f.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Recommended investigation">
        <p className="text-[14px] leading-relaxed">{finding.recommendation}</p>
        <p className="mt-2 text-xs text-ink-3">PacketMind never blocks addresses or runs commands for you. Any containment decision is yours.</p>
      </Section>

      <p className="text-xs text-ink-3">Finding ID <Mono>{finding.id}</Mono></p>
    </div>
  );
}
