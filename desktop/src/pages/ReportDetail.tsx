import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import type { ExportFormat, InvestigationResult, SavedReport } from "../api/types";
import { ApiError, isAbort } from "../api/client";
import { BarList } from "../components/charts/BarList";
import { EvidenceView } from "../components/results/EvidenceView";
import { Card } from "../components/ui/Card";
import { ConfidenceMeter } from "../components/ui/ConfidenceMeter";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { DataTable, Mono } from "../components/ui/DataTable";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { formatBytes, formatDuration, formatNumber } from "../lib/format";
import { typeLabel } from "../lib/severity";
import { useApi } from "../state/ApiContext";
import { formatStamp } from "./Reports";
import { PageHeader } from "./Placeholder";

const List = ({ items }: { items: string[] }) =>
  items.length ? <ul className="list-disc space-y-0.5 pl-5 text-sm text-ink-2">{items.map((i, n) => <li key={n}>{i}</li>)}</ul> : <p className="text-sm text-ink-3">None.</p>;

function AiBlock({ r }: { r: InvestigationResult }) {
  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center gap-3"><SeverityBadge severity={r.severity} /><ConfidenceMeter value={r.confidence} /><span className="text-xs text-ink-3">{typeLabel(r.finding_type)}</span></div>
      <p>{r.investigation_summary}</p>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Evidence cited</h4><List items={r.evidence} /></div>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Interpretation</h4><p className="text-ink-2">{r.interpretation}</p></div>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Possible explanations</h4><List items={r.possible_explanations} /></div>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Recommended next steps</h4><List items={r.recommended_next_steps} /></div>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Additional evidence needed</h4><List items={r.additional_evidence_needed} /></div>
      <div><h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Limitations</h4><List items={r.limitations} /></div>
    </div>
  );
}

export function ReportDetail() {
  const { id = "" } = useParams();
  const api = useApi();
  const navigate = useNavigate();
  const [saved, setSaved] = useState<SavedReport | null>(null);
  const [error, setError] = useState<{ missing: boolean; message: string } | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const ctl = new AbortController();
    api.getReport(id, ctl.signal).then(setSaved).catch((e) => {
      if (isAbort(e)) return;
      setError({ missing: e instanceof ApiError && e.status === 404, message: e instanceof ApiError ? e.message : "Could not load the report." });
    });
    return () => ctl.abort();
  }, [api, id]);

  if (error) {
    return error.missing
      ? <EmptyState title="Report not found" action={<Link to="/reports" className={linkButtonClass("primary")}>Back to reports</Link>}>It may have been deleted.</EmptyState>
      : <ErrorPanel title="Could not load report">{error.message}</ErrorPanel>;
  }
  if (!saved) return <Spinner label="Loading report…" />;
  const c = saved.content;

  const doExport = async (fmt: ExportFormat) => {
    setExported(null); setExportError(null);
    try { setExported((await api.exportReport(saved.id, fmt)).path); }
    catch (e) { setExportError(e instanceof ApiError ? e.message : "Export failed."); }
  };
  const doDelete = async () => {
    setDeleting(true);
    try { await api.deleteReport(saved.id); navigate("/reports"); }
    catch (e) { setExportError(e instanceof ApiError ? e.message : "Could not delete the report."); setConfirming(false); setDeleting(false); }
  };

  return (
    <div className="space-y-4">
      <PageHeader title={c.title} subtitle={`Investigation report · ${formatStamp(c.investigation_timestamp)}`}
        actions={
          <div className="flex flex-wrap justify-end gap-2">
            <Link to="/reports" className={linkButtonClass()}>All reports</Link>
            {(["html", "md", "json"] as const).map((f) => <Button key={f} onClick={() => doExport(f)}>Export {f === "md" ? "Markdown" : f.toUpperCase()}</Button>)}
            <Button variant="ghost" onClick={() => setConfirming(true)}>Delete</Button>
          </div>} />
      {exported && <Notice tone="info">Exported to <span className="font-mono">{exported}</span></Notice>}
      {exportError && <Notice>{exportError}</Notice>}
      <Card><p className="text-sm">{c.summary.headline}</p>{c.analyst_notes && <p className="mt-2 text-sm text-ink-2"><strong>Analyst notes:</strong> {c.analyst_notes}</p>}</Card>

      <Card title="1. Capture information">
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
          <dt className="text-ink-3">Source</dt><dd>{c.capture.source_kind === "live" ? `Live capture${c.capture.interface ? ` (${c.capture.interface})` : ""}` : "PCAP file"}</dd>
          <dt className="text-ink-3">Name</dt><dd className="font-mono">{c.capture.name}</dd>
          <dt className="text-ink-3">Format</dt><dd>{c.capture.capture_format}</dd>
          {c.capture.size_bytes > 0 && <><dt className="text-ink-3">Size</dt><dd>{formatBytes(c.capture.size_bytes)}</dd></>}
          {c.capture.sha256 && <><dt className="text-ink-3">SHA-256</dt><dd className="break-all font-mono text-xs">{c.capture.sha256}</dd></>}
          <dt className="text-ink-3">Packets</dt><dd>{formatNumber(c.capture.packets)}</dd>
          <dt className="text-ink-3">Duration</dt><dd>{formatDuration(c.capture.duration_seconds)}</dd>
          <dt className="text-ink-3">Time range</dt><dd>{c.capture.first_packet_time_iso ?? "n/a"} – {c.capture.last_packet_time_iso ?? "n/a"}</dd>
        </dl>
        {c.capture.warnings.length > 0 && <div className="mt-3 space-y-2">{c.capture.warnings.map((w) => <Notice key={w}>{w}</Notice>)}</div>}
      </Card>

      <Card title="2. Analysis summary">
        <dl className="grid grid-cols-2 gap-3 text-sm lg:grid-cols-4">
          {[["Packets", formatNumber(c.summary.total_packets)], ["Bytes", formatBytes(c.summary.total_bytes)],
            ["Avg packets/s", c.summary.avg_packets_per_second?.toFixed(1) ?? "n/a"], ["Peak packets/s", c.summary.peak_packets_per_second?.toString() ?? "n/a"],
            ["Source IPs", String(c.summary.unique_source_ips)], ["Destination IPs", String(c.summary.unique_destination_ips)],
            ["Findings", String(c.summary.finding_count)], ["Highest severity", c.summary.highest_severity ?? "none"]].map(([k, v]) => (
            <div key={k}><dt className="text-xs uppercase tracking-wide text-ink-3">{k}</dt><dd className="font-mono text-base">{v}</dd></div>))}
        </dl>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="3. Protocol statistics">
          <BarList ariaLabel="Protocol statistics" items={c.protocols.map((p) => ({ key: p.protocol, label: p.protocol, value: p.packets, valueLabel: `${formatNumber(p.packets)} · ${p.percent_of_packets.toFixed(1)}%` }))} />
        </Card>
        <Card title="4. Top talkers" padded={false}>
          <DataTable caption="Top talkers" rows={c.top_talkers} rowKey={(t) => t.ip}
            columns={[{ header: "Host", cell: (t) => <Mono>{t.ip}</Mono> }, { header: "Packets", align: "right", cell: (t) => formatNumber(t.total_packets) }, { header: "Bytes", align: "right", cell: (t) => formatBytes(t.total_bytes) }]} />
        </Card>
      </div>

      {c.domains && c.domains.length > 0 && (
        <Card title="Top domains" subtitle="Inferred from DNS lookups followed by connections. Not exact URLs." padded={false}>
          <DataTable caption="Top domains" rows={c.domains} rowKey={(d) => d.domain}
            columns={[{ header: "Domain", cell: (d) => <Mono>{d.domain}</Mono> }, { header: "Connections", align: "right", cell: (d) => formatNumber(d.connections) },
              { header: "Sent", align: "right", cell: (d) => formatBytes(d.bytes_sent) }, { header: "Received", align: "right", cell: (d) => formatBytes(d.bytes_received) }]} />
        </Card>
      )}

      <Card title="5. Findings" subtitle="Possible issues with evidence. Confidence is evidence strength, not the probability of an attack.">
        {c.findings.length === 0 ? <p className="text-sm text-ink-3">No detector threshold was exceeded.</p> : (
          <ol className="space-y-4" aria-label="Report findings">
            {c.findings.map((f, i) => (
              <li key={f.id} className="rounded-md border border-line p-4">
                <div className="flex flex-wrap items-center gap-3"><span className="font-semibold">{i + 1}. {f.title}</span><SeverityBadge severity={f.severity} /><ConfidenceMeter value={f.confidence} /></div>
                <p className="mt-1 text-xs text-ink-3">{typeLabel(f.type)} · {[f.source_ip, f.destination_ip].filter(Boolean).join(" → ") || "capture-wide"}{f.first_seen_iso ? ` · ${f.first_seen_iso} – ${f.last_seen_iso}` : ""}</p>
                <p className="mt-2 text-sm">{f.description}</p>
                <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Evidence</h4><EvidenceView evidence={f.evidence} />
                <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Investigation steps</h4><List items={f.investigation_steps} />
                <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Possible benign explanations</h4><List items={f.caveats} />
                <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Recommendation</h4><p className="text-sm text-ink-2">{f.recommendation}</p>
                {f.ai_assessment && <div className="mt-3 rounded-md bg-surface-2 p-3"><h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-3">AI assessment</h4><AiBlock r={f.ai_assessment} /></div>}
              </li>))}
          </ol>)}
      </Card>

      <Card title="6. AI investigation summary" subtitle={c.ai_investigation.status === "completed" ? `${c.ai_investigation.provider} · ${c.ai_investigation.model} · advisory, from aggregated evidence only` : undefined}>
        {c.ai_investigation.status === "completed" && c.ai_investigation.result
          ? <><AiBlock r={c.ai_investigation.result} />{c.ai_investigation.notes.length > 0 && <p className="mt-3 text-xs text-ink-3">Safeguards applied: {c.ai_investigation.notes.join("; ")}</p>}</>
          : <p className="text-sm text-ink-3">{c.ai_investigation.message ?? "No AI investigation is included in this report."}</p>}
      </Card>

      <Card title="7. Recommended actions" subtitle="Manual investigative steps. PacketMind never blocks traffic or changes configuration.">
        {c.recommended_actions.length === 0 ? <p className="text-sm text-ink-3">None.</p> : (
          <ol className="list-decimal space-y-1.5 pl-5 text-sm">
            {c.recommended_actions.map((a, i) => <li key={i}>{a.priority && <strong className="mr-1">{a.priority}</strong>}{a.action} <span className="text-xs text-ink-3">({a.source === "ai" ? "AI" : "detector"})</span></li>)}
          </ol>)}
      </Card>

      <Card title="8. Limitations"><List items={c.limitations} /></Card>
      <Card title="9. Investigation timestamp"><p className="font-mono text-sm">{formatStamp(c.investigation_timestamp)}</p></Card>

      {confirming && (
        <ConfirmDialog title="Delete this report?" confirmLabel="Delete report" danger busy={deleting} onConfirm={doDelete} onCancel={() => setConfirming(false)}>
          “{c.title}” will be permanently removed from this machine. This can’t be undone.
        </ConfirmDialog>)}
    </div>
  );
}
