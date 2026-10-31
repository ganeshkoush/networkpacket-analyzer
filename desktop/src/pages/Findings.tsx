import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Card } from "../components/ui/Card";
import { ConfidenceMeter } from "../components/ui/ConfidenceMeter";
import { DataTable, Mono } from "../components/ui/DataTable";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { EmptyState, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { countBySeverity, SEVERITY_ORDER, SEVERITY_STYLE, typeLabel } from "../lib/severity";
import type { Finding, Severity } from "../api/types";
import { useAnalysis } from "../state/AnalysisContext";
import { PageHeader } from "./Placeholder";

export function Findings() {
  const { session } = useAnalysis();
  const navigate = useNavigate();
  const [active, setActive] = useState<Set<Severity>>(new Set());
  const [query, setQuery] = useState("");

  const findings: Finding[] = session.phase === "ready" ? session.bundle.findings : [];
  const counts = useMemo(() => countBySeverity(findings), [findings]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) =>
      (active.size === 0 || active.has(f.severity)) &&
      (!q || [f.type, f.title, f.description, f.source_ip, f.destination_ip].some((x) => x?.toLowerCase().includes(q))));
  }, [findings, active, query]);

  if (session.phase === "uploading" || session.phase === "analyzing") {
    return <><PageHeader title="Findings" /><Card><Spinner label="Analysis in progress…" /></Card></>;
  }
  if (session.phase !== "ready") {
    return (
      <>
        <PageHeader title="Findings" subtitle="Possible issues detected in the current capture" />
        <EmptyState title="No capture analyzed yet" action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>
          Findings appear here after you analyze a capture.
        </EmptyState>
      </>
    );
  }

  const toggle = (s: Severity) => setActive((prev) => { const n = new Set(prev); if (n.has(s)) n.delete(s); else n.add(s); return n; });

  return (
    <>
      <PageHeader title="Findings" subtitle={`${findings.length} possible issue${findings.length === 1 ? "" : "s"} in ${session.filename}`} />
      {Object.keys(session.bundle.detector_errors).length > 0 && (
        <div className="mb-3"><Notice>Some detectors failed, so results may be incomplete: {Object.keys(session.bundle.detector_errors).join(", ")}.</Notice></div>
      )}
      {findings.length === 0 ? (
        <EmptyState title="No findings">No detector exceeded its threshold for this capture. That is not proof the traffic is safe — detectors only see what this capture contains.</EmptyState>
      ) : (
        <Card padded={false}>
          <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
            {SEVERITY_ORDER.map((s) => (
              <button key={s} type="button" aria-pressed={active.has(s)} disabled={counts[s] === 0} onClick={() => toggle(s)}
                className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs font-medium disabled:opacity-40 ${active.has(s) ? `${SEVERITY_STYLE[s].bg} ${SEVERITY_STYLE[s].border} text-ink` : "border-line text-ink-2 hover:border-ink-3"}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_STYLE[s].dot}`} aria-hidden />{s}<span className="font-mono tabular-nums text-ink-3">{counts[s]}</span>
              </button>
            ))}
            <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by type, IP or text…" aria-label="Filter findings"
              className="ml-auto w-64 rounded-md border border-line bg-bg px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-3" />
          </div>
          <DataTable caption="Findings" rows={shown} rowKey={(f) => f.id} onRowClick={(f) => navigate(`/findings/${f.id}`)}
            empty="No findings match the current filters."
            columns={[
              { header: "Severity", cell: (f) => <SeverityBadge severity={f.severity} />, className: "whitespace-nowrap" },
              { header: "Type", cell: (f) => <Link to={`/findings/${f.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-ink hover:text-accent hover:underline">{typeLabel(f.type)}</Link>, className: "whitespace-nowrap" },
              { header: "Source", cell: (f) => f.source_ip ? <Mono>{f.source_ip}</Mono> : <span className="text-ink-3">–</span> },
              { header: "Destination", cell: (f) => f.destination_ip ? <Mono>{f.destination_ip}</Mono> : <span className="text-ink-3">–</span> },
              { header: "Confidence", cell: (f) => <ConfidenceMeter value={f.confidence} />, className: "whitespace-nowrap" },
              { header: "Description", cell: (f) => <span className="line-clamp-2 text-ink-2">{f.description}</span>, className: "min-w-[18rem]" },
            ]} />
        </Card>
      )}
    </>
  );
}
