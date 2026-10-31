import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { ReportListItem } from "../api/types";
import { ApiError, isAbort } from "../api/client";
import { Card } from "../components/ui/Card";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { formatNumber } from "../lib/format";
import { useApi } from "../state/ApiContext";
import { PageHeader } from "./Placeholder";

export const AI_LABEL = { completed: "AI summary included", failed: "AI unavailable", not_run: "No AI summary" } as const;
export const formatStamp = (iso: string) => iso.replace("T", " ").replace(/\.\d+/, "").replace(/(\+00:00|Z)$/, " UTC");

export function Reports() {
  const api = useApi();
  const [items, setItems] = useState<ReportListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ReportListItem | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try { setItems(await api.listReports(signal)); setError(null); }
    catch (e) { if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not load reports."); }
  }, [api]);

  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.deleteReport(pendingDelete.id);
      setNotice(`Deleted “${pendingDelete.title}”.`);
      setPendingDelete(null);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not delete the report.");
      setPendingDelete(null);
    } finally { setDeleting(false); }
  };

  return (
    <>
      <PageHeader title="Reports" subtitle="Saved investigations, stored locally on this machine." />
      {error && <div className="mb-4"><ErrorPanel title="Reports unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel></div>}
      {notice && <div className="mb-4"><Notice tone="info">{notice}</Notice></div>}
      {items === null && !error && <Spinner label="Loading reports…" />}
      {items?.length === 0 && (
        <EmptyState title="No saved investigations yet" action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>
          Analyze a capture, then choose “Save investigation” to keep a report here.
        </EmptyState>
      )}
      {items && items.length > 0 && (
        <Card padded={false}>
          <ul aria-label="Saved reports" className="divide-y divide-line">
            {items.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <Link to={`/reports/${r.id}`} className="font-medium text-ink hover:underline">{r.title}</Link>
                  <div className="mt-0.5 text-xs text-ink-3">
                    {formatStamp(r.created_at)} · {r.source_kind === "live" ? "Live capture" : "PCAP"} · <span className="font-mono">{r.capture_name}</span> · {formatNumber(r.total_packets)} packets
                  </div>
                </div>
                <div className="flex items-center gap-3 text-xs text-ink-2">
                  {r.highest_severity ? <SeverityBadge severity={r.highest_severity} /> : <span className="text-ink-3">No findings</span>}
                  <span>{r.finding_count} finding{r.finding_count === 1 ? "" : "s"}</span>
                  <span>{AI_LABEL[r.ai_status]}</span>
                </div>
                <div className="flex gap-2">
                  <Link to={`/reports/${r.id}`} className={linkButtonClass()}>Open</Link>
                  <Button variant="ghost" onClick={() => setPendingDelete(r)} aria-label={`Delete ${r.title}`}>Delete</Button>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {pendingDelete && (
        <ConfirmDialog title="Delete this report?" confirmLabel="Delete report" danger busy={deleting}
          onConfirm={confirmDelete} onCancel={() => setPendingDelete(null)}>
          “{pendingDelete.title}” will be permanently removed from this machine. This can’t be undone. Exported files are not affected.
        </ConfirmDialog>
      )}
    </>
  );
}
