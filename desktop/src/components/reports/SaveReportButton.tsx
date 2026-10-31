import { useState } from "react";
import { Link } from "react-router-dom";
import type { CreateReportRequest, SavedReport } from "../../api/types";
import { ApiError } from "../../api/client";
import { useApi } from "../../state/ApiContext";
import { Button, Notice, Spinner } from "../ui/feedback";

/** "Save investigation": snapshots the current analysis (or live capture) into local report history. */
export function SaveReportButton({ source, analysisId, defaultTitle, label = "Save investigation" }: {
  source: "analysis" | "live"; analysisId?: string; defaultTitle: string; label?: string;
}) {
  const api = useApi();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState(defaultTitle);
  const [notes, setNotes] = useState("");
  const [runAi, setRunAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedReport | null>(null);

  const save = async () => {
    setBusy(true); setError(null);
    const req: CreateReportRequest = { source, analysis_id: analysisId, title: title.trim() || undefined, notes: notes.trim() || undefined, run_ai: runAi };
    try {
      setSaved(await api.createReport(req));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save the report.");
    } finally { setBusy(false); }
  };

  if (saved) {
    const ai = saved.content.ai_investigation;
    return (
      <div className="flex flex-wrap items-center gap-2 text-sm" role="status">
        <span className="text-series-3">Saved.</span>
        {ai.status === "failed" && <span className="text-sev-medium">{ai.message}</span>}
        <Link to={`/reports/${saved.id}`} className="text-accent underline">View report</Link>
        <Button variant="ghost" onClick={() => { setSaved(null); setOpen(false); }}>Dismiss</Button>
      </div>
    );
  }
  if (!open) return <Button onClick={() => { setTitle(defaultTitle); setOpen(true); }}>{label}</Button>;
  return (
    <div className="w-full max-w-md rounded-lg border border-line bg-surface p-4" role="group" aria-label="Save investigation">
      <label className="block text-xs font-medium uppercase tracking-wide text-ink-3">Title
        <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200}
          className="mt-1 w-full rounded-md border border-line bg-surface-2 px-2 py-1.5 text-sm normal-case text-ink" />
      </label>
      <label className="mt-3 block text-xs font-medium uppercase tracking-wide text-ink-3">Notes (optional)
        <textarea value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={5000} rows={3}
          className="mt-1 w-full rounded-md border border-line bg-surface-2 px-2 py-1.5 text-sm normal-case text-ink" />
      </label>
      <label className="mt-3 flex items-start gap-2 text-sm text-ink-2">
        <input type="checkbox" className="mt-1" checked={runAi} onChange={(e) => setRunAi(e.target.checked)} />
        <span>Include an AI investigation summary. This sends aggregated evidence about the findings (never packets) to the configured AI provider. Off by default.</span>
      </label>
      {error && <div className="mt-3"><Notice>{error}</Notice></div>}
      <div className="mt-4 flex items-center gap-2">
        <Button variant="primary" onClick={save} disabled={busy}>Save</Button>
        <Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
        {busy && <Spinner label={runAi ? "Saving (AI summary may take a moment)…" : "Saving…"} />}
      </div>
    </div>
  );
}
