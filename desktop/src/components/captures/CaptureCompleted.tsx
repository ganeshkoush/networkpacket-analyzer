import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { CaptureSession, LiveCaptureFile } from "../../api/types";
import { ApiError, isAbort } from "../../api/client";
import { formatBytes, formatClockDuration, formatNumber } from "../../lib/format";
import { useAnalysis } from "../../state/AnalysisContext";
import { useApi } from "../../state/ApiContext";
import { useSettings } from "../../state/SettingsContext";
import { Card } from "../ui/Card";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Button, ErrorPanel, linkButtonClass, Notice, Spinner } from "../ui/feedback";
import { ExportButton } from "./ExportButton";

/** The "Capture Completed" screen: what was saved, what the analysis of that file found, and what to do next. */
export function CaptureCompleted({ file, interfaceLabel, onDeleted }: { file: LiveCaptureFile; interfaceLabel: string | null; onDeleted: () => void }) {
  const api = useApi();
  const navigate = useNavigate();
  const { openCapture } = useAnalysis();
  const { saved } = useSettings();
  const [capture, setCapture] = useState<CaptureSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // The saved file is analyzed in the background; follow it until it is analyzed (or failed).
  useEffect(() => {
    let alive = true;
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const c = await api.getCapture(file.id, ctl.signal);
        if (!alive) return;
        setCapture(c); setError(null);
        if (c.status === "ANALYZING" || c.status === "COMPLETED" || c.status === "CAPTURING") timer = setTimeout(poll, 1500);
      } catch (e) {
        if (!alive || isAbort(e)) return;
        setError(e instanceof ApiError ? e.message : "The capture details could not be loaded.");
      }
    };
    void poll();
    return () => { alive = false; ctl.abort(); clearTimeout(timer); };
  }, [api, file.id]);

  const c = capture;
  const failed = file.status === "FAILED" || c?.status === "FAILED";
  const message = file.error ?? c?.error_message ?? null;
  const summary = c?.summary;
  const analyzing = !failed && (!c || c.status !== "ANALYZED");
  const analyze = async () => { if (c) { void openCapture(c); navigate("/"); } };

  const confirmDelete = async () => {
    setDeleting(true);
    try { await api.deleteCapture(file.id); setConfirming(false); onDeleted(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "The capture could not be deleted."); setConfirming(false); }
    finally { setDeleting(false); }
  };

  return (
    <section aria-label="Capture completed" className="mb-4">
      <Card title={failed ? "Capture not saved cleanly" : "Capture completed"}>
        {failed && <div className="mb-3"><ErrorPanel title="The capture file could not be saved completely">{message ?? "The capture file is incomplete."}</ErrorPanel></div>}
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[max-content_1fr_max-content_1fr]">
          <dt className="text-ink-3">File</dt><dd className="break-all font-mono text-[13px]">{file.filename}</dd>
          <dt className="text-ink-3">Interface</dt><dd>{c?.interface ?? interfaceLabel ?? "–"}</dd>
          <dt className="text-ink-3">Duration</dt><dd className="font-mono">{formatClockDuration(c?.duration_seconds)}</dd>
          <dt className="text-ink-3">Packets</dt><dd className="font-mono">{formatNumber(c?.packet_count ?? file.packets)}</dd>
          <dt className="text-ink-3">Size</dt><dd className="font-mono">{formatBytes(c?.file_size ?? file.file_size)}</dd>
          <dt className="text-ink-3">Format</dt><dd>{file.format.toUpperCase()}</dd>
        </dl>

        {analyzing && <div className="mt-4"><Spinner label="Analyzing the saved capture…" /></div>}
        {summary && (
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            <div>
              <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">Protocols</h3>
              <ul aria-label="Protocols" className="space-y-0.5 font-mono text-sm">
                {summary.protocols.map((p) => <li key={p.protocol} className="flex justify-between gap-4"><span>{p.protocol}</span><span>{Math.round(p.percent)}%</span></li>)}
              </ul>
            </div>
            <div><h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">Domains</h3><div className="font-mono text-2xl">{formatNumber(summary.domains)}</div></div>
            <div><h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">Findings</h3><div className="font-mono text-2xl">{formatNumber(summary.findings)}</div></div>
          </div>
        )}
        {error && <div className="mt-3"><Notice>{error}</Notice></div>}

        <p className="mt-4 text-xs text-ink-3">Captured traffic can contain sensitive information. The file stays on this computer; PacketMind never sends it to the AI provider, only summaries of what its local analysis finds.</p>
        <div className="mt-4 flex flex-wrap items-start gap-2">
          {c && !failed && <ExportButton capture={c} variant="primary" />}
          {c && !failed && <Button onClick={analyze}>Analyze Capture</Button>}
          {c && <Button variant="ghost" onClick={() => (saved.security.confirm_delete_captures ? setConfirming(true) : void confirmDelete())}>Delete Capture</Button>}
          <Link to="/" className={linkButtonClass()}>Back to Dashboard</Link>
        </div>
      </Card>
      {confirming && c && (
        <ConfirmDialog title="Delete this capture?" confirmLabel="Delete capture" danger busy={deleting} onCancel={() => setConfirming(false)} onConfirm={confirmDelete}>
          <p>“{c.original_filename}” and its analysis will be permanently deleted from PacketMind. Copies you exported are not affected.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}
