import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { CaptureSession } from "../api/types";
import { ApiError, isAbort } from "../api/client";
import { ExportButton } from "../components/captures/ExportButton";
import { sourceLabel, StatusBadge } from "../components/captures/status";
import { Card } from "../components/ui/Card";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, Spinner } from "../components/ui/feedback";
import { formatBytes, formatNumber } from "../lib/format";
import { useAnalysis } from "../state/AnalysisContext";
import { useApi } from "../state/ApiContext";
import { useSettings } from "../state/SettingsContext";
import { PageHeader } from "./Placeholder";

const stamp = (iso: string) => iso.replace("T", " ").replace(/\+00:00$|Z$/, " UTC");
const BUSY = new Set(["CAPTURING", "ANALYZING"]);

export function Captures() {
  const api = useApi();
  const navigate = useNavigate();
  const { openCapture } = useAnalysis();
  const { saved } = useSettings();
  const [items, setItems] = useState<CaptureSession[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<CaptureSession | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async (signal?: AbortSignal) => {
    try { setItems(await api.listCaptures(signal)); setError(null); }
    catch (e) { if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not load the capture library."); }
  }, [api]);

  useEffect(() => { const c = new AbortController(); void load(c.signal); return () => c.abort(); }, [load]);
  // Follow captures that are still recording or being analyzed.
  const anyBusy = items?.some((c) => BUSY.has(c.status)) ?? false;
  useEffect(() => {
    if (!anyBusy) return;
    const t = setInterval(() => void load(), 2000);
    return () => clearInterval(t);
  }, [anyBusy, load]);

  const open = (c: CaptureSession, force = false) => { void openCapture(c, { force }); navigate("/"); };

  const removeNow = async (c: CaptureSession) => {
    setDeleting(true);
    try {
      await api.deleteCapture(c.id);
      setNotice(`Deleted “${c.original_filename}”.`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not delete the capture.");
    } finally { setPendingDelete(null); setDeleting(false); }
  };
  const confirmDelete = () => { if (pendingDelete) void removeNow(pendingDelete); };

  return (
    <>
      <PageHeader title="Captures" subtitle="Every capture PacketMind has saved on this computer: live recordings and imported files."
        actions={<div className="flex gap-2"><Link to="/analysis" className={linkButtonClass()}>Import PCAP</Link><Link to="/live" className={linkButtonClass("primary")}>Live capture</Link></div>} />
      {error && <div className="mb-4"><ErrorPanel title="Captures unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel></div>}
      {notice && <div className="mb-4"><Notice tone="info">{notice}</Notice></div>}
      {items === null && !error && <Spinner label="Loading captures…" />}
      {items?.length === 0 && (
        <EmptyState title="No captures yet" action={<Link to="/analysis" className={linkButtonClass("primary")}>Import PCAP</Link>}>
          Import a .pcap or .pcapng file, or record a live capture, and it will be kept here for analysis and export.
        </EmptyState>
      )}
      {items && items.length > 0 && (
        <Card padded={false}>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-[13px]">
              <caption className="sr-only">Capture history</caption>
              <thead>
                <tr className="border-b border-line text-xs uppercase tracking-wide text-ink-3">
                  {["Capture name", "Source", "Packets", "Size", "Status", "Saved", "Actions"].map((h, i) => (
                    <th key={h} scope="col" className={`px-3 py-2 font-medium ${i === 2 || i === 3 ? "text-right" : ""}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((c) => {
                  const ready = c.status === "COMPLETED" || c.status === "ANALYZED";
                  return (
                    <tr key={c.id} className="border-b border-line/60 last:border-0" aria-label={c.original_filename}>
                      <td className="max-w-xs px-3 py-2">
                        {ready || c.status === "ANALYZING"
                          ? <button type="button" onClick={() => open(c)} className="break-all text-left font-mono text-ink hover:text-accent hover:underline" title="Open the analysis">{c.original_filename}</button>
                          : <span className="break-all font-mono">{c.original_filename}</span>}
                        {saved.advanced.show_internal_ids && <div className="mt-0.5 font-mono text-[11px] text-ink-3">id {c.id}</div>}
                        {c.error_message && <div className="mt-0.5 text-xs text-sev-critical">{c.error_message}</div>}
                      </td>
                      <td className="px-3 py-2">{sourceLabel(c)}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{c.packet_count ? formatNumber(c.packet_count) : "–"}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{formatBytes(c.file_size)}</td>
                      <td className="px-3 py-2"><StatusBadge status={c.status} /></td>
                      <td className="px-3 py-2 text-xs text-ink-3">{stamp(c.created_at)}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap items-start gap-1.5">
                          {c.status === "ANALYZED"
                            ? <Button variant="secondary" onClick={() => open(c, true)} aria-label={`Analyze again ${c.original_filename}`}>Analyze Again</Button>
                            : <Button variant="secondary" disabled={c.status === "CAPTURING" || (c.status === "FAILED" && c.packet_count === 0)} onClick={() => open(c)} aria-label={`Analyze ${c.original_filename}`}>Analyze</Button>}
                          <ExportButton capture={c} label="Export" variant="ghost" />
                          <Button variant="ghost" disabled={BUSY.has(c.status)} onClick={() => (saved.security.confirm_delete_captures ? setPendingDelete(c) : void removeNow(c))} aria-label={`Delete ${c.original_filename}`}>Delete</Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      <p className="mt-4 text-xs text-ink-3">Captured traffic can contain sensitive information. Files stay in PacketMind&apos;s private capture folder on this computer until you delete them, and are never sent to the AI provider.</p>
      {pendingDelete && (
        <ConfirmDialog title="Delete this capture?" confirmLabel="Delete capture" danger busy={deleting} onCancel={() => setPendingDelete(null)} onConfirm={confirmDelete}>
          <p>“{pendingDelete.original_filename}” will be permanently deleted from PacketMind. Copies you exported are not affected.</p>
        </ConfirmDialog>
      )}
    </>
  );
}
