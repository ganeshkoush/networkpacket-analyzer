import { useCallback, useEffect, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { ProcessSourceStatus } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Button, Notice } from "../ui/feedback";
import { formatNumber, formatTime } from "../../lib/format";

const WATCH_POLL_MS = 5000;

/** Explicit controls for reading the OS process list: nothing is read until a button is pressed. */
export function ProcessControls() {
  const api = useApi();
  const [status, setStatus] = useState<ProcessSourceStatus | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const load = useCallback((signal?: AbortSignal) => {
    api.getProcessStatus(signal).then(setStatus).catch((e) => { if (!isAbort(e)) setStatus(null); });
  }, [api]);
  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);
  useEffect(() => {
    if (!status?.watching) return;
    const t = setInterval(() => load(), WATCH_POLL_MS);
    return () => clearInterval(t);
  }, [status?.watching, load]);

  const run = async (action: () => Promise<unknown>, done?: (r: never) => string) => {
    setBusy(true); setError(null); setMessage(null);
    try { const r = await action(); if (done) setMessage(done(r as never)); load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "The request failed."); }
    finally { setBusy(false); }
  };

  if (!status) return null;
  return (
    <div className="rounded-md border border-line bg-surface px-4 py-3 text-xs text-ink-2">
      <p><strong className="text-ink">Local applications</strong>{" "}
        {status.supported
          ? <>· optional. A packet capture cannot tell which application sent a packet; your operating system can, for connections that are open <em>right now</em>. Take snapshots while the traffic you are capturing is happening, then analyse the capture.</>
          : <>· Process information unavailable on {status.platform}: this platform is not supported yet.</>}
      </p>
      <p className="mt-1 text-ink-3">{status.permission_note}</p>
      {status.supported && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button variant="secondary" disabled={busy} onClick={() => run(() => api.takeProcessSnapshot(),
            (r: { sockets: number; processes: number; applications: number }) => `Snapshot taken: ${formatNumber(r.sockets)} sockets from ${formatNumber(r.processes)} processes (${formatNumber(r.applications)} applications).`)}>
            Take a snapshot now
          </Button>
          {status.watching
            ? <Button variant="secondary" disabled={busy} onClick={() => run(() => api.stopProcessWatch(), () => "Stopped watching.")}>Stop watching</Button>
            : <Button variant="secondary" disabled={busy} onClick={() => run(() => api.startProcessWatch(5), () => "Watching: a snapshot every 5 seconds (stops by itself after an hour).")}>Watch while capturing</Button>}
          {status.snapshots > 0 && <Button variant="ghost" disabled={busy} onClick={() => setConfirmClear(true)}>Clear snapshots…</Button>}
          <span className="text-ink-3">
            {status.snapshots === 0 ? "No snapshots yet." : `${formatNumber(status.snapshots)} snapshot${status.snapshots === 1 ? "" : "s"} in memory, latest ${formatTime(status.last_snapshot_at)}.`}
            {status.watching && " Watching…"}
          </span>
        </div>
      )}
      {message && <div className="mt-2"><Notice tone="info">{message}</Notice></div>}
      {(error || status.last_error) && <div className="mt-2"><Notice>{error ?? `The last snapshot failed: ${status.last_error}`}</Notice></div>}
      {confirmClear && (
        <ConfirmDialog title="Forget process snapshots?" confirmLabel="Clear snapshots" danger busy={busy} onCancel={() => setConfirmClear(false)}
          onConfirm={async () => { await run(() => api.clearProcessSnapshots(), () => "Snapshots cleared."); setConfirmClear(false); }}>
          This removes the {formatNumber(status.snapshots)} process snapshot(s) held in memory. Without them, connections can no longer be matched to applications.
        </ConfirmDialog>
      )}
    </div>
  );
}
