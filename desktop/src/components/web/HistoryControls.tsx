import { useCallback, useEffect, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { HistoryStatus } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Button, Notice } from "../ui/feedback";
import { formatNumber, formatTime } from "../../lib/format";

/** What performance history is stored locally, with an explicit, confirmed way to erase it. */
export function HistoryControls({ onCleared }: { onCleared: () => void }) {
  const api = useApi();
  const [status, setStatus] = useState<HistoryStatus | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    api.getHistoryStatus(signal).then(setStatus).catch((e) => { if (!isAbort(e)) setStatus(null); });
  }, [api]);
  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  const clear = async () => {
    setBusy(true);
    try {
      await api.clearHistory();
      setMessage("Performance history deleted.");
      onCleared();
      load();
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : "Could not delete the history.");
    } finally { setBusy(false); setConfirming(false); }
  };

  if (!status) return null;
  return (
    <div className="rounded-md border border-line bg-surface px-4 py-3 text-xs text-ink-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p>
          <strong className="text-ink">Performance history</strong>{" "}
          {!status.enabled ? "is turned off." : status.observations === 0 ? "is empty." :
            `· ${formatNumber(status.sources)} capture${status.sources === 1 ? "" : "s"} · ${formatNumber(status.observations)} domain observations${status.oldest != null ? ` since ${formatTime(status.oldest)}` : ""}.`}
          {" "}Only domain names and aggregate numbers are kept, on this computer only.
        </p>
        {status.observations > 0 && <Button variant="secondary" onClick={() => setConfirming(true)}>Clear history…</Button>}
      </div>
      {message && <div className="mt-2"><Notice tone="info">{message}</Notice></div>}
      {confirming && (
        <ConfirmDialog title="Delete performance history?" confirmLabel="Delete history" danger busy={busy} onConfirm={clear} onCancel={() => setConfirming(false)}>
          This permanently removes the learned baselines ({formatNumber(status.observations)} observations from {formatNumber(status.sources)} captures). Saved reports and your capture files are not affected.
        </ConfirmDialog>
      )}
    </div>
  );
}
