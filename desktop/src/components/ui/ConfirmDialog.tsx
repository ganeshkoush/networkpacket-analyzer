import { useEffect, useRef, type ReactNode } from "react";
import { Button } from "./feedback";

/** Modal dialog; Escape or Cancel dismisses it. Used for destructive confirmations. */
export function ConfirmDialog({ title, children, confirmLabel, onConfirm, onCancel, busy = false, danger = false }: {
  title: string; children: ReactNode; confirmLabel: string; onConfirm: () => void; onCancel: () => void; busy?: boolean; danger?: boolean;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !busy) onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" className="w-full max-w-md rounded-lg border border-line bg-surface p-5 shadow-xl">
        <h2 id="confirm-title" className="text-base font-semibold">{title}</h2>
        <div className="mt-2 text-sm text-ink-2">{children}</div>
        <div className="mt-5 flex justify-end gap-2">
          <button ref={cancelRef} type="button" onClick={onCancel} disabled={busy}
            className="rounded-md border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:border-ink-3 disabled:opacity-50">Cancel</button>
          <Button variant="primary" onClick={onConfirm} disabled={busy}
            className={danger ? "!bg-sev-critical !text-white hover:!bg-sev-critical/85" : ""}>{busy ? "Working…" : confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}
