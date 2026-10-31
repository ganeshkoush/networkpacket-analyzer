import { useCallback, useState } from "react";
import { ApiError } from "../../api/client";

export interface ActionState { busy: boolean; message: string | null; error: string | null; run: <T>(fn: () => Promise<T>, success: (r: T) => string) => Promise<T | undefined>; clear: () => void }

/** Runs one explicit action (a button) and keeps its outcome: a success message or a plain-language error. */
export function useAction(): ActionState {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>, success: (r: T) => string) => {
    setBusy(true); setMessage(null); setError(null);
    try { const r = await fn(); setMessage(success(r)); return r; }
    catch (e) { setError(e instanceof ApiError ? e.message : "That did not work. Please try again."); return undefined; }
    finally { setBusy(false); }
  }, []);
  return { busy, message, error, run, clear: () => { setMessage(null); setError(null); } };
}
