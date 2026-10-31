import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api as defaultApi, type Api } from "../api/client";
import type { Health } from "../api/types";

export type BackendStatus = "checking" | "online" | "offline";

interface BackendValue {
  status: BackendStatus;
  info: Health | null;
  retry: () => void;
}

const Ctx = createContext<BackendValue | null>(null);

/** Polls the backend health endpoint so the UI can say when the local service is unavailable. */
export function BackendProvider({
  children, api = defaultApi, onlineIntervalMs = 10_000, offlineIntervalMs = 3_000,
}: { children: ReactNode; api?: Pick<Api, "fetchHealth">; onlineIntervalMs?: number; offlineIntervalMs?: number }) {
  const [status, setStatus] = useState<BackendStatus>("checking");
  const [info, setInfo] = useState<Health | null>(null);
  const [tick, setTick] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const ctl = new AbortController();
    let cancelled = false;
    const check = async () => {
      let next: BackendStatus;
      try {
        const health = await api.fetchHealth(ctl.signal);
        if (cancelled) return;
        setInfo(health);
        next = "online";
      } catch {
        if (cancelled) return;
        next = "offline";
      }
      setStatus(next);
      timer.current = setTimeout(check, next === "online" ? onlineIntervalMs : offlineIntervalMs);
    };
    void check();
    return () => { cancelled = true; ctl.abort(); clearTimeout(timer.current); };
  }, [api, tick, onlineIntervalMs, offlineIntervalMs]);

  const retry = useCallback(() => { setStatus("checking"); setTick((t) => t + 1); }, []);
  const value = useMemo(() => ({ status, info, retry }), [status, info, retry]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useBackend(): BackendValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useBackend must be used inside <BackendProvider>");
  return v;
}
