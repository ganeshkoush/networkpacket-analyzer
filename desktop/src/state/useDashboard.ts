import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, isAbort } from "../api/client";
import type { DashboardData, DashboardRange } from "../api/types";
import { useApi } from "./ApiContext";

export type DashboardSource = { kind: "capture"; analysisId: string } | { kind: "live" };

export interface DashboardState { data: DashboardData | null; loading: boolean; error: string | null; reload: () => void }

/** Fetches the backend-aggregated dashboard. Keeps the previous data on screen while a new range loads; live data refreshes quietly. */
export function useDashboard(source: DashboardSource | null, range: DashboardRange, liveRefreshMs = 5000): DashboardState {
  const api = useApi();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const ctl = useRef<AbortController | null>(null);
  const key = source ? (source.kind === "live" ? "live" : `capture:${source.analysisId}`) : "none";
  const lastKey = useRef(key);

  const load = useCallback(async (quiet: boolean) => {
    if (!source) return;
    ctl.current?.abort();
    const controller = new AbortController();
    ctl.current = controller;
    if (!quiet) setLoading(true);
    try {
      const next = source.kind === "live" ? await api.getLiveDashboard(range, controller.signal) : await api.getDashboard(source.analysisId, range, controller.signal);
      setData(next);
      setError(null);
    } catch (e) {
      if (isAbort(e)) return;
      setError(e instanceof ApiError ? e.message : "The dashboard could not be loaded.");
    } finally {
      if (ctl.current === controller) setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, key, range]);

  useEffect(() => {
    if (lastKey.current !== key) { lastKey.current = key; setData(null); }   // never show another source's numbers
    if (source) void load(false); else setData(null);
    return () => ctl.current?.abort();
  }, [load, tick, key, source]);

  useEffect(() => {
    if (source?.kind !== "live") return;
    const t = setInterval(() => void load(true), liveRefreshMs);
    return () => clearInterval(t);
  }, [source?.kind, load, liveRefreshMs]);

  return { data, loading, error, reload: () => setTick((n) => n + 1) };
}
