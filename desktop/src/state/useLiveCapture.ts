import { useCallback, useEffect, useRef, useState } from "react";
import { api as defaultApi, ApiError, isAbort, type Api } from "../api/client";
import type { CaptureFormat, InterfaceInfo, LiveError, LiveStatus } from "../api/types";

type LiveApi = Pick<Api, "listInterfaces" | "getLiveStatus" | "startLive" | "stopLive">;

export const IDLE_STATUS: LiveStatus = {
  state: "stopped", interface: null, started_at: null, elapsed_seconds: 0, packets_total: 0, bytes_total: 0,
  packets_per_second: 0, bits_per_second: 0, window_seconds: 0, window_packets: 0, window_truncated: false,
  last_analysis_at: null, protocols: [], top_talkers: [], top_ports: [], findings: [], capture: null, notice: null, auto_investigate: false,
  parse_errors: 0, error: null,
};

/** Interfaces + polled capture status. Nothing is started here except by an explicit `start()` call. */
export function useLiveCapture(api: LiveApi = defaultApi, pollMs = 1000) {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[] | null>(null);
  const [status, setStatus] = useState<LiveStatus>(IDLE_STATUS);
  const [backendDown, setBackendDown] = useState(false);
  const [actionError, setActionError] = useState<LiveError | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    const ctl = new AbortController();
    let cancelled = false;
    api.listInterfaces(ctl.signal).then((l) => !cancelled && setInterfaces(l)).catch((e) => {
      if (!isAbort(e) && !cancelled) { setInterfaces([]); setBackendDown(true); }
    });
    const poll = async () => {
      try {
        const s = await api.getLiveStatus(ctl.signal);
        if (cancelled) return;
        setStatus(s); setBackendDown(false);
      } catch (e) {
        if (isAbort(e) || cancelled) return;
        setBackendDown(true);
      }
      timer.current = setTimeout(poll, pollMs);
    };
    poll();
    return () => { cancelled = true; ctl.abort(); clearTimeout(timer.current); };
  }, [api, pollMs]);

  const run = useCallback(async (fn: () => Promise<LiveStatus>) => {
    setBusy(true); setActionError(null);
    try {
      setStatus(await fn());
    } catch (e) {
      if (e instanceof ApiError) {
        setActionError({ code: e.code ?? e.kind, message: e.message, hint: e.hint ?? null });
        // Permission failures are also reflected in the backend status; refresh it right away.
        try { setStatus(await api.getLiveStatus()); } catch { /* shown via backendDown on next poll */ }
      } else throw e;
    } finally { setBusy(false); }
  }, [api]);

  const start = useCallback((iface: string, autoInvestigate: boolean, opts: { save?: boolean; format?: CaptureFormat } = {}) =>
    // save/format are sent only when they differ from the defaults (record to a .pcap)
    run(() => api.startLive({ interface: iface, auto_investigate: autoInvestigate,
      ...(opts.save === false ? { save: false } : {}), ...(opts.format && opts.format !== "pcap" ? { format: opts.format } : {}) })), [api, run]);
  const stop = useCallback(() => run(() => api.stopLive()), [api, run]);

  return { interfaces, status, backendDown, actionError, busy, start, stop };
}
