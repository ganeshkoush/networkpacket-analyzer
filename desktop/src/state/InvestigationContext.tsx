import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, isAbort } from "../api/client";
import type { NetworkInvestigation } from "../api/types";
import { useApi } from "./ApiContext";
import { useAnalysis } from "./AnalysisContext";

export type InvestigationState =
  | { phase: "idle" }
  | { phase: "running"; analysisId: string; useAi: boolean }
  | { phase: "done"; analysisId: string; result: NetworkInvestigation }
  | { phase: "error"; analysisId: string; message: string; useAi: boolean };

interface Value {
  state: InvestigationState;
  /** One click: the backend measures locally and (unless `useAi` is false) asks Gemini to analyse that summary. */
  run: (analysisId: string, useAi?: boolean) => Promise<void>;
}

const Ctx = createContext<Value | null>(null);

/** Keeps the latest investigation across page navigation; it is dropped when the loaded capture changes. */
export function InvestigationProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const { session } = useAnalysis();
  const [state, setState] = useState<InvestigationState>({ phase: "idle" });
  const ctl = useRef<AbortController | null>(null);
  const currentId = session.phase === "ready" ? session.bundle.job.id : null;

  useEffect(() => () => ctl.current?.abort(), []);
  useEffect(() => {
    if (state.phase !== "idle" && state.analysisId !== currentId) { ctl.current?.abort(); setState({ phase: "idle" }); }
  }, [currentId, state]);

  const run = useCallback(async (analysisId: string, useAi = true) => {
    ctl.current?.abort();
    const controller = new AbortController();
    ctl.current = controller;
    setState({ phase: "running", analysisId, useAi });
    try {
      const result = await api.investigateNetwork(analysisId, { useAi }, controller.signal);
      setState({ phase: "done", analysisId, result });
    } catch (e) {
      if (isAbort(e)) return;
      setState({ phase: "error", analysisId, useAi, message: e instanceof ApiError ? e.message : "The investigation could not be completed." });
    }
  }, [api]);

  const value = useMemo(() => ({ state, run }), [state, run]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useInvestigation(): Value {
  const v = useContext(Ctx);
  if (!v) throw new Error("useInvestigation must be used inside <InvestigationProvider>");
  return v;
}
