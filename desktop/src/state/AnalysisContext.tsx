import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api as defaultApi, ApiError, isAbort, type Api, type ProblemKind } from "../api/client";
import type { AnalysisBundle, JobStatus } from "../api/types";

export interface Problem { kind: ProblemKind; message: string }

export type Session =
  | { phase: "idle" }
  | { phase: "uploading"; filename: string; size: number }
  | { phase: "analyzing"; filename: string; size: number; job: JobStatus }
  | { phase: "ready"; filename: string; size: number; bundle: AnalysisBundle }
  | { phase: "error"; filename: string | null; problem: Problem };

interface AnalysisValue {
  session: Session;
  /** Upload and analyze a capture. `maxUploadBytes` (from the backend) lets us reject oversize files early. */
  analyze: (file: File, opts?: { maxUploadBytes?: number }) => Promise<void>;
  /** Analyze a capture that is already in the library (a live recording or an earlier import); `force` re-runs the pipeline. */
  openCapture: (capture: { id: string; original_filename: string; file_size: number }, opts?: { force?: boolean }) => Promise<void>;
  reset: () => void;
}

const Ctx = createContext<AnalysisValue | null>(null);

function toProblem(e: unknown): Problem {
  if (e instanceof ApiError) return { kind: e.kind, message: e.message };
  return { kind: "unknown", message: e instanceof Error ? e.message : "Unexpected error." };
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new DOMException("Aborted", "AbortError"));
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("Aborted", "AbortError")); }, { once: true });
  });
}

const MAX_POLL_FAILURES = 3;

/**
 * Holds the current analysis for the whole app, so results survive navigation between pages.
 * The provider only orchestrates upload -> poll -> fetch; all analysis is done by the backend.
 */
export function AnalysisProvider({
  children, api = defaultApi, pollIntervalMs = 400,
}: { children: ReactNode; api?: Omit<Api, "fetchHealth">; pollIntervalMs?: number }) {
  const [session, setSession] = useState<Session>({ phase: "idle" });
  const ctl = useRef<AbortController | null>(null);

  useEffect(() => () => ctl.current?.abort(), []);

  const reset = useCallback(() => { ctl.current?.abort(); ctl.current = null; setSession({ phase: "idle" }); }, []);

  /** Shared by import and library analysis: start a job, poll it to the end, fetch the result. */
  const run = useCallback(async (base: { filename: string; size: number }, start: (signal: AbortSignal) => Promise<JobStatus>) => {
    ctl.current?.abort();
    const controller = new AbortController();
    ctl.current = controller;
    const { signal } = controller;
    setSession({ phase: "uploading", ...base });
    try {
      let job = await start(signal);
      let failures = 0;
      for (;;) {
        setSession({ phase: "analyzing", ...base, job });
        if (job.status === "completed") break;
        if (job.status === "failed") {
          const code = job.error?.code as ProblemKind | undefined;
          throw new ApiError(code ?? "analysis_failed", job.error?.message ?? "The analysis failed.");
        }
        await sleep(pollIntervalMs, signal);
        try {
          job = await api.getStatus(job.id, signal);
          failures = 0;
        } catch (e) {
          if (isAbort(e) || ++failures >= MAX_POLL_FAILURES) throw e; // tolerate brief blips
        }
      }
      const bundle = await api.getResult(job.id, signal);
      setSession({ phase: "ready", ...base, bundle });
    } catch (e) {
      if (isAbort(e)) return;
      setSession({ phase: "error", filename: base.filename, problem: toProblem(e) });
    }
  }, [api, pollIntervalMs]);

  const analyze = useCallback(async (file: File, opts?: { maxUploadBytes?: number }) => {
    await run({ filename: file.name, size: file.size }, async (signal) => {
      if (opts?.maxUploadBytes && file.size > opts.maxUploadBytes) {
        throw new ApiError("file_too_large", "This file is larger than the backend's upload limit.");
      }
      return api.submitCapture(file, signal);
    });
  }, [api, run]);

  const openCapture = useCallback(async (capture: { id: string; original_filename: string; file_size: number }, opts?: { force?: boolean }) => {
    await run({ filename: capture.original_filename, size: capture.file_size }, (signal) => api.analyzeCapture(capture.id, { force: opts?.force }, signal));
  }, [api, run]);

  const value = useMemo(() => ({ session, analyze, openCapture, reset }), [session, analyze, openCapture, reset]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAnalysis(): AnalysisValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAnalysis must be used inside <AnalysisProvider>");
  return v;
}

/** The completed analysis, or null if none is loaded. */
export function useBundle(): AnalysisBundle | null {
  const { session } = useAnalysis();
  return session.phase === "ready" ? session.bundle : null;
}
