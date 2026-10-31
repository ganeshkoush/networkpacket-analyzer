import { useRef, useState, type DragEvent } from "react";
import { Link } from "react-router-dom";
import { ResultTabs } from "../components/results/ResultTabs";
import { Card } from "../components/ui/Card";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, ProgressBar, Spinner } from "../components/ui/feedback";
import { formatBytes, formatDuration, formatNumber } from "../lib/format";
import type { ProblemKind } from "../api/client";
import { useAnalysis, type Problem } from "../state/AnalysisContext";
import { useBackend } from "../state/BackendContext";
import { InvestigateButton } from "../components/investigation/InvestigateButton";
import { SaveReportButton } from "../components/reports/SaveReportButton";
import { PageHeader } from "./Placeholder";

const LARGE_FILE = 500 * 1024 * 1024;

const PROBLEM_TITLES: Record<ProblemKind, string> = {
  backend_unavailable: "Can't reach the PacketMind backend",
  invalid_capture: "Not a valid capture file",
  empty_file: "The file is empty",
  file_too_large: "File is too large",
  unsupported_file_type: "Unsupported file type",
  disk_full: "The disk is full",
  not_found: "Analysis not found",
  analysis_failed: "The analysis failed",
  server_error: "The backend reported an error",
  unknown: "Something went wrong",
};

function ProblemHelp({ problem }: { problem: Problem }) {
  switch (problem.kind) {
    case "backend_unavailable":
      return <>Start the local backend, then try again: <code className="rounded bg-bg px-1.5 py-0.5 font-mono text-xs">cd backend &amp;&amp; .venv/bin/python main.py</code></>;
    case "invalid_capture":
      return <>{problem.message} PacketMind reads classic <strong>.pcap</strong> and <strong>.pcapng</strong> files. Other formats (for example compressed or Snoop captures) need converting first, e.g. with <code className="font-mono text-xs">editcap -F pcapng in out.pcapng</code>.</>;
    case "unsupported_file_type":
      return <>{problem.message} Import a <strong>.pcap</strong> or <strong>.pcapng</strong> capture.</>;
    case "disk_full":
      return <>{problem.message}</>;
    case "file_too_large":
      return <>{problem.message} Split the capture (for example <code className="font-mono text-xs">editcap -c 2000000 in.pcap part.pcap</code>) or filter it down with TShark first.</>;
    case "not_found":
      return <>{problem.message} Run the analysis again.</>;
    default:
      return <>{problem.message}</>;
  }
}

function FilePicker({ onFile, disabled, maxBytes }: { onFile: (f: File) => void; disabled: boolean; maxBytes?: number }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const pick = (files: FileList | null) => { const f = files?.[0]; if (f) onFile(f); if (input.current) input.current.value = ""; };
  const onDrop = (e: DragEvent) => { e.preventDefault(); setOver(false); if (!disabled) pick(e.dataTransfer.files); };
  return (
    <div
      onDragOver={(e) => { e.preventDefault(); if (!disabled) setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}
      className={`flex flex-col items-center rounded-lg border-2 border-dashed px-6 py-14 text-center transition-colors ${over ? "border-accent bg-accent/5" : "border-line bg-surface"}`}>
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--color-ink-3)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><path d="M14 3v6h6M12 18v-6M9.5 14.5 12 12l2.5 2.5" /></svg>
      <h2 className="mt-3 text-base font-semibold">Select a capture to analyze</h2>
      <p className="mt-1 max-w-md text-sm text-ink-2">Drop a <strong>.pcap</strong> or <strong>.pcapng</strong> file here. The file is analyzed by the local backend on this computer and kept in your <Link to="/captures" className="text-accent hover:underline">capture library</Link>. It is never uploaded anywhere else, and never sent to the AI provider.</p>
      <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="sr-only" aria-label="Capture file" tabIndex={-1} onChange={(e) => pick(e.target.files)} />
      <Button variant="primary" className="mt-5" disabled={disabled} onClick={() => input.current?.click()}>Import PCAP</Button>
      {maxBytes ? <p className="mt-3 text-xs text-ink-3">Maximum file size: {formatBytes(maxBytes)}</p> : null}
    </div>
  );
}

export function PcapAnalysis() {
  const { session, analyze, reset } = useAnalysis();
  const backend = useBackend();
  const start = (file: File) => void analyze(file, { maxUploadBytes: backend.info?.max_upload_bytes });
  const offline = backend.status === "offline";

  return (
    <>
      <PageHeader title="PCAP Analysis" subtitle="Analyze a saved capture locally. Packets are parsed and aggregated on this machine." />

      {(session.phase === "idle" || session.phase === "error") && (
        <div className="space-y-4">
          {offline && session.phase === "idle" && (
            <Notice>The backend is not reachable yet — you can pick a file once it is running (see the banner above).</Notice>
          )}
          {session.phase === "error" && (
            <ErrorPanel title={PROBLEM_TITLES[session.problem.kind]}
              actions={<><Button onClick={reset}>Choose another file</Button>{session.problem.kind === "backend_unavailable" && <Button onClick={backend.retry}>Retry connection</Button>}</>}>
              {session.filename && <p className="mb-1 font-mono text-xs text-ink-3">{session.filename}</p>}
              <ProblemHelp problem={session.problem} />
            </ErrorPanel>
          )}
          {session.phase === "idle" && <FilePicker onFile={start} disabled={false} maxBytes={backend.info?.max_upload_bytes} />}
        </div>
      )}

      {(session.phase === "uploading" || session.phase === "analyzing") && (
        <Card>
          <div className="space-y-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div className="min-w-0"><div className="truncate font-mono text-[13.5px]" title={session.filename}>{session.filename}</div><div className="text-xs text-ink-3">{formatBytes(session.size)}</div></div>
              <Spinner label={session.phase === "uploading" ? "Sending to local backend…" : "Analyzing packets…"} />
            </div>
            <ProgressBar label="Analysis progress" percent={session.phase === "analyzing" ? session.job.progress_percent : null} />
            {session.phase === "analyzing" && (
              <div className="flex justify-between font-mono text-xs tabular-nums text-ink-2">
                <span>{formatNumber(session.job.packets_read)} packets read</span>
                <span>{session.job.progress_percent != null ? `${session.job.progress_percent.toFixed(0)}%` : ""} {session.job.elapsed_seconds != null ? `· ${formatDuration(session.job.elapsed_seconds)}` : ""}</span>
              </div>
            )}
            {session.size > LARGE_FILE && <Notice tone="info">This is a large capture. Analysis can take several minutes; you can keep using other pages meanwhile.</Notice>}
            <Button variant="ghost" onClick={reset}>Cancel</Button>
          </div>
        </Card>
      )}

      {session.phase === "ready" && (() => {
        const { analysis: a, findings, detector_errors } = session.bundle;
        const empty = a.packet_statistics.total_packets === 0;
        return (
          <div className="space-y-4">
            <Card>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-mono text-[14px]" title={a.metadata.file_name}>{a.metadata.file_name}</div>
                  <div className="text-xs text-ink-2">
                    {formatNumber(a.packet_statistics.total_packets)} packets · {formatBytes(a.metadata.file_size_bytes)} · {formatDuration(a.metadata.duration_seconds)} · analyzed in {formatDuration(a.metadata.analysis_seconds)}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {!empty && <InvestigateButton analysisId={session.bundle.job.id} />}
                  <Link to="/" className={linkButtonClass()}>Dashboard</Link>
                  <Link to="/findings" className={linkButtonClass("primary")}>{findings.length} finding{findings.length === 1 ? "" : "s"}</Link>
                  <Button onClick={reset}>New analysis</Button>
                </div>
              </div>
              {!empty && <div className="mt-3 border-t border-line pt-3"><SaveReportButton source="analysis" analysisId={session.bundle.job.id} defaultTitle={`Investigation of ${a.metadata.file_name}`} /></div>}
            </Card>
            {a.metadata.warnings.map((w) => <Notice key={w}>{w}</Notice>)}
            {Object.entries(detector_errors).map(([k, v]) => <Notice key={k}>Detector “{k}” failed and was skipped: {v}</Notice>)}
            {empty ? (
              <EmptyState title="This capture contains no packets">The file is a valid capture but has no packets to analyze. Check that the capture was running on the right interface or that a filter did not discard everything.</EmptyState>
            ) : <ResultTabs a={a} />}
          </div>
        );
      })()}
    </>
  );
}
