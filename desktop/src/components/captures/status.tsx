import type { CaptureSession, CaptureStatus } from "../../api/types";

const STATUS: Record<CaptureStatus, { label: string; cls: string }> = {
  CAPTURING: { label: "Capturing", cls: "text-sev-high border-sev-high/40 bg-sev-high/10" },
  COMPLETED: { label: "Ready", cls: "text-sev-low border-sev-low/40 bg-sev-low/10" },
  ANALYZING: { label: "Analyzing", cls: "text-sev-medium border-sev-medium/40 bg-sev-medium/10" },
  ANALYZED: { label: "Analyzed", cls: "text-series-3 border-series-3/40 bg-series-3/10" },
  FAILED: { label: "Failed", cls: "text-sev-critical border-sev-critical/40 bg-sev-critical/10" },
};

export const statusLabel = (s: CaptureStatus) => STATUS[s].label;
export const sourceLabel = (c: Pick<CaptureSession, "source_type">) => (c.source_type === "LIVE_CAPTURE" ? "Live" : "Upload");

export function StatusBadge({ status }: { status: CaptureStatus }) {
  const s = STATUS[status];
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${s.cls}`}>{s.label}</span>;
}
