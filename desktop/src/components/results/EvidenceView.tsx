import { humanizeKey } from "../../lib/format";

function scalar(v: unknown): string {
  if (v == null) return "–";
  if (typeof v === "number") return Number.isInteger(v) ? v.toLocaleString("en-US") : String(Math.round(v * 10000) / 10000);
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}

function isScalar(v: unknown): boolean {
  return v == null || typeof v !== "object";
}

function Value({ v }: { v: unknown }) {
  if (isScalar(v)) return <span className="break-all font-mono text-ink">{scalar(v)}</span>;
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="text-ink-3">none</span>;
    if (v.every(isScalar)) {
      return <span className="flex flex-wrap gap-1">{v.map((x, i) => <span key={i} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink">{scalar(x)}</span>)}</span>;
    }
    return <ul className="space-y-1">{v.map((x, i) => <li key={i} className="rounded border border-line/70 bg-bg/40 p-2"><Value v={x} /></li>)}</ul>;
  }
  return <Entries data={v as Record<string, unknown>} />;
}

function Entries({ data }: { data: Record<string, unknown> }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-5 gap-y-1.5 text-[13px]">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="contents"><dt className="text-ink-3">{humanizeKey(k)}</dt><dd className="min-w-0"><Value v={v} /></dd></div>
      ))}
    </dl>
  );
}

/** Renders a finding's `evidence` object (arbitrary JSON) as labelled values. */
export function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  if (Object.keys(evidence).length === 0) return <p className="text-sm text-ink-3">No evidence recorded.</p>;
  return <Entries data={evidence} />;
}
