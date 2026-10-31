/** Confidence is an evidence-strength score in [0,1], not a probability that an attack occurred. */
export function ConfidenceMeter({ value, wide = false }: { value: number; wide?: boolean }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="flex items-center gap-2" title={`Confidence ${value.toFixed(2)} (evidence strength, not probability)`}>
      <div
        className={`${wide ? "w-40" : "w-16"} h-1.5 overflow-hidden rounded-full bg-surface-2`}
        role="meter" aria-valuemin={0} aria-valuemax={1} aria-valuenow={value} aria-label="Confidence"
      >
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums text-ink">{value.toFixed(2)}</span>
    </div>
  );
}
