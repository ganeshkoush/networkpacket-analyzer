import type { ReactNode } from "react";

export interface BarItem { key: string; label: ReactNode; value: number; valueLabel: string; sub?: ReactNode }

/** Ranked horizontal bars. Single series, so no legend: the card title names it. Values are labelled directly. */
export function BarList({ items, ariaLabel, empty = "No data." }: { items: BarItem[]; ariaLabel: string; empty?: string }) {
  if (items.length === 0) return <p className="text-sm text-ink-3">{empty}</p>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="space-y-2.5" aria-label={ariaLabel}>
      {items.map((it) => (
        <li key={it.key} title={`${typeof it.label === "string" ? it.label : it.key}: ${it.valueLabel}`}>
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[13px]">
            <span className="min-w-0 truncate">{it.label}</span>
            <span className="shrink-0 font-mono tabular-nums text-ink-2">{it.valueLabel}</span>
          </div>
          <div className="h-1.5 rounded-r-[4px] rounded-l-[1px] bg-surface-2">
            <div className="h-full rounded-r-[4px] rounded-l-[1px] bg-series-1" style={{ width: `${Math.max(1.5, (it.value / max) * 100)}%` }} />
          </div>
          {it.sub && <div className="mt-0.5 text-xs text-ink-3">{it.sub}</div>}
        </li>
      ))}
    </ul>
  );
}
