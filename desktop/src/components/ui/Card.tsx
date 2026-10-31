import type { ReactNode } from "react";

export function Card({ title, subtitle, actions, children, className = "", padded = true }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean;
}) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold uppercase tracking-wide text-ink-2">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-3">{subtitle}</p>}
          </div>
          {actions && <div className="shrink-0">{actions}</div>}
        </header>
      )}
      <div className={padded ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function StatTile({ label, value, sub, children }: { label: string; value: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wide text-ink-3">{label}</div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums text-ink">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-ink-2">{sub}</div>}
      {children}
    </div>
  );
}
