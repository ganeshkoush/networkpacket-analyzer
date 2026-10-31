import type { ReactNode } from "react";

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-ink-2" role="status">
      <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
        <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {label && <span>{label}</span>}
    </span>
  );
}

export function ProgressBar({ percent, label }: { percent: number | null; label: string }) {
  const indeterminate = percent == null;
  return (
    <div
      className="h-2 overflow-hidden rounded-full bg-surface-2"
      role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={indeterminate ? undefined : Math.round(percent)}
    >
      <div
        className={`h-full rounded-full bg-accent ${indeterminate ? "w-1/3 animate-pulse" : ""}`}
        style={indeterminate ? undefined : { width: `${Math.max(2, percent)}%` }}
      />
    </div>
  );
}

export function EmptyState({ title, children, action, icon }: { title: string; children?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-line px-6 py-14 text-center">
      {icon && <div className="mb-3 text-ink-3">{icon}</div>}
      <h3 className="text-base font-semibold text-ink">{title}</h3>
      {children && <div className="mt-1.5 max-w-md text-sm text-ink-2">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorPanel({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div role="alert" className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 p-4">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-sev-critical">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
          <circle cx="12" cy="12" r="9" /><path d="M12 7v6M12 16.5v.5" strokeLinecap="round" />
        </svg>
        {title}
      </h3>
      <div className="mt-1.5 text-sm text-ink-2">{children}</div>
      {actions && <div className="mt-3 flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function Notice({ tone = "warn", children }: { tone?: "warn" | "info"; children: ReactNode }) {
  const c = tone === "warn" ? "border-sev-medium/40 bg-sev-medium/10 text-ink" : "border-sev-low/40 bg-sev-low/10 text-ink";
  return <div role="note" className={`rounded-md border px-3 py-2 text-sm ${c}`}>{children}</div>;
}

const BTN = "inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";
export function Button({ variant = "secondary", className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" }) {
  const styles = {
    primary: "bg-accent text-bg hover:bg-accent/85",
    secondary: "border border-line bg-surface-2 text-ink hover:border-ink-3",
    ghost: "text-ink-2 hover:bg-surface-2 hover:text-ink",
  }[variant];
  return <button type="button" className={`${BTN} ${styles} ${className}`} {...props} />;
}

export const linkButtonClass = (variant: "primary" | "secondary" = "secondary") =>
  `${BTN} ${variant === "primary" ? "bg-accent text-bg hover:bg-accent/85" : "border border-line bg-surface-2 text-ink hover:border-ink-3"}`;
