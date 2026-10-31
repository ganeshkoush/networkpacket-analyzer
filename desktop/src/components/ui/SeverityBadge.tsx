import type { Severity } from "../../api/types";
import { SEVERITY_STYLE } from "../../lib/severity";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${s.text} ${s.bg} ${s.border}`}
      aria-label={`Severity ${severity}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden />
      {severity}
    </span>
  );
}
