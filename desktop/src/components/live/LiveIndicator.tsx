import type { LiveState } from "../../api/types";

const MAP: Record<LiveState, { glyph: string; label: string; cls: string }> = {
  capturing: { glyph: "●", label: "Capturing", cls: "text-sev-critical" },
  stopped: { glyph: "○", label: "Stopped", cls: "text-ink-2" },
  permission_error: { glyph: "⚠", label: "Permission error", cls: "text-sev-medium" },
  error: { glyph: "⚠", label: "Capture error", cls: "text-sev-high" },
};

/** ● Capturing / ○ Stopped / ⚠ Permission error. Glyph + text, never colour alone. */
export function LiveIndicator({ state }: { state: LiveState }) {
  const m = MAP[state];
  return (
    <span role="status" aria-live="polite" className={`inline-flex items-center gap-2 text-sm font-semibold ${m.cls}`}>
      <span aria-hidden className={state === "capturing" ? "animate-pulse" : ""}>{m.glyph}</span>
      <span>{m.label}</span>
    </span>
  );
}
