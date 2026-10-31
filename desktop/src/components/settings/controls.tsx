import { useId, useState, type ReactNode } from "react";
import { NUMERIC_LABELS, getAt } from "../../lib/settingsSchema";
import { useSettings } from "../../state/SettingsContext";
import { Button } from "../ui/feedback";

/** One setting: a title, a short plain-language explanation, and the control. Errors and "unavailable" reasons are text, not colour. */
export function SettingRow({ id, title, help, children, error, disabledReason, note }: {
  id: string; title: string; help: ReactNode; children?: ReactNode; error?: string; disabledReason?: string; note?: ReactNode;
}) {
  return (
    <div className={`flex flex-col gap-2 border-b border-line py-3.5 last:border-b-0 sm:flex-row sm:items-start sm:justify-between sm:gap-6 ${disabledReason ? "opacity-75" : ""}`}>
      <div className="min-w-0 sm:max-w-xl">
        <label htmlFor={id} id={`${id}-label`} className="text-[13.5px] font-medium text-ink">{title}</label>
        <p id={`${id}-help`} className="mt-0.5 text-xs leading-relaxed text-ink-2">{help}</p>
        {disabledReason && <p className="mt-1 text-xs text-ink-3"><strong className="font-semibold">Not available:</strong> {disabledReason}</p>}
        {note && <p className="mt-1 text-xs text-ink-3">{note}</p>}
        {error && <p role="alert" className="mt-1 text-xs font-medium text-sev-critical">{error}</p>}
      </div>
      {children && <div className="shrink-0 sm:pt-0.5">{children}</div>}
    </div>
  );
}

export function Switch({ id, checked, onChange, disabled, label }: { id: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button id={id} type="button" role="switch" aria-checked={checked} aria-labelledby={label ? undefined : `${id}-label`} aria-label={label} disabled={disabled}
      aria-describedby={`${id}-help`} onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${checked ? "border-accent bg-accent" : "border-line bg-surface-2"}`}>
      <span aria-hidden className={`inline-block h-4 w-4 rounded-full transition-transform ${checked ? "translate-x-6 bg-bg" : "translate-x-1 bg-ink-2"}`} />
      <span className="sr-only">{checked ? "On" : "Off"}</span>
    </button>
  );
}

/** Bound to the draft settings by path: a toggle. "On"/"Off" is also written out, so state never relies on colour. */
export function ToggleSetting({ path, title, help, invert = false, note }: { path: string; title: string; help: ReactNode; invert?: boolean; note?: ReactNode }) {
  const { draft, setField } = useSettings();
  const id = useId();
  const raw = getAt(draft, path) as boolean;
  const checked = invert ? !raw : raw;
  return (
    <SettingRow id={id} title={title} help={help} note={note}>
      <div className="flex items-center gap-2"><span className="w-7 text-right text-xs text-ink-3" aria-hidden>{checked ? "On" : "Off"}</span>
        <Switch id={id} checked={checked} onChange={(v) => setField(path, invert ? !v : v)} /></div>
    </SettingRow>
  );
}

const INPUT = "rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-3 disabled:opacity-60";

export function NumberSetting({ path, title, help, step = 1, nullable = false, placeholder, note }: {
  path: string; title: string; help: ReactNode; step?: number; nullable?: boolean; placeholder?: string; note?: ReactNode;
}) {
  const { draft, setField, errors } = useSettings();
  const id = useId();
  const value = getAt(draft, path) as number | null;
  const [text, setText] = useState<string | null>(null); // while typing, show exactly what was typed
  const shown = text ?? (value === null || value === undefined ? "" : String(value));
  const unit = NUMERIC_LABELS[path]?.unit?.trim();
  return (
    <SettingRow id={id} title={title} help={help} error={errors[path]} note={note}>
      <div className="flex items-center gap-2">
        <input id={id} type="number" inputMode="decimal" step={step} value={shown} placeholder={placeholder} aria-invalid={Boolean(errors[path])} aria-describedby={`${id}-help`}
          onChange={(e) => { setText(e.target.value); setField(path, e.target.value === "" ? (nullable ? null : Number.NaN) : Number(e.target.value)); }}
          onBlur={() => setText(null)} className={`${INPUT} w-28 text-right tabular-nums ${errors[path] ? "border-sev-critical" : ""}`} />
        {unit && <span className="w-16 text-xs text-ink-3">{unit}</span>}
      </div>
    </SettingRow>
  );
}

export function SelectSetting({ path, title, help, options, note, disabled }: {
  path: string; title: string; help: ReactNode; options: [string, string][]; note?: ReactNode; disabled?: boolean;
}) {
  const { draft, setField } = useSettings();
  const id = useId();
  return (
    <SettingRow id={id} title={title} help={help} note={note}>
      <select id={id} value={String(getAt(draft, path))} disabled={disabled} aria-describedby={`${id}-help`} onChange={(e) => setField(path, e.target.value)} className={`${INPUT} min-w-40`}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
    </SettingRow>
  );
}

/** A yes/no setting shown as a two-way choice ("Full packets" / "Headers only") that is stored as a boolean. */
export function ChoiceSetting({ path, title, help, whenTrue, whenFalse, note }: { path: string; title: string; help: ReactNode; whenTrue: string; whenFalse: string; note?: ReactNode }) {
  const { draft, setField } = useSettings();
  const id = useId();
  const v = getAt(draft, path) as boolean;
  return (
    <SettingRow id={id} title={title} help={help} note={note}>
      <select id={id} value={v ? "t" : "f"} aria-describedby={`${id}-help`} onChange={(e) => setField(path, e.target.value === "t")} className={`${INPUT} min-w-40`}>
        <option value="t">{whenTrue}</option><option value="f">{whenFalse}</option>
      </select>
    </SettingRow>
  );
}

export function TextSetting({ path, title, help, placeholder, note, mono = false }: { path: string; title: string; help: ReactNode; placeholder?: string; note?: ReactNode; mono?: boolean }) {
  const { draft, setField, errors } = useSettings();
  const id = useId();
  return (
    <SettingRow id={id} title={title} help={help} error={errors[path]} note={note}>
      <input id={id} type="text" value={String(getAt(draft, path) ?? "")} placeholder={placeholder} maxLength={100} autoComplete="off" spellCheck={false} aria-describedby={`${id}-help`}
        onChange={(e) => setField(path, e.target.value)} className={`${INPUT} w-64 ${mono ? "font-mono" : ""}`} />
    </SettingRow>
  );
}

/** A read-only fact (a folder, a version) shown in the same layout as a setting. */
export function InfoRow({ title, children, help }: { title: string; children: ReactNode; help?: ReactNode }) {
  const id = useId();
  return (
    <SettingRow id={id} title={title} help={help ?? ""}>
      <div className="max-w-md break-all text-right font-mono text-[13px] text-ink">{children}</div>
    </SettingRow>
  );
}

/** A control PacketMind cannot honour: shown, disabled, with the reason. Never stored. */
export function UnavailableRows({ section }: { section: string }) {
  const { payload } = useSettings();
  const items = payload?.unavailable[section] ?? [];
  if (!items.length) return null;
  return (
    <div className="mt-2" aria-label="Unavailable settings">
      {items.map((u) => (
        <SettingRow key={u.key} id={`na-${section}-${u.key}`} title={u.label} help="" disabledReason={u.reason}>
          <Switch id={`na-${section}-${u.key}`} checked={false} disabled onChange={() => undefined} label={`${u.label} (not available)`} />
        </SettingRow>
      ))}
    </div>
  );
}

export function Panel({ title, description, children, actions }: { title: string; description?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section aria-label={title} className="mb-4 rounded-lg border border-line bg-surface">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div><h2 className="text-[13px] font-semibold uppercase tracking-wide text-ink-2">{title}</h2>{description && <p className="mt-0.5 text-xs text-ink-3">{description}</p>}</div>
        {actions}
      </header>
      <div className="px-4">{children}</div>
    </section>
  );
}

export function ActionRow({ title, help, children }: { title: string; help: ReactNode; children: ReactNode }) {
  const id = useId();
  return <SettingRow id={id} title={title} help={help}>{<div className="flex flex-wrap justify-end gap-2">{children}</div>}</SettingRow>;
}

/** Shown while there are unsaved changes (or just after a save). Settings are saved explicitly, all together. */
export function SaveBar() {
  const { dirty, saving, errors, serverErrors, save, cancel, justSaved } = useSettings();
  const invalid = Object.keys(errors).length > 0;
  if (!dirty && !justSaved && !serverErrors.length) return null;
  return (
    <div role="region" aria-label="Unsaved changes" className="sticky bottom-0 z-10 -mx-6 mt-2 border-t border-line bg-surface/95 px-6 py-3 backdrop-blur">
      {serverErrors.length > 0 && <ul role="alert" className="mb-2 list-disc space-y-0.5 pl-5 text-xs font-medium text-sev-critical">{serverErrors.map((m) => <li key={m}>{m}</li>)}</ul>}
      <div className="flex flex-wrap items-center gap-3">
        {dirty ? <span className="text-sm text-ink-2">You have unsaved changes.{invalid && <strong className="ml-2 text-sev-critical">Fix the highlighted values to save.</strong>}</span>
               : <span role="status" className="text-sm font-medium text-series-3">Saved</span>}
        {dirty && <div className="ml-auto flex gap-2"><Button onClick={cancel} disabled={saving}>Cancel</Button><Button variant="primary" onClick={() => void save()} disabled={saving || invalid}>{saving ? "Saving…" : "Save Changes"}</Button></div>}
      </div>
    </div>
  );
}
