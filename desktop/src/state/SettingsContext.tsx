import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, isAbort, setRequestTimeout } from "../api/client";
import type { AppSettings, SettingsPayload } from "../api/types";
import { setTimeFormat } from "../lib/format";
import { diff, FALLBACK_SETTINGS, getAt, setAt, validateSettings } from "../lib/settingsSchema";
import { useApi } from "./ApiContext";

interface Value {
  /** The settings in force (saved). Falls back to the defaults until the backend answers. */
  saved: AppSettings;
  draft: AppSettings;
  payload: SettingsPayload | null;
  loading: boolean;
  loadError: string | null;
  dirty: boolean;
  /** Client-side validation of the draft: path -> message. Saving is blocked while this is not empty. */
  errors: Record<string, string>;
  /** Messages from a change the backend rejected. */
  serverErrors: string[];
  saving: boolean;
  /** Set for a few seconds after a successful save ("Saved"). */
  justSaved: boolean;
  setField: (path: string, value: unknown) => void;
  save: () => Promise<boolean>;
  cancel: () => void;
  reset: (section: string | null) => Promise<boolean>;
  /** Use a payload returned by another settings operation (key saved, file imported ...). */
  adopt: (payload: SettingsPayload) => void;
  reload: () => void;
}

const Ctx = createContext<Value | null>(null);
const NOOP_ASYNC = async () => false;

/** Safe outside a provider (component tests, storybook): the defaults, read-only. */
const FALLBACK: Value = {
  saved: FALLBACK_SETTINGS, draft: FALLBACK_SETTINGS, payload: null, loading: false, loadError: null, dirty: false, errors: {}, serverErrors: [], saving: false, justSaved: false,
  setField: () => undefined, save: NOOP_ASYNC, cancel: () => undefined, reset: NOOP_ASYNC, adopt: () => undefined, reload: () => undefined,
};

function resolveTheme(theme: AppSettings["general"]["theme"]): "light" | "dark" {
  if (theme !== "system") return theme;
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/** The one place settings are held in the UI. Pages edit a draft; Save sends one validated change to the backend. */
export function SettingsProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const [payload, setPayload] = useState<SettingsPayload | null>(null);
  const [draft, setDraft] = useState<AppSettings>(FALLBACK_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [justSaved, setJustSaved] = useState(false);
  const [tick, setTick] = useState(0);

  const saved = payload?.settings ?? FALLBACK_SETTINGS;

  useEffect(() => {
    const ctl = new AbortController();
    setLoading(true);
    api.getSettings(ctl.signal).then((p) => { setPayload(p); setDraft(p.settings); setLoadError(null); }).catch((e) => {
      if (!isAbort(e)) setLoadError(e instanceof ApiError ? e.message : "Could not load settings.");
    }).finally(() => setLoading(false));
    return () => ctl.abort();
  }, [api, tick]);

  // Settings that change how the UI itself looks or behaves take effect as soon as they are saved.
  useEffect(() => {
    const root = document.documentElement;
    const apply = () => { root.dataset.theme = resolveTheme(saved.general.theme); };
    apply();
    if (saved.general.theme === "system" && window.matchMedia) {
      const mq = window.matchMedia("(prefers-color-scheme: light)");
      mq.addEventListener?.("change", apply);
      return () => mq.removeEventListener?.("change", apply);
    }
  }, [saved.general.theme]);
  useEffect(() => { setTimeFormat(saved.general.time_format); }, [saved.general.time_format]);
  useEffect(() => { setRequestTimeout(saved.advanced.backend_timeout_seconds); }, [saved.advanced.backend_timeout_seconds]);
  useEffect(() => { document.documentElement.dataset.debug = saved.advanced.debug_mode ? "on" : "off"; }, [saved.advanced.debug_mode]);

  const constraints = payload?.constraints ?? {};
  const errors = useMemo(() => validateSettings(draft, constraints), [draft, constraints]);
  const patch = useMemo(() => diff(saved, draft), [saved, draft]);
  const dirty = patch !== undefined;

  const setField = useCallback((path: string, value: unknown) => { setServerErrors([]); setJustSaved(false); setDraft((d) => setAt(d, path, value)); }, []);
  const adopt = useCallback((p: SettingsPayload) => { setPayload(p); setDraft(p.settings); setServerErrors([]); }, []);

  const save = useCallback(async () => {
    if (!patch || Object.keys(errors).length) return false;
    setSaving(true); setServerErrors([]);
    try {
      adopt(await api.updateSettings(patch as never));
      setJustSaved(true);
      setTimeout(() => setJustSaved(false), 4000);
      return true;
    } catch (e) {
      setServerErrors(e instanceof ApiError ? (e.errors?.map((x) => x.message) ?? [e.message]) : ["The settings could not be saved."]);
      return false;
    } finally { setSaving(false); }
  }, [api, patch, errors, adopt]);

  const cancel = useCallback(() => { setDraft(saved); setServerErrors([]); }, [saved]);

  const reset = useCallback(async (section: string | null) => {
    setSaving(true); setServerErrors([]);
    try { adopt(await api.resetSettings(section)); setJustSaved(true); setTimeout(() => setJustSaved(false), 4000); return true; }
    catch (e) { setServerErrors([e instanceof ApiError ? e.message : "The settings could not be reset."]); return false; }
    finally { setSaving(false); }
  }, [api, adopt]);

  const value = useMemo<Value>(() => ({ saved, draft, payload, loading, loadError, dirty, errors, serverErrors, saving, justSaved, setField, save, cancel, reset, adopt,
    reload: () => setTick((t) => t + 1) }), [saved, draft, payload, loading, loadError, dirty, errors, serverErrors, saving, justSaved, setField, save, cancel, reset, adopt]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSettings(): Value {
  return useContext(Ctx) ?? FALLBACK;
}

/** Typed read of one saved setting by path. */
export function useSetting<T>(path: string): T {
  return getAt(useSettings().saved, path) as T;
}
