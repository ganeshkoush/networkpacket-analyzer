import { useEffect, useState } from "react";
import type { AboutInfo, AiUsageToday, CleanupPreview, DatabaseInfo, StorageInfo } from "../../api/types";
import { ApiError, backendUrl, BACKEND_URL, isLoopbackUrl, isManagedBackend, setBackendUrl } from "../../api/client";
import { formatBytes, formatNumber } from "../../lib/format";
import { hasNativeDialogs, pickOpenPath, pickSavePath } from "../../lib/nativeFiles";
import { useApi } from "../../state/ApiContext";
import { useSettings } from "../../state/SettingsContext";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { Button, Notice, Spinner } from "../ui/feedback";
import { ActionRow, InfoRow, NumberSetting, Panel, SelectSetting, SettingRow, TextSetting, ToggleSetting, UnavailableRows } from "./controls";
import { DataPolicy } from "./sections";
import { useAction, type ActionState } from "./useAction";

const Outcome = ({ a }: { a: ActionState }) => (
  <>
    {a.message && <div className="py-2"><Notice tone="info">{a.message}</Notice></div>}
    {a.error && <div className="py-2" role="alert"><Notice>{a.error}</Notice></div>}
  </>
);
const NEEDS_DESKTOP = "Choosing a file location needs the PacketMind desktop app.";

// ------------------------------------------------------------------------------------------------ AI / Gemini
export function AiSection() {
  const api = useApi();
  const { payload, adopt, draft } = useSettings();
  const [key, setKey] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);
  const save = useAction(), test = useAction(), remove = useAction();
  const status = payload?.ai;
  const sourceText = !status ? "Checking…" : status.source === "keychain" ? "Configured — stored securely in your system keychain" : status.source === "environment" ? "Configured — from the GEMINI_API_KEY environment variable" : "Not configured";

  const saveKey = async () => {
    const r = await save.run(() => api.saveApiKey(key), () => "API key saved to your system keychain.");
    if (r) { adopt(r); setKey(""); }
  };
  const testIt = () => test.run(() => api.testAiConnection(), (r) => (r.ok ? `Connected to Gemini (${r.model}, ${r.latency_ms} ms). This used one request.` : ""));
  const lastTest = test.error ? null : payload?.ai.last_test;

  return (
    <>
      <DataPolicy />
      <Panel title="Gemini" description="PacketMind's AI investigator. It writes up findings from the evidence PacketMind has already measured locally.">
        <InfoRow title="AI provider" help="The only provider PacketMind supports.">Google Gemini</InfoRow>
        <TextSetting path="ai.model" title="Model" mono placeholder={status?.model ?? "gemini-2.5-flash"} help="Leave empty to use GEMINI_MODEL or the built-in default." />
        <NumberSetting path="ai.timeout_seconds" title="Investigation timeout" nullable placeholder="default" help="How long to wait for Gemini before giving up. Empty uses GEMINI_TIMEOUT_SECONDS or 60." />
        <UnavailableRows section="ai" />
      </Panel>
      <Panel title="API key" description="Write-only. Once saved, the key is never shown again, not even in part.">
        <SettingRow id="key-status" title="API key status" help={status && !status.secure_storage_available ? "No secure storage was found on this computer, so a key cannot be saved here. Set GEMINI_API_KEY in the environment instead." : ""}>
          <span className="text-sm" role="status">{sourceText}</span>
        </SettingRow>
        <SettingRow id="key-input" title="Set a new API key" help="Paste a key from Google AI Studio. It goes straight to your system keychain, not to a settings file or the database.">
          <div className="flex flex-wrap items-center gap-2">
            <input id="key-input" type="password" autoComplete="off" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} placeholder="Paste API key" disabled={status ? !status.secure_storage_available : false}
              aria-describedby="key-input-help" className="w-64 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 font-mono text-sm text-ink placeholder:text-ink-3 disabled:opacity-60" />
            <Button variant="primary" onClick={saveKey} disabled={!key.trim() || save.busy}>Save key</Button>
          </div>
        </SettingRow>
        <Outcome a={save} />
        <ActionRow title="Connection" help="Sends one tiny request to Gemini (no capture data) to check the key, the model and the network. It counts as one request.">
          <Button onClick={testIt} disabled={test.busy || !status?.configured}>{test.busy ? "Testing…" : "Test Connection"}</Button>
          {status?.source === "keychain" && <Button onClick={() => setConfirmRemove(true)}>Remove saved key</Button>}
        </ActionRow>
        <Outcome a={test} />
        {lastTest && !test.message && <p className="py-2 text-xs text-ink-3" role="status">Last test: {lastTest.ok ? "connected" : `failed — ${lastTest.message}`}</p>}
        <Outcome a={remove} />
      </Panel>
      <Panel title="Automatic investigation" description="Applies to live capture when you tick “Automatically investigate suspicious events” before starting. Counted against the daily limits under AI Usage.">
        <ToggleSetting path="ai.auto_critical" title="Automatically investigate critical findings" help="Ask Gemini about critical findings as they appear." />
        <ToggleSetting path="ai.auto_high" title="Automatically investigate high findings" help="Ask Gemini about high-severity findings." />
        <ToggleSetting path="ai.auto_medium" title="Automatically investigate medium findings" help="Ask Gemini about medium-severity findings." />
        <ToggleSetting path="ai.auto_low" title="Automatically investigate low findings" help="Ask Gemini about low-severity findings. Uses more requests." />
        <NumberSetting path="ai.auto_min_confidence" title="Minimum confidence for automatic investigation" step={0.05} help="Only investigate findings at or above this confidence (0 to 1)." />
        <ToggleSetting path="ai_usage.cache_enabled" title="Reuse recent investigation results" help="If the exact same evidence was investigated recently, show that answer instead of asking again." note="The same setting as AI Usage → Enable result caching." />
      </Panel>
      {confirmRemove && (
        <ConfirmDialog title="Remove the saved API key?" confirmLabel="Remove key" danger onCancel={() => setConfirmRemove(false)}
          onConfirm={async () => { const r = await remove.run(() => api.deleteApiKey(), () => "Saved API key removed."); if (r) adopt(r); setConfirmRemove(false); }}>
          <p>The key is deleted from your system keychain. AI features stop working until you add a key again{draft.ai.model ? "" : " (or set GEMINI_API_KEY)"}.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

// ------------------------------------------------------------------------------------------------ AI usage
export function AiUsageSection() {
  const api = useApi();
  const [usage, setUsage] = useState<AiUsageToday | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { const c = new AbortController(); api.getAiUsage(c.signal).then(setUsage).catch((e) => { if (e?.name !== "AbortError") setError("Usage could not be loaded."); }); return () => c.abort(); }, [api]);
  const limit = (n: number) => (n === 0 ? "no limit" : formatNumber(n));
  return (
    <>
      <Panel title="AI Usage Today" description="Request counts, not money: PacketMind cannot know what Google charges.">
        {error && <div className="py-3" role="alert"><Notice>{error}</Notice></div>}
        {!usage && !error && <div className="py-3"><Spinner label="Loading usage…" /></div>}
        {usage && (
          <dl className="grid grid-cols-2 gap-4 py-4 sm:grid-cols-4" aria-label="AI usage today">
            <div><dt className="text-xs text-ink-3">Investigations</dt><dd className="font-mono text-xl">{formatNumber(usage.requests)} <span className="text-sm text-ink-3">/ {limit(usage.daily_limit)}</span></dd></div>
            <div><dt className="text-xs text-ink-3">Automatic</dt><dd className="font-mono text-xl">{formatNumber(usage.automatic)} <span className="text-sm text-ink-3">/ {limit(usage.max_automatic_per_day)}</span></dd></div>
            <div><dt className="text-xs text-ink-3">Cached investigations</dt><dd className="font-mono text-xl">{formatNumber(usage.cached)}</dd></div>
            <div><dt className="text-xs text-ink-3">Blocked by the limit</dt><dd className="font-mono text-xl">{formatNumber(usage.blocked)}</dd></div>
          </dl>
        )}
      </Panel>
      <Panel title="Limits" description="Protect against surprise usage. When a limit is reached the AI step is skipped and everything else keeps working.">
        <NumberSetting path="ai_usage.daily_limit" title="Daily investigation limit" help="Most requests to Gemini per day (UTC). 0 means no limit." />
        <NumberSetting path="ai_usage.max_auto_per_day" title="Maximum automatic investigations per day" help="Most investigations PacketMind may start on its own per day. 0 turns automatic investigation off." />
        <ToggleSetting path="ai_usage.cache_enabled" title="Enable result caching" help="Remember answers for identical evidence so repeating an investigation costs nothing." />
        <NumberSetting path="ai_usage.cache_minutes" title="Cache duration" help="How long a remembered answer is reused." />
        <UnavailableRows section="ai_usage" />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Notifications
export function NotificationsSection() {
  return (
    <>
      <Panel title="Notifications" description="Desktop notifications from PacketMind. Nothing is sent over the network.">
        <ToggleSetting path="notifications.enabled" title="Enable notifications" help="Master switch. Off silences everything below." />
        <ToggleSetting path="notifications.only_in_background" title="Notify only when PacketMind is in the background" help="Skip notifications while you are looking at the PacketMind window." />
        <ToggleSetting path="notifications.sound" title="Sound notifications" help="Play your system's notification sound." />
      </Panel>
      <Panel title="Security">
        <ToggleSetting path="notifications.critical_finding" title="Critical security finding" help="A new critical finding was detected." />
        <ToggleSetting path="notifications.high_finding" title="High security finding" help="A new high-severity finding was detected." />
        <ToggleSetting path="notifications.medium_finding" title="Medium security finding" help="A new medium-severity finding was detected." />
      </Panel>
      <Panel title="Performance, captures and AI">
        <ToggleSetting path="notifications.performance_anomaly" title="Performance anomaly" help="A domain is slower than its usual baseline." />
        <ToggleSetting path="notifications.capture_completed" title="Capture completed" help="A live capture finished and was saved." />
        <ToggleSetting path="notifications.analysis_completed" title="Analysis completed" help="An analysis finished." />
        <ToggleSetting path="notifications.ai_completed" title="AI investigation completed" help="An AI investigation finished." />
        <ToggleSetting path="notifications.capture_error" title="Capture error" help="A live capture failed or could not be saved." />
        <ToggleSetting path="notifications.analysis_error" title="Analysis error" help="An analysis failed." />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Storage
export function StorageSection() {
  const api = useApi();
  const { saved } = useSettings();
  const [info, setInfo] = useState<StorageInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<CleanupPreview | null>(null);
  const open = useAction(), clean = useAction();
  const load = () => { api.getStorageInfo().then(setInfo).catch((e) => setError(e instanceof ApiError ? e.message : "Storage information could not be loaded.")); };
  useEffect(load, [api]); // eslint-disable-line react-hooks/exhaustive-deps

  const loc = (k: string) => info?.locations[k] ?? "not available";
  const folder = (f: "captures" | "reports" | "logs") => open.run(() => api.openFolder(f), () => `Opened the ${f} folder.`);
  const managePreview = async () => { const p = await clean.run(() => api.storageCleanup({ dryRun: true }), (r) => (r.candidates.length ? "" : "Nothing to clean up: no capture matches your retention rules.")); if (p?.candidates.length) setPreview(p); };
  const doClean = async () => {
    const r = await clean.run(() => api.storageCleanup({ dryRun: false, confirm: true }), (x) => `Deleted ${x.deleted} capture${x.deleted === 1 ? "" : "s"} (${formatBytes(x.freed_bytes)}).`);
    setPreview(null); if (r) load();
  };
  const usage = info?.usage;
  return (
    <>
      <Panel title="Storage used" description="Everything PacketMind keeps on this computer.">
        {error && <div className="py-3" role="alert"><Notice>{error}</Notice></div>}
        {!info && !error && <div className="py-3"><Spinner label="Measuring…" /></div>}
        {usage && (
          <dl className="grid grid-cols-2 gap-4 py-4 sm:grid-cols-5" aria-label="Storage usage">
            {([["Captures", usage.captures], ["Reports", usage.reports], ["Database", usage.database], ["Logs", usage.logs], ["Total", usage.total]] as const).map(([k, v]) => (
              <div key={k}><dt className="text-xs text-ink-3">{k}</dt><dd className="font-mono text-lg">{formatBytes(v)}</dd></div>))}
          </dl>
        )}
        <ActionRow title="Folders" help="Open PacketMind's folders in your file manager.">
          <Button onClick={() => folder("captures")} disabled={open.busy}>Open Capture Folder</Button>
          <Button onClick={() => folder("reports")} disabled={open.busy}>Open Report Folder</Button>
          <Button onClick={managePreview} disabled={clean.busy}>Manage Storage</Button>
        </ActionRow>
        <Outcome a={open} /><Outcome a={clean} />
        <InfoRow title="Capture directory" help="Saved and imported captures (private to you).">{loc("captures")}</InfoRow>
        <InfoRow title="Report directory" help="Exported reports.">{loc("reports")}</InfoRow>
        <InfoRow title="Database location" help="Reports, the capture library and performance history.">{loc("database")}</InfoRow>
        <InfoRow title="Log directory" help="PacketMind's own log files (no packet data).">{loc("logs")}</InfoRow>
      </Panel>
      <Panel title="Limits and automatic cleanup" description="Nothing is ever deleted unless you turn on automatic cleanup or confirm a cleanup yourself.">
        <NumberSetting path="storage.max_capture_storage_gb" title="Maximum capture storage" help="New recordings are refused when saved captures use this much space (or, with automatic cleanup, the oldest are removed first)." />
        <ToggleSetting path="storage.auto_delete_old" title="Automatically delete old captures" help="Delete captures older than the retention period (and, if needed, the oldest ones to stay under the limit) when PacketMind starts or before a recording." />
        <NumberSetting path="storage.capture_retention_days" title="Capture retention period" help="Captures older than this are eligible for cleanup." />
        <ToggleSetting path="storage.keep_analyzed" title="Keep analyzed captures" help="Never clean up captures that have been analyzed." />
        <ToggleSetting path="storage.keep_failed" title="Keep failed captures" help="Never clean up captures that failed to save or analyze." />
      </Panel>
      {preview && (
        <ConfirmDialog title="Delete these captures?" confirmLabel={`Delete ${preview.candidates.length} capture${preview.candidates.length === 1 ? "" : "s"}`} danger onCancel={() => setPreview(null)} onConfirm={doClean} busy={clean.busy}>
          <p>Based on your rules ({saved.storage.capture_retention_days}-day retention, {formatBytes(preview.would_free_bytes)} to free) these captures will be permanently deleted:</p>
          <ul className="mt-2 max-h-40 list-disc overflow-auto pl-5 text-xs" aria-label="Captures to delete">{preview.candidates.map((c) => <li key={c.id}><span className="font-mono">{c.name}</span> — {c.reason}</li>)}</ul>
        </ConfirmDialog>
      )}
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Database
export function DatabaseSection() {
  const api = useApi();
  const { saved } = useSettings();
  const [info, setInfo] = useState<DatabaseInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<"restore" | "clear" | null>(null);
  const [restoreFrom, setRestoreFrom] = useState<string | null>(null);
  const [opts, setOpts] = useState({ performanceHistory: true, reports: false, captureSummaries: true, deleteCaptureFiles: false });
  const backup = useAction(), restore = useAction(), clear = useAction();
  const load = () => { api.getDatabaseInfo().then(setInfo).catch((e) => setError(e instanceof ApiError ? e.message : "Database information could not be loaded.")); };
  useEffect(load, [api]); // eslint-disable-line react-hooks/exhaustive-deps

  const doBackup = () => backup.run(async () => {
    const dest = await pickSavePath(`packetmind-backup-${new Date().toISOString().slice(0, 10)}.sqlite3`, [{ name: "PacketMind database backup", extensions: ["sqlite3"] }], "Back up database");
    if (!dest) throw new ApiError("unknown", hasNativeDialogs() ? "No file was chosen." : NEEDS_DESKTOP);
    return api.backupDatabase(dest);
  }, (r) => `Database backed up to ${r.filename} in ${r.directory}.`);
  const chooseRestore = async () => {
    const p = await pickOpenPath([{ name: "PacketMind database backup", extensions: ["sqlite3", "db", "sqlite"] }], "Restore database");
    if (!p) { restore.run(async () => { throw new ApiError("unknown", hasNativeDialogs() ? "No file was chosen." : NEEDS_DESKTOP); }, () => ""); return; }
    setRestoreFrom(p); setConfirm("restore");
  };
  const doRestore = async () => { setConfirm(null); const r = await restore.run(() => api.restoreDatabase(restoreFrom!), (x) => `Database restored. A copy of the previous database was saved as ${x.safety_copy} in the backups folder.`); if (r) setInfo(r.info); };
  const doClear = async () => {
    setConfirm(null);
    const r = await clear.run(() => api.clearAnalysisHistory(opts), (x) => `Cleared: ${x.performance_history ?? 0} history sources, ${x.reports ?? 0} reports, ${x.capture_summaries ?? 0} analysis summaries${x.captures_deleted ? `, ${x.captures_deleted} captures deleted` : ""}.`);
    if (r) load();
  };
  return (
    <>
      <Panel title="Database" description="PacketMind keeps its own records in a local SQLite database.">
        {error && <div className="py-3" role="alert"><Notice>{error}</Notice></div>}
        {!info && !error && <div className="py-3"><Spinner label="Reading database…" /></div>}
        {info && (<>
          <InfoRow title="Database type" help="">{info.type} (schema version {info.schema_version})</InfoRow>
          <InfoRow title="Database location" help="">{info.path ?? "not available"}</InfoRow>
          <InfoRow title="Database size" help="">{formatBytes(info.size_bytes)}</InfoRow>
          <InfoRow title="Number of captures" help="Saved and imported captures in the library.">{formatNumber(info.captures)}</InfoRow>
          <InfoRow title="Number of findings" help="Findings are not stored on their own; this counts those inside saved reports.">{formatNumber(info.findings_in_reports)}</InfoRow>
          <InfoRow title="Number of reports" help="">{formatNumber(info.reports)}</InfoRow>
          <InfoRow title="Retention period" help="Saved reports older than this are deleted at startup. Change it under Privacy.">{saved.privacy.data_retention_days ? `${saved.privacy.data_retention_days} days` : "Kept until you delete them"}</InfoRow>
        </>)}
      </Panel>
      <Panel title="Backup and restore" description="A backup is one file you can keep safe. Restoring replaces the current database; a safety copy is made first.">
        <ActionRow title="Backup" help="Save a copy of the database to a place you choose."><Button onClick={doBackup} disabled={backup.busy}>Backup Database</Button></ActionRow>
        <Outcome a={backup} />
        <ActionRow title="Restore" help="Replace the current database with a backup. Captures files are not part of a database backup."><Button onClick={chooseRestore} disabled={restore.busy}>Restore Database</Button></ActionRow>
        <Outcome a={restore} />
      </Panel>
      <Panel title="Clear analysis history" description="Capture files (PCAPs) are kept unless you explicitly tick the option to delete them.">
        <ActionRow title="Clear" help="Choose what to clear, then confirm.">
          <Button onClick={() => setConfirm("clear")} disabled={clear.busy}>Clear Analysis History</Button>
        </ActionRow>
        <Outcome a={clear} />
      </Panel>
      {confirm === "restore" && (
        <ConfirmDialog title="Restore this database?" confirmLabel="Restore database" danger onCancel={() => setConfirm(null)} onConfirm={doRestore}>
          <p>This replaces your current reports, capture library and history with the contents of the backup. A copy of the current database is saved first.</p>
        </ConfirmDialog>
      )}
      {confirm === "clear" && (
        <ConfirmDialog title="Clear analysis history?" confirmLabel="Clear history" danger onCancel={() => setConfirm(null)} onConfirm={doClear}>
          <p className="mb-2">This cannot be undone. Choose what to clear:</p>
          {([["performanceHistory", "Performance history (baselines)"], ["captureSummaries", "Analysis summaries of captures (the capture files stay)"], ["reports", "Saved reports"]] as const).map(([k, l]) => (
            <label key={k} className="flex items-center gap-2 py-0.5 text-sm"><input type="checkbox" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} /> {l}</label>))}
          <label className="mt-2 flex items-center gap-2 border-t border-line pt-2 text-sm font-medium text-sev-critical">
            <input type="checkbox" checked={opts.deleteCaptureFiles} onChange={(e) => setOpts({ ...opts, deleteCaptureFiles: e.target.checked })} /> Also delete the capture files (PCAPs)</label>
        </ConfirmDialog>
      )}
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Diagnostics
export function DiagnosticsSection() {
  const api = useApi();
  const logs = useAction(), diag = useAction();
  const exportReport = () => diag.run(async () => {
    const dest = await pickSavePath(`packetmind-diagnostics-${new Date().toISOString().slice(0, 10)}.json`, [{ name: "Diagnostic report", extensions: ["json"] }], "Export diagnostic report");
    if (!dest) throw new ApiError("unknown", hasNativeDialogs() ? "No file was chosen." : NEEDS_DESKTOP);
    return api.exportDiagnostics(dest);
  }, (r) => `Diagnostic report saved as ${r.filename} in ${r.directory}. It contains no API keys or packet data.`);
  return (
    <>
      <Panel title="Logging" description="PacketMind's own log. It records what the app did and any errors, never packet contents or API keys.">
        <SelectSetting path="diagnostics.log_level" title="Logging level" help="Error is quietest; Debug records everything and grows fast." options={[["error", "Error"], ["warning", "Warning"], ["info", "Info"], ["debug", "Debug"]]} />
        <ToggleSetting path="diagnostics.save_logs" title="Save logs locally" help="Write the log to a file you can open or send to support." />
        <NumberSetting path="diagnostics.max_log_mb" title="Maximum log size" help="Size of one log file before it is rotated." />
        <ToggleSetting path="diagnostics.rotation" title="Automatic log rotation" help="Keep a few older log files and delete the rest, so logs never fill your disk." />
      </Panel>
      <Panel title="Support tools">
        <ActionRow title="Logs" help="Open the folder that holds the log files."><Button onClick={() => logs.run(() => api.openFolder("logs"), () => "Opened the logs folder.")} disabled={logs.busy}>Open Logs Folder</Button></ActionRow>
        <Outcome a={logs} />
        <ActionRow title="Diagnostic report" help="Versions, your settings, storage sizes and recent redacted log lines, in one file. No API keys, passwords or packet data."><Button onClick={exportReport} disabled={diag.busy}>Export Diagnostic Report</Button></ActionRow>
        <Outcome a={diag} />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Security
export function SecuritySection() {
  const { payload } = useSettings();
  const perms = payload?.ai_permissions ?? { allowed: ["Read network statistics", "Read findings", "Read performance metrics", "Read domain statistics"],
    never: ["Execute commands", "Modify firewall", "Modify routing", "Modify network configuration", "Delete files"] };
  return (
    <>
      <Panel title="Safety controls">
        <ToggleSetting path="security.confirm_delete_captures" title="Confirm before deleting captures" help="Ask first. (The backend also refuses a delete that is not confirmed.)" />
        <ToggleSetting path="security.confirm_clear_history" title="Confirm before clearing history" help="Ask first before clearing analysis history." />
        <ToggleSetting path="security.allow_ai" title="Allow AI features" help="Master switch for every AI feature. Off means nothing is ever sent to Gemini; analysis and detection still work." />
        <UnavailableRows section="security" />
      </Panel>
      <section aria-label="AI Permissions" className="mb-4 rounded-lg border border-line bg-surface-2 p-4">
        <h2 className="text-[13px] font-semibold uppercase tracking-wide text-ink-2">AI Permissions</h2>
        <p className="mt-1 text-xs text-ink-3">Fixed in PacketMind's design. They cannot be changed here or by any settings file: AI only reads analysis results and gives advice.</p>
        <ul className="mt-3 space-y-1 text-sm" aria-label="Allowed AI actions">{perms.allowed.map((p) => <li key={p} className="flex justify-between gap-6"><span>{p}</span><span className="font-mono text-series-3">✓ Allowed</span></li>)}</ul>
        <ul className="mt-2 space-y-1 border-t border-line pt-2 text-sm" aria-label="Forbidden AI actions">{perms.never.map((p) => <li key={p} className="flex justify-between gap-6"><span>{p}</span><span className="font-mono text-sev-critical">✕ Never</span></li>)}</ul>
      </section>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Advanced
export function AdvancedSection() {
  const { saved } = useSettings();
  const [unlocked, setUnlocked] = useState(false);
  const [url, setUrl] = useState(backendUrl());
  const [urlMsg, setUrlMsg] = useState<string | null>(null);
  if (!unlocked) {
    return (
      <Panel title="Advanced settings">
        <div className="py-4"><Notice>These settings are for troubleshooting. Changing them can stop PacketMind from reaching its backend. The defaults are right for almost everyone.</Notice>
          <div className="mt-3"><Button variant="primary" onClick={() => setUnlocked(true)}>Show Advanced Settings</Button></div></div>
      </Panel>
    );
  }
  const apply = () => {
    if (!isLoopbackUrl(url)) { setUrlMsg("The backend address must be on this computer: http://127.0.0.1, http://localhost or http://[::1], optionally with a port."); return; }
    setBackendUrl(url);
    setUrlMsg(url.trim().replace(/\/$/, "") === BACKEND_URL ? "Using the default backend address." : "Backend address saved. Reload PacketMind to use it.");
  };
  return (
    <>
      <Panel title="Connection" description={isManagedBackend()
        ? "PacketMind starts and secures its own local analysis service. Its address and access token change on every launch and are managed automatically."
        : "Where the app finds its local backend. Only addresses on this computer are accepted, so captured data can never be sent elsewhere."}>
        {!isManagedBackend() && (
        <SettingRow id="backend-url" title="Backend URL" help={`The default is ${BACKEND_URL}. Stored in this app only (it is needed before settings can load).`} error={urlMsg && !urlMsg.startsWith("Backend address saved") && !urlMsg.startsWith("Using") ? urlMsg : undefined}
          note={urlMsg && (urlMsg.startsWith("Backend address saved") || urlMsg.startsWith("Using")) ? urlMsg : undefined}>
          <div className="flex items-center gap-2">
            <input id="backend-url" type="text" value={url} onChange={(e) => { setUrl(e.target.value); setUrlMsg(null); }} spellCheck={false} aria-describedby="backend-url-help"
              className="w-64 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 font-mono text-sm text-ink" />
            <Button onClick={apply}>Apply</Button>
          </div>
        </SettingRow>
        )}
        <NumberSetting path="advanced.backend_timeout_seconds" title="Backend timeout" help="How long the app waits for the backend to answer a request. Imports and file operations are not limited." />
        <NumberSetting path="advanced.max_concurrent_analyses" title="Maximum concurrent analyses" help="Captures analyzed at the same time." note="Takes effect the next time the backend starts." />
      </Panel>
      <Panel title="Troubleshooting">
        <ToggleSetting path="advanced.debug_mode" title="Debug mode" help="Verbose logging for troubleshooting. Off by default; logs still never contain packet data or keys." />
        <ToggleSetting path="advanced.show_internal_ids" title="Show internal identifiers" help="Show capture and analysis IDs in lists, useful when reporting a problem." />
        <UnavailableRows section="advanced" />
      </Panel>
      <span hidden>{saved.advanced.debug_mode ? "debug" : ""}</span>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ About
export function AboutSection() {
  const api = useApi();
  const [info, setInfo] = useState<AboutInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [app, setApp] = useState<{ version: string; tauri: string } | null>(null);
  const [tick, setTick] = useState(0);
  const act = useAction();
  useEffect(() => {
    const c = new AbortController();
    setInfo(null); setError(null);
    api.getAbout(c.signal).then(setInfo).catch((e) => { if (e?.name !== "AbortError") setError(e instanceof ApiError ? e.message : "System information could not be loaded."); });
    if (hasNativeDialogs()) import("@tauri-apps/api/app").then(async (m) => setApp({ version: await m.getVersion(), tauri: await m.getTauriVersion() })).catch(() => undefined);
    return () => c.abort();
  }, [api, tick]);
  const priv = { likely: "Likely available", unlikely: "Probably not available", unknown: "Unknown until you start a capture" } as const;
  const ai = info?.ai;
  return (
    <>
      <Panel title="PacketMind" description="AI-Powered Network Security Analyst" actions={<Button onClick={() => setTick((t) => t + 1)}>Check System</Button>}>
        {error && <div className="py-3" role="alert"><Notice>{error}</Notice></div>}
        {!info && !error && <div className="py-3"><Spinner label="Checking the system…" /></div>}
        {info && (<>
          <InfoRow title="Application version" help="">{app?.version ?? info.backend_version}</InfoRow>
          <InfoRow title="Backend version" help="">{info.backend_version}</InfoRow>
          <InfoRow title="Desktop framework" help="">{app ? `Tauri ${app.tauri}` : "Tauri 2 (not running inside the desktop shell)"}</InfoRow>
          <InfoRow title="Python version" help="">{info.python}</InfoRow>
          <InfoRow title="Packet analysis engine" help="">{info.analysis_engine}</InfoRow>
          <InfoRow title="Database engine" help="">{info.database_engine}</InfoRow>
          <InfoRow title="AI provider" help="">{info.ai_provider}</InfoRow>
          <InfoRow title="Gemini connection" help="">{!ai?.configured ? "No API key configured" : !ai.last_test ? "Key configured — not tested yet (use Test Connection under AI / Gemini)" : ai.last_test.ok ? "Connected at last test" : `Last test failed: ${ai.last_test.message}`}</InfoRow>
          <InfoRow title="Operating system" help="">{info.os}</InfoRow>
          <InfoRow title="Architecture" help="">{info.architecture}</InfoRow>
          <InfoRow title="Capture capability" help={info.capture.note}>{info.capture.library_available ? "Capture library installed" : "Capture library missing"}</InfoRow>
          <InfoRow title="Capture permission" help="">{priv[info.capture.privileges]}</InfoRow>
          <InfoRow title="TShark" help="Optional: PacketMind does not need Wireshark/TShark.">{info.tshark ? "Available" : "Not installed (not required)"}</InfoRow>
        </>)}
      </Panel>
      <Panel title="Help">
        <ActionRow title="Documentation and logs" help="Open the documentation folder or the log files.">
          <Button onClick={() => act.run(() => api.openFolder("docs"), () => "Opened the documentation folder.")}>Open Documentation</Button>
          <Button onClick={() => act.run(() => api.openFolder("logs"), () => "Opened the logs folder.")}>Open Logs</Button>
        </ActionRow>
        <Outcome a={act} />
      </Panel>
    </>
  );
}
