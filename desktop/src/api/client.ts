// The only module that talks to the backend. All analysis happens in the Python service;
// this layer just moves files and JSON.
import type {
  AnalysisBundle, CreateReportRequest, ExportFormat, ExportResult, Health, InterfaceInfo, JobStatus, LiveStatus,
  ReportListItem, SavedReport, StartLiveRequest, SystemInfo, WebActivityList, WebActivityQuery, WebDomainDetail,
  AboutInfo, AiUsageToday, AnomalyList, AppSettings, CaptureExportResult, CleanupPreview, DatabaseInfo, SavedFile, SettingsPayload, StorageInfo, CaptureSession, CorrelationList, DashboardData, DashboardRange, NetworkInvestigation, DomainApplications, DomainBaselineView, HistoryStatus, NetworkMapData, NetworkMapQuery, ProcessSnapshotSummary, ProcessSourceStatus,
} from "./types";

export const BACKEND_URL: string =
  import.meta.env.VITE_BACKEND_URL ?? "http://127.0.0.1:8765";

// Settings → Advanced. The backend address is needed before any setting can be loaded, so it is kept in this browser profile
// (localStorage), and only loopback addresses are accepted: packet data must never be sent anywhere else.
const URL_KEY = "packetmind.backendUrl";
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?\/?$/;
export const isLoopbackUrl = (u: string): boolean => LOOPBACK.test(u.trim());

// Installed app: the desktop shell starts the backend on a free port with a per-launch token and hands both over at startup
// (see lib/bootstrap.ts). These then win over every other setting. Plain browser / `tauri dev`: nothing is set, the defaults apply.
let managed: { url: string; token: string } | null = null;
export function configureBackend(c: { url: string; token: string } | null): void { managed = c; }
export const isManagedBackend = (): boolean => managed !== null;
/** fetch() to the backend: adds the per-launch access token when there is one. */
function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  if (!managed) return fetch(input, init);
  const headers = new Headers(init.headers);
  headers.set("X-PacketMind-Token", managed.token);
  return fetch(input, { ...init, headers });
}

export function backendUrl(): string {
  if (managed) return managed.url;
  try {
    const saved = localStorage.getItem(URL_KEY);
    if (saved && isLoopbackUrl(saved)) return saved.trim().replace(/\/$/, "");
  } catch { /* storage unavailable */ }
  return BACKEND_URL;
}
export function setBackendUrl(url: string | null): void {
  try { if (url && isLoopbackUrl(url) && url.trim().replace(/\/$/, "") !== BACKEND_URL) localStorage.setItem(URL_KEY, url.trim()); else localStorage.removeItem(URL_KEY); } catch { /* ignore */ }
}
let requestTimeoutMs = 0; // 0 = none; set from Settings → Advanced
export function setRequestTimeout(seconds: number): void { requestTimeoutMs = seconds > 0 ? seconds * 1000 : 0; }

export type ProblemKind =
  | "backend_unavailable"
  | "invalid_capture"
  | "empty_file"
  | "file_too_large"
  | "unsupported_file_type"
  | "disk_full"
  | "not_found"
  | "analysis_failed"
  | "server_error"
  | "unknown";

const KNOWN_KINDS = new Set<string>([
  "invalid_capture", "empty_file", "file_too_large", "not_found", "analysis_failed", "file_missing", "unsupported_file_type", "disk_full",
]);

/** A failure the UI can describe to the user. */
export class ApiError extends Error {
  /** Per-field messages from a rejected settings change. */
  errors?: { field: string; message: string }[];
  constructor(public kind: ProblemKind, message: string, public status?: number, public code?: string, public hint?: string) {
    super(message);
    this.name = "ApiError";
  }
}

export function isAbort(e: unknown): boolean {
  return (e instanceof DOMException && e.name === "AbortError") || (e instanceof Error && e.name === "AbortError");
}

/** `long: true` for uploads and file operations that may legitimately take minutes: no timeout. */
async function request<T>(path: string, init?: RequestInit, opts: { long?: boolean } = {}): Promise<T> {
  let res: Response;
  const base = backendUrl();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  if (requestTimeoutMs && !opts.long && typeof AbortController !== "undefined") {
    const controller = new AbortController();
    const outer = init?.signal;
    if (outer) outer.addEventListener("abort", () => controller.abort(), { once: true });
    timer = setTimeout(() => { timedOut = true; controller.abort(); }, requestTimeoutMs);
    init = { ...init, signal: controller.signal };
  }
  try {
    res = await apiFetch(`${base}${path}`, init);
  } catch (e) {
    if (timedOut) throw new ApiError("backend_unavailable", "The PacketMind backend did not answer in time (see Settings → Advanced → Backend timeout).");
    if (isAbort(e)) throw e;
    throw new ApiError("backend_unavailable", `Cannot reach the PacketMind backend at ${base}.`);
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw await toApiError(res);
  return (await res.json()) as T;
}

async function toApiError(res: Response): Promise<ApiError> {
  let code: string | undefined;
  let message: string | undefined;
  let hint: string | undefined;
  let fieldErrors: { field: string; message: string }[] | undefined;
  try {
    const body = await res.json();
    code = body?.detail?.code;
    fieldErrors = Array.isArray(body?.detail?.errors) ? body.detail.errors : undefined;
    hint = body?.detail?.hint ?? undefined;
    message = body?.detail?.message ?? (typeof body?.detail === "string" ? body.detail : undefined);
  } catch {
    /* non-JSON error body */
  }
  const kind: ProblemKind =
    code && KNOWN_KINDS.has(code)
      ? (code === "file_missing" ? "analysis_failed" : (code as ProblemKind))
      : res.status >= 500 ? "server_error" : "unknown";
  const err = new ApiError(kind, message ?? `The backend returned an error (HTTP ${res.status}).`, res.status, code, hint);
  err.errors = fieldErrors;
  return err;
}

export type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

export interface Api {
  fetchHealth(signal?: AbortSignal): Promise<Health>;
  getSystem(signal?: AbortSignal): Promise<SystemInfo>;
  submitCapture(file: File, signal?: AbortSignal): Promise<JobStatus>;
  getStatus(id: string, signal?: AbortSignal): Promise<JobStatus>;
  getResult(id: string, signal?: AbortSignal): Promise<AnalysisBundle>;
  /** Domain / web activity table; the backend does the searching, sorting, filtering and paging. */
  listWebActivity(id: string, query?: WebActivityQuery, signal?: AbortSignal): Promise<WebActivityList>;
  /** The network map (local host -> domains -> IPs -> ports); filtering and the node budget are applied by the backend. */
  getNetworkMap(id: string, query?: NetworkMapQuery, signal?: AbortSignal): Promise<NetworkMapData>;
  /** Whether this OS can map connections to processes, what permission that needs, and what has been collected. */
  getProcessStatus(signal?: AbortSignal): Promise<ProcessSourceStatus>;
  /** Reads the OS socket table once (read-only). Only ever called from an explicit user action. */
  takeProcessSnapshot(): Promise<ProcessSnapshotSummary>;
  startProcessWatch(intervalSeconds?: number): Promise<ProcessSourceStatus>;
  stopProcessWatch(): Promise<ProcessSourceStatus>;
  /** Forgets collected snapshots; the backend refuses unless confirm=true, which only the confirmed UI path sends. */
  clearProcessSnapshots(): Promise<void>;
  /** Applications that held a domain's connections according to OS snapshots (never from packets). */
  getDomainApplications(id: string, domain: string, signal?: AbortSignal): Promise<DomainApplications>;
  /** Performance changes that are potentially related to a finding (correlation, not causation). */
  getCorrelations(id: string, findingId: string, signal?: AbortSignal): Promise<CorrelationList>;
  /** Performance anomalies of this capture against the domains' own earlier captures (local history). */
  getAnomalies(id: string, signal?: AbortSignal): Promise<AnomalyList>;
  /** Historical baseline vs this capture for one domain, plus its stored history for charts. */
  getDomainBaseline(id: string, domain: string, signal?: AbortSignal): Promise<DomainBaselineView>;
  /** One-click investigation: local measurements and rating, plus an optional Gemini analysis of that summary (never of the capture). */
  investigateNetwork(id: string, opts?: { useAi?: boolean }, signal?: AbortSignal): Promise<NetworkInvestigation>;
  /** Network Intelligence Dashboard for a capture; the backend aggregates and caps everything. */
  getDashboard(id: string, range?: DashboardRange, signal?: AbortSignal): Promise<DashboardData>;
  /** The same dashboard for the live capture's rolling window. */
  getLiveDashboard(range?: DashboardRange, signal?: AbortSignal): Promise<DashboardData>;
  // ---- capture library
  listCaptures(signal?: AbortSignal): Promise<CaptureSession[]>;
  getCapture(id: string, signal?: AbortSignal): Promise<CaptureSession>;
  /** Analyze (or, with `force`, analyze again) a saved capture with the current pipeline; the file is never modified. */
  analyzeCapture(id: string, opts?: { force?: boolean }, signal?: AbortSignal): Promise<JobStatus>;
  /** Copies the capture to a destination the user chose in the save dialog; the backend validates it. */
  exportCapture(id: string, destination: string, overwrite?: boolean): Promise<CaptureExportResult>;
  /** URL that streams the capture as a file (browser fallback when there is no native save dialog). */
  captureDownloadUrl(id: string): string;
  /** Permanently deletes; the backend refuses unless confirm=true, which only the confirmed UI path sends. */
  deleteCapture(id: string): Promise<void>;
  // ---- settings (one validated document; secrets are write-only)
  getSettings(signal?: AbortSignal): Promise<SettingsPayload>;
  /** Merges a partial change; the backend rejects the whole change if any value is invalid. */
  updateSettings(patch: DeepPartial<AppSettings>): Promise<SettingsPayload>;
  /** Restores defaults for one section (or all, with `section` null). Only settings: no captures, reports or database content. */
  resetSettings(section: string | null): Promise<SettingsPayload>;
  exportSettingsFile(destination: string, overwrite?: boolean): Promise<SavedFile>;
  settingsDownloadUrl(): string;
  importSettings(document: unknown): Promise<SettingsPayload>;
  saveApiKey(apiKey: string): Promise<SettingsPayload>;
  deleteApiKey(): Promise<SettingsPayload>;
  testAiConnection(): Promise<{ ok: boolean; message: string; code: string | null; model: string | null; latency_ms: number | null }>;
  getAiUsage(signal?: AbortSignal): Promise<AiUsageToday>;
  getStorageInfo(signal?: AbortSignal): Promise<StorageInfo>;
  /** Previews (default) or performs (`confirm`) the retention cleanup of saved captures. */
  storageCleanup(opts: { dryRun: boolean; confirm?: boolean }): Promise<CleanupPreview>;
  openFolder(folder: "captures" | "reports" | "logs" | "docs"): Promise<void>;
  getDatabaseInfo(signal?: AbortSignal): Promise<DatabaseInfo>;
  backupDatabase(destination: string, overwrite?: boolean): Promise<SavedFile>;
  restoreDatabase(source: string): Promise<{ safety_copy: string; info: DatabaseInfo }>;
  clearAnalysisHistory(opts: { performanceHistory: boolean; reports: boolean; captureSummaries: boolean; deleteCaptureFiles: boolean }): Promise<Record<string, number>>;
  exportDiagnostics(destination: string, overwrite?: boolean): Promise<SavedFile>;
  getAbout(signal?: AbortSignal): Promise<AboutInfo>;
  getHistoryStatus(signal?: AbortSignal): Promise<HistoryStatus>;
  /** Permanently deletes the stored performance history; the backend refuses unless confirm=true, which only the confirmed UI path sends. */
  clearHistory(): Promise<void>;
  /** One domain's overview, performance, traffic, connections and time series. */
  getWebDomain(id: string, domain: string, signal?: AbortSignal): Promise<WebDomainDetail>;
  listInterfaces(signal?: AbortSignal): Promise<InterfaceInfo[]>;
  getLiveStatus(signal?: AbortSignal): Promise<LiveStatus>;
  startLive(req: StartLiveRequest): Promise<LiveStatus>;
  stopLive(): Promise<LiveStatus>;
  createReport(req: CreateReportRequest): Promise<SavedReport>;
  listReports(signal?: AbortSignal): Promise<ReportListItem[]>;
  getReport(id: string, signal?: AbortSignal): Promise<SavedReport>;
  /** Permanently deletes; the backend refuses unless confirm=true, which only the confirmed UI path sends. */
  deleteReport(id: string): Promise<void>;
  /** Writes the export into the backend's reports folder and returns where it was saved. */
  exportReport(id: string, format: ExportFormat): Promise<ExportResult>;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export const api: Api = {
  fetchHealth: (signal) => request<Health>("/api/health", { signal }),

  getSystem: (signal) => request<SystemInfo>("/api/system", { signal }),

  /** Streams the file as the raw request body; the backend validates and analyzes it. */
  submitCapture: (file, signal) =>
    request<JobStatus>("/api/analyses", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(file.name),
      },
      body: file,
      signal,
    }, { long: true }),

  getStatus: (id, signal) => request<JobStatus>(`/api/analyses/${encodeURIComponent(id)}`, { signal }),
  getResult: (id, signal) => request<AnalysisBundle>(`/api/analyses/${encodeURIComponent(id)}/result`, { signal }),

  listWebActivity: (id, q = {}, signal) => {
    const params = new URLSearchParams();
    if (q.search?.trim()) params.set("search", q.search.trim());
    if (q.sort) params.set("sort", q.sort);
    if (q.health) params.set("health", q.health);
    if (q.includeDnsOnly) params.set("include_dns_only", "true");
    if (q.limit != null) params.set("limit", String(q.limit));
    if (q.offset) params.set("offset", String(q.offset));
    const qs = params.toString();
    return request<WebActivityList>(`/api/analyses/${encodeURIComponent(id)}/web-activity${qs ? `?${qs}` : ""}`, { signal });
  },
  getWebDomain: (id, domain, signal) =>
    request<WebDomainDetail>(`/api/analyses/${encodeURIComponent(id)}/web-activity/${encodeURIComponent(domain)}`, { signal }),

  getNetworkMap: (id, q = {}, signal) => {
    const params = new URLSearchParams();
    if (q.local) params.set("local", q.local);
    if (q.search?.trim()) params.set("search", q.search.trim());
    if (q.protocol) params.set("protocol", q.protocol);
    if (q.health) params.set("health", q.health);
    if (q.start != null) params.set("start", String(q.start));
    if (q.end != null) params.set("end", String(q.end));
    if (q.maxNodes != null) params.set("max_nodes", String(q.maxNodes));
    if (q.includeApplications) params.set("include_applications", "true");
    const qs = params.toString();
    return request<NetworkMapData>(`/api/analyses/${encodeURIComponent(id)}/network-map${qs ? `?${qs}` : ""}`, { signal });
  },
  getProcessStatus: (signal) => request<ProcessSourceStatus>("/api/processes", { signal }),
  takeProcessSnapshot: () => request<ProcessSnapshotSummary>("/api/processes/snapshot?confirm=true", { method: "POST" }),
  startProcessWatch: (intervalSeconds = 5) => request<ProcessSourceStatus>("/api/processes/watch", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: true, interval_seconds: intervalSeconds }),
  }),
  stopProcessWatch: () => request<ProcessSourceStatus>("/api/processes/watch", { method: "DELETE" }),
  clearProcessSnapshots: async () => {
    const res = await apiFetch(`${backendUrl()}/api/processes?confirm=true`, { method: "DELETE" }).catch(() => {
      throw new ApiError("backend_unavailable", `Cannot reach the PacketMind backend at ${backendUrl()}.`);
    });
    if (!res.ok) throw await toApiError(res);
  },
  getDomainApplications: (id, domain, signal) =>
    request<DomainApplications>(`/api/analyses/${encodeURIComponent(id)}/web-activity/${encodeURIComponent(domain)}/applications`, { signal }),
  getCorrelations: (id, findingId, signal) =>
    request<CorrelationList>(`/api/analyses/${encodeURIComponent(id)}/correlations?finding_id=${encodeURIComponent(findingId)}`, { signal }),
  getAnomalies: (id, signal) => request<AnomalyList>(`/api/analyses/${encodeURIComponent(id)}/anomalies`, { signal }),
  getDomainBaseline: (id, domain, signal) =>
    request<DomainBaselineView>(`/api/analyses/${encodeURIComponent(id)}/web-activity/${encodeURIComponent(domain)}/baseline`, { signal }),
  investigateNetwork: (id, opts = {}, signal) =>
    request<NetworkInvestigation>(`/api/analyses/${encodeURIComponent(id)}/investigate-network`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ use_ai: opts.useAi ?? true }), signal,
    }),
  getDashboard: (id, range = "all", signal) => request<DashboardData>(`/api/analyses/${encodeURIComponent(id)}/dashboard?range=${range}`, { signal }),
  getLiveDashboard: (range = "all", signal) => request<DashboardData>(`/api/live/dashboard?range=${range}`, { signal }),
  listCaptures: (signal) => request<CaptureSession[]>("/api/captures", { signal }),
  getCapture: (id, signal) => request<CaptureSession>(`/api/captures/${encodeURIComponent(id)}`, { signal }),
  analyzeCapture: (id, opts = {}, signal) =>
    request<JobStatus>(`/api/captures/${encodeURIComponent(id)}/analyze${opts.force ? "?force=true" : ""}`, { method: "POST", signal }),
  exportCapture: (id, destination, overwrite = false) =>
    request<CaptureExportResult>(`/api/captures/${encodeURIComponent(id)}/export`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ destination, overwrite }),
    }, { long: true }),
  captureDownloadUrl: (id) => `${backendUrl()}/api/captures/${encodeURIComponent(id)}/download`,
  deleteCapture: async (id) => {
    const res = await apiFetch(`${backendUrl()}/api/captures/${encodeURIComponent(id)}?confirm=true`, { method: "DELETE" }).catch(() => {
      throw new ApiError("backend_unavailable", `Cannot reach the PacketMind backend at ${backendUrl()}.`);
    });
    if (!res.ok) throw await toApiError(res);
  },
  getSettings: (signal) => request<SettingsPayload>("/api/settings", { signal }),
  updateSettings: (patch) => request<SettingsPayload>("/api/settings", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(patch) }),
  resetSettings: (section) => request<SettingsPayload>("/api/settings/reset", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ section, confirm: true }) }),
  exportSettingsFile: (destination, overwrite = false) =>
    request<SavedFile>("/api/settings/export-file", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ destination, overwrite }) }),
  settingsDownloadUrl: () => `${backendUrl()}/api/settings/export`,
  importSettings: (document) => request<SettingsPayload>("/api/settings/import", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ document }) }),
  saveApiKey: (apiKey) => request<SettingsPayload>("/api/settings/ai/key", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify({ api_key: apiKey }) }),
  deleteApiKey: () => request<SettingsPayload>("/api/settings/ai/key?confirm=true", { method: "DELETE" }),
  testAiConnection: () => request("/api/settings/ai/test", { method: "POST" }, { long: true }),
  getAiUsage: (signal) => request<AiUsageToday>("/api/settings/ai/usage", { signal }),
  getStorageInfo: (signal) => request<StorageInfo>("/api/settings/storage", { signal }),
  storageCleanup: ({ dryRun, confirm = false }) =>
    request<CleanupPreview>("/api/settings/storage/cleanup", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ dry_run: dryRun, confirm }) }, { long: true }),
  openFolder: async (folder) => { await request("/api/settings/open-folder", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ folder }) }); },
  getDatabaseInfo: (signal) => request<DatabaseInfo>("/api/settings/database", { signal }),
  backupDatabase: (destination, overwrite = false) =>
    request<SavedFile>("/api/settings/database/backup", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ destination, overwrite }) }, { long: true }),
  restoreDatabase: (source) =>
    request("/api/settings/database/restore", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ source, confirm: true }) }, { long: true }),
  clearAnalysisHistory: (o) => request<Record<string, number>>("/api/settings/database/clear", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({
    performance_history: o.performanceHistory, reports: o.reports, capture_summaries: o.captureSummaries, delete_capture_files: o.deleteCaptureFiles, confirm: true }) }, { long: true }),
  exportDiagnostics: (destination, overwrite = false) =>
    request<SavedFile>("/api/settings/diagnostics/export", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ destination, overwrite }) }, { long: true }),
  getAbout: (signal) => request<AboutInfo>("/api/settings/about", { signal }),
  getHistoryStatus: (signal) => request<HistoryStatus>("/api/baselines", { signal }),
  clearHistory: async () => {
    const res = await apiFetch(`${backendUrl()}/api/baselines?confirm=true`, { method: "DELETE" }).catch(() => {
      throw new ApiError("backend_unavailable", `Cannot reach the PacketMind backend at ${backendUrl()}.`);
    });
    if (!res.ok) throw await toApiError(res);
  },

  listInterfaces: (signal) => request<InterfaceInfo[]>("/api/live/interfaces", { signal }),
  getLiveStatus: (signal) => request<LiveStatus>("/api/live/status", { signal }),
  /** `confirm: true` is sent only from the Start button handler: capture is never implicit. */
  startLive: (req) => request<LiveStatus>("/api/live/start", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...req, confirm: true }),
  }),
  stopLive: () => request<LiveStatus>("/api/live/stop", { method: "POST" }),

  createReport: (req) => request<SavedReport>("/api/reports", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req),
  }),
  listReports: (signal) => request<ReportListItem[]>("/api/reports", { signal }),
  getReport: (id, signal) => request<SavedReport>(`/api/reports/${encodeURIComponent(id)}`, { signal }),
  deleteReport: async (id) => {
    const res = await apiFetch(`${backendUrl()}/api/reports/${encodeURIComponent(id)}?confirm=true`, { method: "DELETE" }).catch(() => {
      throw new ApiError("backend_unavailable", `Cannot reach the PacketMind backend at ${backendUrl()}.`);
    });
    if (!res.ok) throw await toApiError(res);
  },
  exportReport: (id, format) => request<ExportResult>(`/api/reports/${encodeURIComponent(id)}/export?format=${format}`, { method: "POST" }),
};
