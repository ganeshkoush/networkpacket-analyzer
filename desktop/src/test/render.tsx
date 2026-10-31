import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AppRoutes } from "../App";
import { ApiError, type Api } from "../api/client";
import type { AnalysisBundle, JobStatus } from "../api/types";
import { ApiProvider } from "../state/ApiContext";
import { AnalysisProvider } from "../state/AnalysisContext";
import { BackendProvider } from "../state/BackendContext";
import { makeBundle, makeDashboard, makeJob, makeSettingsPayload } from "./fixtures";

export type MockApi = { [K in keyof Api]: ReturnType<typeof vi.fn> } & Api;

/** An API double whose upload succeeds and completes immediately (override per test). */
export function mockApi(over: Partial<Api> = {}, bundle: AnalysisBundle = makeBundle()): MockApi {
  return {
    fetchHealth: vi.fn().mockResolvedValue({ status: "ok", app: "PacketMind", version: "0.1.0", max_upload_bytes: 1024 ** 3 }),
    getSystem: vi.fn().mockResolvedValue({
      app: "PacketMind", version: "0.1.0",
      ai: { configured: false, provider: "Google Gemini", model: "gemini-2.5-flash" },
      live: { platform: "darwin", capture_library: true, privileges: "unlikely", note: "Capture needs read access to /dev/bpf*." },
      max_upload_bytes: 1024 ** 3, max_retained_analyses: 10, log_level: "INFO",
      data_dir: "/data", captures_dir: "/captures", reports_dir: "/reports" }),
    submitCapture: vi.fn().mockResolvedValue(makeJob({ status: "queued", progress_percent: 0 })),
    getStatus: vi.fn().mockResolvedValue(makeJob()),
    getResult: vi.fn().mockResolvedValue(bundle),
    listWebActivity: vi.fn(),
    getWebDomain: vi.fn(),
    getNetworkMap: vi.fn(),
    getProcessStatus: vi.fn().mockResolvedValue({ platform: "macOS", supported: true, mechanism: "lsof + ps (read-only)", permission_note: "No administrator rights needed.", snapshots: 0,
      first_snapshot_at: null, last_snapshot_at: null, watching: false, watch_interval_seconds: null, last_error: null, notes: [] }),
    takeProcessSnapshot: vi.fn(),
    startProcessWatch: vi.fn(),
    stopProcessWatch: vi.fn(),
    clearProcessSnapshots: vi.fn().mockResolvedValue(undefined),
    getDomainApplications: vi.fn().mockResolvedValue({ domain: "", status: "no_snapshots", message: "Process information unavailable: no local process snapshot has been taken.", applications: [],
      connections_considered: 0, connections_matched: 0, connections_unmatched: 0, snapshots_used: 0, permission_note: "", source_note: "" }),
    getCorrelations: vi.fn().mockResolvedValue({ finding_id: null, correlations: [], not_evaluated: [], no_related_change: [], flow_data_thinned: false, notes: [] }),
    getAnomalies: vi.fn().mockResolvedValue({ history_enabled: true, domains_evaluated: 0, domains_with_baseline: 0, anomalies: [], notes: [] }),
    getDomainBaseline: vi.fn().mockResolvedValue({ domain: "", history_enabled: true, prior_observations: 0, comparisons: [], anomalies: [], history: [], notes: [] }),
    investigateNetwork: vi.fn(),
    getSettings: vi.fn().mockResolvedValue(makeSettingsPayload()),
    updateSettings: vi.fn(), resetSettings: vi.fn(), exportSettingsFile: vi.fn(), settingsDownloadUrl: vi.fn().mockReturnValue("http://backend/api/settings/export"),
    importSettings: vi.fn(), saveApiKey: vi.fn(), deleteApiKey: vi.fn(), testAiConnection: vi.fn(),
    getAiUsage: vi.fn().mockResolvedValue({ day: "2026-10-07", requests: 7, cached: 4, automatic: 1, blocked: 0, daily_limit: 20, max_automatic_per_day: 20, cache_enabled: true, note: "" }),
    getStorageInfo: vi.fn().mockResolvedValue({ usage: { captures: 3_435_973_836, reports: 130_023_424, database: 85_983_232, logs: 26_214_400, total: 3_678_194_892, temporary_uploads: 0 },
      locations: { captures: "/data/captures", reports: "/data/reports", logs: "/data/logs", database: "/data/packetmind.db" }, limits: { max_capture_storage_gb: 50 }, note: "" }),
    storageCleanup: vi.fn(), openFolder: vi.fn().mockResolvedValue(undefined),
    getDatabaseInfo: vi.fn().mockResolvedValue({ type: "SQLite", path: "/data/packetmind.db", size_bytes: 85_983_232, schema_version: 4, captures: 12, reports: 3, findings_in_reports: 9, history_domains_observations: 40, retention_days: 0, notes: [] }),
    backupDatabase: vi.fn(), restoreDatabase: vi.fn(), clearAnalysisHistory: vi.fn(), exportDiagnostics: vi.fn(),
    getAbout: vi.fn().mockResolvedValue({ app: "PacketMind", tagline: "AI-Powered Network Security Analyst", backend_version: "0.1.0", python: "3.14.0", analysis_engine: "Scapy 2.8.0", database_engine: "SQLite 3.45",
      ai_provider: "Google Gemini", os: "Darwin 25.6.0", architecture: "arm64", capture: { library_available: true, privileges: "likely", note: "Capture needs read access to /dev/bpf*." }, tshark: false,
      ai: { configured: false, source: "none", secure_storage_available: true, secure_storage: "Keyring", model: "gemini-2.5-flash", last_test: null } }),
    listCaptures: vi.fn().mockResolvedValue([]),
    getCapture: vi.fn(),
    analyzeCapture: vi.fn().mockResolvedValue(makeJob({ status: "queued", progress_percent: 0 })),
    exportCapture: vi.fn(),
    captureDownloadUrl: vi.fn().mockImplementation((id: string) => `http://backend/api/captures/${id}/download`),
    deleteCapture: vi.fn().mockResolvedValue(undefined),
    getDashboard: vi.fn().mockResolvedValue(makeDashboard()),
    getLiveDashboard: vi.fn().mockResolvedValue(makeDashboard({ source: "live" })),
    getHistoryStatus: vi.fn().mockResolvedValue({ enabled: true, sources: 0, observations: 0, domains: 0, oldest: null, newest: null, notes: [] }),
    clearHistory: vi.fn().mockResolvedValue(undefined),
    listInterfaces: vi.fn().mockResolvedValue([]),
    getLiveStatus: vi.fn().mockResolvedValue({ state: "stopped", interface: null, started_at: null, elapsed_seconds: 0, packets_total: 0, bytes_total: 0, packets_per_second: 0, bits_per_second: 0, window_seconds: 0, window_packets: 0, window_truncated: false, last_analysis_at: null, protocols: [], top_talkers: [], top_ports: [], findings: [], auto_investigate: false, parse_errors: 0, error: null }),
    startLive: vi.fn(),
    stopLive: vi.fn(),
    createReport: vi.fn(),
    listReports: vi.fn().mockResolvedValue([]),
    getReport: vi.fn(),
    deleteReport: vi.fn().mockResolvedValue(undefined),
    exportReport: vi.fn(),
    ...over,
  } as MockApi;
}

export function renderApp(api: MockApi, route = "/") {
  return render(
    <ApiProvider api={api}>
      <BackendProvider api={api} onlineIntervalMs={60_000} offlineIntervalMs={60_000}>
        <AnalysisProvider api={api} pollIntervalMs={5}>
          <MemoryRouter initialEntries={[route]}><AppRoutes /></MemoryRouter>
        </AnalysisProvider>
      </BackendProvider>
    </ApiProvider>,
  );
}

export const pcapFile = (name = "demo.pcap", size = 1000) => new File([new Uint8Array(Math.min(size, 64))], name, { type: "application/octet-stream" });
export const apiError = (kind: ApiError["kind"], message: string) => new ApiError(kind, message);
export type { JobStatus };
