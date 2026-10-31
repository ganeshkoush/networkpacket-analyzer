import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DomainApplications, ProcessSourceStatus } from "../api/types";
import { makeWebDetail, makeWebList } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

const STATUS: ProcessSourceStatus = {
  platform: "macOS", supported: true, mechanism: "lsof + ps (read-only)", snapshots: 0, first_snapshot_at: null, last_snapshot_at: null, watching: false,
  watch_interval_seconds: null, last_error: null, notes: [],
  permission_note: "macOS: uses the built-in read-only tools lsof and ps. No administrator rights are requested; only your own user account's processes are visible.",
};
const APPS: DomainApplications = {
  domain: "github.com", status: "available", message: "All 18 connection(s) matched an OS-reported process.", connections_considered: 18, connections_matched: 18, connections_unmatched: 0,
  snapshots_used: 3, permission_note: STATUS.permission_note,
  source_note: "Application names come from the operating system's process list on this computer at the moment each snapshot was taken, not from the captured packets.",
  applications: [
    { name: "Visual Studio Code", kind: "application", process_names: ["Code Helper", "Code Helper (Plugin)"], pids: [1000, 1001], connections: 12, confidence_counts: { HIGH: 12 } },
    { name: "Google Chrome", kind: "application", process_names: ["Google Chrome Helper"], pids: [2000], connections: 6, confidence_counts: { HIGH: 4, MEDIUM: 2 } },
  ],
};

async function openWeb(over: Partial<MockApi> = {}) {
  const api = mockApi({
    listWebActivity: vi.fn().mockResolvedValue(makeWebList()),
    getWebDomain: vi.fn().mockResolvedValue(makeWebDetail()),
    getProcessStatus: vi.fn().mockResolvedValue(STATUS),
    getDomainApplications: vi.fn().mockResolvedValue(APPS),
    ...over,
  });
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Web Activity/ }));
  return { user, api };
}
const openDomain = async (over: Partial<MockApi> = {}) => {
  const ctx = await openWeb(over);
  await ctx.user.click(await screen.findByRole("row", { name: /github\.com/ }));
  await screen.findByRole("heading", { name: "github.com" });
  return ctx;
};

describe("Applications in the domain details", () => {
  it("lists applications with their connection counts", async () => {
    const { api } = await openDomain();
    expect(api.getDomainApplications).toHaveBeenCalledWith("job1", "github.com", expect.anything());
    const list = await screen.findByRole("list", { name: "Applications" });
    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Visual Studio Code — 12 connections");
    expect(items[1]).toHaveTextContent("Google Chrome — 6 connections");
    expect(items[0]).toHaveTextContent("Code Helper, Code Helper (Plugin)");
    expect(items[1]).toHaveTextContent("match confidence high ×4, medium ×2");
  });

  it("states that this is operating-system information, not packet information", async () => {
    await openDomain();
    await screen.findByRole("list", { name: "Applications" });
    expect(screen.getAllByText(/not from the captured packets/).length).toBeGreaterThanOrEqual(2);   // card subtitle and footer
    expect(screen.getByText(/at the moment snapshots were taken, not from the captured packets/)).toBeInTheDocument();
    expect(screen.getByText(/only your own user account's processes are visible/)).toBeInTheDocument();
  });

  it("says which connections have no process information when only some matched", async () => {
    await openDomain({ getDomainApplications: vi.fn().mockResolvedValue({ ...APPS, status: "partial", connections_matched: 12, connections_unmatched: 6,
      message: "6 of 18 connection(s) could not be matched: process information unavailable for them.", applications: [APPS.applications[0]] }) });
    expect(await screen.findByText("6 of 18 connection(s) could not be matched: process information unavailable for them.")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Applications" })).toHaveTextContent("Visual Studio Code — 12 connections");
  });

  it("marks non-app executables as processes and uses singular for one connection", async () => {
    await openDomain({ getDomainApplications: vi.fn().mockResolvedValue({ ...APPS, applications: [{ name: "curl", kind: "process", process_names: ["curl"], pids: [7], connections: 1, confidence_counts: { LOW: 1 } }] }) });
    const item = within(await screen.findByRole("list", { name: "Applications" })).getByRole("listitem");
    expect(item).toHaveTextContent("curl — 1 connection");
    expect(item).toHaveTextContent("(process, not an app bundle)");
    expect(item).toHaveTextContent("match confidence low ×1");
  });

  it.each([
    ["no_snapshots", "Process information unavailable: no local process snapshot has been taken."],
    ["no_overlap", "Process information unavailable: none of the 2 snapshot(s) were taken while this capture was recorded."],
    ["no_matches", "Process information unavailable: no open local socket matched these connections."],
    ["unsupported", "Process information unavailable: process mapping is not supported on Windows yet."],
  ] as const)("shows 'Process information unavailable' for %s and never an application name", async (status, message) => {
    await openDomain({ getDomainApplications: vi.fn().mockResolvedValue({ ...APPS, status, message, applications: [], connections_matched: 0, connections_unmatched: 18 }) });
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Applications" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Visual Studio Code|Google Chrome/)).not.toBeInTheDocument();
  });

  it("explains the permission model when information is unavailable", async () => {
    await openDomain({ getDomainApplications: vi.fn().mockResolvedValue({ ...APPS, status: "no_snapshots", message: "Process information unavailable: no snapshot.", applications: [] }) });
    expect(await screen.findByText(/No administrator rights are requested/, { selector: "p.text-xs" })).toBeInTheDocument();
  });

  it("shows a loading state, then an error with Retry", async () => {
    const getDomainApplications = vi.fn().mockRejectedValueOnce(apiError("server_error", "lookup failed")).mockResolvedValue(APPS);
    const { user } = await openDomain({ getDomainApplications });
    expect(await screen.findByText("Application lookup unavailable")).toBeInTheDocument();
    expect(screen.getByText("lookup failed")).toBeInTheDocument();
    await user.click(within(screen.getByText("Application lookup unavailable").closest("[role=alert]") as HTMLElement).getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("list", { name: "Applications" })).toBeInTheDocument();
  });

  it("a failing application lookup does not break the rest of the domain page", async () => {
    await openDomain({ getDomainApplications: vi.fn().mockRejectedValue(apiError("server_error", "boom")) });
    expect(await screen.findByText("Application lookup unavailable")).toBeInTheDocument();
    expect(screen.getByLabelText("Performance")).toBeInTheDocument();
  });
});

describe("Process snapshot controls", () => {
  it("reads nothing until a button is pressed, and explains what it does and needs", async () => {
    const { api } = await openWeb();
    expect(await screen.findByText(/A packet capture cannot tell which application sent a packet/)).toBeInTheDocument();
    expect(screen.getByText(/only your own user account's processes are visible/)).toBeInTheDocument();
    expect(api.takeProcessSnapshot).not.toHaveBeenCalled();
    expect(api.startProcessWatch).not.toHaveBeenCalled();
  });

  it("takes a snapshot on request and reports what it found", async () => {
    const takeProcessSnapshot = vi.fn().mockResolvedValue({ timestamp: 1, platform: "macOS", sockets: 43, processes: 11, applications: 7, truncated: false, notes: [] });
    const getProcessStatus = vi.fn().mockResolvedValueOnce(STATUS).mockResolvedValue({ ...STATUS, snapshots: 1, last_snapshot_at: 1_700_000_000 });
    const { user } = await openWeb({ takeProcessSnapshot, getProcessStatus });
    await user.click(await screen.findByRole("button", { name: "Take a snapshot now" }));
    expect(await screen.findByText("Snapshot taken: 43 sockets from 11 processes (7 applications).")).toBeInTheDocument();
    expect(takeProcessSnapshot).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/1 snapshot in memory, latest 2023-11-14/)).toBeInTheDocument();
  });

  it("reports an OS failure without pretending anything was learned", async () => {
    const { user } = await openWeb({ takeProcessSnapshot: vi.fn().mockRejectedValue(apiError("server_error", "lsof did not answer within 15 seconds.")) });
    await user.click(await screen.findByRole("button", { name: "Take a snapshot now" }));
    expect(await screen.findByText("lsof did not answer within 15 seconds.")).toBeInTheDocument();
    expect(screen.getByText("No snapshots yet.")).toBeInTheDocument();
  });

  it("starts and stops a watch", async () => {
    const watching = { ...STATUS, watching: true, watch_interval_seconds: 5, snapshots: 2, last_snapshot_at: 1_700_000_000 };
    const getProcessStatus = vi.fn().mockResolvedValueOnce(STATUS).mockResolvedValueOnce(watching).mockResolvedValue(STATUS);
    const { user, api } = await openWeb({ getProcessStatus, startProcessWatch: vi.fn().mockResolvedValue(watching), stopProcessWatch: vi.fn().mockResolvedValue(STATUS) });
    await user.click(await screen.findByRole("button", { name: "Watch while capturing" }));
    expect(api.startProcessWatch).toHaveBeenCalledWith(5);
    expect(await screen.findByText(/a snapshot every 5 seconds \(stops by itself after an hour\)/)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Stop watching" }));
    expect(api.stopProcessWatch).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: "Watch while capturing" })).toBeInTheDocument();
  });

  it("clears snapshots only after confirmation", async () => {
    const withSnaps = { ...STATUS, snapshots: 3, last_snapshot_at: 1_700_000_000 };
    const getProcessStatus = vi.fn().mockResolvedValueOnce(withSnaps).mockResolvedValue(STATUS);
    const { user, api } = await openWeb({ getProcessStatus });
    await user.click(await screen.findByRole("button", { name: "Clear snapshots…" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("removes the 3 process snapshot(s) held in memory");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.clearProcessSnapshots).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Clear snapshots…" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Clear snapshots" }));
    await waitFor(() => expect(api.clearProcessSnapshots).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Snapshots cleared.")).toBeInTheDocument();
  });

  it("on an unsupported platform offers no actions and says information is unavailable", async () => {
    await openWeb({ getProcessStatus: vi.fn().mockResolvedValue({ ...STATUS, platform: "Windows", supported: false, permission_note: "Process mapping is not implemented for Windows yet; no process information is available." }) });
    expect(await screen.findByText(/Process information unavailable on Windows: this platform is not supported yet\./)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Take a snapshot now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Watch while capturing" })).not.toBeInTheDocument();
  });

  it("shows when the last background snapshot failed", async () => {
    await openWeb({ getProcessStatus: vi.fn().mockResolvedValue({ ...STATUS, last_error: "lsof failed: permission denied" }) });
    expect(await screen.findByText("The last snapshot failed: lsof failed: permission denied")).toBeInTheDocument();
  });
});
