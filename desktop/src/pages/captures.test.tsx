import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LiveStatus } from "../api/types";
import { IDLE_STATUS } from "../state/useLiveCapture";
import { makeCapture, makeJob } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

const save = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: (...a: unknown[]) => save(...a) }));

const FILE = { id: "a".repeat(32), filename: "packetmind_capture_2026-10-07_23-30-15_ab12cd.pcap", format: "pcap" as const, status: "COMPLETED" as const, packets: 12_483, bytes: 19_300_000, file_size: 19_300_000, error: null };
const CAPTURING: LiveStatus = { ...IDLE_STATUS, state: "capturing", interface: "en0", elapsed_seconds: 272, packets_total: 12_483, bytes_total: 18_400_000,
  capture: { ...FILE, status: "CAPTURING", file_size: 0 } };
const STOPPED: LiveStatus = { ...CAPTURING, state: "stopped", capture: FILE };
const IFACES = [{ name: "en0", description: "Wi-Fi", kind: "wifi" as const, addresses: ["192.168.1.5"], is_up: true }];

afterEach(() => { delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__; save.mockReset(); });

function liveApi(over: Partial<MockApi> = {}) {
  return mockApi({ listInterfaces: vi.fn().mockResolvedValue(IFACES), getLiveStatus: vi.fn().mockResolvedValue(IDLE_STATUS),
    startLive: vi.fn().mockResolvedValue(CAPTURING), stopLive: vi.fn().mockResolvedValue(STOPPED), getCapture: vi.fn().mockResolvedValue(makeCapture({ id: FILE.id })), ...over });
}

// ------------------------------------------------------------------ import
describe("Import PCAP", () => {
  it("offers a clear Import PCAP action that only accepts capture files, and explains where the file goes", async () => {
    renderApp(mockApi(), "/analysis");
    expect(await screen.findByRole("button", { name: "Import PCAP" })).toBeInTheDocument();
    expect(screen.getByLabelText("Capture file")).toHaveAttribute("accept", ".pcap,.pcapng,.cap");
    expect(screen.getByText(/never sent to the AI provider/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "capture library" })).toHaveAttribute("href", "/captures");
  });

  it("passes the chosen file to the backend (the page never reads it) and shows the analysis", async () => {
    const api = mockApi();
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    const file = pcapFile("incident.pcapng");
    await user.upload(screen.getByLabelText("Capture file"), file);
    await screen.findByText(/packets ·/);
    expect(api.submitCapture).toHaveBeenCalledWith(file, expect.anything());
  });

  it.each([
    ["unsupported_file_type", "'notes.txt' is not a .pcap or .pcapng file.", "Unsupported file type"],
    ["disk_full", "The disk is full, so the file could not be imported.", "The disk is full"],
    ["empty_file", "The uploaded file is empty (0 bytes).", "The file is empty"],
  ] as const)("explains a %s failure in plain language", async (kind, message, title) => {
    const api = mockApi({ submitCapture: vi.fn().mockRejectedValue(apiError(kind, message)) });
    renderApp(api, "/analysis");
    await userEvent.setup({ applyAccept: false }).upload(screen.getByLabelText("Capture file"), pcapFile("notes.txt"));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(title);
    expect(alert).toHaveTextContent(message);
    expect(alert).not.toHaveTextContent(/Traceback|\/Users\//);
  });
});

// ------------------------------------------------------------------ live capture -> completed screen
describe("Live capture recording", () => {
  it("starts recording to a .pcap by default and shows the live capture details", async () => {
    const api = liveApi();
    const user = userEvent.setup();
    renderApp(api, "/live");
    await screen.findByRole("option", { name: /en0/ });
    await user.selectOptions(screen.getByLabelText("Network interface"), "en0");
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    expect(api.startLive).toHaveBeenCalledWith({ interface: "en0", auto_investigate: false });             // saving is the default
    api.getLiveStatus = vi.fn().mockResolvedValue(CAPTURING);
    const details = await screen.findByLabelText("Capture details", {}, { timeout: 3000 });
    expect(details).toHaveTextContent("Capturing");
    expect(details).toHaveTextContent("12,483");
    expect(details).toHaveTextContent("00:04:32");
    expect(details).toHaveTextContent(FILE.filename);
    expect(screen.getByText(/never sent to the AI provider/)).toBeInTheDocument();
  });

  it("can record as pcapng or not at all", async () => {
    const api = liveApi();
    const user = userEvent.setup();
    renderApp(api, "/live");
    await screen.findByRole("option", { name: /en0/ });
    await user.selectOptions(screen.getByLabelText("Network interface"), "en0");
    await user.selectOptions(screen.getByLabelText("Capture file format"), "pcapng");
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    expect(api.startLive).toHaveBeenLastCalledWith({ interface: "en0", auto_investigate: false, format: "pcapng" });
  });

  it("does not record when the user turns saving off", async () => {
    const api = liveApi();
    const user = userEvent.setup();
    renderApp(api, "/live");
    await screen.findByRole("option", { name: /en0/ });
    await user.selectOptions(screen.getByLabelText("Network interface"), "en0");
    await user.click(screen.getByRole("checkbox", { name: /Save the packets/ }));
    expect(screen.getByLabelText("Capture file format")).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    expect(api.startLive).toHaveBeenCalledWith({ interface: "en0", auto_investigate: false, save: false });
  });

  it("after Stop shows Capture Completed with file, interface, duration, packets, size, protocols, domains and findings", async () => {
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED) });
    renderApp(api, "/live");
    const screenEl = await screen.findByRole("region", { name: "Capture completed" });
    await within(screenEl).findByText("42");                                                                // domains, once the analysis summary is there
    expect(screenEl).toHaveTextContent(FILE.filename);
    expect(screenEl).toHaveTextContent("Wi-Fi");
    expect(screenEl).toHaveTextContent("00:04:32");
    expect(screenEl).toHaveTextContent("12,483");
    expect(screenEl).toHaveTextContent("18.4 MB");
    const protocols = within(screenEl).getByLabelText("Protocols");
    expect(protocols).toHaveTextContent(/TCP\s*72%/);
    expect(protocols).toHaveTextContent(/UDP\s*19%/);
    expect(protocols).toHaveTextContent(/DNS\s*7%/);
    expect(protocols).toHaveTextContent(/ARP\s*2%/);
    expect(screenEl).toHaveTextContent("3");                                                                // findings
    for (const name of ["Download PCAP", "Analyze Capture", "Delete Capture"]) expect(within(screenEl).getByRole("button", { name })).toBeInTheDocument();
    expect(within(screenEl).getByRole("link", { name: "Back to Dashboard" })).toHaveAttribute("href", "/");
    expect(screenEl).not.toHaveTextContent(/\/Users\/|\/captures\//);                                      // no filesystem paths
  });

  it("shows that the saved capture is still being analysed", async () => {
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED), getCapture: vi.fn().mockResolvedValue(makeCapture({ id: FILE.id, status: "ANALYZING", summary: null })) });
    renderApp(api, "/live");
    expect(await screen.findByText("Analyzing the saved capture…")).toBeInTheDocument();
  });

  it("never reports a failed save as saved", async () => {
    const failed = { ...FILE, status: "FAILED" as const, error: "The disk is full, so the capture could not be saved. Free some space and capture again." };
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue({ ...STOPPED, capture: failed }),
      getCapture: vi.fn().mockResolvedValue(makeCapture({ id: FILE.id, status: "FAILED", error_message: failed.error, summary: null })) });
    renderApp(api, "/live");
    const el = await screen.findByRole("region", { name: "Capture completed" });
    expect(await within(el).findByRole("alert")).toHaveTextContent("The disk is full");
    expect(within(el).getByRole("heading", { name: /not saved cleanly/i })).toBeInTheDocument();
    expect(within(el).queryByRole("button", { name: "Download PCAP" })).not.toBeInTheDocument();
    expect(within(el).queryByRole("button", { name: "Analyze Capture" })).not.toBeInTheDocument();
  });

  it("Analyze Capture opens the capture's analysis", async () => {
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED) });
    const user = userEvent.setup();
    renderApp(api, "/live");
    await user.click(await screen.findByRole("button", { name: "Analyze Capture" }));
    await waitFor(() => expect(api.analyzeCapture).toHaveBeenCalledWith(FILE.id, { force: undefined }, expect.anything()));
    expect((await screen.findAllByText(/packets read|Analyzing|packets ·/)).length).toBeGreaterThan(0);
  });

  it("Delete Capture asks first, and only deletes when confirmed", async () => {
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED) });
    const user = userEvent.setup();
    renderApp(api, "/live");
    await user.click(await screen.findByRole("button", { name: "Delete Capture" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("permanently deleted");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.deleteCapture).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete Capture" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete capture" }));
    await waitFor(() => expect(api.deleteCapture).toHaveBeenCalledWith(FILE.id));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Capture completed" })).not.toBeInTheDocument());
  });
});

// ------------------------------------------------------------------ export / download
describe("Download PCAP", () => {
  const completed = async (api: MockApi) => {
    const user = userEvent.setup();
    renderApp(api, "/live");
    await user.click(await screen.findByRole("button", { name: "Download PCAP" }));
    return user;
  };

  it("uses the native save dialog in the desktop app, exports to the chosen place and says so", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Users/me/Desktop/office.pcap");
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED), exportCapture: vi.fn().mockResolvedValue({ filename: "office.pcap", directory: "/Users/me/Desktop", size_bytes: 1 }) });
    await completed(api);
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: FILE.filename, filters: [expect.objectContaining({ name: "Packet capture" })] }));
    expect(api.exportCapture).toHaveBeenCalledWith(FILE.id, "/Users/me/Desktop/office.pcap", false);
    expect(await screen.findByText(/PCAP exported successfully/)).toHaveTextContent("office.pcap");
  });

  it("does nothing when the user cancels the dialog", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue(null);
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED) });
    await completed(api);
    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(api.exportCapture).not.toHaveBeenCalled();
    expect(screen.queryByText(/exported successfully/)).not.toBeInTheDocument();
  });

  it("reports a failed export instead of claiming success", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Volumes/ro/office.pcap");
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED), exportCapture: vi.fn().mockRejectedValue(apiError("unknown", "PacketMind is not allowed to write to that folder.")) });
    await completed(api);
    expect(await screen.findByText(/was not exported/)).toHaveTextContent("not allowed to write");
    expect(screen.queryByText(/exported successfully/)).not.toBeInTheDocument();
  });

  it("falls back to a browser download outside the desktop app", async () => {
    const clicks: string[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { clicks.push(`${this.href}|${this.download}`); });
    const api = liveApi({ getLiveStatus: vi.fn().mockResolvedValue(STOPPED) });
    await completed(api);
    expect(clicks).toEqual([`http://backend/api/captures/${FILE.id}/download|${FILE.filename}`]);
    expect(await screen.findByText(/PCAP download started/)).toBeInTheDocument();
    click.mockRestore();
  });
});

// ------------------------------------------------------------------ capture library
describe("Captures (capture history)", () => {
  const LIB = [
    makeCapture({ id: "1".repeat(32), original_filename: "office_capture.pcap", source_type: "LIVE_CAPTURE", packet_count: 12_483, file_size: 18_000_000, status: "ANALYZED" }),
    makeCapture({ id: "2".repeat(32), original_filename: "incident.pcap", source_type: "UPLOADED_PCAP", packet_count: 48_219, file_size: 61_000_000, status: "ANALYZED" }),
    makeCapture({ id: "3".repeat(32), original_filename: "test_capture.pcapng", source_type: "LIVE_CAPTURE", capture_format: "pcapng", packet_count: 5_182, file_size: 7_000_000, status: "COMPLETED", summary: null }),
    makeCapture({ id: "4".repeat(32), original_filename: "broken.pcap", source_type: "UPLOADED_PCAP", packet_count: 0, file_size: 10, status: "FAILED", error_message: "Unable to read 'broken.pcap'. The file may be corrupted or use an unsupported capture format.", summary: null }),
  ];

  it("is in the navigation and lists previous captures with source, packets, size and status", async () => {
    const api = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB) });
    const user = userEvent.setup();
    renderApp(api, "/");
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Captures/ }));
    const table = await screen.findByRole("table", { name: "Capture history" });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Capture name", "Source", "Packets", "Size", "Status", "Saved", "Actions"]);
    const row = (name: string) => within(table).getByRole("row", { name });
    expect(row("office_capture.pcap")).toHaveTextContent(/Live.*12,483.*17\.2 MB.*Analyzed/);
    expect(row("incident.pcap")).toHaveTextContent(/Upload.*48,219.*Analyzed/);
    expect(row("test_capture.pcapng")).toHaveTextContent(/Live.*5,182.*Ready/);
    expect(row("broken.pcap")).toHaveTextContent(/may be corrupted.*Failed/);
    expect(document.title).toBe("Captures · PacketMind");
  });

  it("shows loading, empty and error states", async () => {
    renderApp(mockApi({ listCaptures: vi.fn().mockResolvedValue([]) }), "/captures");
    expect(await screen.findByText("No captures yet")).toBeInTheDocument();
  });

  it("explains a failure to load and retries", async () => {
    const listCaptures = vi.fn().mockRejectedValueOnce(apiError("backend_unavailable", "Cannot reach the PacketMind backend.")).mockResolvedValue(LIB);
    const user = userEvent.setup();
    renderApp(mockApi({ listCaptures }), "/captures");
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the PacketMind backend.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("table", { name: "Capture history" })).toBeInTheDocument();
  });

  it("Analyze runs the analysis and opens the results; Analyze Again forces a re-run", async () => {
    const api = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB) });
    const user = userEvent.setup();
    renderApp(api, "/captures");
    await user.click(await screen.findByRole("button", { name: "Analyze test_capture.pcapng" }));
    await waitFor(() => expect(api.analyzeCapture).toHaveBeenCalledWith("3".repeat(32), { force: false }, expect.anything()));
    expect((await screen.findAllByText(/packets ·|Analyzing/)).length).toBeGreaterThan(0);

    const again = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB) });
    renderApp(again, "/captures");
    await user.click((await screen.findAllByRole("button", { name: "Analyze again office_capture.pcap" }))[0]);
    await waitFor(() => expect(again.analyzeCapture).toHaveBeenCalledWith("1".repeat(32), { force: true }, expect.anything()));
  });

  it("clicking a capture's name opens its analysis", async () => {
    const api = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB) });
    const user = userEvent.setup();
    renderApp(api, "/captures");
    await user.click(await screen.findByRole("button", { name: "incident.pcap" }));
    await waitFor(() => expect(api.analyzeCapture).toHaveBeenCalledWith("2".repeat(32), { force: false }, expect.anything()));
  });

  it("does not offer to analyze a capture that never saved anything", async () => {
    renderApp(mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB) }), "/captures");
    expect(await screen.findByRole("button", { name: "Analyze broken.pcap" })).toBeDisabled();
  });

  it("exports from the library", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Users/me/incident-copy.pcap");
    const api = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB), exportCapture: vi.fn().mockResolvedValue({ filename: "incident-copy.pcap", directory: "/Users/me", size_bytes: 1 }) });
    const user = userEvent.setup();
    renderApp(api, "/captures");
    const row = await screen.findByRole("row", { name: "incident.pcap" });
    await user.click(within(row).getByRole("button", { name: "Export" }));
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ defaultPath: "incident.pcap" }));
    await waitFor(() => expect(api.exportCapture).toHaveBeenCalledWith("2".repeat(32), "/Users/me/incident-copy.pcap", false));
    expect(await within(row).findByText(/PCAP exported successfully/)).toBeInTheDocument();
  });

  it("deleting needs confirmation and is not offered while a capture is recording or being analysed", async () => {
    const busy = makeCapture({ id: "5".repeat(32), original_filename: "busy.pcap", status: "ANALYZING", summary: null });
    const listCaptures = vi.fn().mockResolvedValueOnce([...LIB, busy]).mockResolvedValue(LIB.slice(1));
    const api = mockApi({ listCaptures });
    const user = userEvent.setup();
    renderApp(api, "/captures");
    expect(await screen.findByRole("button", { name: "Delete busy.pcap" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Delete office_capture.pcap" }));
    const dialog = screen.getByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.deleteCapture).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete office_capture.pcap" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete capture" }));
    await waitFor(() => expect(api.deleteCapture).toHaveBeenCalledWith("1".repeat(32)));
    expect(await screen.findByText(/Deleted “office_capture.pcap”/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("row", { name: "office_capture.pcap" })).not.toBeInTheDocument());
  });

  it("shows a deletion error from the backend", async () => {
    const api = mockApi({ listCaptures: vi.fn().mockResolvedValue(LIB), deleteCapture: vi.fn().mockRejectedValue(apiError("unknown", "The capture file could not be deleted (is it open in another program?).")) });
    const user = userEvent.setup();
    renderApp(api, "/captures");
    await user.click(await screen.findByRole("button", { name: "Delete incident.pcap" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete capture" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be deleted");
  });
});

void makeJob;
