import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { InterfaceInfo, LiveStatus } from "../api/types";
import { IDLE_STATUS } from "../state/useLiveCapture";
import { makeFinding } from "../test/fixtures";
import { LiveCapture } from "./LiveCapture";

const IFACES: InterfaceInfo[] = [
  { name: "en0", description: "Wi-Fi", kind: "wifi", addresses: ["192.168.1.5"], is_up: true },
  { name: "utun3", description: "utun3", kind: "vpn", addresses: [], is_up: true },
  { name: "lo0", description: "lo0", kind: "loopback", addresses: ["127.0.0.1"], is_up: true },
];
const CAPTURING: LiveStatus = {
  ...IDLE_STATUS, state: "capturing", interface: "en0", elapsed_seconds: 12, packets_total: 4321, bytes_total: 900_000,
  packets_per_second: 120.5, bits_per_second: 80_000, window_packets: 4000,
  protocols: [{ protocol: "TCP", packets: 3000, bytes: 1, percent_of_packets: 75 }, { protocol: "DNS", packets: 1000, bytes: 1, percent_of_packets: 25 }],
  top_talkers: [{ ip: "10.0.0.2", is_private: true, packets_sent: 5, packets_received: 5, bytes_sent: 1, bytes_received: 1, total_packets: 3000, total_bytes: 2000 }],
  top_ports: [{ protocol: "TCP", port: 443, packets: 2500, bytes: 1, service_hint: "https" }],
};

function api(over: Record<string, unknown> = {}) {
  return {
    listInterfaces: vi.fn().mockResolvedValue(IFACES),
    getLiveStatus: vi.fn().mockResolvedValue(IDLE_STATUS),
    startLive: vi.fn().mockResolvedValue(CAPTURING),
    stopLive: vi.fn().mockResolvedValue({ ...CAPTURING, state: "stopped" }),
    ...over,
  } as never;
}

// The page links to the capture library, so it renders inside a router like it does in the app.
const renderLive = (a: never) => render(<MemoryRouter><LiveCapture api={a} /></MemoryRouter>);

describe("Live Capture page", () => {
  it("never starts capturing on its own and shows the stopped indicator", async () => {
    const a = api();
    renderLive(a);
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText("○")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start capture" })).toBeDisabled();
    expect((a as { startLive: ReturnType<typeof vi.fn> }).startLive).not.toHaveBeenCalled();
  });

  it("groups interfaces by kind", async () => {
    renderLive(api());
    const select = await screen.findByLabelText("Network interface");
    const groups = Array.from(select.querySelectorAll("optgroup")).map((g) => g.label);
    expect(groups).toEqual(["Wi-Fi", "VPN", "Loopback"]);
  });

  it("starts on explicit click, shows ● Capturing, counts, rate, protocols, talkers, ports", async () => {
    const a = api();
    const user = userEvent.setup();
    renderLive(a);
    await user.selectOptions(await screen.findByLabelText("Network interface"), "en0");
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    expect((a as { startLive: ReturnType<typeof vi.fn> }).startLive).toHaveBeenCalledWith({ interface: "en0", auto_investigate: false });
    expect(await screen.findByText("Capturing")).toBeInTheDocument();
    expect(screen.getByText("●")).toBeInTheDocument();
    expect(screen.getByText("4,321")).toBeInTheDocument();
    expect(screen.getByText("120.5")).toBeInTheDocument();
    expect(screen.getByLabelText("Protocol statistics")).toHaveTextContent("TCP");
    expect(screen.getByRole("table", { name: "Top talkers" })).toHaveTextContent("10.0.0.2");
    expect(screen.getByLabelText("Top ports")).toHaveTextContent("TCP/443 · https");
    expect(screen.getByRole("button", { name: "Stop capture" })).toBeEnabled();
  });

  it("sends the AI opt-in only when the box is ticked", async () => {
    const a = api();
    const user = userEvent.setup();
    renderLive(a);
    await user.selectOptions(await screen.findByLabelText("Network interface"), "lo0");
    await user.click(screen.getByRole("checkbox", { name: /Automatically investigate/ }));
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    expect((a as { startLive: ReturnType<typeof vi.fn> }).startLive).toHaveBeenCalledWith({ interface: "lo0", auto_investigate: true });
  });

  it("stops on click", async () => {
    const a = api({ getLiveStatus: vi.fn().mockResolvedValue(CAPTURING) });
    const user = userEvent.setup();
    renderLive(a);
    await user.click(await screen.findByRole("button", { name: "Stop capture" }));
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
  });

  it("shows ⚠ Permission error with the OS hint", async () => {
    const err = new ApiError("unknown", "Permission denied: PacketMind may not capture on this interface.", 403, "permission_denied", "macOS: run the backend with sudo");
    const a = api({
      startLive: vi.fn().mockRejectedValue(err),
      getLiveStatus: vi.fn().mockResolvedValue({ ...IDLE_STATUS, state: "permission_error", error: { code: "permission_denied", message: err.message, hint: err.hint } }),
    });
    const user = userEvent.setup();
    renderLive(a);
    await user.selectOptions(await screen.findByLabelText("Network interface"), "en0");
    await user.click(screen.getByRole("button", { name: "Start capture" }));
    await waitFor(() => expect(screen.getAllByText("Permission error").length).toBeGreaterThan(0));
    expect(screen.getByText("⚠", { selector: "span[aria-hidden]" })).toBeInTheDocument();
    expect(await screen.findByText(/run the backend with sudo/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start capture" })).toBeEnabled(); // user can retry
  });

  it("lists findings and a completed AI investigation; failed investigations say so", async () => {
    const f = makeFinding();
    const inv = { status: "completed", requested_at: 1, error: null, report: { model: "gemini-x", provider: "gemini", notes: [], result: {
      investigation_summary: "Possible port scanning.", finding_type: "PORT_SCAN", severity: "HIGH", confidence: 0.8, evidence: [],
      interpretation: "Consistent with scanning.", possible_explanations: [], recommended_next_steps: ["Confirm the scan was authorized."],
      additional_evidence_needed: [], limitations: ["PCAP cannot show intent."] } } };
    const failed = { status: "failed", requested_at: 1, report: null, error: { code: "missing_api_key", message: "GEMINI_API_KEY is not set.", hint: null } };
    const status = { ...CAPTURING, findings: [
      { finding: f, first_detected_at: 1, last_detected_at: 2, detections: 3, active: true, investigation: inv },
      { finding: makeFinding({ id: "X-1", type: "DNS_HIGH_NXDOMAIN", title: "Many NXDOMAIN" }), first_detected_at: 1, last_detected_at: 2, detections: 1, active: false, investigation: failed },
    ] };
    renderLive(api({ getLiveStatus: vi.fn().mockResolvedValue(status) }));
    const list = await screen.findByLabelText("Live findings");
    expect(list).toHaveTextContent("Possible TCP port scan");
    expect(list).toHaveTextContent("Confirm the scan was authorized.");
    expect(list).toHaveTextContent("AI investigation unavailable: GEMINI_API_KEY is not set.");
    expect(list).toHaveTextContent("No longer in window");
  });

  it("explains when the backend is unreachable", async () => {
    const a = api({ getLiveStatus: vi.fn().mockRejectedValue(new ApiError("backend_unavailable", "down")), listInterfaces: vi.fn().mockRejectedValue(new ApiError("backend_unavailable", "down")) });
    renderLive(a);
    expect(await screen.findByText("Backend unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start capture" })).toBeDisabled();
  });
});
