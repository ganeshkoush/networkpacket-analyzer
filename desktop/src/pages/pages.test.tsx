import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { emptyAnalysis, emptyDashboard, makeBundle, makeFinding, makeJob } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp } from "../test/render";

async function analyzeDemo(api = mockApi()) {
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  return { user, api };
}

describe("Dashboard", () => {
  it("shows an empty state before any analysis", async () => {
    renderApp(mockApi(), "/");
    expect(await screen.findByText("No capture analyzed yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open PCAP Analysis" })).toHaveAttribute("href", "/analysis");
  });

  it("shows the health score, key metrics, traffic breakdown, timeline and findings after analysis", async () => {
    const { user } = await analyzeDemo();
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
    expect(await screen.findByText("Total traffic")).toBeInTheDocument();
    expect(screen.getByTestId("health-score")).toHaveTextContent("72");
    expect(screen.getByText("Protocol distribution")).toBeInTheDocument();
    expect(screen.getByLabelText("Top source IPs")).toHaveTextContent("10.0.0.99");
    expect(screen.getByLabelText("Top destination IPs")).toHaveTextContent("10.0.0.9");
    expect(screen.getByLabelText("Top destination ports")).toHaveTextContent("443");
    expect(screen.getByLabelText("Top destination ports")).toHaveTextContent("https");
    expect(screen.getByRole("img", { name: /Packets per second/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Protocol distribution: TCP 75%/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Security findings 1" })).toBeInTheDocument();
  });

  it("offers a table view of the timeline", async () => {
    const { user } = await analyzeDemo();
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
    await user.click(await screen.findByRole("button", { name: "View as table" }));
    expect(screen.getByRole("columnheader", { name: "Pkt/s" })).toBeInTheDocument();
  });

  it("handles an empty capture", async () => {
    const api = mockApi({ getDashboard: vi.fn().mockResolvedValue(emptyDashboard()) }, makeBundle({ analysis: emptyAnalysis(), findings: [] }));
    const { user } = await analyzeDemo(api).catch(async () => {
      const user = userEvent.setup(); return { user, api };
    });
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
    expect(await screen.findByText("This capture contains no packets")).toBeInTheDocument();
  });
});

describe("PCAP Analysis", () => {
  it("shows the picker and the backend limit initially", async () => {
    renderApp(mockApi(), "/analysis");
    expect(await screen.findByText("Select a capture to analyze")).toBeInTheDocument();
    expect(await screen.findByText(/Maximum file size: 1\.0 GB/)).toBeInTheDocument();
  });

  it("analyzes a file and shows result tabs", async () => {
    const { user, api } = await analyzeDemo();
    expect(api.submitCapture).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("link", { name: "3 findings" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Summary" })).toHaveAttribute("aria-selected", "true");
    for (const [tab, text] of [["Hosts", "Top talkers"], ["Ports", "Destination ports"], ["TCP", "Retransmission indicators"], ["DNS", "Top queried names"], ["Connections", "93.184.216.34:443"]] as const) {
      await user.click(screen.getByRole("tab", { name: tab }));
      expect((await screen.findAllByText(text)).length).toBeGreaterThan(0);
    }
  });

  it("shows live progress while analyzing", async () => {
    const running = makeJob({ status: "running", progress_percent: 42, packets_read: 4321, elapsed_seconds: 3 });
    const api = mockApi({ submitCapture: vi.fn().mockResolvedValue(running), getStatus: vi.fn().mockResolvedValue(running) });
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    await user.upload(screen.getByLabelText("Capture file"), pcapFile("big.pcap"));
    expect(await screen.findByText(/4,321 packets read/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Analysis progress" })).toHaveAttribute("aria-valuenow", "42");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("Select a capture to analyze")).toBeInTheDocument();
  });

  it("explains an invalid PCAP file and lets the user pick another", async () => {
    const api = mockApi({ submitCapture: vi.fn().mockRejectedValue(apiError("invalid_capture", "'notes.txt' is not a valid PCAP or PCAPNG capture file.")) });
    const user = userEvent.setup({ applyAccept: false });   // the picker filters by extension, but a dropped file or "All files" is not
    renderApp(api, "/analysis");
    await user.upload(screen.getByLabelText("Capture file"), pcapFile("notes.txt"));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Not a valid capture file");
    expect(alert).toHaveTextContent("not a valid PCAP or PCAPNG");
    expect(alert).toHaveTextContent("editcap");
    await user.click(within(alert).getByRole("button", { name: "Choose another file" }));
    expect(await screen.findByText("Select a capture to analyze")).toBeInTheDocument();
  });

  it("tells the user how to start the backend when it is unavailable", async () => {
    const api = mockApi({ fetchHealth: vi.fn().mockRejectedValue(apiError("backend_unavailable", "down")),
      submitCapture: vi.fn().mockRejectedValue(apiError("backend_unavailable", "down")) });
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    expect(await screen.findByText("Backend unavailable.")).toBeInTheDocument();       // global banner
    await user.upload(screen.getByLabelText("Capture file"), pcapFile());
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((a) => a.textContent?.includes("Can't reach the PacketMind backend"))).toBe(true);
    expect(screen.getAllByText(/main\.py/).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Retry connection" })).toBeInTheDocument();
  });

  it("recovers when the backend comes back (Retry)", async () => {
    const health = vi.fn().mockRejectedValueOnce(apiError("backend_unavailable", "down")).mockResolvedValue({ status: "ok", app: "PacketMind", version: "0.1.0" });
    const user = userEvent.setup();
    renderApp(mockApi({ fetchHealth: health }), "/analysis");
    await user.click(await screen.findByRole("button", { name: "Retry now" }));
    await waitFor(() => expect(screen.queryByText("Backend unavailable.")).not.toBeInTheDocument());
  });

  it("shows an empty-capture result and warnings", async () => {
    const api = mockApi({ getDashboard: vi.fn().mockResolvedValue(emptyDashboard()) }, makeBundle({ analysis: emptyAnalysis(), findings: [] }));
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    await user.upload(screen.getByLabelText("Capture file"), pcapFile("empty.pcap"));
    expect(await screen.findByText("This capture contains no packets")).toBeInTheDocument();
  });

  it("warns about very large files and rejects oversize ones before uploading", async () => {
    const user = userEvent.setup();
    const api = mockApi({ fetchHealth: vi.fn().mockResolvedValue({ status: "ok", app: "PacketMind", version: "1", max_upload_bytes: 1000 }) });
    renderApp(api, "/analysis");
    await screen.findByText(/Maximum file size: 1000 B/);
    const big = pcapFile("huge.pcap");
    Object.defineProperty(big, "size", { value: 2_000_000 });
    await user.upload(screen.getByLabelText("Capture file"), big);
    expect(await screen.findByText("File is too large")).toBeInTheDocument();
    expect(api.submitCapture).not.toHaveBeenCalled();
  });

  it("shows a large-file notice during analysis", async () => {
    const running = makeJob({ status: "running", progress_percent: 5 });
    const api = mockApi({ submitCapture: vi.fn().mockResolvedValue(running), getStatus: vi.fn().mockResolvedValue(running) });
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    const big = pcapFile("big.pcap");
    Object.defineProperty(big, "size", { value: 900 * 1024 * 1024 });
    await user.upload(screen.getByLabelText("Capture file"), big);
    expect(await screen.findByText(/large capture/i)).toBeInTheDocument();
  });
});

describe("Findings", () => {
  it("shows an empty state without a capture", async () => {
    renderApp(mockApi(), "/findings");
    expect(await screen.findByText("No capture analyzed yet")).toBeInTheDocument();
  });

  it("lists severity, type, source, destination, confidence and description", async () => {
    const { user } = await analyzeDemo();
    await user.click(screen.getByRole("link", { name: /^Findings/ }));
    const table = await screen.findByRole("table", { name: "Findings" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4); // header + 3
    const first = within(rows[1]);
    expect(first.getByLabelText("Severity HIGH")).toBeInTheDocument();
    expect(first.getByText("Port scan")).toBeInTheDocument();
    expect(first.getByText("10.0.0.99")).toBeInTheDocument();
    expect(first.getByText("10.0.0.9")).toBeInTheDocument();
    expect(first.getByText("0.91")).toBeInTheDocument();
    expect(first.getByText(/consistent with possible TCP port scanning/)).toBeInTheDocument();
  });

  it("filters by severity and text", async () => {
    const { user } = await analyzeDemo();
    await user.click(screen.getByRole("link", { name: /^Findings/ }));
    await screen.findByRole("table", { name: "Findings" });
    await user.click(screen.getByRole("button", { name: /^MEDIUM/ }));
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2);
    expect(screen.getByText("DNS DGA-like")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^MEDIUM/ }));
    await user.type(screen.getByLabelText("Filter findings"), "10.0.0.1");
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2);
    await user.clear(screen.getByLabelText("Filter findings"));
    await user.type(screen.getByLabelText("Filter findings"), "zzz-no-match");
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();
  });

  it("opens a detail view with what/why/evidence/confidence/recommendation", async () => {
    const { user } = await analyzeDemo();
    await user.click(screen.getByRole("link", { name: /^Findings/ }));
    await user.click(await screen.findByText("Port scan"));
    expect(await screen.findByRole("heading", { name: "Possible TCP port scan from 10.0.0.99" })).toBeInTheDocument();
    for (const h of ["What was detected", "Why it was detected", "Evidence", "Confidence", "Recommended investigation"]) {
      expect(screen.getByRole("heading", { name: h })).toBeInTheDocument();
    }
    expect(screen.getByText("Probed 119 distinct ports (threshold 15).")).toBeInTheDocument();
    expect(screen.getAllByText("unique ports").length).toBeGreaterThan(0);  // humanized evidence key
    expect(screen.getAllByText("119", { selector: "span.font-mono" }).length).toBeGreaterThan(0);
    expect(screen.getByText("Authorized vulnerability scanners produce this pattern.")).toBeInTheDocument();
    expect(screen.getByText("Check whether 10.0.0.99 is an authorized scanner.")).toBeInTheDocument();
    expect(screen.getByText(/never blocks addresses/)).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: /All findings/ }));
    expect(await screen.findByRole("table", { name: "Findings" })).toBeInTheDocument();
  });

  it("shows a clear state when there are no findings", async () => {
    const { user } = await analyzeDemo(mockApi({}, makeBundle({ findings: [] })));
    await user.click(screen.getByRole("link", { name: /^Findings/ }));
    expect(await screen.findByText("No findings")).toBeInTheDocument();
    expect(screen.getByText(/not proof the traffic is safe/)).toBeInTheDocument();
  });

  it("handles an unknown finding id", async () => {
    renderApp(mockApi(), "/findings/does-not-exist");
    expect(await screen.findByText("Finding not found")).toBeInTheDocument();
  });

  it("warns when detectors failed", async () => {
    const bundle = { ...makeBundle({ findings: [makeFinding()] }), detector_errors: { dns_anomaly: "RuntimeError: x" } };
    const { user } = await analyzeDemo(mockApi({}, bundle));
    await user.click(screen.getByRole("link", { name: /^Findings/ }));
    expect(await screen.findByText(/Some detectors failed/)).toHaveTextContent("dns_anomaly");
  });
});

describe("Navigation", () => {
  it("lists every section and has no dead-end placeholders", async () => {
    renderApp(mockApi(), "/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    for (const name of ["Dashboard", "PCAP Analysis", "Live Capture", "Findings", "Reports", "Settings"]) {
      expect(within(nav).getByRole("link", { name: new RegExp(name) })).toBeInTheDocument();
    }
    expect(within(nav).queryByText(/soon/i)).not.toBeInTheDocument();
  });

  it("groups sections, links Investigate Network, and collapses the sidebar", async () => {
    const user = userEvent.setup();
    localStorage.removeItem("pm.sidebar");
    renderApp(mockApi(), "/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: /Investigate Network/ })).toHaveAttribute("href", "/investigation");
    for (const g of ["Network", "Security", "Data", "System"]) expect(within(nav).getByText(g)).toBeInTheDocument();
    await user.click(within(nav).getByRole("button", { name: "Collapse sidebar" }));
    expect(within(nav).getByRole("button", { name: "Expand sidebar" })).toHaveAttribute("aria-pressed", "true");
    expect(localStorage.getItem("pm.sidebar")).toBe("collapsed");
    expect(within(nav).getByRole("link", { name: /Dashboard/ })).toBeInTheDocument(); // still reachable, with its tooltip
    localStorage.removeItem("pm.sidebar");
  });

  it("shows Capturing in the sidebar only when the backend reports a running capture", async () => {
    const api = mockApi();
    const idle = await api.getLiveStatus();
    renderApp(api, "/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await waitFor(() => expect(api.getLiveStatus).toHaveBeenCalled());
    expect(within(nav).queryByText("Capturing")).not.toBeInTheDocument();
    (api.getLiveStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ ...idle, state: "capturing" });
    renderApp(api, "/");
    expect((await screen.findAllByText("Capturing")).length).toBeGreaterThan(0);
  });

  it("sets the window title per route and offers a skip link", async () => {
    const user = userEvent.setup();
    renderApp(mockApi(), "/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    await user.click(within(nav).getByRole("link", { name: /Reports/ }));
    await waitFor(() => expect(document.title).toBe("Reports · PacketMind"));
  });

  it("shows a friendly page for unknown routes", async () => {
    renderApp(mockApi(), "/nope");
    expect(await screen.findByText("That page does not exist")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to dashboard" })).toBeInTheDocument();
  });
});
