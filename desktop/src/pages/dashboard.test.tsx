import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DashboardData } from "../api/types";
import { emptyDashboard, makeBundle, makeDashboard, makeInvestigation, makeWebRow } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

async function open(api: MockApi) {
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
  await screen.findByRole("tablist", { name: "Dashboard sections" }).catch(() => undefined);
  return user;
}
const tab = (name: string) => screen.getByRole("tab", { name });

describe("Network Intelligence Dashboard", () => {
  it("shows the health score with its deductions and every key metric", async () => {
    await open(mockApi());
    const score = await screen.findByRole("region", { name: "Network health score" });
    expect(within(score).getByTestId("health-score")).toHaveTextContent("72");
    expect(within(score).getByTestId("health-label")).toHaveTextContent("Degraded");
    expect(within(score).getByLabelText("Score deductions")).toHaveTextContent("Retransmission rate 6.2% is elevated");
    const kpis = screen.getByRole("group", { name: "Key metrics" });
    expect(within(kpis).getByText("Active connections").parentElement).toHaveTextContent("4");
    expect(within(kpis).getByText("Domains contacted").parentElement).toHaveTextContent("3");
    expect(within(kpis).getByText("Total traffic").parentElement).toHaveTextContent("2.4 MB");
    expect(within(kpis).getByText("Avg TCP handshake").parentElement).toHaveTextContent("48 ms");
    expect(within(kpis).getByText("Avg RTT").parentElement).toHaveTextContent("102 ms");
    expect(within(kpis).getByText("DNS latency").parentElement).toHaveTextContent("22 ms");
    expect(within(kpis).getByText("Retransmission rate").parentElement).toHaveTextContent("6.2%");
    expect(within(kpis).getByRole("button", { name: "Security findings 1" })).toBeInTheDocument();
    expect(within(kpis).getByRole("button", { name: "Performance anomalies 1" })).toBeInTheDocument();
  });

  it("offers the eight sections and the overview has the tables, timeline and activity", async () => {
    await open(mockApi());
    await screen.findByTestId("health-score");
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Overview", "Domains", "Connections", "Performance", "Security", "AI Investigation", "Network Map", "Reports"]);
    expect(tab("Overview")).toHaveAttribute("aria-selected", "true");
    const top = screen.getByRole("table", { name: "Top domains" });
    expect(within(top).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Domain", "Connections", "Traffic", "Latency", "Health"]);
    expect(top).toHaveTextContent("github.com");
    const slow = screen.getByRole("table", { name: "Slowest services" });
    expect(within(slow).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Domain", "Avg RTT", "P95 RTT", "TCP handshake", "Status"]);
    expect(within(slow).getAllByRole("row")[1]).toHaveTextContent(/slow\.example\.com.*420 ms.*610 ms.*350 ms.*Poor/);
    const findings = screen.getByRole("table", { name: "Recent findings" });
    expect(within(findings).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Finding", "Severity", "Confidence", "Evidence"]);
    expect(findings).toHaveTextContent("Possible port scan from 10.0.0.99");
    expect(findings).toHaveTextContent("distinct_ports: 220");
    expect(screen.getByRole("table", { name: "Suspicious connections" })).toHaveTextContent("10.0.0.9:22");
    expect(screen.getByLabelText("Recent activity")).toHaveTextContent("First contact with github.com");
    expect(screen.getByRole("img", { name: /Packets per second/ })).toBeInTheDocument();
    expect(screen.getByLabelText("Events on the timeline")).toHaveTextContent("Possible port scan");
  });

  it("requests the backend for each time range and keeps the old numbers while loading", async () => {
    const getDashboard = vi.fn().mockImplementation(async (_id: string, range: string) => makeDashboard({ window: { ...makeDashboard().window, key: range as DashboardData["window"]["key"] } }));
    const user = await open(mockApi({ getDashboard }));
    await screen.findByTestId("health-score");
    expect(getDashboard).toHaveBeenLastCalledWith("job1", "all", expect.anything());
    const group = screen.getByRole("radiogroup", { name: "Time range" });
    expect(within(group).getAllByRole("radio").map((r) => r.textContent)).toEqual(["Last 5 minutes", "Last 15 minutes", "Last hour", "Capture duration"]);
    expect(within(group).getByRole("radio", { name: "Capture duration" })).toHaveAttribute("aria-checked", "true");
    for (const [label, key] of [["Last 5 minutes", "5m"], ["Last 15 minutes", "15m"], ["Last hour", "1h"]] as const) {
      await user.click(within(group).getByRole("radio", { name: label }));
      await waitFor(() => expect(getDashboard).toHaveBeenLastCalledWith("job1", key, expect.anything()));
      expect(within(group).getByRole("radio", { name: label })).toHaveAttribute("aria-checked", "true");
    }
    expect(screen.getByTestId("health-score")).toBeInTheDocument();      // the view never blanked out
  });

  it("shows a notice when the range is longer than the capture", async () => {
    const d = makeDashboard({ window: { ...makeDashboard().window, key: "1h", note: "The capture is shorter than this range (30 s), so the whole capture is shown." } });
    await open(mockApi({ getDashboard: vi.fn().mockResolvedValue(d) }));
    expect(await screen.findByText(/capture is shorter than this range/)).toBeInTheDocument();
  });

  it("shows a loading state and then an error with retry", async () => {
    const getDashboard = vi.fn().mockRejectedValueOnce(apiError("backend_unavailable", "Cannot reach the PacketMind backend.")).mockResolvedValue(makeDashboard());
    const user = await open(mockApi({ getDashboard }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the PacketMind backend.");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByTestId("health-score")).toBeInTheDocument();
  });

  it("handles an empty capture without a score", async () => {
    await open(mockApi({ getDashboard: vi.fn().mockResolvedValue(emptyDashboard()) }, makeBundle()));
    expect(await screen.findByText("This capture contains no packets")).toBeInTheDocument();
    expect(screen.queryByTestId("health-score")).not.toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("missing DNS: no domains, and the tables say why instead of looking broken", async () => {
    const d = makeDashboard({ top_domains: [], slowest_domains: [], kpis: { ...makeDashboard().kpis, domains_contacted: 0, avg_rtt_ms: null, dns_latency_ms: null, rtt_samples: 0, dns_samples: 0 } });
    await open(mockApi({ getDashboard: vi.fn().mockResolvedValue(d) }));
    expect(await screen.findByText(/No domains were attributed in this range/)).toBeInTheDocument();
    expect(screen.getByText("No domain has timing data in this range.")).toBeInTheDocument();
    const kpis = screen.getByRole("group", { name: "Key metrics" });
    expect(within(kpis).getByText("Avg RTT").parentElement).toHaveTextContent("not measurable here");
    expect(within(kpis).getByText("DNS latency").parentElement).toHaveTextContent("not measurable here");
  });

  it("missing timing data: the score is Unknown, never Healthy", async () => {
    const d = makeDashboard({
      health: { score: null, label: "Unknown", deductions: [], basis: "Nothing measurable in this range (no timing data and no findings), so no score is claimed." },
      kpis: { ...makeDashboard().kpis, avg_handshake_ms: null, avg_rtt_ms: null, dns_latency_ms: null, retransmission_rate: null, findings: 0, anomalies: 0 }, findings: [], anomalies: [],
      top_domains: [makeWebRow({ domain: "udp.example.com", avg_rtt_ms: null, tcp_handshake_ms: null, health: "unknown" })], slowest_domains: [],
    });
    await open(mockApi({ getDashboard: vi.fn().mockResolvedValue(d) }));
    const score = await screen.findByRole("region", { name: "Network health score" });
    expect(within(score).getByTestId("health-score")).toHaveTextContent("–");
    expect(within(score).getByTestId("health-label")).toHaveTextContent("Unknown");
    expect(within(score).queryByText("Healthy")).not.toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Top domains" })).toHaveTextContent("Unknown");
  });

  it("opens each section with its own content", async () => {
    const user = await open(mockApi());
    await screen.findByTestId("health-score");
    await user.click(tab("Domains"));
    expect(screen.getByRole("heading", { name: "Top domains" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Domains / Web Activity" })).toHaveAttribute("href", "/web");
    await user.click(tab("Connections"));
    expect(screen.getByRole("table", { name: "Active connections" })).toHaveTextContent("github.com");
    expect(screen.getByRole("table", { name: "Suspicious connections" })).toHaveTextContent("PORT_SCAN-1");
    await user.click(tab("Performance"));
    expect(screen.getByRole("article", { name: "Performance anomaly github.com" })).toBeInTheDocument();
    await user.click(tab("Security"));
    expect(screen.getByRole("table", { name: "Recent findings" })).toHaveTextContent("HIGH");
    expect(screen.getByRole("link", { name: /Possible port scan/ })).toHaveAttribute("href", "/findings/PORT_SCAN-1");
    await user.click(tab("Network Map"));
    expect(screen.getByRole("link", { name: "Open the network map" })).toHaveAttribute("href", "/map");
    await user.click(tab("Reports"));
    expect(screen.getByRole("link", { name: "Open saved reports" })).toHaveAttribute("href", "/reports");
  });

  it("the findings and anomalies tiles jump to their sections", async () => {
    const user = await open(mockApi());
    await user.click(await screen.findByRole("button", { name: "Security findings 1" }));
    expect(tab("Security")).toHaveAttribute("aria-selected", "true");
    await user.click(tab("Overview"));
    await user.click(screen.getByRole("button", { name: "Performance anomalies 1" }));
    expect(tab("Performance")).toHaveAttribute("aria-selected", "true");
  });

  it("the AI Investigation section starts the investigation and then shows its verdict", async () => {
    const investigateNetwork = vi.fn().mockResolvedValue(makeInvestigation());
    const user = await open(mockApi({ investigateNetwork }));
    await screen.findByTestId("health-score");
    await user.click(tab("AI Investigation"));
    const panel = screen.getByRole("tabpanel");
    await user.click(within(panel).getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByTestId("health")).toHaveTextContent("DEGRADED");   // taken to the full result screen
    expect(investigateNetwork).toHaveBeenCalledTimes(1);
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
    await user.click(await screen.findByRole("tab", { name: "AI Investigation" }));
    expect(screen.getByText(/Elevated packet retransmissions/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the full investigation" })).toBeInTheDocument();
  });

  it("stays quick with the largest response the backend can send", async () => {
    const rows = Array.from({ length: 10 }, (_, i) => makeWebRow({ domain: `host${i}.example.com`, total_bytes: 1000 * (10 - i) }));
    const act = Array.from({ length: 15 }, (_, i) => ({ time: 1_700_000_000 + i, kind: "domain" as const, text: `First contact with host${i}.example.com`, severity: null, ref: `host${i}` }));
    const timeline = Array.from({ length: 300 }, (_, i) => ({ start_time: 1_700_000_000 + i, interval_seconds: 1, packets: 10 + i, bytes: 1000 }));
    const d = makeDashboard({ top_domains: rows, recent_activity: act, timeline });
    const t0 = performance.now();
    await open(mockApi({ getDashboard: vi.fn().mockResolvedValue(d) }));
    await screen.findByTestId("health-score");
    expect(performance.now() - t0).toBeLessThan(5000);
    expect(screen.getByRole("table", { name: "Top domains" }).querySelectorAll("tbody tr")).toHaveLength(5);   // the overview shows a short list; the Domains section all
  });

  it("live capture: offers the live dashboard and switches source", async () => {
    const live = makeDashboard({ source: "live", health: { ...makeDashboard().health, score: 90, label: "Healthy" } });
    const getLiveStatus = vi.fn().mockResolvedValue({ state: "capturing", interface: "en0", started_at: 1, elapsed_seconds: 5, packets_total: 10, bytes_total: 10, packets_per_second: 1, bits_per_second: 1, window_seconds: 5, window_packets: 10,
      window_truncated: false, last_analysis_at: 1, protocols: [], top_talkers: [], top_ports: [], findings: [], auto_investigate: false, parse_errors: 0, error: null });
    const getLiveDashboard = vi.fn().mockResolvedValue(live);
    const user = await open(mockApi({ getLiveStatus, getLiveDashboard }));
    const source = await screen.findByRole("group", { name: "Data source" });
    expect(screen.getByTestId("health-score")).toHaveTextContent("72");
    await user.click(within(source).getByRole("button", { name: "Live capture" }));
    await waitFor(() => expect(screen.getByTestId("health-score")).toHaveTextContent("90"));
    expect(getLiveDashboard).toHaveBeenCalledWith("all", expect.anything());
    expect(screen.queryByRole("button", { name: /Investigate Network/ })).not.toBeInTheDocument();     // investigation needs a saved capture
    await user.click(within(source).getByRole("button", { name: "Capture file" }));
    await waitFor(() => expect(screen.getByTestId("health-score")).toHaveTextContent("72"));
  });

  it("with only a live capture running and no file, the dashboard shows the live data", async () => {
    const getLiveStatus = vi.fn().mockResolvedValue({ state: "capturing", interface: "en0", started_at: 1, elapsed_seconds: 5, packets_total: 10, bytes_total: 10, packets_per_second: 1, bits_per_second: 1, window_seconds: 5,
      window_packets: 10, window_truncated: false, last_analysis_at: 1, protocols: [], top_talkers: [], top_ports: [], findings: [], auto_investigate: false, parse_errors: 0, error: null });
    const api = mockApi({ getLiveStatus, getLiveDashboard: vi.fn().mockResolvedValue(makeDashboard({ source: "live" })) });
    renderApp(api, "/");
    expect(await screen.findByTestId("health-score")).toBeInTheDocument();
    expect(screen.getByText("Live capture · rolling window")).toBeInTheDocument();
    expect(api.getDashboard).not.toHaveBeenCalled();
  });

  it("without a capture or live capture there is nothing to show", async () => {
    const api = mockApi();
    renderApp(api, "/");
    expect(await screen.findByText("No capture analyzed yet")).toBeInTheDocument();
    expect(api.getDashboard).not.toHaveBeenCalled();
  });
});
