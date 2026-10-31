import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AnomalyList, DomainBaselineView, HistoryStatus } from "../api/types";
import { makeAnomaly, makeAnomalyList, makeBaselineView, makeWebDetail, makeWebList, makeWebRow } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

const STATUS: HistoryStatus = { enabled: true, sources: 12, observations: 34, domains: 5, oldest: 1_700_000_000, newest: 1_700_100_000, notes: [] };

async function openWeb(over: Partial<MockApi> = {}) {
  const api = mockApi({
    listWebActivity: vi.fn().mockResolvedValue(makeWebList([makeWebRow({ anomalies: 2 }), makeWebRow({ domain: "quiet.example.org", anomalies: 0 })])),
    getWebDomain: vi.fn().mockResolvedValue(makeWebDetail()),
    getAnomalies: vi.fn().mockResolvedValue(makeAnomalyList()),
    getDomainBaseline: vi.fn().mockResolvedValue(makeBaselineView()),
    getHistoryStatus: vi.fn().mockResolvedValue(STATUS),
    ...over,
  });
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Web Activity/ }));
  return { user, api };
}

describe("Performance anomalies on Web Activity", () => {
  it("shows the anomaly with baseline, current, increase and confidence", async () => {
    await openWeb();
    const card = await screen.findByRole("article", { name: "Performance anomaly github.com" });
    expect(within(card).getByRole("heading", { name: /Performance anomaly/ })).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "github.com" })).toBeInTheDocument();
    const hs = within(card).getByRole("region", { name: "TCP handshake" });
    const value = (k: string) => within(hs).getByText(k).nextSibling;
    expect(value("Baseline:")).toHaveTextContent("45 ms");
    expect(value("Current:")).toHaveTextContent("131 ms");
    expect(value("Increase:")).toHaveTextContent("+191%");
    expect(value("Confidence:")).toHaveTextContent("Medium");
    const retx = within(card).getByRole("region", { name: "Retransmission rate" });
    expect(within(retx).getByText("Baseline:").nextSibling).toHaveTextContent("0.8%");
    expect(within(retx).getByText("Current:").nextSibling).toHaveTextContent("6.2%");
    expect(within(retx).getByText("Confidence:").nextSibling).toHaveTextContent("High");
    expect(screen.getByText("Performance anomalies (2)")).toBeInTheDocument();
  });

  it("explains the evidence and keeps the language hedged", async () => {
    const { user } = await openWeb();
    const card = await screen.findByRole("article", { name: "Performance anomaly github.com" });
    await user.click(within(card).getAllByText("Evidence")[0]);
    expect(within(card).getAllByText(/against a typical 45 ms over the previous 14 observations/).length).toBeGreaterThan(0);
    expect(within(card).getAllByText(/not a diagnosis/).length).toBeGreaterThan(0);
    expect(card).not.toHaveTextContent(/definitely|certainly|malicious/i);
  });

  it("marks the domain in the table and opens its details from the anomaly", async () => {
    const { user, api } = await openWeb();
    const table = await screen.findByRole("table", { name: "Domain web activity" });
    expect(within(table).getByLabelText("2 performance anomalies")).toHaveTextContent("⚠ 2");
    expect(within(within(table).getByRole("row", { name: /quiet\.example\.org/ })).queryByText(/⚠/)).not.toBeInTheDocument();
    await user.click(within(await screen.findByRole("article", { name: "Performance anomaly github.com" })).getByRole("button", { name: "github.com" }));
    expect(await screen.findByRole("heading", { name: "github.com" })).toBeInTheDocument();
    expect(api.getWebDomain).toHaveBeenCalledWith("job1", "github.com", expect.anything());
  });

  it("says baselines are still being learned instead of flagging anything", async () => {
    await openWeb({ getAnomalies: vi.fn().mockResolvedValue(makeAnomalyList({ anomalies: [], domains_with_baseline: 0 })) });
    expect(await screen.findByText(/Learning baselines: no domain has enough earlier captures/)).toBeInTheDocument();
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("is calm when there is a baseline and nothing unusual", async () => {
    await openWeb({ getAnomalies: vi.fn().mockResolvedValue(makeAnomalyList({ anomalies: [], domains_with_baseline: 3, domains_evaluated: 4 })) });
    expect(await screen.findByText(/No performance anomalies compared with earlier captures \(3 of 4 domains/)).toBeInTheDocument();
  });

  it("reports when history is turned off and when it cannot be loaded", async () => {
    await openWeb({ getAnomalies: vi.fn().mockResolvedValue({ history_enabled: false, domains_evaluated: 0, domains_with_baseline: 0, anomalies: [], notes: [] } satisfies AnomalyList) });
    expect(await screen.findByText(/Performance history is turned off, so no baselines are learned/)).toBeInTheDocument();
  });

  it("does not block the table when anomaly loading fails", async () => {
    await openWeb({ getAnomalies: vi.fn().mockRejectedValue(apiError("server_error", "history db locked")) });
    expect(await screen.findByText(/Performance history is unavailable: history db locked/)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Domain web activity" })).toBeInTheDocument();
  });
});

describe("Historical baseline in domain details", () => {
  const openGithub = async (over: Partial<MockApi> = {}) => {
    const ctx = await openWeb(over);
    await ctx.user.click(await screen.findByRole("row", { name: /github\.com/ }));
    await screen.findByRole("heading", { name: "github.com" });
    return ctx;
  };

  it("compares baseline and current for each measured metric and says why some are not judged", async () => {
    const { api } = await openGithub();
    expect(api.getDomainBaseline).toHaveBeenCalledWith("job1", "github.com", expect.anything());
    const table = await screen.findByRole("table", { name: "Baseline versus current" });
    const cells = (name: RegExp) => within(within(table).getByRole("row", { name })).getAllByRole("cell").map((c) => c.textContent);
    expect(cells(/TCP handshake/)).toEqual(["TCP handshake", "45 ms", "131 ms", "+191%", "⚠ Unusual"]);
    expect(cells(/Average RTT/)).toEqual(["Average RTT", "38 ms", "40 ms", "+5%", "Normal"]);
    expect(cells(/P95 RTT/)[4]).toBe("Too few samples");
    expect(cells(/DNS latency/)[4]).toBe("Still learning (3 of 5)");
    expect(cells(/Retransmission rate/).slice(1, 4)).toEqual(["0.8%", "6.2%", "+675%"]);
    expect(within(table).queryByRole("row", { name: /Response time/ })).not.toBeInTheDocument(); // not measured in this capture
    expect(screen.getByText(/Compared with 14 earlier captures of this domain/)).toBeInTheDocument();
  });

  it("repeats the anomaly in the details and draws the historical charts", async () => {
    await openGithub();
    expect(await screen.findAllByRole("article", { name: "Performance anomaly github.com" })).not.toHaveLength(0);
    expect(screen.getByRole("img", { name: /Latency history: 15 measurements/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /DNS and response-time history: 15 measurements/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Retransmission and failure rate history: 15 measurements/ })).toBeInTheDocument();
    expect(screen.getByText(/the capture itself is never stored/)).toBeInTheDocument();
  });

  it("says the baseline is still being learned for a first-time domain", async () => {
    const first = makeBaselineView({ prior_observations: 0, anomalies: [], history: [makeBaselineView().history[14]],
      comparisons: makeBaselineView().comparisons.map((c) => ({ ...c, status: c.current == null ? "no_data" : "insufficient_baseline", baseline: null, z_score: null, relative_change: null })) });
    await openGithub({ getDomainBaseline: vi.fn().mockResolvedValue(first) });
    expect(await screen.findByText(/first capture of this domain on this computer: baselines are still being learned/)).toBeInTheDocument();
    expect(screen.getByText("Not enough history to chart yet: this is capture 1 of this domain.")).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /Latency history/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("article", { name: /Performance anomaly/ })).not.toBeInTheDocument();
  });

  it("notes that a judgement needs at least five earlier captures", async () => {
    await openGithub({ getDomainBaseline: vi.fn().mockResolvedValue(makeBaselineView({ prior_observations: 3, anomalies: [] })) });
    expect(await screen.findByText(/Compared with 3 earlier captures of this domain \(a judgement needs at least 5\)/)).toBeInTheDocument();
  });

  it("handles missing metrics, a disabled history and load errors", async () => {
    const none: DomainBaselineView = makeBaselineView({ comparisons: makeBaselineView().comparisons.map((c) => ({ ...c, status: "no_data" as const, current: null })), anomalies: [] });
    await openGithub({ getDomainBaseline: vi.fn().mockResolvedValue(none) });
    expect(await screen.findByText("Nothing measurable in this capture to compare.")).toBeInTheDocument();
  });

  it("offers Retry when the baseline cannot be loaded", async () => {
    const getDomainBaseline = vi.fn().mockRejectedValueOnce(apiError("server_error", "boom")).mockResolvedValue(makeBaselineView());
    const { user } = await openGithub({ getDomainBaseline });
    expect(await screen.findByText("Historical baseline unavailable")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("table", { name: "Baseline versus current" })).toBeInTheDocument();
  });

  it("says when performance history is turned off", async () => {
    await openGithub({ getDomainBaseline: vi.fn().mockResolvedValue(makeBaselineView({ history_enabled: false })) });
    expect(await screen.findByText("Performance history is turned off.")).toBeInTheDocument();
  });
});

describe("Local history controls", () => {
  it("states what is stored and that it stays local", async () => {
    await openWeb();
    expect(await screen.findByText(/12 captures · 34 domain observations since/)).toBeInTheDocument();
    expect(screen.getByText(/Only domain names and aggregate numbers are kept, on this computer only\./)).toBeInTheDocument();
  });

  it("deletes only after confirmation and refreshes the anomalies", async () => {
    const getAnomalies = vi.fn().mockResolvedValueOnce(makeAnomalyList()).mockResolvedValue(makeAnomalyList({ anomalies: [], domains_with_baseline: 0 }));
    const getHistoryStatus = vi.fn().mockResolvedValueOnce(STATUS).mockResolvedValue({ ...STATUS, sources: 0, observations: 0 });
    const { user, api } = await openWeb({ getAnomalies, getHistoryStatus });
    await user.click(await screen.findByRole("button", { name: "Clear history…" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("permanently removes the learned baselines (34 observations from 12 captures)");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.clearHistory).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Clear history…" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete history" }));
    await waitFor(() => expect(api.clearHistory).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Performance history deleted.")).toBeInTheDocument();
    expect(await screen.findByText(/Learning baselines/)).toBeInTheDocument();
    expect(screen.queryByRole("article", { name: /Performance anomaly/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear history…" })).not.toBeInTheDocument();
  });

  it("shows an error if deleting fails and keeps the history", async () => {
    const { user } = await openWeb({ clearHistory: vi.fn().mockRejectedValue(apiError("server_error", "database is locked")) });
    await user.click(await screen.findByRole("button", { name: "Clear history…" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete history" }));
    expect(await screen.findByText("database is locked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear history…" })).toBeInTheDocument();
  });

  it("says when history is empty", async () => {
    await openWeb({ getHistoryStatus: vi.fn().mockResolvedValue({ ...STATUS, observations: 0, sources: 0, oldest: null }) });
    expect(await screen.findByText(/is empty\./)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clear history…" })).not.toBeInTheDocument();
  });
});

describe("anomaly record content", () => {
  it("shows how long an anomaly has persisted", async () => {
    await openWeb({ getAnomalies: vi.fn().mockResolvedValue(makeAnomalyList({ anomalies: [makeAnomaly({ observations_in_run: 4 })] })) });
    expect(await screen.findByText(/Unusual in 4 consecutive captures, since/)).toBeInTheDocument();
  });
});
