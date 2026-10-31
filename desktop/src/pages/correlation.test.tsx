import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { CorrelationList } from "../api/types";
import { describeTiming } from "../components/results/RelatedEvents";
import { makeCorrelation, makeCorrelationList } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

async function openFinding(over: Partial<MockApi> = {}) {
  const api = mockApi(over);
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(screen.getByRole("link", { name: /^Findings/ }));
  await user.click(await screen.findByText("Port scan"));
  await screen.findByRole("heading", { name: "Possible TCP port scan from 10.0.0.99" });
  return { user, api };
}
const withList = (list: CorrelationList | Promise<CorrelationList>) => ({ getCorrelations: vi.fn().mockResolvedValue(list) });

describe("Related Events on a finding", () => {
  it("shows the finding, 'Potentially related' and the performance change as a chain", async () => {
    const { api } = await openFinding(withList(makeCorrelationList()));
    expect(api.getCorrelations).toHaveBeenCalledWith("job1", "PORT_SCAN-abc123", expect.anything());
    expect(screen.getByRole("heading", { name: "Related Events" })).toBeInTheDocument();
    const event = await screen.findByRole("article", { name: /Related event: TCP handshake latency increased 4\.5x/ });
    expect(within(event).getByText("Possible SYN flood against 10.0.0.9:80")).toBeInTheDocument();
    expect(within(event).getByText("Potentially related")).toBeInTheDocument();
    expect(within(event).getByText("TCP handshake latency increased 4.5x (40 ms → 180 ms)")).toBeInTheDocument();
    expect(within(event).getByText("within this capture")).toBeInTheDocument();
    expect(within(event).getAllByText("↓")).toHaveLength(2);
  });

  it("shows confidence, timing, time difference and shared scope", async () => {
    await openFinding(withList(makeCorrelationList()));
    const event = await screen.findByRole("article", { name: /Related event/ });
    expect(within(event).getByText("Confidence").nextSibling).toHaveTextContent("High (78% that the two are related; never certainty)");
    expect(within(event).getByText("Timing").nextSibling).toHaveTextContent("began 0.5 s after the security event started, while it was in progress");
    expect(within(event).getByText("Time difference").nextSibling).toHaveTextContent("+0.5 s");
    const scope = within(event).getByText("Shared scope").nextSibling as HTMLElement;
    expect(scope).toHaveTextContent("10.0.0.9");
    expect(scope).toHaveTextContent("shop.example.com");
    expect(scope).toHaveTextContent("specific host");
  });

  it("shows the underlying evidence and the caveats without needing a click", async () => {
    await openFinding(withList(makeCorrelationList()));
    const evidence = await screen.findByLabelText("Correlation evidence");
    expect(within(evidence).getByText(/median of 180 ms across 11 consecutive slow handshakes/)).toBeInTheDocument();
    expect(within(evidence).getByText(/were left out of both sides/)).toBeInTheDocument();
    expect(screen.getAllByText(/Correlation is not proof of causation/).length).toBeGreaterThan(0);
  });

  it("never claims causation anywhere in the section", async () => {
    await openFinding(withList(makeCorrelationList({ correlations: [makeCorrelation(), makeCorrelation({ id: "c2", temporal_relation: "same_connections", scope: "network", shared_domains: [] })] })));
    const card = (await screen.findByRole("heading", { name: "Related Events" })).closest("section") ?? document.body;
    expect(card.textContent).not.toMatch(/\b(caused|causes|because of|due to|result of|responsible for)\b/i);
    expect(card.textContent).toMatch(/Potentially related/);
  });

  it("explains each kind of timing, with a negative difference when performance came first", async () => {
    expect(describeTiming(makeCorrelation({ temporal_relation: "performance_precedes_finding", time_difference_seconds: -20 }))).toBe("The performance change began 20.0 s before the security event started.");
    expect(describeTiming(makeCorrelation({ temporal_relation: "performance_follows_finding", time_difference_seconds: 25 }))).toBe("The performance change began 25.0 s after the security event started, once it had ended.");
    expect(describeTiming(makeCorrelation({ temporal_relation: "same_connections" }))).toMatch(/same connections/);
    expect(describeTiming(makeCorrelation({ temporal_relation: "capture_level" }))).toMatch(/capture-level timing/);
    await openFinding(withList(makeCorrelationList({ correlations: [makeCorrelation({ temporal_relation: "performance_precedes_finding", time_difference_seconds: -20 })] })));
    expect((await screen.findByText("Time difference")).nextSibling).toHaveTextContent("−20.0 s");
  });

  it("marks history-based and network-wide correlations differently", async () => {
    await openFinding(withList(makeCorrelationList({ correlations: [makeCorrelation({
      temporal_relation: "capture_level", time_difference_seconds: 0, scope: "network", shared_ips: [], shared_domains: [],
      performance: { ...makeCorrelation().performance, basis: "history" } })] })));
    const event = await screen.findByRole("article");
    expect(within(event).getByText("vs. history")).toBeInTheDocument();
    expect(within(event).getByText("Time difference").nextSibling).toHaveTextContent("–");
    expect(within(event).getByText("Shared scope").nextSibling).toHaveTextContent("network-wide");
  });

  it("says plainly when nothing is related, and lists what was checked", async () => {
    await openFinding(withList(makeCorrelationList({ correlations: [], no_related_change: ["Possible SYN flood: no significant change in TCP handshake latency was found for the same scope and time."],
      not_evaluated: ["Possible SYN flood: DNS could not be checked because only 2 sample(s) inside the window (need 3)."] })));
    expect(await screen.findByText("No potentially related performance events were found for this finding.")).toBeInTheDocument();
    const details = screen.getByText("What was checked (2)").closest("details") as HTMLElement;
    expect(within(details).getByText(/no significant change in TCP handshake latency/)).toBeInTheDocument();
    expect(within(details).getByText(/only 2 sample\(s\) inside the window/)).toBeInTheDocument();
  });

  it("shows a loading state, then an error with Retry", async () => {
    let resolve!: (l: CorrelationList) => void;
    await openFinding({ getCorrelations: vi.fn().mockReturnValue(new Promise<CorrelationList>((r) => { resolve = r; })) });
    expect(screen.getByText("Looking for related performance events…")).toBeInTheDocument();
    resolve(makeCorrelationList({ correlations: [] }));
    expect(await screen.findByText(/No potentially related performance events/)).toBeInTheDocument();
  });

  it("offers Retry when the lookup fails and does not break the rest of the finding", async () => {
    const getCorrelations = vi.fn().mockRejectedValueOnce(apiError("server_error", "correlation backend hiccup")).mockResolvedValue(makeCorrelationList());
    const { user } = await openFinding({ getCorrelations });
    expect(await screen.findByText("Related events unavailable")).toBeInTheDocument();
    expect(screen.getByText("correlation backend hiccup")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Recommended investigation" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("article", { name: /Related event/ })).toBeInTheDocument();
  });

  it("discloses that connection data was thinned for a very large capture", async () => {
    await openFinding(withList(makeCorrelationList({ flow_data_thinned: true })));
    expect(await screen.findByText(/connection data was thinned to a uniform sample/)).toBeInTheDocument();
  });

  it("shows several related events for one finding", async () => {
    await openFinding(withList(makeCorrelationList({ correlations: [makeCorrelation(), makeCorrelation({ id: "c2", headline: "Round-trip time increased 4.0x (30 ms → 120 ms)" })] })));
    expect(await screen.findAllByRole("article", { name: /Related event/ })).toHaveLength(2);
  });
});
