import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { WebActivityList, WebDomainDetail } from "../api/types";
import { emptyAnalysis, makeBundle, makeWebDetail, makeWebList, makeWebRow } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

const nav = () => within(screen.getByRole("navigation", { name: "Main" }));

/** Analyze a capture on /analysis, then open Web Activity from the sidebar (like a user would). */
async function openWeb(api: MockApi) {
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(nav().getByRole("link", { name: /Web Activity/ }));
  return user;
}

const apiWith = (list: WebActivityList | Promise<WebActivityList> = makeWebList(), detail: WebDomainDetail = makeWebDetail()) =>
  mockApi({ listWebActivity: vi.fn().mockResolvedValue(list), getWebDomain: vi.fn().mockResolvedValue(detail) });

const lastQuery = (api: MockApi) => api.listWebActivity.mock.calls[api.listWebActivity.mock.calls.length - 1][1];

describe("Web Activity: table", () => {
  it("asks for a capture first", async () => {
    renderApp(apiWith(), "/web");
    expect(await screen.findByRole("heading", { name: "No capture loaded" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open PCAP Analysis" })).toHaveAttribute("href", "/analysis");
  });

  it("lists domains with the requested columns and values", async () => {
    const api = apiWith();
    await openWeb(api);
    const table = await screen.findByRole("table", { name: "Domain web activity" });
    for (const h of ["Domain", "Connections", "Traffic", "DNS Latency", "TCP Handshake", "Avg RTT", "P95 RTT", "Health"]) {
      expect(within(table).getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    const cells = (name: RegExp) => within(within(table).getByRole("row", { name })).getAllByRole("cell").map((c) => c.textContent);
    expect(cells(/github\.com/)).toEqual(["github.com", "18", "3.1 MB", "18 ms", "51 ms", "72 ms", "104 ms", "Good"]);
    expect(cells(/youtube\.com/)).toEqual(["youtube.com", "31", "24.7 MB", "29 ms", "73 ms", "410 ms", "650 ms", "Poor"]);
    expect(api.listWebActivity).toHaveBeenCalledWith("job1", expect.objectContaining({ search: "", sort: "traffic", limit: 25, offset: 0 }), expect.anything());
  });

  it("shows a dash, not a number, for measurements the capture does not contain", async () => {
    await openWeb(apiWith());
    const row = within(await screen.findByRole("table", { name: "Domain web activity" })).getByRole("row", { name: /quic\.example\.org/ });
    expect(within(row).getAllByRole("cell").map((c) => c.textContent)).toEqual(["quic.example.org", "2", "8.8 KB", "–", "–", "–", "–", "Unknown"]);
  });

  it("explains a health rating on hover and says it is not a verdict", async () => {
    await openWeb(apiWith());
    expect(await screen.findByLabelText("Health Poor")).toHaveAttribute("title", "Average RTT 410 ms is high (threshold 300 ms)");
    expect(screen.getByText(/not a verdict on a site/)).toBeInTheDocument();
  });

  it("shows a loading state, then the table", async () => {
    let resolve!: (l: WebActivityList) => void;
    const api = apiWith(new Promise<WebActivityList>((r) => { resolve = r; }));
    await openWeb(api);
    expect(screen.getByText("Loading web activity…")).toBeInTheDocument();
    resolve(makeWebList());
    expect(await screen.findByRole("table", { name: "Domain web activity" })).toBeInTheDocument();
  });

  it("shows an error with Retry that reloads", async () => {
    const listWebActivity = vi.fn().mockRejectedValueOnce(apiError("server_error", "Backend exploded")).mockResolvedValue(makeWebList());
    const user = await openWeb(mockApi({ listWebActivity, getWebDomain: vi.fn() }));
    expect(await screen.findByText("Web activity unavailable")).toBeInTheDocument();
    expect(screen.getByText("Backend exploded")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("table", { name: "Domain web activity" })).toBeInTheDocument();
    expect(listWebActivity).toHaveBeenCalledTimes(2);
  });

  it("says when there is no DNS information at all", async () => {
    await openWeb(apiWith(makeWebList([], { summary: { total_domains: 0, domains_with_connections: 0, health_counts: {}, notes: [] } })));
    expect(await screen.findByText("No DNS information available")).toBeInTheDocument();
    expect(screen.getByText(/connections can't be mapped to domains/)).toBeInTheDocument();
  });

  it("says when domains were looked up but nothing connected, and can show them", async () => {
    const empty = makeWebList([], { summary: { total_domains: 3, domains_with_connections: 0, health_counts: {}, notes: [] } });
    const api = apiWith(empty);
    const user = await openWeb(api);
    expect(await screen.findByText("No connections found")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show DNS-only domains" }));
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ includeDnsOnly: true })));
  });

  it("handles a capture with no packets", async () => {
    const api = mockApi({}, makeBundle({ analysis: emptyAnalysis(), findings: [] }));
    await openWeb(api).catch(() => undefined);
    expect(await screen.findByText("This capture contains no packets")).toBeInTheDocument();
    expect(api.listWebActivity).not.toHaveBeenCalled();
  });
});

describe("Web Activity: search, sort, filter, paging", () => {
  it("sends search (debounced), sort and health filter to the backend", async () => {
    const api = apiWith();
    const user = await openWeb(api);
    await screen.findByRole("table", { name: "Domain web activity" });
    await user.type(screen.getByLabelText("Search domains"), "git");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ search: "git" })));
    await user.selectOptions(screen.getByLabelText("Sort domains"), "rtt");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ sort: "rtt", search: "git" })));
    await user.selectOptions(screen.getByLabelText("Filter by health"), "poor");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ health: "poor", sort: "rtt" })));
  });

  it("explains an empty filter result and clears the filters", async () => {
    const listWebActivity = vi.fn().mockImplementation((_id, q) => Promise.resolve(q.health === "fair" ? makeWebList([], { total_matching: 0, summary: makeWebList().summary }) : makeWebList()));
    const api = mockApi({ listWebActivity, getWebDomain: vi.fn() });
    const user = await openWeb(api);
    await screen.findByRole("table", { name: "Domain web activity" });
    await user.selectOptions(screen.getByLabelText("Filter by health"), "fair");
    expect(await screen.findByText("No domains match these filters")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("table", { name: "Domain web activity" })).toBeInTheDocument();
    expect(screen.getByLabelText("Filter by health")).toHaveValue("");
  });

  it("pages through a large result", async () => {
    const page = (offset: number) => makeWebList(Array.from({ length: 25 }, (_, i) => makeWebRow({ domain: `site${offset + i}.example.com` })), { total_matching: 12_000, offset });
    const listWebActivity = vi.fn().mockImplementation((_id, q) => Promise.resolve(page(q.offset ?? 0)));
    const api = mockApi({ listWebActivity, getWebDomain: vi.fn() });
    const user = await openWeb(api);
    expect(await screen.findByText("Showing 1–25 of 12,000")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("Showing 26–50 of 12,000")).toBeInTheDocument();
    expect(lastQuery(api)).toEqual(expect.objectContaining({ offset: 25, limit: 25 }));
    expect(screen.getByText("site25.example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("Showing 1–25 of 12,000")).toBeInTheDocument();
  });

  it("disables Next on the last page", async () => {
    await openWeb(apiWith());
    await screen.findByText("Showing 1–3 of 3");
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });
});

describe("Web Activity: domain details", () => {
  const openGithub = async (api = apiWith()) => {
    const user = await openWeb(api);
    await user.click(await screen.findByRole("row", { name: /github\.com/ }));
    return { user, api };
  };

  it("opens the domain with overview, performance, traffic and connections", async () => {
    const { api } = await openGithub();
    expect(await screen.findByRole("heading", { name: "github.com" })).toBeInTheDocument();
    expect(api.getWebDomain).toHaveBeenCalledWith("job1", "github.com", expect.anything());
    const overview = screen.getByLabelText("Overview");
    expect(within(overview).getByText("Connections").nextSibling).toHaveTextContent("18 (18 TCP · 0 UDP)");
    expect(within(overview).getByText("First seen")).toBeInTheDocument();
    expect(within(overview).getByText("Last seen")).toBeInTheDocument();
    expect(within(overview).getByText("Total traffic").nextSibling).toHaveTextContent("4.8 MB");
    const perf = screen.getByLabelText("Performance");
    const val = (k: string) => within(perf).getByText(k).nextSibling;
    expect(val("DNS latency")).toHaveTextContent("19 ms (median of 2 lookups)");
    expect(val("TCP handshake")).toHaveTextContent("51 ms (average of 18; connection set-up time)");
    expect(val("Average RTT")).toHaveTextContent("72 ms");
    expect(val("P95 RTT")).toHaveTextContent("104 ms");
    expect(val("Maximum RTT")).toHaveTextContent("180 ms");
    expect(val("Retransmissions")).toHaveTextContent("3 (heuristic indicator)");
    expect(val("Resets")).toHaveTextContent("2 RST packets in 1 connection");
    const traffic = screen.getByLabelText("Traffic");
    expect(within(traffic).getByText("Packets sent").nextSibling).toHaveTextContent("400");
    expect(within(traffic).getByText("Packets received").nextSibling).toHaveTextContent("900");
    expect(within(traffic).getByText("Bytes sent")).toBeInTheDocument();
    const conns = screen.getByRole("table", { name: "Connections to this domain" });
    expect(within(conns).getByText("10.0.0.5:50000")).toBeInTheDocument();
    expect(screen.getByText("The 1 largest of 18")).toBeInTheDocument();
    expect(screen.getByLabelText("Health observations")).toHaveTextContent("TCP handshake (average) 150 ms is elevated");
  });

  it("never presents the handshake as response time, and says HTTPS response time is not visible", async () => {
    await openGithub();
    const perf = await screen.findByLabelText("Performance");
    expect(within(perf).getByText("Response time").nextSibling).toHaveTextContent("not visible (HTTPS)");
    expect(within(perf).getByText("Response time").nextSibling).not.toHaveTextContent("51");
  });

  it("shows a visible cleartext HTTP response time", async () => {
    const d = makeWebDetail();
    await openGithub(apiWith(makeWebList(), { ...d, performance: { ...d.performance!, application_response_ms: 80, application_response_samples: 1, http_connections: 1, encrypted_connections: 0 } }));
    const perf = await screen.findByLabelText("Performance");
    expect(within(perf).getByText("Response time").nextSibling).toHaveTextContent("80 ms (cleartext HTTP, 1 exchange)");
  });

  it("draws the three charts", async () => {
    await openGithub();
    await screen.findByRole("heading", { name: "github.com" });
    expect(screen.getByRole("img", { name: /Response \/ RTT over time.*3 measurements/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /TCP handshake over time.*2 measurements/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Traffic volume over time.*3 time bins/ })).toBeInTheDocument();
  });

  it("shows clear empty states when the data is incomplete", async () => {
    const base = makeWebDetail();
    const incomplete = makeWebDetail({
      health: "unknown", health_reasons: [], performance: null, connections: [], connections_total: 0,
      overview: { ...base.overview, packets_sent: undefined, packets_received: undefined, resolved_ips: [], server_ports: [] },
      series: { bin_seconds: 1, rtt: [], handshake: [], traffic: [] },
    });
    await openGithub(apiWith(makeWebList(), incomplete));
    const perf = await screen.findByLabelText("Performance");
    expect(within(perf).getByText("DNS latency").nextSibling).toHaveTextContent("No DNS information available");
    expect(within(perf).getByText("Response time").nextSibling).toHaveTextContent("No measurable response-time data");
    expect(within(perf).getByText("Average RTT").nextSibling).toHaveTextContent("–");
    expect(screen.getByText("No connections found")).toBeInTheDocument();
    expect(screen.getAllByText("No measurable response-time data")).toHaveLength(2); // performance row + RTT chart
    expect(screen.getByText("No completed TCP handshakes to chart")).toBeInTheDocument();
    expect(screen.getByText("No traffic recorded")).toBeInTheDocument();
    expect(within(screen.getByLabelText("Traffic")).getByText("Packets sent").nextSibling).toHaveTextContent("–");
    expect(screen.queryAllByRole("img")).toHaveLength(0);
  });

  it("shows loading, then an error with Retry and a way back", async () => {
    const getWebDomain = vi.fn().mockRejectedValueOnce(apiError("not_found", "That domain was not seen in this analysis.")).mockResolvedValue(makeWebDetail());
    const api = mockApi({ listWebActivity: vi.fn().mockResolvedValue(makeWebList()), getWebDomain });
    const user = await openWeb(api);
    await user.click(await screen.findByRole("row", { name: /github\.com/ }));
    expect(await screen.findByText("Domain details unavailable")).toBeInTheDocument();
    expect(screen.getByText("That domain was not seen in this analysis.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { name: "github.com" })).toBeInTheDocument();
  });

  it("shows a loading state while the domain loads and goes back to the table", async () => {
    let resolve!: (d: WebDomainDetail) => void;
    const getWebDomain = vi.fn().mockReturnValue(new Promise<WebDomainDetail>((r) => { resolve = r; }));
    const user = await openWeb(mockApi({ listWebActivity: vi.fn().mockResolvedValue(makeWebList()), getWebDomain }));
    await user.click(await screen.findByRole("row", { name: /github\.com/ }));
    expect(screen.getByText("Loading github.com…")).toBeInTheDocument();
    resolve(makeWebDetail());
    await screen.findByRole("heading", { name: "github.com" });
    await user.click(screen.getByRole("button", { name: "← Back to domains" }));
    expect(await screen.findByRole("table", { name: "Domain web activity" })).toBeInTheDocument();
  });
});
