import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { NetworkMapData } from "../api/types";
import { emptyAnalysis, makeBundle, makeNetworkMap, makeWebDetail, makeWebList, mapEdge, mapNode } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

const T = 1_700_000_000;

/** Analyze a capture on /analysis, then open the Network Map from the sidebar. Graph clicks use fireEvent: the graph library listens to raw mouse events. */
async function openMap(over: Partial<MockApi> = {}, bundle = makeBundle()) {
  const api = mockApi({ getNetworkMap: vi.fn().mockResolvedValue(makeNetworkMap()), ...over }, bundle);
  const user = userEvent.setup();
  renderApp(api, "/analysis");
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Network Map/ }));
  return { user, api };
}
const node = (name: RegExp | string) => screen.findByRole("button", { name });
const lastQuery = (api: MockApi) => api.getNetworkMap.mock.calls[api.getNetworkMap.mock.calls.length - 1][1];
const panel = () => screen.getByRole("complementary", { name: "Map details" });

describe("Network Map: drawing", () => {
  it("asks for a capture first", async () => {
    renderApp(mockApi(), "/map");
    expect(await screen.findByRole("heading", { name: "No capture loaded" })).toBeInTheDocument();
  });

  it("draws the local host, domains, addresses and ports with their health state in words", async () => {
    await openMap();
    await screen.findByRole("region", { name: "Network map" });
    for (const name of ["This computer 192.168.1.10, No health data", "Domain github.com, Healthy", "Domain youtube.com, Degraded", "IP address 140.82.112.3, Healthy",
      "IP address 45.33.32.156, Suspicious, 1 security finding", "Port TCP/443, Healthy", "Port UDP/443, No health data"]) {
      expect(await node(name)).toBeInTheDocument();
    }
  });

  it("shows latency (as RTT or handshake, never mixed up) and traffic on nodes", async () => {
    await openMap();
    const github = await node(/Domain github\.com/);
    expect(github).toHaveTextContent("72 ms RTT");
    expect(github).toHaveTextContent("3 connections");
    expect(within(github).getByTitle(/1 address/)).toBeInTheDocument();
    expect(await node(/Domain google\.com/)).toHaveTextContent("84 ms RTT");
  });

  it("labels each line with connection count, protocol, port, latency and traffic", async () => {
    await openMap();
    const line = await screen.findByRole("button", { name: "Connections from 192.168.1.10 to github.com: 3, TCP" });
    expect(line).toHaveTextContent("3 conn · TCP · :443");
    expect(line).toHaveTextContent("72 ms RTT");
    expect(line).toHaveTextContent("11.7 KB");
    expect(await screen.findByRole("button", { name: /Connections from 192\.168\.1\.10 to youtube\.com: 1, UDP/ })).toHaveTextContent("1 conn · UDP · :443");
  });

  it("offers zoom and pan controls, a minimap and a legend", async () => {
    await openMap();
    for (const name of ["Zoom In", "Zoom Out", "Fit View"]) expect(await screen.findByRole("button", { name })).toBeInTheDocument();
    const legend = screen.getByRole("list", { name: "Legend" });
    for (const word of ["Healthy", "Degraded", "Suspicious", "No health data"]) expect(legend).toHaveTextContent(word);
    expect(screen.getByRole("region", { name: "Network map" }).querySelector(".react-flow__minimap")).not.toBeNull();
    expect(screen.getByLabelText(/scroll to zoom, drag to pan/)).toBeInTheDocument();
  });

  it("warns that findings involve addresses on the map and marks them", async () => {
    await openMap();
    expect(await screen.findByText(/1 security finding involve addresses on this map|1 security finding involves|security finding.* involve addresses on this map/)).toBeInTheDocument();
  });

  it("says how much of the capture is shown", async () => {
    await openMap();
    expect(await screen.findByText("5 of 5 connections shown · 9 nodes")).toBeInTheDocument();
  });

  it("explains folded destinations and the node budget", async () => {
    const m = makeNetworkMap({ hidden: { destinations: 80, connections: 95, bytes: 123_000 }, shown_connections: 5, total_connections: 100 });
    m.nodes.push(mapNode("other", "other", "80 more destinations", 2, { members: 80, connections: 95, bytes: 123_000, state: "unknown" }));
    m.edges.push(mapEdge("local", "other", { connections: 95 }));
    await openMap({ getNetworkMap: vi.fn().mockResolvedValue(m) });
    expect(await screen.findByText(/80 lower-traffic destination\(s\) \(95 connections, 120 KB\) are folded into one node/)).toBeInTheDocument();
    fireEvent.click(await node(/More destinations 80 more destinations/));
    expect(panel()).toHaveTextContent("Folded in");
    expect(panel()).toHaveTextContent("Narrow the filters to see them individually");
  });
});

describe("Network Map: clicking", () => {
  it("a domain shows its details and opens the full domain page", async () => {
    const { user, api } = await openMap({ listWebActivity: vi.fn().mockResolvedValue(makeWebList()), getWebDomain: vi.fn().mockResolvedValue(makeWebDetail()) });
    fireEvent.click(await node(/Domain youtube\.com/));
    const p = panel();
    expect(p).toHaveTextContent("youtube.com");
    expect(p).toHaveTextContent("Degraded");
    expect(within(p).getByRole("list", { name: "Why this state" })).toHaveTextContent("Average RTT 410 ms is high");
    expect(p).toHaveTextContent("126 ms RTT");
    expect(p).toHaveTextContent("inferred from DNS");
    await user.click(within(p).getByRole("button", { name: "Open domain details" }));
    expect(await screen.findByRole("heading", { name: "github.com" })).toBeInTheDocument();          // Web Activity opened the domain directly
    expect(api.getWebDomain).toHaveBeenCalledWith("job1", "youtube.com", expect.anything());
  });

  it("a line shows its connections, and a connection shows its details", async () => {
    await openMap();
    fireEvent.click(await screen.findByRole("button", { name: /Connections from 192\.168\.1\.10 to github\.com/ }));
    const group = panel();
    expect(group).toHaveTextContent("192.168.1.10 → github.com");
    expect(group).toHaveTextContent("Protocol");
    expect(within(group).getByRole("list", { name: "Connections" }).children).toHaveLength(3);
    fireEvent.click(within(group).getAllByRole("button", { name: /TCP 192\.168\.1\.10:5000/ })[2]);
    const d = within(panel()).getByRole("list", { name: "Why this state" });
    expect(d).toHaveTextContent("4 retransmitted segments");
    const facts = within(panel()).getByLabelText("Connection details");
    expect(within(facts).getByText("TCP handshake").nextSibling).toHaveTextContent("45 ms (set-up time)");
    expect(within(facts).getByText("Round-trip time").nextSibling).toHaveTextContent("72 ms");
    expect(within(facts).getByText("Domain").nextSibling).toHaveTextContent("github.com (inferred from DNS)");
    expect(within(facts).getByText("Retransmissions").nextSibling).toHaveTextContent("4 (heuristic)");
  });

  it("a connection with an application says it comes from the operating system", async () => {
    await openMap();
    fireEvent.click(await node(/Domain google\.com/));
    fireEvent.click(within(panel()).getByRole("button", { name: /UDP 192\.168\.1\.10:50000/ }));
    expect(within(panel()).getByText("Application").nextSibling).toHaveTextContent("Google Chrome (from the operating system)");
  });

  it("a flagged address shows its finding, and the finding opens", async () => {
    const { user } = await openMap();
    fireEvent.click(await node(/IP address 45\.33\.32\.156/));
    expect(panel()).toHaveTextContent("Suspicious");
    expect(panel()).toHaveTextContent("Only known from a security finding");
    fireEvent.click(within(within(panel()).getByRole("list", { name: "Security findings" })).getByRole("button", { name: /Possible TCP port scan/ }));
    expect(panel()).toHaveTextContent("Security finding");
    expect(panel()).toHaveTextContent("confidence 91%");
    expect(panel()).toHaveTextContent("a possibility for a person to check, not a verdict");
    await user.click(within(panel()).getByRole("button", { name: "Open finding" }));
    expect(await screen.findByRole("heading", { name: "Possible TCP port scan from 10.0.0.99" })).toBeInTheDocument();
  });

  it("clicking the background or 'Clear selection' clears the selection", async () => {
    const { user } = await openMap();
    expect(panel()).toHaveTextContent("Click a node to see its details");
    fireEvent.click(await node(/Domain github\.com/));
    expect(panel()).toHaveTextContent("github.com");
    await user.click(within(panel()).getByRole("button", { name: "Clear selection" }));
    expect(panel()).toHaveTextContent("Click a node to see its details");
    fireEvent.click(await node(/Domain github\.com/));
    fireEvent.click(document.querySelector(".react-flow__pane") as Element);
    expect(panel()).toHaveTextContent("Click a node to see its details");
  });

  it("the selected node is marked", async () => {
    await openMap();
    const github = await node(/Domain github\.com/);
    expect(github).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(github);
    expect(await node(/Domain github\.com/)).toHaveAttribute("aria-pressed", "true");
  });

  it("an application node says where its name comes from", async () => {
    const m = makeNetworkMap();
    m.nodes.push(mapNode("app:Google Chrome", "application", "Google Chrome", 1, { connections: 1 }));
    await openMap({ getNetworkMap: vi.fn().mockResolvedValue(m) });
    fireEvent.click(await node(/Application Google Chrome/));
    expect(panel()).toHaveTextContent("from this computer's operating system at the moment snapshots were taken, not from the captured packets");
  });
});

describe("Network Map: filters", () => {
  it("sends the search to the backend after a short pause", async () => {
    const { user, api } = await openMap();
    await screen.findByRole("region", { name: "Network map" });
    await user.type(screen.getByLabelText("Search the map"), "github");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ search: "github" })));
  });

  it("filters by protocol and health", async () => {
    const { user, api } = await openMap();
    await screen.findByRole("region", { name: "Network map" });
    await user.selectOptions(screen.getByLabelText("Protocol"), "UDP");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ protocol: "UDP" })));
    await user.selectOptions(screen.getByLabelText("Health"), "suspicious");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ protocol: "UDP", health: "suspicious" })));
  });

  it("selects the local host, including all of them", async () => {
    const { user, api } = await openMap();
    const select = await screen.findByLabelText("Local host");
    expect(select).toHaveValue("192.168.1.10");
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["192.168.1.10 (5)", "192.168.1.20 (2)", "All local hosts"]);
    await user.selectOptions(select, "all");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ local: "all" })));
  });

  it("limits the time range along the capture", async () => {
    const { api } = await openMap();
    await screen.findByRole("region", { name: "Network map" });
    expect(api.getNetworkMap.mock.calls[0][1]).toEqual(expect.objectContaining({ start: undefined, end: undefined }));    // full range: no limit
    fireEvent.change(screen.getByLabelText("Time range start"), { target: { value: "250" } });
    fireEvent.change(screen.getByLabelText("Time range end"), { target: { value: "750" } });
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ start: T + 25, end: T + 75 })));
    expect(screen.getByLabelText("Time range start")).toHaveValue("250");
    expect(screen.getByText(/2023-11-14 22:13:45 UTC → 2023-11-14 22:14:35 UTC/)).toBeInTheDocument();
  });

  it("keeps the start of the range at or before its end", async () => {
    await openMap();
    await screen.findByRole("region", { name: "Network map" });
    fireEvent.change(screen.getByLabelText("Time range end"), { target: { value: "300" } });
    fireEvent.change(screen.getByLabelText("Time range start"), { target: { value: "900" } });
    expect(screen.getByLabelText("Time range start")).toHaveValue("300");
  });

  it("controls the node budget and the applications option", async () => {
    const { user, api } = await openMap();
    await screen.findByRole("region", { name: "Network map" });
    await user.selectOptions(screen.getByLabelText("Node budget"), "30");
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ maxNodes: 30 })));
    expect(api.getNetworkMap.mock.calls[0][1]).toEqual(expect.objectContaining({ includeApplications: false }));
    await user.click(screen.getByLabelText("Show applications"));
    await waitFor(() => expect(lastQuery(api)).toEqual(expect.objectContaining({ includeApplications: true, maxNodes: 30 })));
  });

  it("explains why applications are unavailable instead of inventing them", async () => {
    const getNetworkMap = vi.fn().mockImplementation((_id, q) => Promise.resolve(makeNetworkMap(q.includeApplications ? { applications_status: "Process information unavailable: no local process snapshot has been taken." } : {})));
    const { user } = await openMap({ getNetworkMap });
    await screen.findByRole("region", { name: "Network map" });
    await user.click(screen.getByLabelText("Show applications"));
    expect(await screen.findByText("Process information unavailable: no local process snapshot has been taken.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Application / })).not.toBeInTheDocument();
  });

  it("shows an empty state when nothing matches and clears the filters", async () => {
    const getNetworkMap = vi.fn().mockImplementation((_id, q) => Promise.resolve(q.search ? makeNetworkMap({ nodes: [], edges: [], connections: [], findings: [], shown_connections: 0 }) : makeNetworkMap()));
    const { user } = await openMap({ getNetworkMap });
    await screen.findByRole("region", { name: "Network map" });
    await user.type(screen.getByLabelText("Search the map"), "zzz");
    expect(await screen.findByText("No connections match these filters")).toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
    expect(await screen.findByRole("region", { name: "Network map" })).toBeInTheDocument();
    expect(screen.getByLabelText("Search the map")).toHaveValue("");
  });

  it("says plainly when a capture has nothing to draw", async () => {
    await openMap({ getNetworkMap: vi.fn().mockResolvedValue(makeNetworkMap({ nodes: [], edges: [], connections: [], findings: [], total_connections: 0, shown_connections: 0 })) });
    expect(await screen.findByText("No connections to show")).toBeInTheDocument();
    expect(screen.getByText(/no TCP or UDP connections with detail to draw/)).toBeInTheDocument();
  });

  it("drops the selection when its node is filtered away", async () => {
    const getNetworkMap = vi.fn().mockImplementation((_id, q) => {
      const m = makeNetworkMap();
      return Promise.resolve(q.protocol === "UDP" ? { ...m, nodes: m.nodes.filter((n) => n.id !== "domain:github.com"), edges: m.edges.filter((e) => !e.id.includes("github")) } : m);
    });
    const { user } = await openMap({ getNetworkMap });
    fireEvent.click(await node(/Domain github\.com/));
    expect(panel()).toHaveTextContent("github.com");
    await user.selectOptions(screen.getByLabelText("Protocol"), "UDP");
    await waitFor(() => expect(panel()).toHaveTextContent("Click a node to see its details"));
  });
});

describe("Network Map: loading, errors and edge cases", () => {
  it("shows a loading state and then the map", async () => {
    let resolve!: (m: NetworkMapData) => void;
    await openMap({ getNetworkMap: vi.fn().mockReturnValue(new Promise<NetworkMapData>((r) => { resolve = r; })) });
    expect(await screen.findByText("Building the network map…")).toBeInTheDocument();
    resolve(makeNetworkMap());
    expect(await screen.findByRole("region", { name: "Network map" })).toBeInTheDocument();
  });

  it("shows an error with Retry", async () => {
    const getNetworkMap = vi.fn().mockRejectedValueOnce(apiError("server_error", "map backend hiccup")).mockResolvedValue(makeNetworkMap());
    const { user } = await openMap({ getNetworkMap });
    expect(await screen.findByText("Network map unavailable")).toBeInTheDocument();
    expect(screen.getByText("map backend hiccup")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("region", { name: "Network map" })).toBeInTheDocument();
  });

  it("keeps the current map visible when a refresh fails", async () => {
    const getNetworkMap = vi.fn().mockImplementation((_id, q) => q.protocol ? Promise.reject(apiError("server_error", "refresh failed")) : Promise.resolve(makeNetworkMap()));
    const { user } = await openMap({ getNetworkMap });
    await screen.findByRole("region", { name: "Network map" });
    await user.selectOptions(screen.getByLabelText("Protocol"), "TCP");
    expect(await screen.findByText("Could not refresh the map")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Network map" })).toBeInTheDocument();
  });

  it("handles a capture with no packets without asking the backend", async () => {
    const { api } = await openMap({}, makeBundle({ analysis: emptyAnalysis(), findings: [] }));
    expect(await screen.findByText("This capture contains no packets")).toBeInTheDocument();
    expect(api.getNetworkMap).not.toHaveBeenCalled();
  });

  it("copes with a map that has only the local host and a long list of hosts", async () => {
    const m = makeNetworkMap({ nodes: [mapNode("local", "local", "192.168.1.10", 0, { state: "unknown" })], edges: [], connections: [], findings: [], total_connections: 0, shown_connections: 0 });
    await openMap({ getNetworkMap: vi.fn().mockResolvedValue(m) });
    expect(await screen.findByRole("button", { name: /This computer 192\.168\.1\.10/ })).toBeInTheDocument();
  });

  it("is reachable from the sidebar and titles the window", async () => {
    await openMap();
    await screen.findByRole("region", { name: "Network map" });
    expect(screen.getByRole("heading", { name: "Network Map" })).toBeInTheDocument();
    expect(document.title).toBe("Network Map · PacketMind");
  });
});

describe("Network Map: folded ports", () => {
  it("describes a folded-ports node as ports, not destinations", async () => {
    const m = makeNetworkMap();
    m.nodes.push(mapNode("ports:140.82.112.3", "other", "+111 more ports", 4, { ip: "140.82.112.3", members: 111, connections: 111, state: "suspicious", connection_ids: ["c1"] }));
    m.edges.push(mapEdge("ip:140.82.112.3", "ports:140.82.112.3", { connections: 111 }));
    await openMap({ getNetworkMap: vi.fn().mockResolvedValue(m) });
    const folded = await node(/More ports \+111 more ports/);
    expect(folded).toHaveTextContent("More ports");
    fireEvent.click(folded);
    expect(panel()).toHaveTextContent("Folded in111 ports");
    expect(panel()).toHaveTextContent("Less-used ports of this address are folded into this node");
    expect(panel()).not.toHaveTextContent("Lower-traffic destinations");
  });
});

describe("Network Map: real-browser behaviour that jsdom cannot see", () => {
  it("nodes accept pointer events (otherwise real mouse clicks fall through to the background and clear the selection)", async () => {
    await openMap();
    await screen.findByRole("region", { name: "Network map" });
    const nodes = [...document.querySelectorAll<HTMLElement>(".react-flow__node")];
    expect(nodes.length).toBeGreaterThan(0);
    for (const n of nodes) expect(n.style.pointerEvents).toBe("all");
  });

  it("clicking a node's own wrapper (not only its inner button) selects it", async () => {
    await openMap();
    await screen.findByRole("region", { name: "Network map" });
    const wrapper = document.querySelector<HTMLElement>('.react-flow__node[data-id="domain:github.com"]')!;
    fireEvent.click(wrapper);
    expect(panel()).toHaveTextContent("github.com");
  });
});
