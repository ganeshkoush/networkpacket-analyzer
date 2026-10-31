import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { makeAnalysis } from "../../test/fixtures";
import { ConnectionsTab, NO_FILTERS, filterConnections, stateOf } from "./ConnectionsTab";

const a = makeAnalysis();
const render_ = (connections = a.connections) => render(<ConnectionsTab connections={connections} summary={a.connection_summary} />);
const ids = (rows: { id?: string }[]) => rows.map((r) => r.id);

describe("filterConnections", () => {
  it("filters by domain, IPs, protocol, port (either side) and state", () => {
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, domain: "CDN" }))).toEqual(["aaaaaaaaaaaa"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, src: "2001:db8" }))).toEqual(["bbbbbbbbbbbb"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, dst: "203.0.113" }))).toEqual(["cccccccccccc"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, protocol: "UDP" }))).toEqual(["bbbbbbbbbbbb"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, port: "50000" }))).toEqual(["aaaaaaaaaaaa"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, port: "53" }))).toEqual(["bbbbbbbbbbbb"]);
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, state: "SYN_SENT" }))).toEqual(["cccccccccccc"]);
    expect(filterConnections(a.connections, { ...NO_FILTERS, domain: "nothing" })).toEqual([]);
  });
  it("combines filters and ignores a blank or invalid port", () => {
    expect(ids(filterConnections(a.connections, { ...NO_FILTERS, protocol: "TCP", port: "443" }))).toEqual(["aaaaaaaaaaaa"]);
    expect(filterConnections(a.connections, { ...NO_FILTERS, port: "abc" })).toHaveLength(3);
  });
});

describe("stateOf", () => {
  it("is null for non-TCP and falls back for results without a state", () => {
    expect(stateOf(a.connections[1])).toBeNull();
    const old = { ...a.connections[0], state: undefined };
    expect(stateOf({ ...old, rst_seen: true })).toBe("RESET");
    expect(stateOf({ ...old, rst_seen: false, handshake_complete: true })).toBe("ESTABLISHED");
  });
});

describe("ConnectionsTab", () => {
  it("shows the required columns and falls back to the destination IP when there is no domain", () => {
    render_();
    for (const h of ["Domain / Destination", "Source", "Destination", "Protocol", "Port", "Duration", "Bytes", "Packets", "State"]) {
      expect(screen.getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    const row = screen.getByRole("row", { name: /203\.0\.113\.9/ });
    expect(within(row).getAllByText("203.0.113.9").length).toBeGreaterThan(0); // destination shown without a domain
    expect(within(row).getByText("SYN sent")).toBeInTheDocument();
    expect(screen.getByText("[2001:db8::10]:41000")).toBeInTheDocument(); // IPv6 endpoints are bracketed
  });

  it("filters through the inputs and reports no matches", async () => {
    const user = userEvent.setup();
    render_();
    await user.selectOptions(screen.getByLabelText("Filter by protocol"), "UDP");
    expect(screen.queryByText("93.184.216.34:443")).not.toBeInTheDocument();
    expect(screen.getByText("[2001:db8::10]:41000")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Filter by domain"), "zzz");
    expect(screen.getByText("No connection matches these filters.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.getByText("93.184.216.34:443")).toBeInTheDocument();
  });

  it("opens and closes a detailed view when a connection is clicked", async () => {
    const user = userEvent.setup();
    render_();
    await user.click(screen.getByRole("row", { name: /cdn\.example\.net/ }));
    const detail = screen.getByLabelText("Connection detail");
    expect(within(detail).getByText(/cdn\.example\.net \(inferred from DNS\)/)).toBeInTheDocument();
    expect(within(detail).getByText(/2 \(heuristic indicator\)/)).toBeInTheDocument();
    expect(within(detail).getByText(/1,?711 ms|1\.71 s/)).toBeInTheDocument();
    expect(within(detail).getByText(/FIN yes · RST no/)).toBeInTheDocument();
    expect(within(detail).getByText(/8 packets/)).toBeInTheDocument();
    expect(screen.getByText(/also resolved for other domains/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Connection detail")).not.toBeInTheDocument();
    expect(screen.queryByText(/inferred from DNS\)/)).not.toBeInTheDocument();
  });

  it("shows the TCP handshake timings and status for a completed handshake", async () => {
    const user = userEvent.setup();
    render_();
    await user.click(screen.getByRole("row", { name: /cdn\.example\.net/ }));
    const hs = screen.getByRole("region", { name: "TCP Handshake" });
    expect(within(hs).getByText("Handshake status").nextSibling).toHaveTextContent("Completed");
    expect(within(hs).getByText("SYN → SYN-ACK").nextSibling).toHaveTextContent("45 ms");
    expect(within(hs).getByText("SYN-ACK → ACK").nextSibling).toHaveTextContent("7 ms");
    expect(within(hs).getByText("Total").nextSibling).toHaveTextContent("52 ms");
    expect(within(hs).queryByText(/retransmission/)).not.toBeInTheDocument();
  });

  it("never shows invented latencies for an incomplete handshake, and explains why", async () => {
    const user = userEvent.setup();
    render_();
    await user.click(screen.getByRole("row", { name: /203\.0\.113\.9/ }));
    const hs = screen.getByRole("region", { name: "TCP Handshake" });
    expect(within(hs).getByText("Handshake status").nextSibling).toHaveTextContent("Incomplete");
    for (const k of ["SYN → SYN-ACK", "SYN-ACK → ACK", "Total"]) expect(within(hs).getByText(k).nextSibling).toHaveTextContent("–");
    expect(within(hs).getByText(/no SYN-ACK that answers it/)).toBeInTheDocument();
    expect(within(hs).getByText(/2 SYN retransmission\(s\)/)).toBeInTheDocument();
  });

  it("lists the average TCP handshake time by domain, slowest first", () => {
    render_();
    const table = screen.getByRole("table", { name: "Average TCP handshake by domain" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(rows[0]).toContain("youtube.com73 ms");
    expect(rows[1]).toContain("github.com51 ms");
    expect(rows[2]).toContain("google.com42 ms40 ms – 44 ms2");
    expect(screen.getByText(/3 completed handshakes timed · 55.3 ms average · 1 incomplete/)).toBeInTheDocument();
  });

  it("explains a UDP connection without TCP fields or a domain", async () => {
    const user = userEvent.setup();
    render_();
    await user.click(screen.getByRole("row", { name: /2606:4700:4700::1111/ }));
    expect(screen.getByText(/no preceding DNS lookup was captured/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "TCP Handshake" })).not.toBeInTheDocument();
  });

  it("copes with results from before connection tracking", () => {
    const { id: _id, state: _s, ...legacy } = a.connections[0];
    render_([legacy]);
    expect(within(screen.getByRole("table", { name: "Connections" })).getByText("Established")).toBeInTheDocument();
  });
});
