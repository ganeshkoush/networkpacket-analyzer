import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { makeAnalysis } from "../../test/fixtures";
import { PerformanceTab, filterAndSortDomains } from "./PerformanceTab";

const a = makeAnalysis();
const stats = a.performance_statistics!;
const names = (rows: { domain: string }[]) => rows.map((r) => r.domain);
const renderTab = (s = stats) => render(<PerformanceTab stats={s} connections={a.connections} />);

describe("filterAndSortDomains", () => {
  it("puts the slowest first and domains without the measurement last", () => {
    expect(names(filterAndSortDomains(stats.domains, "", "rtt"))).toEqual(["slow.example.net", "github.com", "plain.example.org"]);
    expect(names(filterAndSortDomains(stats.domains, "", "response"))).toEqual(["plain.example.org", "github.com", "slow.example.net"]);
    expect(names(filterAndSortDomains(stats.domains, "", "handshake"))[0]).toBe("slow.example.net");
    expect(names(filterAndSortDomains(stats.domains, "", "connections"))[0]).toBe("github.com");
    expect(names(filterAndSortDomains(stats.domains, "", "name"))[0]).toBe("github.com");
  });
  it("searches case-insensitively", () => {
    expect(names(filterAndSortDomains(stats.domains, " GITHUB", "rtt"))).toEqual(["github.com"]);
  });
});

describe("PerformanceTab", () => {
  it("shows the domain columns and the handshake-is-not-response-time notice", () => {
    renderTab();
    const table = screen.getByRole("table", { name: "Performance by domain" });
    for (const h of ["Domain", "DNS", "TCP Handshake", "Avg RTT", "P95 RTT", "Response Time"]) {
      expect(within(table).getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    expect(screen.getByText(/not website or application response time/)).toBeInTheDocument();
    const row = within(table).getByRole("row", { name: /github\.com/ });
    const cells = within(row).getAllByRole("cell").map((c) => c.textContent);
    expect(cells.slice(0, 5)).toEqual(["github.com", "19 ms", "42 ms", "36 ms", "71 ms"]);
  });

  it("never fills Response Time from the handshake: HTTPS says not visible, unmeasured is a dash", () => {
    renderTab();
    const table = screen.getByRole("table", { name: "Performance by domain" });
    const cell = (name: RegExp) => within(within(table).getByRole("row", { name })).getAllByRole("cell")[5];
    expect(cell(/github\.com/)).toHaveTextContent("not visible (HTTPS)");
    expect(cell(/github\.com/)).not.toHaveTextContent("42");
    expect(cell(/plain\.example\.org/)).toHaveTextContent("80 ms");
    expect(cell(/slow\.example\.net/)).toHaveTextContent("–");
  });

  it("shows a dash instead of a number when there is no RTT", () => {
    renderTab();
    const row = within(screen.getByRole("table", { name: "Performance by domain" })).getByRole("row", { name: /plain\.example\.org/ });
    const cells = within(row).getAllByRole("cell");
    expect(cells[3]).toHaveTextContent("–");
    expect(cells[4]).toHaveTextContent("–");
    expect(cells[6]).toHaveTextContent(/unavailable/i);
  });

  it("sorts and searches through the controls", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.selectOptions(screen.getByLabelText("Sort performance"), "rtt");
    const first = () => within(screen.getByRole("table", { name: "Performance by domain" })).getAllByRole("row")[1];
    expect(first()).toHaveTextContent("slow.example.net");
    await user.type(screen.getByLabelText("Search performance domains"), "zzz");
    expect(screen.getByText(/No domain matches/)).toBeInTheDocument();
  });

  it("opens the per-connection measurements with the encryption caveat", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(within(screen.getByRole("table", { name: "Connection performance" })).getByRole("row", { name: /github\.com/ }));
    const d = screen.getByLabelText("Connection measurements");
    expect(within(d).getByText("RTT samples").nextSibling).toHaveTextContent("40");
    expect(within(d).getByText("RTT min / avg / median").nextSibling).toHaveTextContent("30 ms / 36 ms / 35 ms");
    expect(within(d).getByText("TCP handshake (set-up time)").nextSibling).toHaveTextContent("42 ms");
    expect(within(d).getByText("TLS ClientHello → ServerHello").nextSibling).toHaveTextContent("65 ms");
    expect(within(d).getByText("Response time").nextSibling).toHaveTextContent("not visible (HTTPS)");
    expect(screen.getByText(/HTTP request\/response timing is not visible/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Connection measurements")).not.toBeInTheDocument();
  });

  it("labels unmeasurable values and a cleartext HTTP response", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(within(screen.getByRole("table", { name: "Connection performance" })).getByRole("row", { name: /TCP · HTTP/ }));
    const d = screen.getByLabelText("Connection measurements");
    expect(within(d).getByText("HTTP response time").nextSibling).toHaveTextContent("80 ms");
    expect(within(d).getByText("RTT min / avg / median").nextSibling).toHaveTextContent("–");
    expect(within(d).getByText("TCP handshake (set-up time)").nextSibling).toHaveTextContent("–");
  });

  it("explains a DNS flow without TCP rows", async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(within(screen.getByRole("table", { name: "Connection performance" })).getByRole("row", { name: /UDP · DNS/ }));
    const d = screen.getByLabelText("Connection measurements");
    expect(within(d).getByText(/DNS lookup/).nextSibling).toHaveTextContent("21 ms");
    expect(within(d).queryByText("RTT samples")).not.toBeInTheDocument();
  });

  it("copes with results from before latency analysis", () => {
    render(<PerformanceTab stats={undefined} connections={[]} />);
    expect(screen.getByText(/No latency measurements/)).toBeInTheDocument();
  });
});
