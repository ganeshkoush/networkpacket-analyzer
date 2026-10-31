import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { makeAnalysis } from "../../test/fixtures";
import { DomainsTab, filterAndSortDomains } from "./DomainsTab";

const stats = makeAnalysis().domain_statistics!;
const names = (rows: { domain: string }[]) => rows.map((r) => r.domain);

describe("filterAndSortDomains", () => {
  it("sorts by traffic, connections, latest activity and name", () => {
    expect(names(filterAndSortDomains(stats.domains, "", "traffic"))[0]).toBe("github.com");
    expect(names(filterAndSortDomains(stats.domains, "", "connections"))[0]).toBe("cdn.example.net");
    expect(names(filterAndSortDomains(stats.domains, "", "recent"))[0]).toBe("cdn.example.net");
    expect(names(filterAndSortDomains(stats.domains, "", "name"))[0]).toBe("cdn.example.net");
  });
  it("searches case-insensitively", () => {
    expect(names(filterAndSortDomains(stats.domains, "  GITHUB", "traffic"))).toEqual(["github.com"]);
  });
});

describe("DomainsTab", () => {
  it("shows columns, the HTTPS caveat and no URL claims", () => {
    render(<DomainsTab stats={stats} />);
    for (const h of ["Domain", "Connections", "Data sent", "Data received", "First seen", "Last seen"]) {
      expect(screen.getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    expect(screen.getByText(/HTTPS URLs, paths and page content are encrypted/)).toBeInTheDocument();
    expect(screen.getByText("3.6 MB")).toBeInTheDocument();
  });

  it("filters via the search box, reports no matches, and expands details", async () => {
    const user = userEvent.setup();
    render(<DomainsTab stats={stats} />);
    await user.type(screen.getByLabelText("Search domains"), "nothing-here");
    expect(screen.getByText(/No domain matches/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Search domains"));
    await user.type(screen.getByLabelText("Search domains"), "cdn");
    const row = screen.getByRole("row", { name: /cdn\.example\.net/ });
    await user.click(row);
    expect(within(row).getByText(/also resolved for other domains/)).toBeInTheDocument();
  });

  it("explains when nothing could be identified", () => {
    render(<DomainsTab stats={{ domains: [], summary: { ...stats.summary, total_domains: 0, notes: ["base", "No DNS queries were captured, so connections cannot be mapped to domains."] } }} />);
    expect(screen.getByText(/No domains could be identified/)).toBeInTheDocument();
    expect(screen.getByText(/No DNS queries were captured/)).toBeInTheDocument();
  });

  it("handles results from before this feature", () => {
    render(<DomainsTab stats={undefined} />);
    expect(screen.getByText(/No domains could be identified/)).toBeInTheDocument();
  });
});
