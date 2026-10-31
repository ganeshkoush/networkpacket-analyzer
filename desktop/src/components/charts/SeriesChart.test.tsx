import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { formatBytes, formatMs } from "../../lib/format";
import { SeriesChart } from "./SeriesChart";

const T = 1_700_000_000;

describe("SeriesChart", () => {
  it("draws a line chart with an accessible summary and a legend", () => {
    render(<SeriesChart title="RTT over time" kind="line" formatValue={formatMs} empty="nothing"
      series={[{ key: "a", label: "Average RTT", color: "red", points: [{ t: T, v: 40 }, { t: T + 10, v: 80 }] }]} />);
    expect(screen.getByRole("img", { name: /RTT over time: 2 measurements from 22:13:20 to 22:13:30 UTC; maximum 100 ms/ })).toBeInTheDocument();
    expect(screen.getByText("Average RTT")).toBeInTheDocument();
  });

  it("shows a single measurement as a point", () => {
    const { container } = render(<SeriesChart title="One" kind="line" formatValue={formatMs} empty="nothing"
      series={[{ key: "a", label: "A", color: "red", points: [{ t: T, v: 40 }] }]} />);
    expect(container.querySelectorAll("circle")).toHaveLength(1);
    expect(container.querySelectorAll("path")).toHaveLength(0);
  });

  it("stacks bars and sizes the axis to the stacked total", () => {
    const { container } = render(<SeriesChart title="Traffic" kind="bars" formatValue={formatBytes} binSeconds={2} empty="nothing"
      series={[{ key: "s", label: "Sent", color: "blue", points: [{ t: T, v: 600 }, { t: T + 2, v: 100 }] },
        { key: "r", label: "Received", color: "green", points: [{ t: T, v: 1400 }, { t: T + 2, v: 100 }] }]} />);
    expect(container.querySelectorAll("rect")).toHaveLength(4);
    expect(screen.getByRole("img", { name: /2 time bins/ })).toHaveAccessibleName(/maximum 2\.0 KB/);
  });

  it("offers the same data as a table, with a dash where a series has no value", async () => {
    const user = userEvent.setup();
    render(<SeriesChart title="RTT" kind="line" formatValue={formatMs} empty="nothing"
      series={[{ key: "a", label: "Average", color: "red", points: [{ t: T, v: 40 }, { t: T + 10, v: 50 }] }, { key: "b", label: "P95", color: "blue", points: [{ t: T, v: 90 }] }]} />);
    await user.click(screen.getByRole("button", { name: "View as table" }));
    const table = screen.getByRole("table", { name: "RTT" });
    const rows = within(table).getAllByRole("row").slice(1).map((r) => r.textContent);
    expect(rows).toEqual(["2023-11-14 22:13:20 UTC40 ms90 ms", "2023-11-14 22:13:30 UTC50 ms–"]);
    await user.click(screen.getByRole("button", { name: "Show chart" }));
    expect(screen.getByRole("img")).toBeInTheDocument();
  });

  it("shows the empty message instead of an empty chart", () => {
    render(<SeriesChart title="RTT" kind="line" formatValue={formatMs} empty="No measurable response-time data"
      series={[{ key: "a", label: "A", color: "red", points: [] }]} />);
    expect(screen.getByText("No measurable response-time data")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});
