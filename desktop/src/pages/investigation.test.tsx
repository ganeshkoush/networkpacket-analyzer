import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { makeInvestigation } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";

async function analyzed(api: MockApi, route = "/analysis") {
  const user = userEvent.setup();
  renderApp(api, route);
  await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
  await screen.findByText(/packets ·/);
  return user;
}

describe("Investigate Network", () => {
  it("offers a one-click button and shows the health banner, problems, evidence, explanations, steps, confidence and limits", async () => {
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(makeInvestigation()) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByTestId("health")).toHaveTextContent("DEGRADED");
    expect(api.investigateNetwork).toHaveBeenCalledWith("job1", { useAi: true }, expect.anything());
    expect(screen.getByText(/Elevated packet retransmissions are affecting network latency/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Top problems" })).toBeInTheDocument();
    const ev = screen.getByRole("heading", { name: "Evidence" }).closest("section")!;
    expect(within(ev).getByText(/Retransmission rate: Normal 0\.8% · Current 6\.2%/)).toBeInTheDocument();
    expect(within(ev).getByText(/Average RTT: Normal 38 ms · Current 102 ms/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Potential explanations" }).closest("section")).toHaveTextContent(/not confirmed causes/);
    expect(screen.getByText("Compare latency to multiple independent services.")).toBeInTheDocument();
    expect(screen.getByText(/never runs, changes or blocks anything/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Limitations" })).toBeInTheDocument();
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.getByText(/never the capture/)).toBeInTheDocument();
  });

  it("shows the local measurements grouped by area with normal, current, change and status", async () => {
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(makeInvestigation()) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    const local = (await screen.findByRole("heading", { name: "Local measurements" })).closest("section")!;
    expect(within(local).getByRole("heading", { name: "Retransmissions" })).toBeInTheDocument();
    expect(within(local).getByRole("heading", { name: "DNS latency" })).toBeInTheDocument();
    const row = within(local).getByRole("row", { name: /Average RTT/ });
    expect(row).toHaveTextContent("38 ms");
    expect(row).toHaveTextContent("102 ms");
    expect(row).toHaveTextContent("+168%");
    expect(row).toHaveTextContent("Elevated");
  });

  it("shows a loading state while it works, then the result stays when navigating away and back", async () => {
    let resolve!: (v: ReturnType<typeof makeInvestigation>) => void;
    const api = mockApi({ investigateNetwork: vi.fn().mockReturnValue(new Promise((r) => { resolve = r; })) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByText(/asking Gemini/)).toBeInTheDocument();
    resolve(makeInvestigation());
    await screen.findByTestId("health");
    await user.click(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: /Dashboard/ }));
    await user.click(await screen.findByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByTestId("health")).toBeInTheDocument();
  });

  it("explains an unavailable AI and still shows the local rating", async () => {
    const inv = makeInvestigation({ status: "local_only", report: null, evidence: [], confidence: "Low",
      ai: { requested: true, provider: null, model: null, error_code: "missing_api_key", error_message: "Set GEMINI_API_KEY to enable AI analysis." } });
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(inv) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByTestId("health")).toHaveTextContent("DEGRADED");
    expect(screen.getByText(/Set GEMINI_API_KEY/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Top problems" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Local measurements" })).toBeInTheDocument();
  });

  it("keeps the local result when the AI answer was rejected", async () => {
    const inv = makeInvestigation({ status: "ai_failed", report: null, ai: { requested: true, provider: "Google Gemini", model: "m", error_code: "invalid_output", error_message: "The AI answer failed PacketMind's safety checks." } });
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(inv) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByText(/safety checks/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Local measurements" })).toBeInTheDocument();
  });

  it("colours Poor and Unknown differently and never calls an unmeasurable capture healthy", async () => {
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(makeInvestigation({ health: "Unknown", status: "local_only", report: null, confidence: "Low" })) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByTestId("health")).toHaveTextContent("UNKNOWN");
    expect(screen.queryByText("HEALTHY")).not.toBeInTheDocument();
  });

  it("offers a retry when the request fails", async () => {
    const investigateNetwork = vi.fn().mockRejectedValueOnce(apiError("backend_unavailable", "Cannot reach the PacketMind backend.")).mockResolvedValue(makeInvestigation());
    const user = await analyzed(mockApi({ investigateNetwork }));
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the PacketMind backend.");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.getByTestId("health")).toBeInTheDocument());
    expect(investigateNetwork).toHaveBeenCalledTimes(2);
  });

  it("runs again on request, and asks to analyze a capture first when there is none", async () => {
    const api = mockApi({ investigateNetwork: vi.fn().mockResolvedValue(makeInvestigation()) });
    const user = await analyzed(api);
    await user.click(screen.getByRole("button", { name: /Investigate Network/ }));
    await screen.findByTestId("health");
    await user.click(screen.getByRole("button", { name: "Run again" }));
    await waitFor(() => expect(api.investigateNetwork).toHaveBeenCalledTimes(2));
  });

  it("without a capture there is nothing to investigate", () => {
    renderApp(mockApi(), "/investigation");
    expect(screen.getByText("No capture analyzed yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Investigate Network/ })).not.toBeInTheDocument();
  });
});
