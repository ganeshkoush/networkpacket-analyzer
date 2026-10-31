import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ReportListItem, SavedReport } from "../api/types";
import { makeFinding } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp } from "../test/render";

const ITEM: ReportListItem = {
  id: "a".repeat(32), title: "Case alpha", created_at: "2026-10-06T10:00:00+00:00", source_kind: "pcap",
  capture_name: "demo.pcap", highest_severity: "HIGH", finding_count: 2, total_packets: 1200, ai_status: "completed",
};
const AI = {
  investigation_summary: "The traffic is consistent with possible TCP SYN scanning.", finding_type: "PORT_SCAN", severity: "HIGH" as const,
  confidence: 0.9, evidence: ["119 SYN packets were observed."], interpretation: "Consistent with scanning.",
  possible_explanations: ["Security scanning"], recommended_next_steps: ["Confirm the scan was authorized."],
  additional_evidence_needed: ["Host logs"], limitations: ["A PCAP cannot establish intent."],
};
function saved(over: Partial<SavedReport["content"]> = {}): SavedReport {
  const f = makeFinding();
  return { id: ITEM.id, content: {
    schema_version: 1, title: "Case alpha", investigation_timestamp: "2026-10-06T10:00:00+00:00", app_version: "0.1.0",
    capture: { source_kind: "pcap", name: "demo.pcap", capture_format: "pcap", size_bytes: 150000, sha256: "ab".repeat(32), packets: 1200, duration_seconds: 30, first_packet_time_iso: "2023-11-14 22:13:20 UTC", last_packet_time_iso: "2023-11-14 22:13:50 UTC", interface: null, warnings: [] },
    summary: { total_packets: 1200, total_bytes: 150000, duration_seconds: 30, avg_packets_per_second: 40, peak_packets_per_second: 300, unique_source_ips: 4, unique_destination_ips: 5, finding_count: 1, severity_counts: { HIGH: 1 }, highest_severity: "HIGH", headline: "Analysis of 1,200 packets produced 1 possible finding(s)." },
    protocols: [{ protocol: "TCP", packets: 900, bytes: 100000, percent_of_packets: 75 }],
    top_talkers: [{ ip: "10.0.0.99", is_private: true, packets_sent: 5, packets_received: 5, bytes_sent: 1, bytes_received: 1, total_packets: 900, total_bytes: 5000 }],
    top_ports: [],
    findings: [{ id: f.id, type: f.type, severity: f.severity, confidence: f.confidence, title: f.title, description: f.description, source_ip: f.source_ip, destination_ip: f.destination_ip, evidence: f.evidence, investigation_steps: f.reasoning, caveats: f.caveats, recommendation: f.recommendation, first_seen_iso: null, last_seen_iso: null, ai_assessment: null }],
    ai_investigation: { status: "completed", provider: "gemini", model: "gemini-x", result: AI, notes: [], message: null },
    recommended_actions: [{ action: "Confirm the scan was authorized.", priority: "HIGH", source: "ai", related_finding: null }],
    limitations: ["Findings are possibilities, not confirmed incidents."], analyst_notes: "Seen on VLAN 5", ...over } };
}

describe("Reports list", () => {
  it("shows an empty state", async () => {
    renderApp(mockApi(), "/reports");
    expect(await screen.findByText("No saved investigations yet")).toBeInTheDocument();
  });

  it("lists saved reports with severity, findings and AI status", async () => {
    renderApp(mockApi({ listReports: vi.fn().mockResolvedValue([ITEM, { ...ITEM, id: "b".repeat(32), title: "Live one", source_kind: "live", highest_severity: null, finding_count: 0, ai_status: "not_run" }]) }), "/reports");
    const list = await screen.findByLabelText("Saved reports");
    expect(within(list).getByRole("link", { name: "Case alpha" })).toHaveAttribute("href", `/reports/${ITEM.id}`);
    expect(list).toHaveTextContent("2 findings");
    expect(list).toHaveTextContent("AI summary included");
    expect(list).toHaveTextContent("No findings");
    expect(list).toHaveTextContent("Live capture");
  });

  it("deletes only after confirmation, and cancel keeps the report", async () => {
    const listReports = vi.fn().mockResolvedValueOnce([ITEM]).mockResolvedValue([]);
    const api = mockApi({ listReports });
    const user = userEvent.setup();
    renderApp(api, "/reports");
    await user.click(await screen.findByRole("button", { name: "Delete Case alpha" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("permanently removed");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(api.deleteReport).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete Case alpha" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete report" }));
    await waitFor(() => expect(api.deleteReport).toHaveBeenCalledWith(ITEM.id));
    expect(await screen.findByText("No saved investigations yet")).toBeInTheDocument();
    expect(screen.getByText(/Deleted “Case alpha”/)).toBeInTheDocument();
  });

  it("shows an error with retry when the backend fails", async () => {
    renderApp(mockApi({ listReports: vi.fn().mockRejectedValue(apiError("backend_unavailable", "Cannot reach backend")) }), "/reports");
    expect(await screen.findByText("Cannot reach backend")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("Report detail", () => {
  it("renders every report section, evidence, AI summary and recommendations", async () => {
    renderApp(mockApi({ getReport: vi.fn().mockResolvedValue(saved()) }), `/reports/${ITEM.id}`);
    expect(await screen.findByRole("heading", { name: "Case alpha" })).toBeInTheDocument();
    for (const h of ["1. Capture information", "2. Analysis summary", "3. Protocol statistics", "4. Top talkers", "5. Findings",
      "6. AI investigation summary", "7. Recommended actions", "8. Limitations", "9. Investigation timestamp"]) {
      expect(screen.getByText(h)).toBeInTheDocument();
    }
    expect(screen.getByText(/Seen on VLAN 5/)).toBeInTheDocument();
    expect(screen.getByLabelText("Report findings")).toHaveTextContent("Possible TCP port scan from 10.0.0.99");
    expect(screen.getByLabelText("Report findings")).toHaveTextContent("Investigation steps");
    expect(screen.getByText(/consistent with possible TCP SYN scanning/)).toBeInTheDocument();
    expect(screen.getAllByText("Confirm the scan was authorized.").length).toBeGreaterThan(0);
    expect(screen.getByText("2026-10-06 10:00:00 UTC", { selector: "p.font-mono" })).toBeInTheDocument();
  });

  it("explains a missing AI summary", async () => {
    const r = saved({ ai_investigation: { status: "failed", provider: null, model: null, result: null, notes: [], message: "AI investigation unavailable: GEMINI_API_KEY is not set." } });
    renderApp(mockApi({ getReport: vi.fn().mockResolvedValue(r) }), `/reports/${ITEM.id}`);
    expect(await screen.findByText(/GEMINI_API_KEY is not set/)).toBeInTheDocument();
  });

  it("exports and reports where the file was written", async () => {
    const api = mockApi({ getReport: vi.fn().mockResolvedValue(saved()), exportReport: vi.fn().mockResolvedValue({ path: "/tmp/reports/x.md", filename: "x.md", format: "md" }) });
    const user = userEvent.setup();
    renderApp(api, `/reports/${ITEM.id}`);
    await user.click(await screen.findByRole("button", { name: "Export Markdown" }));
    expect(api.exportReport).toHaveBeenCalledWith(ITEM.id, "md");
    expect(await screen.findByText("/tmp/reports/x.md")).toBeInTheDocument();
  });

  it("deletes with confirmation and returns to the list", async () => {
    const api = mockApi({ getReport: vi.fn().mockResolvedValue(saved()) });
    const user = userEvent.setup();
    renderApp(api, `/reports/${ITEM.id}`);
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    expect(api.deleteReport).not.toHaveBeenCalled();
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete report" }));
    await waitFor(() => expect(api.deleteReport).toHaveBeenCalledWith(ITEM.id));
    expect(await screen.findByText("No saved investigations yet")).toBeInTheDocument();
  });

  it("handles an unknown report", async () => {
    renderApp(mockApi({ getReport: vi.fn().mockRejectedValue(Object.assign(apiError("not_found", "nope"), { status: 404 })) }), `/reports/${"c".repeat(32)}`);
    expect(await screen.findByText("Report not found")).toBeInTheDocument();
  });
});

describe("Save investigation", () => {
  async function ready(api = mockApi()) {
    const user = userEvent.setup();
    renderApp(api, "/analysis");
    await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
    await screen.findByText(/packets ·/);
    await user.click(screen.getByRole("button", { name: "Save investigation" }));
    return { user, api };
  }

  it("saves without AI by default and links to the report", async () => {
    const api = mockApi({ createReport: vi.fn().mockResolvedValue(saved()) });
    const { user } = await ready(api);
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(api.createReport).toHaveBeenCalledWith(expect.objectContaining({ source: "analysis", analysis_id: expect.any(String), run_ai: false, title: expect.stringContaining("demo.pcap") }));
    expect(await screen.findByRole("link", { name: "View report" })).toHaveAttribute("href", `/reports/${ITEM.id}`);
  });

  it("requests the AI summary only when ticked, and surfaces AI failure", async () => {
    const failed = saved({ ai_investigation: { status: "failed", provider: null, model: null, result: null, notes: [], message: "AI investigation unavailable: key rejected" } });
    const api = mockApi({ createReport: vi.fn().mockResolvedValue(failed) });
    const { user } = await ready(api);
    await user.click(screen.getByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(api.createReport).toHaveBeenCalledWith(expect.objectContaining({ run_ai: true }));
    expect(await screen.findByText(/key rejected/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View report" })).toBeInTheDocument();
  });

  it("shows save errors and lets the user retry", async () => {
    const api = mockApi({ createReport: vi.fn().mockRejectedValue(apiError("server_error", "Disk full")) });
    const { user } = await ready(api);
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Disk full")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });
});
