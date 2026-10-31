// End-to-end: the real API client against a RUNNING backend (cd backend && .venv/bin/python main.py).
// Run with: npm run test:e2e
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { api, ApiError } from "../api/client";
import type { AnalysisBundle, JobStatus } from "../api/types";

const FIXTURES = resolve(__dirname, "../../../backend/tests/fixtures");
const pcap = (name: string) => new File([readFileSync(resolve(FIXTURES, name))], name);

async function analyze(file: File): Promise<{ bundle: AnalysisBundle; polls: JobStatus[] }> {
  let job = await api.submitCapture(file);
  const polls = [job];
  for (let i = 0; i < 200 && job.status !== "completed" && job.status !== "failed"; i++) {
    await new Promise((r) => setTimeout(r, 50));
    job = await api.getStatus(job.id);
    polls.push(job);
  }
  expect(job.status).toBe("completed");
  return { bundle: await api.getResult(job.id), polls };
}

describe("frontend client <-> real backend", () => {
  it("backend is reachable", async () => {
    const h = await api.fetchHealth();
    expect(h.status).toBe("ok");
    expect(h.max_upload_bytes).toBeGreaterThan(0);
  });

  it("analyzes the attack demo capture and returns findings", async () => {
    const { bundle } = await analyze(pcap("attack_demo.pcap"));
    expect(bundle.analysis.packet_statistics.total_packets).toBeGreaterThan(1000);
    expect(bundle.analysis.metadata.capture_format).toBe("pcap");
    const types = bundle.findings.map((f) => f.type);
    expect(types).toEqual(expect.arrayContaining(["PORT_SCAN", "SYN_FLOOD", "ARP_SPOOFING", "DNS_DGA_LIKE"]));
    const scan = bundle.findings.find((f) => f.type === "PORT_SCAN")!;
    expect(scan.source_ip).toBe("10.0.0.99");
    expect(scan.confidence).toBeLessThanOrEqual(0.95);
    expect(scan.description.toLowerCase()).toContain("possible");
    expect(Object.keys(scan.evidence)).toEqual(expect.arrayContaining(["unique_ports", "syn_packets"]));
    expect(bundle.analysis.timeline.length).toBeGreaterThan(0);
    expect(bundle.analysis.protocol_statistics.distribution[0].protocol).toBe("TCP");
  });

  it("analyzes the clean sample capture with no findings", async () => {
    const { bundle } = await analyze(pcap("sample.pcap"));
    expect(bundle.analysis.packet_statistics.total_packets).toBe(30);
    expect(bundle.findings).toEqual([]);
  });

  it("rejects an invalid PCAP file with a typed error", async () => {
    const err = await api.submitCapture(new File(["definitely not a capture"], "notes.pcap")).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ kind: "invalid_capture", status: 400 });
  });

  it("rejects an empty file", async () => {
    await expect(api.submitCapture(new File([], "empty.pcap"))).rejects.toMatchObject({ kind: "empty_file" });
  });

  it("handles an empty capture (valid header, zero packets)", async () => {
    const header = Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex");
    const { bundle } = await analyze(new File([header], "zero.pcap"));
    expect(bundle.analysis.packet_statistics.total_packets).toBe(0);
    expect(bundle.analysis.metadata.warnings.join(" ")).toContain("no packets");
  });

  it("reports unknown ids as not_found", async () => {
    await expect(api.getStatus("nope")).rejects.toMatchObject({ kind: "not_found" });
  });
});
