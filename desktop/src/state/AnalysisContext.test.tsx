import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { apiError, mockApi, pcapFile } from "../test/render";
import { makeJob } from "../test/fixtures";
import { AnalysisProvider, useAnalysis } from "./AnalysisContext";

const setup = (api = mockApi()) => {
  const wrapper = ({ children }: { children: ReactNode }) => <AnalysisProvider api={api} pollIntervalMs={1}>{children}</AnalysisProvider>;
  return { api, ...renderHook(() => useAnalysis(), { wrapper }) };
};

describe("AnalysisProvider", () => {
  it("goes idle -> uploading -> analyzing -> ready", async () => {
    const { result, api } = setup(mockApi({ getStatus: vi.fn().mockResolvedValueOnce(makeJob({ status: "running", progress_percent: 40 })).mockResolvedValue(makeJob()) }));
    expect(result.current.session.phase).toBe("idle");
    let done: Promise<void>;
    act(() => { done = result.current.analyze(pcapFile("a.pcap")); });
    expect(result.current.session.phase).toBe("uploading");
    await act(async () => { await done; });
    expect(result.current.session.phase).toBe("ready");
    expect(api.submitCapture).toHaveBeenCalledTimes(1);
    expect(api.getResult).toHaveBeenCalledWith("job1", expect.anything());
  });

  it("surfaces an invalid capture as an error with its kind and message", async () => {
    const { result } = setup(mockApi({ submitCapture: vi.fn().mockRejectedValue(apiError("invalid_capture", "'x.pcap' is not a valid PCAP or PCAPNG capture file.")) }));
    await act(() => result.current.analyze(pcapFile("x.pcap")));
    expect(result.current.session).toMatchObject({ phase: "error", filename: "x.pcap", problem: { kind: "invalid_capture" } });
  });

  it("reports an unreachable backend", async () => {
    const { result } = setup(mockApi({ submitCapture: vi.fn().mockRejectedValue(apiError("backend_unavailable", "down")) }));
    await act(() => result.current.analyze(pcapFile()));
    expect(result.current.session).toMatchObject({ phase: "error", problem: { kind: "backend_unavailable" } });
  });

  it("rejects oversize files before uploading", async () => {
    const { result, api } = setup();
    const big = pcapFile("big.pcap");
    Object.defineProperty(big, "size", { value: 5_000 });
    await act(() => result.current.analyze(big, { maxUploadBytes: 1_000 }));
    expect(api.submitCapture).not.toHaveBeenCalled();
    expect(result.current.session).toMatchObject({ phase: "error", problem: { kind: "file_too_large" } });
  });

  it("turns a failed job into an error", async () => {
    const failed = makeJob({ status: "failed", progress_percent: null, error: { code: "analysis_failed", message: "The analysis failed unexpectedly." } });
    const { result } = setup(mockApi({ submitCapture: vi.fn().mockResolvedValue(failed) }));
    await act(() => result.current.analyze(pcapFile()));
    expect(result.current.session).toMatchObject({ phase: "error", problem: { kind: "analysis_failed", message: "The analysis failed unexpectedly." } });
  });

  it("tolerates brief polling failures but gives up after repeated ones", async () => {
    const running = makeJob({ status: "running", progress_percent: 10 });
    const blip = mockApi({ submitCapture: vi.fn().mockResolvedValue(running),
      getStatus: vi.fn().mockRejectedValueOnce(new ApiError("backend_unavailable", "x")).mockResolvedValue(makeJob()) });
    const a = setup(blip);
    await act(() => a.result.current.analyze(pcapFile()));
    expect(a.result.current.session.phase).toBe("ready");

    const dead = mockApi({ submitCapture: vi.fn().mockResolvedValue(running), getStatus: vi.fn().mockRejectedValue(new ApiError("backend_unavailable", "x")) });
    const b = setup(dead);
    await act(() => b.result.current.analyze(pcapFile()));
    expect(b.result.current.session).toMatchObject({ phase: "error", problem: { kind: "backend_unavailable" } });
    expect(dead.getStatus).toHaveBeenCalledTimes(3);
  });

  it("reset aborts an in-flight analysis and returns to idle", async () => {
    const running = makeJob({ status: "running", progress_percent: 10 });
    const { result } = setup(mockApi({ submitCapture: vi.fn().mockResolvedValue(running), getStatus: vi.fn().mockResolvedValue(running) }));
    act(() => { void result.current.analyze(pcapFile()); });
    await waitFor(() => expect(result.current.session.phase).toBe("analyzing"));
    act(() => result.current.reset());
    expect(result.current.session.phase).toBe("idle");
    await new Promise((r) => setTimeout(r, 20));
    expect(result.current.session.phase).toBe("idle"); // no late state updates
  });
});
