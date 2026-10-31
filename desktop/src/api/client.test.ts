import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./client";

afterEach(() => vi.unstubAllGlobals());

const json = (status: number, body: unknown) => ({ ok: status < 400, status, json: async () => body });

describe("api client", () => {
  it("maps a network failure to backend_unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.fetchHealth()).rejects.toMatchObject({ kind: "backend_unavailable" });
  });

  it("re-throws aborts untouched", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("x", "AbortError")));
    await expect(api.fetchHealth()).rejects.toMatchObject({ name: "AbortError" });
  });

  it.each([
    [400, "invalid_capture", "invalid_capture"],
    [400, "empty_file", "empty_file"],
    [413, "file_too_large", "file_too_large"],
    [404, "not_found", "not_found"],
    [409, "file_missing", "analysis_failed"],
  ])("maps HTTP %i code %s to kind %s", async (status, code, kind) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(status, { detail: { code, message: "boom" } })));
    const err = await api.getStatus("x").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ kind, message: "boom", status });
  });

  it("handles non-JSON server errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 502, json: async () => { throw new Error("html"); } }));
    await expect(api.getStatus("x")).rejects.toMatchObject({ kind: "server_error", status: 502 });
  });

  it("uploads the file as a raw body with an encoded filename", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(202, { id: "j", status: "queued" }));
    vi.stubGlobal("fetch", fetchMock);
    const file = new File(["abc"], "my capture é.pcap");
    await api.submitCapture(file);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toMatch(/\/api\/analyses$/);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(file);
    expect(init.headers["Content-Type"]).toBe("application/octet-stream");
    expect(decodeURIComponent(init.headers["X-Filename"])).toBe("my capture é.pcap");
  });

  it("encodes ids in paths", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(200, {}));
    vi.stubGlobal("fetch", fetchMock);
    await api.getResult("a/b");
    expect(fetchMock.mock.calls[0][0]).toMatch(/\/api\/analyses\/a%2Fb\/result$/);
  });
});
