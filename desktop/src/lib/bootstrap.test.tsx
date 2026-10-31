import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, backendUrl, configureBackend, isManagedBackend } from "../api/client";
import { Startup } from "../components/layout/Startup";
import { connectBackend } from "./bootstrap";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

afterEach(() => {
  configureBackend(null);
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  invoke.mockReset();
  vi.unstubAllGlobals();
});
const asDesktop = () => { (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {}; };

describe("connectBackend", () => {
  it("does nothing in a plain browser / dev build (no managed backend)", async () => {
    expect(await connectBackend()).toEqual({ ok: true });
    expect(invoke).not.toHaveBeenCalled();
    expect(isManagedBackend()).toBe(false);
  });

  it("adopts the address and token the desktop shell reports once the backend is ready", async () => {
    asDesktop();
    invoke.mockResolvedValue({ url: "http://127.0.0.1:50123", token: "abc" });
    expect(await connectBackend()).toEqual({ ok: true });
    expect(invoke).toHaveBeenCalledWith("backend_info");
    expect(backendUrl()).toBe("http://127.0.0.1:50123");
  });

  it("keeps the default address when the shell says there is no managed backend (tauri dev)", async () => {
    asDesktop();
    invoke.mockResolvedValue(null);
    expect(await connectBackend()).toEqual({ ok: true });
    expect(isManagedBackend()).toBe(false);
  });

  it("reports the startup failure message, and retry asks the shell to restart first", async () => {
    asDesktop();
    invoke.mockRejectedValueOnce("The PacketMind backend did not become ready within 60 seconds. Log: /x/backend.log");
    expect(await connectBackend()).toEqual({ ok: false, message: expect.stringContaining("did not become ready") });
    invoke.mockResolvedValue(null);
    await connectBackend(true);
    expect(invoke.mock.calls.map((c) => c[0])).toEqual(["backend_info", "retry_backend", "backend_info"]);
  });
});

describe("API requests in the installed app", () => {
  it("send the per-launch token to the managed address, and none in development", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ status: "ok", app: "PacketMind", version: "1", max_upload_bytes: 1 })));
    vi.stubGlobal("fetch", fetchMock);
    await api.fetchHealth();
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).has("X-PacketMind-Token")).toBe(false);

    configureBackend({ url: "http://127.0.0.1:50123", token: "tok-1" });
    await api.fetchHealth();
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("http://127.0.0.1:50123/api/health");
    expect(new Headers(init.headers).get("X-PacketMind-Token")).toBe("tok-1");
  });

  it("also protect the confirm-style DELETE calls that bypass the shared request helper", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}"));
    vi.stubGlobal("fetch", fetchMock);
    configureBackend({ url: "http://127.0.0.1:50123", token: "tok-2" });
    await api.deleteCapture("abc").catch(() => undefined);
    expect(new Headers(fetchMock.mock.calls[0][1].headers).get("X-PacketMind-Token")).toBe("tok-2");
  });

  it("a saved dev backend address cannot override the managed one", () => {
    localStorage.setItem("packetmind.backendUrl", "http://127.0.0.1:9999");
    configureBackend({ url: "http://127.0.0.1:50123", token: "t" });
    expect(backendUrl()).toBe("http://127.0.0.1:50123");
    localStorage.removeItem("packetmind.backendUrl");
  });
});

describe("Startup screen", () => {
  it("shows progress, then the app once the backend is ready", async () => {
    let done: (v: { ok: true }) => void = () => undefined;
    const connect = vi.fn().mockReturnValue(new Promise((r) => { done = r; }));
    render(<Startup connect={connect}><p>the app</p></Startup>);
    expect(screen.getByText("Starting PacketMind…")).toBeInTheDocument();
    expect(screen.queryByText("the app")).not.toBeInTheDocument();
    done({ ok: true });
    expect(await screen.findByText("the app")).toBeInTheDocument();
  });

  it("explains a startup failure and retries on request", async () => {
    const user = userEvent.setup();
    const connect = vi.fn().mockResolvedValueOnce({ ok: false, message: "Backend exited during startup. Log: /logs/backend.log" }).mockResolvedValue({ ok: true });
    render(<Startup connect={connect}><p>the app</p></Startup>);
    expect(await screen.findByRole("alert")).toHaveTextContent("Backend exited during startup. Log: /logs/backend.log");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.getByText("the app")).toBeInTheDocument());
    expect(connect).toHaveBeenLastCalledWith(true);
  });
});
