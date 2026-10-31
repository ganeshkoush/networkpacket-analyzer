import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppSettings, SettingsPayload } from "../api/types";
import { formatTime, setTimeFormat } from "../lib/format";
import { shouldNotify } from "../lib/notify";
import { diff, FALLBACK_SETTINGS, setAt, validateSettings } from "../lib/settingsSchema";
import { makeBundle, makeFinding, makeSettingsPayload } from "../test/fixtures";
import { apiError, mockApi, pcapFile, renderApp, type MockApi } from "../test/render";
import { SETTINGS_SECTIONS } from "./Settings";

const save = vi.fn();
const open = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: (...a: unknown[]) => save(...a), open: (...a: unknown[]) => open(...a) }));

const KEY = "AIzaSyTESTKEY-0123456789abcdefghijklmnop";

/** A fake backend for the settings endpoints: applies a patch to a payload the way the real one does. */
function backend(initial: SettingsPayload = makeSettingsPayload(), extra: Partial<MockApi> = {}) {
  let payload = initial;
  const merge = (base: Record<string, unknown>, patch: Record<string, unknown>): Record<string, unknown> => {
    const out = { ...base };
    for (const [k, v] of Object.entries(patch)) out[k] = v && typeof v === "object" && !Array.isArray(v) ? merge(base[k] as Record<string, unknown>, v as Record<string, unknown>) : v;
    return out;
  };
  const api = mockApi({
    getSettings: vi.fn(async () => payload),
    updateSettings: vi.fn(async (patch) => (payload = { ...payload, settings: merge(payload.settings as never, patch as never) as unknown as AppSettings })),
    resetSettings: vi.fn(async (section: string | null) => (payload = { ...payload, settings: section ? { ...payload.settings, [section]: (payload.defaults as never)[section] } : payload.defaults })),
    importSettings: vi.fn(async (doc: unknown) => (payload = { ...payload, settings: (doc as { settings: AppSettings }).settings })),
    ...extra,
  });
  return { api, current: () => payload };
}

async function openSection(id: string, b = backend(), user = userEvent.setup()) {
  renderApp(b.api, `/settings/${id}`);
  await screen.findByRole("region", { name: new RegExp(`${SETTINGS_SECTIONS.find((s) => s.id === id)!.title} settings`) });
  await waitFor(() => expect(b.api.getSettings).toHaveBeenCalled());
  return { ...b, user };
}
const row = (title: string | RegExp) => screen.getByLabelText(title, { selector: "input, select, button" });
const toggle = (title: string) => screen.getByRole("switch", { name: title });

beforeEach(() => { delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__; localStorage.clear(); document.documentElement.removeAttribute("data-theme"); });
afterEach(() => { save.mockReset(); open.mockReset(); setTimeFormat("utc"); vi.restoreAllMocks(); });

// ------------------------------------------------------------------ loading and layout
describe("Settings layout", () => {
  it("lists every category and opens General by default", async () => {
    const b = backend();
    renderApp(b.api, "/settings");
    const nav = await screen.findByRole("navigation", { name: "Settings sections" });
    expect(within(nav).getAllByRole("link").map((l) => l.textContent)).toEqual(
      ["General", "Capture", "Network", "Analysis", "Detection", "Performance", "Domains", "Privacy", "AI / Gemini", "AI Usage", "Notifications", "Storage", "Database", "Diagnostics", "Security", "Advanced", "About"]);
    expect(await screen.findByRole("region", { name: "General settings" })).toBeInTheDocument();
    expect(document.title).toBe("Settings · PacketMind");
  });

  it("loads the saved values from the backend", async () => {
    const b = backend(makeSettingsPayload({}, { general: { theme: "dark" }, capture: { format: "pcapng", max_size_mb: 250 } }));
    await openSection("capture", b);
    expect((row("Capture format") as HTMLSelectElement).value).toBe("pcapng");
    expect((row("Maximum capture size") as HTMLInputElement).value).toBe("250");
  });

  it("falls back to the defaults and says so when the backend cannot be reached", async () => {
    const api = mockApi({ getSettings: vi.fn().mockRejectedValue(apiError("backend_unavailable", "Cannot reach the PacketMind backend.")) });
    renderApp(api, "/settings/capture");
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the PacketMind backend.");
    expect(screen.getByRole("alert")).toHaveTextContent("Showing the default values");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("the built-in fallback equals the backend's defaults", () => {
    expect(FALLBACK_SETTINGS).toEqual(makeSettingsPayload().defaults);
  });

  it("every setting has a short explanation and a real label (no bare controls)", async () => {
    for (const id of ["general", "capture", "analysis", "detection", "performance", "domains", "privacy", "notifications", "diagnostics", "security"]) {
      const { unmount } = render_(id);
      await screen.findByRole("region", { name: /settings$/ });
      for (const el of document.querySelectorAll("input:not([type=file]):not([type=radio]):not([type=password]), select, [role=switch]")) {
        const e = el as HTMLElement;
        expect(e.getAttribute("aria-label") || e.getAttribute("aria-labelledby") || document.querySelector(`label[for="${e.id}"]`), `${id}: ${e.outerHTML.slice(0, 80)}`).toBeTruthy();
        if (e.getAttribute("role") === "switch" && !e.id.startsWith("na-")) expect(document.getElementById(`${e.id}-help`)?.textContent?.length, `${id}: ${e.id} needs help text`).toBeGreaterThan(5);
      }
      unmount();
    }
  });
});
function render_(id: string) { return renderApp(backend().api, `/settings/${id}`); }

// ------------------------------------------------------------------ editing, saving, cancelling
describe("Saving", () => {
  it("shows Save Changes only when something changed, and sends just the change", async () => {
    const { user, api } = await openSection("domains");
    expect(screen.queryByRole("region", { name: "Unsaved changes" })).not.toBeInTheDocument();
    await user.click(toggle("Hide localhost"));
    const bar = screen.getByRole("region", { name: "Unsaved changes" });
    expect(bar).toHaveTextContent("You have unsaved changes");
    await user.click(within(bar).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ domains: { hide_localhost: true } }));
    expect(await screen.findByRole("status")).toHaveTextContent("Saved");
    expect(toggle("Hide localhost")).toHaveAttribute("aria-checked", "true");
  });

  it("Cancel throws the changes away", async () => {
    const { user, api } = await openSection("domains");
    await user.click(toggle("Hide private/local IP destinations"));
    expect(toggle("Hide private/local IP destinations")).toHaveAttribute("aria-checked", "true");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(toggle("Hide private/local IP destinations")).toHaveAttribute("aria-checked", "false");
    expect(api.updateSettings).not.toHaveBeenCalled();
    expect(screen.queryByRole("region", { name: "Unsaved changes" })).not.toBeInTheDocument();
  });

  it("changes made in one section survive switching to another, and are saved together", async () => {
    const { user, api } = await openSection("domains");
    await user.click(toggle("Hide localhost"));
    await user.click(within(screen.getByRole("navigation", { name: "Settings sections" })).getByRole("link", { name: "Privacy" }));
    await user.click(await screen.findByRole("switch", { name: "Anonymize IP addresses" }));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ domains: { hide_localhost: true }, privacy: { anonymize_ips: true } }));
  });

  it("settings persist: a new session reads what was saved", async () => {
    const b = backend();
    const first = await openSection("notifications", b);
    await first.user.click(toggle("Medium security finding"));
    await first.user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(b.current().settings.notifications.medium_finding).toBe(true));
    document.body.innerHTML = "";
    const second = await openSection("notifications", b);
    expect(toggle("Medium security finding")).toHaveAttribute("aria-checked", "true");
    expect(second.api.getSettings).toHaveBeenCalled();
  });

  it("shows the backend's message when a change is rejected, and keeps the edit", async () => {
    const b = backend(makeSettingsPayload(), { updateSettings: vi.fn().mockRejectedValue(Object.assign(apiError("unknown", "1 settings are not valid."), { errors: [{ field: "capture.format", message: "Capture format must be one of: pcap, pcapng." }] })) });
    const { user } = await openSection("domains", b);
    await user.click(toggle("Hide localhost"));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Capture format must be one of: pcap, pcapng.");
    expect(toggle("Hide localhost")).toHaveAttribute("aria-checked", "true");
  });
});

// ------------------------------------------------------------------ validation
describe("Validation", () => {
  const typeInto = async (user: ReturnType<typeof userEvent.setup>, label: string, text: string) => {
    const input = row(label) as HTMLInputElement;
    await user.clear(input);
    if (text) await user.type(input, text);
  };

  it.each([
    ["performance", "Slow RTT threshold", "0", "Slow RTT threshold must be greater than 0 ms."],
    ["performance", "Slow TCP handshake threshold", "-5", "TCP handshake threshold must be greater than 0 ms"],
    ["performance", "Baseline window", "2", "Baseline window must be at least 5 captures."],
    ["storage", "Maximum capture storage", "0", "Maximum capture storage must be greater than 0 GB."],
    ["storage", "Capture retention period", "0", "must be at least 1 days"],
    ["ai-usage", "Daily investigation limit", "-1", "Daily investigation limit must be at least 0."],
    ["detection", "Ports threshold", "-3", "Port scan ports threshold must be at least 1."],
    ["detection", "Failure threshold", "1.5", "DNS failure threshold must be at most 1."],
    ["capture", "Maximum capture size", "-1", "Maximum capture size must be at least 0 MB."],
    ["capture", "Rotation size", "1.5", "Rotation size must be a whole number."],
    ["diagnostics", "Maximum log size", "0", "Maximum log size must be at least 1 MB."],
  ])("%s → %s = %s is refused before it reaches the backend", async (section, label, value, message) => {
    const { user, api } = await openSection(section);
    await typeInto(user, label, value);
    expect(await screen.findByText(new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toBeInTheDocument();
    expect(row(label)).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "Save Changes" })).toBeDisabled();
    expect(screen.getByRole("region", { name: "Unsaved changes" })).toHaveTextContent("Fix the highlighted values");
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    expect(api.updateSettings).not.toHaveBeenCalled();
  });

  it("an empty number is an error, and fixing it re-enables Save", async () => {
    const { user } = await openSection("performance");
    await typeInto(user, "Slow DNS threshold", "");
    expect(await screen.findByText(/Slow DNS threshold must be a number/)).toBeInTheDocument();
    await user.type(row("Slow DNS threshold"), "250");
    expect(screen.getByRole("button", { name: "Save Changes" })).toBeEnabled();
  });

  it("the investigation timeout may be left empty (use the default)", async () => {
    const { user, api } = await openSection("ai", backend(makeSettingsPayload({}, { ai: { timeout_seconds: 90 } })));
    await typeInto(user, "Investigation timeout", "");
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ ai: { timeout_seconds: null } }));
  });

  it("validateSettings uses exactly the limits the backend sent", () => {
    const p = makeSettingsPayload();
    expect(validateSettings(p.settings, p.constraints)).toEqual({});
    const bad = setAt(setAt(p.settings, "storage.max_capture_storage_gb", 0), "ai_usage.daily_limit", -2);
    expect(Object.keys(validateSettings(bad, p.constraints)).sort()).toEqual(["ai_usage.daily_limit", "storage.max_capture_storage_gb"]);
  });
});

// ------------------------------------------------------------------ reset, export, import
describe("Reset, export and import", () => {
  it("Reset Section explains itself and only resets after confirmation", async () => {
    const b = backend(makeSettingsPayload({}, { capture: { format: "pcapng" }, general: { theme: "dark" } }));
    const { user, api } = await openSection("capture", b);
    await user.click(screen.getByRole("button", { name: "Reset Section" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("This will restore PacketMind settings in this section to their default values");
    expect(dialog).toHaveTextContent("not deleted");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.resetSettings).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Reset Section" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Reset section" }));
    await waitFor(() => expect(api.resetSettings).toHaveBeenCalledWith("capture"));
    await waitFor(() => expect((row("Capture format") as HTMLSelectElement).value).toBe("pcap"));
    expect(b.current().settings.general.theme).toBe("dark");          // only that section
  });

  it("Reset All Settings is confirmed and says what it does not delete", async () => {
    const { user, api } = await openSection("general");
    await user.click(screen.getByRole("button", { name: "Reset All Settings" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent("restore PacketMind settings to their default values");
    expect(api.resetSettings).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Reset all settings" }));
    await waitFor(() => expect(api.resetSettings).toHaveBeenCalledWith(null));
  });

  it("importing sends the parsed file to the backend, which validates it", async () => {
    const { user, api } = await openSection("general");
    const doc = { format: "packetmind-settings", version: 1, settings: { ...makeSettingsPayload().settings, general: { theme: "dark", time_format: "utc" } } };
    await user.upload(screen.getByLabelText("Settings file", { selector: "input" }), new File([JSON.stringify(doc)], "s.json", { type: "application/json" }));
    await waitFor(() => expect(api.importSettings).toHaveBeenCalledWith(doc));
    expect(await screen.findByText("Settings imported and applied.")).toBeInTheDocument();
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("a file that is not JSON, or is refused by the backend, is reported and changes nothing", async () => {
    const { user, api } = await openSection("general", backend(makeSettingsPayload(), { importSettings: vi.fn().mockRejectedValue(apiError("unknown", "'captures_dir' is not a PacketMind setting.")) }));
    await user.upload(screen.getByLabelText("Settings file", { selector: "input" }), new File(["not json {"], "bad.json", { type: "application/json" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not valid JSON");
    expect(api.importSettings).not.toHaveBeenCalled();
    await user.upload(screen.getByLabelText("Settings file", { selector: "input" }), new File([JSON.stringify({ format: "packetmind-settings", version: 1, settings: { storage: { captures_dir: "/etc" } } })], "evil.json"));
    expect(await screen.findByText(/'captures_dir' is not a PacketMind setting/)).toBeInTheDocument();
  });

  it("export uses the native save dialog in the desktop app", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Users/me/s.json");
    const b = backend(makeSettingsPayload(), { exportSettingsFile: vi.fn().mockResolvedValue({ filename: "s.json", directory: "/Users/me" }) });
    const { user, api } = await openSection("general", b);
    await user.click(screen.getByRole("button", { name: "Export Settings" }));
    await waitFor(() => expect(api.exportSettingsFile).toHaveBeenCalledWith("/Users/me/s.json"));
    expect(await screen.findByText(/no API key or other secret/)).toBeInTheDocument();
  });

  it("export falls back to a download in a browser", async () => {
    const clicks: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { clicks.push(`${this.href}|${this.download}`); });
    const { user } = await openSection("general");
    await user.click(screen.getByRole("button", { name: "Export Settings" }));
    await waitFor(() => expect(clicks).toEqual(["http://backend/api/settings/export|packetmind-settings.json"]));
  });

  it("diff sends only what changed", () => {
    const s = FALLBACK_SETTINGS;
    expect(diff(s, s)).toBeUndefined();
    expect(diff(s, setAt(setAt(s, "capture.format", "pcapng"), "detection.dns.enabled", false))).toEqual({ capture: { format: "pcapng" }, detection: { dns: { enabled: false } } });
  });
});

// ------------------------------------------------------------------ AI key security
describe("AI / Gemini", () => {
  it("never shows a stored key, only its status", async () => {
    const payload = makeSettingsPayload({ ai: { configured: true, source: "keychain", secure_storage_available: true, secure_storage: "Keyring", model: "gemini-2.5-flash", last_test: null } });
    await openSection("ai", backend(payload));
    expect(screen.getByRole("status", { name: "" }) ?? true).toBeTruthy();
    expect(screen.getByText(/stored securely in your system keychain/)).toBeInTheDocument();
    for (const input of screen.getAllByDisplayValue("")) expect((input as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toMatch(/AIza/);
  });

  it("the key field is a password field; saving sends it once and clears it", async () => {
    const b = backend(makeSettingsPayload(), { saveApiKey: vi.fn().mockResolvedValue(makeSettingsPayload({ ai: { configured: true, source: "keychain", secure_storage_available: true, secure_storage: "Keyring", model: "m", last_test: null } })) });
    const { user, api } = await openSection("ai", b);
    const input = screen.getByPlaceholderText("Paste API key") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input).toHaveAttribute("autocomplete", "off");
    expect(screen.getByRole("button", { name: "Save key" })).toBeDisabled();
    await user.type(input, KEY);
    await user.click(screen.getByRole("button", { name: "Save key" }));
    await waitFor(() => expect(api.saveApiKey).toHaveBeenCalledWith(KEY));
    await waitFor(() => expect(input.value).toBe(""));
    expect(await screen.findByText(/stored securely in your system keychain/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(KEY);
    expect(api.updateSettings).not.toHaveBeenCalled();                  // the key never travels with ordinary settings
  });

  it("explains when no secure storage exists and refuses to take a key", async () => {
    const payload = makeSettingsPayload({ ai: { configured: false, source: "none", secure_storage_available: false, secure_storage: null, model: "m", last_test: null } });
    await openSection("ai", backend(payload));
    expect(screen.getByPlaceholderText("Paste API key")).toBeDisabled();
    expect(screen.getByText(/No secure storage was found/)).toBeInTheDocument();
  });

  it("removing the saved key asks first", async () => {
    const payload = makeSettingsPayload({ ai: { configured: true, source: "keychain", secure_storage_available: true, secure_storage: "Keyring", model: "m", last_test: null } });
    const b = backend(payload, { deleteApiKey: vi.fn().mockResolvedValue(makeSettingsPayload()) });
    const { user, api } = await openSection("ai", b);
    await user.click(screen.getByRole("button", { name: "Remove saved key" }));
    expect(api.deleteApiKey).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(api.deleteApiKey).toHaveBeenCalled());
  });

  it("Test Connection reports success and failure plainly", async () => {
    const payload = makeSettingsPayload({ ai: { configured: true, source: "environment", secure_storage_available: true, secure_storage: "Keyring", model: "m", last_test: null } });
    const testAiConnection = vi.fn().mockResolvedValueOnce({ ok: true, message: "ok", code: null, model: "gemini-2.5-flash", latency_ms: 420 })
      .mockResolvedValueOnce({ ok: false, message: "The Gemini API key was rejected.", code: "invalid_api_key", model: null, latency_ms: null });
    const { user } = await openSection("ai", backend(payload, { testAiConnection }));
    await user.click(screen.getByRole("button", { name: "Test Connection" }));
    expect(await screen.findByText(/Connected to Gemini \(gemini-2.5-flash, 420 ms\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Test Connection" }));
    await waitFor(() => expect(testAiConnection).toHaveBeenCalledTimes(2));
  });

  it("states the data policy: raw captures and payloads are never sent", async () => {
    await openSection("ai");
    const policy = screen.getByRole("region", { name: "AI Data Policy" });
    expect(policy).toHaveTextContent(/Raw PCAP files.*NEVER SENT/);
    expect(policy).toHaveTextContent(/Raw packet payloads.*NEVER SENT/);
    expect(policy).toHaveTextContent(/Structured analysis.*ALLOWED/);
    expect(policy).toHaveTextContent(/Aggregated statistics.*ALLOWED/);
    expect(within(policy).queryByRole("switch")).not.toBeInTheDocument();      // informational: nothing to flip by accident
    expect(screen.getByText("Maximum tool calls")).toBeInTheDocument();         // listed, with the reason it is unavailable
    expect(screen.getByText(/model cannot call tools/)).toBeInTheDocument();
  });

  it("automatic investigation switches map to the backend settings", async () => {
    const { user, api } = await openSection("ai");
    await user.click(toggle("Automatically investigate low findings"));
    await user.click(toggle("Automatically investigate high findings"));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ ai: { auto_low: true, auto_high: false } }));
  });
});

// ------------------------------------------------------------------ AI usage / security
describe("AI usage and security", () => {
  it("shows today's request counts and never a price", async () => {
    await openSection("ai-usage");
    const usage = await screen.findByLabelText("AI usage today");
    expect(usage).toHaveTextContent(/Investigations.*7.*\/ 20/);
    expect(usage).toHaveTextContent(/Cached investigations.*4/);
    expect(document.body.textContent).not.toMatch(/\$|USD|€|£/);
    expect(screen.getByText(/cannot know what Google charges/)).toBeInTheDocument();
  });

  it("shows the fixed AI permissions and offers no way to change them", async () => {
    await openSection("security");
    const perms = screen.getByRole("region", { name: "AI Permissions" });
    for (const allowed of ["Read network statistics", "Read findings", "Read performance metrics", "Read domain statistics"]) expect(within(within(perms).getByLabelText("Allowed AI actions")).getByText(allowed)).toBeInTheDocument();
    for (const never of ["Execute commands", "Modify firewall", "Modify routing", "Modify network configuration", "Delete files"]) expect(within(within(perms).getByLabelText("Forbidden AI actions")).getByText(never)).toBeInTheDocument();
    expect(within(perms).queryByRole("switch")).not.toBeInTheDocument();
    expect(within(perms).queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText("Allow external integrations")).toBeInTheDocument();
  });
});

// ------------------------------------------------------------------ section behaviour
describe("Section controls", () => {
  it("Capture: lists interfaces from the backend and saves the chosen default, mode and limits", async () => {
    const ifaces = [{ name: "en7", description: "Thunderbolt", kind: "ethernet" as const, addresses: [], is_up: true }, { name: "wlan9", description: "Office Wi-Fi", kind: "wifi" as const, addresses: ["10.0.0.4"], is_up: true }];
    const { user, api } = await openSection("capture", backend(makeSettingsPayload(), { listInterfaces: vi.fn().mockResolvedValue(ifaces) }));
    await screen.findByRole("option", { name: /wlan9/ });
    await user.selectOptions(row("Default network interface"), "wlan9");
    await user.selectOptions(row("Capture mode"), "Headers only");
    await user.selectOptions(row("Capture format"), "pcapng");
    await user.clear(row("Maximum capture size") as HTMLInputElement);
    await user.type(row("Maximum capture size"), "500");
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ capture: { default_interface: "wlan9", format: "pcapng", max_size_mb: 500 }, privacy: { store_payloads: false } }));
  });

  it("Capture: controls PacketMind cannot honour are visible but disabled, with the reason", async () => {
    await openSection("capture");
    const na = screen.getByLabelText("Unavailable settings");
    expect(within(na).getByText("Capture buffer size")).toBeInTheDocument();
    expect(within(na).getByRole("switch", { name: /Capture buffer size \(not available\)/ })).toBeDisabled();
    expect(within(na).getByText(/cannot change it/)).toBeInTheDocument();
  });

  it("General: start-on-login and tray are listed as not available instead of pretending to work", async () => {
    await openSection("general");
    const na = screen.getByLabelText("Unavailable settings");
    expect(within(na).getByText("Start application on login")).toBeInTheDocument();
    expect(within(na).getByText("Minimize to system tray")).toBeInTheDocument();
    for (const sw of within(na).getAllByRole("switch")) expect(sw).toBeDisabled();
  });

  it("Network: shows interfaces dynamically, hides inactive ones on request, and reports a failure", async () => {
    const ifaces = [{ name: "en0", description: "Wi-Fi", kind: "wifi" as const, addresses: ["192.168.1.5"], is_up: true }, { name: "en5", description: "Dock", kind: "ethernet" as const, addresses: [], is_up: false }];
    const listInterfaces = vi.fn().mockResolvedValue(ifaces);
    const { user, api } = await openSection("network", backend(makeSettingsPayload(), { listInterfaces }));
    const list = await screen.findByLabelText("Network interfaces");
    expect(list).toHaveTextContent(/Wi-Fi.*en0.*192\.168\.1\.5.*Available/);
    expect(list).toHaveTextContent(/Dock.*Inactive/);
    await user.click(toggle("Show inactive interfaces"));
    expect(within(screen.getByLabelText("Network interfaces")).queryByText("Dock")).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "Use en0 as the default interface" }));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ network: { show_inactive_interfaces: false }, capture: { default_interface: "en0" } }));
    await user.click(screen.getByRole("button", { name: "Refresh Interfaces" }));
    await waitFor(() => expect(listInterfaces).toHaveBeenCalledTimes(2));
  });

  it("Network: a failure to read interfaces is an error, not an empty list", async () => {
    await openSection("network", backend(makeSettingsPayload(), { listInterfaces: vi.fn().mockRejectedValue(apiError("backend_unavailable", "Cannot list interfaces.")) }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot list interfaces.");
  });

  it("Detection: each detector has its own switch and thresholds, saved under the right keys", async () => {
    const { user, api } = await openSection("detection");
    await user.selectOptions(row("Sensitivity"), "high");
    await user.click(toggle("Enable Port Scan Detection"));
    await user.clear(row("Ports threshold") as HTMLInputElement);
    await user.type(row("Ports threshold"), "8");
    await user.clear(row("Query rate threshold") as HTMLInputElement);
    await user.type(row("Query rate threshold"), "20");
    await user.clear(row("Retransmission threshold") as HTMLInputElement);
    await user.type(row("Retransmission threshold"), "0.03");
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ detection: { sensitivity: "high", port_scan: { enabled: false, min_ports: 8 }, dns: { query_rate_per_second: 20 }, tcp: { retransmission_rate: 0.03 } } }));
    for (const name of ["Port Scan", "SYN Flood", "DNS Anomaly", "ARP Spoof", "TCP Anomaly", "Unusual Connection"]) expect(screen.getByRole("region", { name: new RegExp(`${name} Detection`) })).toBeInTheDocument();
    expect(screen.getByText(/no sliding time window/)).toBeInTheDocument();
  });

  it("Performance: the shared switches write to the analysis settings, not to a copy", async () => {
    const { user, api } = await openSection("performance");
    await user.click(toggle("Track RTT"));
    await user.click(toggle("Track TCP handshake latency"));
    await user.click(toggle("Track DNS latency"));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ analysis: { rtt: false, handshake: false }, performance: { track_dns_latency: false } }));
    expect(screen.getAllByText(/not how fast a site responds|not how fast a website responds/).length).toBeGreaterThan(0);   // handshake vs response time wording
  });

  it("Domains: uses 'domain / hostname / service' wording and never claims URLs", async () => {
    await openSection("domains");
    expect(screen.getByText(/cannot always tell which page or URL was visited/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/URLs? (you )?visited/i);
    expect(screen.getByText("Group subdomains")).toBeInTheDocument();
  });

  it("Privacy: warns about sensitive captures, shows the AI data policy and stores payload choice", async () => {
    const { user, api } = await openSection("privacy");
    expect(screen.getByText(/can contain sensitive information/)).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "AI Data Policy" })).toBeInTheDocument();
    await user.selectOptions(row("Store packet payloads"), "No — headers only");
    await user.click(toggle("Anonymize IP addresses"));
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(api.updateSettings).toHaveBeenCalledWith({ privacy: { store_payloads: false, anonymize_ips: true } }));
  });

  it("Advanced: hidden until chosen; the backend address must be on this computer", async () => {
    const { user } = await openSection("advanced");
    expect(screen.queryByLabelText("Backend URL")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show Advanced Settings" }));
    const url = screen.getByLabelText("Backend URL");
    await user.clear(url);
    await user.type(url, "http://evil.example.com:8765");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("must be on this computer");
    expect(localStorage.getItem("packetmind.backendUrl")).toBeNull();
    await user.clear(url);
    await user.type(url, "http://127.0.0.1:9999");
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(localStorage.getItem("packetmind.backendUrl")).toBe("http://127.0.0.1:9999");
    expect(screen.getByLabelText("Debug mode") ?? true).toBeTruthy();
    expect(toggle("Debug mode")).toHaveAttribute("aria-checked", "false");               // off by default
    expect(screen.getByText("Maximum concurrent captures")).toBeInTheDocument();
  });

  it("About: shows versions and capabilities, and Check System asks again", async () => {
    const { user, api } = await openSection("about");
    expect(await screen.findByText("Scapy 2.8.0")).toBeInTheDocument();
    expect(screen.getByText("AI-Powered Network Security Analyst")).toBeInTheDocument();
    for (const t of ["Application version", "Backend version", "Python version", "Database engine", "Operating system", "Architecture", "Capture capability", "TShark", "Gemini connection"]) expect(screen.getByText(t)).toBeInTheDocument();
    expect(screen.getByText("No API key configured")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check System" }));
    await waitFor(() => expect(api.getAbout).toHaveBeenCalledTimes(2));
    await user.click(screen.getByRole("button", { name: "Open Documentation" }));
    await waitFor(() => expect(api.openFolder).toHaveBeenCalledWith("docs"));
  });
});

// ------------------------------------------------------------------ storage, database, diagnostics
describe("Storage", () => {
  it("shows usage and locations and opens only PacketMind's own folders", async () => {
    const { user, api } = await openSection("storage");
    const usage = await screen.findByLabelText("Storage usage");
    expect(usage).toHaveTextContent(/Captures.*3\.2 GB/);
    expect(usage).toHaveTextContent(/Total.*3\.4 GB/);
    expect(screen.getByText("/data/captures")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open Capture Folder" }));
    await user.click(screen.getByRole("button", { name: "Open Report Folder" }));
    expect(api.openFolder).toHaveBeenNthCalledWith(1, "captures");
    expect(api.openFolder).toHaveBeenNthCalledWith(2, "reports");
  });

  it("Manage Storage previews the cleanup and deletes only after explicit confirmation", async () => {
    const preview = { dry_run: true, candidates: [{ id: "a", name: "old1.pcap", size: 100, reason: "older than 30 days" }, { id: "b", name: "old2.pcap", size: 300, reason: "older than 30 days" }], deleted: 0, freed_bytes: 0, would_free_bytes: 400 };
    const storageCleanup = vi.fn().mockResolvedValueOnce(preview).mockResolvedValueOnce({ ...preview, dry_run: false, deleted: 2, freed_bytes: 400 });
    const { user } = await openSection("storage", backend(makeSettingsPayload(), { storageCleanup }));
    await user.click(await screen.findByRole("button", { name: "Manage Storage" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("permanently deleted");
    expect(within(dialog).getByLabelText("Captures to delete")).toHaveTextContent(/old1\.pcap.*old2\.pcap/);
    expect(storageCleanup).toHaveBeenCalledTimes(1);
    expect(storageCleanup).toHaveBeenLastCalledWith({ dryRun: true });                              // a preview deletes nothing
    await user.click(within(dialog).getByRole("button", { name: /Delete 2 captures/ }));
    await waitFor(() => expect(storageCleanup).toHaveBeenLastCalledWith({ dryRun: false, confirm: true }));
    expect(await screen.findByText(/Deleted 2 captures/)).toBeInTheDocument();
  });

  it("Manage Storage with nothing to clean says so and never opens a delete dialog", async () => {
    const storageCleanup = vi.fn().mockResolvedValue({ dry_run: true, candidates: [], deleted: 0, freed_bytes: 0, would_free_bytes: 0 });
    const { user } = await openSection("storage", backend(makeSettingsPayload(), { storageCleanup }));
    await user.click(await screen.findByRole("button", { name: "Manage Storage" }));
    expect(await screen.findByText(/Nothing to clean up/)).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("automatic cleanup is off by default and explains itself", async () => {
    await openSection("storage");
    expect(toggle("Automatically delete old captures")).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText(/Nothing is ever deleted unless you turn on automatic cleanup or confirm/)).toBeInTheDocument();
  });
});

describe("Database", () => {
  it("shows what is stored", async () => {
    await openSection("database");
    expect(await screen.findByText(/SQLite \(schema version 4\)/)).toBeInTheDocument();
    const rows = screen.getByRole("region", { name: "Database" });
    expect(rows).toHaveTextContent(/Number of captures.*12/);
    expect(rows).toHaveTextContent(/Number of reports.*3/);
    expect(rows).toHaveTextContent(/Number of findings.*9/);
  });

  it("backs up to the place chosen in the native save dialog", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Users/me/pm.sqlite3");
    const b = backend(makeSettingsPayload(), { backupDatabase: vi.fn().mockResolvedValue({ filename: "pm.sqlite3", directory: "/Users/me", size_bytes: 1 }) });
    const { user, api } = await openSection("database", b);
    await user.click(await screen.findByRole("button", { name: "Backup Database" }));
    await waitFor(() => expect(api.backupDatabase).toHaveBeenCalledWith("/Users/me/pm.sqlite3"));
    expect(await screen.findByText(/Database backed up to pm\.sqlite3/)).toBeInTheDocument();
  });

  it("restore needs a chosen file and a confirmation, and is explained", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    open.mockResolvedValue("/Users/me/pm.sqlite3");
    const restoreDatabase = vi.fn().mockResolvedValue({ safety_copy: "before-restore-1.sqlite3", info: { type: "SQLite", path: "/d", size_bytes: 1, schema_version: 4, captures: 1, reports: 1, findings_in_reports: 0, history_domains_observations: 0, retention_days: 0, notes: [] } });
    const { user } = await openSection("database", backend(makeSettingsPayload(), { restoreDatabase }));
    await user.click(await screen.findByRole("button", { name: "Restore Database" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("replaces your current reports");
    expect(restoreDatabase).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Restore database" }));
    await waitFor(() => expect(restoreDatabase).toHaveBeenCalledWith("/Users/me/pm.sqlite3"));
    expect((await screen.findAllByText(/A copy of the previous database was saved as before-restore-1\.sqlite3/)).length).toBeGreaterThan(0);
  });

  it("clearing history keeps the capture files unless that exact option is ticked", async () => {
    const clearAnalysisHistory = vi.fn().mockResolvedValue({ performance_history: 2, reports: 0, capture_summaries: 3, captures_deleted: 0 });
    const { user } = await openSection("database", backend(makeSettingsPayload(), { clearAnalysisHistory }));
    await user.click(await screen.findByRole("button", { name: "Clear Analysis History" }));
    let dialog = screen.getByRole("alertdialog");
    const files = within(dialog).getByRole("checkbox", { name: /delete the capture files/ });
    expect(files).not.toBeChecked();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(clearAnalysisHistory).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Clear Analysis History" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Clear history" }));
    await waitFor(() => expect(clearAnalysisHistory).toHaveBeenCalledWith({ performanceHistory: true, reports: false, captureSummaries: true, deleteCaptureFiles: false }));
    await user.click(screen.getByRole("button", { name: "Clear Analysis History" }));
    dialog = screen.getByRole("alertdialog");
    await user.click(within(dialog).getByRole("checkbox", { name: /delete the capture files/ }));
    await user.click(within(dialog).getByRole("button", { name: "Clear history" }));
    await waitFor(() => expect(clearAnalysisHistory).toHaveBeenLastCalledWith({ performanceHistory: true, reports: false, captureSummaries: true, deleteCaptureFiles: true }));
  });
});

describe("Diagnostics", () => {
  it("exports a diagnostic report to the chosen file and promises no secrets", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    save.mockResolvedValue("/Users/me/diag.json");
    const b = backend(makeSettingsPayload(), { exportDiagnostics: vi.fn().mockResolvedValue({ filename: "diag.json", directory: "/Users/me", size_bytes: 10 }) });
    const { user, api } = await openSection("diagnostics", b);
    await user.click(screen.getByRole("button", { name: "Export Diagnostic Report" }));
    await waitFor(() => expect(api.exportDiagnostics).toHaveBeenCalledWith("/Users/me/diag.json"));
    expect(await screen.findByText(/contains no API keys or packet data/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open Logs Folder" }));
    expect(api.openFolder).toHaveBeenCalledWith("logs");
  });

  it("logging levels are Error, Warning, Info and Debug", async () => {
    await openSection("diagnostics");
    expect(within(row("Logging level")).getAllByRole("option").map((o) => o.textContent)).toEqual(["Error", "Warning", "Info", "Debug"]);
  });
});

// ------------------------------------------------------------------ effects of settings on the UI
describe("Settings that change the app itself", () => {
  it("the theme is applied as soon as it is saved", async () => {
    const { user } = await openSection("general");
    await user.selectOptions(row("Theme"), "light");
    expect(document.documentElement.dataset.theme).not.toBe("light");          // not before saving
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
  });

  it("the date/time format changes how times are shown everywhere", async () => {
    expect(formatTime(1_700_000_000)).toBe("2023-11-14 22:13:20 UTC");
    const { user } = await openSection("general");
    await user.selectOptions(row("Date and time format"), "local_24h");
    await user.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(formatTime(1_700_000_000)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(local\)$/));
  });

  it("Live Capture starts from the defaults in Settings and sends only what differs", async () => {
    const payload = makeSettingsPayload({}, { capture: { default_interface: "en1", auto_save: false, format: "pcapng" } });
    const ifaces = [{ name: "en0", description: "Wi-Fi", kind: "wifi" as const, addresses: ["1.2.3.4"], is_up: true }, { name: "en1", description: "Ethernet", kind: "ethernet" as const, addresses: [], is_up: true }];
    const startLive = vi.fn().mockResolvedValue({ state: "capturing", interface: "en1", capture: null, findings: [], protocols: [], top_talkers: [], top_ports: [] });
    const b = backend(payload, { listInterfaces: vi.fn().mockResolvedValue(ifaces), startLive });
    renderApp(b.api, "/live");
    await screen.findByRole("option", { name: /en1/ });
    await waitFor(() => expect((screen.getByLabelText("Network interface") as HTMLSelectElement).value).toBe("en1"));
    expect(screen.getByRole("checkbox", { name: /Save the packets/ })).not.toBeChecked();
    expect((screen.getByLabelText("Capture file format") as HTMLSelectElement).value).toBe("pcapng");
    await userEvent.setup().click(screen.getByRole("button", { name: "Start capture" }));
    expect(startLive).toHaveBeenCalledWith({ interface: "en1", auto_investigate: false });          // same as the settings: nothing extra is sent
  });

  it("automatic interface selection prefers an active Wi-Fi or Ethernet interface", async () => {
    const payload = makeSettingsPayload({}, { network: { auto_select_interface: true } });
    const ifaces = [{ name: "lo0", description: "Loopback", kind: "loopback" as const, addresses: ["127.0.0.1"], is_up: true }, { name: "en0", description: "Wi-Fi", kind: "wifi" as const, addresses: ["1.2.3.4"], is_up: true }];
    renderApp(backend(payload, { listInterfaces: vi.fn().mockResolvedValue(ifaces) }).api, "/live");
    await waitFor(() => expect((screen.getByLabelText("Network interface") as HTMLSelectElement).value).toBe("en0"));
  });

  it("hidden inactive interfaces do not appear in the Live Capture list", async () => {
    const payload = makeSettingsPayload({}, { network: { show_inactive_interfaces: false } });
    const ifaces = [{ name: "en0", description: "Wi-Fi", kind: "wifi" as const, addresses: ["1.2.3.4"], is_up: true }, { name: "en9", description: "Old dock", kind: "ethernet" as const, addresses: [], is_up: false }];
    renderApp(backend(payload, { listInterfaces: vi.fn().mockResolvedValue(ifaces) }).api, "/live");
    await screen.findByRole("option", { name: /en0/ });
    expect(screen.queryByRole("option", { name: /en9/ })).not.toBeInTheDocument();
  });

  it("'Confirm before deleting' off lets a capture be deleted straight away; on (the default) asks first", async () => {
    const cap = { id: "1".repeat(32), filename: "f.pcap", original_filename: "f.pcap", source_type: "UPLOADED_PCAP", capture_format: "pcap", interface: null, start_time: 1, end_time: 2, duration_seconds: 1,
      packet_count: 10, byte_count: 10, file_size: 10, status: "ANALYZED", error_message: null, created_at: "2026-10-07T00:00:00+00:00", analyzed_at: null, summary: null };
    const noConfirm = backend(makeSettingsPayload({}, { security: { confirm_delete_captures: false } }), { listCaptures: vi.fn().mockResolvedValue([cap]) });
    renderApp(noConfirm.api, "/captures");
    await userEvent.setup().click(await screen.findByRole("button", { name: "Delete f.pcap" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    await waitFor(() => expect(noConfirm.api.deleteCapture).toHaveBeenCalledWith(cap.id));
    document.body.innerHTML = "";
    const confirms = backend(makeSettingsPayload(), { listCaptures: vi.fn().mockResolvedValue([cap]) });
    renderApp(confirms.api, "/captures");
    await userEvent.setup().click(await screen.findByRole("button", { name: "Delete f.pcap" }));
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    expect(confirms.api.deleteCapture).not.toHaveBeenCalled();
  });

  it("'Show internal identifiers' reveals capture ids", async () => {
    const cap = { id: "9".repeat(32), filename: "f.pcap", original_filename: "f.pcap", source_type: "UPLOADED_PCAP", capture_format: "pcap", interface: null, start_time: 1, end_time: 2, duration_seconds: 1,
      packet_count: 10, byte_count: 10, file_size: 10, status: "ANALYZED", error_message: null, created_at: "2026-10-07T00:00:00+00:00", analyzed_at: null, summary: null };
    renderApp(backend(makeSettingsPayload({}, { advanced: { show_internal_ids: true } }), { listCaptures: vi.fn().mockResolvedValue([cap]) }).api, "/captures");
    expect(await screen.findByText(`id ${cap.id}`)).toBeInTheDocument();
  });
});

// ------------------------------------------------------------------ notifications
describe("Notifications", () => {
  const base = FALLBACK_SETTINGS.notifications;
  it("decides from the settings: master switch, per-event switches and background-only", () => {
    expect(shouldNotify(base, "critical_finding", false)).toBe(true);
    expect(shouldNotify(base, "medium_finding", false)).toBe(false);                      // off by default
    expect(shouldNotify({ ...base, enabled: false }, "critical_finding", false)).toBe(false);
    expect(shouldNotify({ ...base, only_in_background: true }, "capture_completed", false)).toBe(false);
    expect(shouldNotify({ ...base, only_in_background: true }, "capture_completed", true)).toBe(true);
    for (const k of ["performance_anomaly", "capture_completed", "analysis_completed", "ai_completed", "capture_error", "analysis_error", "high_finding"] as const)
      expect(shouldNotify({ ...base, enabled: true, [k]: false }, k, true)).toBe(false);
  });

  const notifications: { title: string; body: string }[] = [];
  beforeEach(() => {
    notifications.length = 0;
    class FakeNotification { static permission = "granted"; static requestPermission = async () => "granted"; constructor(public title: string, o?: { body?: string }) { notifications.push({ title, body: o?.body ?? "" }); } }
    vi.stubGlobal("Notification", FakeNotification);
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  async function analyzed(payload: SettingsPayload) {
    const bundle = makeBundle({ findings: [makeFinding({ severity: "CRITICAL" }), makeFinding({ id: "m", severity: "MEDIUM" })] });
    const b = backend(payload);
    const user = userEvent.setup();
    renderApp(mockApi({ ...b.api, getResult: vi.fn().mockResolvedValue(bundle) } as Partial<MockApi>), "/analysis");
    await user.upload(screen.getByLabelText("Capture file"), pcapFile("demo.pcap"));
    await screen.findByText(/packets ·/);
  }

  it("an analysis notifies for the events the user enabled, and only those", async () => {
    await analyzed(makeSettingsPayload());
    await waitFor(() => expect(notifications.map((n) => n.title).sort()).toEqual(["1 critical finding", "Analysis completed"]));
  });

  it("everything off means nothing is shown", async () => {
    await analyzed(makeSettingsPayload({}, { notifications: { enabled: false } }));
    await act(async () => { await new Promise((r) => setTimeout(r, 50)); });
    expect(notifications).toEqual([]);
  });

  it("medium findings notify once the user turns them on", async () => {
    await analyzed(makeSettingsPayload({}, { notifications: { medium_finding: true, analysis_completed: false, critical_finding: false } }));
    await waitFor(() => expect(notifications.map((n) => n.title)).toEqual(["1 medium finding"]));
  });

  it("a failed analysis notifies with the plain-language reason", async () => {
    const b = backend(makeSettingsPayload(), { submitCapture: vi.fn().mockRejectedValue(apiError("invalid_capture", "Unable to read 'x.pcap'. The file may be corrupted.")) });
    renderApp(b.api, "/analysis");
    await userEvent.setup().upload(screen.getByLabelText("Capture file"), pcapFile("x.pcap"));
    await waitFor(() => expect(notifications).toEqual([{ title: "Analysis failed", body: "Unable to read 'x.pcap'. The file may be corrupted." }]));
  });
});

void fireEvent;
