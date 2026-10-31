import { configureBackend } from "../api/client";
import { hasNativeDialogs } from "./exportCapture";

export type ConnectResult = { ok: true } | { ok: false; message: string };

interface BackendInfo { url: string; token: string }

/**
 * Installed desktop app: wait until the desktop shell reports the backend ready (a real /api/health answer, not a timer) and
 * take over its address and token. Plain browser and `tauri dev` have no managed backend, so nothing is configured.
 */
export async function connectBackend(retry = false): Promise<ConnectResult> {
  if (!hasNativeDialogs()) return { ok: true };
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    if (retry) await invoke("retry_backend");
    const info = await invoke<BackendInfo | null>("backend_info");
    configureBackend(info);
    return { ok: true };
  } catch (e) {
    return { ok: false, message: typeof e === "string" ? e : e instanceof Error ? e.message : "The PacketMind backend could not be started." };
  }
}
