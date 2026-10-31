import type { Api } from "../api/client";
import { ApiError } from "../api/client";
import type { CaptureSession } from "../api/types";

export type ExportOutcome =
  | { kind: "saved"; filename: string; directory: string }   // the backend copied the file to the chosen place
  | { kind: "download_started"; filename: string }           // browser fallback: the browser saves the download
  | { kind: "cancelled" };

/** True inside the Tauri desktop shell, where native dialogs are available. */
export const hasNativeDialogs = (): boolean => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** The name suggested in the save dialog: always a plain file name with the right extension. */
export function suggestedName(c: Pick<CaptureSession, "original_filename" | "filename" | "source_type" | "capture_format">): string {
  const base = (c.source_type === "UPLOADED_PCAP" ? c.original_filename : c.filename).replace(/^.*[\\/]/, "").replace(/\.(pcap|pcapng)$/i, "");
  return `${base || "packetmind_capture"}.${c.capture_format}`;
}

/**
 * Export a capture. In the desktop app the user picks the destination in the native save dialog and the local backend copies
 * the file there (validated, atomic, never loading it into the page). In a plain browser the backend streams a download.
 */
export async function exportCapture(
  api: Pick<Api, "exportCapture" | "captureDownloadUrl">, capture: CaptureSession,
  confirmOverwrite: (filename: string) => boolean = () => false,
): Promise<ExportOutcome> {
  const name = suggestedName(capture);
  if (!hasNativeDialogs()) {
    const a = document.createElement("a");
    a.href = api.captureDownloadUrl(capture.id);
    a.download = name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
    return { kind: "download_started", filename: name };
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const destination = await save({ title: "Export capture", defaultPath: name, filters: [{ name: "Packet capture", extensions: [capture.capture_format, "pcap", "pcapng"] }] });
  if (!destination) return { kind: "cancelled" };
  try {
    const r = await api.exportCapture(capture.id, destination, false);
    return { kind: "saved", filename: r.filename, directory: r.directory };
  } catch (e) {
    // The native dialog already asks before replacing a file; this covers a file that appeared in between.
    if (e instanceof ApiError && e.code === "destination_exists" && confirmOverwrite(destination.split(/[\\/]/).pop() ?? destination)) {
      const r = await api.exportCapture(capture.id, destination, true);
      return { kind: "saved", filename: r.filename, directory: r.directory };
    }
    throw e;
  }
}
