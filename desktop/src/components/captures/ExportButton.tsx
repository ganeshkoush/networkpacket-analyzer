import { useState } from "react";
import { ApiError } from "../../api/client";
import type { CaptureSession } from "../../api/types";
import { exportCapture } from "../../lib/exportCapture";
import { useApi } from "../../state/ApiContext";
import { Button, Notice } from "../ui/feedback";

/** "Download PCAP": the native save dialog in the desktop app; says plainly when it worked or why it did not. */
export function ExportButton({ capture, label = "Download PCAP", variant = "secondary" }: { capture: CaptureSession; label?: string; variant?: "primary" | "secondary" | "ghost" }) {
  const api = useApi();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "info" | "warn"; text: string } | null>(null);
  const disabled = busy || !["COMPLETED", "ANALYZING", "ANALYZED"].includes(capture.status);

  const run = async () => {
    setBusy(true); setMessage(null);
    try {
      const r = await exportCapture(api, capture, (name) => window.confirm(`“${name}” already exists. Replace it?`));
      if (r.kind === "saved") setMessage({ tone: "info", text: `PCAP exported successfully. Saved as ${r.filename} in ${r.directory}.` });
      else if (r.kind === "download_started") setMessage({ tone: "info", text: `PCAP download started: ${r.filename}.` });
    } catch (e) {
      setMessage({ tone: "warn", text: e instanceof ApiError ? `The PCAP was not exported. ${e.message}` : "The PCAP was not exported. Something went wrong while saving it." });
    } finally { setBusy(false); }
  };

  return (
    <span className="inline-flex flex-col items-start gap-2">
      <Button variant={variant} onClick={run} disabled={disabled}>{busy ? "Exporting…" : label}</Button>
      {message && <span className="max-w-md"><Notice tone={message.tone === "warn" ? "warn" : "info"}>{message.text}</Notice></span>}
    </span>
  );
}
