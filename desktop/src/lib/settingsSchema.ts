import defaultSettingsJson from "./defaultSettings.json";
import type { AppSettings, FieldConstraint } from "../api/types";

/** What the app uses until the backend answers (and if it never does). A test keeps this file identical to the backend's defaults. */
export const FALLBACK_SETTINGS = defaultSettingsJson as unknown as AppSettings;

/** Read / write a value inside the settings document by its dotted path, e.g. "detection.port_scan.min_ports". */
export function getAt(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), obj);
}
export function setAt<T>(obj: T, path: string, value: unknown): T {
  const [head, ...rest] = path.split(".");
  const o = obj as Record<string, unknown>;
  return { ...o, [head]: rest.length ? setAt(o[head], rest.join("."), value) : value } as T;
}
/** The smallest patch describing the difference between two settings documents (what is sent to the backend). */
export function diff(saved: unknown, draft: unknown): Record<string, unknown> | undefined {
  if (typeof draft !== "object" || draft === null || typeof saved !== "object" || saved === null) return saved === draft ? undefined : (draft as never);
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(draft as object)) {
    const d = diff((saved as Record<string, unknown>)[k], (draft as Record<string, unknown>)[k]);
    if (d !== undefined) out[k] = d;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Human names (and units) of the numeric settings, for validation messages. */
export const NUMERIC_LABELS: Record<string, { label: string; unit?: string }> = {
  "capture.max_size_mb": { label: "Maximum capture size", unit: " MB" }, "capture.max_duration_minutes": { label: "Maximum capture duration", unit: " minutes" },
  "capture.rotation_size_mb": { label: "Rotation size", unit: " MB" }, "capture.rotation_minutes": { label: "Rotation time", unit: " minutes" },
  "analysis.max_packets": { label: "Maximum packets analyzed" },
  "detection.port_scan.min_ports": { label: "Port scan ports threshold" }, "detection.port_scan.min_confidence": { label: "Port scan confidence threshold" },
  "detection.syn_flood.min_syn_packets": { label: "SYN flood SYN threshold" }, "detection.syn_flood.min_peak_syn_per_second": { label: "SYN flood peak rate", unit: " SYN/s" },
  "detection.syn_flood.min_confidence": { label: "SYN flood confidence threshold" },
  "detection.dns.query_rate_per_second": { label: "DNS query rate threshold", unit: " queries/s" }, "detection.dns.nxdomain_ratio": { label: "DNS failure threshold" },
  "detection.dns.min_confidence": { label: "DNS confidence threshold" }, "detection.arp.min_macs_per_ip": { label: "ARP MAC addresses per IP" },
  "detection.arp.min_confidence": { label: "ARP confidence threshold" }, "detection.tcp.retransmission_rate": { label: "TCP retransmission threshold" },
  "detection.tcp.reset_ratio": { label: "TCP reset threshold" }, "detection.tcp.min_confidence": { label: "TCP confidence threshold" },
  "detection.connection.min_upload_mb": { label: "Large upload threshold", unit: " MB" }, "detection.connection.min_confidence": { label: "Unusual connection confidence threshold" },
  "performance.baseline_window": { label: "Baseline window", unit: " captures" }, "performance.baseline_min_samples": { label: "Minimum samples required", unit: " captures" },
  "performance.slow_dns_ms": { label: "Slow DNS threshold", unit: " ms" }, "performance.slow_handshake_ms": { label: "TCP handshake threshold", unit: " ms" },
  "performance.slow_rtt_ms": { label: "Slow RTT threshold", unit: " ms" },
  "domains.retention_days": { label: "Domain retention period", unit: " days" }, "privacy.data_retention_days": { label: "Data retention period", unit: " days" },
  "ai.timeout_seconds": { label: "Investigation timeout", unit: " seconds" }, "ai.auto_min_confidence": { label: "Minimum confidence for automatic investigation" },
  "ai_usage.daily_limit": { label: "Daily investigation limit" }, "ai_usage.max_auto_per_day": { label: "Automatic investigations per day" },
  "ai_usage.cache_minutes": { label: "Cache duration", unit: " minutes" },
  "storage.max_capture_storage_gb": { label: "Maximum capture storage", unit: " GB" }, "storage.capture_retention_days": { label: "Capture retention period", unit: " days" },
  "diagnostics.max_log_mb": { label: "Maximum log size", unit: " MB" },
  "advanced.backend_timeout_seconds": { label: "Backend timeout", unit: " seconds" }, "advanced.max_concurrent_analyses": { label: "Maximum concurrent analyses" },
};

const n = (v: number) => v.toLocaleString("en-US");

/** The same rules the backend enforces (they come from its model), checked before anything is sent. One message per bad field. */
export function validateSettings(draft: AppSettings, constraints: Record<string, FieldConstraint>): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const [path, c] of Object.entries(constraints)) {
    const value = getAt(draft, path);
    const meta = NUMERIC_LABELS[path];
    if (!meta || c.max_length !== undefined) continue;
    if (value === null && path === "ai.timeout_seconds") continue; // empty = use the default
    const label = meta.label, unit = meta.unit ?? "";
    if (typeof value !== "number" || Number.isNaN(value)) { errors[path] = `${label} must be a number.`; continue; }
    if (c.exclusive_min !== undefined && !(value > c.exclusive_min)) errors[path] = `${label} must be greater than ${n(c.exclusive_min)}${unit}.`;
    else if (c.min !== undefined && value < c.min) errors[path] = `${label} must be at least ${n(c.min)}${unit}.`;
    else if (c.max !== undefined && value > c.max) errors[path] = `${label} must be at most ${n(c.max)}${unit}.`;
    else if (c.exclusive_max !== undefined && !(value < c.exclusive_max)) errors[path] = `${label} must be less than ${n(c.exclusive_max)}${unit}.`;
    else if (c.type === "integer" && !Number.isInteger(value)) errors[path] = `${label} must be a whole number.`;
  }
  return errors;
}
