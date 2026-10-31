const nf = new Intl.NumberFormat("en-US");

export function formatNumber(n: number | null | undefined): string {
  return n == null ? "–" : nf.format(n);
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null) return "–";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "–";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}

/** Milliseconds -> "45 ms", "7.5 ms", "1.25 s". At most one decimal below 1 s; "–" when not measured. */
export function formatMs(ms: number | null | undefined): string {
  if (ms == null || Number.isNaN(ms)) return "–";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Number(ms.toFixed(1))} ms`;
}

export function formatPercent(fraction: number | null | undefined, digits = 1): string {
  return fraction == null ? "–" : `${(fraction * 100).toFixed(digits)}%`;
}

// Settings → General → Date/time format. "utc" (the default) is what packet captures use; the others show this computer's local time.
export type TimeFormat = "utc" | "local" | "local_24h";
let timeFormat: TimeFormat = "utc";
export function setTimeFormat(mode: TimeFormat): void { timeFormat = mode; }

const pad = (n: number, w = 2) => String(n).padStart(w, "0");
function stamp(d: Date, millis: boolean): string {
  if (timeFormat === "utc") {
    const iso = d.toISOString().replace("T", " ");
    return (millis ? iso.replace("Z", "") : iso.replace(/\.\d+Z$/, "")) + " UTC";
  }
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const time = timeFormat === "local_24h"
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    : d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" });
  return `${date} ${time}${millis ? `.${pad(d.getMilliseconds(), 3)}` : ""} (local)`;
}

/** Epoch seconds -> "2023-11-14 22:13:19 UTC" (or local time, per the setting). */
export function formatTime(epoch: number | null | undefined): string {
  if (epoch == null) return "–";
  const d = new Date(epoch * 1000);
  return Number.isNaN(d.getTime()) ? "–" : stamp(d, false);
}

/** Epoch seconds -> "2023-11-14 22:13:19.120 UTC" (millisecond precision). */
export function formatTimeMs(epoch: number | null | undefined): string {
  if (epoch == null) return "–";
  const d = new Date(epoch * 1000);
  return Number.isNaN(d.getTime()) ? "–" : stamp(d, true);
}

/** Epoch seconds -> "22:13:19" (clock time, for chart axes). */
export function formatClock(epoch: number): string {
  const d = new Date(epoch * 1000);
  if (Number.isNaN(d.getTime())) return "–";
  return timeFormat === "utc" ? d.toISOString().slice(11, 19) : `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** Seconds offset -> "m:ss" (or "h:mm:ss"). */
export function formatOffset(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
}

export function humanizeKey(key: string): string {
  return key.replace(/_/g, " ");
}

export function endpoint(ip: string, port: number | null): string {
  if (port == null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`; // bracket IPv6 so the port is unambiguous
}

/** Seconds -> "00:04:32" (hours:minutes:seconds), the way a running capture clock reads. */
export function formatClockDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return "–";
  const t = Math.max(0, Math.floor(seconds));
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(Math.floor(t / 3600))}:${p(Math.floor((t % 3600) / 60))}:${p(t % 60)}`;
}
