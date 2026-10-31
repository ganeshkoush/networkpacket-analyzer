import type { AppSettings } from "../api/types";
import { hasNativeDialogs } from "./exportCapture";

export type NotificationKind =
  | "critical_finding" | "high_finding" | "medium_finding" | "performance_anomaly" | "capture_completed" | "analysis_completed"
  | "ai_completed" | "capture_error" | "analysis_error";

/** Whether this event should notify, from the Notifications settings. Pure, so it is easy to test. */
export function shouldNotify(s: AppSettings["notifications"], kind: NotificationKind, inBackground: boolean): boolean {
  if (!s.enabled || !s[kind]) return false;
  return !s.only_in_background || inBackground;
}

export const isInBackground = (): boolean => typeof document !== "undefined" && (document.hidden || !document.hasFocus());

/** Show an operating-system notification (Tauri plugin in the desktop app, the Web Notification API elsewhere). Best effort. */
export async function sendDesktopNotification(title: string, body: string, sound: boolean): Promise<void> {
  try {
    if (hasNativeDialogs()) {
      const n = await import("@tauri-apps/plugin-notification");
      let ok = await n.isPermissionGranted();
      if (!ok) ok = (await n.requestPermission()) === "granted";
      if (ok) n.sendNotification(sound ? { title, body, sound: "default" } : { title, body });
      return;
    }
    if (typeof Notification === "undefined") return;
    if (Notification.permission === "default") await Notification.requestPermission();
    if (Notification.permission === "granted") new Notification(title, { body, silent: !sound });
  } catch { /* a notification is never worth interrupting the app */ }
}
