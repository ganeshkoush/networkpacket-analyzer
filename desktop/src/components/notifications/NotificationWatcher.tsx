import { useEffect, useRef } from "react";
import type { Severity } from "../../api/types";
import { isInBackground, sendDesktopNotification, shouldNotify, type NotificationKind } from "../../lib/notify";
import { useAnalysis } from "../../state/AnalysisContext";
import { useApi } from "../../state/ApiContext";
import { useInvestigation } from "../../state/InvestigationContext";
import { useSettings } from "../../state/SettingsContext";

const FINDING_KIND: Partial<Record<Severity, NotificationKind>> = { CRITICAL: "critical_finding", HIGH: "high_finding", MEDIUM: "medium_finding" };
const LIVE_POLL_MS = 5000;

/** Turns app events into desktop notifications, honouring Settings → Notifications. Renders nothing. */
export function NotificationWatcher() {
  const api = useApi();
  const { saved } = useSettings();
  const { session } = useAnalysis();
  const { state: investigation } = useInvestigation();
  const settings = useRef(saved.notifications);
  settings.current = saved.notifications;
  const seen = useRef(new Set<string>());

  const notify = (kind: NotificationKind, key: string, title: string, body: string) => {
    if (seen.current.has(key) || !shouldNotify(settings.current, kind, isInBackground())) return;
    seen.current.add(key);
    void sendDesktopNotification(title, body, settings.current.sound);
  };

  // An analysis finished or failed, and what it found.
  useEffect(() => {
    if (session.phase === "ready") {
      const id = session.bundle.job.id;
      notify("analysis_completed", `analysis:${id}`, "Analysis completed", `${session.filename} was analyzed.`);
      for (const sev of ["CRITICAL", "HIGH", "MEDIUM"] as Severity[]) {
        const n = session.bundle.findings.filter((f) => f.severity === sev).length;
        const kind = FINDING_KIND[sev]!;
        if (n) notify(kind, `findings:${id}:${sev}`, `${n} ${sev.toLowerCase()} finding${n === 1 ? "" : "s"}`, `Possible issues were found in ${session.filename}. Open Findings to review them.`);
      }
      if (settings.current.enabled && settings.current.performance_anomaly) {
        api.getAnomalies(id).then((a) => { if (a.anomalies.length) notify("performance_anomaly", `anomaly:${id}`, "Performance anomaly", `${a.anomalies.length} metric${a.anomalies.length === 1 ? " is" : "s are"} slower than usual in ${session.filename}.`); }).catch(() => undefined);
      }
    } else if (session.phase === "error") {
      notify("analysis_error", `analysis-error:${session.filename ?? ""}:${session.problem.message}`, "Analysis failed", session.problem.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // An AI investigation finished.
  useEffect(() => {
    if (investigation.phase === "done") notify("ai_completed", `ai:${investigation.analysisId}:${investigation.result.generated_at}`, "AI investigation completed", `Network health: ${investigation.result.health}.`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigation]);

  // Live capture: finished, failed, or new findings. Polled only while some live-related notification is wanted.
  const wantsLive = saved.notifications.enabled && (saved.notifications.capture_completed || saved.notifications.capture_error || saved.notifications.critical_finding
    || saved.notifications.high_finding || saved.notifications.medium_finding);
  useEffect(() => {
    if (!wantsLive) return;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api.getLiveStatus();
        if (!alive) return;
        if (s.capture?.status === "COMPLETED" && s.state === "stopped") notify("capture_completed", `capture:${s.capture.id}`, "Capture completed", `${s.capture.filename} was saved (${s.capture.packets.toLocaleString()} packets).`);
        if (s.error && s.state !== "stopped") notify("capture_error", `capture-error:${s.started_at}:${s.error.code}`, "Capture problem", s.error.message);
        if (s.capture?.status === "FAILED" && s.capture.error) notify("capture_error", `capture-failed:${s.capture.id}`, "Capture not saved", s.capture.error);
        for (const ev of s.findings) {
          const kind = FINDING_KIND[ev.finding.severity];
          if (kind) notify(kind, `live-finding:${ev.finding.id}`, `${ev.finding.severity} finding`, ev.finding.title);
        }
      } catch { /* backend offline: the banner already says so */ }
    };
    const t = setInterval(tick, LIVE_POLL_MS);
    return () => { alive = false; clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, wantsLive]);

  return null;
}
