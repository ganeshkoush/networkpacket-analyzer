import { useState, type ComponentType } from "react";
import { NavLink, Navigate, useParams } from "react-router-dom";
import { AdvancedSection, AboutSection, AiSection, AiUsageSection, DatabaseSection, DiagnosticsSection, NotificationsSection, SecuritySection, StorageSection } from "../components/settings/sections2";
import { AnalysisSection, CaptureSection, DetectionSection, DomainsSection, GeneralSection, NetworkSection, PerformanceSection, PrivacySection } from "../components/settings/sections";
import { SaveBar } from "../components/settings/controls";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Button, ErrorPanel, Notice, Spinner } from "../components/ui/feedback";
import { useSettings } from "../state/SettingsContext";
import { PageHeader } from "./Placeholder";

interface Def { id: string; key: string | null; title: string; description: string; Body: ComponentType; resettable?: boolean }

export const SETTINGS_SECTIONS: Def[] = [
  { id: "general", key: "general", title: "General", description: "Appearance, notifications and your settings file.", Body: GeneralSection },
  { id: "capture", key: "capture", title: "Capture", description: "How live capture records traffic.", Body: CaptureSection },
  { id: "network", key: "network", title: "Network", description: "Network interfaces and how one is chosen.", Body: NetworkSection },
  { id: "analysis", key: "analysis", title: "Analysis", description: "What PacketMind works out from captures.", Body: AnalysisSection },
  { id: "detection", key: "detection", title: "Detection", description: "Threat detectors and their thresholds.", Body: DetectionSection },
  { id: "performance", key: "performance", title: "Performance", description: "Latency, baselines and what counts as slow.", Body: PerformanceSection },
  { id: "domains", key: "domains", title: "Domains", description: "Domain and web activity tracking.", Body: DomainsSection },
  { id: "privacy", key: "privacy", title: "Privacy", description: "What is stored, and what AI can see.", Body: PrivacySection },
  { id: "ai", key: "ai", title: "AI / Gemini", description: "Gemini model, API key and automatic investigation.", Body: AiSection },
  { id: "ai-usage", key: "ai_usage", title: "AI Usage", description: "Request limits and caching.", Body: AiUsageSection },
  { id: "notifications", key: "notifications", title: "Notifications", description: "Which events notify you.", Body: NotificationsSection },
  { id: "storage", key: "storage", title: "Storage", description: "Disk use, limits and cleanup.", Body: StorageSection },
  { id: "database", key: null, title: "Database", description: "Backup, restore and history.", Body: DatabaseSection },
  { id: "diagnostics", key: "diagnostics", title: "Diagnostics", description: "Logging and support tools.", Body: DiagnosticsSection },
  { id: "security", key: "security", title: "Security", description: "Safety controls and AI permissions.", Body: SecuritySection },
  { id: "advanced", key: "advanced", title: "Advanced", description: "Troubleshooting options.", Body: AdvancedSection },
  { id: "about", key: null, title: "About", description: "Versions and system check.", Body: AboutSection },
];

export function Settings() {
  const { section = "general" } = useParams();
  const { loading, loadError, reload, reset, saving, dirty } = useSettings();
  const [confirmReset, setConfirmReset] = useState(false);
  const def = SETTINGS_SECTIONS.find((s) => s.id === section);
  if (!def) return <Navigate to="/settings/general" replace />;
  const { Body } = def;

  return (
    <>
      <PageHeader title="Settings" subtitle="Changes are saved together with Save Changes, and checked before anything is applied." />
      {loadError && <div className="mb-4"><ErrorPanel title="Could not load settings" actions={<Button onClick={reload}>Try again</Button>}>{loadError} Showing the default values.</ErrorPanel></div>}
      <div className="flex flex-col gap-6 md:flex-row">
        <nav aria-label="Settings sections" className="md:w-52 md:shrink-0">
          <ul className="flex gap-1 overflow-x-auto md:flex-col">
            {SETTINGS_SECTIONS.map((s) => (
              <li key={s.id}>
                <NavLink to={`/settings/${s.id}`} className={({ isActive }) => `block whitespace-nowrap rounded-md px-3 py-1.5 text-sm ${isActive ? "bg-surface-2 font-medium text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"}`}>{s.title}</NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 flex-1" role="region" aria-label={`${def.title} settings`}>
          <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div><h2 className="text-lg font-semibold">{def.title}</h2><p className="text-sm text-ink-2">{def.description}</p></div>
            {def.key && <Button onClick={() => setConfirmReset(true)} disabled={saving}>Reset Section</Button>}
          </div>
          {loading ? <Spinner label="Loading settings…" /> : <Body />}
          <SaveBar />
          {dirty && <p className="mt-2 text-xs text-ink-3">Switching sections keeps your unsaved changes until you save or cancel.</p>}
        </div>
      </div>
      {confirmReset && def.key && (
        <ConfirmDialog title={`Reset ${def.title} settings?`} confirmLabel="Reset section" danger onCancel={() => setConfirmReset(false)} busy={saving}
          onConfirm={async () => { await reset(def.key); setConfirmReset(false); }}>
          <p>This will restore PacketMind settings in this section to their default values. Captures, reports, findings and the database are not deleted.</p>
        </ConfirmDialog>
      )}
      <Notice tone="info">PacketMind never lets AI run commands, change your firewall or network, or delete files. See Security → AI Permissions.</Notice>
    </>
  );
}
