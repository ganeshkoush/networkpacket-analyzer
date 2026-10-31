import { lazy, Suspense } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./components/layout/Shell";
import { Spinner } from "./components/ui/feedback";
import { Captures } from "./pages/Captures";
import { Dashboard } from "./pages/Dashboard";
import { FindingDetail } from "./pages/FindingDetail";
import { Investigation } from "./pages/Investigation";
import { Findings } from "./pages/Findings";
import { LiveCapture } from "./pages/LiveCapture";
import { ReportDetail } from "./pages/ReportDetail";
import { Reports } from "./pages/Reports";
import { PcapAnalysis } from "./pages/PcapAnalysis";
import { NotFound } from "./pages/NotFound";
import { Settings } from "./pages/Settings";
import { WebActivity } from "./pages/WebActivity";
import { ApiProvider } from "./state/ApiContext";
import { AnalysisProvider } from "./state/AnalysisContext";
import { BackendProvider } from "./state/BackendContext";
import { InvestigationProvider } from "./state/InvestigationContext";
import { SettingsProvider } from "./state/SettingsContext";
import { NotificationWatcher } from "./components/notifications/NotificationWatcher";

// The graph library is only needed on this page, so it is loaded when the page is first opened.
const NetworkMap = lazy(() => import("./pages/NetworkMap").then((m) => ({ default: m.NetworkMap })));

export function AppRoutes() {
  return (
    <SettingsProvider>
    <InvestigationProvider>
    <NotificationWatcher />
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Dashboard />} />
        <Route path="analysis" element={<PcapAnalysis />} />
        <Route path="investigation" element={<Investigation />} />
        <Route path="web" element={<WebActivity />} />
        <Route path="map" element={<Suspense fallback={<Spinner label="Loading the network map…" />}><NetworkMap /></Suspense>} />
        <Route path="live" element={<LiveCapture />} />
        <Route path="captures" element={<Captures />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:id" element={<FindingDetail />} />
        <Route path="reports" element={<Reports />} />
        <Route path="reports/:id" element={<ReportDetail />} />
        <Route path="settings" element={<Navigate to="/settings/general" replace />} />
        <Route path="settings/:section" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
    </InvestigationProvider>
    </SettingsProvider>
  );
}

// HashRouter keeps routing working under Tauri's custom protocol without server-side fallbacks.
export default function App() {
  return (
    <ApiProvider>
      <BackendProvider>
        <AnalysisProvider>
          <HashRouter><AppRoutes /></HashRouter>
        </AnalysisProvider>
      </BackendProvider>
    </ApiProvider>
  );
}
