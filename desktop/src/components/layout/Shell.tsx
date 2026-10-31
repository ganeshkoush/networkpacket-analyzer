import { Component, Fragment, useEffect, useState, type ErrorInfo, type ReactNode } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useApi } from "../../state/ApiContext";
import { isManagedBackend } from "../../api/client";
import { useBackend } from "../../state/BackendContext";
import { useAnalysis } from "../../state/AnalysisContext";
import { countBySeverity } from "../../lib/severity";
import { Button, ErrorPanel } from "../ui/feedback";
import { formatBytes } from "../../lib/format";
import type { LiveStatus } from "../../api/types";

const icon = (d: ReactNode) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>{d}</svg>
);

type NavItem = { to: string; label: string; icon: ReactNode; group?: string };
const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: icon(<><rect x="3" y="3" width="7" height="9" /><rect x="14" y="3" width="7" height="5" /><rect x="14" y="12" width="7" height="9" /><rect x="3" y="16" width="7" height="5" /></>) },
  { group: "Network", to: "/live", label: "Live Capture", icon: icon(<><circle cx="12" cy="12" r="3" /><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2" /></>) },
  { to: "/web", label: "Web Activity", icon: icon(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>) },
  { to: "/map", label: "Network Map", icon: icon(<><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" /><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5l5.5 5.5" /></>) },
  { group: "Security", to: "/findings", label: "Findings", icon: icon(<><path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17.5v.5" /></>) },
  { to: "/investigation", label: "Investigate Network", icon: icon(<><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5M11 8v6M8 11h6" /></>) },
  { group: "Data", to: "/analysis", label: "PCAP Analysis", icon: icon(<><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><path d="M14 3v6h6M8 14h8M8 18h5" /></>) },
  { to: "/captures", label: "Captures", icon: icon(<><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></>) },
  { to: "/reports", label: "Reports", icon: icon(<><path d="M5 3h10l4 4v14H5z" /><path d="M9 13h6M9 17h6M9 9h3" /></>) },
  { group: "System", to: "/settings", label: "Settings", icon: icon(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>) },
];

function BackendBanner() {
  const { status, retry } = useBackend();
  if (status !== "offline") return null;
  return (
    <div role="alert" className="flex flex-wrap items-center gap-3 border-b border-sev-critical/40 bg-sev-critical/10 px-6 py-2.5 text-sm">
      <strong className="text-sev-critical">Backend unavailable.</strong>
      {isManagedBackend() ? (
        <span className="text-ink-2">PacketMind's analysis service stopped. PacketMind restarts it automatically; if this stays, quit and reopen PacketMind.</span>
      ) : (<>
        <span className="text-ink-2">PacketMind can't reach its local analysis service. Start it with</span>
        <code className="rounded bg-bg px-1.5 py-0.5 font-mono text-xs text-ink">cd backend &amp;&amp; .venv/bin/python main.py</code>
      </>)}
      <Button variant="secondary" onClick={retry} className="ml-auto">Retry now</Button>
    </div>
  );
}

/** Capture state as the backend reports it - nothing is shown as "capturing" until the backend says so. */
function CaptureState({ wide }: { wide: boolean }) {
  const api = useApi();
  const { status } = useBackend();
  const [live, setLive] = useState<LiveStatus["state"] | null>(null);
  useEffect(() => {
    if (status !== "online") { setLive(null); return; }
    let alive = true;
    const poll = () => api.getLiveStatus().then((s) => { if (alive) setLive(s.state); }).catch(() => { if (alive) setLive(null); });
    void poll();
    const t = setInterval(poll, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [api, status]);
  if (live !== "capturing") return null;
  return (
    <NavLink to="/live" title="Live capture is running" className="flex items-center gap-2 rounded-md text-xs font-medium text-sev-critical">
      <span className="relative flex h-2 w-2" aria-hidden><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sev-critical opacity-60" /><span className="relative inline-flex h-2 w-2 rounded-full bg-sev-critical" /></span>
      <span className={wide ? "hidden lg:inline" : "sr-only"}>Capturing</span>
      {wide && <span className="sr-only lg:hidden">Capturing</span>}
    </NavLink>
  );
}

function StatusDot({ wide }: { wide: boolean }) {
  const { status, info } = useBackend();
  const map = { online: ["bg-series-3", "Backend online"], offline: ["bg-sev-critical", "Backend offline"], checking: ["bg-sev-info", "Checking backend…"] } as const;
  const [color, label] = map[status];
  return (
    <div className="flex items-center gap-2 text-xs text-ink-2" title={info ? `${info.app} backend v${info.version}` : undefined}>
      <span className={`h-2 w-2 rounded-full ${color}`} aria-hidden /><span className={wide ? "hidden lg:inline" : "sr-only"}>{label}</span>
      {wide && <span className="sr-only lg:hidden">{label}</span>}
    </div>
  );
}

function CaptureChip() {
  const { session } = useAnalysis();
  if (session.phase === "idle") return <span className="text-xs text-ink-3">No capture loaded</span>;
  const name = session.phase === "error" ? session.filename : session.filename;
  const state = { uploading: "Uploading…", analyzing: "Analyzing…", ready: "", error: "Failed" }[session.phase];
  return (
    <span className="flex min-w-0 items-center gap-2 text-xs text-ink-2">
      <span className="truncate font-mono text-ink" title={name ?? undefined}>{name}</span>
      {session.phase === "ready" && <span className="text-ink-3">{formatBytes(session.size)}</span>}
      {state && <span className={session.phase === "error" ? "text-sev-critical" : "text-accent"}>{state}</span>}
    </span>
  );
}

const TITLES: [RegExp, string][] = [
  [/^\/analysis/, "PCAP Analysis"], [/^\/web/, "Domains / Web Activity"], [/^\/map/, "Network Map"], [/^\/investigation/, "Investigate Network"], [/^\/live/, "Live Capture"], [/^\/captures/, "Captures"], [/^\/findings/, "Findings"],
  [/^\/reports/, "Reports"], [/^\/settings/, "Settings"], [/^\/$/, "Dashboard"],
];

/** Keeps the window title meaningful and moves focus to the page on navigation (keyboard/screen-reader users). */
function useRouteAnnouncement() {
  const { pathname } = useLocation();
  useEffect(() => {
    document.title = `${TITLES.find(([re]) => re.test(pathname))?.[1] ?? "Not found"} · PacketMind`;
    document.getElementById("main")?.focus({ preventScroll: true });
  }, [pathname]);
}

/** A render error in one page must not blank the whole app; navigation stays usable. */
class PageBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("Page render failed", error, info.componentStack); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <ErrorPanel title="This page hit an unexpected error"
        actions={<><Button variant="secondary" onClick={() => this.setState({ error: null })}>Try again</Button><Link to="/" className="text-sm text-accent underline" onClick={() => this.setState({ error: null })}>Go to dashboard</Link></>}>
        Your loaded capture and saved reports are unaffected. <span className="font-mono text-xs">{this.state.error.message}</span>
      </ErrorPanel>
    );
  }
}

function PageOutlet() {
  const { pathname } = useLocation();
  return <PageBoundary key={pathname}><Outlet /></PageBoundary>;
}

function useSidebarWide(): [boolean, () => void] {
  const [wide, setWide] = useState(() => { try { return localStorage.getItem("pm.sidebar") !== "collapsed"; } catch { return true; } });
  const toggle = () => setWide((w) => { try { localStorage.setItem("pm.sidebar", w ? "collapsed" : "wide"); } catch { /* per-viewer convenience only */ } return !w; });
  return [wide, toggle];
}

export function Shell() {
  useRouteAnnouncement();
  const [wide, toggle] = useSidebarWide();
  const { session } = useAnalysis();
  const findingCount = session.phase === "ready" ? session.bundle.findings.length : 0;
  const worst = session.phase === "ready" ? countBySeverity(session.bundle.findings) : null;
  return (
    <div className="flex h-full">
      <a href="#main" onClick={(e) => { e.preventDefault(); document.getElementById("main")?.focus(); }}
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-1.5 focus:text-bg">Skip to content</a>
      <nav aria-label="Main" className={`flex shrink-0 flex-col border-r border-line bg-surface transition-[width] duration-150 ${wide ? "w-14 lg:w-56" : "w-14"}`}>
        <div className="flex h-14 items-center gap-2 border-b border-line px-3.5">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M3 12h4l3-8 4 16 3-8h4" /></svg>
          <span className={`text-[15px] font-semibold tracking-tight ${wide ? "hidden lg:inline" : "hidden"}`}>PacketMind</span>
        </div>
        <ul className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {NAV.map((n) => (
            <Fragment key={n.to}>
            {n.group && <li role="presentation" aria-hidden className={`px-2.5 pb-1 pt-3.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-ink-3 ${wide ? "hidden lg:block" : "hidden"}`}>{n.group}</li>}
            <li>
              <NavLink to={n.to} end={n.to === "/"} title={n.label}
                className={({ isActive }) => `relative flex items-center gap-3 rounded-md px-2.5 py-2 text-[13.5px] transition-colors duration-150 ${isActive ? "bg-surface-2 text-ink before:absolute before:inset-y-1.5 before:-left-2 before:w-0.5 before:rounded-full before:bg-accent" : "text-ink-2 hover:bg-surface-2/60 hover:text-ink"}`}>
                {n.icon}
                <span className={`flex-1 ${wide ? "hidden lg:inline" : "hidden"}`}>{n.label}</span>
                {n.to === "/findings" && findingCount > 0 && (
                  <span className={`rounded bg-surface-2 px-1.5 font-mono text-[11px] text-ink ${wide ? "hidden lg:inline" : "hidden"}`} aria-label={`${findingCount} findings`}>{findingCount}</span>
                )}
              </NavLink>
            </li>
            </Fragment>
          ))}
        </ul>
        <div className="space-y-2 border-t border-line p-3">
          <CaptureState wide={wide} />
          <StatusDot wide={wide} />
          <button type="button" onClick={toggle} aria-pressed={!wide} aria-label={wide ? "Collapse sidebar" : "Expand sidebar"} title={wide ? "Collapse sidebar" : "Expand sidebar"}
            className="hidden w-full items-center gap-2 rounded-md px-1 py-1 text-xs text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink lg:flex">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden className={wide ? "" : "rotate-180"}><path d="m11 17-5-5 5-5M18 17l-5-5 5-5" /></svg>
            {wide && <span>Collapse</span>}
          </button>
        </div>
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface px-6">
          <CaptureChip />
          {worst && findingCount > 0 && (
            <span className="text-xs text-ink-2">{findingCount} finding{findingCount === 1 ? "" : "s"}</span>
          )}
        </header>
        <BackendBanner />
        <main id="main" tabIndex={-1} className="min-h-0 flex-1 overflow-y-auto px-6 py-6 outline-none"><div className="mx-auto max-w-[1280px]"><PageOutlet /></div></main>
      </div>
    </div>
  );
}
