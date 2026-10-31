import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { BarList } from "../components/charts/BarList";
import { ProtocolChart } from "../components/charts/ProtocolChart";
import { TimelineChart } from "../components/charts/TimelineChart";
import {
  ActivityList, ConnectionsTable, FindingsTable, HealthScoreCard, KpiGrid, RangeControl, SectionCard, SectionTabs, SlowestTable, TopDomainsTable, type Section,
} from "../components/dashboard/parts";
import { InvestigateButton } from "../components/investigation/InvestigateButton";
import { SaveReportButton } from "../components/reports/SaveReportButton";
import { AnomalyCard } from "../components/web/AnomalyCard";
import { Card } from "../components/ui/Card";
import { Button, EmptyState, ErrorPanel, linkButtonClass, Notice, ProgressBar, Spinner } from "../components/ui/feedback";
import { HEALTH_STYLE } from "../lib/investigation";
import { formatBytes, formatNumber, formatTime } from "../lib/format";
import type { DashboardData, DashboardRange, LiveStatus, TimelinePoint } from "../api/types";
import { useApi } from "../state/ApiContext";
import { useAnalysis } from "../state/AnalysisContext";
import { useInvestigation } from "../state/InvestigationContext";
import { useDashboard, type DashboardSource } from "../state/useDashboard";
import { PageHeader } from "./Placeholder";

/** Dashboard bins as the points the existing timeline chart draws. */
function toPoints(d: DashboardData): TimelinePoint[] {
  const t0 = d.timeline[0]?.start_time ?? 0;
  return d.timeline.map((b) => ({ start_time: b.start_time, offset_seconds: b.start_time - t0, interval_seconds: b.interval_seconds, packets: b.packets, bytes: b.bytes, packets_per_second: b.packets / Math.max(1, b.interval_seconds) }));
}

function useLiveCapturing(): boolean {
  const api = useApi();
  const [live, setLive] = useState<LiveStatus["state"]>("stopped");
  useEffect(() => {
    let alive = true;
    const poll = () => api.getLiveStatus().then((s) => { if (alive) setLive(s.state); }).catch(() => undefined);
    void poll();
    const t = setInterval(poll, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [api]);
  return live === "capturing";
}

function Timeline({ d }: { d: DashboardData }) {
  if (!d.timeline.length) return <p className="text-sm text-ink-3">No traffic in this range.</p>;
  return (
    <>
      <TimelineChart points={toPoints(d)} />
      {d.markers.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2" aria-label="Events on the timeline">
          {d.markers.slice(0, 6).map((m, i) => <li key={i}><span className="font-mono text-ink-3">{formatTime(m.time).slice(11, 19)}</span> {m.label}</li>)}
        </ul>
      )}
    </>
  );
}

function Overview({ d, open, analysis }: { d: DashboardData; open: (s: Section) => void; analysis: ReturnType<typeof useAnalysis>["session"] }) {
  const a = analysis.phase === "ready" && d.source === "capture" ? analysis.bundle.analysis : null;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <HealthScoreCard health={d.health} />
        <KpiGrid k={d.kpis} onOpen={open} />
      </div>
      <Card title="Network timeline" subtitle={d.window.start ? `${formatTime(d.window.start)} → ${formatTime(d.window.end)}` : undefined}><Timeline d={d} /></Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <SectionCard title="Top domains" subtitle="By traffic" actions={<button type="button" className="text-xs text-accent hover:underline" onClick={() => open("Domains")}>View all</button>}>
          <TopDomainsTable rows={d.top_domains.slice(0, 5)} />
        </SectionCard>
        <SectionCard title="Slowest services" subtitle="By average RTT" actions={<button type="button" className="text-xs text-accent hover:underline" onClick={() => open("Performance")}>View all</button>}>
          <SlowestTable rows={d.slowest_domains.slice(0, 5)} />
        </SectionCard>
      </div>
      <SectionCard title="Recent findings" actions={<Link to="/findings" className="text-xs text-accent hover:underline">All findings</Link>}><FindingsTable rows={d.findings.slice(0, 5)} /></SectionCard>
      <div className="grid gap-4 xl:grid-cols-2">
        <SectionCard title="Suspicious connections" subtitle="Connections with an endpoint named by a finding. Possible, requires investigation.">
          <ConnectionsTable caption="Suspicious connections" rows={d.suspicious_connections.slice(0, 5)} empty="No connection has an endpoint named by a finding." />
        </SectionCard>
        <SectionCard title="Recent activity"><ActivityList items={d.recent_activity} /></SectionCard>
      </div>
      {a && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Protocol distribution"><ProtocolChart distribution={a.protocol_statistics.distribution} /></Card>
          <Card title="Top destination ports" subtitle="By packets · service names are conventions, not proof of content">
            <BarList ariaLabel="Top destination ports" empty="No TCP/UDP traffic."
              items={a.port_statistics.top_destination_ports.slice(0, 8).map((p) => ({
                key: `${p.protocol}-${p.port}`,
                label: <span><span className="font-mono">{p.port}</span> <span className="text-ink-3">{p.protocol}{p.service_hint ? ` · ${p.service_hint}` : ""}</span></span>,
                value: p.packets, valueLabel: formatNumber(p.packets),
              }))} />
          </Card>
          <Card title="Top source IPs" subtitle="By bytes sent">
            <BarList ariaLabel="Top source IPs" empty="No IP traffic."
              items={a.ip_statistics.top_sources.slice(0, 8).map((s) => ({ key: s.ip, label: <span className="font-mono">{s.ip}{s.is_private ? "" : <span className="ml-2 text-xs text-ink-3">public</span>}</span>, value: s.bytes, valueLabel: formatBytes(s.bytes), sub: `${formatNumber(s.packets)} packets` }))} />
          </Card>
          <Card title="Top destination IPs" subtitle="By bytes received">
            <BarList ariaLabel="Top destination IPs" empty="No IP traffic."
              items={a.ip_statistics.top_destinations.slice(0, 8).map((s) => ({ key: s.ip, label: <span className="font-mono">{s.ip}{s.is_private ? "" : <span className="ml-2 text-xs text-ink-3">public</span>}</span>, value: s.bytes, valueLabel: formatBytes(s.bytes), sub: `${formatNumber(s.packets)} packets` }))} />
          </Card>
        </div>
      )}
    </div>
  );
}

function Panel({ section, d, analysisId, defaultTitle, open }: { section: Exclude<Section, "Overview">; d: DashboardData; analysisId: string | null; defaultTitle: string; open: (s: Section) => void }) {
  const inv = useInvestigation();
  switch (section) {
    case "Domains":
      return (
        <div className="space-y-4">
          <SectionCard title="Top domains" subtitle="By traffic. Domains are inferred from DNS lookups, never read from the traffic." actions={<Link to="/web" className="text-xs text-accent hover:underline">Open Domains / Web Activity</Link>}>
            <TopDomainsTable rows={d.top_domains} />
          </SectionCard>
          <SectionCard title="Slowest services"><SlowestTable rows={d.slowest_domains} /></SectionCard>
        </div>
      );
    case "Connections":
      return (
        <div className="space-y-4">
          <SectionCard title="Active connections" subtitle="Largest first. TCP connections not yet closed or reset; UDP flows seen in the last seconds of the range.">
            <ConnectionsTable caption="Active connections" rows={d.active_connections} empty="No active connections in this range." />
          </SectionCard>
          <SectionCard title="Suspicious connections" subtitle="An endpoint is named by a finding: possible, requires investigation.">
            <ConnectionsTable caption="Suspicious connections" rows={d.suspicious_connections} showReasons empty="No connection has an endpoint named by a finding." />
          </SectionCard>
        </div>
      );
    case "Performance":
      return (
        <div className="space-y-4">
          <KpiGrid k={d.kpis} onOpen={open} />
          <SectionCard title="Slowest services"><SlowestTable rows={d.slowest_domains} /></SectionCard>
          <SectionCard title="Performance anomalies" subtitle="Compared with this computer's own earlier captures. Possible, not a diagnosis.">
            {d.anomalies.length === 0
              ? <p className="text-sm text-ink-3">No performance anomalies. Anomalies need at least five earlier captures of the same domain.</p>
              : <div className="space-y-3">{[...new Set(d.anomalies.map((x) => x.domain))].map((dom) => <AnomalyCard key={dom} domain={dom} anomalies={d.anomalies.filter((x) => x.domain === dom)} />)}</div>}
          </SectionCard>
        </div>
      );
    case "Security":
      return (
        <div className="space-y-4">
          <SectionCard title="Recent findings" actions={<Link to="/findings" className="text-xs text-accent hover:underline">All findings</Link>}><FindingsTable rows={d.findings} /></SectionCard>
          <SectionCard title="Suspicious connections" subtitle="Possible, requires investigation. PacketMind never blocks anything.">
            <ConnectionsTable caption="Suspicious connections" rows={d.suspicious_connections} showReasons empty="No connection has an endpoint named by a finding." />
          </SectionCard>
        </div>
      );
    case "AI Investigation": {
      const done = inv.state.phase === "done" && inv.state.analysisId === analysisId ? inv.state.result : null;
      const h = done ? HEALTH_STYLE[done.health] : null;
      return (
        <SectionCard title="AI investigation" subtitle="PacketMind measures locally, then asks Gemini to analyse a summary. Analysis and recommendations only.">
          {!analysisId ? <p className="text-sm text-ink-2">AI investigation works on a saved capture. Analyze a capture file to use it.</p> : (
            <div className="space-y-3">
              {done && h && (
                <div className={`rounded-md border p-3 ${h.border} ${h.bg}`}>
                  <div className={`text-xl font-bold ${h.text}`}>{h.label}</div>
                  {done.report?.main_issue && <p className="mt-1 text-sm">{done.report.main_issue}</p>}
                  <p className="mt-1 text-xs text-ink-3">Confidence {done.confidence}</p>
                </div>
              )}
              <div className="flex flex-wrap gap-2">
                <InvestigateButton analysisId={analysisId} />
                {done && <Link to="/investigation" className={linkButtonClass()}>Open the full investigation</Link>}
              </div>
            </div>
          )}
        </SectionCard>
      );
    }
    case "Network Map":
      return (
        <SectionCard title="Network map" subtitle="Local host → domains → IP addresses → ports, drawn from this capture.">
          <p className="mb-3 text-sm text-ink-2">{formatNumber(d.kpis.domains_contacted)} domains and {formatNumber(d.kpis.connections_in_window)} connections in this range.</p>
          {analysisId ? <Link to="/map" className={linkButtonClass("primary")}>Open the network map</Link> : <p className="text-sm text-ink-3">The map works on a saved capture.</p>}
        </SectionCard>
      );
    case "Reports":
      return (
        <SectionCard title="Reports" subtitle="Save this investigation as a report you can reopen and export.">
          <div className="flex flex-wrap items-center gap-3">
            {analysisId ? <SaveReportButton source="analysis" analysisId={analysisId} defaultTitle={defaultTitle} /> : <p className="text-sm text-ink-3">Reports are saved from an analyzed capture or from the Live Capture page.</p>}
            <Link to="/reports" className={linkButtonClass()}>Open saved reports</Link>
          </div>
        </SectionCard>
      );
  }
}

export function Dashboard() {
  const { session } = useAnalysis();
  const liveCapturing = useLiveCapturing();
  const [range, setRange] = useState<DashboardRange>("all");
  const [section, setSection] = useState<Section>("Overview");
  const [choice, setChoice] = useState<"capture" | "live" | null>(null);

  const analysisId = session.phase === "ready" ? session.bundle.job.id : null;
  const kind: "capture" | "live" | null = choice === "live" && liveCapturing ? "live" : choice === "capture" && analysisId ? "capture" : analysisId ? "capture" : liveCapturing ? "live" : null;
  const source: DashboardSource | null = useMemo(() => kind === "live" ? { kind: "live" } : kind === "capture" && analysisId ? { kind: "capture", analysisId } : null, [kind, analysisId]);
  const { data, loading, error, reload } = useDashboard(source, range);

  if (session.phase === "uploading" || session.phase === "analyzing") {
    const pct = session.phase === "analyzing" ? session.job.progress_percent : null;
    return (
      <>
        <PageHeader title="Dashboard" />
        <Card><div className="space-y-3"><Spinner label={`Analyzing ${session.filename}…`} /><ProgressBar percent={pct} label="Analysis progress" /></div></Card>
      </>
    );
  }
  if (!source) {
    return (
      <>
        <PageHeader title="Dashboard" subtitle="Network intelligence for the current capture" />
        <EmptyState title={session.phase === "error" ? "The last analysis failed" : "No capture analyzed yet"}
          action={<Link to="/analysis" className={linkButtonClass("primary")}>Open PCAP Analysis</Link>}>
          {session.phase === "error" ? session.problem.message : "Analyze a PCAP or PCAPNG file, or start a live capture, to see network health, domains, latency and findings here."}
        </EmptyState>
      </>
    );
  }

  const subtitle = source.kind === "live" ? "Live capture · rolling window" : session.phase === "ready" ? session.bundle.analysis.metadata.file_name : "";
  const actions = (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {analysisId && liveCapturing && (
        <div role="group" aria-label="Data source" className="inline-flex overflow-hidden rounded-md border border-line text-xs">
          {(["capture", "live"] as const).map((k) => (
            <button key={k} type="button" aria-pressed={kind === k} onClick={() => setChoice(k)} className={`px-3 py-1.5 font-medium ${kind === k ? "bg-accent text-bg" : "bg-surface-2 text-ink-2"}`}>{k === "capture" ? "Capture file" : "Live capture"}</button>
          ))}
        </div>
      )}
      {source.kind === "capture" && data && !data.empty && <InvestigateButton analysisId={source.analysisId} />}
      {source.kind === "capture" && <Link to="/analysis" className={linkButtonClass()}>Analyze another capture</Link>}
    </div>
  );

  return (
    <>
      <PageHeader title="Dashboard" subtitle={subtitle} actions={actions} />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <RangeControl value={range} onChange={setRange} disabled={loading && !data} />
        {loading && data && <Spinner label="Updating…" />}
        {data?.window.start && <span className="text-xs text-ink-3">{formatTime(data.window.start)} → {formatTime(data.window.end)}</span>}
      </div>
      {error && <div className="mb-3"><ErrorPanel title="The dashboard could not be loaded" actions={<Button onClick={reload}>Try again</Button>}>{error}</ErrorPanel></div>}
      {!data && !error && <Card><Spinner label="Loading the dashboard…" /></Card>}
      {data && (
        <>
          {data.window.note && <div className="mb-3"><Notice tone="info">{data.window.note}</Notice></div>}
          {session.phase === "ready" && source.kind === "capture" && session.bundle.analysis.metadata.warnings.map((w) => <div key={w} className="mb-3"><Notice>{w}</Notice></div>)}
          {data.empty ? (
            <EmptyState title={source.kind === "live" ? "No live traffic captured yet" : "This capture contains no packets"}>
              {source.kind === "live" ? "Packets will appear here as the rolling window fills." : "The file is a valid capture but has no packets to analyze. Check that the capture was running on the right interface or that a filter did not discard everything."}
            </EmptyState>
          ) : (
            <>
              <SectionTabs value={section} onChange={setSection} />
              <div id="dashboard-panel" role="tabpanel" aria-labelledby={`tab-${section}`}>
                {section === "Overview"
                  ? <Overview d={data} open={setSection} analysis={session} />
                  : <Panel section={section} d={data} analysisId={source.kind === "capture" ? source.analysisId : null} open={setSection}
                      defaultTitle={`Investigation of ${session.phase === "ready" ? session.bundle.analysis.metadata.file_name : "capture"}`} />}
              </div>
              <details className="mt-4 text-xs text-ink-3"><summary className="cursor-pointer">About these numbers</summary><ul className="mt-1 list-disc space-y-0.5 pl-5">{data.notes.map((n) => <li key={n}>{n}</li>)}</ul></details>
            </>
          )}
        </>
      )}
    </>
  );
}
