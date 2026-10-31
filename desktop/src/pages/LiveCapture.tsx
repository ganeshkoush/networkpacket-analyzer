import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { CaptureFormat, InterfaceInfo, InterfaceKind, LiveFindingEvent } from "../api/types";
import { CaptureCompleted } from "../components/captures/CaptureCompleted";
import { BarList } from "../components/charts/BarList";
import { LiveIndicator } from "../components/live/LiveIndicator";
import { Card, StatTile } from "../components/ui/Card";
import { ConfidenceMeter } from "../components/ui/ConfidenceMeter";
import { DataTable, Mono, type Column } from "../components/ui/DataTable";
import { Button, ErrorPanel, Notice, Spinner } from "../components/ui/feedback";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { formatBytes, formatClockDuration, formatDuration, formatNumber } from "../lib/format";
import { typeLabel } from "../lib/severity";
import { useApi } from "../state/ApiContext";
import { useSettings } from "../state/SettingsContext";
import { useLiveCapture } from "../state/useLiveCapture";
import { SaveReportButton } from "../components/reports/SaveReportButton";
import { PageHeader } from "./Placeholder";

const KIND_LABEL: Record<InterfaceKind, string> = {
  wifi: "Wi-Fi", ethernet: "Ethernet", vpn: "VPN", loopback: "Loopback", other: "Other",
};
const KIND_ORDER: InterfaceKind[] = ["wifi", "ethernet", "vpn", "loopback", "other"];

/** The interface to preselect: the default from Settings → Network/Capture, else (if enabled) the first active Wi-Fi or Ethernet one. */
export function preferredInterface(interfaces: InterfaceInfo[], preferred: string, autoSelect: boolean): string {
  if (preferred && interfaces.some((i) => i.name === preferred)) return preferred;
  if (!autoSelect) return "";
  const active = (kind: InterfaceKind) => interfaces.find((i) => i.kind === kind && i.is_up && i.addresses.length > 0);
  return (active("wifi") ?? active("ethernet"))?.name ?? "";
}

function InterfacePicker({ interfaces, value, onChange, disabled }: {
  interfaces: InterfaceInfo[]; value: string; onChange: (v: string) => void; disabled: boolean;
}) {
  const showInactive = useSettings().saved.network.show_inactive_interfaces;
  return (
    <select
      aria-label="Network interface" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}
      className="min-w-64 rounded-md border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink disabled:opacity-60"
    >
      <option value="">Select an interface…</option>
      {KIND_ORDER.map((k) => {
        const group = interfaces.filter((i) => i.kind === k && (showInactive || i.is_up !== false || i.name === value));
        if (group.length === 0) return null;
        return (
          <optgroup key={k} label={KIND_LABEL[k]}>
            {group.map((i) => (
              <option key={i.name} value={i.name}>
                {i.name}{i.addresses[0] ? ` — ${i.addresses[0]}` : ""}{i.description && i.description !== i.name ? ` (${i.description})` : ""}
              </option>
            ))}
          </optgroup>
        );
      })}
    </select>
  );
}

function InvestigationView({ ev }: { ev: LiveFindingEvent }) {
  const inv = ev.investigation;
  if (!inv) return null;
  if (inv.status === "pending") return <p className="mt-2 text-xs text-ink-2"><Spinner label="AI investigation in progress…" /></p>;
  if (inv.status === "failed" || !inv.report)
    return <p className="mt-2 text-xs text-sev-medium">AI investigation unavailable: {inv.error?.message ?? "unknown error"}</p>;
  const r = inv.report.result;
  return (
    <div className="mt-3 rounded-md border border-line bg-surface-2 p-3 text-[13px]" aria-label="AI investigation">
      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">AI investigation ({inv.report.model})</div>
      <p>{r.investigation_summary}</p>
      <p className="mt-1 text-ink-2">{r.interpretation}</p>
      {r.recommended_next_steps.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-5 text-ink-2">{r.recommended_next_steps.map((s) => <li key={s}>{s}</li>)}</ul>
      )}
      {r.limitations.length > 0 && <p className="mt-2 text-xs text-ink-3">Limitations: {r.limitations.join(" ")}</p>}
    </div>
  );
}

function FindingRow({ ev }: { ev: LiveFindingEvent }) {
  const f = ev.finding;
  return (
    <li className="rounded-md border border-line p-3">
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={f.severity} />
        <span className="font-medium">{typeLabel(f.type)}</span>
        <ConfidenceMeter value={f.confidence} />
        <span className={`ml-auto text-xs ${ev.active ? "text-sev-high" : "text-ink-3"}`}>{ev.active ? "Active in current window" : "No longer in window"}</span>
      </div>
      <p className="mt-1.5 text-sm">{f.title}</p>
      <p className="mt-0.5 text-[13px] text-ink-2">{f.description}</p>
      <p className="mt-1 text-xs text-ink-3">Next step: {f.recommendation}</p>
      <InvestigationView ev={ev} />
    </li>
  );
}

export function LiveCapture({ api }: { api?: Parameters<typeof useLiveCapture>[0] } = {}) {
  const contextApi = useApi();
  const { interfaces, status, backendDown, actionError, busy, start, stop } = useLiveCapture(api ?? contextApi);
  const { saved } = useSettings();
  const [iface, setIface] = useState("");
  const [auto, setAuto] = useState(false);
  const [save, setSave] = useState(saved.capture.auto_save);
  const [format, setFormat] = useState<CaptureFormat>(saved.capture.format);
  const touched = useRef({ iface: false, save: false, format: false });
  // Start from the defaults in Settings until the user changes a control here.
  useEffect(() => {
    if (!touched.current.iface && interfaces) setIface(preferredInterface(interfaces, saved.capture.default_interface, saved.network.auto_select_interface));
    if (!touched.current.save) setSave(saved.capture.auto_save);
    if (!touched.current.format) setFormat(saved.capture.format);
  }, [interfaces, saved.capture.default_interface, saved.capture.auto_save, saved.capture.format, saved.network.auto_select_interface]);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const capturing = status.state === "capturing";
  const error = actionError ?? status.error;
  const isPermission = status.state === "permission_error" || error?.code === "permission_denied";

  const talkerCols: Column<(typeof status.top_talkers)[number]>[] = [
    { header: "Host", cell: (t) => <Mono>{t.ip}</Mono> },
    { header: "Packets", align: "right", cell: (t) => formatNumber(t.total_packets) },
    { header: "Bytes", align: "right", cell: (t) => formatBytes(t.total_bytes) },
  ];

  return (
    <>
      <PageHeader
        title="Live Capture"
        subtitle="Passively observe traffic on one interface, analyse a rolling window locally, and surface suspicious events."
        actions={<LiveIndicator state={backendDown ? "stopped" : status.state} />}
      />
      {backendDown && <div className="mb-4"><ErrorPanel title="Backend unavailable">Start the PacketMind backend, then this page will reconnect.</ErrorPanel></div>}

      <Card title="Capture" className="mb-4">
        <div className="flex flex-wrap items-end gap-4">
          <label className="text-xs font-medium uppercase tracking-wide text-ink-3">
            <span className="mb-1 block">Interface</span>
            {interfaces === null ? <Spinner label="Loading interfaces…" /> :
              <InterfacePicker interfaces={interfaces} value={capturing ? status.interface ?? iface : iface} onChange={(v) => { touched.current.iface = true; setIface(v); }} disabled={capturing || busy} />}
          </label>
          {capturing
            ? <Button variant="primary" onClick={stop} disabled={busy}>Stop capture</Button>
            : <Button variant="primary" onClick={() => { setDismissed(null); void start(iface, auto, { save: save !== saved.capture.auto_save ? save : undefined, format: format !== saved.capture.format ? format : undefined }); }} disabled={!iface || busy || backendDown}>Start capture</Button>}
        </div>
        <label className="mt-3 flex items-start gap-2 text-sm text-ink-2">
          <input type="checkbox" className="mt-1" checked={capturing ? status.auto_investigate : auto} disabled={capturing || busy}
            onChange={(e) => setAuto(e.target.checked)} />
          <span>
            Automatically investigate suspicious events with AI. When enabled, <em>only aggregated evidence about an
            event</em> (never packets) is sent to the configured AI provider, and only when a finding crosses the
            severity/confidence thresholds. Off by default.
          </span>
        </label>
        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-ink-2">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={capturing ? status.capture != null : save} disabled={capturing || busy} onChange={(e) => { touched.current.save = true; setSave(e.target.checked); }} />
            Save the packets to a capture file
          </label>
          <label className="flex items-center gap-2">
            Format
            <select aria-label="Capture file format" value={format} disabled={capturing || busy || !save} onChange={(e) => { touched.current.format = true; setFormat(e.target.value as CaptureFormat); }}
              className="rounded-md border border-line bg-surface-2 px-2 py-1 text-sm text-ink disabled:opacity-60">
              <option value="pcap">.pcap</option>
              <option value="pcapng">.pcapng</option>
            </select>
          </label>
        </div>
        <p className="mt-3 text-xs text-ink-3">
          Capture starts only when you click Start. It is passive: no packets are sent, modified or blocked.
          {" "}When saving is on, packets are written to a standard capture file in PacketMind&apos;s private capture folder on this computer
          (see <Link to="/captures" className="text-accent hover:underline">Captures</Link>). Captured traffic can contain sensitive information;
          the file is never sent to the AI provider, which only receives summaries of PacketMind&apos;s local analysis.
        </p>
      </Card>

      {status.notice && !capturing && <div className="mb-4"><Notice tone="info">{status.notice}</Notice></div>}
      {error && (
        <div className="mb-4">
          <ErrorPanel title={isPermission ? "⚠ Permission error" : "Capture problem"}>
            <p>{error.message}</p>
            {error.hint && <p className="mt-1.5 font-mono text-xs">{error.hint}</p>}
          </ErrorPanel>
        </div>
      )}

      {capturing && status.capture && (
        <Card title="Live capture" className="mb-4">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[max-content_1fr_max-content_1fr]" aria-label="Capture details">
            <dt className="text-ink-3">Interface</dt><dd>{status.interface}</dd>
            <dt className="text-ink-3">Status</dt><dd className={status.capture.error ? "text-sev-critical" : "text-sev-high"}>{status.capture.error ? "● Problem saving" : "● Capturing"}</dd>
            <dt className="text-ink-3">Packets</dt><dd className="font-mono">{formatNumber(status.capture.packets)}</dd>
            <dt className="text-ink-3">Data</dt><dd className="font-mono">{formatBytes(status.capture.bytes)}</dd>
            <dt className="text-ink-3">Duration</dt><dd className="font-mono">{formatClockDuration(status.elapsed_seconds)}</dd>
            <dt className="text-ink-3">Current capture file</dt><dd className="break-all font-mono text-[13px]">{status.capture.filename}</dd>
          </dl>
        </Card>
      )}
      {!capturing && status.capture && status.capture.id !== dismissed && (
        <CaptureCompleted file={status.capture} interfaceLabel={status.interface} onDeleted={() => setDismissed(status.capture!.id)} />
      )}

      {(capturing || status.packets_total > 0) && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile label="Packets" value={formatNumber(status.packets_total)} sub={formatBytes(status.bytes_total)} />
            <StatTile label="Packets / s" value={status.packets_per_second.toFixed(1)} sub="recent average" />
            <StatTile label="Bit rate" value={`${formatBytes(status.bits_per_second / 8)}/s`} sub="recent average" />
            <StatTile label="Elapsed" value={formatDuration(status.elapsed_seconds)} sub={`window: ${formatNumber(status.window_packets)} pkts`} />
          </div>
          {status.window_truncated && <div className="mb-4"><Notice>The rolling window hit its packet cap, so it covers less than the configured time. Detection still runs on what is kept.</Notice></div>}
          <div className="mb-4 grid gap-4 lg:grid-cols-3">
            <Card title="Protocols" subtitle="rolling window">
              <BarList ariaLabel="Protocol statistics" empty="Waiting for traffic…"
                items={status.protocols.map((p) => ({ key: p.protocol, label: p.protocol, value: p.packets, valueLabel: `${formatNumber(p.packets)} · ${p.percent_of_packets.toFixed(0)}%` }))} />
            </Card>
            <Card title="Top talkers" subtitle="rolling window" padded={false}>
              <DataTable columns={talkerCols} rows={status.top_talkers.slice(0, 8)} rowKey={(t) => t.ip} empty="Waiting for traffic…" caption="Top talkers" />
            </Card>
            <Card title="Top ports" subtitle="destination, rolling window">
              <BarList ariaLabel="Top ports" empty="Waiting for traffic…"
                items={status.top_ports.slice(0, 8).map((p) => ({ key: `${p.protocol}/${p.port}`, label: `${p.protocol}/${p.port}${p.service_hint ? ` · ${p.service_hint}` : ""}`, value: p.packets, valueLabel: formatNumber(p.packets) }))} />
            </Card>
          </div>
          <Card title="Findings" subtitle="Possible issues, with evidence. These are hypotheses to check, not verdicts."
            actions={status.window_packets > 0 ? <SaveReportButton source="live" label="Save report" defaultTitle={`Live capture on ${status.interface ?? "interface"}`} /> : undefined}>
            {status.findings.length === 0
              ? <p className="text-sm text-ink-3">No detector threshold exceeded so far. (That is not proof of safety.)</p>
              : <ul className="space-y-3" aria-label="Live findings">{status.findings.map((ev) => <FindingRow key={ev.finding.id} ev={ev} />)}</ul>}
          </Card>
        </>
      )}
    </>
  );
}

