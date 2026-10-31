import { useEffect, useRef, useState } from "react";
import type { InterfaceInfo, InterfaceKind } from "../../api/types";
import { ApiError } from "../../api/client";
import { useApi } from "../../state/ApiContext";
import { useSettings } from "../../state/SettingsContext";
import { pickSavePath, hasNativeDialogs } from "../../lib/nativeFiles";
import { Button, Notice, Spinner } from "../ui/feedback";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import {
  ActionRow, ChoiceSetting, InfoRow, NumberSetting, Panel, SelectSetting, SettingRow, ToggleSetting, UnavailableRows,
} from "./controls";
import { useAction } from "./useAction";

const Outcome = ({ a }: { a: ReturnType<typeof useAction> }) => (
  <>
    {a.message && <div className="py-2"><Notice tone="info">{a.message}</Notice></div>}
    {a.error && <div className="py-2" role="alert"><Notice>{a.error}</Notice></div>}
  </>
);

// ------------------------------------------------------------------------------------------------ General
export function GeneralSection() {
  const api = useApi();
  const { adopt, saved } = useSettings();
  const file = useRef<HTMLInputElement>(null);
  const a = useAction();
  const [confirmAll, setConfirmAll] = useState(false);
  const { reset } = useSettings();

  const exportFile = () => a.run(async () => {
    if (hasNativeDialogs()) {
      const dest = await pickSavePath("packetmind-settings.json", [{ name: "PacketMind settings", extensions: ["json"] }], "Export settings");
      if (!dest) return null;
      return api.exportSettingsFile(dest);
    }
    const link = document.createElement("a"); link.href = api.settingsDownloadUrl(); link.download = "packetmind-settings.json"; document.body.appendChild(link); link.click(); link.remove();
    return { filename: "packetmind-settings.json", directory: "your downloads folder" };
  }, (r) => (r ? `Settings exported to ${r.filename} in ${r.directory}. The file contains no API key or other secret.` : "Export cancelled."));

  const importFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 1024 * 1024) { a.run(async () => { throw new ApiError("unknown", "That file is too large to be a PacketMind settings file."); }, () => ""); return; }
    await a.run(async () => {
      let doc: unknown;
      try { doc = JSON.parse(await f.text()); } catch { throw new ApiError("unknown", "That file is not valid JSON, so it cannot be a PacketMind settings file."); }
      adopt(await api.importSettings(doc));
    }, () => "Settings imported and applied.");
    if (file.current) file.current.value = "";
  };

  return (
    <>
      <Panel title="Appearance & behaviour">
        <SelectSetting path="general.theme" title="Theme" help="Use the light or dark look, or follow your operating system." options={[["system", "System"], ["light", "Light"], ["dark", "Dark"]]} />
        <SelectSetting path="general.time_format" title="Date and time format" help="UTC is what network captures use. Local time converts to this computer's clock."
          options={[["utc", "UTC (2026-10-07 22:13:19 UTC)"], ["local", "Local time (12-hour)"], ["local_24h", "Local time (24-hour)"]]} />
        <ToggleSetting path="notifications.enabled" title="Show notifications" help="Allow PacketMind to show desktop notifications. Choose which events notify you under Notifications." />
        <ToggleSetting path="security.confirm_delete_captures" title="Confirm before deleting" help="Ask before a capture is permanently deleted. (The backend also refuses deletes that are not confirmed.)" />
        <UnavailableRows section="general" />
      </Panel>
      <Panel title="Where PacketMind keeps things" description="Folders are fixed by the PACKETMIND_* environment variables, so a settings file can never redirect them.">
        <InfoRow title="Default capture directory" help="Saved and imported captures. Open it from Storage.">see Storage</InfoRow>
        <InfoRow title="Default report directory" help="Exported reports. Open it from Storage.">see Storage</InfoRow>
      </Panel>
      <Panel title="Settings file" description="Back up or move your settings. The file never contains your API key.">
        <ActionRow title="Export / import" help="Export writes your settings to a file. Import checks the whole file first and applies nothing if any value is invalid.">
          <Button onClick={exportFile} disabled={a.busy}>Export Settings</Button>
          <Button onClick={() => file.current?.click()} disabled={a.busy}>Import Settings</Button>
          <input ref={file} type="file" accept=".json,application/json" className="sr-only" aria-label="Settings file" tabIndex={-1} onChange={(e) => void importFile(e.target.files?.[0])} />
        </ActionRow>
        <Outcome a={a} />
        <ActionRow title="Reset all settings" help="This will restore PacketMind settings to their default values. Your captures, reports, findings and database are not touched.">
          <Button onClick={() => setConfirmAll(true)}>Reset All Settings</Button>
        </ActionRow>
      </Panel>
      {confirmAll && (
        <ConfirmDialog title="Reset all settings?" confirmLabel="Reset all settings" danger onCancel={() => setConfirmAll(false)}
          onConfirm={async () => { await reset(null); setConfirmAll(false); }}>
          <p>This will restore PacketMind settings to their default values. Captures, reports, findings and the database are not deleted.</p>
        </ConfirmDialog>
      )}
      <span hidden>{saved.general.theme}</span>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Capture
export function CaptureSection() {
  const api = useApi();
  const [ifaces, setIfaces] = useState<InterfaceInfo[] | null>(null);
  useEffect(() => { const c = new AbortController(); api.listInterfaces(c.signal).then(setIfaces).catch(() => setIfaces([])); return () => c.abort(); }, [api]);
  return (
    <>
      <Panel title="Capture" description="How live capture records traffic. These are the defaults used when you press Start capture.">
        <SelectSetting path="capture.default_interface" title="Default network interface" help="The interface preselected on the Live Capture page. Pick the list under Network for details."
          options={[["", "None (choose each time)"], ...(ifaces ?? []).map((i): [string, string] => [i.name, `${i.name}${i.description && i.description !== i.name ? ` — ${i.description}` : ""}`])]} />
        <SelectSetting path="capture.format" title="Capture format" help="PCAP works everywhere. PCAPNG can hold more metadata." options={[["pcap", "PCAP (.pcap)"], ["pcapng", "PCAPNG (.pcapng)"]]} />
        <ChoiceSetting path="privacy.store_payloads" title="Capture mode" whenTrue="Full packets" whenFalse="Headers only"
          help="Full packets keep everything on the wire. Headers only cuts off the application data (page content, passwords) and keeps addresses, ports, flags and sizes — safer to store."
          note="The same setting as Privacy → Store packet payloads." />
        <NumberSetting path="capture.max_size_mb" title="Maximum capture size" help="PacketMind stops the capture by itself when the saved file reaches this size. 0 means no limit." />
        <NumberSetting path="capture.max_duration_minutes" title="Maximum capture duration" help="PacketMind stops the capture by itself after this many minutes. 0 means no limit." />
        <ToggleSetting path="capture.auto_save" title="Automatically save captures" help="Record each live capture to a capture file you can export. Turn off to watch traffic without saving it." />
        <ToggleSetting path="capture.auto_analyze" title="Automatically analyze after capture" help="Analyze the saved file as soon as the capture stops. If off, it waits in Captures as “Ready”." />
        <ToggleSetting path="capture.rotation_enabled" title="Capture file rotation" help="Split a long capture into several files. Each file is saved, checked and analyzed like a normal capture." />
        <NumberSetting path="capture.rotation_size_mb" title="Rotation size" help="Start a new file when the current one reaches this size." />
        <NumberSetting path="capture.rotation_minutes" title="Rotation time" help="Start a new file after this many minutes. Whichever comes first applies." />
        <UnavailableRows section="capture" />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Network
const KIND: Record<InterfaceKind, string> = { wifi: "Wi-Fi", ethernet: "Ethernet", vpn: "VPN", loopback: "Loopback", other: "Other" };

export function NetworkSection() {
  const api = useApi();
  const { draft, setField } = useSettings();
  const [ifaces, setIfaces] = useState<InterfaceInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const c = new AbortController();
    setIfaces(null); setError(null);
    api.listInterfaces(c.signal).then(setIfaces).catch((e) => { if (e?.name !== "AbortError") setError(e instanceof ApiError ? e.message : "The list of network interfaces could not be read."); });
    return () => c.abort();
  }, [api, tick]);
  const shown = (ifaces ?? []).filter((i) => draft.network.show_inactive_interfaces || i.is_up !== false);
  return (
    <>
      <Panel title="Interfaces" description="Read from this computer each time, never a fixed list."
        actions={<Button onClick={() => setTick((t) => t + 1)}>Refresh Interfaces</Button>}>
        {ifaces === null && !error && <div className="py-3"><Spinner label="Reading interfaces…" /></div>}
        {error && <div className="py-3" role="alert"><Notice>{error}</Notice></div>}
        {ifaces && shown.length === 0 && !error && <p className="py-3 text-sm text-ink-3">No interfaces to show.</p>}
        {shown.length > 0 && (
          <ul aria-label="Network interfaces" className="divide-y divide-line">
            {shown.map((i) => (
              <li key={i.name} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-3">
                <input type="radio" name="default-interface" id={`if-${i.name}`} checked={draft.capture.default_interface === i.name} onChange={() => setField("capture.default_interface", i.name)}
                  aria-label={`Use ${i.name} as the default interface`} />
                <label htmlFor={`if-${i.name}`} className="min-w-0 flex-1">
                  <span className="block font-medium">{i.description && i.description !== i.name ? i.description : KIND[i.kind]}</span>
                  <span className="block font-mono text-xs text-ink-3">{i.name}{i.addresses[0] ? ` · ${i.addresses[0]}` : ""} · {KIND[i.kind]}</span>
                </label>
                <span className="text-xs text-ink-2">{i.is_up === false ? "Inactive" : i.is_up ? "Available" : "Status unknown"}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="Choosing an interface">
        <ToggleSetting path="network.auto_select_interface" title="Automatically select active interface" help="Preselect the first active Wi-Fi or Ethernet interface on the Live Capture page when no default interface is chosen." />
        <ToggleSetting path="network.show_inactive_interfaces" title="Show inactive interfaces" help="Include interfaces that are down in the lists." />
        <UnavailableRows section="network" />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Analysis
export function AnalysisSection() {
  return (
    <Panel title="Analysis" description="What PacketMind works out from a capture. Turning something off makes its results empty, and the analysis says so.">
      <ToggleSetting path="analysis.dns" title="Enable DNS analysis" help="Count DNS lookups, answers, failures and lookup times." />
      <ToggleSetting path="analysis.tcp" title="Enable TCP analysis" help="Study TCP flags, resets and retransmissions." />
      <ToggleSetting path="analysis.connection_tracking" title="Enable connection tracking" help="Group packets into connections. Needed for handshake, RTT, domain performance and the network map." />
      <ToggleSetting path="analysis.domain_tracking" title="Enable domain tracking" help="Match DNS answers to the connections that follow, to name the domains and services contacted. This is an inference, not a list of pages visited." />
      <ToggleSetting path="analysis.rtt" title="Enable RTT calculation" help="Measure round-trip time from data packets and their acknowledgements." />
      <ToggleSetting path="analysis.handshake" title="Enable TCP handshake calculation" help="Measure how long TCP connections take to set up. This is set-up time, not how fast a website responds." />
      <ToggleSetting path="analysis.performance" title="Enable performance analysis" help="Latency, health ratings and baselines per domain. Turning this off hides performance data everywhere." />
      <SelectSetting path="analysis.depth" title="Analysis depth" help="How much detail each list keeps. Basic is lighter and faster, Deep keeps more entries for large captures."
        options={[["basic", "Basic"], ["standard", "Standard"], ["deep", "Deep"]]} />
      <NumberSetting path="analysis.max_packets" title="Maximum packets analyzed" help="Stop after this many packets, to keep very large captures quick. 0 means analyze everything." />
      <UnavailableRows section="analysis" />
    </Panel>
  );
}

// ------------------------------------------------------------------------------------------------ Detection
export function DetectionSection() {
  return (
    <>
      <Panel title="Detection sensitivity" description="How much evidence a detector needs. Low reports less, High reports more. It adjusts the thresholds below.">
        <SelectSetting path="detection.sensitivity" title="Sensitivity" help="Medium uses your thresholds as they are; Low needs about 50% more evidence; High about a third less."
          options={[["low", "Low"], ["medium", "Medium"], ["high", "High"]]} />
      </Panel>
      <Panel title="Port Scan Detection" description="One host probing many ports.">
        <ToggleSetting path="detection.port_scan.enabled" title="Enable Port Scan Detection" help="Look for hosts that try many different ports." />
        <NumberSetting path="detection.port_scan.min_ports" title="Ports threshold" help="Different ports one host must try before it is reported." />
        <NumberSetting path="detection.port_scan.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1). 0 reports everything the detector finds." />
      </Panel>
      <Panel title="SYN Flood Detection" description="A flood of connection requests that are never completed.">
        <ToggleSetting path="detection.syn_flood.enabled" title="Enable SYN Flood Detection" help="Look for floods of SYN packets against one target." />
        <NumberSetting path="detection.syn_flood.min_syn_packets" title="SYN threshold" help="SYN packets to one target before it is reported." />
        <NumberSetting path="detection.syn_flood.min_peak_syn_per_second" title="Peak SYN rate" help="Busiest second, in SYN packets, before it is reported." />
        <NumberSetting path="detection.syn_flood.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1)." />
      </Panel>
      <Panel title="DNS Anomaly Detection" description="Unusual DNS behaviour.">
        <ToggleSetting path="detection.dns.enabled" title="Enable DNS Anomaly Detection" help="Look for floods of lookups, many failed lookups, random-looking names and data hidden in names." />
        <NumberSetting path="detection.dns.query_rate_per_second" title="Query rate threshold" help="DNS queries per second from one host before it is reported as excessive." />
        <NumberSetting path="detection.dns.nxdomain_ratio" title="Failure threshold" step={0.05} help="Share of lookups that fail (0 to 1) before a host is reported. 0.5 means half." />
        <NumberSetting path="detection.dns.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1)." />
      </Panel>
      <Panel title="ARP Spoof Detection" description="Addresses that seem to belong to more than one device.">
        <ToggleSetting path="detection.arp.enabled" title="Enable ARP Spoof Detection" help="Look for one IP address claimed by several devices, and sudden changes." />
        <NumberSetting path="detection.arp.min_macs_per_ip" title="Devices per address" help="Different devices claiming one address before it is reported (2 or more)." />
        <NumberSetting path="detection.arp.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1)." />
      </Panel>
      <Panel title="TCP Anomaly Detection" description="Unhealthy or odd TCP behaviour.">
        <ToggleSetting path="detection.tcp.enabled" title="Enable TCP Anomaly Detection" help="Look for unusual flag combinations, many retransmissions and many resets." />
        <NumberSetting path="detection.tcp.retransmission_rate" title="Retransmission threshold" step={0.01} help="Share of data packets sent again (0 to 1) before it is reported. 0.05 means 5%." />
        <NumberSetting path="detection.tcp.reset_ratio" title="Reset threshold" step={0.05} help="Share of packets that are resets (0 to 1) before it is reported." />
        <NumberSetting path="detection.tcp.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1)." />
      </Panel>
      <Panel title="Unusual Connection Detection" description="Large uploads and clear-text management protocols.">
        <ToggleSetting path="detection.connection.enabled" title="Enable Unusual Connection Detection" help="Look for big one-way uploads to the internet and use of unencrypted protocols like Telnet or FTP." />
        <NumberSetting path="detection.connection.min_upload_mb" title="Large upload threshold" help="Data sent out by one connection before it is reported." />
        <NumberSetting path="detection.connection.min_confidence" title="Confidence threshold" step={0.05} help="Only report findings at or above this confidence (0 to 1)." />
      </Panel>
      <UnavailableRows section="detection" />
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Performance
export function PerformanceSection() {
  return (
    <>
      <Panel title="Performance monitoring" description="How connection quality is measured. TCP handshake time is how long a connection takes to set up; it is not how fast a site responds.">
        <ToggleSetting path="analysis.performance" title="Enable performance monitoring" help="Measure network latency and connection quality." note="The same setting as Analysis → Enable performance analysis." />
        <ToggleSetting path="performance.track_dns_latency" title="Track DNS latency" help="Measure how long DNS lookups take." />
        <ToggleSetting path="analysis.handshake" title="Track TCP handshake latency" help="Measure how long TCP connections take to set up (SYN to ACK)." note="The same setting as Analysis → Enable TCP handshake calculation." />
        <ToggleSetting path="analysis.rtt" title="Track RTT" help="Measure round-trip time of data packets." note="The same setting as Analysis → Enable RTT calculation." />
        <ToggleSetting path="performance.track_retransmissions" title="Track retransmissions" help="Count packets that had to be sent again, an indicator of loss or congestion." />
        <ToggleSetting path="performance.track_failures" title="Track connection failures" help="Count connection attempts that were never answered or were reset." />
      </Panel>
      <Panel title="Historical baseline" description="Compare each capture with this computer's earlier ones to spot what is unusual.">
        <ToggleSetting path="performance.baseline_enabled" title="Create historical baseline" help="Remember per-domain averages (names and numbers only) to learn what is normal. Needs Domains → Store domain history." />
        <NumberSetting path="performance.baseline_window" title="Baseline window" help="How many earlier captures form the baseline." />
        <NumberSetting path="performance.baseline_min_samples" title="Minimum samples required" help="Earlier captures needed before anything is called unusual. Too few makes false alarms." />
        <SelectSetting path="performance.anomaly_sensitivity" title="Anomaly sensitivity" help="High flags smaller changes from normal; Low only large ones." options={[["low", "Low"], ["medium", "Medium"], ["high", "High"]]} />
      </Panel>
      <Panel title="What counts as slow" description="Domains slower than these limits are rated Fair; three to five times slower is Poor.">
        <NumberSetting path="performance.slow_dns_ms" title="Slow DNS threshold" help="DNS lookup time above which a domain is rated Fair." />
        <NumberSetting path="performance.slow_handshake_ms" title="Slow TCP handshake threshold" help="Connection set-up time above which a domain is rated Fair." />
        <NumberSetting path="performance.slow_rtt_ms" title="Slow RTT threshold" help="Round-trip time above which a domain is rated Fair." />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Domains
export function DomainsSection() {
  return (
    <>
      <Panel title="Domains and services" description="PacketMind names domains from DNS lookups that precede a connection. It cannot always tell which page or URL was visited, so it shows domains, hostnames, services and destination IPs only.">
        <ToggleSetting path="analysis.domain_tracking" title="Track DNS domains" help="Name the domains and services each connection belongs to." note="The same setting as Analysis → Enable domain tracking." />
        <ToggleSetting path="domains.track_history" title="Store domain history" help="Remember per-domain performance numbers between captures (used for baselines)." note="The same setting as Privacy → Store domain names." />
        <NumberSetting path="domains.retention_days" title="Domain retention period" help="Forget domain history older than this. 0 keeps it (bounded per domain)." />
      </Panel>
      <Panel title="Hide from lists" description="Only hides rows in Web Activity and the dashboard's domain lists. The traffic is still analysed.">
        <ToggleSetting path="domains.hide_localhost" title="Hide localhost" help="Hide this computer's own loopback traffic." />
        <ToggleSetting path="domains.hide_private_ips" title="Hide private/local IP destinations" help="Hide destinations on your own network (192.168.x.x, 10.x.x.x, 172.16–31.x.x)." />
        <ToggleSetting path="domains.hide_local_domains" title="Hide local network domains" help="Hide names such as printer.local, nas.lan or single-word hostnames." />
        <UnavailableRows section="domains" />
      </Panel>
    </>
  );
}

// ------------------------------------------------------------------------------------------------ Privacy
export function DataPolicy({ compact = false }: { compact?: boolean }) {
  const { payload } = useSettings();
  const policy = payload?.ai_data_policy ?? [
    { item: "Raw PCAP files", policy: "NEVER SENT" }, { item: "Raw packet payloads", policy: "NEVER SENT" },
    { item: "Structured analysis", policy: "ALLOWED" }, { item: "Aggregated statistics", policy: "ALLOWED" }];
  return (
    <section aria-label="AI Data Policy" className={`rounded-lg border border-line bg-surface-2 p-4 ${compact ? "" : "mb-4"}`}>
      <h2 className="text-[13px] font-semibold uppercase tracking-wide text-ink-2">AI Data Policy</h2>
      <p className="mt-1 text-xs text-ink-3">Built into PacketMind. It cannot be changed in Settings, so it cannot be changed by accident.</p>
      <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-6 gap-y-1.5 text-sm">
        {policy.map((p) => (
          <div key={p.item} className="contents"><dt>{p.item}</dt>
            <dd className={`font-mono text-xs font-semibold ${p.policy === "NEVER SENT" ? "text-sev-critical" : "text-series-3"}`}>{p.policy === "NEVER SENT" ? "✕ NEVER SENT" : "✓ ALLOWED"}</dd></div>
        ))}
      </dl>
      <p className="mt-3 text-xs text-ink-3">Gemini only receives structured evidence PacketMind produced locally: aggregated statistics, DNS and TCP statistics, performance metrics, domain information and security findings.</p>
    </section>
  );
}

export function PrivacySection() {
  return (
    <>
      <Notice>Network captures can contain sensitive information: passwords, cookies, messages and the addresses of everything you connect to. Keep capture files private and delete them when you no longer need them.</Notice>
      <div className="mt-4" />
      <DataPolicy />
      <Panel title="What PacketMind keeps">
        <ChoiceSetting path="privacy.store_payloads" title="Store packet payloads" whenTrue="Yes — full packets" whenFalse="No — headers only"
          help="Saved capture files normally contain the full packets. Choose headers only to keep addresses, ports and sizes but drop the content." />
        <ToggleSetting path="privacy.store_dns_queries" title="Store DNS queries" help="Keep the list of individual DNS lookups in analysis results. Off keeps only the totals." />
        <ToggleSetting path="domains.track_history" title="Store domain names" help="Remember domain names with their performance numbers between captures." note="The same setting as Domains → Store domain history." />
        <ToggleSetting path="privacy.anonymize_ips" title="Anonymize IP addresses" help="In reports you save, replace every IP address with a label such as host-1." />
        <ToggleSetting path="privacy.clear_temp_on_exit" title="Clear temporary capture data on exit" help="Remove half-imported files left in the temporary folder when PacketMind closes. Saved captures are not touched." />
        <NumberSetting path="privacy.data_retention_days" title="Data retention period" help="Delete saved reports older than this when PacketMind starts. 0 keeps them." />
        <SettingRow id="info-ip" title="Store IP addresses" help="IP addresses are part of every analysis (they identify the connections and findings), so this cannot be turned off. Use Anonymize to hide them in saved reports.">
          <span className="text-xs text-ink-3">Always on</span></SettingRow>
        <SettingRow id="info-meta" title="Store packet metadata" help="PacketMind never keeps per-packet records. It stores only totals and per-connection summaries.">
          <span className="text-xs text-ink-3">Not stored</span></SettingRow>
      </Panel>
    </>
  );
}
