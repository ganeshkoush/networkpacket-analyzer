import type { ProtocolStat } from "../../api/types";
import { formatBytes, formatNumber } from "../../lib/format";

const SLOTS = ["var(--color-series-1)", "var(--color-series-2)", "var(--color-series-3)", "var(--color-series-4)", "var(--color-series-5)", "var(--color-series-6)"];
const OTHER = "var(--color-series-other)";

interface Slice { name: string; packets: number; bytes: number; percent: number; color: string }

/** Top 6 protocols keep fixed colors by rank; the rest fold into "Other". */
export function toSlices(dist: ProtocolStat[]): Slice[] {
  const top = dist.slice(0, SLOTS.length).map((p, i) => ({ name: p.protocol, packets: p.packets, bytes: p.bytes, percent: p.percent_of_packets, color: SLOTS[i] }));
  const rest = dist.slice(SLOTS.length);
  if (rest.length === 0) return top;
  return [...top, {
    name: `Other (${rest.length})`, packets: rest.reduce((a, p) => a + p.packets, 0), bytes: rest.reduce((a, p) => a + p.bytes, 0),
    percent: Math.round(rest.reduce((a, p) => a + p.percent_of_packets, 0) * 100) / 100, color: OTHER,
  }];
}

export function ProtocolChart({ distribution }: { distribution: ProtocolStat[] }) {
  const slices = toSlices(distribution);
  const total = slices.reduce((a, s) => a + s.packets, 0);
  if (total === 0) return <p className="text-sm text-ink-3">No packets to classify.</p>;
  return (
    <div>
      <div className="flex h-3 gap-[2px]" role="img" aria-label={`Protocol distribution: ${slices.map((s) => `${s.name} ${s.percent}%`).join(", ")}`}>
        {slices.map((s) => (
          <div key={s.name} title={`${s.name}: ${formatNumber(s.packets)} packets (${s.percent}%)`}
            className="h-full rounded-[2px]" style={{ width: `${(s.packets / total) * 100}%`, background: s.color, minWidth: 3 }} />
        ))}
      </div>
      <table className="mt-3 w-full text-[13px]">
        <thead className="sr-only"><tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Share</th></tr></thead>
        <tbody>
          {slices.map((s) => (
            <tr key={s.name}>
              <td className="py-1 pr-2"><span className="inline-flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-[2px]" style={{ background: s.color }} aria-hidden />{s.name}</span></td>
              <td className="py-1 text-right font-mono tabular-nums text-ink-2">{formatNumber(s.packets)}</td>
              <td className="py-1 pl-3 text-right font-mono tabular-nums text-ink-3">{formatBytes(s.bytes)}</td>
              <td className="w-16 py-1 text-right font-mono tabular-nums">{s.percent}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
