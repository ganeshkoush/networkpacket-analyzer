import { useEffect, useRef, useState } from "react";
import type { TimelinePoint } from "../../api/types";
import { formatBytes, formatNumber, formatOffset } from "../../lib/format";

const H = 190;
const M = { top: 10, right: 12, bottom: 24, left: 44 };

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

function useWidth(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement | null>(null);
  const [w, setW] = useState(640);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([entry]) => setW(Math.max(280, Math.floor(entry.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/** Packets per second over time: one series, area under a 2px line, hover crosshair + tooltip, table view. */
export function TimelineChart({ points }: { points: TimelinePoint[] }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);

  if (points.length === 0) return <p className="text-sm text-ink-3">No timeline data.</p>;

  const interval = points[0].interval_seconds;
  const innerW = width - M.left - M.right;
  const innerH = H - M.top - M.bottom;
  const yMax = niceMax(Math.max(...points.map((p) => p.packets_per_second)));
  const last = points[points.length - 1];
  const xMax = Math.max(last.offset_seconds + interval, 1);
  const x = (offset: number) => M.left + (points.length === 1 ? innerW / 2 : (offset / (xMax - interval || 1)) * innerW);
  const y = (v: number) => M.top + innerH - (v / yMax) * innerH;

  const line = points.map((p, i) => `${i ? "L" : "M"}${x(p.offset_seconds).toFixed(1)},${y(p.packets_per_second).toFixed(1)}`).join(" ");
  const area = `${line} L${x(last.offset_seconds).toFixed(1)},${y(0)} L${x(points[0].offset_seconds).toFixed(1)},${y(0)} Z`;
  const yTicks = [0, yMax / 2, yMax];
  const xTickCount = Math.min(6, points.length);
  const xTicks = Array.from({ length: xTickCount }, (_, i) => points[Math.round((i * (points.length - 1)) / Math.max(xTickCount - 1, 1))]);

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * width;
    let best = 0, bestD = Infinity;
    points.forEach((p, i) => { const d = Math.abs(x(p.offset_seconds) - px); if (d < bestD) { bestD = d; best = i; } });
    setHover(best);
  };
  const hp = hover != null ? points[hover] : null;

  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs text-ink-3">
        <span>Packets per second{interval > 1 ? ` (${interval}s buckets)` : ""}</span>
        <button type="button" className="rounded px-1.5 py-0.5 text-ink-2 hover:bg-surface-2 hover:text-ink" onClick={() => setAsTable((v) => !v)}>
          {asTable ? "Show chart" : "View as table"}
        </button>
      </div>
      {asTable ? (
        <div className="max-h-52 overflow-auto">
          <table className="w-full text-[13px]">
            <thead className="sticky top-0 bg-surface text-xs uppercase text-ink-3">
              <tr><th className="px-2 py-1 text-left">Offset</th><th className="px-2 py-1 text-right">Packets</th><th className="px-2 py-1 text-right">Pkt/s</th><th className="px-2 py-1 text-right">Bytes</th></tr>
            </thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.start_time} className="border-t border-line/60">
                  <td className="px-2 py-1 font-mono">{formatOffset(p.offset_seconds)}</td>
                  <td className="px-2 py-1 text-right font-mono tabular-nums">{formatNumber(p.packets)}</td>
                  <td className="px-2 py-1 text-right font-mono tabular-nums">{p.packets_per_second}</td>
                  <td className="px-2 py-1 text-right font-mono tabular-nums">{formatBytes(p.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div ref={ref} className="relative">
          <svg width="100%" viewBox={`0 0 ${width} ${H}`} role="img" onMouseMove={onMove} onMouseLeave={() => setHover(null)}
            aria-label={`Packets per second over ${formatOffset(xMax)}; peak ${Math.max(...points.map((p) => p.packets_per_second))} packets per second`}>
            {yTicks.map((t) => (
              <g key={t}>
                <line x1={M.left} x2={width - M.right} y1={y(t)} y2={y(t)} stroke="var(--color-line)" strokeWidth={1} />
                <text x={M.left - 6} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--color-ink-3)" className="font-mono">{formatNumber(Math.round(t * 10) / 10)}</text>
              </g>
            ))}
            {xTicks.map((p) => (
              <text key={p.start_time} x={x(p.offset_seconds)} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--color-ink-3)" className="font-mono">{formatOffset(p.offset_seconds)}</text>
            ))}
            <path d={area} fill="var(--color-series-1)" fillOpacity={0.18} />
            <path d={line} fill="none" stroke="var(--color-series-1)" strokeWidth={2} strokeLinejoin="round" />
            {points.length === 1 && <circle cx={x(points[0].offset_seconds)} cy={y(points[0].packets_per_second)} r={4} fill="var(--color-series-1)" />}
            {hp && (
              <g>
                <line x1={x(hp.offset_seconds)} x2={x(hp.offset_seconds)} y1={M.top} y2={y(0)} stroke="var(--color-ink-3)" strokeDasharray="3 3" />
                <circle cx={x(hp.offset_seconds)} cy={y(hp.packets_per_second)} r={4} fill="var(--color-series-1)" stroke="var(--color-surface)" strokeWidth={2} />
              </g>
            )}
          </svg>
          {hp && (
            <div className="pointer-events-none absolute top-1 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-lg"
              style={{ left: Math.min(Math.max(x(hp.offset_seconds) + 10, 0), width - 160) }}>
              <div className="font-mono text-ink-2">+{formatOffset(hp.offset_seconds)}{interval > 1 ? ` (${interval}s)` : ""}</div>
              <div className="font-mono tabular-nums">{hp.packets_per_second} pkt/s · {formatNumber(hp.packets)} pkts</div>
              <div className="font-mono tabular-nums text-ink-3">{formatBytes(hp.bytes)}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
