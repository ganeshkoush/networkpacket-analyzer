import { useEffect, useRef, useState } from "react";
import { formatClock, formatTime } from "../../lib/format";

export interface ChartSeries {
  key: string;
  label: string;
  color: string; // CSS colour, normally a --color-series-N token
  points: { t: number; v: number }[]; // t = epoch seconds
}

const H = 190;
const M = { top: 10, right: 12, bottom: 24, left: 56 };

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

/**
 * A small time-series chart in the style of TimelineChart (hand-rolled SVG, no chart library).
 * `line`: one marker per measurement (sparse points are fine). `bars`: stacked bars, one per time bin of `binSeconds`
 * (series must share timestamps). Hover shows the values; "View as table" gives the same data as text.
 * Only draws what it is given: an empty chart shows `empty` instead.
 */
export function SeriesChart({ title, series, kind, formatValue, binSeconds = 1, empty }: {
  title: string; series: ChartSeries[]; kind: "line" | "bars"; formatValue: (v: number) => string; binSeconds?: number; empty: string;
}) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);
  const times = [...new Set(series.flatMap((s) => s.points.map((p) => p.t)))].sort((a, b) => a - b);

  if (times.length === 0) {
    return (
      <figure aria-label={title}>
        <figcaption className="mb-2 text-xs text-ink-3">{title}</figcaption>
        <p className="rounded-md border border-dashed border-line px-3 py-6 text-center text-sm text-ink-3">{empty}</p>
      </figure>
    );
  }

  const innerW = width - M.left - M.right;
  const innerH = H - M.top - M.bottom;
  const tMin = times[0];
  const tMax = kind === "bars" ? times[times.length - 1] + binSeconds : times[times.length - 1];
  const span = tMax - tMin || 1;
  const x = (t: number) => M.left + (times.length === 1 && kind === "line" ? innerW / 2 : ((t - tMin) / span) * innerW);
  const valueAt = (s: ChartSeries, t: number) => s.points.find((p) => p.t === t)?.v;
  const stackTotal = (t: number) => series.reduce((sum, s) => sum + (valueAt(s, t) ?? 0), 0);
  const yMax = niceMax(kind === "bars" ? Math.max(...times.map(stackTotal)) : Math.max(...series.flatMap((s) => s.points.map((p) => p.v))));
  const y = (v: number) => M.top + innerH - (v / yMax) * innerH;
  const barW = Math.max(2, Math.min(40, (binSeconds / span) * innerW - 1));
  const xTicks = Array.from({ length: Math.min(5, times.length) }, (_, i) => times[Math.round((i * (times.length - 1)) / Math.max(Math.min(5, times.length) - 1, 1))]);

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * width;
    let best = 0, bestD = Infinity;
    times.forEach((t, i) => { const d = Math.abs(x(t) + (kind === "bars" ? barW / 2 : 0) - px); if (d < bestD) { bestD = d; best = i; } });
    setHover(best);
  };
  const ht = hover != null ? times[hover] : null;

  return (
    <figure aria-label={title}>
      <figcaption className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-ink-3">
        <span>{title}</span>
        <span className="flex items-center gap-3">
          {series.map((s) => <span key={s.key} className="inline-flex items-center gap-1.5 text-ink-2"><span className="h-2 w-2 rounded-sm" style={{ background: s.color }} aria-hidden />{s.label}</span>)}
          <button type="button" className="rounded px-1.5 py-0.5 text-ink-2 hover:bg-surface-2 hover:text-ink" onClick={() => setAsTable((v) => !v)}>
            {asTable ? "Show chart" : "View as table"}
          </button>
        </span>
      </figcaption>
      {asTable ? (
        <div className="max-h-52 overflow-auto">
          <table className="w-full text-[13px]">
            <caption className="sr-only">{title}</caption>
            <thead className="sticky top-0 bg-surface text-xs uppercase text-ink-3">
              <tr><th className="px-2 py-1 text-left">Time (UTC)</th>{series.map((s) => <th key={s.key} className="px-2 py-1 text-right">{s.label}</th>)}</tr>
            </thead>
            <tbody>
              {times.map((t) => (
                <tr key={t} className="border-t border-line/60">
                  <td className="px-2 py-1 font-mono">{formatTime(t)}</td>
                  {series.map((s) => { const v = valueAt(s, t); return <td key={s.key} className="px-2 py-1 text-right font-mono tabular-nums">{v == null ? "–" : formatValue(v)}</td>; })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div ref={ref} className="relative">
          <svg width="100%" viewBox={`0 0 ${width} ${H}`} role="img" onMouseMove={onMove} onMouseLeave={() => setHover(null)}
            aria-label={`${title}: ${times.length} ${kind === "bars" ? "time bins" : "measurements"} from ${formatClock(tMin)} to ${formatClock(tMax)} UTC; maximum ${formatValue(yMax)}`}>
            {[0, yMax / 2, yMax].map((tick) => (
              <g key={tick}>
                <line x1={M.left} x2={width - M.right} y1={y(tick)} y2={y(tick)} stroke="var(--color-line)" strokeWidth={1} />
                <text x={M.left - 6} y={y(tick) + 4} textAnchor="end" fontSize={11} fill="var(--color-ink-3)" className="font-mono">{formatValue(tick)}</text>
              </g>
            ))}
            {xTicks.map((t) => (
              <text key={t} x={x(t)} y={H - 6} textAnchor="middle" fontSize={11} fill="var(--color-ink-3)" className="font-mono">{formatClock(t)}</text>
            ))}
            {kind === "bars"
              ? times.map((t) => {
                  let base = 0;
                  return series.map((s) => {
                    const v = valueAt(s, t) ?? 0;
                    const top = base + v;
                    const rect = <rect key={`${t}-${s.key}`} x={x(t)} y={y(top)} width={barW} height={Math.max(0, y(base) - y(top))} fill={s.color} fillOpacity={ht === t ? 1 : 0.85} />;
                    base = top;
                    return rect;
                  });
                })
              : series.map((s) => (
                  <g key={s.key}>
                    {s.points.length > 1 && <path d={s.points.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ")} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" />}
                    {s.points.map((p) => <circle key={p.t} cx={x(p.t)} cy={y(p.v)} r={ht === p.t ? 4.5 : 3} fill={s.color} stroke="var(--color-surface)" strokeWidth={1.5} />)}
                  </g>
                ))}
            {ht != null && kind === "line" && <line x1={x(ht)} x2={x(ht)} y1={M.top} y2={y(0)} stroke="var(--color-ink-3)" strokeDasharray="3 3" />}
          </svg>
          {ht != null && (
            <div className="pointer-events-none absolute top-1 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-lg"
              style={{ left: Math.min(Math.max(x(ht) + 10, 0), width - 190) }}>
              <div className="font-mono text-ink-2">{formatTime(ht)}{kind === "bars" && binSeconds > 1 ? ` (${binSeconds}s bin)` : ""}</div>
              {series.map((s) => { const v = valueAt(s, ht); return v == null ? null : <div key={s.key} className="font-mono tabular-nums">{s.label}: {formatValue(v)}</div>; })}
            </div>
          )}
        </div>
      )}
    </figure>
  );
}
