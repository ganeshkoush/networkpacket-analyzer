import type { ReactNode } from "react";

export interface Column<T> {
  header: string;
  cell: (row: T) => ReactNode;
  align?: "left" | "right";
  className?: string;
}

export function DataTable<T>({ columns, rows, rowKey, empty = "No data.", onRowClick, caption }: {
  columns: Column<T>[]; rows: T[]; rowKey: (row: T, i: number) => string; empty?: string;
  onRowClick?: (row: T) => void; caption?: string;
}) {
  if (rows.length === 0) return <p className="px-1 py-3 text-sm text-ink-3">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-[13px]">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-line text-xs uppercase tracking-wide text-ink-3">
            {columns.map((c) => (
              <th key={c.header} scope="col" className={`px-3 py-2 font-medium ${c.align === "right" ? "text-right" : ""} ${c.className ?? ""}`}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={rowKey(row, i)}
              className={`border-b border-line/60 last:border-0 ${onRowClick ? "cursor-pointer hover:bg-surface-2" : ""}`}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              onKeyDown={onRowClick ? (e) => { if (e.key === "Enter") onRowClick(row); } : undefined}
              tabIndex={onRowClick ? 0 : undefined}
            >
              {columns.map((c) => (
                <td key={c.header} className={`px-3 py-2 align-top ${c.align === "right" ? "text-right tabular-nums" : ""} ${c.className ?? ""}`}>{c.cell(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const Mono = ({ children, className = "" }: { children: ReactNode; className?: string }) => (
  <span className={`font-mono text-[12.5px] ${className}`}>{children}</span>
);
