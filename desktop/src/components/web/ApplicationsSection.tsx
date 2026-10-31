import { useCallback, useEffect, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { DomainApplications } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { Card } from "../ui/Card";
import { Button, ErrorPanel, Spinner } from "../ui/feedback";
import { formatNumber } from "../../lib/format";

const CONF_ORDER = ["HIGH", "MEDIUM", "LOW"] as const;

/**
 * Which local applications held this domain's connections. This is operating-system information (the socket table on
 * this computer at the moment a snapshot was taken), not something the packets reveal, and it says so.
 */
export function ApplicationsSection({ analysisId, domain }: { analysisId: string; domain: string }) {
  const api = useApi();
  const [data, setData] = useState<DomainApplications | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setData(null); setError(null);
    api.getDomainApplications(analysisId, domain, signal).then(setData).catch((e) => {
      if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not look up applications.");
    });
  }, [api, analysisId, domain]);
  useEffect(() => { const c = new AbortController(); load(c.signal); return () => c.abort(); }, [load]);

  const usable = data && (data.status === "available" || data.status === "partial");
  return (
    <Card title="Applications" subtitle="From this computer's operating system at the moment snapshots were taken, not from the captured packets.">
      {error && <ErrorPanel title="Application lookup unavailable" actions={<Button onClick={() => load()}>Retry</Button>}>{error}</ErrorPanel>}
      {!error && !data && <Spinner label="Looking up applications…" />}
      {data && !usable && (
        <div>
          <p className="text-sm text-ink-2">{data.message}</p>
          {data.permission_note && <p className="mt-2 text-xs text-ink-3">{data.permission_note}</p>}
        </div>
      )}
      {data && usable && (
        <>
          <ul aria-label="Applications" className="space-y-2">
            {data.applications.map((a) => (
              <li key={a.name} className="text-[14px]">
                <span className="font-medium">{a.name}</span>
                <span className="text-ink-2"> — {formatNumber(a.connections)} connection{a.connections === 1 ? "" : "s"}</span>
                {a.kind === "process" && <span className="ml-2 text-xs text-ink-3">(process, not an app bundle)</span>}
                <div className="text-xs text-ink-3">
                  {a.process_names.join(", ")}
                  {" · match confidence "}
                  {CONF_ORDER.filter((k) => a.confidence_counts[k]).map((k) => `${k.toLowerCase()} ×${a.confidence_counts[k]}`).join(", ")}
                </div>
              </li>
            ))}
          </ul>
          {data.status === "partial" && <p className="mt-3 text-sm text-ink-2">{data.message}</p>}
          <p className="mt-3 text-xs text-ink-3">{data.source_note} {data.permission_note}</p>
        </>
      )}
    </Card>
  );
}
