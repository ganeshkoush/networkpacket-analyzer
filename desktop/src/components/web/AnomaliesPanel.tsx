import { useEffect, useMemo, useState } from "react";
import { ApiError, isAbort } from "../../api/client";
import type { AnomalyList, PerformanceAnomaly } from "../../api/types";
import { useApi } from "../../state/ApiContext";
import { Card } from "../ui/Card";
import { Notice } from "../ui/feedback";
import { AnomalyCard } from "./AnomalyCard";

/** Performance anomalies of this capture vs. each domain's own history. Quiet when there is nothing to say. */
export function AnomaliesPanel({ analysisId, reloadKey, onOpenDomain }: { analysisId: string; reloadKey: number; onOpenDomain: (domain: string) => void }) {
  const api = useApi();
  const [data, setData] = useState<AnomalyList | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const c = new AbortController();
    setError(null);
    api.getAnomalies(analysisId, c.signal).then(setData).catch((e) => {
      if (!isAbort(e)) setError(e instanceof ApiError ? e.message : "Could not load performance history.");
    });
    return () => c.abort();
  }, [api, analysisId, reloadKey]);

  const groups = useMemo(() => {
    const byDomain = new Map<string, PerformanceAnomaly[]>();
    for (const a of data?.anomalies ?? []) byDomain.set(a.domain, [...(byDomain.get(a.domain) ?? []), a]);
    return [...byDomain];
  }, [data]);

  if (error) return <Notice tone="info">Performance history is unavailable: {error}</Notice>;
  if (!data) return null;
  if (!data.history_enabled) return <Notice tone="info">Performance history is turned off, so no baselines are learned and no anomalies are reported.</Notice>;
  if (groups.length === 0) {
    return (
      <p className="text-xs text-ink-3">
        {data.domains_with_baseline === 0
          ? "Learning baselines: no domain has enough earlier captures to be compared yet, so nothing is flagged. Baselines stay on this computer."
          : `No performance anomalies compared with earlier captures (${data.domains_with_baseline} of ${data.domains_evaluated} domains had enough history to judge).`}
      </p>
    );
  }
  return (
    <Card title={`Performance anomalies (${data.anomalies.length})`}
      subtitle="Compared with each domain's own earlier captures on this computer. These are possible changes, not diagnoses.">
      <div className="grid gap-3 lg:grid-cols-2">
        {groups.map(([domain, list]) => <AnomalyCard key={domain} domain={domain} anomalies={list} onOpen={onOpenDomain} />)}
      </div>
    </Card>
  );
}
