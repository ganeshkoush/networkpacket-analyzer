"""Local history of per-domain performance and the baseline/anomaly evaluation over it.

Stores only domain names and aggregate numbers in the local SQLite database (parameterised SQL; schema from
``app/migrations.py``). One observation = what one capture showed for one domain; re-analysing the same capture
replaces its observation instead of counting it twice. Anomaly records are *derived* from the stored observations
(``app/analysis/baseline.py``), so they stay consistent when history is re-recorded or cleared.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import Engine, text

from app.analysis.baseline import DEFAULT_CONFIG, BaselineConfig, Observation, evaluate_observation
from app.config import settings
from app.models.analysis import AnalysisResult, DomainPerformance
from app.models.baseline import (
    AnomalyList, DomainBaselineView, HistoryPoint, HistoryStatus, MetricComparison, PerformanceAnomaly,
)

logger = logging.getLogger(__name__)

_FETCH_PER_DOMAIN = 160  # enough for the rolling window plus the lookback for the start of an anomaly run
_COLUMNS = ("source_id", "domain", "captured_at", "connections", "handshake_ms", "handshake_samples", "rtt_avg_ms",
            "rtt_p95_ms", "rtt_samples", "dns_ms", "dns_lookups", "response_ms", "response_samples", "tcp_packets",
            "retransmissions", "tcp_attempted", "tcp_failed")
NOTES = [
    "Baselines are learned from this computer's earlier captures and stay in the local database (domain names and "
    "aggregate numbers only).",
    "A domain needs several earlier observations before a deviation can be judged; until then nothing is flagged.",
]


def observation_from_performance(p: DomainPerformance, *, source_id: str, source_name: str, captured_at: float) -> Observation:
    return Observation(
        source_id=source_id, source_name=source_name, captured_at=captured_at, domain=p.domain, connections=p.connections,
        values={"tcp_handshake_ms": p.tcp_handshake_ms, "avg_rtt_ms": p.avg_rtt_ms, "p95_rtt_ms": p.p95_rtt_ms,
                "dns_latency_ms": p.dns_latency_ms, "response_ms": p.application_response_ms},
        samples={"tcp_handshake_ms": p.handshake_samples, "avg_rtt_ms": p.rtt_samples, "p95_rtt_ms": p.rtt_samples,
                 "dns_latency_ms": p.dns_lookups, "response_ms": p.application_response_samples},
        tcp_packets=p.tcp_packets, retransmissions=p.retransmissions,
        attempted=p.tcp_connections_attempted, failed=p.tcp_connections_failed)


def _from_row(row, source_names: dict[str, str] | None = None) -> Observation:
    r = dict(row)
    return Observation(
        source_id=r["source_id"], source_name=r.get("name") or (source_names or {}).get(r["source_id"], ""),
        captured_at=r["captured_at"], domain=r["domain"], connections=r["connections"],
        values={"tcp_handshake_ms": r["handshake_ms"], "avg_rtt_ms": r["rtt_avg_ms"], "p95_rtt_ms": r["rtt_p95_ms"],
                "dns_latency_ms": r["dns_ms"], "response_ms": r["response_ms"]},
        samples={"tcp_handshake_ms": r["handshake_samples"], "avg_rtt_ms": r["rtt_samples"], "p95_rtt_ms": r["rtt_samples"],
                 "dns_latency_ms": r["dns_lookups"], "response_ms": r["response_samples"]},
        tcp_packets=r["tcp_packets"], retransmissions=r["retransmissions"], attempted=r["tcp_attempted"], failed=r["tcp_failed"])


def source_id_for(result: AnalysisResult) -> str | None:
    """Stable identity of a file capture (its SHA-256); None for results without one (live windows)."""
    return result.metadata.sha256 or None


class PerformanceHistory:
    def __init__(self, engine: Engine, config: BaselineConfig = DEFAULT_CONFIG, enabled: bool = True,
                 max_per_domain: int = 500) -> None:
        self._engine = engine
        self._config = config
        self._enabled = enabled
        self.max_per_domain = max_per_domain
        # The app-wide instance follows the user's Settings (baseline on/off, window, sensitivity) through these hooks;
        # instances built directly (tests, tools) have none and behave exactly as constructed.
        self.config_provider = None
        self.gate = None

    @property
    def config(self) -> BaselineConfig:
        return self.config_provider() if self.config_provider is not None else self._config

    @config.setter
    def config(self, value: BaselineConfig) -> None:
        self._config = value

    @property
    def enabled(self) -> bool:
        return self._enabled and (self.gate() if self.gate is not None else True)

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def prune_older_than(self, captured_before: float) -> int:
        """Forget observations of captures older than this time (the 'domain retention' setting). Returns sources removed."""
        with self._engine.begin() as conn:
            return conn.execute(text("DELETE FROM perf_sources WHERE captured_at < :t"), {"t": captured_before}).rowcount or 0

    # ------------------------------------------------------------------ recording
    def record(self, result: AnalysisResult, *, source_kind: str, source_id: str, name: str,
               captured_at: float | None = None) -> int:
        """Store this capture's per-domain observations; returns how many domains were recorded."""
        if not self.enabled:
            return 0
        when = captured_at if captured_at is not None else (
            result.metadata.first_packet_time or result.metadata.analyzed_at.timestamp())
        obs = [observation_from_performance(p, source_id=source_id, source_name=name, captured_at=when)
               for p in result.performance_statistics.domains if p.connections > 0]
        if not obs:
            return 0
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM perf_observations WHERE source_id = :s"), {"s": source_id})  # re-analysis replaces
            conn.execute(text("""
                INSERT INTO perf_sources (source_id, source_kind, name, captured_at, recorded_at)
                VALUES (:s, :k, :n, :t, :r)
                ON CONFLICT(source_id) DO UPDATE SET source_kind=:k, name=:n, captured_at=:t, recorded_at=:r"""),
                {"s": source_id, "k": source_kind, "n": name[:200], "t": when, "r": datetime.now(timezone.utc).isoformat()})
            conn.execute(text(f"""
                INSERT INTO perf_observations ({", ".join(_COLUMNS)}) VALUES ({", ".join(":" + c for c in _COLUMNS)})"""),
                [self._row(o) for o in obs])
            for o in obs:
                conn.execute(text("""
                    DELETE FROM perf_observations WHERE domain = :d AND rowid NOT IN (
                        SELECT rowid FROM perf_observations WHERE domain = :d ORDER BY captured_at DESC, source_id DESC LIMIT :m)"""),
                    {"d": o.domain, "m": self.max_per_domain})
            conn.execute(text("DELETE FROM perf_sources WHERE source_id NOT IN (SELECT DISTINCT source_id FROM perf_observations)"))
        return len(obs)

    @staticmethod
    def _row(o: Observation) -> dict:
        v, s = o.values, o.samples
        return {"source_id": o.source_id, "domain": o.domain, "captured_at": o.captured_at, "connections": o.connections,
                "handshake_ms": v.get("tcp_handshake_ms"), "handshake_samples": s.get("tcp_handshake_ms", 0),
                "rtt_avg_ms": v.get("avg_rtt_ms"), "rtt_p95_ms": v.get("p95_rtt_ms"), "rtt_samples": s.get("avg_rtt_ms", 0),
                "dns_ms": v.get("dns_latency_ms"), "dns_lookups": s.get("dns_latency_ms", 0),
                "response_ms": v.get("response_ms"), "response_samples": s.get("response_ms", 0),
                "tcp_packets": o.tcp_packets, "retransmissions": o.retransmissions,
                "tcp_attempted": o.attempted, "tcp_failed": o.failed}

    # ------------------------------------------------------------------ reading
    def _domain_series(self, domains: list[str], until: float | None) -> dict[str, list[Observation]]:
        """Observations per domain, oldest first (at most ``_FETCH_PER_DOMAIN`` latest, none after ``until``)."""
        out: dict[str, list[Observation]] = {}
        if not domains:
            return out
        with self._engine.connect() as conn:
            for chunk_start in range(0, len(domains), 500):
                chunk = domains[chunk_start:chunk_start + 500]
                params = {f"d{i}": d for i, d in enumerate(chunk)}
                params["until"] = until if until is not None else 1e18
                rows = conn.execute(text(f"""
                    SELECT o.*, s.name FROM perf_observations o JOIN perf_sources s USING (source_id)
                    WHERE o.domain IN ({", ".join(":" + k for k in params if k != "until")}) AND o.captured_at <= :until
                    ORDER BY o.domain, o.captured_at, o.source_id"""), params).mappings().all()
                for row in rows:
                    out.setdefault(row["domain"], []).append(_from_row(row))
        return {d: obs[-_FETCH_PER_DOMAIN:] for d, obs in out.items()}

    def _source_time(self, source_id: str) -> float | None:
        with self._engine.connect() as conn:
            return conn.execute(text("SELECT captured_at FROM perf_sources WHERE source_id = :s"), {"s": source_id}).scalar()

    def _evaluate(self, domains: list[str], source_id: str):
        """{domain: (prior_count, comparisons, anomalies)} for the observation ``source_id`` recorded for each domain."""
        at = self._source_time(source_id)
        if at is None:
            return {}
        out = {}
        for domain, series in self._domain_series(domains, at).items():
            idx = next((i for i, o in enumerate(series) if o.source_id == source_id), None)
            if idx is None:
                continue
            comparisons, anomalies = evaluate_observation(series, idx, self.config)
            out[domain] = (idx, comparisons, anomalies)
        return out

    def _source_domains(self, source_id: str) -> list[str]:
        with self._engine.connect() as conn:
            return [r[0] for r in conn.execute(text("SELECT domain FROM perf_observations WHERE source_id = :s ORDER BY domain"), {"s": source_id})]

    def anomalies_for(self, source_id: str | None) -> AnomalyList:
        """Performance anomalies of one capture against the history that preceded it."""
        if not self.enabled:
            return AnomalyList(history_enabled=False, notes=["Performance history is turned off."])
        if source_id is None:
            return AnomalyList(history_enabled=True, notes=list(NOTES))
        evaluated = self._evaluate(self._source_domains(source_id), source_id)
        anomalies: list[PerformanceAnomaly] = []
        judged = 0
        for _, comparisons, found in evaluated.values():
            anomalies += found
            judged += any(c.status in ("normal", "anomalous") for c in comparisons)
        anomalies.sort(key=lambda a: (-a.severity.rank, -a.confidence, a.domain, a.metric))
        return AnomalyList(history_enabled=True, domains_evaluated=len(evaluated), domains_with_baseline=judged,
                           anomalies=anomalies, notes=list(NOTES))

    def anomaly_counts(self, source_id: str | None, domains: list[str]) -> dict[str, int]:
        if not self.enabled or source_id is None:
            return {}
        return {d: len(found) for d, (_, _, found) in self._evaluate(domains, source_id).items() if found}

    def domain_view(self, domain: str, source_id: str | None) -> DomainBaselineView:
        """Baseline vs current for one domain in one capture, plus the domain's stored history for charts."""
        if not self.enabled:
            return DomainBaselineView(domain=domain, history_enabled=False, notes=["Performance history is turned off."])
        series = self._domain_series([domain], None).get(domain, [])
        idx = next((i for i, o in enumerate(series) if o.source_id == source_id), None) if source_id else None
        comparisons: list[MetricComparison] = []
        anomalies: list[PerformanceAnomaly] = []
        if idx is not None:
            comparisons, anomalies = evaluate_observation(series, idx, self.config)
        history = [HistoryPoint(
            t=o.captured_at, source_name=o.source_name, current=i == idx,
            tcp_handshake_ms=o.values.get("tcp_handshake_ms"), avg_rtt_ms=o.values.get("avg_rtt_ms"),
            p95_rtt_ms=o.values.get("p95_rtt_ms"), dns_latency_ms=o.values.get("dns_latency_ms"),
            response_ms=o.values.get("response_ms"),
            retransmission_rate=o.retransmissions / o.tcp_packets if o.tcp_packets else None,
            failure_rate=o.failed / o.attempted if o.attempted else None) for i, o in enumerate(series)]
        return DomainBaselineView(domain=domain, history_enabled=True, prior_observations=idx if idx is not None else len(series),
                                  comparisons=comparisons, anomalies=anomalies, history=history, notes=list(NOTES))

    def network_normals(self, source_id: str | None, *, max_sources: int | None = None, min_sources: int | None = None) -> tuple[int, dict[str, float], dict[str, int]]:
        """Pooled, sample-weighted "normal" values over this computer's earlier captures (all domains together).

        ``max_sources`` / ``min_sources`` default to the baseline window / minimum samples of the Performance settings.
        Returns ``(earlier captures used, {metric: value}, {metric: samples})``. Fewer than ``min_sources`` earlier captures
        means no baseline: the dict is empty. The capture ``source_id`` itself is never part of its own normal.
        """
        if not self.enabled:
            return 0, {}, {}
        max_sources = max_sources or self.config.window
        min_sources = self.config.min_observations if min_sources is None else min_sources
        at = self._source_time(source_id) if source_id else None
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT o.* FROM perf_observations o
                WHERE o.source_id IN (
                    SELECT source_id FROM perf_sources WHERE (:s IS NULL OR source_id != :s) AND (:at IS NULL OR captured_at < :at)
                    ORDER BY captured_at DESC LIMIT :n)"""), {"s": source_id, "at": at, "n": max_sources}).mappings().all()
        sources = len({r["source_id"] for r in rows})
        if sources < min_sources:
            return sources, {}, {}

        def weighted(value: str, weight: str) -> tuple[float, int] | None:
            pairs = [(r[value], r[weight]) for r in rows if r[value] is not None and r[weight] > 0]
            n = sum(w for _, w in pairs)
            return (sum(v * w for v, w in pairs) / n, n) if n else None

        out: dict[str, float] = {}
        samples: dict[str, int] = {}
        for key, (value, weight) in {"handshake_ms": ("handshake_ms", "handshake_samples"), "avg_rtt_ms": ("rtt_avg_ms", "rtt_samples"),
                                     "p95_rtt_ms": ("rtt_p95_ms", "rtt_samples"), "dns_ms": ("dns_ms", "dns_lookups"),
                                     "response_ms": ("response_ms", "response_samples")}.items():
            w = weighted(value, weight)
            if w:
                out[key], samples[key] = round(w[0], 3), w[1]
        packets, retrans = sum(r["tcp_packets"] for r in rows), sum(r["retransmissions"] for r in rows)
        attempted, failed = sum(r["tcp_attempted"] for r in rows), sum(r["tcp_failed"] for r in rows)
        if packets:
            out["retransmission_rate"], samples["retransmission_rate"] = retrans / packets, packets
        if attempted:
            out["failure_rate"], samples["failure_rate"] = failed / attempted, attempted
        return sources, out, samples

    # ------------------------------------------------------------------ housekeeping
    def status(self) -> HistoryStatus:
        with self._engine.connect() as conn:
            row = conn.execute(text("""
                SELECT (SELECT COUNT(*) FROM perf_sources), COUNT(*), COUNT(DISTINCT domain), MIN(captured_at), MAX(captured_at)
                FROM perf_observations""")).one()
        return HistoryStatus(enabled=self.enabled, sources=row[0], observations=row[1], domains=row[2], oldest=row[3], newest=row[4],
                             notes=list(NOTES))

    def clear(self) -> int:
        """Delete all stored history; returns the number of observations removed."""
        with self._engine.begin() as conn:
            n = conn.execute(text("SELECT COUNT(*) FROM perf_observations")).scalar() or 0
            conn.execute(text("DELETE FROM perf_observations"))
            conn.execute(text("DELETE FROM perf_sources"))
        return int(n)


_history: PerformanceHistory | None = None


def get_history() -> PerformanceHistory:
    """The app-wide history bound to the local database (tests replace ``_history``)."""
    global _history
    if _history is None:
        from app.database import engine

        from app.services.effective_config import baseline_config, history_enabled

        _history = PerformanceHistory(engine, enabled=settings.perf_history_enabled,
                                      max_per_domain=settings.perf_history_max_per_domain)
        _history.config_provider, _history.gate = baseline_config, history_enabled  # follow Settings → Performance / Domains
    return _history
