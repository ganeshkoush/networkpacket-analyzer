"""Statistics for historical performance baselines (pure functions: no I/O, no packets).

For one domain and one metric the *current* observation (one capture) is compared with a rolling window of the
domain's earlier observations. Nothing here uses a single fixed cut-off on its own:

* **Latency metrics (ms)** are positive and right-skewed, so they are compared on a log scale with a robust
  z-score: ``z = (ln current - median(ln history)) / max(1.4826 * MAD(ln history), min_log_sd)``. The median/MAD
  pair ignores earlier outliers; the floor stops a perfectly flat history from turning tiny wobble into "significant".
* **Rate metrics** (retransmission rate, connection failure rate) use a binomial z-test against the pooled historical
  rate, with a scale widened to the observed observation-to-observation spread (real traffic is over-dispersed).
* An anomaly also needs the current value to exceed the history's 95th percentile (percentile comparison), enough
  samples in the current capture, enough earlier observations, and an effect size worth reporting (relative and
  absolute floors), so statistically "significant" but trivial changes are not announced.
* Only worsening (higher) values are anomalies. Anything with too little data says why instead of concluding.

Confidence combines baseline depth, current sample depth, effect size, baseline stability and persistence.
"""
from __future__ import annotations

import hashlib
import math
import statistics
from dataclasses import dataclass, field
from typing import Literal

from app.detection.severity import (
    ConfidenceBounds, Severity, confidence_from_score, min_severity, ramp, weighted_score,
)
from app.models.baseline import (
    ConfidenceLabel, MetricBaseline, MetricComparison, MetricName, PerformanceAnomaly,
)

_MAD_TO_SD = 1.4826
_FLOOR_MS = 0.01  # ln() guard


@dataclass(frozen=True)
class MetricSpec:
    name: MetricName
    label: str
    unit: Literal["ms", "%"]
    kind: Literal["latency", "rate"]
    min_current: int  # samples (latency) or events base (rate: packets / connections) needed in the current capture
    min_baseline: int  # same, for an earlier observation to count towards the baseline
    min_abs_increase: float  # ms, or absolute rate increase (fraction)


METRICS: tuple[MetricSpec, ...] = (
    MetricSpec("tcp_handshake_ms", "TCP handshake", "ms", "latency", 3, 1, 10.0),
    MetricSpec("avg_rtt_ms", "Average RTT", "ms", "latency", 10, 5, 10.0),
    MetricSpec("p95_rtt_ms", "P95 RTT", "ms", "latency", 20, 10, 20.0),
    MetricSpec("dns_latency_ms", "DNS latency", "ms", "latency", 2, 1, 10.0),
    MetricSpec("response_ms", "Response time", "ms", "latency", 3, 1, 20.0),
    MetricSpec("retransmission_rate", "Retransmission rate", "%", "rate", 200, 100, 0.01),
    MetricSpec("failure_rate", "Connection failure rate", "%", "rate", 10, 5, 0.05),
)
SPECS = {m.name: m for m in METRICS}


@dataclass(frozen=True)
class BaselineConfig:
    window: int = 30  # most recent earlier observations that form the baseline
    min_observations: int = 5  # earlier observations needed before anything may be called anomalous
    z_threshold: float = 3.5
    min_log_sd: float = 0.10  # smallest spread assumed for latency (about 10 % typical variation)
    min_rel_increase: float = 0.25  # latency must also be at least this much above the typical value
    max_run_lookback: int = 30  # how far back to look for the start of an anomaly run
    bounds: ConfidenceBounds = field(default_factory=ConfidenceBounds)


DEFAULT_CONFIG = BaselineConfig()


@dataclass(frozen=True)
class Observation:
    """What one capture showed for one domain (aggregates only)."""

    source_id: str
    source_name: str
    captured_at: float
    domain: str
    connections: int = 0
    values: dict[str, float | None] = field(default_factory=dict)  # latency metrics
    samples: dict[str, int] = field(default_factory=dict)  # samples behind each latency value
    tcp_packets: int = 0
    retransmissions: int = 0
    attempted: int = 0
    failed: int = 0

    def metric(self, spec: MetricSpec) -> tuple[float | None, int]:
        """(value, sample size) of ``spec`` in this observation; value None when it was not measured."""
        if spec.name == "retransmission_rate":
            return (self.retransmissions / self.tcp_packets if self.tcp_packets else None), self.tcp_packets
        if spec.name == "failure_rate":
            return (self.failed / self.attempted if self.attempted else None), self.attempted
        return self.values.get(spec.name), self.samples.get(spec.name, 0)


# --------------------------------------------------------------------- small statistics
def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (pct in 0..100) of an unsorted list."""
    ordered = sorted(values)
    return ordered[max(1, math.ceil(pct / 100 * len(ordered))) - 1]


def _std(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def window_stats(values: list[float], observations: int | None = None) -> MetricBaseline:
    """Distribution of ``values``; ``observations`` is the window size before outliers were set aside."""
    return MetricBaseline(
        observations=observations if observations is not None else len(values),
        excluded_outliers=(observations - len(values)) if observations is not None else 0, mean=round(statistics.fmean(values), 6), std=round(_std(values), 6),
        median=round(statistics.median(values), 6), p95=round(percentile(values, 95), 6),
        min=round(min(values), 6), max=round(max(values), 6))


def _inlier_mask(values: list[float], spec: MetricSpec, cfg: BaselineConfig) -> list[bool]:
    """False for unusually *high* values inside the window itself (robust z >= threshold).

    The baseline should describe usual behaviour: if it also learned from earlier anomalies, a problem that
    persists for a few captures would raise the window's own percentile/spread and hide itself. Median/MAD are
    robust, so the window can still adapt to a lasting level shift once the new level is the majority.
    """
    if len(values) < 3:
        return [True] * len(values)
    if spec.kind == "latency":
        xs, floor = [math.log(max(v, _FLOOR_MS)) for v in values], cfg.min_log_sd
    else:
        xs, floor = list(values), 0.002
    center = statistics.median(xs)
    scale = max(statistics.median([abs(x - center) for x in xs]) * _MAD_TO_SD, floor)
    return [(x - center) / scale < cfg.z_threshold for x in xs]


def _eligible(spec: MetricSpec, prior: list[Observation], window: int) -> list[tuple[float, int, Observation]]:
    out = []
    for obs in prior:
        value, n = obs.metric(spec)
        if value is not None and n >= spec.min_baseline:
            out.append((value, n, obs))
    return out[-window:]


# --------------------------------------------------------------------- comparison
def compare_metric(spec: MetricSpec, current: Observation, prior: list[Observation],
                   cfg: BaselineConfig = DEFAULT_CONFIG) -> MetricComparison:
    """Compare ``current`` with the rolling window of ``prior`` (earlier observations, oldest first)."""
    value, n_cur = current.metric(spec)
    base = dict(metric=spec.name, label=spec.label, unit=spec.unit, current=value, current_samples=n_cur)
    if value is None:
        return MetricComparison(status="no_data", note="Not measurable in this capture.", **base)
    window = _eligible(spec, prior, cfg.window)
    history = [v for v, _, _ in window]  # robust centre/spread (z-score) use the whole window
    mask = _inlier_mask(history, spec, cfg)
    clean = [w for w, keep in zip(window, mask) if keep] or window  # distribution statistics skip earlier outliers
    baseline = window_stats([v for v, _, _ in clean], observations=len(window)) if history else None
    base["baseline"] = baseline
    if len(history) < cfg.min_observations:
        return MetricComparison(
            status="insufficient_baseline",
            note=f"Baseline needs {cfg.min_observations} earlier observations with this metric; {len(history)} so far.", **base)
    typical = baseline.median  # type: ignore[union-attr]
    rel = (value - typical) / typical if typical > 0 else None
    base["relative_change"] = None if rel is None else round(rel, 4)

    if spec.kind == "latency":
        z = _latency_z(value, history, cfg)
    else:
        z = _rate_z(value, n_cur, clean, cfg)
    base["z_score"] = round(z, 2)
    if n_cur < spec.min_current:
        return MetricComparison(
            status="insufficient_current",
            note=f"This capture has {n_cur} samples for this metric; at least {spec.min_current} are needed to judge it.", **base)

    anomalous = (
        z >= cfg.z_threshold
        and value >= baseline.p95  # type: ignore[union-attr]
        and value - typical >= spec.min_abs_increase
        and (spec.kind == "rate" or (rel is not None and rel >= cfg.min_rel_increase)))
    return MetricComparison(status="anomalous" if anomalous else "normal", **base)


def latency_z(value: float, history: list[float], cfg: BaselineConfig = DEFAULT_CONFIG) -> float:
    """Robust log-scale z-score of ``value`` against ``history`` (median / scaled MAD, spread floored at ``min_log_sd``)."""
    return _latency_z(value, history, cfg)


def _latency_z(value: float, history: list[float], cfg: BaselineConfig) -> float:
    logs = [math.log(max(v, _FLOOR_MS)) for v in history]
    center = statistics.median(logs)
    mad = statistics.median([abs(x - center) for x in logs]) * _MAD_TO_SD
    return (math.log(max(value, _FLOOR_MS)) - center) / max(mad, cfg.min_log_sd)


def _rate_z(value: float, n_current: int, window: list[tuple[float, int, Observation]], cfg: BaselineConfig) -> float:
    rates = [v for v, _, _ in window]
    total_n = sum(n for _, n, _ in window)
    pooled = sum(v * n for v, n, _ in window) / total_n if total_n else 0.0
    se = math.sqrt(max(pooled, 0.001) * (1 - min(pooled, 0.999)) / max(n_current, 1))
    scale = max(se, _std(rates), 1e-4)  # binomial noise, widened to the real observation-to-observation spread
    return (value - pooled) / scale


# --------------------------------------------------------------------- anomalies
def confidence_label(confidence: float) -> ConfidenceLabel:
    return "High" if confidence >= 0.70 else "Medium" if confidence >= 0.50 else "Low"


def _severity(z: float, confidence: float) -> Severity:
    by_effect = Severity.HIGH if z >= 8 else Severity.MEDIUM if z >= 5 else Severity.LOW
    cap = Severity.HIGH if confidence >= 0.70 else Severity.MEDIUM if confidence >= 0.50 else Severity.LOW
    return min_severity(by_effect, cap)  # a weakly-supported deviation is never rated above LOW


def severity_for(z: float, confidence: float) -> Severity:
    """Severity of a deviation with z-score ``z``, never higher than the confidence supports."""
    return _severity(z, confidence)


def _anomaly_run(spec: MetricSpec, domain_obs: list[Observation], index: int, cfg: BaselineConfig) -> list[Observation]:
    """Consecutive anomalous observations ending at ``domain_obs[index]`` (each judged against its own history)."""
    run = [domain_obs[index]]
    for i in range(index - 1, max(index - 1 - cfg.max_run_lookback, -1), -1):
        if compare_metric(spec, domain_obs[i], domain_obs[:i], cfg).status != "anomalous":
            break
        run.append(domain_obs[i])
    return run[::-1]


def build_anomaly(spec: MetricSpec, comp: MetricComparison, domain_obs: list[Observation], index: int,
                  cfg: BaselineConfig = DEFAULT_CONFIG) -> PerformanceAnomaly:
    """Turn an "anomalous" comparison of ``domain_obs[index]`` into a record with run, confidence and evidence."""
    assert comp.status == "anomalous" and comp.baseline is not None and comp.current is not None and comp.z_score is not None
    current, b = domain_obs[index], comp.baseline
    run = _anomaly_run(spec, domain_obs, index, cfg)
    cv = b.std / abs(b.mean) if b.mean else 1.0
    score = weighted_score([
        (0.25, ramp(b.observations, cfg.min_observations, cfg.window)),
        (0.20, ramp(comp.current_samples, spec.min_current, 5 * spec.min_current)),
        (0.30, ramp(comp.z_score, cfg.z_threshold, 3 * cfg.z_threshold)),
        (0.10, 1 - ramp(cv, 0.25, 1.0)),
        (0.15, ramp(len(run), 1, 3)),
    ])
    confidence = confidence_from_score(score, cfg.bounds)
    rel = comp.relative_change or 0.0
    fmt = _fmt(spec)
    evidence = [
        *([f"{b.excluded_outliers} earlier unusual observation(s) were not learned from."] if b.excluded_outliers else []),
        f"{spec.label} was {fmt(comp.current)} in this capture ({comp.current_samples:,} "
        f"{'packets' if spec.name == 'retransmission_rate' else 'connections' if spec.name == 'failure_rate' else 'samples'}), "
        f"against a typical {fmt(b.median)} over the previous {b.observations} observations "
        f"(mean {fmt(b.mean)}, range {fmt(b.min)}–{fmt(b.max)}).",
        f"That is {rel:+.0%} versus the typical value and above the 95th percentile of the usual history ({fmt(b.p95)}).",
        f"Robust z-score {comp.z_score:.1f} ({'log scale, median/MAD' if spec.kind == 'latency' else 'binomial, widened to the observed spread'}); "
        f"significance threshold {cfg.z_threshold:g}.",
    ]
    if len(run) > 1:
        evidence.append(f"The previous {len(run) - 1} observation(s) of this domain were also unusual for this metric.")
    return PerformanceAnomaly(
        id=hashlib.sha1(f"{current.domain}|{spec.name}|{run[0].captured_at}".encode()).hexdigest()[:12],
        domain=current.domain, metric=spec.name, label=spec.label, unit=spec.unit,
        baseline=b.median, baseline_mean=b.mean, baseline_std=b.std, baseline_observations=b.observations,
        current_value=comp.current, deviation=round(rel, 4), absolute_change=round(comp.current - b.median, 6),
        z_score=comp.z_score, severity=_severity(comp.z_score, confidence), confidence=confidence,
        confidence_label=confidence_label(confidence), first_seen=run[0].captured_at, last_seen=current.captured_at,
        observations_in_run=len(run), evidence=evidence,
        caveats=["This is a possible performance change relative to this domain's own earlier captures, not a diagnosis.",
                 "Different networks, capture points, times of day or server locations can shift these measurements."])


def _fmt(spec: MetricSpec):
    return (lambda v: f"{v:.0f} ms") if spec.unit == "ms" else (lambda v: f"{v:.1%}")


def evaluate_observation(domain_obs: list[Observation], index: int,
                         cfg: BaselineConfig = DEFAULT_CONFIG) -> tuple[list[MetricComparison], list[PerformanceAnomaly]]:
    """Compare ``domain_obs[index]`` (one domain, oldest first) with everything before it.

    Returns every metric's comparison and the anomaly records for those that are anomalous.
    """
    current, prior = domain_obs[index], domain_obs[:index]
    comparisons, anomalies = [], []
    for spec in METRICS:
        comp = compare_metric(spec, current, prior, cfg)
        comparisons.append(comp)
        if comp.status == "anomalous":
            anomalies.append(build_anomaly(spec, comp, domain_obs, index, cfg))
    return comparisons, anomalies
