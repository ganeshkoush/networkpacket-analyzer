"""Window-vs-reference comparisons used to find performance changes around a security finding.

Three tests, matching the kind of metric (all pure functions):

* ``compare_latency``: median of the samples inside the window against the robust log-scale distribution of the
  samples outside it (same z-score as the history baselines), with a percentile gate and effect-size floors.
* ``compare_rates``: events per second inside vs outside (two-sample Poisson z-test).
* ``compare_proportions``: failures per attempt inside vs outside (one-sided two-proportion z-test).

A comparison is only "significant" if it clears the z threshold *and* an effect-size floor, and it says
"insufficient" (with the reason) when either side has too little data, so nothing is concluded from a handful of points.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Literal

from app.analysis.baseline import DEFAULT_CONFIG, BaselineConfig, latency_z, percentile


@dataclass(frozen=True)
class Comparison:
    status: Literal["significant", "not_significant", "insufficient"]
    reason: str = ""
    inside: float = 0.0
    outside: float = 0.0
    ratio: float | None = None  # inside / outside
    z: float = 0.0
    n_in: int = 0
    n_out: int = 0
    outside_mean: float = 0.0
    outside_std: float = 0.0
    onset: float | None = None  # first affected sample/event inside the window
    last: float | None = None   # last affected sample/event inside the window

    @property
    def significant(self) -> bool:
        return self.status == "significant"


@dataclass(frozen=True)
class Gates:
    """Minimum data and effect size for a comparison to count."""

    min_in: int = 3
    min_out: int = 5
    min_abs: float = 10.0       # smallest absolute increase worth reporting (ms, events/s, or a rate fraction)
    min_ratio: float = 1.25     # inside / outside must be at least this


def _second_counts(times: list[float], lo: float, hi: float) -> tuple[int, list[int]]:
    """(first whole second, events per whole second) over [lo, hi), zero-filled."""
    sec0 = math.floor(lo)
    counts = [0] * max(1, math.ceil(hi) - sec0)
    for t in times:
        if lo <= t < hi:
            counts[min(int(t) - sec0, len(counts) - 1)] += 1
    return sec0, counts


def find_burst(times: list[float], lo: float, hi: float, *, min_factor: float = 3.0, min_count: int = 5) -> tuple[float, float] | None:
    """Narrow [lo, hi] to the dense burst of ``times`` inside it, or None if there is no clear burst.

    Per-second counts are compared with their median/MAD (robust to the burst itself); seconds clearly above the usual
    level form clusters (gaps of up to 2 s are bridged) and the heaviest cluster wins. Used because a finding's own
    first/last-seen can span all of a host's traffic, background included.
    """
    if hi - lo < 4:
        return None
    sec0, counts = _second_counts(times, lo, hi)
    med = statistics.median(counts)
    mad = statistics.median(abs(c - med) for c in counts) * 1.4826
    threshold = max(med + 5 * max(mad, 1.0), min_factor * max(med, 1.0), min_count)
    hot = [i for i, c in enumerate(counts) if c >= threshold]
    if not hot:
        return None
    clusters, cur = [], [hot[0]]
    for i in hot[1:]:
        if i - cur[-1] <= 3:
            cur.append(i)
        else:
            clusters.append(cur)
            cur = [i]
    clusters.append(cur)
    best = max(clusters, key=lambda c: sum(counts[i] for i in c))
    start, end = float(sec0 + best[0]), float(sec0 + best[-1] + 1)
    return (start, end) if end - start < 0.8 * (hi - lo) else None


def _insufficient(reason: str, n_in: int, n_out: int) -> Comparison:
    return Comparison("insufficient", reason, n_in=n_in, n_out=n_out)


def compare_latency(inside: list[tuple[float, float]], outside: list[tuple[float, float]], gates: Gates,
                    cfg: BaselineConfig = DEFAULT_CONFIG, *, temporal: bool = True) -> Comparison:
    """``inside``/``outside``: (time, value) samples. Only increases are significant.

    With ``temporal`` (samples ordered in time) the window is searched for a *run* of consecutive samples that are all
    above the reference's usual range, and that run is tested against the reference. A slowdown that fills only part of
    the (padded) window is therefore not diluted by the normal samples around it, and its start/end are exact. If no such
    run exists the whole group's median is tested instead (and ``temporal=False`` always does this, for groups of
    connections that are not ordered in time).
    """
    n_in, n_out = len(inside), len(outside)
    if n_in < gates.min_in:
        return _insufficient(f"only {n_in} sample(s) inside the window (need {gates.min_in})", n_in, n_out)
    if n_out < gates.min_out:
        return _insufficient(f"only {n_out} reference sample(s) outside the window (need {gates.min_out})", n_in, n_out)
    ref = [v for _, v in outside]
    typical = statistics.median(ref)
    p95 = percentile(ref, 95)
    bar = max(p95, typical * gates.min_ratio)

    def judge(samples: list[tuple[float, float]]) -> Comparison:
        cur = statistics.median(v for _, v in samples)
        z = latency_z(cur, ref, cfg)
        ratio = cur / typical if typical > 0 else None
        ok = (z >= cfg.z_threshold and cur >= p95 and cur - typical >= gates.min_abs and ratio is not None and ratio >= gates.min_ratio)
        affected = [t for t, v in samples if v >= bar]
        return Comparison("significant" if ok else "not_significant", inside=cur, outside=typical, ratio=ratio, z=z, n_in=len(samples), n_out=n_out,
                          outside_mean=statistics.fmean(ref), outside_std=statistics.stdev(ref) if n_out > 1 else 0.0,
                          onset=min(affected) if affected else None, last=max(affected) if affected else None)

    if temporal:
        ordered = sorted(inside)
        runs, cur_run = [], []
        for s in ordered:
            if s[1] >= bar:
                cur_run.append(s)
            else:
                if len(cur_run) >= gates.min_in:
                    runs.append(cur_run)
                cur_run = []
        if len(cur_run) >= gates.min_in:
            runs.append(cur_run)
        verdicts = [judge(run) for run in runs]
        best = max((v for v in verdicts if v.significant), key=lambda v: (v.z, v.n_in), default=None)
        if best is not None:
            return best
    return judge(inside)


def compare_rates(times_in: list[float], span_in: float, times_out: list[float], span_out: float, gates: Gates,
                  cfg: BaselineConfig = DEFAULT_CONFIG) -> Comparison:
    """Events per second inside a window of ``span_in`` seconds vs the rest of the capture (``span_out`` seconds)."""
    k_in, k_out = len(times_in), len(times_out)
    if k_in < gates.min_in:
        return _insufficient(f"only {k_in} event(s) inside the window (need {gates.min_in})", k_in, k_out)
    if k_out < gates.min_out or span_out <= 0 or span_in <= 0:
        return _insufficient(f"only {k_out} reference event(s) over {max(span_out, 0):.0f}s outside the window (need {gates.min_out})", k_in, k_out)
    r_in, r_out = k_in / span_in, k_out / span_out
    z = (r_in - r_out) / math.sqrt(r_in / span_in + r_out / span_out)  # Var(rate) = rate / duration for a Poisson process
    ratio = r_in / r_out
    significant = z >= cfg.z_threshold and ratio >= gates.min_ratio and r_in - r_out >= gates.min_abs
    # onset/last: the first/last *elevated* second (not merely the first event: background traffic is always present)
    lo = min(times_in)
    sec0, counts = _second_counts(times_in, lo, max(times_in) + 1e-6)
    bar = max(r_out * gates.min_ratio, r_out + 3 * math.sqrt(max(r_out, 0.5)))
    hot = [sec0 + i for i, c in enumerate(counts) if c >= bar]
    return Comparison("significant" if significant else "not_significant", inside=r_in, outside=r_out, ratio=ratio, z=z,
                      n_in=k_in, n_out=k_out, onset=float(min(hot)) if hot else lo, last=float(max(hot) + 1) if hot else max(times_in))


def compare_proportions(fail_in: list[float], n_in: int, fail_out: int, n_out: int, gates: Gates,
                        cfg: BaselineConfig = DEFAULT_CONFIG) -> Comparison:
    """Failures per attempt: ``fail_in`` are the failure times inside the window, ``n_in`` the attempts inside."""
    k_in = len(fail_in)
    if n_in < gates.min_in:
        return _insufficient(f"only {n_in} connection attempt(s) inside the window (need {gates.min_in})", n_in, n_out)
    if n_out < gates.min_out:
        return _insufficient(f"only {n_out} reference connection attempt(s) outside the window (need {gates.min_out})", n_in, n_out)
    p_in, p_out = k_in / n_in, fail_out / n_out
    pooled = (k_in + fail_out) / (n_in + n_out)
    se = math.sqrt(max(pooled * (1 - pooled), 1e-6) * (1 / n_in + 1 / n_out))
    z = (p_in - p_out) / se
    significant = z >= cfg.z_threshold and p_in - p_out >= gates.min_abs
    return Comparison("significant" if significant else "not_significant", inside=p_in, outside=p_out,
                      ratio=(p_in / p_out) if p_out > 0 else None, z=z, n_in=n_in, n_out=n_out,
                      onset=min(fail_in) if fail_in else None, last=max(fail_in) if fail_in else None)
