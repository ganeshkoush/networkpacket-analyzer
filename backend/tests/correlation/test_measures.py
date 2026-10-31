"""Window-vs-reference comparisons: minimum data, normal variation, significant change, burst localisation."""
import pytest

from app.correlation.measures import Gates, compare_latency, compare_proportions, compare_rates, find_burst

GATES = Gates(min_in=3, min_out=5, min_abs=10.0, min_ratio=1.25)
OUT = [(float(i), 40.0 + (i % 5) - 2) for i in range(60)]  # 38..42 ms for a minute


def inside(values, start=100.0):
    return [(start + i, v) for i, v in enumerate(values)]


# ------------------------------------------------------------------ latency
def test_latency_needs_samples_on_both_sides():
    few_in = compare_latency(inside([180, 190]), OUT, GATES)
    assert few_in.status == "insufficient" and "inside the window" in few_in.reason and few_in.n_in == 2
    few_out = compare_latency(inside([180, 190, 185]), OUT[:4], GATES)
    assert few_out.status == "insufficient" and "reference" in few_out.reason and few_out.n_out == 4


def test_a_clear_increase_is_significant_with_onset_and_ratio():
    c = compare_latency(inside([40, 41, 175, 180, 185, 190]), OUT, GATES)
    assert c.significant and c.ratio == pytest.approx(182.5 / 40, abs=0.2) and c.z >= 3.5
    assert c.outside == pytest.approx(40, abs=1) and c.inside == pytest.approx(182.5) and c.n_in == 4  # the run of slow samples
    assert c.onset == 102.0 and c.last == 105.0  # first/last affected sample, not the window edges


def test_a_slowdown_filling_only_part_of_a_wide_window_is_not_diluted():
    wide = inside([40, 41, 39, 40, 41, 40, 39, 40] + [170, 175, 180, 185] + [40, 41, 40, 39, 40, 41, 40, 40])  # 4 slow of 20
    c = compare_latency(wide, OUT, GATES)
    assert c.significant and c.n_in == 4 and c.onset == 108.0 and c.last == 111.0
    whole = compare_latency(wide, OUT, GATES, temporal=False)  # the whole-group median is normal: a different question
    assert whole.status == "not_significant"


def test_isolated_spikes_are_not_a_run():
    spiky = inside([40, 200, 41, 210, 40, 205, 42, 200, 41])
    assert compare_latency(spiky, OUT, GATES).status == "not_significant"


def test_ordinary_variation_is_not_significant():
    c = compare_latency(inside([39, 42, 41, 40, 38]), OUT, GATES)
    assert c.status == "not_significant" and c.onset is None


def test_a_decrease_is_never_significant():
    assert compare_latency(inside([5, 6, 5, 6]), OUT, GATES).status == "not_significant"


def test_small_absolute_changes_are_ignored_even_if_statistically_large():
    flat = [(float(i), 2.0) for i in range(30)]
    c = compare_latency(inside([5.0, 5.0, 5.0]), flat, GATES)  # +150 %, but only 3 ms
    assert c.status == "not_significant" and c.z > 3.5


def test_a_noisy_reference_needs_a_bigger_change():
    noisy = [(float(i), v) for i, v in enumerate([20, 90, 35, 140, 28, 75, 50, 110, 30, 95, 40, 60])]
    assert compare_latency(inside([130, 150, 140]), noisy, GATES).status == "not_significant"
    assert compare_latency(inside([130, 150, 140]), [(float(i), 45.0) for i in range(12)], GATES).significant


# ------------------------------------------------------------------ rates
def test_rate_increase_is_detected_with_the_first_elevated_second():
    background = [i * 2.0 for i in range(40)]                      # 0.5 events/s for 80 s
    burst = [100 + k / 30 for k in range(300)]                     # 30 events/s for 10 s
    c = compare_rates(burst, 10.0, background, 90.0, Gates(10, 5, 0.5, 1.5))
    assert c.significant and c.ratio == pytest.approx(30 / (40 / 90), rel=0.05) and c.onset == 100.0 and c.last == 110.0


def test_a_steady_rate_is_not_an_increase():
    steady = [i * 2.0 for i in range(100)]
    inside_ = [t for t in steady if 100 <= t < 120]
    outside = [t for t in steady if not 100 <= t < 120]
    assert compare_rates(inside_, 20.0, outside, 180.0, Gates(5, 5, 0.1, 1.5)).status == "not_significant"


def test_rates_need_enough_events_and_reference_time():
    assert compare_rates([1.0, 2.0], 10.0, [float(i) for i in range(20)], 100.0, Gates(10, 5, 0.5, 1.5)).status == "insufficient"
    assert compare_rates([float(i) for i in range(30)], 10.0, [1.0, 2.0], 100.0, Gates(10, 5, 0.5, 1.5)).status == "insufficient"
    assert compare_rates([float(i) for i in range(30)], 10.0, [float(i) for i in range(20)], 0.0, Gates(10, 5, 0.5, 1.5)).status == "insufficient"


# ------------------------------------------------------------------ proportions
def test_failure_share_increase():
    c = compare_proportions([float(i) for i in range(40)], 50, 2, 100, Gates(5, 10, 0.05, 1.0))
    assert c.significant and c.inside == pytest.approx(0.8) and c.outside == pytest.approx(0.02) and c.onset == 0.0


def test_similar_failure_shares_are_not_significant():
    assert compare_proportions([1.0] * 5, 50, 10, 100, Gates(5, 10, 0.05, 1.0)).status == "not_significant"


def test_failure_share_needs_attempts_on_both_sides():
    assert compare_proportions([1.0, 2.0], 3, 0, 100, Gates(5, 10, 0.05, 1.0)).status == "insufficient"
    assert compare_proportions([1.0] * 5, 20, 0, 4, Gates(5, 10, 0.05, 1.0)).status == "insufficient"


# ------------------------------------------------------------------ burst localisation
def test_find_burst_narrows_a_broad_window_to_the_dense_part():
    times = [float(i) for i in range(180)] + [60 + k / 300 for k in range(3000)]
    burst = find_burst(times, 0.0, 180.0)
    assert burst == (60.0, 70.0)


def test_find_burst_returns_none_without_a_clear_burst_or_when_it_is_the_whole_window():
    assert find_burst([float(i) for i in range(100)], 0.0, 100.0) is None            # steady
    assert find_burst([i / 50 for i in range(500)], 0.0, 10.0) is None                # the burst IS the window
    assert find_burst([1.0, 2.0], 0.0, 3.0) is None                                   # too short to judge
