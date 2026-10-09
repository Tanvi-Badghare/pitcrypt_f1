"""
test_driver_comparison.py
----------------------------
Covers: fastest-lap auto-selection, lap-metric delta correctness, and
distance-aligned speed-trace interpolation/delta.
"""

from __future__ import annotations

import pytest

from performance.driver_comparison import DriverComparison


def make_frame(**overrides) -> dict:
    frame = {
        "lap": 1,
        "driver": "RUS",
        "timestamp": "2026-09-24T20:00:00.000000+00:00",
        "Speed": 100.0,
        "RPM": 10000.0,
        "Throttle": 50.0,
        "Brake": 0,
        "nGear": 3,
        "DRS": 0,
        "X": 0.0,
        "Y": 0.0,
        "Distance": 0.0,
    }
    frame.update(overrides)
    return frame


def make_lap(driver: str, lap: int, start_ts: str, n: int, speed_fn, distance_step: float = 50.0) -> list[dict]:
    """Build `n` evenly time-spaced frames for one lap; `speed_fn(i)`
    gives the speed at frame index `i`.
    """
    import datetime

    start = datetime.datetime.fromisoformat(start_ts)
    frames = []
    for i in range(n):
        ts = (start + datetime.timedelta(seconds=i)).isoformat()
        frames.append(
            make_frame(
                driver=driver,
                lap=lap,
                timestamp=ts,
                Speed=speed_fn(i),
                Distance=i * distance_step,
            )
        )
    return frames


@pytest.fixture
def comparison() -> DriverComparison:
    return DriverComparison()


def test_compare_laps_picks_fastest_lap_by_default(comparison):
    # RUS: lap 1 takes 4s, lap 2 takes 2s (faster) -> should auto-pick lap 2.
    frames = (
        make_lap("RUS", 1, "2026-09-24T20:00:00+00:00", n=5, speed_fn=lambda i: 100.0)
        + make_lap("RUS", 2, "2026-09-24T20:01:00+00:00", n=3, speed_fn=lambda i: 150.0)
        + make_lap("VER", 1, "2026-09-24T20:00:00+00:00", n=3, speed_fn=lambda i: 120.0)
    )

    result = comparison.compare_laps(frames, "RUS", "VER")

    assert result["lap_a"] == 2  # RUS's faster lap
    assert result["lap_b"] == 1
    assert result["metrics_a"]["avg_speed_kph"] == pytest.approx(150.0)


def test_compare_laps_delta_sign(comparison):
    frames = (
        make_lap("RUS", 1, "2026-09-24T20:00:00+00:00", n=3, speed_fn=lambda i: 200.0)
        + make_lap("VER", 1, "2026-09-24T20:00:00+00:00", n=3, speed_fn=lambda i: 150.0)
    )

    result = comparison.compare_laps(frames, "RUS", "VER", lap_a=1, lap_b=1)

    assert result["delta_a_minus_b"]["avg_speed_kph"] == pytest.approx(50.0)
    assert result["delta_a_minus_b"]["top_speed_kph"] == pytest.approx(50.0)


def test_compare_laps_raises_for_missing_driver(comparison):
    frames = make_lap("RUS", 1, "2026-09-24T20:00:00+00:00", n=3, speed_fn=lambda i: 100.0)
    with pytest.raises(ValueError):
        comparison.compare_laps(frames, "RUS", "HAM")


def test_compare_speed_traces_delta(comparison):
    # RUS constant 200 kph, VER constant 150 kph, same distance range.
    frames = (
        make_lap("RUS", 1, "2026-09-24T20:00:00+00:00", n=5, speed_fn=lambda i: 200.0, distance_step=25.0)
        + make_lap("VER", 1, "2026-09-24T20:00:00+00:00", n=5, speed_fn=lambda i: 150.0, distance_step=25.0)
    )

    trace = comparison.compare_speed_traces(frames, "RUS", "VER", lap_a=1, lap_b=1, num_samples=10)

    assert len(trace) == 10
    assert (trace["speed_delta_kph"] - 50.0).abs().max() < 1e-6
    assert trace["distance_m"].is_monotonic_increasing


def test_compare_speed_traces_raises_when_too_few_frames(comparison):
    frames = make_lap("RUS", 1, "2026-09-24T20:00:00+00:00", n=1, speed_fn=lambda i: 100.0) + make_lap(
        "VER", 1, "2026-09-24T20:00:00+00:00", n=3, speed_fn=lambda i: 100.0
    )
    with pytest.raises(ValueError):
        comparison.compare_speed_traces(frames, "RUS", "VER", lap_a=1, lap_b=1)