"""
test_lap_analysis.py
----------------------
Covers: empty input, single-lap metric correctness, grouping of a
mixed/interleaved multi-driver multi-lap stream, gear-shift counting,
DRS status-code handling, and a degenerate single-frame lap.
"""

from __future__ import annotations

import pandas as pd
import pytest

from performance.lap_analysis import LapAnalyzer


def make_frame(**overrides) -> dict:
    """A valid frame matching the simulator's schema, with sane
    defaults; tests override only the fields they care about.
    """
    frame = {
        "lap": 1,
        "driver": "RUS",
        "timestamp": "2026-09-24T20:42:33.000000+00:00",
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


@pytest.fixture
def analyzer() -> LapAnalyzer:
    return LapAnalyzer()


def test_empty_input_returns_empty_dataframe_with_expected_columns(analyzer):
    result = analyzer.analyze([])

    assert isinstance(result, pd.DataFrame)
    assert result.empty
    assert list(result.columns) == LapAnalyzer.COLUMNS


def test_single_lap_basic_metrics(analyzer):
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00.000000+00:00", Speed=100.0, Throttle=50.0, Distance=0.0),
        make_frame(timestamp="2026-09-24T20:00:01.000000+00:00", Speed=200.0, Throttle=100.0, Distance=50.0),
        make_frame(timestamp="2026-09-24T20:00:02.000000+00:00", Speed=150.0, Throttle=75.0, Distance=100.0),
    ]

    result = analyzer.analyze(frames)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["driver"] == "RUS"
    assert row["lap"] == 1
    assert row["n_frames"] == 3
    assert row["observed_span_s"] == pytest.approx(2.0)
    assert row["distance_covered_m"] == pytest.approx(100.0)
    assert row["top_speed_kph"] == pytest.approx(200.0)
    assert row["avg_speed_kph"] == pytest.approx(150.0)
    assert row["full_throttle_pct"] == pytest.approx(100.0 / 3.0)


def test_frames_are_sorted_by_timestamp_regardless_of_input_order(analyzer):
    # Deliberately out of chronological order - the analyzer must sort
    # before computing time- and distance-based metrics.
    frames = [
        make_frame(timestamp="2026-09-24T20:00:02.000000+00:00", Distance=100.0),
        make_frame(timestamp="2026-09-24T20:00:00.000000+00:00", Distance=0.0),
        make_frame(timestamp="2026-09-24T20:00:01.000000+00:00", Distance=50.0),
    ]

    result = analyzer.analyze(frames)

    assert result.iloc[0]["observed_span_s"] == pytest.approx(2.0)
    assert result.iloc[0]["distance_covered_m"] == pytest.approx(100.0)


def test_multi_driver_multi_lap_grouping_on_interleaved_stream(analyzer):
    # Two drivers, two laps each, frames interleaved as they would be if
    # both cars streamed telemetry concurrently.
    frames = [
        make_frame(driver="RUS", lap=1, timestamp="2026-09-24T20:00:00+00:00"),
        make_frame(driver="VER", lap=1, timestamp="2026-09-24T20:00:00+00:00"),
        make_frame(driver="RUS", lap=1, timestamp="2026-09-24T20:00:01+00:00"),
        make_frame(driver="VER", lap=1, timestamp="2026-09-24T20:00:01+00:00"),
        make_frame(driver="RUS", lap=2, timestamp="2026-09-24T20:01:00+00:00"),
        make_frame(driver="VER", lap=2, timestamp="2026-09-24T20:01:00+00:00"),
    ]

    result = analyzer.analyze(frames)

    assert len(result) == 4
    pairs = set(zip(result["driver"], result["lap"]))
    assert pairs == {("RUS", 1), ("RUS", 2), ("VER", 1), ("VER", 2)}
    # sorted by driver then lap
    assert list(result["driver"]) == ["RUS", "RUS", "VER", "VER"]
    assert list(result["lap"]) == [1, 2, 1, 2]


def test_gear_shift_count(analyzer):
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00+00:00", nGear=1),
        make_frame(timestamp="2026-09-24T20:00:01+00:00", nGear=1),  # no shift
        make_frame(timestamp="2026-09-24T20:00:02+00:00", nGear=2),  # shift
        make_frame(timestamp="2026-09-24T20:00:03+00:00", nGear=3),  # shift
        make_frame(timestamp="2026-09-24T20:00:04+00:00", nGear=3),  # no shift
    ]

    result = analyzer.analyze(frames)

    assert result.iloc[0]["gear_shift_count"] == 2


def test_drs_active_pct_only_counts_open_status_codes(analyzer):
    # DRS=1 is "available but not open" per FastF1's coding; only 10/12/14
    # should count as active.
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00+00:00", DRS=0),
        make_frame(timestamp="2026-09-24T20:00:01+00:00", DRS=1),
        make_frame(timestamp="2026-09-24T20:00:02+00:00", DRS=10),
        make_frame(timestamp="2026-09-24T20:00:03+00:00", DRS=12),
    ]

    result = analyzer.analyze(frames)

    assert result.iloc[0]["drs_active_pct"] == pytest.approx(50.0)


def test_braking_pct_counts_nonzero_brake_frames(analyzer):
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00+00:00", Brake=0),
        make_frame(timestamp="2026-09-24T20:00:01+00:00", Brake=1),
        make_frame(timestamp="2026-09-24T20:00:02+00:00", Brake=1),
        make_frame(timestamp="2026-09-24T20:00:03+00:00", Brake=0),
    ]

    result = analyzer.analyze(frames)

    assert result.iloc[0]["braking_pct"] == pytest.approx(50.0)


def test_single_frame_lap_does_not_crash(analyzer):
    frames = [make_frame(timestamp="2026-09-24T20:00:00+00:00")]

    result = analyzer.analyze(frames)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["observed_span_s"] == pytest.approx(0.0)
    assert row["throttle_change_std"] == pytest.approx(0.0)
    assert row["speed_std_kph"] == pytest.approx(0.0)


def test_analyzer_does_not_mutate_input_frames(analyzer):
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00+00:00"),
        make_frame(timestamp="2026-09-24T20:00:01+00:00"),
    ]
    snapshot = [dict(f) for f in frames]

    analyzer.analyze(frames)

    assert frames == snapshot