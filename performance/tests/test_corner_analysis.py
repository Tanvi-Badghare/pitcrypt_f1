"""
test_corner_analysis.py
-----------------------
Tests for dependency-free corner detection.
"""

from __future__ import annotations

import pandas as pd
import pytest

from performance.corner_analysis import CornerAnalyzer


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


def frames_from_speeds(
    speeds: list[float],
    *,
    distance_step: float = 10.0,
    **shared,
) -> list[dict]:
    return [
        make_frame(
            timestamp=(
                f"2026-09-24T20:00:{i:02d}.000000+00:00"
            ),
            Distance=float(i * distance_step),
            Speed=speed,
            **shared,
        )
        for i, speed in enumerate(speeds)
    ]


@pytest.fixture
def analyzer() -> CornerAnalyzer:
    return CornerAnalyzer(
        min_prominence_kph=15.0,
        smoothing_window=1,
        min_corner_separation_m=20.0,
        trend_tolerance_kph=0.0,
    )


def test_empty_input(analyzer):
    result = analyzer.analyze([])

    assert isinstance(result, pd.DataFrame)
    assert result.empty
    assert list(result.columns) == CornerAnalyzer.COLUMNS


def test_detects_single_clear_corner(analyzer):
    speeds = [
        300,
        300,
        280,
        200,
        150,
        100,
        150,
        200,
        280,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)

    for frame in frames[2:6]:
        frame["Brake"] = 1

    result = analyzer.analyze(frames)

    assert len(result) == 1

    row = result.iloc[0]

    assert row["apex_speed_kph"] == pytest.approx(100.0)
    assert row["entry_speed_kph"] == pytest.approx(300.0)
    assert row["exit_speed_kph"] == pytest.approx(300.0)

    assert row["entry_distance_m"] < row["apex_distance_m"]
    assert row["apex_distance_m"] < row["exit_distance_m"]

    assert bool(row["braked_before_apex"]) is True


def test_shallow_dip_below_prominence_threshold_is_ignored(analyzer):
    speeds = [
        300,
        300,
        297,
        295,
        297,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)

    result = analyzer.analyze(frames)

    assert result.empty


def test_lower_threshold_detects_shallow_dip():
    speeds = [
        300,
        300,
        297,
        295,
        297,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)

    result = CornerAnalyzer(
        min_prominence_kph=3.0,
        smoothing_window=1,
        min_corner_separation_m=10.0,
        trend_tolerance_kph=0.0,
    ).analyze(frames)

    assert len(result) == 1
    assert result.iloc[0]["apex_speed_kph"] == pytest.approx(295.0)


def test_detects_multiple_corners_in_order(analyzer):
    speeds = [
        300,
        300,
        150,
        100,
        150,
        300,
        300,
        300,
        200,
        120,
        200,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)

    result = analyzer.analyze(frames)

    assert len(result) == 2
    assert list(result["corner_number"]) == [1, 2]

    assert result.iloc[0]["apex_speed_kph"] == pytest.approx(100.0)
    assert result.iloc[1]["apex_speed_kph"] == pytest.approx(120.0)

    assert (
        result.iloc[0]["entry_distance_m"]
        < result.iloc[1]["entry_distance_m"]
    )

    assert (
        result.iloc[0]["exit_distance_m"]
        <= result.iloc[1]["entry_distance_m"]
    )


def test_overlapping_minima_in_same_braking_zone_produce_one_corner():
    """
    Two nearby minima represent one braking zone rather than two
    independent corners. The stronger minimum should survive.
    """
    speeds = [
        300,
        280,
        220,
        150,
        100,
        120,
        105,
        125,
        180,
        240,
        300,
    ]

    frames = frames_from_speeds(
        speeds,
        distance_step=10.0,
    )

    result = CornerAnalyzer(
        min_prominence_kph=15.0,
        smoothing_window=1,
        min_corner_separation_m=40.0,
        trend_tolerance_kph=0.0,
    ).analyze(frames)

    assert len(result) == 1
    assert result.iloc[0]["apex_speed_kph"] == pytest.approx(100.0)


def test_corner_windows_never_overlap(analyzer):
    speeds = [
        300,
        300,
        150,
        100,
        150,
        300,
        300,
        300,
        200,
        120,
        200,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)

    result = analyzer.analyze(frames)

    for previous, current in zip(
        result.iloc[:-1].to_dict("records"),
        result.iloc[1:].to_dict("records"),
    ):
        assert (
            previous["exit_distance_m"]
            <= current["entry_distance_m"]
        )


def test_multi_lap_grouping_detects_corners_independently(analyzer):
    speeds = [
        300,
        300,
        150,
        100,
        150,
        300,
        300,
    ]

    lap1 = frames_from_speeds(speeds, lap=1)
    lap2 = frames_from_speeds(speeds, lap=2)

    result = analyzer.analyze(lap1 + lap2)

    assert set(result["lap"]) == {1, 2}
    assert len(result) == 2


def test_does_not_mutate_input(analyzer):
    speeds = [
        300,
        300,
        150,
        100,
        150,
        300,
        300,
    ]

    frames = frames_from_speeds(speeds)
    original = [frame.copy() for frame in frames]

    analyzer.analyze(frames)

    assert frames == original