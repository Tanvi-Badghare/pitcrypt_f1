"""
test_sector_analysis.py
--------------------------
Covers: empty input, sector boundary assignment, sector timing/speed
correctness, and multi-lap grouping.
"""

from __future__ import annotations

import pandas as pd
import pytest

from performance.sector_analysis import SectorAnalyzer


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


@pytest.fixture
def analyzer() -> SectorAnalyzer:
    return SectorAnalyzer(num_sectors=3)


def test_empty_input_returns_empty_dataframe_with_expected_columns(analyzer):
    result = analyzer.analyze([])
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    assert list(result.columns) == SectorAnalyzer.COLUMNS


def test_rejects_invalid_num_sectors():
    with pytest.raises(ValueError):
        SectorAnalyzer(num_sectors=0)


def test_frames_split_into_three_equal_distance_sectors(analyzer):
    # Distance 0..90m over 10 frames -> sectors [0,30), [30,60), [60,90].
    frames = [
        make_frame(
            timestamp=f"2026-09-24T20:00:{i:02d}.000000+00:00",
            Distance=float(i * 10),
            Speed=100.0 + i,
        )
        for i in range(10)
    ]

    result = analyzer.analyze(frames)

    assert len(result) == 3
    assert list(result["sector"]) == [1, 2, 3]
    # Sector 1: Distance 0,10,20 (< 30)
    assert result.iloc[0]["n_frames"] == 3
    # Sector 2: Distance 30,40,50 (< 60)
    assert result.iloc[1]["n_frames"] == 3
    # Sector 3: Distance 60,70,80,90 (<= 90, last sector is closed)
    assert result.iloc[2]["n_frames"] == 4


def test_sector_time_and_top_speed(analyzer):
    frames = [
        make_frame(timestamp="2026-09-24T20:00:00+00:00", Distance=0.0, Speed=100.0),
        make_frame(timestamp="2026-09-24T20:00:01+00:00", Distance=10.0, Speed=150.0),
        make_frame(timestamp="2026-09-24T20:00:02+00:00", Distance=95.0, Speed=200.0),
    ]
    result = SectorAnalyzer(num_sectors=1).analyze(frames)

    assert len(result) == 1
    row = result.iloc[0]
    assert row["observed_span_s"] == pytest.approx(2.0)
    assert row["top_speed_kph"] == pytest.approx(200.0)
    assert row["avg_speed_kph"] == pytest.approx(150.0)


def test_multi_lap_grouping(analyzer):
    frames = [
        make_frame(lap=1, timestamp="2026-09-24T20:00:00+00:00", Distance=0.0),
        make_frame(lap=1, timestamp="2026-09-24T20:00:01+00:00", Distance=90.0),
        make_frame(lap=2, timestamp="2026-09-24T20:01:00+00:00", Distance=0.0),
        make_frame(lap=2, timestamp="2026-09-24T20:01:01+00:00", Distance=90.0),
    ]
    result = analyzer.analyze(frames)
    assert set(result["lap"]) == {1, 2}