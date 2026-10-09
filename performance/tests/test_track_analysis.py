"""
test_track_analysis.py
--------------------------
Covers: empty input, reference-lap auto-selection, track map ordering,
length estimation, and sector-boundary point lookup.
"""

from __future__ import annotations

import pandas as pd
import pytest

from performance.track_analysis import TrackAnalyzer


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
def analyzer() -> TrackAnalyzer:
    return TrackAnalyzer()


def test_empty_input(analyzer):
    result = analyzer.get_track_map([])
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    assert analyzer.track_length_m([]) == 0.0


def test_track_map_sorted_by_distance_regardless_of_input_order(analyzer):
    frames = [
        make_frame(Distance=100.0, X=10.0, Y=10.0),
        make_frame(Distance=0.0, X=0.0, Y=0.0),
        make_frame(Distance=50.0, X=5.0, Y=5.0),
    ]
    result = analyzer.get_track_map(frames)
    assert list(result["Distance"]) == [0.0, 50.0, 100.0]
    assert list(result["X"]) == [0.0, 5.0, 10.0]


def test_track_length_estimate(analyzer):
    frames = [
        make_frame(Distance=0.0),
        make_frame(Distance=250.5),
    ]
    assert analyzer.track_length_m(frames) == pytest.approx(250.5)


def test_defaults_to_first_driver_lap_when_unspecified(analyzer):
    frames = [
        make_frame(driver="RUS", lap=1, Distance=0.0),
        make_frame(driver="RUS", lap=1, Distance=100.0),
        make_frame(driver="VER", lap=1, Distance=0.0),
        make_frame(driver="VER", lap=1, Distance=500.0),
    ]
    # First frame in the list belongs to RUS -> should be used as the
    # fallback reference lap.
    result = analyzer.get_track_map(frames)
    assert set(result["driver"]) == {"RUS"}
    assert analyzer.track_length_m(frames) == pytest.approx(100.0)


def test_explicit_driver_and_lap_selection(analyzer):
    frames = [
        make_frame(driver="RUS", lap=1, Distance=0.0),
        make_frame(driver="RUS", lap=1, Distance=100.0),
        make_frame(driver="VER", lap=1, Distance=0.0),
        make_frame(driver="VER", lap=1, Distance=500.0),
    ]
    result = analyzer.get_track_map(frames, driver="VER", lap=1)
    assert set(result["driver"]) == {"VER"}
    assert analyzer.track_length_m(frames, driver="VER", lap=1) == pytest.approx(500.0)


def test_sector_boundary_points_returns_actual_observed_samples(analyzer):
    frames = [
        make_frame(Distance=0.0, X=0.0, Y=0.0),
        make_frame(Distance=30.0, X=3.0, Y=3.0),
        make_frame(Distance=60.0, X=6.0, Y=6.0),
        make_frame(Distance=90.0, X=9.0, Y=9.0),
    ]
    boundaries = analyzer.sector_boundary_points(frames, num_sectors=3)

    # num_sectors=3 -> 4 boundary points (0%, 33%, 67%, 100%)
    assert len(boundaries) == 4
    assert boundaries.iloc[0]["distance_m"] == pytest.approx(0.0)
    assert boundaries.iloc[-1]["distance_m"] == pytest.approx(90.0)
    # every returned point must be one of the actual observed samples
    observed_distances = {0.0, 30.0, 60.0, 90.0}
    assert set(boundaries["distance_m"]).issubset(observed_distances)