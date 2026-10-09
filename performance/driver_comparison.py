"""
driver_comparison.py
-----------------------
Compares two drivers' laps against each other: lap-level metric deltas
(reusing `LapAnalyzer`) and a distance-aligned speed trace with a
running speed delta - the same idea as the "driver comparison" speed
traces common in F1 broadcast/analysis tools.

    SensorSimulator
           |
        frames
           |
    DriverComparison
           |
    lap-metric delta dict  +  distance-aligned speed-delta DataFrame

Read-only: only ever consumes frames handed to it, never the simulator.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

import numpy as np
import pandas as pd

from .lap_analysis import LapAnalyzer


def _normalize_frames(frames) -> list[Mapping]:
    """Accept either the raw frame stream (list/iterable of dicts) or a
    pandas DataFrame of the same rows, and always return a list of
    dicts. Without this, passing a DataFrame accidentally (e.g. handing
    over an already-aggregated metrics table by mistake) fails with a
    cryptic "string indices must be integers" error, because iterating
    a DataFrame directly yields its column names, not its rows.
    """
    if isinstance(frames, pd.DataFrame):
        frames = frames.to_dict("records")
    else:
        frames = list(frames)

    _validate_raw_frames(frames)
    return frames


_REQUIRED_RAW_FRAME_FIELDS = ("driver", "lap", "timestamp", "Speed", "Distance")


def _validate_raw_frames(frames: list[Mapping]) -> None:
    """Raise a clear error if `frames` isn't the raw per-frame telemetry
    stream. The most common mistake is passing an already-aggregated
    table (e.g. LapAnalyzer's output) instead - which looks superficially
    similar (it's rows with a 'driver' and 'lap' column) but is missing
    per-frame fields like 'timestamp' and 'Speed', and produces a
    confusing bare KeyError deep inside LapAnalyzer without this check.
    """
    if not frames:
        return
    missing = [f for f in _REQUIRED_RAW_FRAME_FIELDS if f not in frames[0]]
    if missing:
        raise ValueError(
            "DriverComparison expects the raw per-frame telemetry stream "
            "(the same frames you pass to LapAnalyzer/SectorAnalyzer/"
            "CornerAnalyzer), not an already-aggregated metrics table. "
            f"The first row is missing field(s): {missing}. If you're "
            "passing LapAnalyzer's output here, pass the original raw "
            "frames instead - DriverComparison computes lap metrics "
            "internally."
        )


def _frames_for(frames: list[Mapping], driver: str, lap: int) -> list[Mapping]:
    return [f for f in frames if f["driver"] == driver and int(f["lap"]) == lap]


def _sorted_by_distance(frames: list[Mapping]) -> list[Mapping]:
    return sorted(frames, key=lambda f: f["Distance"])


class DriverComparison:
    """Stateless comparator between two drivers' laps drawn from a
    shared raw frame stream.
    """

    def __init__(self):
        self._lap_analyzer = LapAnalyzer()

    def _resolve_lap(self, frames: list[Mapping], driver: str, lap: Optional[int]) -> int:
        """Default to the driver's fastest completed lap (by
        lap_time_s) when `lap` isn't specified.
        """
        if lap is not None:
            return lap
        lap_metrics = self._lap_analyzer.analyze(frames)
        driver_laps = lap_metrics[lap_metrics["driver"] == driver]
        if driver_laps.empty:
            raise ValueError(f"no frames found for driver {driver!r}")
        fastest = driver_laps.sort_values("observed_span_s").iloc[0]
        return int(fastest["lap"])

    def compare_laps(
        self,
        frames: Iterable[Mapping],
        driver_a: str,
        driver_b: str,
        lap_a: Optional[int] = None,
        lap_b: Optional[int] = None,
    ) -> dict:
        """Compare one lap-metrics row per driver (each driver's fastest
        lap by default) and return per-metric deltas (`driver_a` minus
        `driver_b`) alongside both raw rows.
        """
        frames = _normalize_frames(frames)
        lap_a = self._resolve_lap(frames, driver_a, lap_a)
        lap_b = self._resolve_lap(frames, driver_b, lap_b)

        lap_metrics = self._lap_analyzer.analyze(frames)
        row_a = lap_metrics[(lap_metrics["driver"] == driver_a) & (lap_metrics["lap"] == lap_a)]
        row_b = lap_metrics[(lap_metrics["driver"] == driver_b) & (lap_metrics["lap"] == lap_b)]
        if row_a.empty:
            raise ValueError(f"no data for {driver_a!r} lap {lap_a}")
        if row_b.empty:
            raise ValueError(f"no data for {driver_b!r} lap {lap_b}")
        row_a, row_b = row_a.iloc[0], row_b.iloc[0]

        numeric_cols = [c for c in LapAnalyzer.COLUMNS if c not in ("driver", "lap")]
        deltas = {c: row_a[c] - row_b[c] for c in numeric_cols}

        return {
            "driver_a": driver_a,
            "lap_a": lap_a,
            "driver_b": driver_b,
            "lap_b": lap_b,
            "metrics_a": row_a.to_dict(),
            "metrics_b": row_b.to_dict(),
            "delta_a_minus_b": deltas,
        }

    def compare_speed_traces(
        self,
        frames: Iterable[Mapping],
        driver_a: str,
        driver_b: str,
        lap_a: Optional[int] = None,
        lap_b: Optional[int] = None,
        num_samples: int = 200,
    ) -> pd.DataFrame:
        """Resample both drivers' Speed-vs-Distance traces for the given
        (or each driver's fastest) lap onto a shared distance grid and
        return distance, both speeds, and the delta at each point.

        The grid spans the *overlapping* distance range of both laps, so
        laps of slightly different measured length can still be compared
        directly.
        """
        frames = _normalize_frames(frames)
        lap_a = self._resolve_lap(frames, driver_a, lap_a)
        lap_b = self._resolve_lap(frames, driver_b, lap_b)

        frames_a = _sorted_by_distance(_frames_for(frames, driver_a, lap_a))
        frames_b = _sorted_by_distance(_frames_for(frames, driver_b, lap_b))
        if len(frames_a) < 2:
            raise ValueError(f"need >= 2 frames for {driver_a!r} lap {lap_a}")
        if len(frames_b) < 2:
            raise ValueError(f"need >= 2 frames for {driver_b!r} lap {lap_b}")

        dist_a = np.array([f["Distance"] for f in frames_a], dtype=float)
        speed_a = np.array([f["Speed"] for f in frames_a], dtype=float)
        dist_b = np.array([f["Distance"] for f in frames_b], dtype=float)
        speed_b = np.array([f["Speed"] for f in frames_b], dtype=float)

        common_lo = max(dist_a.min(), dist_b.min())
        common_hi = min(dist_a.max(), dist_b.max())
        if common_hi <= common_lo:
            raise ValueError("the two laps share no overlapping distance range")

        grid = np.linspace(common_lo, common_hi, num_samples)
        resampled_a = np.interp(grid, dist_a, speed_a)
        resampled_b = np.interp(grid, dist_b, speed_b)

        return pd.DataFrame(
            {
                "distance_m": grid,
                f"speed_{driver_a}_kph": resampled_a,
                f"speed_{driver_b}_kph": resampled_b,
                "speed_delta_kph": resampled_a - resampled_b,
            }
        )