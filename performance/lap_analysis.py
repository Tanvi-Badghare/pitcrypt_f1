"""
lap_analysis.py
----------------
Turns raw per-frame telemetry into lap-level performance metrics,
one row per (driver, lap).

Important:
`observed_span_s` is the timestamp span of the supplied telemetry
frames. It is NOT presented as an official or physical lap time unless
the input timestamps are known to represent track-time elapsed time.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Mapping, Sequence

import pandas as pd


DRS_OPEN_CODES = frozenset({10, 12, 14})
FULL_THROTTLE_THRESHOLD = 99.0


@dataclass(frozen=True)
class LapKey:
    driver: str
    lap: int


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(value)


def _group_by_lap(
    frames: Iterable[Mapping],
) -> dict[LapKey, list[Mapping]]:
    groups: dict[LapKey, list[Mapping]] = {}

    for frame in frames:
        key = LapKey(
            driver=frame["driver"],
            lap=int(frame["lap"]),
        )

        groups.setdefault(key, []).append(frame)

    return groups


def _sorted_by_time(
    frames: list[Mapping],
) -> list[Mapping]:
    return sorted(
        frames,
        key=lambda f: _parse_timestamp(f["timestamp"]),
    )


def _pct(
    values: Sequence,
    predicate: Callable,
) -> float:
    if not values:
        return 0.0

    return (
        100.0
        * sum(1 for value in values if predicate(value))
        / len(values)
    )


class LapAnalyzer:
    """
    Computes lap-level metrics from raw telemetry frames.

    Stateless and read-only.
    """

    COLUMNS = [
        "driver",
        "lap",
        "n_frames",
        "observed_span_s",
        "distance_covered_m",
        "top_speed_kph",
        "avg_speed_kph",
        "speed_std_kph",
        "avg_throttle_pct",
        "full_throttle_pct",
        "throttle_change_std",
        "braking_pct",
        "drs_active_pct",
        "gear_shift_count",
    ]

    def analyze(
        self,
        frames: Iterable[Mapping],
    ) -> pd.DataFrame:
        groups = _group_by_lap(frames)

        if not groups:
            return pd.DataFrame(columns=self.COLUMNS)

        rows = [
            self._lap_metrics(key, group)
            for key, group in groups.items()
        ]

        return (
            pd.DataFrame(rows, columns=self.COLUMNS)
            .sort_values(["driver", "lap"])
            .reset_index(drop=True)
        )

    def _lap_metrics(
        self,
        key: LapKey,
        frames: list[Mapping],
    ) -> dict:
        ordered = _sorted_by_time(frames)
        n = len(ordered)

        speeds = [float(f["Speed"]) for f in ordered]
        throttles = [float(f["Throttle"]) for f in ordered]
        brakes = [f["Brake"] for f in ordered]
        drs_values = [f["DRS"] for f in ordered]
        gears = [f["nGear"] for f in ordered]
        distances = [float(f["Distance"]) for f in ordered]

        timestamps = [
            _parse_timestamp(f["timestamp"])
            for f in ordered
        ]

        throttle_deltas = [
            throttles[i] - throttles[i - 1]
            for i in range(1, n)
        ]

        return {
            "driver": key.driver,
            "lap": key.lap,
            "n_frames": n,

            "observed_span_s": (
                timestamps[-1] - timestamps[0]
            ).total_seconds(),

            "distance_covered_m": (
                max(distances) - min(distances)
            ),

            "top_speed_kph": max(speeds),

            "avg_speed_kph": statistics.fmean(speeds),

            "speed_std_kph": statistics.pstdev(speeds),

            "avg_throttle_pct": (
                statistics.fmean(throttles)
            ),

            "full_throttle_pct": _pct(
                throttles,
                lambda value: (
                    value >= FULL_THROTTLE_THRESHOLD
                ),
            ),

            "throttle_change_std": (
                statistics.pstdev(throttle_deltas)
                if throttle_deltas
                else 0.0
            ),

            "braking_pct": _pct(
                brakes,
                bool,
            ),

            "drs_active_pct": _pct(
                drs_values,
                lambda value: value in DRS_OPEN_CODES,
            ),

            "gear_shift_count": sum(
                1
                for i in range(1, n)
                if gears[i] != gears[i - 1]
            ),
        }