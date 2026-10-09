"""
sector_analysis.py
------------------
Splits each lap into fixed-distance sectors and computes per-sector
telemetry metrics.

Sector boundaries are calculated independently for each (driver, lap)
from that lap's observed Distance range.

`observed_span_s` is the timestamp span of the frames belonging to the
sector. It is not presented as an official physical sector time unless
the source timestamps are known to represent track-time elapsed time.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping

import pandas as pd


DEFAULT_NUM_SECTORS = 3


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


def _sorted_by_distance(
    frames: list[Mapping],
) -> list[Mapping]:
    return sorted(
        frames,
        key=lambda f: float(f["Distance"]),
    )


def _sorted_by_time(
    frames: list[Mapping],
) -> list[Mapping]:
    return sorted(
        frames,
        key=lambda f: _parse_timestamp(f["timestamp"]),
    )


class SectorAnalyzer:
    """
    Computes per-sector telemetry metrics.

    Stateless and read-only.
    """

    COLUMNS = [
        "driver",
        "lap",
        "sector",
        "n_frames",
        "distance_start_m",
        "distance_end_m",
        "observed_span_s",
        "top_speed_kph",
        "avg_speed_kph",
        "avg_throttle_pct",
        "braking_pct",
    ]

    def __init__(
        self,
        num_sectors: int = DEFAULT_NUM_SECTORS,
    ):
        if num_sectors < 1:
            raise ValueError(
                "num_sectors must be >= 1"
            )

        self.num_sectors = num_sectors

    def analyze(
        self,
        frames: Iterable[Mapping],
    ) -> pd.DataFrame:
        groups = _group_by_lap(frames)

        if not groups:
            return pd.DataFrame(columns=self.COLUMNS)

        rows: list[dict] = []

        for key, group in groups.items():
            rows.extend(
                self._lap_sectors(key, group)
            )

        if not rows:
            return pd.DataFrame(columns=self.COLUMNS)

        return (
            pd.DataFrame(
                rows,
                columns=self.COLUMNS,
            )
            .sort_values(
                ["driver", "lap", "sector"]
            )
            .reset_index(drop=True)
        )

    def _lap_sectors(
        self,
        key: LapKey,
        frames: list[Mapping],
    ) -> list[dict]:
        ordered = _sorted_by_distance(frames)

        distances = [
            float(f["Distance"])
            for f in ordered
        ]

        dist_min = min(distances)
        dist_max = max(distances)
        span = dist_max - dist_min

        rows: list[dict] = []

        for sector_idx in range(self.num_sectors):
            lo = (
                dist_min
                + span * sector_idx / self.num_sectors
            )

            hi = (
                dist_min
                + span * (sector_idx + 1)
                / self.num_sectors
            )

            if sector_idx == self.num_sectors - 1:
                sector_frames = [
                    f
                    for f in ordered
                    if lo <= float(f["Distance"]) <= hi
                ]
            else:
                sector_frames = [
                    f
                    for f in ordered
                    if lo <= float(f["Distance"]) < hi
                ]

            if not sector_frames:
                continue

            rows.append(
                self._sector_metrics(
                    key,
                    sector_idx + 1,
                    sector_frames,
                    lo,
                    hi,
                )
            )

        return rows

    def _sector_metrics(
        self,
        key: LapKey,
        sector_number: int,
        frames: list[Mapping],
        lo: float,
        hi: float,
    ) -> dict:
        speeds = [
            float(f["Speed"])
            for f in frames
        ]

        throttles = [
            float(f["Throttle"])
            for f in frames
        ]

        brakes = [
            f["Brake"]
            for f in frames
        ]

        ordered_by_time = _sorted_by_time(frames)

        timestamps = [
            _parse_timestamp(f["timestamp"])
            for f in ordered_by_time
        ]

        return {
            "driver": key.driver,
            "lap": key.lap,
            "sector": sector_number,
            "n_frames": len(frames),

            "distance_start_m": lo,
            "distance_end_m": hi,

            "observed_span_s": (
                timestamps[-1] - timestamps[0]
            ).total_seconds(),

            "top_speed_kph": max(speeds),

            "avg_speed_kph": (
                statistics.fmean(speeds)
            ),

            "avg_throttle_pct": (
                statistics.fmean(throttles)
            ),

            "braking_pct": (
                100.0
                * sum(
                    1 for brake in brakes
                    if bool(brake)
                )
                / len(brakes)
            ),
        }