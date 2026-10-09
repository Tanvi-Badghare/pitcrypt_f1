"""
track_analysis.py
-----------------
Builds a track-level view from raw telemetry frames: the (X, Y) path of
a reference lap, an estimate of track length from that lap's Distance
channel, and the (X, Y) points corresponding to sector boundaries (for
plotting sector markers on a track map alongside sector_analysis.py's
distance-based sectors).

    SensorSimulator
           |
        frames
           |
     TrackAnalyzer
           |
    track map / length / sector-boundary points

Read-only: only ever consumes frames handed to it. Track length here is
an estimate from one lap's telemetry (its Distance range), not a
surveyed circuit length. Use the same reference lap consistently when
comparing outputs across calls.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

import pandas as pd

from .sector_analysis import DEFAULT_NUM_SECTORS


def _frames_for(
    frames: list[Mapping],
    driver: Optional[str],
    lap: Optional[int],
) -> list[Mapping]:
    """Filter frames by the requested driver and/or lap."""
    result = frames

    if driver is not None:
        result = [frame for frame in result if frame["driver"] == driver]

    if lap is not None:
        result = [frame for frame in result if int(frame["lap"]) == lap]

    return result


def _sorted_by_distance(frames: list[Mapping]) -> list[Mapping]:
    """Return frames ordered by telemetry Distance."""
    return sorted(frames, key=lambda frame: frame["Distance"])


class TrackAnalyzer:
    """
    Stateless track-geometry helper.

    Each method can receive an optional driver/lap pair identifying the
    reference lap.

    Reference-lap resolution:
      - driver + lap supplied -> use exactly that combination
      - neither supplied -> use the (driver, lap) pair from the first
        frame in the input stream
      - only driver supplied -> use the first lap encountered for that driver
      - only lap supplied -> use the first driver encountered on that lap

    The result is always restricted to one driver/lap pair.
    """

    def _resolve_reference_lap(
        self,
        frames: list[Mapping],
        driver: Optional[str],
        lap: Optional[int],
    ) -> list[Mapping]:
        """Resolve and return exactly one driver/lap pair."""
        if not frames:
            return []

        # No selection supplied: use the first frame as the reference.
        if driver is None and lap is None:
            first = frames[0]
            driver = first["driver"]
            lap = int(first["lap"])

        # Lap supplied, driver omitted: use the first driver encountered
        # on that lap.
        elif driver is None:
            matches = [
                frame
                for frame in frames
                if int(frame["lap"]) == lap
            ]

            if not matches:
                return []

            driver = matches[0]["driver"]

        # Driver supplied, lap omitted: use the first lap encountered
        # for that driver.
        elif lap is None:
            matches = [
                frame
                for frame in frames
                if frame["driver"] == driver
            ]

            if not matches:
                return []

            lap = int(matches[0]["lap"])

        selected = _frames_for(frames, driver, lap)

        return _sorted_by_distance(selected)

    def get_track_map(
        self,
        frames: Iterable[Mapping],
        driver: Optional[str] = None,
        lap: Optional[int] = None,
    ) -> pd.DataFrame:
        """
        Return the (X, Y, Distance) path of the reference lap,
        sorted by Distance.
        """
        ordered = self._resolve_reference_lap(
            list(frames),
            driver,
            lap,
        )

        if not ordered:
            return pd.DataFrame(
                columns=[
                    "driver",
                    "lap",
                    "Distance",
                    "X",
                    "Y",
                ]
            )

        return pd.DataFrame(
            {
                "driver": [frame["driver"] for frame in ordered],
                "lap": [int(frame["lap"]) for frame in ordered],
                "Distance": [frame["Distance"] for frame in ordered],
                "X": [frame["X"] for frame in ordered],
                "Y": [frame["Y"] for frame in ordered],
            }
        )

    def track_length_m(
        self,
        frames: Iterable[Mapping],
        driver: Optional[str] = None,
        lap: Optional[int] = None,
    ) -> float:
        """
        Estimate track length from the Distance range of the
        reference lap.

        Returns 0.0 when no matching frames are found.
        """
        ordered = self._resolve_reference_lap(
            list(frames),
            driver,
            lap,
        )

        if not ordered:
            return 0.0

        distances = [frame["Distance"] for frame in ordered]

        return max(distances) - min(distances)

    def sector_boundary_points(
        self,
        frames: Iterable[Mapping],
        num_sectors: int = DEFAULT_NUM_SECTORS,
        driver: Optional[str] = None,
        lap: Optional[int] = None,
    ) -> pd.DataFrame:
        """
        Return the observed (X, Y) telemetry samples nearest to each
        distance-based sector boundary.

        No interpolation is performed, so every returned point
        corresponds to an actual telemetry sample.
        """
        ordered = self._resolve_reference_lap(
            list(frames),
            driver,
            lap,
        )

        if not ordered or num_sectors < 1:
            return pd.DataFrame(
                columns=[
                    "sector_boundary",
                    "distance_m",
                    "X",
                    "Y",
                ]
            )

        distances = [frame["Distance"] for frame in ordered]

        dist_min = min(distances)
        dist_max = max(distances)
        span = dist_max - dist_min

        rows = []

        for boundary in range(num_sectors + 1):
            target_distance = (
                dist_min
                + span * boundary / num_sectors
            )

            nearest = min(
                ordered,
                key=lambda frame: abs(
                    frame["Distance"] - target_distance
                ),
            )

            rows.append(
                {
                    "sector_boundary": boundary,
                    "distance_m": nearest["Distance"],
                    "X": nearest["X"],
                    "Y": nearest["Y"],
                }
            )

        return pd.DataFrame(rows)