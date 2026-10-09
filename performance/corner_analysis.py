"""
corner_analysis.py
------------------
Detects corners along a lap from its Speed-vs-Distance profile and
reports entry/apex/exit metrics for each detected corner.

    SensorSimulator
           |
        frames
           |
    CornerAnalyzer
           |
    corner-level metrics (one row per detected corner)

Detection is dependency-free and intentionally conservative.

A corner is identified as a local minimum in speed with sufficient
prominence. Around that minimum, the analyzer determines a bounded
braking/acceleration window, clipped so it can never cross into a
neighbouring corner's territory.

The analyzer is stateless and read-only.

Debug mode:
    CornerAnalyzer(debug=True)

prints the candidate apexes and the entry/exit boundaries before and
after neighbouring-corner clipping. This is intended for development
and validation only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

import pandas as pd


# ---------------------------------------------------------------------
# Default detection parameters
# ---------------------------------------------------------------------

DEFAULT_MIN_PROMINENCE_KPH = 15.0
DEFAULT_SMOOTHING_WINDOW = 5
DEFAULT_MIN_CORNER_SEPARATION_M = 40.0
DEFAULT_TREND_TOLERANCE_KPH = 5.0


# ---------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class LapKey:
    driver: str
    lap: int


@dataclass(frozen=True)
class _Candidate:
    apex_idx: int
    prominence: float


# ---------------------------------------------------------------------
# Input preparation
# ---------------------------------------------------------------------

def _group_by_lap(
    frames: Iterable[Mapping],
) -> dict[LapKey, list[Mapping]]:
    """
    Group frames by driver and lap.
    """
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
    """
    Sort frames by telemetry distance.
    """
    return sorted(
        frames,
        key=lambda f: float(f["Distance"]),
    )


# ---------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------

def _median(values: list[float]) -> float:
    """
    Return the median of a non-empty list.
    """
    ordered = sorted(values)
    n = len(ordered)

    if n % 2:
        return ordered[n // 2]

    return (
        ordered[n // 2 - 1]
        + ordered[n // 2]
    ) / 2.0


def _smooth_speeds(
    speeds: list[float],
    window: int,
) -> list[float]:
    """
    Median smoothing.

    Edge samples use a smaller available window rather than padding the
    signal with artificial values.
    """
    if window <= 1 or len(speeds) <= 2:
        return speeds[:]

    if window % 2 == 0:
        window += 1

    radius = window // 2
    smoothed: list[float] = []

    for i in range(len(speeds)):
        lo = max(0, i - radius)
        hi = min(
            len(speeds),
            i + radius + 1,
        )

        smoothed.append(
            _median(speeds[lo:hi])
        )

    return smoothed


# ---------------------------------------------------------------------
# Local-minimum detection
# ---------------------------------------------------------------------

def _find_local_minima_ranges(
    speeds: list[float],
    tolerance_kph: float,
) -> list[tuple[int, int]]:
    """
    Find local-minimum ranges (start, end inclusive) while tolerating
    small telemetry fluctuations.

    A range spans a flat or near-flat valley bottom in the smoothed
    signal.

    The caller is responsible for choosing the actual apex sample
    within the range using the raw speed data.
    """
    n = len(speeds)

    if n < 3:
        return []

    ranges: list[tuple[int, int]] = []

    i = 1

    while i < n - 1:
        left = speeds[i - 1]
        current = speeds[i]
        right = speeds[i + 1]

        # Start of a potential valley.
        if (
            current <= left + tolerance_kph
            and current <= right + tolerance_kph
        ):
            start = i

            while (
                i < n - 1
                and abs(
                    speeds[i + 1] - speeds[i]
                ) <= tolerance_kph
            ):
                i += 1

            end = i

            left_value = speeds[start - 1]

            right_value = speeds[
                min(end + 1, n - 1)
            ]

            valley_value = min(
                speeds[start : end + 1]
            )

            # Require the valley to be lower than both sides.
            if (
                valley_value
                < left_value - tolerance_kph
                and valley_value
                < right_value - tolerance_kph
            ):
                ranges.append(
                    (start, end)
                )

        i += 1

    return ranges


# ---------------------------------------------------------------------
# Prominence
# ---------------------------------------------------------------------

def _prominence(
    speeds: list[float],
    idx: int,
) -> float:
    """
    Estimate local valley prominence.

    The prominence is the lower of the nearest higher boundaries on
    either side minus the apex speed.
    """
    n = len(speeds)

    apex_speed = speeds[idx]

    left_peak = apex_speed
    right_peak = apex_speed

    # Search left.
    for i in range(idx - 1, -1, -1):
        left_peak = max(
            left_peak,
            speeds[i],
        )

        if (
            i > 0
            and speeds[i - 1] < speeds[i]
        ):
            break

    # Search right.
    for i in range(idx + 1, n):
        right_peak = max(
            right_peak,
            speeds[i],
        )

        if (
            i < n - 1
            and speeds[i + 1] < speeds[i]
        ):
            break

    return min(
        left_peak,
        right_peak,
    ) - apex_speed


# ---------------------------------------------------------------------
# Entry / exit detection
# ---------------------------------------------------------------------

def _find_entry_index(
    speeds: list[float],
    apex_idx: int,
    tolerance_kph: float,
) -> int:
    """
    Walk backwards through the braking/deceleration region.

    The search continues while the previous sample remains consistent
    with the approach to the apex within the configured tolerance.
    """
    idx = apex_idx

    while idx > 0:
        previous = speeds[idx - 1]
        current = speeds[idx]

        if previous >= current - tolerance_kph:
            idx -= 1
        else:
            break

    return idx


def _find_exit_index(
    speeds: list[float],
    apex_idx: int,
    tolerance_kph: float,
) -> int:
    """
    Walk forwards through the acceleration region.

    The search continues while the following sample remains consistent
    with acceleration away from the apex within the configured
    tolerance.
    """
    idx = apex_idx

    while idx < len(speeds) - 1:
        current = speeds[idx]
        following = speeds[idx + 1]

        if following >= current - tolerance_kph:
            idx += 1
        else:
            break

    return idx


# ---------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------

def _candidate_corners(
    speeds: list[float],
    min_prominence_kph: float,
    smoothing_window: int,
    trend_tolerance_kph: float,
) -> list[_Candidate]:
    """
    Generate candidate corner apexes.
    """
    smoothed = _smooth_speeds(
        speeds,
        smoothing_window,
    )

    ranges = _find_local_minima_ranges(
        smoothed,
        tolerance_kph=trend_tolerance_kph,
    )

    candidates: list[_Candidate] = []

    for start, end in ranges:
        # Refine the apex using RAW speed within the detected valley.
        raw_window = speeds[
            start : end + 1
        ]

        apex_idx = (
            start
            + raw_window.index(
                min(raw_window)
            )
        )

        prominence = _prominence(
            smoothed,
            apex_idx,
        )

        if prominence >= min_prominence_kph:
            candidates.append(
                _Candidate(
                    apex_idx=apex_idx,
                    prominence=prominence,
                )
            )

    return candidates


# ---------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------

def _select_non_overlapping_candidates(
    candidates: list[_Candidate],
    distances: list[float],
    min_separation_m: float,
) -> list[_Candidate]:
    """
    Prevent multiple minima in the same braking zone from becoming
    separate corners.

    When candidates are too close together, retain the one with greater
    prominence.
    """
    if not candidates:
        return []

    selected: list[_Candidate] = []

    # Strongest candidates first.
    ranked = sorted(
        candidates,
        key=lambda c: c.prominence,
        reverse=True,
    )

    for candidate in ranked:
        candidate_distance = distances[
            candidate.apex_idx
        ]

        too_close = any(
            abs(
                candidate_distance
                - distances[
                    selected_candidate.apex_idx
                ]
            )
            < min_separation_m
            for selected_candidate
            in selected
        )

        if not too_close:
            selected.append(candidate)

    return sorted(
        selected,
        key=lambda c: c.apex_idx,
    )


# ---------------------------------------------------------------------
# Per-lap detection
# ---------------------------------------------------------------------

def _detect_corners_for_lap(
    key: LapKey,
    frames: list[Mapping],
    min_prominence_kph: float,
    smoothing_window: int,
    min_corner_separation_m: float,
    trend_tolerance_kph: float,
    debug: bool = False,
) -> list[dict]:
    """
    Detect corners for one driver/lap.
    """
    ordered = _sorted_by_distance(frames)

    if len(ordered) < 3:
        return []

    speeds = [
        float(f["Speed"])
        for f in ordered
    ]

    distances = [
        float(f["Distance"])
        for f in ordered
    ]

    # -------------------------------------------------------------
    # Candidate detection
    # -------------------------------------------------------------

    candidates = _candidate_corners(
        speeds=speeds,
        min_prominence_kph=min_prominence_kph,
        smoothing_window=smoothing_window,
        trend_tolerance_kph=trend_tolerance_kph,
    )

    if debug:
        print()
        print("=" * 70)
        print(
            f"[CORNER DEBUG] "
            f"{key.driver} | Lap {key.lap}"
        )
        print("=" * 70)

        print(
            f"Frames: {len(ordered)}"
        )

        print(
            f"Candidates before separation filtering: "
            f"{len(candidates)}"
        )

        for candidate_number, candidate in enumerate(
            candidates,
            start=1,
        ):
            print(
                f"  Candidate {candidate_number}: "
                f"apex={distances[candidate.apex_idx]:.2f} m | "
                f"speed={speeds[candidate.apex_idx]:.2f} km/h | "
                f"prominence={candidate.prominence:.2f} km/h"
            )

    # -------------------------------------------------------------
    # Non-overlapping candidate selection
    # -------------------------------------------------------------

    candidates = _select_non_overlapping_candidates(
        candidates=candidates,
        distances=distances,
        min_separation_m=min_corner_separation_m,
    )

    if debug:
        print()
        print(
            f"[CORNER DEBUG] "
            f"Candidates after "
            f"{min_corner_separation_m:.1f} m separation filtering: "
            f"{len(candidates)}"
        )

        for candidate_number, candidate in enumerate(
            candidates,
            start=1,
        ):
            print(
                f"  Selected {candidate_number}: "
                f"apex={distances[candidate.apex_idx]:.2f} m | "
                f"speed={speeds[candidate.apex_idx]:.2f} km/h | "
                f"prominence={candidate.prominence:.2f} km/h"
            )

    # -------------------------------------------------------------
    # Build final corner records
    # -------------------------------------------------------------

    corners: list[dict] = []

    for i, candidate in enumerate(
        candidates
    ):
        apex_idx = candidate.apex_idx

        # ---------------------------------------------------------
        # Raw entry/exit search
        # ---------------------------------------------------------

        entry_idx = _find_entry_index(
            speeds,
            apex_idx,
            trend_tolerance_kph,
        )

        exit_idx = _find_exit_index(
            speeds,
            apex_idx,
            trend_tolerance_kph,
        )

        raw_entry_idx = entry_idx
        raw_exit_idx = exit_idx

        if debug:
            print()
            print(
                f"[CORNER DEBUG] "
                f"Candidate {i + 1}"
            )

            print(
                f"  Apex: "
                f"{distances[apex_idx]:.2f} m"
            )

            print(
                f"  Raw entry: "
                f"{distances[raw_entry_idx]:.2f} m"
            )

            print(
                f"  Raw exit:  "
                f"{distances[raw_exit_idx]:.2f} m"
            )

            print(
                f"  Raw window: "
                f"{distances[raw_exit_idx] - distances[raw_entry_idx]:.2f} m"
            )

        # ---------------------------------------------------------
        # Clip against neighbouring apexes
        # ---------------------------------------------------------

        if i > 0:
            prev_apex_idx = (
                candidates[i - 1].apex_idx
            )

            entry_idx = max(
                entry_idx,
                (
                    prev_apex_idx
                    + apex_idx
                ) // 2,
            )

        if i < len(candidates) - 1:
            next_apex_idx = (
                candidates[i + 1].apex_idx
            )

            exit_idx = min(
                exit_idx,
                (
                    apex_idx
                    + next_apex_idx
                ) // 2,
            )

        if debug:
            print(
                f"  Clipped entry: "
                f"{distances[entry_idx]:.2f} m"
            )

            print(
                f"  Clipped exit:  "
                f"{distances[exit_idx]:.2f} m"
            )

            print(
                f"  Clipped window: "
                f"{distances[exit_idx] - distances[entry_idx]:.2f} m"
            )

        # ---------------------------------------------------------
        # Validity checks
        # ---------------------------------------------------------

        if not (
            entry_idx
            < apex_idx
            < exit_idx
        ):
            if debug:
                print(
                    "  RESULT: REJECTED "
                    "(invalid entry/apex/exit ordering)"
                )

            continue

        entry = ordered[entry_idx]
        apex = ordered[apex_idx]
        exit_ = ordered[exit_idx]

        entry_distance = float(
            entry["Distance"]
        )

        apex_distance = float(
            apex["Distance"]
        )

        exit_distance = float(
            exit_["Distance"]
        )

        # Physical ordering in distance space.
        if not (
            entry_distance
            < apex_distance
            < exit_distance
        ):
            if debug:
                print(
                    "  RESULT: REJECTED "
                    "(invalid distance ordering)"
                )

            continue

        # ---------------------------------------------------------
        # Final corner record
        # ---------------------------------------------------------

        corner = {
            "driver": key.driver,
            "lap": key.lap,
            "corner_number": len(corners) + 1,
            "entry_distance_m": entry_distance,
            "apex_distance_m": apex_distance,
            "exit_distance_m": exit_distance,
            "entry_speed_kph": float(
                entry["Speed"]
            ),
            "apex_speed_kph": float(
                apex["Speed"]
            ),
            "exit_speed_kph": float(
                exit_["Speed"]
            ),
            "speed_prominence_kph": float(
                candidate.prominence
            ),
            "braked_before_apex": any(
                bool(f["Brake"])
                for f in ordered[
                    entry_idx : apex_idx + 1
                ]
            ),
            "gear_at_apex": apex["nGear"],
        }

        corners.append(corner)

        if debug:
            print(
                "  RESULT: ACCEPTED"
            )

    if debug:
        print()
        print(
            f"[CORNER DEBUG] Final detected corners: "
            f"{len(corners)}"
        )
        print("=" * 70)
        print()

    return corners


# ---------------------------------------------------------------------
# Public analyzer
# ---------------------------------------------------------------------

class CornerAnalyzer:
    """
    Stateless, read-only corner detector.

    `analyze()` groups raw frames by (driver, lap) and returns one row
    per detected corner.

    Parameters
    ----------
    min_prominence_kph:
        Minimum speed prominence required for a local minimum to qualify
        as a corner candidate.

    smoothing_window:
        Median smoothing window applied before local-minimum detection.

    min_corner_separation_m:
        Minimum distance between two accepted apexes.

    trend_tolerance_kph:
        Tolerance used when identifying local-minimum ranges and walking
        through entry/exit regions.

    debug:
        If True, prints candidate and entry/exit diagnostics.
        Intended for development and validation.
    """

    COLUMNS = [
        "driver",
        "lap",
        "corner_number",
        "entry_distance_m",
        "apex_distance_m",
        "exit_distance_m",
        "entry_speed_kph",
        "apex_speed_kph",
        "exit_speed_kph",
        "speed_prominence_kph",
        "braked_before_apex",
        "gear_at_apex",
    ]

    def __init__(
        self,
        min_prominence_kph: float = DEFAULT_MIN_PROMINENCE_KPH,
        smoothing_window: int = DEFAULT_SMOOTHING_WINDOW,
        min_corner_separation_m: float = DEFAULT_MIN_CORNER_SEPARATION_M,
        trend_tolerance_kph: float = DEFAULT_TREND_TOLERANCE_KPH,
        debug: bool = False,
    ):
        if min_prominence_kph < 0:
            raise ValueError(
                "min_prominence_kph must be >= 0"
            )

        if smoothing_window < 1:
            raise ValueError(
                "smoothing_window must be >= 1"
            )

        if min_corner_separation_m < 0:
            raise ValueError(
                "min_corner_separation_m must be >= 0"
            )

        if trend_tolerance_kph < 0:
            raise ValueError(
                "trend_tolerance_kph must be >= 0"
            )

        self.min_prominence_kph = (
            min_prominence_kph
        )

        self.smoothing_window = (
            smoothing_window
        )

        self.min_corner_separation_m = (
            min_corner_separation_m
        )

        self.trend_tolerance_kph = (
            trend_tolerance_kph
        )

        self.debug = debug

    def analyze(
        self,
        frames: Iterable[Mapping],
    ) -> pd.DataFrame:
        """
        Analyze raw telemetry frames and return corner metrics.
        """
        groups = _group_by_lap(frames)

        if not groups:
            return pd.DataFrame(
                columns=self.COLUMNS
            )

        rows: list[dict] = []

        for key, group in groups.items():
            rows.extend(
                _detect_corners_for_lap(
                    key=key,
                    frames=group,
                    min_prominence_kph=(
                        self.min_prominence_kph
                    ),
                    smoothing_window=(
                        self.smoothing_window
                    ),
                    min_corner_separation_m=(
                        self.min_corner_separation_m
                    ),
                    trend_tolerance_kph=(
                        self.trend_tolerance_kph
                    ),
                    debug=self.debug,
                )
            )

        if not rows:
            return pd.DataFrame(
                columns=self.COLUMNS
            )

        return (
            pd.DataFrame(
                rows,
                columns=self.COLUMNS,
            )
            .sort_values(
                [
                    "driver",
                    "lap",
                    "corner_number",
                ]
            )
            .reset_index(drop=True)
        )