import os
import json
import math
from typing import Optional, Dict

ROOT       = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
CORNER_DIR = os.path.join(ROOT, 'data', 'circuits')


class CornerLookup:
    """
    Maps a telemetry frame's X/Y track position to the
    nearest known corner for a given circuit.

    Uses Euclidean distance on X/Y track coordinates
    against pre-fetched FastF1 circuit corner data.

    Both telemetry X/Y and corner X/Y use the same
    FastF1 coordinate system (metres, circuit-relative).

    Threshold is computed dynamically per circuit as
    half the median inter-corner spacing — this ensures
    the label always reflects the nearest corner
    regardless of circuit layout scale.
    """

    # Fallback threshold if dynamic calc fails
    _FALLBACK_RADIUS_M = 800

    def __init__(self, race: str):
        self.race      = race
        self.corners   = self._load(race)
        self._threshold = self._compute_threshold()

    def _load(self, race: str) -> list:
        path = os.path.join(CORNER_DIR, f"{race}_corners.json")
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            return data.get('corners', [])
        except Exception:
            return []

    def _compute_threshold(self) -> float:
        """
        Compute adaptive threshold as half the median
        distance between consecutive corner apexes.

        This ensures the threshold scales correctly
        for tight street circuits (Monaco ~200m between
        corners) vs fast layouts (Silverstone ~600m).
        """
        if len(self.corners) < 2:
            return self._FALLBACK_RADIUS_M

        distances = []
        for i in range(len(self.corners) - 1):
            a = self.corners[i]
            b = self.corners[i + 1]
            d = math.hypot(a['x'] - b['x'], a['y'] - b['y'])
            distances.append(d)

        # Also add wrap-around distance (last→first corner)
        a = self.corners[-1]
        b = self.corners[0]
        distances.append(math.hypot(a['x'] - b['x'], a['y'] - b['y']))

        distances.sort()
        median = distances[len(distances) // 2]

        # Use 60% of median inter-corner spacing
        # so the zones overlap slightly — no gap between corners
        threshold = median * 0.6
        return max(threshold, 150.0)   # minimum 150m

    def nearest_corner(
        self, x: float, y: float
    ) -> Optional[Dict]:
        """
        Find nearest corner to X/Y position.
        Returns None if no corner data loaded.
        Always returns the nearest corner — threshold
        determines whether it's labelled as a corner
        or a straight.
        """
        if not self.corners:
            return None

        best      = None
        best_dist = float('inf')

        for corner in self.corners:
            dist = math.hypot(
                x - corner['x'],
                y - corner['y'],
            )
            if dist < best_dist:
                best_dist = dist
                best      = corner

        return {
            'number':    best['number'],
            'letter':    best.get('letter', ''),
            'distance':  round(best_dist, 1),
            'on_straight': best_dist > self._threshold,
        }

    def label(self, x: float, y: float) -> str:
        """Human-readable position label for dashboard."""
        if not self.corners:
            return ''
        result = self.nearest_corner(x, y)
        if result is None:
            return ''
        if result['on_straight']:
            # Show approaching corner rather than blank
            suffix = result['letter'] or ''
            return f"→T{result['number']}{suffix}"
        suffix = result['letter'] or ''
        return f"T{result['number']}{suffix}"