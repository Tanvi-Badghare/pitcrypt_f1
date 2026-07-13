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
    Maps a telemetry frame's track position to the
    nearest known corner for a given circuit.

    Uses Euclidean distance on X/Y track coordinates
    against pre-fetched FastF1 circuit corner data.
    """

    def __init__(self, race: str):
        self.race    = race
        self.corners = self._load_corners(race)

    def _load_corners(self, race: str) -> list:
        path = os.path.join(CORNER_DIR, f"{race}_corners.json")
        if not os.path.exists(path):
            return []
        with open(path, 'r') as f:
            data = json.load(f)
        return data.get('corners', [])

    def nearest_corner(
        self, x: float, y: float
    ) -> Optional[Dict]:
        """
        Find the nearest corner to a given X/Y position.
        Returns None if no corner data available or
        the car is far from any corner (i.e. on a straight).
        """
        if not self.corners:
            return None

        best       = None
        best_dist  = float('inf')

        for corner in self.corners:
            dist = math.hypot(x - corner['x'], y - corner['y'])
            if dist < best_dist:
                best_dist = dist
                best      = corner

        # Threshold — beyond ~150m from any corner apex,
        # the car is considered "on straight"
        if best_dist > 150:
            return None

        return {
            'number':       best['number'],
            'letter':       best['letter'],
            'distance_to':  round(best_dist, 1),
        }

    def label(self, x: float, y: float) -> str:
        """Human-readable position label."""
        corner = self.nearest_corner(x, y)
        if corner is None:
            return "Straight"
        suffix = corner['letter'] or ''
        return f"Turn {corner['number']}{suffix}"