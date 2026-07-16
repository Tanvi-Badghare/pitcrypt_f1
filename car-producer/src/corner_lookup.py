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
    """

    # Max distance in metres to classify as "at a corner"
    # Beyond this = considered on a straight
    CORNER_RADIUS_M = 200

    def __init__(self, race: str):
        self.race    = race
        self.corners = self._load(race)

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

    def nearest_corner(
        self, x: float, y: float
    ) -> Optional[Dict]:
        """
        Find nearest corner to X/Y position.
        Returns None if no corner data or car is on a straight.
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

        if best_dist > self.CORNER_RADIUS_M:
            return None

        return {
            'number':    best['number'],
            'letter':    best.get('letter', ''),
            'distance':  round(best_dist, 1),
        }

    def label(self, x: float, y: float) -> str:
        """Human-readable position label for dashboard."""
        if not self.corners:
            return ''    # Empty string — no corner data loaded
        corner = self.nearest_corner(x, y)
        if corner is None:
            return 'Straight'
        suffix = corner['letter'] or ''
        return f"T{corner['number']}{suffix}"