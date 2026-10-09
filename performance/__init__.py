"""
performance
-----------
Analysis layer that sits downstream of the telemetry simulator:

    SensorSimulator
           |
        frames
           |
      LapAnalyzer
           |
    lap-level metrics

Everything in this package is read-only with respect to whatever
produced the frames (the simulator or, later, a real telemetry source)
- analyzers only ever consume frames handed to them.
"""

from .lap_analysis import LapAnalyzer
from .sector_analysis import SectorAnalyzer
from .driver_comparison import DriverComparison
from .track_analysis import TrackAnalyzer
from .corner_analysis import CornerAnalyzer

__all__ = [
    "LapAnalyzer",
    "SectorAnalyzer",
    "DriverComparison",
    "TrackAnalyzer",
    "CornerAnalyzer",
]