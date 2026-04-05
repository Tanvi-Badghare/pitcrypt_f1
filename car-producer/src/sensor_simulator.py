import os
import json
import random
import logging
from datetime import datetime
from typing import Iterator, Dict, Any

import pandas as pd
import numpy as np

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Paths ───────────────────────────────────────────────────────
PROCESSED_DIR = 'data/processed'
THRESHOLDS_PATH = f'{PROCESSED_DIR}/thresholds.json'

# ── Constants ───────────────────────────────────────────────────
CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
VALID_TEAMS = ['mercedes', 'redbull']
VALID_SESSIONS = ['R', 'Q', 'S']

AVAILABLE_RACES = [
    'Australia', 'Japan', 'Bahrain', 'Saudi Arabia', 'Monaco',
    'Silverstone', 'Netherlands', 'Monza', 'Baku', 'Singapore',
    'São Paulo', 'Qatar', 'Abu Dhabi'
]

SPRINT_RACES = ['São Paulo', 'Qatar']

NOISE_CONFIG = {
    'Speed': 0.05,
    'RPM': 10.0,
    'Throttle': 0.1,
    'Brake': 0.0,
    'nGear': 0.0,
    'DRS': 0.0,
}


class SensorSimulator:
    def __init__(
        self,
        team: str = 'mercedes',
        race: str = None,
        session: str = 'R',
        add_noise: bool = True,
        inject_anomalies: bool = False,
        anomaly_rate: float = 0.001,
    ):
        self.team = self._validate_team(team)
        self.session = self._validate_session(session)
        self.race = self._select_race(race)

        self.add_noise = add_noise
        self.inject_anomalies = inject_anomalies
        self.anomaly_rate = anomaly_rate

        self.thresholds = self._load_thresholds()
        self.data = self._load_data()

        self._idx = 0
        self._total = len(self.data)

        logging.info(f"Simulator ready — {self.team} | {self.race} | {self.session}")
        logging.info(f"Frames loaded: {self._total:,}")

    # ── Validation ───────────────────────────────────────────────

    def _validate_team(self, team: str) -> str:
        team = team.lower()
        if team not in VALID_TEAMS:
            raise ValueError(f"Invalid team: {team}")
        return team

    def _validate_session(self, session: str) -> str:
        session = session.upper()
        if session not in VALID_SESSIONS:
            raise ValueError(f"Invalid session: {session}")
        return session

    def _select_race(self, race: str) -> str:
        if race is None:
            selected = random.choice(AVAILABLE_RACES)
            logging.info(f"Random race selected: {selected}")
            return selected

        if race not in AVAILABLE_RACES:
            raise ValueError(f"Invalid race: {race}")

        if self.session == 'S' and race not in SPRINT_RACES:
            raise ValueError(f"{race} has no sprint session")

        return race

    # ── Loaders ─────────────────────────────────────────────────

    def _load_thresholds(self) -> Dict:
        if not os.path.exists(THRESHOLDS_PATH):
            logging.warning("thresholds.json not found — anomaly injection limited")
            return {}

        try:
            with open(THRESHOLDS_PATH, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load thresholds: {e}")
            return {}

    def _load_data(self) -> pd.DataFrame:
        path = f"{PROCESSED_DIR}/{self.team}_baseline.csv"

        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing processed data: {path}")

        df = pd.read_csv(path)

        filtered = df[
            (df['Race'] == self.race) &
            (df['Session'] == self.session)
        ].dropna(subset=CHANNELS)

        if filtered.empty:
            raise ValueError(f"No data for {self.team} {self.race} {self.session}")

        return filtered.reset_index(drop=True)

    # ── Transformations ─────────────────────────────────────────

    def _add_noise(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        for ch, std in NOISE_CONFIG.items():
            if std > 0:
                frame[ch] = round(float(frame[ch]) + np.random.normal(0, std), 4)
        return frame

    def _inject_anomaly(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        candidate_channels = [c for c in CHANNELS if c not in ['Brake', 'DRS', 'nGear']]
        channel = random.choice(candidate_channels)

        thresholds = self.thresholds.get(self.team) or self.thresholds.get('combined', {})

        if channel in thresholds:
            upper = thresholds[channel]['upper']
            frame[channel] = round(upper * 1.5, 4)
            frame['_anomaly_injected'] = True
            frame['_anomaly_channel'] = channel

        return frame

    # ── Public API ──────────────────────────────────────────────

    def get_next_frame(self) -> Dict[str, Any]:
        if self._total == 0:
            raise RuntimeError("No data loaded")

        if self._idx >= self._total:
            self._idx = 0
            logging.info("Looping back to start")

        row = self.data.iloc[self._idx]
        self._idx += 1

        frame = {
            'team': self.team,
            'race': self.race,
            'session': self.session,
            'lap': int(row.get('LapNumber', 0)),
            'driver': str(row.get('Driver', 'UNK')),
            'timestamp': datetime.utcnow().isoformat(),
            'frame_index': self._idx,
        }

        for ch in CHANNELS:
            val = row.get(ch, 0)
            frame[ch] = int(val) if ch in ['Brake', 'nGear', 'DRS'] else round(float(val), 4)

        if self.add_noise:
            frame = self._add_noise(frame)

        if self.inject_anomalies and random.random() < self.anomaly_rate:
            frame = self._inject_anomaly(frame)

        return frame

    def stream(self, n_frames: int = None) -> Iterator[Dict[str, Any]]:
        count = 0
        while True:
            yield self.get_next_frame()
            count += 1
            if n_frames and count >= n_frames:
                break

    def reset(self):
        self._idx = 0
        logging.info("Stream reset")

    # ── Properties ──────────────────────────────────────────────

    @property
    def total_frames(self) -> int:
        return self._total

    @property
    def current_index(self) -> int:
        return self._idx

    @property
    def progress(self) -> float:
        return round((self._idx / self._total) * 100, 2)