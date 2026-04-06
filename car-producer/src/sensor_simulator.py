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

# ── Root path fix ────────────────────────────────────────────────
# Always resolve paths relative to project root
# regardless of where the script is run from
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)

PROCESSED_DIR   = os.path.join(ROOT, 'data', 'processed')
THRESHOLDS_PATH = os.path.join(PROCESSED_DIR, 'thresholds.json')

# ── Constants ────────────────────────────────────────────────────
CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']

VALID_TEAMS    = ['mercedes', 'redbull']
VALID_SESSIONS = ['R', 'Q', 'S']

AVAILABLE_RACES = [
    'Australia', 'Japan', 'Bahrain', 'Saudi Arabia', 'Monaco',
    'Silverstone', 'Netherlands', 'Monza', 'Baku', 'Singapore',
    'São Paulo', 'Qatar', 'Abu Dhabi'
]

SPRINT_RACES = ['São Paulo', 'Qatar']

NOISE_CONFIG = {
    'Speed':    0.05,
    'RPM':      10.0,
    'Throttle': 0.1,
    'Brake':    0.0,
    'nGear':    0.0,
    'DRS':      0.0,
}


class SensorSimulator:
    def __init__(
        self,
        team:             str   = 'mercedes',
        race:             str   = None,
        session:          str   = 'R',
        add_noise:        bool  = True,
        inject_anomalies: bool  = False,
        anomaly_rate:     float = 0.001,
    ):
        self.team    = self._validate_team(team)
        self.session = self._validate_session(session)
        self.race    = self._select_race(race)

        self.add_noise        = add_noise
        self.inject_anomalies = inject_anomalies
        self.anomaly_rate     = anomaly_rate

        self.thresholds = self._load_thresholds()
        self.data       = self._load_data()

        self._idx   = 0
        self._total = len(self.data)

        logging.info(
            f"Simulator ready — {self.team} | "
            f"{self.race} | {self.session}"
        )
        logging.info(f"Frames loaded: {self._total:,}")

    # ── Validation ───────────────────────────────────────────────

    def _validate_team(self, team: str) -> str:
        team = team.lower()
        if team not in VALID_TEAMS:
            raise ValueError(
                f"Invalid team: '{team}'. "
                f"Use one of: {VALID_TEAMS}"
            )
        return team

    def _validate_session(self, session: str) -> str:
        session = session.upper()
        if session not in VALID_SESSIONS:
            raise ValueError(
                f"Invalid session: '{session}'. "
                f"Use one of: {VALID_SESSIONS}"
            )
        return session

    def _select_race(self, race: str) -> str:
        if race is None:
            selected = random.choice(AVAILABLE_RACES)
            logging.info(f"Random race selected: {selected}")
            return selected

        if race not in AVAILABLE_RACES:
            raise ValueError(
                f"Invalid race: '{race}'. "
                f"Available: {AVAILABLE_RACES}"
            )

        if self.session == 'S' and race not in SPRINT_RACES:
            raise ValueError(
                f"'{race}' has no sprint session. "
                f"Sprint available at: {SPRINT_RACES}"
            )

        return race

    # ── Loaders ──────────────────────────────────────────────────

    def _load_thresholds(self) -> Dict:
        if not os.path.exists(THRESHOLDS_PATH):
            logging.warning(
                f"thresholds.json not found at {THRESHOLDS_PATH}. "
                f"Run forensic/calibrate_thresholds.py first. "
                f"Anomaly injection will be disabled."
            )
            return {}
        try:
            with open(THRESHOLDS_PATH, 'r') as f:
                data = json.load(f)
                logging.info("Thresholds loaded successfully")
                return data
        except Exception as e:
            logging.error(f"Failed to load thresholds: {e}")
            return {}

    def _load_data(self) -> pd.DataFrame:
        """
        Load ALL telemetry CSVs for the selected team
        from data/processed/ and combine into one DataFrame.

        Loads all races and all sessions automatically —
        sensor_simulator streams across the full dataset.

        File naming convention:
            {team}_baseline.csv  ← single combined baseline file
        """
        if not os.path.exists(PROCESSED_DIR):
            raise FileNotFoundError(
                f"Processed data directory not found: {PROCESSED_DIR}\n"
                f"Run forensic/forensic_analysis.py first."
            )

        # ── Strategy 1: Load combined baseline CSV ───────────────
        # forensic_analysis.py produces one baseline per team
        baseline_path = os.path.join(
            PROCESSED_DIR, f"{self.team}_baseline.csv"
        )

        if os.path.exists(baseline_path):
            logging.info(f"Loading baseline: {baseline_path}")
            df = pd.read_csv(baseline_path)
            print(f"\n  Found baseline CSV: {baseline_path}")
            print(f"  Total rows: {len(df):,}")

        else:
            # ── Strategy 2: Load individual race CSVs ───────────
            # Fallback if baseline doesn't exist
            print(f"\n  Baseline not found — scanning for "
                  f"individual race CSVs...")

            raw_dir = os.path.join(ROOT, 'data', 'raw')
            if not os.path.exists(raw_dir):
                raise FileNotFoundError(
                    f"Neither baseline nor raw data found.\n"
                    f"Run fetch_telemetry.py and "
                    f"forensic_analysis.py first."
                )

            files = [
                f for f in os.listdir(raw_dir)
                if f.lower().startswith(self.team)
                and f.endswith('.csv')
            ]

            if not files:
                raise FileNotFoundError(
                    f"No CSV files found for team '{self.team}'.\n"
                    f"Expected files in: {raw_dir}\n"
                    f"Run fetch_telemetry.py first."
                )

            print(f"  Found {len(files)} raw CSV files")
            frames = []
            for fname in sorted(files):
                path = os.path.join(raw_dir, fname)
                try:
                    chunk = pd.read_csv(path)
                    # Parse race and session from filename
                    # Format: mercedes_Bahrain_R.csv
                    parts = fname.replace('.csv', '').split('_')
                    if len(parts) >= 3:
                        chunk['Team']    = parts[0]
                        chunk['Race']    = parts[1]
                        chunk['Session'] = parts[2]
                    frames.append(chunk)
                    print(f"  ✓ {fname} ({len(chunk):,} rows)")
                except Exception as e:
                    print(f"  ⚠ Skipped {fname}: {e}")

            if not frames:
                raise ValueError(
                    "No valid CSV files could be loaded."
                )

            df = pd.concat(frames, ignore_index=True)

        # ── Validate required columns ────────────────────────────
        missing = [c for c in CHANNELS if c not in df.columns]
        if missing:
            raise ValueError(
                f"Missing required telemetry columns: {missing}\n"
                f"Available columns: {list(df.columns)}"
            )

        # ── Clean ────────────────────────────────────────────────
        before = len(df)
        df = df.dropna(subset=CHANNELS)
        df = df.reset_index(drop=True)
        after = len(df)

        if after == 0:
            raise ValueError(
                "Dataset is empty after cleaning. "
                "Check your CSV files."
            )

        print(f"\n  Loaded:  {before:,} rows")
        print(f"  Cleaned: {after:,} rows "
              f"({before - after:,} dropped)")

        if 'Race' in df.columns:
            print(f"  Races:   {sorted(df['Race'].unique())}")
        if 'Session' in df.columns:
            print(f"  Sessions: {sorted(df['Session'].unique())}")

        return df

    # ── Transformations ──────────────────────────────────────────

    def _add_noise(
        self, frame: Dict[str, Any]
    ) -> Dict[str, Any]:
        for ch, std in NOISE_CONFIG.items():
            if std > 0 and ch in frame:
                frame[ch] = round(
                    float(frame[ch]) + np.random.normal(0, std), 4
                )
        return frame

    def _inject_anomaly(
        self, frame: Dict[str, Any]
    ) -> Dict[str, Any]:
        candidates = [
            c for c in CHANNELS
            if c not in ['Brake', 'DRS', 'nGear']
        ]
        channel = random.choice(candidates)

        thresholds = (
            self.thresholds.get(self.team) or
            self.thresholds.get('combined', {})
        )

        if channel in thresholds:
            upper = thresholds[channel]['upper']
            frame[channel]             = round(upper * 1.5, 4)
            frame['_anomaly_injected'] = True
            frame['_anomaly_channel']  = channel

        return frame

    # ── Public API ───────────────────────────────────────────────

    def get_next_frame(self) -> Dict[str, Any]:
        """Return next telemetry frame. Loops on exhaustion."""
        if self._total == 0:
            raise RuntimeError("No data loaded.")

        if self._idx >= self._total:
            self._idx = 0
            logging.info("Data exhausted — looping back to start")

        row = self.data.iloc[self._idx]
        self._idx += 1

        frame = {
            'team':        self.team,
            'race':        str(row.get('Race',      self.race)),
            'session':     str(row.get('Session',   self.session)),
            'lap':         int(row.get('LapNumber', 0)),
            'driver':      str(row.get('Driver',    'UNK')),
            'timestamp':   datetime.utcnow().isoformat(),
            'frame_index': self._idx,
        }

        for ch in CHANNELS:
            val = row.get(ch, 0)
            if ch in ['Brake', 'nGear', 'DRS']:
                frame[ch] = int(val)
            else:
                frame[ch] = round(float(val), 4)

        if self.add_noise:
            frame = self._add_noise(frame)

        if self.inject_anomalies:
            if random.random() < self.anomaly_rate:
                frame = self._inject_anomaly(frame)

        return frame

    def stream(
        self, n_frames: int = None
    ) -> Iterator[Dict[str, Any]]:
        """Generator — yields frames up to n_frames or forever."""
        count = 0
        while True:
            yield self.get_next_frame()
            count += 1
            if n_frames and count >= n_frames:
                break

    def reset(self) -> None:
        """Reset stream to first frame."""
        self._idx = 0
        logging.info("Stream reset to frame 0")

    @property
    def total_frames(self) -> int:
        return self._total

    @property
    def current_index(self) -> int:
        return self._idx

    @property
    def progress(self) -> float:
        if self._total == 0:
            return 0.0
        return round((self._idx / self._total) * 100, 2)


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("  SensorSimulator — Self Test")
    print("=" * 50)

    # Test 1 — Mercedes all races
    print("\n[Test 1] Mercedes — Bahrain Race")
    sim = SensorSimulator(
        team='mercedes',
        race='Bahrain',
        session='R',
        add_noise=True,
        inject_anomalies=False,
    )
    for i, frame in enumerate(sim.stream(n_frames=5)):
        print(
            f"  Frame {i+1}: "
            f"Speed={frame['Speed']} | "
            f"RPM={frame['RPM']} | "
            f"Throttle={frame['Throttle']}% | "
            f"Gear={frame['nGear']} | "
            f"DRS={frame['DRS']} | "
            f"Race={frame['race']}"
        )

    # Test 2 — Red Bull random race
    print("\n[Test 2] Red Bull — Random Race")
    sim2 = SensorSimulator(
        team='redbull',
        race=None,
        session='R',
        add_noise=True,
        inject_anomalies=True,
        anomaly_rate=0.5,
    )
    for i, frame in enumerate(sim2.stream(n_frames=5)):
        anomaly = frame.get('_anomaly_injected', False)
        print(
            f"  Frame {i+1}: "
            f"Speed={frame['Speed']} | "
            f"Race={frame['race']} | "
            f"{'⚠️  ANOMALY: ' + frame.get('_anomaly_channel','') if anomaly else '✅ OK'}"
        )

    # Test 3 — Sprint session
    print("\n[Test 3] Mercedes — São Paulo Sprint")
    sim3 = SensorSimulator(
        team='mercedes',
        race='São Paulo',
        session='S',
        add_noise=True,
    )
    frame = sim3.get_next_frame()
    print(f"  Sprint frame: Speed={frame['Speed']} | "
          f"Race={frame['race']} | Session={frame['session']}")

    # Test 4 — Progress tracking
    print(f"\n[Test 4] Progress")
    print(f"  Total frames: {sim.total_frames:,}")
    print(f"  Current index: {sim.current_index}")
    print(f"  Progress: {sim.progress}%")

    print("\n✅ SensorSimulator self-test complete.")