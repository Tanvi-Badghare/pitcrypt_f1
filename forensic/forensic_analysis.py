import os
import json
import logging
from typing import Dict, List

import pandas as pd
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Root path — always project root ─────────────────────────────
ROOT          = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)
RAW_DIR       = os.path.join(ROOT, 'data', 'raw')
PROCESSED_DIR = os.path.join(ROOT, 'data', 'processed')
ANOMALY_DIR   = os.path.join(ROOT, 'data', 'anomalies')

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(ANOMALY_DIR,   exist_ok=True)

# ── Constants ────────────────────────────────────────────────────
CHANNELS        = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
Z_THRESHOLD     = 3.0
TEAMS           = ['mercedes', 'redbull', 'ferrari', 'mclaren', 'williams']
DEFAULT_SESSIONS = ['R', 'Q']
SPRINT_SESSIONS  = {'São Paulo': ['R', 'Q', 'S'], 'Qatar': ['R', 'Q', 'S']}

RACES = [
    'Australia', 'Japan', 'Bahrain', 'Saudi Arabia', 'Monaco',
    'Silverstone', 'Netherlands', 'Monza', 'Baku', 'Singapore',
    'São Paulo', 'Qatar', 'Abu Dhabi'
]


def load_all_data(team: str) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []

    for race in RACES:
        sessions = SPRINT_SESSIONS.get(race, DEFAULT_SESSIONS)
        for session in sessions:
            path = os.path.join(RAW_DIR, f"{team}_{race}_{session}.csv")
            if not os.path.exists(path):
                logging.warning(f"Missing: {path}")
                continue
            try:
                df = pd.read_csv(path)
                frames.append(df)
                logging.info(f"Loaded: {path} ({len(df):,} rows)")
            except Exception as e:
                logging.error(f"Failed to read {path}: {e}")

    if not frames:
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True)


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    df = df.dropna(subset=CHANNELS, how='all')

    bounds = {
        'Speed':    (0, 400),
        'RPM':      (0, 16000),
        'Throttle': (0, 100),
        'Brake':    (0, 1),
        'nGear':    (0, 8),
        'DRS':      (0, 14),
    }

    for col, (low, high) in bounds.items():
        if col in df.columns:
            df = df[(df[col] >= low) & (df[col] <= high)]

    return df.reset_index(drop=True)


def detect_anomalies(df: pd.DataFrame, team: str) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    anomalies = []

    for (race, session), group in df.groupby(['Race', 'Session']):
        stats = group[CHANNELS].agg(['mean', 'std'])

        for channel in CHANNELS:
            if channel not in group.columns:
                continue

            mean = stats[channel]['mean']
            std  = stats[channel]['std']

            if std == 0 or np.isnan(std):
                continue

            z_scores = (group[channel] - mean) / std
            mask     = np.abs(z_scores) > Z_THRESHOLD
            flagged  = group[mask].copy()

            if not flagged.empty:
                flagged['AnomalyChannel'] = channel
                flagged['ZScore']         = z_scores[mask]
                flagged['Mean']           = mean
                flagged['StdDev']         = std
                flagged['Team']           = team
                anomalies.append(flagged)

    return pd.concat(anomalies, ignore_index=True) if anomalies else pd.DataFrame()


def summarise(df: pd.DataFrame, team: str) -> Dict:
    summary = {'team': team, 'total_rows': len(df), 'channels': {}}
    for ch in CHANNELS:
        if ch in df.columns:
            summary['channels'][ch] = {
                'mean':   float(df[ch].mean()),
                'std':    float(df[ch].std()),
                'min':    float(df[ch].min()),
                'max':    float(df[ch].max()),
                'median': float(df[ch].median()),
            }
    return summary


def main():
    all_summaries = {}

    for team in TEAMS:
        logging.info(f"\n{'='*40}")
        logging.info(f"Processing: {team.upper()}")
        logging.info(f"{'='*40}")

        df = load_all_data(team)
        if df.empty:
            logging.warning(f"No data found for {team} — skipping")
            continue

        logging.info(f"Loaded {len(df):,} rows")

        df = clean_data(df)
        logging.info(f"After cleaning: {len(df):,} rows")

        # Save processed baseline
        processed_path = os.path.join(
            PROCESSED_DIR, f"{team}_baseline.csv"
        )
        df.to_csv(processed_path, index=False)
        logging.info(f"Saved baseline: {processed_path}")

        # Detect anomalies
        anomalies = detect_anomalies(df, team)
        if not anomalies.empty:
            anomaly_path = os.path.join(
                ANOMALY_DIR, f"{team}_anomalies.csv"
            )
            anomalies.to_csv(anomaly_path, index=False)
            logging.info(
                f"Saved {len(anomalies):,} anomalies → {anomaly_path}"
            )

        all_summaries[team] = summarise(df, team)
        logging.info(
            f"Summary: {all_summaries[team]['total_rows']:,} rows analysed"
        )

    # Save summary JSON
    summary_path = os.path.join(PROCESSED_DIR, 'forensic_summary.json')
    with open(summary_path, 'w') as f:
        json.dump(all_summaries, f, indent=2)

    logging.info(f"\nSummary saved → {summary_path}")
    logging.info("Forensic analysis complete.")


if __name__ == "__main__":
    main()