import os
import json
import logging
from typing import Dict, List

import pandas as pd
import numpy as np

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Constants ───────────────────────────────────────────────────
CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
Z_THRESHOLD = 3.0

TEAMS = ['mercedes', 'redbull']

RACES = [
    'Australia', 'Japan', 'Bahrain', 'Saudi Arabia', 'Monaco',
    'Silverstone', 'Netherlands', 'Monza', 'Baku', 'Singapore',
    'São Paulo', 'Qatar', 'Abu Dhabi'
]

SESSIONS = {
    'São Paulo': ['R', 'Q', 'S'],
    'Qatar':     ['R', 'Q', 'S'],
}
DEFAULT_SESSIONS = ['R', 'Q']

# ── Paths ───────────────────────────────────────────────────────
RAW_DIR = "data/raw"
PROCESSED_DIR = "data/processed"
ANOMALY_DIR = "data/anomalies"

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(ANOMALY_DIR, exist_ok=True)


# ── Load Data ───────────────────────────────────────────────────
def load_all_data(team: str) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []

    for race in RACES:
        sessions = SESSIONS.get(race, DEFAULT_SESSIONS)
        for session in sessions:
            path = f"{RAW_DIR}/{team}_{race}_{session}.csv"

            if not os.path.exists(path):
                logging.warning(f"Missing: {path}")
                continue

            try:
                df = pd.read_csv(path)
                frames.append(df)
            except Exception as e:
                logging.error(f"Failed to read {path}: {e}")

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


# ── Clean Data ──────────────────────────────────────────────────
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    df = df.dropna(subset=CHANNELS, how='all')

    bounds = {
        'Speed': (0, 400),
        'RPM': (0, 16000),
        'Throttle': (0, 100),
        'Brake': (0, 1),
        'nGear': (0, 8),
        'DRS': (0, 14),
    }

    for col, (low, high) in bounds.items():
        if col in df.columns:
            df = df[(df[col] >= low) & (df[col] <= high)]

    return df.reset_index(drop=True)


# ── Detect Anomalies (Vectorized) ───────────────────────────────
def detect_anomalies(df: pd.DataFrame, team: str) -> pd.DataFrame:
    if df.empty:
        return df

    anomalies = []

    grouped = df.groupby(['Race', 'Session'])

    for (race, session), group in grouped:
        stats = group[CHANNELS].agg(['mean', 'std'])

        for channel in CHANNELS:
            if channel not in group.columns:
                continue

            mean = stats[channel]['mean']
            std = stats[channel]['std']

            if std == 0 or np.isnan(std):
                continue

            z_scores = (group[channel] - mean) / std
            mask = np.abs(z_scores) > Z_THRESHOLD

            flagged = group[mask].copy()
            if not flagged.empty:
                flagged['AnomalyChannel'] = channel
                flagged['ZScore'] = z_scores[mask]
                flagged['Mean'] = mean
                flagged['StdDev'] = std
                flagged['Team'] = team
                anomalies.append(flagged)

    return pd.concat(anomalies, ignore_index=True) if anomalies else pd.DataFrame()


# ── Summary ─────────────────────────────────────────────────────
def summarise(df: pd.DataFrame, team: str) -> Dict:
    summary = {'team': team, 'total_rows': len(df), 'channels': {}}

    for ch in CHANNELS:
        if ch in df.columns:
            summary['channels'][ch] = {
                'mean': float(df[ch].mean()),
                'std': float(df[ch].std()),
                'min': float(df[ch].min()),
                'max': float(df[ch].max()),
                'median': float(df[ch].median()),
            }

    return summary


# ── Main ────────────────────────────────────────────────────────
def main():
    all_summaries = {}

    for team in TEAMS:
        logging.info(f"Processing team: {team}")

        df = load_all_data(team)
        if df.empty:
            logging.warning(f"No data for {team}")
            continue

        df = clean_data(df)

        processed_path = f"{PROCESSED_DIR}/{team}_baseline.csv"
        df.to_csv(processed_path, index=False)

        anomalies = detect_anomalies(df, team)
        if not anomalies.empty:
            anomaly_path = f"{ANOMALY_DIR}/{team}_anomalies.csv"
            anomalies.to_csv(anomaly_path, index=False)

        all_summaries[team] = summarise(df, team)

    with open(f"{PROCESSED_DIR}/forensic_summary.json", "w") as f:
        json.dump(all_summaries, f, indent=2)

    logging.info("Forensic analysis complete.")


if __name__ == "__main__":
    main()