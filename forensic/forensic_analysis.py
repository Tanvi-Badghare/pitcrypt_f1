import os
import json
import logging
import pandas as pd
import numpy as np

# ── Setup ───────────────────────────────────────────────────────
os.makedirs('data/processed', exist_ok=True)
os.makedirs('data/anomalies', exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
Z_THRESHOLD = 3.0
TEAMS = ['mercedes', 'redbull']

REQUIRED_COLUMNS = ['Race', 'Session'] + CHANNELS


# ── Validation ──────────────────────────────────────────────────
def validate_schema(df: pd.DataFrame):
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")


# ── Load ────────────────────────────────────────────────────────
def load_all_data(team: str) -> pd.DataFrame:
    frames = []
    for file in os.listdir("data/raw"):
        if file.startswith(team) and file.endswith(".csv"):
            frames.append(pd.read_csv(os.path.join("data/raw", file)))

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


# ── Clean ───────────────────────────────────────────────────────
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    validate_schema(df)
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


# ── Robust Z-score ──────────────────────────────────────────────
def robust_z(series: pd.Series):
    median = series.median()
    mad = np.median(np.abs(series - median))
    if mad == 0:
        return pd.Series(np.zeros(len(series)), index=series.index)
    return 0.6745 * (series - median) / mad


# ── Detect ──────────────────────────────────────────────────────
def detect_anomalies(df: pd.DataFrame, team: str) -> pd.DataFrame:
    anomalies = []

    for (race, session), subset in df.groupby(['Race', 'Session']):
        for ch in CHANNELS:
            if ch not in subset.columns:
                continue

            z = robust_z(subset[ch])
            flagged = subset[np.abs(z) > Z_THRESHOLD].copy()

            if not flagged.empty:
                flagged['AnomalyChannel'] = ch
                flagged['ZScore'] = z[np.abs(z) > Z_THRESHOLD]
                flagged['Team'] = team
                anomalies.append(flagged)

    return pd.concat(anomalies, ignore_index=True) if anomalies else pd.DataFrame()


# ── Summary ─────────────────────────────────────────────────────
def summarise(df, team):
    return {
        'team': team,
        'total_rows': len(df),
        'channels': {
            ch: {
                'mean': float(df[ch].mean()),
                'std': float(df[ch].std()),
                'min': float(df[ch].min()),
                'max': float(df[ch].max())
            }
            for ch in CHANNELS if ch in df.columns
        }
    }


# ── Main ────────────────────────────────────────────────────────
def main():
    all_summaries = {}

    for team in TEAMS:
        logger.info(f"Analysing {team}")

        df = load_all_data(team)
        if df.empty:
            logger.warning(f"No data for {team}")
            continue

        df = clean_data(df)
        df.to_csv(f"data/processed/{team}_baseline.csv", index=False)

        anomalies = detect_anomalies(df, team)
        if not anomalies.empty:
            anomalies.to_csv(f"data/anomalies/{team}_anomalies.csv", index=False)

        all_summaries[team] = summarise(df, team)

    with open("data/processed/forensic_summary.json", "w") as f:
        json.dump(all_summaries, f, indent=2)

    logger.info("Analysis complete")


if __name__ == "__main__":
    main()