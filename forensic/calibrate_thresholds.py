import os
import json
import logging
from typing import Dict

import numpy as np

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Constants ───────────────────────────────────────────────────
CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
TEAMS = ['mercedes', 'redbull']
SIGMA = 3.0

PROCESSED_DIR = "data/processed"
SUMMARY_PATH = f"{PROCESSED_DIR}/forensic_summary.json"
OUTPUT_PATH = f"{PROCESSED_DIR}/thresholds.json"

os.makedirs(PROCESSED_DIR, exist_ok=True)

# ── Hard Limits ─────────────────────────────────────────────────
HARD_LIMITS = {
    'Speed':    {'min': 0, 'max': 380},
    'RPM':      {'min': 0, 'max': 15500},
    'Throttle': {'min': 0, 'max': 100},
    'Brake':    {'min': 0, 'max': 1},
    'nGear':    {'min': 0, 'max': 8},
    'DRS':      {'min': 0, 'max': 14},
}


# ── Load Summary ────────────────────────────────────────────────
def load_summary(path: str) -> Dict:
    if not os.path.exists(path):
        raise FileNotFoundError(
            "forensic_summary.json not found. Run forensic_analysis.py first."
        )

    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}")


# ── Compute Thresholds ──────────────────────────────────────────
def compute_thresholds(summary: Dict) -> Dict:
    thresholds = {}

    for team in TEAMS:
        if team not in summary:
            logging.warning(f"No summary data for {team}")
            continue

        thresholds[team] = {}
        team_data = summary[team].get('channels', {})

        logging.info(f"\n{team.upper()} thresholds:")

        for channel in CHANNELS:
            if channel not in team_data:
                continue

            stats = team_data[channel]
            mean = stats.get('mean')
            std = stats.get('std')

            if std is None or np.isnan(std) or std == 0:
                logging.warning(f"Skipping {team}:{channel} (invalid std)")
                continue

            lower_stat = mean - (SIGMA * std)
            upper_stat = mean + (SIGMA * std)

            hard = HARD_LIMITS[channel]
            lower = max(lower_stat, hard['min'])
            upper = min(upper_stat, hard['max'])

            thresholds[team][channel] = {
                'lower': round(lower, 4),
                'upper': round(upper, 4),
                'mean': round(mean, 4),
                'std': round(std, 4),
            }

            logging.info(f"{channel:10s} → [{lower:.2f}, {upper:.2f}]")

    return thresholds


# ── Combined Thresholds ─────────────────────────────────────────
def compute_combined(thresholds: Dict) -> Dict:
    combined = {}

    logging.info("\nCOMBINED thresholds:")

    for channel in CHANNELS:
        lowers = []
        uppers = []

        for team in TEAMS:
            team_data = thresholds.get(team, {})
            if channel in team_data:
                lowers.append(team_data[channel]['lower'])
                uppers.append(team_data[channel]['upper'])

        if lowers and uppers:
            combined_lower = min(lowers)
            combined_upper = max(uppers)

            combined[channel] = {
                'lower': round(combined_lower, 4),
                'upper': round(combined_upper, 4),
            }

            logging.info(
                f"{channel:10s} → [{combined_lower:.2f}, {combined_upper:.2f}]"
            )

    return combined


# ── Main ────────────────────────────────────────────────────────
def main():
    summary = load_summary(SUMMARY_PATH)

    thresholds = compute_thresholds(summary)
    thresholds['combined'] = compute_combined(thresholds)

    with open(OUTPUT_PATH, 'w') as f:
        json.dump(thresholds, f, indent=2)

    logging.info(f"\nThresholds saved to {OUTPUT_PATH}")
    logging.info("Calibration complete.")


if __name__ == "__main__":
    main()