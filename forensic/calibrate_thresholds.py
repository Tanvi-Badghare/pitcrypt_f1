import os
import json
import logging
from typing import Dict

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Root path ────────────────────────────────────────────────────
ROOT          = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)
PROCESSED_DIR = os.path.join(ROOT, 'data', 'processed')
SUMMARY_PATH  = os.path.join(PROCESSED_DIR, 'forensic_summary.json')
OUTPUT_PATH   = os.path.join(PROCESSED_DIR, 'thresholds.json')

os.makedirs(PROCESSED_DIR, exist_ok=True)

# ── Constants ────────────────────────────────────────────────────
CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']
TEAMS    = ['mercedes', 'redbull']
SIGMA    = 3.0

HARD_LIMITS = {
    'Speed':    {'min': 0,   'max': 380},
    'RPM':      {'min': 0,   'max': 15500},
    'Throttle': {'min': 0,   'max': 100},
    'Brake':    {'min': 0,   'max': 1},
    'nGear':    {'min': 0,   'max': 8},
    'DRS':      {'min': 0,   'max': 14},
}


def load_summary() -> Dict:
    if not os.path.exists(SUMMARY_PATH):
        raise FileNotFoundError(
            f"forensic_summary.json not found at {SUMMARY_PATH}.\n"
            f"Run forensic/forensic_analysis.py first."
        )
    with open(SUMMARY_PATH, 'r') as f:
        data = json.load(f)
    if not data:
        raise ValueError(
            "forensic_summary.json is empty.\n"
            "Run forensic/forensic_analysis.py first."
        )
    return data


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
            mean  = stats.get('mean')
            std   = stats.get('std')

            if std is None or np.isnan(std) or std == 0:
                logging.warning(
                    f"Skipping {team}:{channel} — invalid std"
                )
                continue

            lower = max(mean - (SIGMA * std), HARD_LIMITS[channel]['min'])
            upper = min(mean + (SIGMA * std), HARD_LIMITS[channel]['max'])

            thresholds[team][channel] = {
                'lower': round(lower, 4),
                'upper': round(upper, 4),
                'mean':  round(mean,  4),
                'std':   round(std,   4),
            }

            logging.info(f"  {channel:10s} [{lower:.2f}, {upper:.2f}]")

    return thresholds


def compute_combined(thresholds: Dict) -> Dict:
    combined = {}
    logging.info("\nCOMBINED thresholds:")

    for channel in CHANNELS:
        lowers = []
        uppers = []

        for team in TEAMS:
            if channel in thresholds.get(team, {}):
                lowers.append(thresholds[team][channel]['lower'])
                uppers.append(thresholds[team][channel]['upper'])

        if lowers and uppers:
            combined[channel] = {
                'lower': round(min(lowers), 4),
                'upper': round(max(uppers), 4),
            }
            logging.info(
                f"  {channel:10s} [{min(lowers):.2f}, {max(uppers):.2f}]"
            )

    return combined


def main():
    logging.info("Loading forensic summary...")
    summary = load_summary()

    logging.info("Computing per-team thresholds...")
    thresholds = compute_thresholds(summary)

    logging.info("Computing combined thresholds...")
    thresholds['combined'] = compute_combined(thresholds)

    with open(OUTPUT_PATH, 'w') as f:
        json.dump(thresholds, f, indent=2)

    logging.info(f"\nThresholds saved → {OUTPUT_PATH}")
    logging.info("Calibration complete.")


if __name__ == "__main__":
    main()