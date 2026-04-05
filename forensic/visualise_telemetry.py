import os
import logging
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

logging.basicConfig(level=logging.INFO)

OUTPUT_DIR = "architecture/diagrams"
DATA_DIR = "data/processed"

os.makedirs(OUTPUT_DIR, exist_ok=True)

TEAM_COLORS = {
    'mercedes': '#00D2BE',
    'redbull': '#3671C6',
}

TEAM_LABELS = {
    'mercedes': 'Mercedes AMG',
    'redbull': 'Red Bull Racing',
}


def load_team(team: str) -> pd.DataFrame:
    path = f"{DATA_DIR}/{team}_baseline.csv"
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found.")
    return pd.read_csv(path)


def safe_column(df: pd.DataFrame, col: str):
    return df[col].dropna() if col in df.columns else pd.Series([])


def save_plot(fig, filename: str):
    path = f"{OUTPUT_DIR}/{filename}"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    logging.info(f"Saved: {path}")


def plot_speed_distribution(merc, rbr):
    fig, ax = plt.subplots(figsize=(12, 5))

    for team, df in [('mercedes', merc), ('redbull', rbr)]:
        ax.hist(
            safe_column(df, 'Speed'),
            bins=100,
            alpha=0.6,
            label=TEAM_LABELS[team],
            color=TEAM_COLORS[team],
            density=True
        )

    ax.legend()
    ax.set_title("Speed Distribution")
    save_plot(fig, "speed_distribution.png")


def plot_anomaly_counts():
    frames = []

    for team in ['mercedes', 'redbull']:
        path = f"data/anomalies/{team}_anomalies.csv"
        if os.path.exists(path):
            frames.append(pd.read_csv(path))

    if not frames:
        logging.warning("No anomaly data found")
        return

    df = pd.concat(frames)
    counts = df.groupby(['Race', 'Team']).size().unstack(fill_value=0)

    counts.plot(kind='bar', figsize=(12, 5))
    plt.title("Anomaly Count per Race")

    save_plot(plt.gcf(), "anomaly_counts.png")


def main():
    merc = load_team('mercedes')
    rbr = load_team('redbull')

    plot_speed_distribution(merc, rbr)
    plot_anomaly_counts()

    logging.info("All visualisations complete.")


if __name__ == "__main__":
    main()