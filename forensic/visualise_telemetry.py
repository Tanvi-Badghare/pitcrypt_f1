import os
import logging

import pandas as pd
import matplotlib.pyplot as plt
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
ANOMALY_DIR   = os.path.join(ROOT, 'data', 'anomalies')
DIAGRAMS_DIR  = os.path.join(ROOT, 'architecture', 'diagrams')

os.makedirs(DIAGRAMS_DIR, exist_ok=True)

# ── Style ────────────────────────────────────────────────────────
TEAM_COLORS = {
    'mercedes': '#00D2BE',
    'redbull':  '#3671C6',
}
TEAM_LABELS = {
    'mercedes': 'Mercedes AMG',
    'redbull':  'Red Bull Racing',
}


def load_team(team: str) -> pd.DataFrame:
    path = os.path.join(PROCESSED_DIR, f"{team}_baseline.csv")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Baseline not found: {path}\n"
            f"Run forensic/forensic_analysis.py first."
        )
    df = pd.read_csv(path)
    logging.info(f"Loaded {team}: {len(df):,} rows")
    return df


def safe_col(df: pd.DataFrame, col: str) -> pd.Series:
    return df[col].dropna() if col in df.columns else pd.Series([])


def save_plot(fig, filename: str) -> None:
    path = os.path.join(DIAGRAMS_DIR, filename)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    logging.info(f"Saved: {path}")


def plot_speed_distribution(merc: pd.DataFrame,
                            rbr:  pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor('#0F0F0F')
    ax.set_facecolor('#1A1A1A')

    for team, df in [('mercedes', merc), ('redbull', rbr)]:
        ax.hist(
            safe_col(df, 'Speed'),
            bins=100,
            alpha=0.6,
            color=TEAM_COLORS[team],
            label=TEAM_LABELS[team],
            density=True,
        )

    ax.set_title('Speed Distribution — Mercedes vs Red Bull 2025',
                 color='white', fontsize=13)
    ax.set_xlabel('Speed (km/h)', color='white')
    ax.set_ylabel('Density',      color='white')
    ax.tick_params(colors='white')
    ax.legend(facecolor='#2A2A2A', labelcolor='white')
    for spine in ax.spines.values():
        spine.set_edgecolor('#444444')

    save_plot(fig, 'speed_distribution.png')


def plot_throttle_vs_speed(merc: pd.DataFrame,
                           rbr:  pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor('#0F0F0F')

    for ax, (team, df) in zip(
        axes, [('mercedes', merc), ('redbull', rbr)]
    ):
        ax.set_facecolor('#1A1A1A')
        throttle = safe_col(df, 'Throttle')
        speed    = safe_col(df, 'Speed')

        if throttle.empty or speed.empty:
            continue

        ax.hexbin(throttle, speed, gridsize=40,
                  cmap='YlOrRd', mincnt=1)
        ax.set_title(f'{TEAM_LABELS[team]}\nThrottle vs Speed',
                     color='white', fontsize=11)
        ax.set_xlabel('Throttle (%)', color='white')
        ax.set_ylabel('Speed (km/h)', color='white')
        ax.tick_params(colors='white')
        for spine in ax.spines.values():
            spine.set_edgecolor('#444444')

    save_plot(fig, 'throttle_vs_speed.png')


def plot_channel_stats(merc: pd.DataFrame,
                       rbr:  pd.DataFrame) -> None:
    channels = ['Speed', 'RPM', 'Throttle']
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.patch.set_facecolor('#0F0F0F')

    for ax, channel in zip(axes, channels):
        ax.set_facecolor('#1A1A1A')
        means = [
            safe_col(merc, channel).mean(),
            safe_col(rbr,  channel).mean(),
        ]
        stds = [
            safe_col(merc, channel).std(),
            safe_col(rbr,  channel).std(),
        ]
        ax.bar(
            ['Mercedes', 'Red Bull'],
            means,
            yerr=stds,
            color=[TEAM_COLORS['mercedes'], TEAM_COLORS['redbull']],
            capsize=5,
            alpha=0.85,
        )
        ax.set_title(f'{channel} — Mean ± StdDev',
                     color='white', fontsize=11)
        ax.set_ylabel(channel, color='white')
        ax.tick_params(colors='white')
        for spine in ax.spines.values():
            spine.set_edgecolor('#444444')

    save_plot(fig, 'channel_statistics.png')


def plot_anomaly_counts() -> None:
    frames = []
    for team in ['mercedes', 'redbull']:
        path = os.path.join(ANOMALY_DIR, f"{team}_anomalies.csv")
        if os.path.exists(path):
            frames.append(pd.read_csv(path))

    if not frames:
        logging.warning("No anomaly data found — skipping anomaly plot")
        return

    anomalies = pd.concat(frames, ignore_index=True)

    if 'Race' not in anomalies.columns or 'Team' not in anomalies.columns:
        logging.warning("Anomaly CSV missing Race/Team columns")
        return

    counts = anomalies.groupby(
        ['Race', 'Team']
    ).size().unstack(fill_value=0)

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor('#0F0F0F')
    ax.set_facecolor('#1A1A1A')

    x     = np.arange(len(counts.index))
    width = 0.35

    for i, col in enumerate(counts.columns):
        color = TEAM_COLORS.get(col.lower().replace(' ', ''), '#FFFFFF')
        ax.bar(x + i * width, counts[col], width,
               label=col, color=color, alpha=0.85)

    ax.set_title('Anomaly Count per Race',
                 color='white', fontsize=13)
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels(counts.index, rotation=45,
                       ha='right', color='white')
    ax.set_ylabel('Anomalous Rows', color='white')
    ax.tick_params(colors='white')
    ax.legend(facecolor='#2A2A2A', labelcolor='white')
    for spine in ax.spines.values():
        spine.set_edgecolor('#444444')

    save_plot(fig, 'anomaly_counts.png')


def plot_drs_usage(merc: pd.DataFrame,
                   rbr:  pd.DataFrame) -> None:
    if 'Race' not in merc.columns or 'DRS' not in merc.columns:
        logging.warning("Missing Race/DRS columns — skipping DRS plot")
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor('#0F0F0F')

    for ax, (team, df) in zip(
        axes, [('mercedes', merc), ('redbull', rbr)]
    ):
        ax.set_facecolor('#1A1A1A')

        if 'Race' not in df.columns or 'DRS' not in df.columns:
            continue

        drs = df.groupby('Race')['DRS'].mean().sort_values(
            ascending=False
        )
        ax.barh(drs.index, drs.values,
                color=TEAM_COLORS[team], alpha=0.85)
        ax.set_title(f'{TEAM_LABELS[team]}\nAvg DRS State per Circuit',
                     color='white', fontsize=11)
        ax.set_xlabel('Avg DRS Value', color='white')
        ax.tick_params(colors='white')
        for spine in ax.spines.values():
            spine.set_edgecolor('#444444')

    save_plot(fig, 'drs_usage.png')


def main():
    logging.info("Loading processed baselines...")
    merc = load_team('mercedes')
    rbr  = load_team('redbull')

    logging.info("Generating plots...")
    plot_speed_distribution(merc, rbr)
    plot_throttle_vs_speed(merc, rbr)
    plot_channel_stats(merc, rbr)
    plot_anomaly_counts()
    plot_drs_usage(merc, rbr)

    logging.info("All plots saved to architecture/diagrams/")


if __name__ == "__main__":
    main()