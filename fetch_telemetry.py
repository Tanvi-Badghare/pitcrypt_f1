import os
import fastf1
import pandas as pd

# ── Root is wherever this script lives ──────────────────────────
ROOT    = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(ROOT, 'data', 'raw')
CACHE   = os.path.join(ROOT, 'cache')

os.makedirs(CACHE,   exist_ok=True)
os.makedirs(RAW_DIR, exist_ok=True)

fastf1.Cache.enable_cache(CACHE)

RACE_SESSIONS = {
    'Australia':    ['R', 'Q'],
    'Japan':        ['R', 'Q'],
    'Bahrain':      ['R', 'Q'],
    'Saudi Arabia': ['R', 'Q'],
    'Monaco':       ['R', 'Q'],
    'Silverstone':  ['R', 'Q'],
    'Netherlands':  ['R', 'Q'],
    'Monza':        ['R', 'Q'],
    'Baku':         ['R', 'Q'],
    'Singapore':    ['R', 'Q'],
    'São Paulo':    ['R', 'Q', 'S'],
    'Qatar':        ['R', 'Q', 'S'],
    'Abu Dhabi':    ['R', 'Q'],
}

TEAMS = {
    'Mercedes':        'mercedes',
    'Red Bull Racing': 'redbull',
}
YEAR = 2025

for race, sessions in RACE_SESSIONS.items():
    for session_type in sessions:
        try:
            print(f"\nLoading {race} {session_type}...")
            session = fastf1.get_session(YEAR, race, session_type)
            session.load(telemetry=True, laps=True, weather=True)

            for team_name, team_key in TEAMS.items():
                laps = session.laps.pick_teams(team_name)

                all_telemetry = []
                for _, lap in laps.iterlaps():
                    try:
                        tel              = lap.get_telemetry()
                        tel['Driver']    = lap['Driver']
                        tel['LapNumber'] = lap['LapNumber']
                        tel['Team']      = team_name
                        tel['Race']      = race
                        tel['Session']   = session_type
                        all_telemetry.append(tel)
                    except Exception:
                        continue

                if all_telemetry:
                    df       = pd.concat(all_telemetry, ignore_index=True)
                    filename = os.path.join(
                        RAW_DIR, f"{team_key}_{race}_{session_type}.csv"
                    )
                    df.to_csv(filename, index=False)
                    print(f"  Saved: {filename} ({len(df):,} rows)")
                else:
                    print(f"  No data for {team_name} — {race} {session_type}")

        except Exception as e:
            print(f"  Skipped {race} {session_type}: {e}")

print("\nAll done. Check data/raw/ for your CSVs.")