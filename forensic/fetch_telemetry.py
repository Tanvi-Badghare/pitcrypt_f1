import os
import fastf1
import pandas as pd

# Create folders if they don't exist
os.makedirs('cache', exist_ok=True)
os.makedirs('data/raw', exist_ok=True)

# ALWAYS enable cache first
fastf1.Cache.enable_cache('cache/')

# What to download
RACES = [
    'Bahrain',        # Round 1 — clean baseline
    'Saudi Arabia',   # Round 2 — street circuit, night race
    'Australia',      # Round 3 — semi-street, high SC probability
    'Monaco',         # Round 8 — extreme low speed
    'Silverstone',    # Round 10 — highest speed corners
    'Monza',          # Round 16 — highest straight speed
    'Singapore',      # Round 18 — street circuit, high brake events
    'Qatar',          # Round 19 — extreme tyre stress
    'São Paulo',      # Round 21 — sprint weekend format
    'Abu Dhabi',      # Round 24 — season finale, peak development
]
SESSIONS = ['R', 'Q']
TEAMS = {
    'Mercedes': 'mercedes',
    'Red Bull Racing': 'redbull'
}
YEAR = 2025

for race in RACES:
    for session_type in SESSIONS:
        try:
            print(f"\nLoading {race} {session_type}...")
            session = fastf1.get_session(YEAR, race, session_type)
            session.load(telemetry=True, laps=True, weather=True)

            for team_name, team_key in TEAMS.items():
                laps = session.laps.pick_teams(team_name)

                all_telemetry = []
                for _, lap in laps.iterlaps():
                    try:
                        tel = lap.get_telemetry()
                        tel['Driver']    = lap['Driver']
                        tel['LapNumber'] = lap['LapNumber']
                        tel['Team']      = team_name
                        tel['Race']      = race
                        tel['Session']   = session_type
                        all_telemetry.append(tel)
                    except Exception:
                        continue

                if all_telemetry:
                    df = pd.concat(all_telemetry, ignore_index=True)
                    filename = f"data/raw/{team_key}_{race}_{session_type}.csv"
                    df.to_csv(filename, index=False)
                    print(f"  Saved: {filename} ({len(df):,} rows)")
                else:
                    print(f"  No data for {team_name} — {race} {session_type}")

        except Exception as e:
            print(f"  Skipped {race} {session_type}: {e}")

print("\nAll done. Check data/raw/ for your CSVs.")