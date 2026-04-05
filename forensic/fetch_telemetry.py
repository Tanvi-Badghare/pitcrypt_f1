import os
import fastf1
import pandas as pd

# Create folders if they don't exist
os.makedirs('cache', exist_ok=True)
os.makedirs('data/raw', exist_ok=True)

# ALWAYS enable cache first
fastf1.Cache.enable_cache('cache/')

# Races and their available session types
RACE_SESSIONS = {
    'Australia':    ['R', 'Q'],           # Round 1  — season opener, semi-street, high SC probability
    'Japan':        ['R', 'Q'],           # Round 3  — highest sustained high speed, unique S-curves
    'Bahrain':      ['R', 'Q'],           # Round 4  — technical baseline, smooth asphalt
    'Saudi Arabia': ['R', 'Q'],           # Round 5  — street circuit, night race, long straights
    'Monaco':       ['R', 'Q'],           # Round 8  — extreme low speed, highest brake events
    'Silverstone':  ['R', 'Q'],           # Round 12 — fastest corners, high sustained load
    'Netherlands':  ['R', 'Q'],           # Round 15 — high banking, most aero demanding
    'Monza':        ['R', 'Q'],           # Round 16 — highest straight speed, DRS dominant
    'Baku':         ['R', 'Q'],           # Round 17 — longest straight, street circuit
    'Singapore':    ['R', 'Q'],           # Round 18 — street circuit, extreme braking zones
    'São Paulo':    ['R', 'Q', 'S'],      # Round 21 — sprint weekend, high altitude circuit
    'Qatar':        ['R', 'Q', 'S'],      # Round 22 — sprint weekend, extreme tyre stress
    'Abu Dhabi':    ['R', 'Q'],           # Round 24 — season finale, peak car development
}

TEAMS = {
    'Mercedes': 'mercedes',
    'Red Bull Racing': 'redbull'
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