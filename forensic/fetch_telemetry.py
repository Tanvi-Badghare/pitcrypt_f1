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

# ── Real FastF1 team names → internal team key ───────────────────
TEAMS = {
    'Mercedes':        'mercedes',
    'Red Bull Racing': 'redbull',
}

# ── Branded display names — for logging only ─────────────────────
TEAM_DISPLAY_NAMES = {
    'mercedes': 'Mercedes AMG Petronas',
    'redbull':  'Red Bull Racing',
}

CHANNELS = [
    'Speed', 'RPM', 'Throttle', 'Brake',
    'nGear', 'DRS', 'Distance', 'X', 'Y',
]

YEAR = 2025


def get_telemetry_with_gear(lap) -> pd.DataFrame:
    """
    Fetch telemetry for a lap, patching nGear from car data
    if the channel is missing or entirely zero in lap telemetry.
    FastF1's get_telemetry() merges pos + car data but nGear
    occasionally drops out — get_car_data() is the reliable source.
    """
    tel = lap.get_telemetry()
    if tel.empty:
        return tel

    gear_missing = (
        'nGear' not in tel.columns
        or tel['nGear'].eq(0).all()
        or tel['nGear'].isna().all()
    )

    if gear_missing:
        try:
            car_data = lap.get_car_data()
            if not car_data.empty and 'nGear' in car_data.columns:
                gear_values = car_data['nGear'].reset_index(drop=True)
                tel = tel.copy().reset_index(drop=True)
                tel['nGear'] = gear_values.reindex(
                    tel.index, fill_value=0
                )
                print(f"      nGear patched from car_data "
                      f"(max gear: {int(tel['nGear'].max())})")
        except Exception as e:
            print(f"      nGear patch failed: {e}")

    if 'RPM' not in tel.columns or tel['RPM'].eq(0).all():
        try:
            car_data = lap.get_car_data()
            if not car_data.empty and 'RPM' in car_data.columns:
                rpm_values = car_data['RPM'].reset_index(drop=True)
                tel = tel.copy().reset_index(drop=True)
                tel['RPM'] = rpm_values.reindex(
                    tel.index, fill_value=0
                )
        except Exception:
            pass

    return tel


for race, sessions in RACE_SESSIONS.items():
    for session_type in sessions:
        try:
            print(f"\nLoading {race} {session_type}...")
            session = fastf1.get_session(YEAR, race, session_type)
            session.load(telemetry=True, laps=True, weather=True)

            for team_name, team_key in TEAMS.items():
                out_path = os.path.join(
                    RAW_DIR, f"{team_key}_{race}_{session_type}.csv"
                )
                if os.path.exists(out_path):
                    print(f"  Already exists: {out_path} — skipping")
                    continue

                display_name = TEAM_DISPLAY_NAMES[team_key]
                laps = session.laps.pick_teams(team_name)

                if laps.empty:
                    print(f"  No laps for {display_name} "
                          f"— {race} {session_type}")
                    continue

                frames = []
                for _, lap in laps.iterlaps():
                    try:
                        tel = get_telemetry_with_gear(lap)
                        if tel.empty:
                            continue

                        for ch in CHANNELS:
                            if ch not in tel.columns:
                                tel[ch] = 0

                        # Drop near-stationary rows —
                        # pit lane artefacts below 5 km/h
                        tel = tel[tel['Speed'] > 5]
                        if tel.empty:
                            continue

                        tel              = tel[CHANNELS].copy()
                        tel['Driver']    = lap['Driver']
                        tel['LapNumber'] = lap['LapNumber']
                        tel['Team']      = display_name
                        tel['Race']      = race
                        tel['Session']   = session_type
                        frames.append(tel)

                    except Exception as e:
                        print(f"      Lap skipped: {e}")
                        continue

                if frames:
                    df = pd.concat(frames, ignore_index=True)

                    gear_ok  = int(df['nGear'].max()) > 0
                    speed_ok = float(df['Speed'].max()) > 100
                    print(
                        f"  ✓ {team_key}_{race}_{session_type}.csv "
                        f"({len(df):,} rows) | "
                        f"max speed: {df['Speed'].max():.0f} km/h | "
                        f"max gear: {int(df['nGear'].max())} "
                        f"{'✅' if gear_ok and speed_ok else '⚠️  CHECK DATA'}"
                    )

                    df.to_csv(out_path, index=False)
                else:
                    print(f"  No data for {display_name} "
                          f"— {race} {session_type}")

        except Exception as e:
            print(f"  Skipped {race} {session_type}: {e}")

print("\nAll done. Check data/raw/ for your CSVs.")