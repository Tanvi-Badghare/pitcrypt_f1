import os
import fastf1
import pandas as pd

ROOT    = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RAW_DIR = os.path.join(ROOT, 'data', 'raw')
os.makedirs(RAW_DIR, exist_ok=True)

fastf1.Cache.enable_cache(
    os.path.join(ROOT, 'cache')
)

# ── Edit this to fetch one team at a time ────────────────────────
TARGET_TEAM = {
    'Williams': 'williams',         # ← change this each run
}

RACES = [
    'Bahrain', 'Saudi Arabia', 'Australia', 'Japan',
    'Monaco', 'Singapore', 'Monza', 'Silverstone',
    'Netherlands', 'Baku', 'Qatar', 'Abu Dhabi', 'São Paulo',
]

SESSIONS     = ['R', 'Q']
SPRINT_RACES = ['Qatar', 'São Paulo']
CHANNELS     = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS', 'Distance', 'X', 'Y']


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

    # Check if nGear is missing or all zeros
    gear_missing = (
        'nGear' not in tel.columns
        or tel['nGear'].eq(0).all()
        or tel['nGear'].isna().all()
    )

    if gear_missing:
        try:
            car_data = lap.get_car_data()
            if not car_data.empty and 'nGear' in car_data.columns:
                # Align by index length — car_data and tel may differ
                gear_values = car_data['nGear'].reset_index(drop=True)
                tel = tel.copy().reset_index(drop=True)
                tel['nGear'] = gear_values.reindex(
                    tel.index, fill_value=0
                )
                print(f"      nGear patched from car_data "
                      f"(max gear: {int(tel['nGear'].max())})")
        except Exception as e:
            print(f"      nGear patch failed: {e}")

    # Also patch RPM if missing — same source
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


for team_name, team_key in TARGET_TEAM.items():
    print(f"\n{'='*50}")
    print(f"  Fetching: {team_name} ({team_key})")
    print(f"{'='*50}")

    for race in RACES:
        session_types = SESSIONS + (
            ['S'] if race in SPRINT_RACES else []
        )
        for session_type in session_types:
            out_path = os.path.join(
                RAW_DIR,
                f"{team_key}_{race}_{session_type}.csv"
            )

            if os.path.exists(out_path):
                print(
                    f"  Already exists: "
                    f"{team_key}_{race}_{session_type}.csv — skipping"
                )
                continue

            print(f"  Loading {race} {session_type}...")
            try:
                session = fastf1.get_session(
                    2025, race, session_type
                )
                session.load(
                    telemetry=True,
                    laps=True,
                    weather=False,
                    messages=False,
                )

                laps = session.laps.pick_teams(team_name)
                if laps.empty:
                    print(
                        f"  No laps for {team_name} — "
                        f"{race} {session_type}"
                    )
                    continue

                frames = []
                for _, lap in laps.iterlaps():
                    try:
                        tel = get_telemetry_with_gear(lap)
                        if tel.empty:
                            continue

                        # Fill any remaining missing channels with 0
                        for ch in CHANNELS:
                            if ch not in tel.columns:
                                tel[ch] = 0

                        # Drop near-stationary rows —
                        # pit lane artefacts below 5 km/h
                        # skew speed stats and produce gear=0 rows
                        tel = tel[tel['Speed'] > 5]

                        if tel.empty:
                            continue

                        tel = tel[CHANNELS].copy()
                        tel['Driver']    = lap['Driver']
                        tel['LapNumber'] = lap['LapNumber']
                        tel['Team']    = team_name
                        tel['Race']    = race
                        tel['Session'] = session_type
                        frames.append(tel)

                    except Exception as e:
                        print(f"      Lap skipped: {e}")
                        continue

                if frames:
                    df = pd.concat(frames, ignore_index=True)

                    # Sanity check before saving
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
                    print(
                        f"  No telemetry for {team_name} — "
                        f"{race} {session_type}"
                    )

            except Exception as e:
                print(f"  Skipped {race} {session_type}: {e}")