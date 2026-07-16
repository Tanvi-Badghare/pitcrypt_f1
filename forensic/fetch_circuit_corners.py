import os
import json
import time
import fastf1

ROOT       = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CORNER_DIR = os.path.join(ROOT, 'data', 'circuits')
os.makedirs(CORNER_DIR, exist_ok=True)

fastf1.Cache.enable_cache(os.path.join(ROOT, 'cache'))

RACES = [
    'Bahrain', 'Saudi Arabia', 'Australia', 'Japan',
    'Monaco', 'Singapore', 'Monza', 'Silverstone',
    'Netherlands', 'Baku', 'Qatar', 'Abu Dhabi', 'São Paulo',
]

for race in RACES:
    out_path = os.path.join(CORNER_DIR, f"{race}_corners.json")
    if os.path.exists(out_path):
        print(f"  Already exists: {race}_corners.json — skipping")
        continue

    print(f"  Fetching: {race}...")
    try:
        session = fastf1.get_session(2025, race, 'R')
        # laps=True required for get_circuit_info()
        # telemetry=False keeps it fast
        session.load(
            laps=True, telemetry=False,
            weather=False, messages=False,
        )

        ci      = session.get_circuit_info()
        corners = ci.corners

        corner_list = []
        for _, row in corners.iterrows():
            corner_list.append({
                'number': int(row['Number']),
                'letter': str(row['Letter']).strip(),
                'x':      float(row['X']),
                'y':      float(row['Y']),
                'angle':  float(row['Angle']),
            })

        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump({
                'race':    race,
                'corners': corner_list,
            }, f, indent=2)

        print(f"  ✓ {race}: {len(corner_list)} corners saved")
        time.sleep(2)

    except Exception as e:
        print(f"  Skipped {race}: {e}")

print("\nDone. Check data/circuits/ for JSON files.")