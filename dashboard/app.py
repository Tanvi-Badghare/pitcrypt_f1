import os
import sys
import time
import json as _json
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timezone
from typing import Optional
from PIL import Image
from performance.lap_analysis import LapAnalyzer
from performance.sector_analysis import SectorAnalyzer
from performance.driver_comparison import DriverComparison
from performance.track_analysis import TrackAnalyzer
from performance.corner_analysis import CornerAnalyzer


# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)
CAR_SRC = os.path.join(ROOT, 'car-producer', 'src')
REL_SRC = os.path.join(ROOT, 'relay-node', 'src')
VAL_SRC = os.path.join(ROOT, 'validator-node', 'src')
IAM_SRC = os.path.join(ROOT, 'iam-module', 'src')
DASH = os.path.join(ROOT, 'dashboard')

for path in [CAR_SRC, REL_SRC, VAL_SRC, IAM_SRC, DASH]:
    if path not in sys.path:
        sys.path.insert(0, path)

from components.telemetry_feed import TelemetryFeed
from components.threat_panel import ThreatPanel


# ── Team configuration ────────────────────────────────────────────
TEAM_CONFIG = {
    "mercedes": {
        "name": "Mercedes AMG",
        "color": "#00d2be",
        "emoji": "🩵",
    },
    "redbull": {
        "name": "Red Bull Racing",
        "color": "#3671c6",
        "emoji": "🔵",
    },
    "ferrari": {
        "name": "Scuderia Ferrari",
        "color": "#e8002d",
        "emoji": "🔴",
    },
    "mclaren": {
        "name": "McLaren Racing",
        "color": "#ff8000",
        "emoji": "🟠",
    },
    "williams": {
        "name": "Williams Racing",
        "color": "#64c4ff",
        "emoji": "🩶",
    },
}

TEAMS_WITHOUT_DATA = set()


# ── Cached helpers ────────────────────────────────────────────────
@st.cache_data
def peek_drivers_and_laps(team: str, race: str, session: str):
    import pandas as pd

    raw_dir = os.path.join(ROOT, 'data', 'raw')
    target = f"{team}_{race}_{session}.csv"
    path = os.path.join(raw_dir, target)

    if not os.path.exists(path):
        return [], []

    try:
        df = pd.read_csv(
            path,
            usecols=lambda c: c in ['Driver', 'LapNumber'],
        )

        drivers = sorted(
            df['Driver'].dropna().unique().tolist()
        ) if 'Driver' in df.columns else []

        laps = sorted(
            df['LapNumber'].dropna().astype(int).unique().tolist()
        ) if 'LapNumber' in df.columns else []

        return drivers, laps

    except Exception:
        return [], []


@st.cache_data
def peek_driver_laps(
    team: str,
    race: str,
    session: str,
    driver: str,
):
    """
    Return only the laps available for a specific driver.

    This is used by Driver vs Driver comparison so that the
    second driver cannot be assigned a lap that does not exist
    in their telemetry.
    """
    import pandas as pd

    raw_dir = os.path.join(ROOT, 'data', 'raw')
    target = f"{team}_{race}_{session}.csv"
    path = os.path.join(raw_dir, target)

    if not os.path.exists(path):
        return []

    try:
        df = pd.read_csv(
            path,
            usecols=lambda c: c in ['Driver', 'LapNumber'],
        )

        if 'Driver' not in df.columns or 'LapNumber' not in df.columns:
            return []

        driver_df = df[df['Driver'].astype(str) == str(driver)]

        return sorted(
            driver_df['LapNumber']
            .dropna()
            .astype(int)
            .unique()
            .tolist()
        )

    except Exception:
        return []


@st.cache_data
def load_circuit_outline(race: str, team: str) -> tuple:
    """
    Load one reference lap's X/Y coordinates to draw
    the real circuit shape. Tries multiple teams/sessions
    until it finds usable data.

    Cached so it only loads once per race/team combo.
    """
    import pandas as pd

    raw_dir = os.path.join(ROOT, 'data', 'raw')

    for t in [
        team,
        'mercedes',
        'ferrari',
        'redbull',
        'mclaren',
        'williams',
    ]:
        for sess in ['R', 'Q']:
            fname = f"{t}_{race}_{sess}.csv"
            path = os.path.join(raw_dir, fname)

            if not os.path.exists(path):
                continue

            try:
                df = pd.read_csv(
                    path,
                    usecols=lambda c: c in [
                        'X',
                        'Y',
                        'LapNumber',
                    ],
                )

                if 'X' not in df.columns or 'Y' not in df.columns:
                    continue

                if 'LapNumber' in df.columns:
                    min_lap = df['LapNumber'].min()
                    lap1 = df[df['LapNumber'] == min_lap]

                    if len(lap1) > 100:
                        return (
                            lap1['X'].tolist(),
                            lap1['Y'].tolist(),
                        )

                sample = df.head(800)

                if len(sample) > 50:
                    return (
                        sample['X'].tolist(),
                        sample['Y'].tolist(),
                    )

            except Exception:
                continue

    return [], []


# ── Page config ───────────────────────────────────────────────────
try:
    favicon = Image.open(
        os.path.join(
            ROOT,
            'dashboard',
            'assets',
            'favicon.png',
        )
    )

    st.set_page_config(
        page_title="PitCrypt-F1 Security Dashboard",
        page_icon=favicon,
        layout="wide",
        initial_sidebar_state="expanded",
    )

except Exception:
    st.set_page_config(
        page_title="PitCrypt-F1 Security Dashboard",
        page_icon="🏎️",
        layout="wide",
        initial_sidebar_state="expanded",
    )


# ── Custom CSS ────────────────────────────────────────────────────
st.markdown(
    """
<style>
    .main { background-color: #0a0a0a; }

    .accept-badge {
        background-color: #00c851;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
    }

    .reject-badge {
        background-color: #e10600;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
    }

    .flag-badge {
        background-color: #ff8800;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
    }

    .threat-alert {
        background-color: #1a0000;
        border-left: 4px solid #e10600;
        padding: 0.5rem 1rem;
        margin: 0.25rem 0;
        border-radius: 0 4px 4px 0;
        font-size: 0.85rem;
    }

    .crypto-ok {
        color: #00c851;
        font-weight: bold;
    }

    .pipeline-header {
        font-size: 1.1rem;
        font-weight: bold;
        color: #e10600;
        border-bottom: 1px solid #333;
        padding-bottom: 0.25rem;
        margin-bottom: 0.5rem;
    }

    .telemetry-row {
        display: flex;
        align-items: center;
        flex-wrap: nowrap;
        white-space: nowrap;
        gap: 0.35rem;
        width: 100%;
        overflow-x: auto;
        overflow-y: hidden;
        padding: 0.18rem 0;
        margin: 0;
        font-size: 0.86rem;
        line-height: 1.35;
        scrollbar-width: thin;
    }

    .telemetry-row::-webkit-scrollbar {
        height: 4px;
    }

    .telemetry-row .telemetry-seq {
        color: #00c851;
        background: #151923;
        border-radius: 4px;
        padding: 2px 5px;
        font-family: monospace;
        flex: 0 0 auto;
    }

    .telemetry-row .telemetry-main,
    .telemetry-row .telemetry-value {
        flex: 0 0 auto;
    }

    .telemetry-row .telemetry-main {
        font-weight: 600;
    }

    div[data-testid="metric-container"] {
        background: #1a1a2e;
        border: 1px solid #333;
        border-radius: 6px;
        padding: 0.5rem;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ── Session state ─────────────────────────────────────────────────
def init_session_state():
    if 'feed' not in st.session_state:
        st.session_state.feed = TelemetryFeed()

    if 'feed_b' not in st.session_state:
        st.session_state.feed_b = TelemetryFeed()

    if 'threat_panel' not in st.session_state:
        st.session_state.threat_panel = ThreatPanel()

    if 'running' not in st.session_state:
        st.session_state.running = False

    if 'packets_processed' not in st.session_state:
        st.session_state.packets_processed = 0

    if 'start_time' not in st.session_state:
        st.session_state.start_time = None

    if 'run_history' not in st.session_state:
        st.session_state.run_history = []


init_session_state()

feed = st.session_state.feed
feed_b = st.session_state.feed_b
threat_panel = st.session_state.threat_panel


# ── Header ────────────────────────────────────────────────────────
col_logo, col_title, col_status = st.columns([1, 4, 2])

with col_logo:
    st.markdown("# 🏎️")

with col_title:
    st.markdown("## PitCrypt-F1 Security Dashboard")
    st.markdown("*Zero-Trust Cryptographic Telemetry Pipeline*")

with col_status:
    pipeline_status = feed.get_pipeline_status()
    status_color = "🟢" if pipeline_status == "ACTIVE" else "🔴"

    st.markdown(
        f"### {status_color} Pipeline: {pipeline_status}"
    )

    st.markdown(
        f"*{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}*"
    )

st.divider()


with st.expander("ℹ️ What do these numbers mean?"):
    st.markdown(
        """
    - **Speed** — car speed in km/h at this exact moment on track
    - **RPM** — engine revolutions per minute; how hard the engine is working
    - **Throttle %** — how much the driver is pressing the accelerator (100% = flat out)
    - **Gear** — gearbox position (1 = lowest/slowest, 8 = highest/fastest)
    - **seq=XXXX** — packet sequence number; proves no data was skipped or replayed
    - **ACCEPT** — FIA validator confirmed this packet is authentic and unmodified
    - **REJECT** — packet blocked; tampered, replayed, or forged
    - **FLAG** — packet accepted but contains a statistically unusual sensor value
    - **Session key** — one-time cryptographic secret used to encrypt the data stream
    - **ECDH** — how both sides agree on that secret without ever sending it directly
    - **→T4** — car is approaching Turn 4; **T4** — car is at the apex of Turn 4
    """
    )


# ── Sidebar ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Pipeline Controls")

    # ── Team A ────────────────────────────────────────────────────
    team = st.selectbox(
        "Constructor",
        list(TEAM_CONFIG.keys()),
        format_func=lambda x: (
            f"{TEAM_CONFIG[x]['emoji']}  {TEAM_CONFIG[x]['name']}"
        ),
        help="The F1 team whose real telemetry data you're streaming.",
    )

    st.markdown(
        f'<div style="background:{TEAM_CONFIG[team]["color"]};'
        f'height:3px;border-radius:2px;margin:4px 0 8px 0;">'
        f'</div>',
        unsafe_allow_html=True,
    )

    if team in TEAMS_WITHOUT_DATA:
        st.warning(
            f"⚠️ {TEAM_CONFIG[team]['name']} CSV data not yet "
            f"downloaded. Full cryptographic pipeline still active.",
        )

    # ── Circuit + session ─────────────────────────────────────────
    race = st.selectbox(
        "Circuit",
        [
            "Bahrain",
            "Saudi Arabia",
            "Australia",
            "Japan",
            "Monaco",
            "Canada",
            "Singapore",
            "Monza",
            "Silverstone",
            "Netherlands",
            "Baku",
            "Qatar",
            "Abu Dhabi",
        ],
        help="Which Grand Prix circuit's real telemetry to stream.",
    )

    session = st.selectbox(
        "Session",
        ["R", "Q", "S"],
        format_func=lambda x: {
            "R": "Race",
            "Q": "Qualifying",
            "S": "Sprint",
        }[x],
        help="Race / Qualifying / Sprint session.",
    )

    # ── Comparison controls ──────────────────────────────────────
    compare_mode = st.checkbox(
        "⚖️ Enable comparison",
        help=(
            "Run two independent encrypted telemetry pipelines "
            "simultaneously."
        ),
    )

    comparison_type = None

    if compare_mode:
        comparison_type = st.radio(
            "Comparison type",
            [
                "Team vs Team",
                "Driver vs Driver",
            ],
            horizontal=True,
            help=(
                "Team vs Team compares telemetry from two constructors. "
                "Driver vs Driver allows two drivers from the same "
                "constructor to be compared."
            ),
        )

    # ── Team A driver + lap ───────────────────────────────────────
    available_drivers, available_laps = peek_drivers_and_laps(
        team,
        race,
        session,
    )

    selected_driver = 'All drivers'
    selected_lap = 'All laps'

    driver_arg = None
    lap_arg = None

    # Driver vs Driver requires an explicit Driver A.
    # This avoids an ambiguous "All drivers vs Driver B" comparison.
    if (
        compare_mode
        and comparison_type == "Driver vs Driver"
    ):
        st.markdown("---")
        st.markdown("**Driver A**")

        if available_drivers:
            selected_driver = st.selectbox(
                "Driver A",
                available_drivers,
                format_func=lambda x: f"🪖 {x}",
                key="driver_a_compare_select",
                help="First driver in the driver-vs-driver comparison.",
            )

            driver_arg = selected_driver

            # Laps for Driver A
            driver_a_laps = peek_driver_laps(
                team,
                race,
                session,
                selected_driver,
            )

            if driver_a_laps:
                selected_lap = st.selectbox(
                    "Lap",
                    ['All laps'] + [
                        str(l) for l in driver_a_laps
                    ],
                    format_func=lambda x: (
                        x if x == 'All laps' else f"Lap {x}"
                    ),
                    key="lap_a_compare_select",
                    help=(
                        "Choose a lap available to Driver A "
                        "and Driver B."
                    ),
                )
            else:
                selected_lap = 'All laps'
                st.caption("No lap data available for Driver A.")

        else:
            st.warning(
                "No driver telemetry is available for this "
                "constructor/session."
            )

    else:
        # Normal Team A selector
        if available_drivers:
            selected_driver = st.selectbox(
                "Driver",
                ['All drivers'] + available_drivers,
                format_func=lambda x: (
                    x if x == 'All drivers' else f"🪖 {x}"
                ),
                help="Filter to one specific driver's data.",
            )
        else:
            selected_driver = 'All drivers'
            st.caption("No driver data for this selection.")

        if available_laps:
            selected_lap = st.selectbox(
                "Lap",
                ['All laps'] + [
                    str(l) for l in available_laps
                ],
                format_func=lambda x: (
                    x if x == 'All laps' else f"Lap {x}"
                ),
                help="Filter to one specific lap only.",
            )
        else:
            selected_lap = 'All laps'
            st.caption("No lap data for this selection.")

        driver_arg = (
            None
            if selected_driver == 'All drivers'
            else selected_driver
        )

        lap_arg = (
            None
            if selected_lap == 'All laps'
            else int(selected_lap)
        )

    # ── Comparison B controls ────────────────────────────────────
    team_b = None
    selected_driver_b = 'All drivers'
    selected_lap_b = 'All laps'
    driver_b_arg = None
    lap_b_arg = None

    if compare_mode:

        # ==========================================================
        # TEAM VS TEAM
        # ==========================================================
        if comparison_type == "Team vs Team":

            st.markdown("---")
            st.markdown("**Second Constructor**")

            team_b = st.selectbox(
                "Constructor (Team B)",
                [
                    t
                    for t in TEAM_CONFIG.keys()
                    if t != team
                ],
                format_func=lambda x: (
                    f"{TEAM_CONFIG[x]['emoji']} "
                    f"{TEAM_CONFIG[x]['name']}"
                ),
                key='team_b_select',
            )

            b_drivers, b_laps = peek_drivers_and_laps(
                team_b,
                race,
                session,
            )

            if b_drivers:
                selected_driver_b = st.selectbox(
                    "Driver (Team B)",
                    ['All drivers'] + b_drivers,
                    format_func=lambda x: (
                        x
                        if x == 'All drivers'
                        else f"🪖 {x}"
                    ),
                    key='driver_b_select',
                )
            else:
                selected_driver_b = 'All drivers'
                st.caption(
                    "No driver data for Team B "
                    "selection."
                )

            if b_laps:
                selected_lap_b = st.selectbox(
                    "Lap (Team B)",
                    ['All laps'] + [
                        str(l) for l in b_laps
                    ],
                    format_func=lambda x: (
                        x
                        if x == 'All laps'
                        else f"Lap {x}"
                    ),
                    key='lap_b_select',
                )
            else:
                selected_lap_b = 'All laps'

            driver_b_arg = (
                None
                if selected_driver_b == 'All drivers'
                else selected_driver_b
            )

            lap_b_arg = (
                None
                if selected_lap_b == 'All laps'
                else int(selected_lap_b)
            )

        # ==========================================================
        # DRIVER VS DRIVER
        # ==========================================================
        elif comparison_type == "Driver vs Driver":

            st.markdown("---")
            st.markdown(
                f"**Driver B — {TEAM_CONFIG[team]['name']}**"
            )

            # Driver A must exist before Driver B can be selected.
            if available_drivers and selected_driver != 'All drivers':

                driver_b_options = [
                    d
                    for d in available_drivers
                    if d != selected_driver
                ]

                if driver_b_options:
                    selected_driver_b = st.selectbox(
                        "Driver B",
                        driver_b_options,
                        format_func=lambda x: f"🪖 {x}",
                        key="driver_b_same_team_select",
                        help=(
                            "Second driver from the same "
                            "constructor."
                        ),
                    )

                    driver_b_arg = selected_driver_b

                    # ------------------------------------------------
                    # Find laps common to both drivers.
                    # ------------------------------------------------
                    driver_a_laps = set(
                        peek_driver_laps(
                            team,
                            race,
                            session,
                            selected_driver,
                        )
                    )

                    driver_b_laps = set(
                        peek_driver_laps(
                            team,
                            race,
                            session,
                            selected_driver_b,
                        )
                    )

                    common_laps = sorted(
                        driver_a_laps.intersection(
                            driver_b_laps
                        )
                    )

                    if common_laps:

                        # Re-render Driver A lap selector using
                        # only laps that exist for BOTH drivers.
                        #
                        # The selector above may have already shown
                        # Driver A's complete lap list. We retain
                        # its selected value if it is valid.
                        if (
                            selected_lap != 'All laps'
                            and int(selected_lap) in common_laps
                        ):
                            lap_arg = int(selected_lap)

                        elif selected_lap != 'All laps':
                            st.warning(
                                f"Lap {selected_lap} is not "
                                f"available for both drivers. "
                                f"Using all common laps instead."
                            )
                            selected_lap = 'All laps'
                            lap_arg = None

                        st.caption(
                            f"Common laps available: "
                            f"{len(common_laps)}"
                        )

                        # Separate B lap selector is intentionally
                        # synchronized with Driver A. This ensures
                        # the comparison uses the same lap.
                        selected_lap_b = selected_lap
                        lap_b_arg = lap_arg

                    else:
                        st.warning(
                            "No common laps were found for "
                            "these two drivers. "
                            "Try another session or driver pair."
                        )

                        selected_lap_b = 'All laps'
                        lap_b_arg = None

                else:
                    st.warning(
                        "Only one driver is available for "
                        "this constructor/session."
                    )

            else:
                st.info(
                    "Select Driver A first to enable "
                    "Driver B comparison."
                )

            st.caption(
                "Driver B uses the same lap selection as Driver A "
                "so both telemetry streams can be compared directly."
            )

        st.markdown("---")

    # ── Packet controls ───────────────────────────────────────────
    n_packets = st.slider(
        "Packets to simulate",
        min_value=10,
        max_value=500,
        value=100,
        step=10,
        help=(
            "Each packet = one telemetry sample. "
            "500 packets ≈ half a lap on the track map."
        ),
    )

    st.divider()

    col_start, col_stop = st.columns(2)

    with col_start:
        start_btn = st.button(
            "▶ Start",
            use_container_width=True,
            type="primary",
        )

    with col_stop:
        stop_btn = st.button(
            "⏹ Reset",
            use_container_width=True,
        )

    # ── Start pipeline ────────────────────────────────────────────
    if start_btn:

        with st.spinner("Initialising pipeline..."):

            feed.initialise(
                team=team,
                race=race,
                session=session,
                driver=driver_arg,
                lap=lap_arg,
            )

            if compare_mode:
                if comparison_type == "Team vs Team" and team_b:
                    feed_b.initialise(
                        team=team_b,
                        race=race,
                        session=session,
                        driver=driver_b_arg,
                        lap=lap_b_arg,
                    )

                elif (
                    comparison_type == "Driver vs Driver"
                    and driver_b_arg
                ):
                    # Same team, second driver.
                    feed_b.initialise(
                        team=team,
                        race=race,
                        session=session,
                        driver=driver_b_arg,
                        lap=lap_b_arg,
                    )

            threat_panel.reset()

            st.session_state.running = True
            st.session_state.start_time = time.time()
            st.session_state.packets_processed = 0

        st.success("Pipeline ready ✅")

    # ── Reset ─────────────────────────────────────────────────────
    if stop_btn:

        feed.reset()
        feed_b.reset()
        threat_panel.reset()

        st.session_state.running = False
        st.session_state.packets_processed = 0
        st.session_state.start_time = None

        st.info("Pipeline reset")

    # ── Attack simulation ─────────────────────────────────────────
    st.divider()
    st.markdown("### 🎯 Attack Simulation")

    attack_type = st.selectbox(
        "Choose attack",
        ['tamper', 'replay', 'forge'],
        format_func=lambda x: {
            'tamper': '🔓 Tamper Ciphertext',
            'replay': '🔁 Replay Old Packet',
            'forge': '✍️ Forge Signature',
        }[x],
        help=(
            "Inject one malicious packet and watch "
            "the pipeline catch it."
        ),
    )

    if st.button(
        "💀 Inject Attack",
        use_container_width=True,
    ):

        if st.session_state.running:

            attack_result = feed.inject_attack(
                attack_type
            )

            if attack_result:

                threat_panel.ingest(
                    attack_result
                )

                if attack_result['decision'] == 'REJECT':
                    st.error(
                        f"✅ Attack BLOCKED — "
                        f"{attack_type} → "
                        f"{attack_result['reason']}"
                    )

                else:
                    st.warning(
                        f"⚠️ Attack slipped through — "
                        f"{attack_type} → "
                        f"{attack_result['decision']}"
                    )

            else:
                st.info(
                    "No prior packet to replay. "
                    "Run at least one batch first."
                )

        else:
            st.warning(
                "Start the pipeline first."
            )

    # ── Crypto stack ──────────────────────────────────────────────
    st.divider()
    st.markdown("### 🔐 Crypto Stack")
    st.markdown("- X25519 ECDH")
    st.markdown("- ChaCha20-Poly1305")
    st.markdown("- Ed25519 Signatures")
    st.markdown("- HKDF-SHA256")
    st.markdown("- ZKP Hash Commitments")

    # ── Data source ───────────────────────────────────────────────
    st.divider()
    st.markdown("### 📊 Data Source")
    st.markdown(
        f"- **Team:** {TEAM_CONFIG[team]['name']}"
    )
    st.markdown(f"- **Circuit:** {race}")
    st.markdown(f"- **Session:** {session}")

    if compare_mode:
        if comparison_type == "Team vs Team" and team_b:
            st.markdown(
                f"- **Comparison:** "
                f"{TEAM_CONFIG[team]['name']} vs "
                f"{TEAM_CONFIG[team_b]['name']}"
            )

        elif (
            comparison_type == "Driver vs Driver"
            and driver_b_arg
        ):
            st.markdown(
                f"- **Comparison:** "
                f"{driver_arg} vs {driver_b_arg}"
            )

    if driver_arg:
        st.markdown(
            f"- **Driver:** {driver_arg}"
        )

    if lap_arg:
        st.markdown(
            f"- **Lap:** {lap_arg}"
        )

    rows = feed.get_data_rows()

    if rows > 0:
        st.markdown(
            f"- **Rows loaded:** {rows:,}"
        )


# ── Track map builder ─────────────────────────────────────────────
def build_track_map(
    feed_obj,
    race: str,
    team_key: str,
) -> Optional[go.Figure]:

    """
    Build live track position map using real telemetry
    X/Y for circuit outline — no straight-line artefacts.
    """

    corner_path = os.path.join(
        ROOT,
        'data',
        'circuits',
        f"{race}_corners.json",
    )

    corners = []

    if os.path.exists(corner_path):
        with open(
            corner_path,
            encoding='utf-8',
        ) as f:
            corners = _json.load(f).get(
                'corners',
                [],
            )

    recent = feed_obj.get_recent_packets(
        limit=500
    )

    if not recent:
        return None

    xs, ys, speeds = [], [], []

    for pkt in recent:

        payload = pkt.get(
            'payload_json',
            {},
        )

        x = payload.get(
            'X',
            None,
        )

        y = payload.get(
            'Y',
            None,
        )

        s = payload.get(
            'Speed',
            0,
        )

        if x is not None and y is not None:

            xs.append(
                float(x)
            )

            ys.append(
                float(y)
            )

            speeds.append(
                float(s)
            )

    if not xs:
        return None

    team_color = TEAM_CONFIG[
        team_key
    ]['color']

    fig = go.Figure()

    # ── Circuit outline from real telemetry ───────────────────────
    outline_x, outline_y = load_circuit_outline(
        race,
        team_key,
    )

    if outline_x:

        fig.add_trace(
            go.Scatter(
                x=outline_x,
                y=outline_y,
                mode='lines',
                line=dict(
                    color='#1a1a1a',
                    width=20,
                ),
                name='Track bg',
                hoverinfo='skip',
            )
        )

        fig.add_trace(
            go.Scatter(
                x=outline_x,
                y=outline_y,
                mode='lines',
                line=dict(
                    color='#3a3a3a',
                    width=14,
                ),
                name='Track',
                hoverinfo='skip',
            )
        )

        fig.add_trace(
            go.Scatter(
                x=outline_x,
                y=outline_y,
                mode='lines',
                line=dict(
                    color='#555555',
                    width=2,
                    dash='dash',
                ),
                name='Centre',
                hoverinfo='skip',
            )
        )

    else:

        if corners:

            cx = [
                c['x']
                for c in corners
            ] + [
                corners[0]['x']
            ]

            cy = [
                c['y']
                for c in corners
            ] + [
                corners[0]['y']
            ]

            fig.add_trace(
                go.Scatter(
                    x=cx,
                    y=cy,
                    mode='lines',
                    line=dict(
                        color='#333333',
                        width=8,
                    ),
                    name='Circuit',
                    hoverinfo='skip',
                )
            )

    # ── Telemetry trail coloured by speed ─────────────────────────
    fig.add_trace(
        go.Scatter(
            x=xs,
            y=ys,
            mode='lines+markers',
            marker=dict(
                size=4,
                color=speeds,
                colorscale=[
                    [0.0, '#0000ff'],
                    [0.3, '#00ff88'],
                    [0.6, '#ffff00'],
                    [1.0, '#ff0000'],
                ],
                cmin=0,
                cmax=350,
                colorbar=dict(
                    title=dict(
                        text='km/h',
                        font=dict(
                            color='#ffffff',
                            size=9,
                        ),
                    ),
                    thickness=10,
                    len=0.5,
                    tickfont=dict(
                        color='#ffffff',
                        size=8,
                    ),
                    x=1.01,
                ),
                showscale=True,
            ),
            line=dict(
                color='rgba(255,255,255,0.6)',
                width=3,
            ),
            name='Trail',
            hovertemplate='%{text}<extra></extra>',
            text=[
                f'{s:.0f} km/h'
                for s in speeds
            ],
        )
    )

    # ── Current position ──────────────────────────────────────────
    fig.add_trace(
        go.Scatter(
            x=[xs[-1]],
            y=[ys[-1]],
            mode='markers',
            marker=dict(
                size=16,
                color=team_color,
                symbol='circle',
                line=dict(
                    color='white',
                    width=2,
                ),
            ),
            name='Now',
            hovertemplate=(
                f'{speeds[-1]:.0f} km/h'
                '<extra></extra>'
            ),
        )
    )

    # ── Corner labels ─────────────────────────────────────────────
    for c in corners:

        label = (
            f"T{c['number']}"
            f"{c.get('letter', '').strip()}"
        )

        fig.add_annotation(
            x=c['x'],
            y=c['y'],
            text=label,
            showarrow=False,
            font=dict(
                color='#aaaaaa',
                size=8,
            ),
            bgcolor='rgba(0,0,0,0.5)',
        )

    fig.update_layout(
        height=380,
        margin=dict(
            l=0,
            r=55,
            t=30,
            b=0,
        ),
        plot_bgcolor='#0a0a0a',
        paper_bgcolor='#0a0a0a',
        font=dict(
            color='#ffffff'
        ),
        title=dict(
            text=f'🗺️ {race}',
            font=dict(
                color=team_color,
                size=12,
            ),
            x=0,
        ),
        xaxis=dict(
            visible=False,
            scaleanchor='y',
            scaleratio=1,
        ),
        yaxis=dict(
            visible=False
        ),
        showlegend=False,
    )

    return fig


# ── Telemetry column renderer ─────────────────────────────────────
def render_telemetry_column(
    feed_obj,
    team_key,
    label,
):

    st.markdown(
        f'<div class="pipeline-header">'
        f'🚗 {label} — Live Telemetry</div>',
        unsafe_allow_html=True,
    )

    recent = feed_obj.get_recent_packets(
        limit=15
    )

    if recent:

        for pkt in reversed(
            recent[-15:]
        ):

            payload = pkt.get(
                'payload_json',
                {},
            )

            seq = pkt.get(
                'sequence_no',
                0,
            )

            driver = payload.get(
                'driver',
                'UNK',
            )

            lap = payload.get(
                'lap',
                0,
            )

            track_pos = payload.get(
                'track_position',
                '',
            )

            decision = pkt.get(
                'decision',
                'ACCEPT',
            )

            badge_map = {
                'ACCEPT':
                    '<span class="accept-badge">'
                    'ACCEPT'
                    '</span>',

                'REJECT':
                    '<span class="reject-badge">'
                    'REJECT'
                    '</span>',

                'FLAG':
                    '<span class="flag-badge">'
                    'FLAG'
                    '</span>',
            }

            badge = badge_map.get(
                decision,
                badge_map['ACCEPT'],
            )

            speed = payload.get(
                'Speed',
                0,
            )

            rpm = payload.get(
                'RPM',
                0,
            )

            throttle = payload.get(
                'Throttle',
                0,
            )

            gear = payload.get(
                'nGear',
                0,
            )

            position_html = (
                f'<span class="telemetry-main">· '
                f'<b>{track_pos}</b></span>'
                if track_pos
                else ""
            )

            st.markdown(
                f'<div class="telemetry-row">'
                f'{badge}'
                f'<span class="telemetry-seq">'
                f'seq={seq:04d}'
                f'</span>'
                f'<span class="telemetry-main">'
                f'[{driver}] Lap <b>{lap}</b>'
                f'</span>'
                f'{position_html}'
                f'<span class="telemetry-value">· '
                f'<b>{speed:.0f}</b> km/h</span>'
                f'<span class="telemetry-value">· '
                f'<b>{rpm:.0f}</b> RPM</span>'
                f'<span class="telemetry-value">· '
                f'<b>{throttle:.0f}</b>% throttle</span>'
                f'<span class="telemetry-value">· gear '
                f'<b>{gear}</b></span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    else:
        st.info("No packets yet")

    # ── Dual-axis speed/RPM chart ─────────────────────────────────
    history = feed_obj.get_chart_history()

    if history['seq']:

        fig = go.Figure()

        fig.add_trace(
            go.Scatter(
                x=history['seq'],
                y=history['speed'],
                name='Speed (km/h)',
                line=dict(
                    color='#e10600',
                    width=3,
                ),
                yaxis='y1',
            )
        )

        fig.add_trace(
            go.Scatter(
                x=history['seq'],
                y=history['rpm'],
                name='RPM',
                line=dict(
                    color='#00d4ff',
                    width=2,
                ),
                yaxis='y2',
            )
        )

        fig.update_layout(
            height=220,
            margin=dict(
                l=10,
                r=60,
                t=30,
                b=10,
            ),
            plot_bgcolor='#0a0a0a',
            paper_bgcolor='#0a0a0a',
            font=dict(
                color='#ffffff',
                size=9,
            ),
            xaxis=dict(
                title='Packet sequence',
                gridcolor='#222',
            ),
            yaxis=dict(
                title='Speed (km/h)',
                title_font=dict(
                    color='#e10600'
                ),
                tickfont=dict(
                    color='#e10600'
                ),
                gridcolor='#222',
                range=[0, 380],
            ),
            yaxis2=dict(
                title='RPM',
                title_font=dict(
                    color='#00d4ff'
                ),
                tickfont=dict(
                    color='#00d4ff'
                ),
                overlaying='y',
                side='right',
                showgrid=False,
                range=[0, 16000],
            ),
            legend=dict(
                orientation='h',
                y=1.2,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    # ── Live track map ────────────────────────────────────────────
    track_fig = build_track_map(
        feed_obj,
        race,
        team_key,
    )

    if track_fig is not None:

        st.plotly_chart(
            track_fig,
            use_container_width=True,
            key=f"track_{team_key}_{id(feed_obj)}",
        )

    # ── Crypto summary ────────────────────────────────────────────
    crypto = feed_obj.get_crypto_stats()

    st.markdown(
        f'<span class="crypto-ok">✅</span> '
        f'Key: `{crypto["car_key"][:12]}...` · '
        f'Sig verified: **{crypto["signatures"]}** · '
        f'ZKP verified: **{crypto["zkp_verified"]}**',
        unsafe_allow_html=True,
    )


# ── Main content ──────────────────────────────────────────────────
if not st.session_state.running:

    st.info(
        "👈 Select a constructor and circuit, "
        "then click **▶ Start** to begin the simulation."
    )

    st.markdown("### How it works")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("#### 🚗 Car Node")
        st.markdown(
            "Streams real F1 telemetry from FastF1. "
            "Signs each packet with Ed25519. "
            "Encrypts with ChaCha20-Poly1305."
        )

    with col2:
        st.markdown("#### 📡 Relay Node")
        st.markdown(
            "Decrypts, checks integrity and anomalies, "
            "re-encrypts for the validator leg. "
            "First replay defence."
        )

    with col3:
        st.markdown("#### 🏁 FIA Validator")
        st.markdown(
            "Verifies Ed25519 signature, sequence, "
            "and ZKP commitment. "
            "Logs every decision to audit trail."
        )

    # ── Saved run history ─────────────────────────────────────────
    if st.session_state.run_history:

        st.divider()

        st.markdown(
            f"### 📜 Saved Runs "
            f"({len(st.session_state.run_history)})"
        )

        for idx, run in enumerate(
            reversed(
                st.session_state.run_history
            )
        ):

            run_num = (
                len(st.session_state.run_history)
                - idx
            )

            with st.expander(
                f"Run {run_num} — "
                f"{run.get('label', 'Untitled')} · "
                f"{run['timestamp']}",
                expanded=False,
            ):

                col_l, col_r = st.columns(
                    [2, 3]
                )

                with col_l:

                    team_label = run['team']

                    if run.get('team_b'):
                        team_label += (
                            f" vs {run['team_b']}"
                        )

                    st.markdown(
                        f"🏎️ **{team_label}**"
                    )

                    # Show comparison type when available.
                    if run.get(
                        'comparison_type'
                    ):
                        st.markdown(
                            f"⚖️ **{run['comparison_type']}**"
                        )

                    session_label = {
                        'R': 'Race',
                        'Q': 'Qualifying',
                        'S': 'Sprint',
                    }.get(
                        run['session'],
                        run['session'],
                    )

                    st.markdown(
                        f"📍 {run['race']} · {session_label}"
                    )

                    st.markdown(
                        f"👤 {run['driver']} · "
                        f"Lap {run['lap']}"
                    )

                    if run.get('driver_b'):
                        st.markdown(
                            f"👤 **Driver B:** "
                            f"{run['driver_b']}"
                        )

                    st.markdown(
                        f"📦 **{run['packets']}** pkts · "
                        f"✅ {run['accepted']} "
                        f"({run['accept_rate']}) · "
                        f"🚨 {run['rejected']} · "
                        f"⚠️ {run['flagged']}"
                    )

                    st.markdown(
                        f"⚡ {run['throughput']}"
                    )

                    ts = run.get(
                        'threat_stats',
                        {},
                    )

                    if ts.get(
                        'total_threats',
                        0,
                    ) > 0:

                        st.markdown(
                            f"🔴 replay="
                            f"{ts.get('replays', 0)} "
                            f"tamper="
                            f"{ts.get('tampers', 0)} "
                            f"anomaly="
                            f"{ts.get('anomalies', 0)}"
                        )

                    export_data = _json.dumps(
                        {
                            'run_info': {
                                k: v
                                for k, v in run.items()
                                if k != 'chart_history'
                            },
                            'chart_data':
                                run.get(
                                    'chart_history',
                                    {},
                                ),
                            'audit_events':
                                run.get(
                                    'audit_events',
                                    [],
                                ),
                        },
                        indent=2,
                    )

                    fname = (
                        f"pitcrypt_"
                        f"{run['team'].replace(' ', '_')}_"
                        f"{run['race']}_run"
                        f"{run_num}.json"
                    )

                    st.download_button(
                        label="⬇ Export JSON",
                        data=export_data,
                        file_name=fname,
                        mime='application/json',
                        key=f"export_{run_num}",
                    )

                with col_r:

                    h = run.get(
                        'chart_history',
                        {},
                    )

                    if h.get('seq'):

                        fig_h = go.Figure()

                        fig_h.add_trace(
                            go.Scatter(
                                x=h['seq'],
                                y=h['speed'],
                                line=dict(
                                    color='#e10600',
                                    width=2,
                                ),
                                yaxis='y1',
                            )
                        )

                        fig_h.add_trace(
                            go.Scatter(
                                x=h['seq'],
                                y=h['rpm'],
                                line=dict(
                                    color='#00d4ff',
                                    width=1,
                                ),
                                yaxis='y2',
                            )
                        )

                        fig_h.update_layout(
                            height=140,
                            margin=dict(
                                l=0,
                                r=40,
                                t=0,
                                b=0,
                            ),
                            plot_bgcolor='#0a0a0a',
                            paper_bgcolor='#0a0a0a',
                            showlegend=False,
                            xaxis=dict(
                                gridcolor='#111'
                            ),
                            yaxis=dict(
                                range=[0, 380],
                                tickfont=dict(
                                    color='#e10600',
                                    size=8,
                                ),
                                gridcolor='#111',
                            ),
                            yaxis2=dict(
                                overlaying='y',
                                side='right',
                                range=[0, 16000],
                                tickfont=dict(
                                    color='#00d4ff',
                                    size=8,
                                ),
                                showgrid=False,
                            ),
                        )

                        st.plotly_chart(
                            fig_h,
                            use_container_width=True,
                            key=f"hist_{run_num}",
                        )


else:

    progress = st.progress(
        0,
        text="Running pipeline...",
    )

    for i in range(n_packets):

        result = feed.process_one_packet()

        if result:

            threat_panel.ingest(
                result
            )

            st.session_state.packets_processed += 1

        # Process the second pipeline for either:
        # Team vs Team OR Driver vs Driver.
        if compare_mode:

            if (
                comparison_type == "Team vs Team"
                and team_b
            ):
                feed_b.process_one_packet()

            elif (
                comparison_type == "Driver vs Driver"
                and driver_b_arg
            ):
                feed_b.process_one_packet()

        progress.progress(
            (i + 1) / n_packets,
            text=(
                f"Processing packet "
                f"{i + 1}/{n_packets}..."
            ),
        )

    progress.empty()

    stats = feed.get_stats()

    elapsed = (
        time.time()
        - st.session_state.start_time
        if st.session_state.start_time
        else 0
    )

    throughput = round(
        stats['total'] / elapsed
        if elapsed > 0
        else 0,
        1,
    )

    # ── Top metrics ───────────────────────────────────────────────
    m1, m2, m3, m4, m5, m6 = st.columns(6)

    with m1:
        st.metric(
            "📦 Packets",
            stats['total'],
        )

    with m2:
        st.metric(
            "✅ Accepted",
            stats['accepted'],
            delta=f"{stats['accept_rate']:.1%}",
            help="Passed all cryptographic checks.",
        )

    with m3:
        st.metric(
            "🚨 Rejected",
            stats['rejected'],
            delta_color="inverse",
            help="Blocked due to tampering or replay.",
        )

    with m4:
        st.metric(
            "⚠️ Flagged",
            stats['flagged'],
            help="Accepted but statistically unusual.",
        )

    with m5:
        st.metric(
            "🔑 Key Rotations",
            stats['key_rotations'],
        )

    with m6:
        st.metric(
            "⚡ pkt/s",
            f"{throughput:.0f}",
            help=(
                "Packets per second through "
                "full pipeline."
            ),
        )

    st.divider()

    # ── Comparison view ───────────────────────────────────────────
    if compare_mode:

        comparison_is_valid = (
            (
                comparison_type == "Team vs Team"
                and team_b
            )
            or
            (
                comparison_type == "Driver vs Driver"
                and driver_b_arg
            )
        )

        if comparison_is_valid:

            col_a, col_b = st.columns(2)

            # ── A ────────────────────────────────────────────────
            with col_a:

                if comparison_type == "Driver vs Driver":
                    label_a = (
                        f"{TEAM_CONFIG[team]['name']} "
                        f"— {driver_arg}"
                    )
                else:
                    label_a = (
                        TEAM_CONFIG[team]['name']
                    )

                render_telemetry_column(
                    feed,
                    team,
                    label_a,
                )

            # ── B ────────────────────────────────────────────────
            with col_b:

                if comparison_type == "Driver vs Driver":

                    label_b = (
                        f"{TEAM_CONFIG[team]['name']} "
                        f"— {driver_b_arg}"
                    )

                    render_telemetry_column(
                        feed_b,
                        team,
                        label_b,
                    )

                else:

                    label_b = (
                        TEAM_CONFIG[team_b]['name']
                    )

                    render_telemetry_column(
                        feed_b,
                        team_b,
                        label_b,
                    )

            st.divider()

    # ── Normal single-pipeline view ───────────────────────────────
    left, middle, right = st.columns(
        [2, 2, 2]
    )

    with left:

        if not compare_mode:

            render_telemetry_column(
                feed,
                team,
                TEAM_CONFIG[team]['name'],
            )

    # ── Cryptographic pipeline ────────────────────────────────────
    with middle:

        st.markdown(
            '<div class="pipeline-header">'
            '🔐 Cryptographic Pipeline</div>',
            unsafe_allow_html=True,
        )

        crypto = feed.get_crypto_stats()

        st.markdown(
            "**Car → Relay (ECDH Leg A)**"
        )

        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: '
            f'`{crypto["car_key"][:16]}...`',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'Packets encrypted: '
            f'**{crypto["encrypted"]}**'
        )

        st.markdown(
            f'Key age: '
            f'**{crypto["key_age_s"]:.0f}s** '
            f'/ 300s rotation window'
        )

        st.progress(
            min(
                crypto["key_age_s"] / 300,
                1.0,
            ),
            text="Key rotation progress",
        )

        st.markdown("---")

        st.markdown(
            "**Relay → Validator (ECDH Leg B)**"
        )

        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: '
            f'`{crypto["val_key"][:16]}...`',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'Packets re-encrypted: '
            f'**{crypto["reencrypted"]}**'
        )

        st.markdown("---")

        st.markdown(
            "**Authentication**"
        )

        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Ed25519 signatures: '
            f'**{crypto["signatures"]}** verified',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'ZKP commitments: '
            f'**{crypto["zkp_verified"]}** verified',
            unsafe_allow_html=True,
        )

    # ── Threat detection ──────────────────────────────────────────
    with right:

        st.markdown(
            '<div class="pipeline-header">'
            '🚨 Threat Detection</div>',
            unsafe_allow_html=True,
        )

        threat_stats = (
            threat_panel.get_stats()
        )

        t1, t2, t3 = st.columns(3)

        with t1:
            st.metric(
                "Replays",
                threat_stats['replays'],
            )

        with t2:
            st.metric(
                "Tampers",
                threat_stats['tampers'],
            )

        with t3:
            st.metric(
                "IAM",
                threat_stats['iam_blocks'],
            )

        recent_threats = (
            threat_panel.get_recent(
                limit=8
            )
        )

        if recent_threats:

            for threat in recent_threats:

                severity = threat.get(
                    'severity',
                    'WARN',
                )

                icon = (
                    "🔴"
                    if severity == "CRITICAL"
                    else "🟡"
                )

                st.markdown(
                    f'<div class="threat-alert">'
                    f'{icon} '
                    f'<b>{threat["type"]}</b> — '
                    f'{threat["message"]}'
                    f'</div>',
                    unsafe_allow_html=True,
                )

        else:

            st.markdown(
                '<div class="threat-alert">'
                '🟢 No threats detected'
                '</div>',
                unsafe_allow_html=True,
            )

    st.divider()

    # ── Audit + anomaly ───────────────────────────────────────────
    audit_col, anomaly_col = st.columns(
        [3, 2]
    )

    with audit_col:

        st.markdown(
            "#### 📋 Validator Audit Log"
        )

        audit_events = (
            feed.get_audit_events(
                limit=10
            )
        )

        if audit_events:

            for evt in reversed(
                audit_events
            ):

                decision = evt.get(
                    'decision',
                    'ACCEPT',
                )

                seq = evt.get(
                    'sequence_no',
                    0,
                )

                reason = evt.get(
                    'reason',
                    '',
                )

                ts = evt.get(
                    'timestamp',
                    '',
                )[:19]

                icon = {
                    'ACCEPT': '🟢',
                    'REJECT': '🔴',
                    'FLAG': '🟡',
                }.get(
                    decision,
                    '🟢',
                )

                st.markdown(
                    f"{icon} `{ts}` · "
                    f"**{decision}** · "
                    f"seq={seq:04d} · "
                    f"*{reason}*"
                )

        else:
            st.info(
                "No audit events yet"
            )

    with anomaly_col:

        st.markdown(
            "#### 📊 Anomaly Statistics"
        )

        anomaly = (
            feed.get_anomaly_stats()
        )

        st.metric(
            "Packets checked",
            anomaly['checked'],
        )

        st.metric(
            "Anomalies flagged",
            anomaly['flagged'],
        )

        st.metric(
            "Anomalies rejected",
            anomaly['rejected'],
        )

        if anomaly['checked'] > 0:

            flag_rate = (
                anomaly['flagged']
                / anomaly['checked']
            )

            st.progress(
                flag_rate,
                text=(
                    f"Flag rate: "
                    f"{flag_rate:.1%}"
                ),
            )

    st.divider()

    # ── Save prompt ───────────────────────────────────────────────
    st.markdown(
        "#### 💾 Save This Run?"
    )

    save_col, skip_col, label_col = st.columns(
        [1, 1, 3]
    )

    with save_col:

        save_btn = st.button(
            "⭐ Save Run",
            use_container_width=True,
            type="primary",
        )

    with skip_col:

        st.button(
            "Skip",
            use_container_width=True,
        )

    with label_col:

        if comparison_type == "Driver vs Driver":
            default_placeholder = (
                f"{driver_arg or 'Driver A'} "
                f"vs {driver_b_arg or 'Driver B'} "
                f"{race} — comparison"
            )

        elif (
            comparison_type == "Team vs Team"
            and team_b
        ):
            default_placeholder = (
                f"{TEAM_CONFIG[team]['name']} "
                f"vs "
                f"{TEAM_CONFIG[team_b]['name']} "
                f"{race} — comparison"
            )

        else:
            default_placeholder = (
                f"e.g. "
                f"{driver_arg or 'All'} "
                f"Lap {lap_arg or 'All'} "
                f"{race} — attack demo"
            )

        run_label = st.text_input(
            "Label",
            placeholder=default_placeholder,
            label_visibility="collapsed",
        )

    if save_btn:

        if comparison_type == "Driver vs Driver":

            default_label = (
                f"{TEAM_CONFIG[team]['name']} · "
                f"{driver_arg or 'Driver A'} vs "
                f"{driver_b_arg or 'Driver B'} · "
                f"{race}"
            )

        elif (
            comparison_type == "Team vs Team"
            and team_b
        ):

            default_label = (
                f"{TEAM_CONFIG[team]['name']} vs "
                f"{TEAM_CONFIG[team_b]['name']} · "
                f"{race}"
            )

        else:

            default_label = (
                f"{TEAM_CONFIG[team]['name']} · "
                f"{race} · "
                f"{driver_arg or 'All drivers'} · "
                f"Lap {lap_arg or 'All'}"
            )

        record = {
            'label': (
                run_label
                or default_label
            ),

            'timestamp':
                datetime.now(
                    timezone.utc
                ).strftime(
                    '%H:%M:%S UTC'
                ),

            'team':
                TEAM_CONFIG[team]['name'],

            'team_b': (
                TEAM_CONFIG[team_b]['name']
                if (
                    compare_mode
                    and comparison_type
                    == "Team vs Team"
                    and team_b
                )
                else None
            ),

            'comparison_type':
                comparison_type
                if compare_mode
                else None,

            'race':
                race,

            'session':
                session,

            'driver':
                driver_arg
                or 'All',

            'driver_b':
                (
                    driver_b_arg
                    if (
                        compare_mode
                        and comparison_type
                        == "Driver vs Driver"
                    )
                    else (
                        selected_driver_b
                        if (
                            compare_mode
                            and comparison_type
                            == "Team vs Team"
                            and selected_driver_b
                            != 'All drivers'
                        )
                        else None
                    )
                ),

            'lap':
                str(lap_arg)
                if lap_arg
                else 'All',

            'packets':
                stats['total'],

            'accepted':
                stats['accepted'],

            'rejected':
                stats['rejected'],

            'flagged':
                stats['flagged'],

            'accept_rate':
                f"{stats['accept_rate']:.1%}",

            'throughput':
                f"{throughput:.0f} pkt/s",

            'chart_history':
                feed.get_chart_history(),

            'threat_stats':
                threat_panel.get_stats(),

            'audit_events':
                feed.get_audit_events(
                    limit=50
                ),
        }

        st.session_state.run_history.append(
            record
        )

        if len(
            st.session_state.run_history
        ) > 20:

            st.session_state.run_history.pop(
                0
            )

        st.success(
            f"✅ Saved: {record['label']}"
        )

    st.divider()

    col_refresh, col_info = st.columns(
        [1, 4]
    )

    with col_refresh:

        if st.button(
            "🔄 Run More Packets"
        ):
            st.rerun()

    with col_info:

        start_ts = (
            st.session_state.start_time
        )

        if start_ts:
            session_started = datetime.fromtimestamp(
                start_ts,
                tz=timezone.utc,
            ).strftime('%H:%M:%S UTC')
        else:
            session_started = '—'

        st.caption(
            f"Session started: {session_started}"
            f" · Total processed: "
            f"{st.session_state.packets_processed}"
        )