import os
import sys
import time
import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timezone
from PIL import Image

@st.cache_data
def peek_drivers_and_laps(team: str, race: str, session: str):
    """
    Quickly read Driver and LapNumber columns only from
    the raw CSV to populate selectbox options without
    loading the full 1.8M row dataset.
    """
    import pandas as pd
    raw_dir = os.path.join(ROOT, 'data', 'raw')
    # Find matching CSV file
    target = f"{team}_{race}_{session}.csv"
    path   = os.path.join(raw_dir, target)
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
    
# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)
CAR_SRC = os.path.join(ROOT, 'car-producer',  'src')
REL_SRC = os.path.join(ROOT, 'relay-node',    'src')
VAL_SRC = os.path.join(ROOT, 'validator-node', 'src')
IAM_SRC = os.path.join(ROOT, 'iam-module',    'src')
DASH    = os.path.join(ROOT, 'dashboard')

for path in [CAR_SRC, REL_SRC, VAL_SRC, IAM_SRC, DASH]:
    if path not in sys.path:
        sys.path.insert(0, path)

from components.telemetry_feed import TelemetryFeed
from components.threat_panel   import ThreatPanel

# ── Team configuration ────────────────────────────────────────────
TEAM_CONFIG = {
    "mercedes": {"name": "Mercedes AMG",     "color": "#00d2be", "emoji": "🩵"},
    "redbull":  {"name": "Red Bull Racing",  "color": "#3671c6", "emoji": "🔵"},
    "ferrari":  {"name": "Scuderia Ferrari", "color": "#e8002d", "emoji": "🔴"},
    "mclaren":  {"name": "McLaren Racing",   "color": "#ff8000", "emoji": "🟠"},
    "williams": {"name": "Williams Racing",  "color": "#64c4ff", "emoji": "🩶"},
}

TEAMS_WITHOUT_DATA = set()

# ── Page config ───────────────────────────────────────────────────
try:
    favicon = Image.open(
        os.path.join(ROOT, 'dashboard', 'assets', 'favicon.png')
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
st.markdown("""
<style>
    .main { background-color: #0a0a0a; }
    .accept-badge {
        background-color: #00c851; color: white;
        padding: 2px 8px; border-radius: 4px;
        font-size: 0.75rem; font-weight: bold;
    }
    .reject-badge {
        background-color: #e10600; color: white;
        padding: 2px 8px; border-radius: 4px;
        font-size: 0.75rem; font-weight: bold;
    }
    .flag-badge {
        background-color: #ff8800; color: white;
        padding: 2px 8px; border-radius: 4px;
        font-size: 0.75rem; font-weight: bold;
    }
    .threat-alert {
        background-color: #1a0000;
        border-left: 4px solid #e10600;
        padding: 0.5rem 1rem; margin: 0.25rem 0;
        border-radius: 0 4px 4px 0; font-size: 0.85rem;
    }
    .crypto-ok { color: #00c851; font-weight: bold; }
    .pipeline-header {
        font-size: 1.1rem; font-weight: bold; color: #e10600;
        border-bottom: 1px solid #333;
        padding-bottom: 0.25rem; margin-bottom: 0.5rem;
    }
    div[data-testid="metric-container"] {
        background: #1a1a2e; border: 1px solid #333;
        border-radius: 6px; padding: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

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

init_session_state()
feed         = st.session_state.feed
feed_b       = st.session_state.feed_b
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
    status_color    = "🟢" if pipeline_status == "ACTIVE" else "🔴"
    st.markdown(f"### {status_color} Pipeline: {pipeline_status}")
    st.markdown(
        f"*{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}*"
    )

st.divider()

with st.expander("ℹ️ What do these numbers mean?"):
    st.markdown("""
    - **Speed** — car speed in km/h at this exact moment on track
    - **RPM** — engine revolutions per minute; how hard the engine is working
    - **Throttle %** — how much the driver is pressing the accelerator (100% = flat out)
    - **Gear** — current gearbox position (1 = lowest/slowest, 8 = highest/fastest)
    - **seq=XXXX** — packet sequence number; proves no data was skipped or replayed
    - **ACCEPT** — FIA validator confirmed this packet is authentic and unmodified
    - **REJECT** — packet blocked; tampered, replayed, or forged
    - **FLAG** — packet accepted but contains a statistically unusual sensor value
    - **Session key** — a one-time cryptographic secret used to encrypt the data stream
    - **ECDH** — how both sides agree on that secret without ever sending it directly
    """)

# ── Sidebar ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Pipeline Controls")

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
            f"downloaded. Using Mercedes telemetry values — "
            f"full cryptographic pipeline still active.",
        )

    compare_mode = st.checkbox(
        "⚖️ Compare two teams side-by-side",
        help="Run two independent encrypted pipelines simultaneously. "
             "Each team gets its own ECDH session keys, proving "
             "complete cryptographic isolation between constructors.",
    )

    team_b = None
    if compare_mode:
        team_b = st.selectbox(
            "Second Constructor",
            [t for t in TEAM_CONFIG.keys() if t != team],
            format_func=lambda x: (
                f"{TEAM_CONFIG[x]['emoji']} {TEAM_CONFIG[x]['name']}"
            ),
            key='team_b_select',
        )

    race = st.selectbox(
        "Circuit",
        [
            "Bahrain", "Saudi Arabia", "Australia",
            "Japan", "Monaco", "Canada", "Singapore",
            "Monza", "Silverstone", "Netherlands",
            "Baku", "Qatar", "Abu Dhabi",
        ],
        help="Which Grand Prix circuit's real telemetry to stream.",
    )

    session = st.selectbox(
        "Session",
        ["R", "Q", "S"],
        format_func=lambda x: {
            "R": "Race", "Q": "Qualifying", "S": "Sprint"
        }[x],
        help="Race = full grand prix, Qualifying = single-lap "
             "pace runs, Sprint = short-format Saturday race.",
    )

    # ── Driver + lap selection ────────────────────────────────────
    available_drivers, available_laps = peek_drivers_and_laps(
        team, race, session
    )

    if available_drivers:
        driver_options  = ['All drivers'] + available_drivers
        selected_driver = st.selectbox(
            "Driver",
            driver_options,
            format_func=lambda x: (
                x if x == 'All drivers'
                else f"🪖 {x}"
            ),
            help="Stream data from one specific driver only. "
                 "Useful for lap-by-lap comparison.",
        )
    else:
        selected_driver = 'All drivers'
        st.caption("Driver data not available for this selection.")

    if available_laps:
        lap_options  = ['All laps'] + [str(l) for l in available_laps]
        selected_lap = st.selectbox(
            "Lap",
            lap_options,
            format_func=lambda x: (
                x if x == 'All laps'
                else f"Lap {x}"
            ),
            help="Stream data from one specific lap only. "
                 "Combine with driver for a single-lap trace.",
        )
    else:
        selected_lap = 'All laps'
        st.caption("Lap data not available for this selection.")

    driver_arg = (
        None if selected_driver == 'All drivers'
        else selected_driver
    )
    lap_arg = (
        None if selected_lap == 'All laps'
        else int(selected_lap)
    )

    n_packets = st.slider(
        "Packets to simulate",
        min_value=10,
        max_value=200,
        value=50,
        step=10,
        help="Each packet = one telemetry sample at one instant in "
             "time. 50 packets ≈ a few seconds of real on-track data.",
    )

    st.divider()

    col_start, col_stop = st.columns(2)
    with col_start:
        start_btn = st.button(
            "▶ Start", use_container_width=True, type="primary",
        )
    with col_stop:
        stop_btn = st.button(
            "⏹ Reset", use_container_width=True,
        )
        if start_btn:
            with st.spinner("Initialising pipeline..."):
                feed.initialise(
                    team=team, race=race, session=session,
                    driver=driver_arg, lap=lap_arg,
                )
            
            if compare_mode and team_b:
                feed_b.initialise(
                    team=team_b, race=race, session=session
                )
            threat_panel.reset()
            st.session_state.running    = True
            st.session_state.start_time = time.time()
        st.success("Pipeline ready ✅")

    if stop_btn:
        feed.reset()
        feed_b.reset()
        threat_panel.reset()
        st.session_state.running           = False
        st.session_state.packets_processed = 0
        st.session_state.start_time        = None
        st.info("Pipeline reset")

    st.divider()
    st.markdown("### 🎯 Attack Simulation")
    attack_type = st.selectbox(
        "Choose attack",
        ['tamper', 'replay', 'forge'],
        format_func=lambda x: {
            'tamper': '🔓 Tamper Ciphertext',
            'replay': '🔁 Replay Old Packet',
            'forge':  '✍️ Forge Signature',
        }[x],
        help="Inject one malicious packet into the live pipeline "
             "and watch the security layer catch it in real time.",
    )
    if st.button("💀 Inject Attack", use_container_width=True):
        if st.session_state.running:
            attack_result = feed.inject_attack(attack_type)
            if attack_result:
                threat_panel.ingest(attack_result)
                if attack_result['decision'] == 'REJECT':
                    st.error(
                        f"✅ Attack BLOCKED — {attack_type} → "
                        f"{attack_result['reason']}"
                    )
                else:
                    st.warning(
                        f"⚠️ Attack slipped through — {attack_type} "
                        f"→ {attack_result['decision']}"
                    )
            else:
                st.info(
                    "No prior packet available to replay. "
                    "Run at least one packet batch first."
                )
        else:
            st.warning("Start the pipeline first.")

    st.divider()
    st.markdown("### 🔐 Crypto Stack")
    st.markdown("- X25519 ECDH")
    st.markdown("- ChaCha20-Poly1305")
    st.markdown("- Ed25519 Signatures")
    st.markdown("- HKDF-SHA256")
    st.markdown("- ZKP Hash Commitments")

    st.divider()
    st.markdown("### 📊 Data Source")
    st.markdown(f"- **Team:** {TEAM_CONFIG[team]['name']}")
    st.markdown(f"- **Circuit:** {race}")
    st.markdown(f"- **Session:** {session}")
    if driver_arg:
        st.markdown(f"- **Driver:** {driver_arg}")
    if lap_arg:
        st.markdown(f"- **Lap:** {lap_arg}")
    rows = feed.get_data_rows()
    if rows > 0:
        st.markdown(f"- **Rows loaded:** {rows:,}")


def render_telemetry_column(feed_obj, team_key, label):
    """Render one team's telemetry column including
    live stream, dual-axis chart, and crypto summary."""

    team_color = TEAM_CONFIG[team_key]['color']

    st.markdown(
        f'<div class="pipeline-header">'
        f'🚗 {label} — Live Telemetry</div>',
        unsafe_allow_html=True,
    )

    recent = feed_obj.get_recent_packets(limit=15)
    if recent:
        for pkt in reversed(recent[-15:]):
            payload   = pkt.get('payload_json', {})
            seq       = pkt.get('sequence_no', 0)
            driver    = payload.get('driver', 'UNK')
            lap       = payload.get('lap', 0)
            track_pos = payload.get('track_position', '')
            decision  = pkt.get('decision', 'ACCEPT')

            badge_map = {
                'ACCEPT': '<span class="accept-badge">ACCEPT</span>',
                'REJECT': '<span class="reject-badge">REJECT</span>',
                'FLAG':   '<span class="flag-badge">FLAG</span>',
            }
            badge    = badge_map.get(decision, badge_map['ACCEPT'])
            speed    = payload.get('Speed',    0)
            rpm      = payload.get('RPM',      0)
            throttle = payload.get('Throttle', 0)
            gear     = payload.get('nGear',    0)

            # Build position label — only show if non-empty
            pos_label = f" · **{track_pos}**" if track_pos else ""

            st.markdown(
                f"{badge} `seq={seq:04d}` "
                f"**[{driver}]** Lap **{lap}**{pos_label} · "
                f"**{speed:.0f}** km/h · "
                f"**{rpm:.0f}** RPM · "
                f"**{throttle:.0f}**% throttle · "
                f"gear **{gear}**",
                unsafe_allow_html=True,
            )
    else:
        st.info("No packets yet")

    # ── Dual-axis telemetry trace chart ───────────────────────────
    history = feed_obj.get_chart_history()
    if history['seq']:
        fig = go.Figure()

        # Speed — team colour, left axis
        fig.add_trace(go.Scatter(
            x=history['seq'],
            y=history['speed'],
            name='Speed (km/h)',
            line=dict(color='#e10600', width=3),
            yaxis='y1',
        ))

        # RPM — electric blue, right axis (raw values, own scale)
        fig.add_trace(go.Scatter(
            x=history['seq'],
            y=history['rpm'],
            name='RPM',
            line=dict(color='#00d4ff', width=2),
            yaxis='y2',
        ))

        fig.update_layout(
            height=220,
            margin=dict(l=10, r=60, t=30, b=10),
            plot_bgcolor='#0a0a0a',
            paper_bgcolor='#0a0a0a',
            font=dict(color='#ffffff', size=9),
            xaxis=dict(
                title='Packet sequence',
                gridcolor='#222',
            ),
            yaxis=dict(
                title='Speed (km/h)',
                title_font=dict(color='#e10600'),
                tickfont=dict(color='#e10600'),
                gridcolor='#222',
                range=[0, 380],
            ),
            yaxis2=dict(
                title='RPM',
                title_font=dict(color='#00d4ff'),
                tickfont=dict(color='#00d4ff'),
                overlaying='y',
                side='right',
                showgrid=False,
                range=[0, 16000],
            ),
            legend=dict(orientation='h', y=1.2),
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Crypto summary line ───────────────────────────────────────
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

else:
    progress = st.progress(0, text="Running pipeline...")

    for i in range(n_packets):
        result = feed.process_one_packet()
        if result:
            threat_panel.ingest(result)
            st.session_state.packets_processed += 1
        if compare_mode and team_b:
            feed_b.process_one_packet()
        progress.progress(
            (i + 1) / n_packets,
            text=f"Processing packet {i+1}/{n_packets}..."
        )

    progress.empty()

    stats   = feed.get_stats()
    elapsed = (
        time.time() - st.session_state.start_time
        if st.session_state.start_time else 0
    )
    throughput = round(
        stats['total'] / elapsed if elapsed > 0 else 0, 1
    )

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    with m1:
        st.metric("📦 Packets", stats['total'])
    with m2:
        st.metric(
            "✅ Accepted", stats['accepted'],
            delta=f"{stats['accept_rate']:.1%}",
            help="Packets that passed all cryptographic checks "
                 "— signature, sequence, and ZKP commitment.",
        )
    with m3:
        st.metric(
            "🚨 Rejected", stats['rejected'],
            delta_color="inverse",
            help="Packets blocked due to tampering, "
                 "replay, or forged signatures.",
        )
    with m4:
        st.metric(
            "⚠️ Flagged", stats['flagged'],
            help="Accepted packets with statistically "
                 "unusual sensor values.",
        )
    with m5:
        st.metric("🔑 Key Rotations", stats['key_rotations'])
    with m6:
        st.metric(
            "⚡ pkt/s", f"{throughput:.0f}",
            help="Packets processed per second through "
                 "the full cryptographic pipeline.",
        )

    st.divider()

    if compare_mode and team_b:
        col_a, col_b = st.columns(2)
        with col_a:
            render_telemetry_column(
                feed, team, TEAM_CONFIG[team]['name']
            )
        with col_b:
            render_telemetry_column(
                feed_b, team_b, TEAM_CONFIG[team_b]['name']
            )
        st.divider()

    left, middle, right = st.columns([2, 2, 2])

    with left:
        if not compare_mode:
            render_telemetry_column(
                feed, team, TEAM_CONFIG[team]['name']
            )

    with middle:
        st.markdown(
            '<div class="pipeline-header">'
            '🔐 Cryptographic Pipeline</div>',
            unsafe_allow_html=True,
        )
        crypto = feed.get_crypto_stats()
        st.markdown("**Car → Relay (ECDH Leg A)**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: `{crypto["car_key"][:16]}...`',
            unsafe_allow_html=True,
        )
        st.markdown(f'Packets encrypted: **{crypto["encrypted"]}**')
        st.markdown(
            f'Key age: **{crypto["key_age_s"]:.0f}s** '
            f'/ 300s rotation window'
        )
        st.progress(
            min(crypto["key_age_s"] / 300, 1.0),
            text="Key rotation progress"
        )
        st.markdown("---")
        st.markdown("**Relay → Validator (ECDH Leg B)**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: `{crypto["val_key"][:16]}...`',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'Packets re-encrypted: **{crypto["reencrypted"]}**'
        )
        st.markdown("---")
        st.markdown("**Authentication**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Ed25519 signatures: **{crypto["signatures"]}** verified',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'ZKP commitments: **{crypto["zkp_verified"]}** verified',
            unsafe_allow_html=True,
        )

    with right:
        st.markdown(
            '<div class="pipeline-header">'
            '🚨 Threat Detection</div>',
            unsafe_allow_html=True,
        )
        threat_stats = threat_panel.get_stats()
        t1, t2, t3 = st.columns(3)
        with t1:
            st.metric("Replays", threat_stats['replays'])
        with t2:
            st.metric("Tampers", threat_stats['tampers'])
        with t3:
            st.metric("IAM",     threat_stats['iam_blocks'])

        recent_threats = threat_panel.get_recent(limit=8)
        if recent_threats:
            for threat in recent_threats:
                severity = threat.get('severity', 'WARN')
                icon     = "🔴" if severity == "CRITICAL" else "🟡"
                st.markdown(
                    f'<div class="threat-alert">'
                    f'{icon} <b>{threat["type"]}</b> — '
                    f'{threat["message"]}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div class="threat-alert">'
                '🟢 No threats detected</div>',
                unsafe_allow_html=True,
            )

    st.divider()

    audit_col, anomaly_col = st.columns([3, 2])

    with audit_col:
        st.markdown("#### 📋 Validator Audit Log")
        audit_events = feed.get_audit_events(limit=10)
        if audit_events:
            for evt in reversed(audit_events):
                decision = evt.get('decision', 'ACCEPT')
                seq      = evt.get('sequence_no', 0)
                reason   = evt.get('reason', '')
                ts       = evt.get('timestamp', '')[:19]
                icon = {
                    'ACCEPT': '🟢', 'REJECT': '🔴', 'FLAG': '🟡',
                }.get(decision, '🟢')
                st.markdown(
                    f"{icon} `{ts}` · **{decision}** · "
                    f"seq={seq:04d} · *{reason}*"
                )
        else:
            st.info("No audit events yet")

    with anomaly_col:
        st.markdown("#### 📊 Anomaly Statistics")
        anomaly = feed.get_anomaly_stats()
        st.metric("Packets checked",    anomaly['checked'])
        st.metric("Anomalies flagged",  anomaly['flagged'])
        st.metric("Anomalies rejected", anomaly['rejected'])
        if anomaly['checked'] > 0:
            flag_rate = anomaly['flagged'] / anomaly['checked']
            st.progress(
                flag_rate, text=f"Flag rate: {flag_rate:.1%}"
            )

    st.divider()
    col_refresh, col_info = st.columns([1, 4])
    with col_refresh:
        if st.button("🔄 Run More Packets"):
            st.rerun()
    with col_info:
        start_ts = st.session_state.start_time
        st.caption(
            f"Session started: "
            f"{datetime.fromtimestamp(start_ts, tz=timezone.utc).strftime('%H:%M:%S UTC') if start_ts else '—'}"
            f" · Total processed: {st.session_state.packets_processed}"
        )