import os
import sys
import time
import threading
import streamlit as st
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
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

"""
app.py — PitCrypt-F1 Security Dashboard

Real-time monitoring dashboard for the PitCrypt-F1
cryptographic telemetry pipeline.

Displays:
    - Live telemetry stream from Mercedes AMG / Red Bull
    - Cryptographic pipeline health (ECDH, AEAD, Ed25519)
    - Threat detection events (replay, tamper, IAM breach)
    - Anomaly filter alerts
    - Validator audit decisions
    - Key rotation events
    - IAM access control decisions

Run with:
    streamlit run dashboard/app.py
"""

# ── Page config ───────────────────────────────────────────────────
from PIL import Image

favicon = Image.open(
    os.path.join(ROOT, 'dashboard', 'assets', 'favicon.png')
)

st.set_page_config(
    page_title="PitCrypt-F1 Security Dashboard",
    page_icon=favicon,
    layout="wide",
)

# ── Custom CSS ────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark racing theme */
    .main { background-color: #0a0a0a; }

    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #e10600;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
    }

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

    div[data-testid="metric-container"] {
        background: #1a1a2e;
        border: 1px solid #333;
        border-radius: 6px;
        padding: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


# ── Session state initialisation ─────────────────────────────────
def init_session_state():
    if 'feed' not in st.session_state:
        st.session_state.feed = TelemetryFeed()
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
threat_panel = st.session_state.threat_panel


# ── Header ────────────────────────────────────────────────────────
col_logo, col_title, col_status = st.columns([1, 4, 2])

with col_logo:
    st.markdown("# 🏎️")

with col_title:
    st.markdown("## PitCrypt-F1 Security Dashboard")
    st.markdown(
        "*Zero-Trust Cryptographic Telemetry Pipeline*"
    )

with col_status:
    pipeline_status = feed.get_pipeline_status()
    status_color = (
        "🟢" if pipeline_status == "ACTIVE"
        else "🔴"
    )
    st.markdown(f"### {status_color} Pipeline: {pipeline_status}")
    st.markdown(
        f"*{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}*"
    )


st.divider()


# ── Sidebar controls ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Pipeline Controls")

    team = st.selectbox(
        "Constructor",
        ["mercedes", "redbull"],
        format_func=lambda x: (
            "🔵 Mercedes AMG" if x == "mercedes"
            else "🔴 Red Bull Racing"
        ),
    )

    race = st.selectbox(
        "Circuit",
        [
            "Bahrain", "Saudi Arabia", "Australia",
            "Japan", "Monaco", "Canada", "Singapore",
            "Monza", "Silverstone", "Netherlands",
            "Baku", "Qatar", "Abu Dhabi",
        ],
    )

    session = st.selectbox(
        "Session",
        ["R", "Q", "S"],
        format_func=lambda x: {
            "R": "Race", "Q": "Qualifying", "S": "Sprint"
        }[x],
    )

    n_packets = st.slider(
        "Packets to simulate",
        min_value=10,
        max_value=200,
        value=50,
        step=10,
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

    if start_btn:
        with st.spinner("Initialising pipeline..."):
            feed.initialise(
                team=team, race=race, session=session
            )
            threat_panel.reset()
            st.session_state.running    = True
            st.session_state.start_time = time.time()
        st.success("Pipeline ready ✅")

    if stop_btn:
        feed.reset()
        threat_panel.reset()
        st.session_state.running           = False
        st.session_state.packets_processed = 0
        st.session_state.start_time        = None
        st.info("Pipeline reset")

    st.divider()
    st.markdown("### 🔐 Crypto Stack")
    st.markdown("- X25519 ECDH")
    st.markdown("- ChaCha20-Poly1305")
    st.markdown("- Ed25519 Signatures")
    st.markdown("- HKDF-SHA256")
    st.markdown("- ZKP Hash Commitments")

    st.divider()
    st.markdown("### 📊 Data Source")
    st.markdown(f"- **Team:** {team.title()}")
    st.markdown(f"- **Circuit:** {race}")
    st.markdown(f"- **Session:** {session}")
    rows = feed.get_data_rows()
    if rows > 0:
        st.markdown(f"- **Rows loaded:** {rows:,}")


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
    # ── Run simulation ────────────────────────────────────────────
    progress = st.progress(0, text="Running pipeline...")
    results  = []

    for i in range(n_packets):
        result = feed.process_one_packet()
        if result:
            results.append(result)
            threat_panel.ingest(result)
            st.session_state.packets_processed += 1

        progress.progress(
            (i + 1) / n_packets,
            text=f"Processing packet {i+1}/{n_packets}..."
        )

    progress.empty()

    # ── Top metrics row ───────────────────────────────────────────
    stats = feed.get_stats()
    elapsed = (
        time.time() - st.session_state.start_time
        if st.session_state.start_time else 0
    )
    throughput = round(
        stats['total'] / elapsed if elapsed > 0 else 0, 1
    )

    m1, m2, m3, m4, m5, m6 = st.columns(6)

    with m1:
        st.metric(
            "📦 Packets",
            stats['total'],
            delta=None,
        )
    with m2:
        st.metric(
            "✅ Accepted",
            stats['accepted'],
            delta=f"{stats['accept_rate']:.1%}",
        )
    with m3:
        st.metric(
            "🚨 Rejected",
            stats['rejected'],
            delta=None,
            delta_color="inverse",
        )
    with m4:
        st.metric(
            "⚠️ Flagged",
            stats['flagged'],
        )
    with m5:
        st.metric(
            "🔑 Key Rotations",
            stats['key_rotations'],
        )
    with m6:
        st.metric(
            "⚡ Throughput",
            f"{throughput} pkt/s",
        )

    st.divider()

    # ── Three column layout ───────────────────────────────────────
    left, middle, right = st.columns([2, 2, 2])

    # ── Left: Telemetry stream ────────────────────────────────────
    with left:
        st.markdown(
            '<div class="pipeline-header">'
            '🚗 Live Telemetry Stream</div>',
            unsafe_allow_html=True,
        )

        recent = feed.get_recent_packets(limit=15)
        if recent:
            for pkt in reversed(recent[-15:]):
                payload = pkt.get('payload_json', {})
                seq     = pkt.get('sequence_no', 0)
                team_   = pkt.get('team', '')
                decision = pkt.get('decision', 'ACCEPT')

                badge_map = {
                    'ACCEPT': '<span class="accept-badge">ACCEPT</span>',
                    'REJECT': '<span class="reject-badge">REJECT</span>',
                    'FLAG':   '<span class="flag-badge">FLAG</span>',
                }
                badge = badge_map.get(
                    decision,
                    '<span class="accept-badge">ACCEPT</span>'
                )

                speed    = payload.get('Speed',    0)
                rpm      = payload.get('RPM',      0)
                throttle = payload.get('Throttle', 0)
                gear     = payload.get('nGear',    0)

                st.markdown(
                    f"{badge} "
                    f"`seq={seq:04d}` "
                    f"**{speed:.0f}** km/h · "
                    f"**{rpm:.0f}** RPM · "
                    f"**{throttle:.0f}**% throttle · "
                    f"gear **{gear}**",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No packets yet")

    # ── Middle: Crypto pipeline health ───────────────────────────
    with middle:
        st.markdown(
            '<div class="pipeline-header">'
            '🔐 Cryptographic Pipeline</div>',
            unsafe_allow_html=True,
        )

        crypto_stats = feed.get_crypto_stats()

        st.markdown("**Car → Relay (ECDH Leg A)**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: `{crypto_stats["car_key"][:16]}...`',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'Packets encrypted: '
            f'**{crypto_stats["encrypted"]}**'
        )
        st.markdown(
            f'Key age: **{crypto_stats["key_age_s"]:.0f}s** '
            f'/ 300s rotation window'
        )

        st.progress(
            min(crypto_stats["key_age_s"] / 300, 1.0),
            text="Key rotation progress"
        )

        st.markdown("---")
        st.markdown("**Relay → Validator (ECDH Leg B)**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Session key: `{crypto_stats["val_key"][:16]}...`',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'Packets re-encrypted: '
            f'**{crypto_stats["reencrypted"]}**'
        )

        st.markdown("---")
        st.markdown("**Authentication**")
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'Ed25519 signatures: '
            f'**{crypto_stats["signatures"]}** verified',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<span class="crypto-ok">✅</span> '
            f'ZKP commitments: '
            f'**{crypto_stats["zkp_verified"]}** verified',
            unsafe_allow_html=True,
        )

    # ── Right: Threat detection ───────────────────────────────────
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
            st.metric("IAM", threat_stats['iam_blocks'])

        recent_threats = threat_panel.get_recent(limit=12)
        if recent_threats:
            for threat in recent_threats:
                severity = threat.get('severity', 'WARN')
                icon = "🔴" if severity == "CRITICAL" else "🟡"
                st.markdown(
                    f'<div class="threat-alert">'
                    f'{icon} <b>{threat["type"]}</b> — '
                    f'{threat["message"]}'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div class="threat-alert">'
                '🟢 No threats detected</div>',
                unsafe_allow_html=True,
            )

    st.divider()

    # ── Bottom row: Audit log + anomaly stats ─────────────────────
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

                badge_map = {
                    'ACCEPT': '🟢',
                    'REJECT': '🔴',
                    'FLAG':   '🟡',
                }
                icon = badge_map.get(decision, '🟢')
                st.markdown(
                    f"{icon} `{ts}` · "
                    f"**{decision}** · "
                    f"seq={seq:04d} · "
                    f"*{reason}*"
                )
        else:
            st.info("No audit events yet")

    with anomaly_col:
        st.markdown("#### 📊 Anomaly Statistics")
        anomaly_stats = feed.get_anomaly_stats()

        st.metric(
            "Packets checked",
            anomaly_stats['checked'],
        )
        st.metric(
            "Anomalies flagged",
            anomaly_stats['flagged'],
        )
        st.metric(
            "Anomalies rejected",
            anomaly_stats['rejected'],
        )

        if anomaly_stats['checked'] > 0:
            flag_rate = (
                anomaly_stats['flagged'] /
                anomaly_stats['checked']
            )
            st.progress(
                flag_rate,
                text=f"Flag rate: {flag_rate:.1%}"
            )

    # ── Auto-refresh ──────────────────────────────────────────────
    st.divider()
    col_refresh, col_info = st.columns([1, 4])
    with col_refresh:
        if st.button("🔄 Run More Packets"):
            st.rerun()
    with col_info:
        st.caption(
            f"Session started: "
            f"{datetime.fromtimestamp(st.session_state.start_time, tz=timezone.utc).strftime('%H:%M:%S UTC') if st.session_state.start_time else '—'} · "
            f"Total processed: {st.session_state.packets_processed}"
        )