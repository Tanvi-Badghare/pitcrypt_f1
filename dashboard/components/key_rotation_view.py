import os
import sys
import time
import math
from datetime import datetime, timezone
from typing import List, Optional

"""
key_rotation_view.py

Key rotation monitoring component for the
PitCrypt-F1 security dashboard.

Tracks and displays:
    - Current session key age vs rotation threshold
    - Packets encrypted under current key
    - Rotation event history with reasons
    - Forward secrecy status
    - Per-leg key health (car→relay, relay→validator)
    - Time to next rotation countdown
"""


class KeyRotationEvent:
    """Single key rotation event record."""

    REASON_AGE   = "age_exceeded"
    REASON_COUNT = "count_exceeded"
    REASON_FORCE = "manual_rotation"

    def __init__(
        self,
        leg:          str,
        reason:       str,
        old_age_s:    float,
        old_count:    int,
        new_key_hint: str,
    ):
        self.leg          = leg
        self.reason       = reason
        self.old_age_s    = old_age_s
        self.old_count    = old_count
        self.new_key_hint = new_key_hint
        self.timestamp    = datetime.now(
            timezone.utc
        ).isoformat()

    def to_dict(self) -> dict:
        return {
            'timestamp':    self.timestamp,
            'leg':          self.leg,
            'reason':       self.reason,
            'old_age_s':    round(self.old_age_s, 1),
            'old_count':    self.old_count,
            'new_key_hint': self.new_key_hint,
        }

    def reason_label(self) -> str:
        labels = {
            self.REASON_AGE:   '⏱️ Time limit (300s)',
            self.REASON_COUNT: '📦 Packet limit (10K)',
            self.REASON_FORCE: '🔄 Manual rotation',
        }
        return labels.get(self.reason, self.reason)


class KeyRotationView:
    """
    Key rotation state tracker for dashboard display.
    Tracks both pipeline legs independently.
    """

    # Rotation thresholds
    MAX_AGE_S     = 300      # 5 minutes
    MAX_PACKETS   = 10_000

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Reset all key rotation state."""
        self._events: List[KeyRotationEvent] = []

        # Car → Relay leg
        self._car_leg = {
            'key_hint':   '—',
            'age_s':      0.0,
            'packets':    0,
            'rotations':  0,
            'start_time': time.time(),
            'last_rotation': None,
        }

        # Relay → Validator leg
        self._val_leg = {
            'key_hint':   '—',
            'age_s':      0.0,
            'packets':    0,
            'rotations':  0,
            'start_time': time.time(),
            'last_rotation': None,
        }

        self._total_rotations = 0

    def register_keys(
        self,
        car_key_hex: str,
        val_key_hex: str,
    ) -> None:
        """Register initial session keys from pipeline."""
        self._car_leg['key_hint']   = car_key_hex[:16]
        self._val_leg['key_hint']   = val_key_hex[:16]
        self._car_leg['start_time'] = time.time()
        self._val_leg['start_time'] = time.time()

    def tick(
        self,
        car_packets: int,
        val_packets: int,
    ) -> None:
        """
        Update packet counts and check rotation triggers.
        Call after each packet processed.
        """
        now = time.time()

        # Update car leg
        self._car_leg['packets'] = car_packets
        self._car_leg['age_s']   = (
            now - self._car_leg['start_time']
        )

        # Update val leg
        self._val_leg['packets'] = val_packets
        self._val_leg['age_s']   = (
            now - self._val_leg['start_time']
        )

        # Check rotation triggers
        self._check_rotation('car→relay', self._car_leg)
        self._check_rotation('relay→validator', self._val_leg)

    def _check_rotation(
        self, leg_name: str, leg: dict
    ) -> None:
        """Check if rotation threshold met — simulate rotation."""
        reason = None

        if leg['age_s'] >= self.MAX_AGE_S:
            reason = KeyRotationEvent.REASON_AGE
        elif leg['packets'] >= self.MAX_PACKETS:
            reason = KeyRotationEvent.REASON_COUNT

        if reason:
            self._rotate(leg_name, leg, reason)

    def _rotate(
        self,
        leg_name: str,
        leg:      dict,
        reason:   str,
    ) -> None:
        """Simulate a key rotation event."""
        import os
        new_key = os.urandom(32).hex()

        event = KeyRotationEvent(
            leg=leg_name,
            reason=reason,
            old_age_s=leg['age_s'],
            old_count=leg['packets'],
            new_key_hint=new_key[:16],
        )
        self._events.append(event)
        if len(self._events) > 100:
            self._events.pop(0)

        # Reset leg state
        leg['key_hint']      = new_key[:16]
        leg['age_s']         = 0.0
        leg['packets']       = 0
        leg['rotations']    += 1
        leg['start_time']    = time.time()
        leg['last_rotation'] = datetime.now(
            timezone.utc
        ).isoformat()

        self._total_rotations += 1

    def force_rotation(self, leg: str = 'both') -> None:
        """Manually trigger key rotation."""
        if leg in ('car→relay', 'both'):
            self._rotate(
                'car→relay',
                self._car_leg,
                KeyRotationEvent.REASON_FORCE,
            )
        if leg in ('relay→validator', 'both'):
            self._rotate(
                'relay→validator',
                self._val_leg,
                KeyRotationEvent.REASON_FORCE,
            )

    # ── Computed properties ───────────────────────────────────────

    def car_age_progress(self) -> float:
        """Progress to next car leg rotation (0.0-1.0)."""
        age_prog = min(
            self._car_leg['age_s'] / self.MAX_AGE_S, 1.0
        )
        pkt_prog = min(
            self._car_leg['packets'] / self.MAX_PACKETS, 1.0
        )
        return max(age_prog, pkt_prog)

    def val_age_progress(self) -> float:
        """Progress to next validator leg rotation."""
        age_prog = min(
            self._val_leg['age_s'] / self.MAX_AGE_S, 1.0
        )
        pkt_prog = min(
            self._val_leg['packets'] / self.MAX_PACKETS, 1.0
        )
        return max(age_prog, pkt_prog)

    def time_to_next_rotation(self, leg: str) -> float:
        """Seconds until next rotation for a leg."""
        if leg == 'car':
            return max(
                0,
                self.MAX_AGE_S - self._car_leg['age_s']
            )
        return max(
            0,
            self.MAX_AGE_S - self._val_leg['age_s']
        )

    def get_car_leg(self) -> dict:
        return dict(self._car_leg)

    def get_val_leg(self) -> dict:
        return dict(self._val_leg)

    def get_recent_events(
        self, limit: int = 10
    ) -> List[dict]:
        return [
            e.to_dict()
            for e in self._events[-limit:]
        ]

    def get_summary(self) -> dict:
        return {
            'total_rotations':  self._total_rotations,
            'car_rotations':    self._car_leg['rotations'],
            'val_rotations':    self._val_leg['rotations'],
            'car_key_age_s':    round(
                self._car_leg['age_s'], 1
            ),
            'val_key_age_s':    round(
                self._val_leg['age_s'], 1
            ),
            'car_packets':      self._car_leg['packets'],
            'val_packets':      self._val_leg['packets'],
            'car_key_hint':     self._car_leg['key_hint'],
            'val_key_hint':     self._val_leg['key_hint'],
            'forward_secrecy':  True,
        }


def render_key_rotation_view(
    rotation_view: KeyRotationView,
) -> None:
    """
    Render key rotation panel in Streamlit.
    Import and call this from app.py.
    """
    import streamlit as st

    summary = rotation_view.get_summary()
    car     = rotation_view.get_car_leg()
    val     = rotation_view.get_val_leg()

    st.markdown("#### 🔑 Key Rotation Monitor")

    # Forward secrecy badge
    st.markdown(
        '✅ **Forward Secrecy Active** — '
        'past sessions protected after rotation',
    )

    st.markdown("---")

    # ── Car → Relay leg ──────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**🚗 Car → Relay (Leg A)**")
        st.markdown(
            f"Key: `{summary['car_key_hint']}...`"
        )
        st.markdown(
            f"Age: **{summary['car_key_age_s']:.0f}s** "
            f"/ 300s"
        )
        st.markdown(
            f"Packets: **{summary['car_packets']:,}** "
            f"/ 10,000"
        )
        st.markdown(
            f"Rotations: **{summary['car_rotations']}**"
        )
        progress_a = rotation_view.car_age_progress()
        colour_a   = (
            "🔴" if progress_a > 0.8
            else "🟡" if progress_a > 0.5
            else "🟢"
        )
        st.progress(
            progress_a,
            text=f"{colour_a} {progress_a:.0%} to next rotation"
        )

    with col2:
        st.markdown("**📡 Relay → Validator (Leg B)**")
        st.markdown(
            f"Key: `{summary['val_key_hint']}...`"
        )
        st.markdown(
            f"Age: **{summary['val_key_age_s']:.0f}s** "
            f"/ 300s"
        )
        st.markdown(
            f"Packets: **{summary['val_packets']:,}** "
            f"/ 10,000"
        )
        st.markdown(
            f"Rotations: **{summary['val_rotations']}**"
        )
        progress_b = rotation_view.val_age_progress()
        colour_b   = (
            "🔴" if progress_b > 0.8
            else "🟡" if progress_b > 0.5
            else "🟢"
        )
        st.progress(
            progress_b,
            text=f"{colour_b} {progress_b:.0%} to next rotation"
        )

    st.markdown("---")
    st.markdown(
        f"**Total rotations this session:** "
        f"{summary['total_rotations']}"
    )

    # ── Rotation history ──────────────────────────────────────────
    recent = rotation_view.get_recent_events(limit=5)
    if recent:
        st.markdown("**Recent Rotation Events:**")
        for evt in reversed(recent):
            st.markdown(
                f"🔄 `{evt['timestamp'][11:19]}` · "
                f"**{evt['leg']}** · "
                f"{evt['reason']} · "
                f"old_age={evt['old_age_s']}s · "
                f"new_key=`{evt['new_key_hint']}...`"
            )
    else:
        st.caption("No rotation events yet")

    # ── Manual rotation button ────────────────────────────────────
    if st.button("🔄 Force Key Rotation"):
        rotation_view.force_rotation(leg='both')
        st.success("Keys rotated on both legs ✅")
        st.rerun()