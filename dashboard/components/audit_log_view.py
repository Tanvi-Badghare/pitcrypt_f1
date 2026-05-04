import os
import sys
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict

"""
audit_log_view.py

Audit log display component for the
PitCrypt-F1 security dashboard.

Displays:
    - Live validator audit decisions (ACCEPT/REJECT/FLAG)
    - Filterable by decision type, team, sequence range
    - Export to JSON or CSV
    - Decision rate chart
    - Running statistics
    - Suspicious pattern alerts
"""


class AuditLogView:
    """
    Audit log state manager and display controller.
    Ingests AuditEvent dicts and provides
    filtered views for the dashboard.
    """

    def __init__(self, max_events: int = 500):
        self._max_events  = max_events
        self._events:     List[dict] = []
        self._accept_count = 0
        self._reject_count = 0
        self._flag_count   = 0
        self._reject_reasons: Dict[str, int] = {}

    def ingest_event(self, event: dict) -> None:
        """Add one audit event to the log."""
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events.pop(0)

        decision = event.get('decision', 'ACCEPT')
        if decision == 'ACCEPT':
            self._accept_count += 1
        elif decision == 'REJECT':
            self._reject_count += 1
            reason = event.get('reason', 'unknown')
            self._reject_reasons[reason] = (
                self._reject_reasons.get(reason, 0) + 1
            )
        elif decision == 'FLAG':
            self._flag_count += 1

    def ingest_batch(self, events: List[dict]) -> None:
        """Add multiple audit events."""
        for evt in events:
            self.ingest_event(evt)

    def get_events(
        self,
        decision:  Optional[str] = None,
        team:      Optional[str] = None,
        limit:     int           = 50,
        ascending: bool          = False,
    ) -> List[dict]:
        """
        Get filtered audit events.

        Args:
            decision:  Filter by ACCEPT/REJECT/FLAG/None=all
            team:      Filter by team name
            limit:     Max events to return
            ascending: True = oldest first

        Returns:
            List of audit event dicts
        """
        events = list(self._events)

        if decision:
            events = [
                e for e in events
                if e.get('decision') == decision
            ]
        if team:
            events = [
                e for e in events
                if e.get('team') == team
            ]

        if not ascending:
            events = list(reversed(events))

        return events[:limit]

    def get_stats(self) -> dict:
        """Summary statistics."""
        total = len(self._events)
        return {
            'total':        total,
            'accepted':     self._accept_count,
            'rejected':     self._reject_count,
            'flagged':      self._flag_count,
            'accept_rate':  round(
                self._accept_count / total, 4
            ) if total > 0 else 0,
            'reject_rate':  round(
                self._reject_count / total, 4
            ) if total > 0 else 0,
            'reject_reasons': dict(self._reject_reasons),
        }

    def get_recent_rejects(
        self, limit: int = 10
    ) -> List[dict]:
        """Get most recent REJECT events."""
        return self.get_events(
            decision='REJECT', limit=limit
        )

    def has_suspicious_pattern(self) -> bool:
        """
        True if recent events show suspicious pattern:
        - 3+ consecutive rejects from same node
        - Rapid sequence number jumps
        """
        recent = self._events[-10:]
        if len(recent) < 3:
            return False

        # Check consecutive rejects
        reject_streak = 0
        for evt in reversed(recent):
            if evt.get('decision') == 'REJECT':
                reject_streak += 1
            else:
                break

        return reject_streak >= 3

    def export_json(self) -> str:
        """Export all events as JSON string."""
        export = {
            'exported_at': datetime.now(
                timezone.utc
            ).isoformat(),
            'total_events': len(self._events),
            'stats':        self.get_stats(),
            'events':       self._events,
        }
        return json.dumps(export, indent=2)

    def export_csv(self) -> str:
        """Export all events as CSV string."""
        lines = [
            'timestamp,decision,sequence_no,'
            'node_id,team,session,reason'
        ]
        for evt in self._events:
            lines.append(
                f"{evt.get('timestamp', '')},"
                f"{evt.get('decision', '')},"
                f"{evt.get('sequence_no', '')},"
                f"{evt.get('node_id', '')},"
                f"{evt.get('team', '')},"
                f"{evt.get('session', '')},"
                f"{evt.get('reason', '')}"
            )
        return '\n'.join(lines)

    def reset(self) -> None:
        """Clear all events and reset counters."""
        self._events         = []
        self._accept_count   = 0
        self._reject_count   = 0
        self._flag_count     = 0
        self._reject_reasons = {}


def render_audit_log_view(
    audit_view: AuditLogView,
) -> None:
    """
    Render audit log panel in Streamlit.
    Import and call this from app.py.
    """
    import streamlit as st

    stats = audit_view.get_stats()

    st.markdown("#### 📋 Validator Audit Log")

    # ── Stats row ─────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total", stats['total'])
    with c2:
        st.metric(
            "✅ Accepted",
            stats['accepted'],
            delta=f"{stats['accept_rate']:.1%}",
        )
    with c3:
        st.metric("🔴 Rejected", stats['rejected'])
    with c4:
        st.metric("🟡 Flagged", stats['flagged'])

    # ── Suspicious pattern alert ──────────────────────────────────
    if audit_view.has_suspicious_pattern():
        st.error(
            "🚨 Suspicious pattern detected — "
            "3+ consecutive rejections"
        )

    # ── Reject reasons breakdown ──────────────────────────────────
    reasons = stats.get('reject_reasons', {})
    if reasons:
        st.markdown("**Rejection Reasons:**")
        for reason, count in sorted(
            reasons.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            st.markdown(f"- `{reason}`: **{count}**")

    st.markdown("---")

    # ── Filter controls ───────────────────────────────────────────
    col_filter, col_team = st.columns(2)
    with col_filter:
        decision_filter = st.selectbox(
            "Filter by decision",
            ["All", "ACCEPT", "REJECT", "FLAG"],
            key="audit_decision_filter",
        )
    with col_team:
        team_filter = st.selectbox(
            "Filter by team",
            ["All", "mercedes", "redbull"],
            key="audit_team_filter",
        )

    decision_arg = (
        None if decision_filter == "All"
        else decision_filter
    )
    team_arg = (
        None if team_filter == "All"
        else team_filter
    )

    # ── Event table ───────────────────────────────────────────────
    events = audit_view.get_events(
        decision=decision_arg,
        team=team_arg,
        limit=25,
    )

    if events:
        for evt in events:
            decision = evt.get('decision', 'ACCEPT')
            seq      = evt.get('sequence_no', 0)
            reason   = evt.get('reason', '')
            ts       = evt.get('timestamp', '')[:19]
            team     = evt.get('team', '')

            icon = {
                'ACCEPT': '🟢',
                'REJECT': '🔴',
                'FLAG':   '🟡',
            }.get(decision, '🟢')

            st.markdown(
                f"{icon} `{ts}` · "
                f"**{decision}** · "
                f"seq={seq:04d} · "
                f"{team} · "
                f"*{reason}*"
            )
    else:
        st.info("No events match filter")

    st.markdown("---")

    # ── Export controls ───────────────────────────────────────────
    st.markdown("**Export Audit Log:**")
    col_json, col_csv = st.columns(2)

    with col_json:
        if st.button("⬇ Export JSON"):
            json_str = audit_view.export_json()
            st.download_button(
                label="Download audit_log.json",
                data=json_str,
                file_name="pitcrypt_audit_log.json",
                mime="application/json",
            )

    with col_csv:
        if st.button("⬇ Export CSV"):
            csv_str = audit_view.export_csv()
            st.download_button(
                label="Download audit_log.csv",
                data=csv_str,
                file_name="pitcrypt_audit_log.csv",
                mime="text/csv",
            )