import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

"""
threat_panel.py

Threat detection and display component for
the PitCrypt-F1 security dashboard.

Ingests pipeline results and classifies
security events:
    - Replay attacks
    - Tamper attempts
    - Anomaly detections
    - IAM violations
    - Signature failures
    - ZKP commitment mismatches
    - Key rotation events

Provides real-time threat feed for dashboard.
"""


class ThreatEvent:
    """Single threat detection event."""

    SEVERITY_INFO     = "INFO"
    SEVERITY_WARN     = "WARN"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(
        self,
        event_type: str,
        message:    str,
        severity:   str,
        seq:        int  = 0,
        team:       str  = '',
        details:    dict = None,
    ):
        self.event_type = event_type
        self.message    = message
        self.severity   = severity
        self.seq        = seq
        self.team       = team
        self.details    = details or {}
        self.timestamp  = datetime.now(
            timezone.utc
        ).isoformat()

    def to_dict(self) -> dict:
        return {
            'type':      self.event_type,
            'message':   self.message,
            'severity':  self.severity,
            'seq':       self.seq,
            'team':      self.team,
            'details':   self.details,
            'timestamp': self.timestamp,
        }


class ThreatPanel:
    """
    Real-time threat detection panel.
    Classifies pipeline events as security threats.
    Deduplicates consecutive identical anomaly flags
    into a single summary card.
    """

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Reset all threat state."""
        self._events:       List[ThreatEvent] = []
        self._replay_count  = 0
        self._tamper_count  = 0
        self._anomaly_count = 0
        self._iam_count     = 0
        self._sig_count     = 0
        self._zkp_count     = 0
        self._last_seq      = 0
        self._accepted      = 0
        self._rejected      = 0

    def ingest(self, result: dict) -> None:
        """
        Ingest pipeline result and classify threats.

        Args:
            result: Dict from TelemetryFeed.process_one_packet()
        """
        if not result:
            return

        decision = result.get('decision', 'ACCEPT')
        reason   = result.get('reason', '')
        seq      = result.get('sequence_no', 0)
        team     = result.get('team', '')

        if decision == 'ACCEPT':
            self._accepted += 1
        else:
            self._rejected += 1

        # ── Classify by reason ───────────────────────────────────

        if 'replay' in reason or 'sequence' in reason:
            self._replay_count += 1
            self._add_event(ThreatEvent(
                event_type='REPLAY_ATTACK',
                message=(
                    f"Replay detected — "
                    f"seq={seq} team={team}"
                ),
                severity=ThreatEvent.SEVERITY_CRITICAL,
                seq=seq,
                team=team,
            ))

        elif 'aead' in reason or 'tamper' in reason:
            self._tamper_count += 1
            self._add_event(ThreatEvent(
                event_type='TAMPERING',
                message=(
                    f"AEAD tag failure — "
                    f"seq={seq} ciphertext modified"
                ),
                severity=ThreatEvent.SEVERITY_CRITICAL,
                seq=seq,
                team=team,
            ))

        elif 'sig' in reason:
            self._sig_count    += 1
            self._tamper_count += 1
            self._add_event(ThreatEvent(
                event_type='SIGNATURE_FAILURE',
                message=(
                    f"Ed25519 invalid — "
                    f"seq={seq} team={team} "
                    f"packet may be forged"
                ),
                severity=ThreatEvent.SEVERITY_CRITICAL,
                seq=seq,
                team=team,
            ))

        elif 'zkp' in reason:
            self._zkp_count    += 1
            self._tamper_count += 1
            self._add_event(ThreatEvent(
                event_type='ZKP_MISMATCH',
                message=(
                    f"ZKP commitment mismatch — "
                    f"seq={seq} payload modified "
                    f"after commitment"
                ),
                severity=ThreatEvent.SEVERITY_CRITICAL,
                seq=seq,
                team=team,
            ))

        elif 'anomaly_rejected' in reason:
            self._anomaly_count += 1
            self._add_event(ThreatEvent(
                event_type='ANOMALY_REJECT',
                message=(
                    f"Physical bounds violation — "
                    f"seq={seq} impossible sensor value"
                ),
                severity=ThreatEvent.SEVERITY_WARN,
                seq=seq,
                team=team,
            ))

        elif 'iam' in reason:
            self._iam_count += 1
            self._add_event(ThreatEvent(
                event_type='IAM_VIOLATION',
                message=(
                    f"IAM access denied — "
                    f"seq={seq} team={team}"
                ),
                severity=ThreatEvent.SEVERITY_CRITICAL,
                seq=seq,
                team=team,
            ))

        elif decision == 'FLAG':
            self._anomaly_count += 1
            anomaly_result = result.get('anomaly_result', {})
            violations     = anomaly_result.get('violations', [])
            channels       = ', '.join(
                v.get('channel', '') for v in violations
            ) if violations else 'unknown'
            self._add_event(ThreatEvent(
                event_type='ANOMALY_FLAG',
                message=(
                    f"Statistical threshold — "
                    f"seq={seq} channels: {channels}"
                ),
                severity=ThreatEvent.SEVERITY_WARN,
                seq=seq,
                team=team,
            ))

        self._last_seq = max(self._last_seq, seq)

    def _add_event(self, event: ThreatEvent) -> None:
        """Add event to buffer — keep last 200."""
        self._events.append(event)
        if len(self._events) > 200:
            self._events.pop(0)

    # ── Getters ───────────────────────────────────────────────────

    def get_recent(
        self, limit: int = 20
    ) -> List[dict]:
        """
        Get most recent threat events as dicts.
        Deduplicates consecutive identical event
        types and channels into a single summary
        card with a count badge.
        """
        raw = [e.to_dict() for e in self._events]

        # ── Deduplication ────────────────────────────────────────
        deduplicated = []
        i = 0
        while i < len(raw):
            current = raw[i]
            count   = 1
            first_seq = current.get('seq', '?')
            last_seq  = first_seq

            # Count consecutive events of same type
            # with same channel signature
            def _channel_key(evt):
                msg = evt.get('message', '')
                return msg.split('channels:')[-1].strip()

            while (
                i + count < len(raw) and
                raw[i + count].get('type') == current.get('type') and
                _channel_key(raw[i + count]) == _channel_key(current)
            ):
                last_seq = raw[i + count].get('seq', '?')
                count   += 1

            if count > 1:
                merged         = dict(current)
                channel_part   = _channel_key(current)
                merged['message'] = (
                    f"Statistical threshold — "
                    f"channels: {channel_part} "
                    f"×{count} (seq {first_seq}–{last_seq})"
                )
                deduplicated.append(merged)
            else:
                deduplicated.append(current)

            i += count

        return deduplicated[-limit:]

    def get_stats(self) -> dict:
        """Get threat statistics."""
        return {
            'replays':      self._replay_count,
            'tampers':      self._tamper_count,
            'anomalies':    self._anomaly_count,
            'iam_blocks':   self._iam_count,
            'sig_failures': self._sig_count,
            'zkp_failures': self._zkp_count,
            'total_threats': len(self._events),
            'accepted':     self._accepted,
            'rejected':     self._rejected,
        }

    def get_critical_events(self) -> List[dict]:
        """Get only CRITICAL severity events."""
        return [
            e.to_dict()
            for e in self._events
            if e.severity == ThreatEvent.SEVERITY_CRITICAL
        ]

    def has_active_threats(self) -> bool:
        """True if any critical threats detected."""
        return any(
            e.severity == ThreatEvent.SEVERITY_CRITICAL
            for e in self._events[-10:]
        )