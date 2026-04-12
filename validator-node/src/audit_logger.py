import os
import sys
import json
import logging
import threading
from typing import List, Optional
from datetime import datetime, timezone
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT     = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
LOGS_DIR = os.path.join(ROOT, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

"""
audit_logger.py

Structured audit trail at the FIA validator node.

Every packet decision — accept, reject, flag — is logged
with full context for forensic analysis and compliance.

Log entries contain:
    - ISO timestamp
    - Packet sequence number
    - Car node identity
    - Team and session
    - Decision (ACCEPT/REJECT/FLAG)
    - Reason for decision
    - Signature verification result
    - Sequence check result
    - Anomaly flags if any

Why audit logging matters:
    - FIA requires audit trail for all telemetry decisions
    - Enables post-race forensic analysis
    - Provides evidence for regulatory disputes
    - Supports incident response runbook
    See: docs/INCIDENT_RESPONSE.md
    See: docs/FIA_DATA_PRIVACY_MODEL.md
"""


class AuditDecision(Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    FLAG   = "FLAG"


class AuditEvent:
    """Single audit log entry."""

    def __init__(
        self,
        decision:   AuditDecision,
        packet:     dict,
        reason:     str,
        details:    Optional[dict] = None,
    ):
        self.decision    = decision
        self.sequence_no = packet.get('sequence_no', 0)
        self.node_id     = (
            packet.get('original_node') or
            packet.get('node_id', 'unknown')
        )
        self.team        = packet.get('team',    '')
        self.session     = packet.get('session', '')
        self.reason      = reason
        self.details     = details or {}
        self.timestamp   = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            'timestamp':   self.timestamp,
            'decision':    self.decision.value,
            'sequence_no': self.sequence_no,
            'node_id':     self.node_id,
            'team':        self.team,
            'session':     self.session,
            'reason':      self.reason,
            'details':     self.details,
        }

    def __repr__(self) -> str:
        return (
            f"AuditEvent("
            f"{self.decision.value} | "
            f"seq={self.sequence_no} | "
            f"node={self.node_id} | "
            f"{self.reason})"
        )


class AuditLogger:
    """
    Thread-safe structured audit logger for validator node.

    Maintains in-memory log and optionally writes to file.
    Emits alerts for REJECT events.
    """

    def __init__(
        self,
        node_id:      str  = 'validator',
        log_to_file:  bool = True,
        log_file:     str  = None,
        alert_on_reject: bool = True,
    ):
        self.node_id         = node_id
        self._log_to_file    = log_to_file
        self._alert_on_reject = alert_on_reject
        self._lock           = threading.Lock()
        self._events:        List[AuditEvent] = []

        # Stats
        self._accept_count = 0
        self._reject_count = 0
        self._flag_count   = 0

        # File logging
        if log_to_file:
            self._log_file = log_file or os.path.join(
                LOGS_DIR, f'audit_{node_id}.jsonl'
            )
            os.makedirs(
                os.path.dirname(self._log_file),
                exist_ok=True,
            )
        else:
            self._log_file = None

        print(f"  [AuditLogger] Initialised: {node_id}")
        if self._log_file:
            print(f"  [AuditLogger] Log file: {self._log_file}")

    # ── Logging ──────────────────────────────────────────────────

    def log_accept(
        self,
        packet:  dict,
        reason:  str = 'all_checks_passed',
        details: Optional[dict] = None,
    ) -> AuditEvent:
        """Log a packet acceptance decision."""
        event = AuditEvent(
            decision=AuditDecision.ACCEPT,
            packet=packet,
            reason=reason,
            details=details,
        )
        self._record(event)
        return event

    def log_reject(
        self,
        packet:  dict,
        reason:  str,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        """Log a packet rejection decision."""
        event = AuditEvent(
            decision=AuditDecision.REJECT,
            packet=packet,
            reason=reason,
            details=details,
        )
        self._record(event)

        if self._alert_on_reject:
            logging.error(
                f"[AuditLogger] 🚨 REJECT ALERT — "
                f"node={event.node_id} "
                f"seq={event.sequence_no} "
                f"reason={reason}"
            )
        return event

    def log_flag(
        self,
        packet:  dict,
        reason:  str,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        """Log a packet flag decision — accepted with warning."""
        event = AuditEvent(
            decision=AuditDecision.FLAG,
            packet=packet,
            reason=reason,
            details=details,
        )
        self._record(event)
        logging.warning(
            f"[AuditLogger] ⚠️  FLAG — "
            f"node={event.node_id} "
            f"seq={event.sequence_no} "
            f"reason={reason}"
        )
        return event

    def _record(self, event: AuditEvent) -> None:
        """Thread-safe event recording."""
        with self._lock:
            self._events.append(event)

            if event.decision == AuditDecision.ACCEPT:
                self._accept_count += 1
            elif event.decision == AuditDecision.REJECT:
                self._reject_count += 1
            elif event.decision == AuditDecision.FLAG:
                self._flag_count   += 1

        # Write to file
        if self._log_file:
            self._write_to_file(event)

    def _write_to_file(self, event: AuditEvent) -> None:
        """Append event to JSONL log file."""
        try:
            with open(self._log_file, 'a') as f:
                f.write(
                    json.dumps(event.to_dict()) + '\n'
                )
        except Exception as e:
            logging.error(
                f"[AuditLogger] File write error: {e}"
            )

    # ── Query ────────────────────────────────────────────────────

    def get_events(
        self,
        decision:  Optional[AuditDecision] = None,
        node_id:   Optional[str]           = None,
        limit:     Optional[int]           = None,
    ) -> List[AuditEvent]:
        """
        Query audit events with optional filters.

        Args:
            decision: Filter by ACCEPT/REJECT/FLAG
            node_id:  Filter by car node
            limit:    Max events to return

        Returns:
            List of matching AuditEvent objects
        """
        with self._lock:
            events = list(self._events)

        if decision is not None:
            events = [
                e for e in events
                if e.decision == decision
            ]
        if node_id is not None:
            events = [
                e for e in events
                if e.node_id == node_id
            ]
        if limit is not None:
            events = events[-limit:]

        return events

    def get_reject_events(self) -> List[AuditEvent]:
        return self.get_events(decision=AuditDecision.REJECT)

    def get_flag_events(self) -> List[AuditEvent]:
        return self.get_events(decision=AuditDecision.FLAG)

    def summary(self) -> dict:
        """Audit summary statistics."""
        with self._lock:
            total = len(self._events)
        return {
            'node_id':      self.node_id,
            'total':        total,
            'accepted':     self._accept_count,
            'rejected':     self._reject_count,
            'flagged':      self._flag_count,
            'reject_rate':  round(
                self._reject_count / total, 4
            ) if total > 0 else 0,
        }

    def export_jsonl(self, path: str) -> None:
        """Export all events to a JSONL file."""
        with self._lock:
            events = list(self._events)
        with open(path, 'w') as f:
            for event in events:
                f.write(json.dumps(event.to_dict()) + '\n')
        logging.info(
            f"[AuditLogger] Exported {len(events)} "
            f"events → {path}"
        )

    # ── Properties ───────────────────────────────────────────────

    @property
    def total_events(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def accept_count(self) -> int:
        return self._accept_count

    @property
    def reject_count(self) -> int:
        return self._reject_count

    @property
    def flag_count(self) -> int:
        return self._flag_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  AuditLogger — Self Test")
    print("="*55)

    logger = AuditLogger(
        node_id='fia_validator',
        log_to_file=True,
    )

    # Fake packet for testing
    fake_packet = {
        'sequence_no':  42,
        'original_node': 'mercedes_car',
        'team':         'mercedes',
        'session':      'R',
    }

    # ── Test 1: Log accept ───────────────────────────────────────
    print("\n[Test 1] Log accept event")
    e1 = logger.log_accept(
        fake_packet,
        reason='all_checks_passed',
        details={'sig': 'valid', 'seq': 'valid'},
    )
    print(f"  Event: {e1}")
    assert e1.decision == AuditDecision.ACCEPT
    print(f"  Accept logged: ✅")

    # ── Test 2: Log reject ───────────────────────────────────────
    print("\n[Test 2] Log reject event")
    e2 = logger.log_reject(
        fake_packet,
        reason='invalid_signature',
        details={'error': 'Ed25519 verification failed'},
    )
    print(f"  Event: {e2}")
    assert e2.decision == AuditDecision.REJECT
    print(f"  Reject logged: ✅")

    # ── Test 3: Log flag ─────────────────────────────────────────
    print("\n[Test 3] Log flag event")
    e3 = logger.log_flag(
        fake_packet,
        reason='anomaly_detected',
        details={'channel': 'Speed', 'value': 350.0},
    )
    assert e3.decision == AuditDecision.FLAG
    print(f"  Flag logged: ✅")

    # ── Test 4: Query events ─────────────────────────────────────
    print("\n[Test 4] Query events")
    all_events    = logger.get_events()
    reject_events = logger.get_reject_events()
    flag_events   = logger.get_flag_events()

    print(f"  Total:    {len(all_events)}")
    print(f"  Rejected: {len(reject_events)}")
    print(f"  Flagged:  {len(flag_events)}")
    assert len(all_events)    == 3
    assert len(reject_events) == 1
    assert len(flag_events)   == 1
    print(f"  Query: ✅")

    # ── Test 5: Summary ──────────────────────────────────────────
    print("\n[Test 5] Summary")
    summary = logger.summary()
    print(f"  {summary}")
    assert summary['accepted'] == 1
    assert summary['rejected'] == 1
    assert summary['flagged']  == 1
    print(f"  Summary: ✅")

    # ── Test 6: Export JSONL ─────────────────────────────────────
    print("\n[Test 6] Export JSONL")
    export_path = os.path.join(LOGS_DIR, 'test_audit.jsonl')
    logger.export_jsonl(export_path)
    assert os.path.exists(export_path)
    with open(export_path) as f:
        lines = f.readlines()
    assert len(lines) == 3
    print(f"  Exported {len(lines)} lines: ✅")

    print(f"\n  Total events: {logger.total_events}")
    print(f"  Accept:       {logger.accept_count}")
    print(f"  Reject:       {logger.reject_count}")
    print(f"  Flag:         {logger.flag_count}")
    print(f"\n✅ AuditLogger self-test complete.")