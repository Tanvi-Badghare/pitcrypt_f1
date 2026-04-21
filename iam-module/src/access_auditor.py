import os
import sys
import json
import logging
import threading
from typing import List, Optional
from datetime import datetime, timezone

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
access_auditor.py

IAM access decision audit logger for PitCrypt-F1.

Records every access control decision — both allows
and denials — to an immutable audit trail.

Detects suspicious patterns:
    - Repeated denied access attempts
    - Unknown node access attempts
"""

ALERT_THRESHOLD = 3


class AccessAuditEvent:
    """Single IAM access audit event."""

    def __init__(
        self,
        node_id:   str,
        action:    str,
        resource:  str,
        allowed:   bool,
        reason:    str,
        role:      Optional[str] = None,
        policy:    Optional[str] = None,
    ):
        self.node_id   = node_id
        self.action    = action
        self.resource  = resource
        self.allowed   = allowed
        self.reason    = reason
        self.role      = role
        self.policy    = policy
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp,
            'node_id':   self.node_id,
            'action':    self.action,
            'resource':  self.resource,
            'allowed':   self.allowed,
            'reason':    self.reason,
            'role':      self.role,
            'policy':    self.policy,
        }


class AccessAuditor:
    """IAM access decision auditor with anomaly detection."""

    def __init__(
        self,
        node_id:     str  = 'iam',
        log_to_file: bool = True,
        log_file:    str  = None,
    ):
        self.node_id      = node_id
        self._lock        = threading.Lock()
        self._events:     List[AccessAuditEvent] = []
        self._consecutive_denials = {}
        self._allow_count = 0
        self._deny_count  = 0
        self._alert_count = 0

        self._log_file = (
            log_file or
            os.path.join(LOGS_DIR, 'iam_access_audit.jsonl')
        ) if log_to_file else None

        print(f"  [AccessAuditor] Initialised: {node_id}")

    def record(
        self,
        node_id:  str,
        action:   str,
        resource: str,
        allowed:  bool,
        reason:   str,
        role:     Optional[str] = None,
        policy:   Optional[str] = None,
    ) -> AccessAuditEvent:
        """Record an IAM access decision."""
        event = AccessAuditEvent(
            node_id=node_id, action=action,
            resource=resource, allowed=allowed,
            reason=reason, role=role, policy=policy,
        )

        with self._lock:
            self._events.append(event)
            if allowed:
                self._allow_count += 1
                self._consecutive_denials[node_id] = 0
            else:
                self._deny_count += 1
                self._consecutive_denials[node_id] = (
                    self._consecutive_denials.get(
                        node_id, 0
                    ) + 1
                )

        self._check_alert(node_id, event)

        if self._log_file:
            self._write(event)

        return event

    def record_from_decision(self, decision) -> AccessAuditEvent:
        """Record from an AccessDecision object."""
        return self.record(
            node_id=decision.node_id,
            action=decision.action,
            resource=decision.resource,
            allowed=decision.allowed,
            reason=decision.reason,
            role=decision.role,
            policy=decision.policy,
        )

    def _check_alert(
        self, node_id: str, event: AccessAuditEvent
    ) -> None:
        consecutive = self._consecutive_denials.get(
            node_id, 0
        )
        if consecutive >= ALERT_THRESHOLD:
            self._alert_count += 1
            logging.error(
                f"[AccessAuditor] 🚨 ALERT — "
                f"node={node_id} has "
                f"{consecutive} consecutive denials"
            )
        if event.reason == 'node_not_registered':
            logging.error(
                f"[AccessAuditor] 🚨 UNKNOWN NODE — "
                f"{node_id} attempted {event.action}"
            )

    def _write(self, event: AccessAuditEvent) -> None:
        try:
            with open(self._log_file, 'a') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception as e:
            logging.error(
                f"[AccessAuditor] Write error: {e}"
            )

    def get_events(
        self,
        node_id: Optional[str]  = None,
        allowed: Optional[bool] = None,
        limit:   Optional[int]  = None,
    ) -> List[AccessAuditEvent]:
        with self._lock:
            events = list(self._events)
        if node_id is not None:
            events = [e for e in events
                      if e.node_id == node_id]
        if allowed is not None:
            events = [e for e in events
                      if e.allowed == allowed]
        if limit is not None:
            events = events[-limit:]
        return events

    def get_denials(
        self, node_id: Optional[str] = None
    ) -> List[AccessAuditEvent]:
        return self.get_events(
            node_id=node_id, allowed=False
        )

    def summary(self) -> dict:
        with self._lock:
            total = len(self._events)
        return {
            'total':   total,
            'allowed': self._allow_count,
            'denied':  self._deny_count,
            'alerts':  self._alert_count,
        }

    def export_jsonl(self, path: str) -> None:
        with self._lock:
            events = list(self._events)
        with open(path, 'w') as f:
            for e in events:
                f.write(json.dumps(e.to_dict()) + '\n')
        logging.info(
            f"[AccessAuditor] Exported "
            f"{len(events)} events → {path}"
        )

    @property
    def total_events(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def allow_count(self) -> int:
        return self._allow_count

    @property
    def deny_count(self) -> int:
        return self._deny_count

    @property
    def alert_count(self) -> int:
        return self._alert_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  AccessAuditor — Self Test")
    print("="*55)

    auditor = AccessAuditor(
        node_id='iam_auditor', log_to_file=True
    )

    e1 = auditor.record(
        node_id='mercedes_car',
        action='telemetry.produce',
        resource='own_telemetry',
        allowed=True,
        reason='policy_allow',
        role='car_producer',
        policy='car_node_policy',
    )
    assert e1.allowed is True
    print(f"\n  Allow recorded: ✅")

    e2 = auditor.record(
        node_id='mercedes_car',
        action='network.transmit',
        resource='validator_node',
        allowed=False,
        reason='policy_deny',
        role='car_producer',
    )
    assert e2.allowed is False
    print(f"  Denial recorded: ✅")

    for _ in range(ALERT_THRESHOLD):
        auditor.record(
            node_id='suspicious_node',
            action='telemetry.read',
            resource='all_telemetry',
            allowed=False,
            reason='node_not_registered',
        )
    assert auditor.alert_count >= 1
    print(f"  Alert triggered: ✅")

    summary = auditor.summary()
    assert summary['total']   > 0
    assert summary['allowed'] >= 1
    assert summary['denied']  >= 1
    print(f"  Summary: {summary} ✅")

    export_path = os.path.join(LOGS_DIR, 'test_iam.jsonl')
    auditor.export_jsonl(export_path)
    assert os.path.exists(export_path)
    print(f"  Export: ✅")

    print(f"\n✅ AccessAuditor self-test complete.")