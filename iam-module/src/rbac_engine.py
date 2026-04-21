import os
import sys
import logging
from typing import Optional
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
IAM_DIR = os.path.join(ROOT, 'iam-module')
sys.path.insert(0, os.path.join(IAM_DIR, 'src'))

from identity_store import IdentityStore
from policy_loader  import PolicyLoader

"""
rbac_engine.py

Role-Based Access Control enforcement engine.

Combines IdentityStore + PolicyLoader to answer:
    "Is node X allowed to perform action Y on resource Z?"

Zero-trust principle:
    Every request evaluated explicitly.
    Unknown nodes always denied.
    Deny rules always override allow rules.
"""


class AccessDecision:
    """Result of an RBAC access check."""

    def __init__(
        self,
        allowed:   bool,
        node_id:   str,
        action:    str,
        resource:  str,
        reason:    str,
        policy:    Optional[str] = None,
        role:      Optional[str] = None,
    ):
        self.allowed    = allowed
        self.node_id    = node_id
        self.action     = action
        self.resource   = resource
        self.reason     = reason
        self.policy     = policy
        self.role       = role
        self.decided_at = datetime.now(
            timezone.utc
        ).isoformat()

    def to_dict(self) -> dict:
        return {
            'allowed':    self.allowed,
            'node_id':    self.node_id,
            'action':     self.action,
            'resource':   self.resource,
            'reason':     self.reason,
            'policy':     self.policy,
            'role':       self.role,
            'decided_at': self.decided_at,
        }

    def __repr__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return (
            f"AccessDecision("
            f"{verdict} | "
            f"node={self.node_id} | "
            f"{self.action} → {self.resource})"
        )


class RBACEngine:
    """Zero-trust RBAC enforcement engine."""

    def __init__(
        self,
        identity_store: Optional[IdentityStore] = None,
        policy_loader:  Optional[PolicyLoader]  = None,
        enforcement:    str = 'strict',
    ):
        self._store       = identity_store or IdentityStore()
        self._loader      = policy_loader  or PolicyLoader()
        self._enforcement = enforcement
        self._allow_count = 0
        self._deny_count  = 0
        self._decisions   = []

        print(
            f"\n[RBACEngine] Initialised — "
            f"enforcement={enforcement}"
        )
        print(
            f"[RBACEngine] Nodes:    "
            f"{self._store.node_count}"
        )
        print(
            f"[RBACEngine] Policies: "
            f"{self._loader.loaded_policies}"
        )

    def check(
        self,
        node_id:  str,
        action:   str,
        resource: str,
    ) -> AccessDecision:
        """
        Check if a node is allowed to perform an action.
        Returns AccessDecision with allowed flag and reason.
        """
        # ── 1. Node identity check ───────────────────────────────
        if not self._store.is_registered(node_id):
            decision = AccessDecision(
                allowed=False,
                node_id=node_id,
                action=action,
                resource=resource,
                reason='node_not_registered',
            )
            self._record(decision)
            return decision

        identity    = self._store.get(node_id)
        role        = identity.role
        policy_name = identity.policy or \
                      self._default_policy(role)

        # ── 2. Policy lookup ─────────────────────────────────────
        policy = self._loader.get(policy_name)
        if policy is None:
            decision = AccessDecision(
                allowed=False,
                node_id=node_id,
                action=action,
                resource=resource,
                reason='policy_not_found',
                policy=policy_name,
                role=role,
            )
            self._record(decision)
            return decision

        # ── 3. Policy evaluation ─────────────────────────────────
        allowed = policy.is_allowed(action, resource)
        decision = AccessDecision(
            allowed=allowed,
            node_id=node_id,
            action=action,
            resource=resource,
            reason='policy_allow' if allowed else 'policy_deny',
            policy=policy_name,
            role=role,
        )
        self._record(decision)
        return decision

    def enforce(
        self,
        node_id:  str,
        action:   str,
        resource: str,
    ) -> bool:
        """
        Enforce access — raises PermissionError on denial.
        Returns True if allowed.
        """
        decision = self.check(node_id, action, resource)

        if not decision.allowed:
            logging.error(
                f"[RBACEngine] 🚨 ACCESS DENIED — "
                f"node={node_id} action={action} "
                f"resource={resource} "
                f"reason={decision.reason}"
            )
            raise PermissionError(
                f"Access denied: '{node_id}' cannot "
                f"'{action}' on '{resource}'. "
                f"Reason: {decision.reason}"
            )

        logging.info(
            f"[RBACEngine] ✅ ACCESS ALLOWED — "
            f"node={node_id} action={action}"
        )
        return True

    def _default_policy(self, role: str) -> str:
        return {
            'car_producer':  'car_node_policy',
            'relay':         'relay_node_policy',
            'fia_validator': 'validator_node_policy',
        }.get(role, 'unknown_policy')

    def _record(self, decision: AccessDecision) -> None:
        self._decisions.append(decision)
        if decision.allowed:
            self._allow_count += 1
        else:
            self._deny_count += 1

    def get_decisions(
        self,
        node_id: Optional[str]  = None,
        allowed: Optional[bool] = None,
    ) -> list:
        decisions = list(self._decisions)
        if node_id is not None:
            decisions = [
                d for d in decisions
                if d.node_id == node_id
            ]
        if allowed is not None:
            decisions = [
                d for d in decisions
                if d.allowed == allowed
            ]
        return decisions

    @property
    def allow_count(self) -> int:
        return self._allow_count

    @property
    def deny_count(self) -> int:
        return self._deny_count

    @property
    def total_decisions(self) -> int:
        return len(self._decisions)


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  RBACEngine — Self Test")
    print("="*55)

    engine = RBACEngine(enforcement='strict')

    # Car node — allowed
    d1 = engine.check(
        'mercedes_car', 'telemetry.produce', 'own_telemetry'
    )
    assert d1.allowed is True
    print(f"\n  mercedes_car produce: ✅ ALLOW")

    # Car node — denied
    d2 = engine.check(
        'mercedes_car', 'network.transmit', 'validator_node'
    )
    assert d2.allowed is False
    print(f"  mercedes_car → validator: ✅ DENY")

    # Relay — allowed
    d3 = engine.check(
        'relay_01', 'telemetry.receive', 'car_nodes'
    )
    assert d3.allowed is True
    print(f"  relay_01 receive: ✅ ALLOW")

    # Relay — denied
    d4 = engine.check(
        'relay_01', 'telemetry.sign', 'any_packets'
    )
    assert d4.allowed is False
    print(f"  relay_01 sign: ✅ DENY")

    # Validator — allowed
    d5 = engine.check(
        'fia_validator', 'signature.verify', 'all_packets'
    )
    assert d5.allowed is True
    print(f"  validator verify: ✅ ALLOW")

    # Validator — denied
    d6 = engine.check(
        'fia_validator', 'telemetry.produce', 'any'
    )
    assert d6.allowed is False
    print(f"  validator produce: ✅ DENY")

    # Unknown node
    d7 = engine.check(
        'unknown_attacker', 'telemetry.read', 'any'
    )
    assert d7.allowed is False
    assert d7.reason  == 'node_not_registered'
    print(f"  Unknown node: ✅ DENY")

    # Enforce raises
    try:
        engine.enforce(
            'mercedes_car', 'network.transmit', 'validator_node'
        )
    except PermissionError:
        print(f"  PermissionError raised: ✅")

    print(f"\n  Total: {engine.total_decisions}")
    print(f"  Allow: {engine.allow_count}")
    print(f"  Deny:  {engine.deny_count}")
    print(f"\n✅ RBACEngine self-test complete.")