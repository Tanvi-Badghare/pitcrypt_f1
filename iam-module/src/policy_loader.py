import os
import sys
import yaml
import logging
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
IAM_DIR = os.path.join(ROOT, 'iam-module')

"""
policy_loader.py

Loads and validates IAM policy YAML files.
Provides permission checking by action and resource.

Policy evaluation order:
    1. Deny rules first — deny always wins
    2. Allow rules — explicit allow required
    3. Default deny — zero-trust baseline
"""


class PolicyLoadError(Exception):
    pass


class Policy:
    """Loaded IAM policy with permission checking."""

    def __init__(self, name: str, data: dict):
        self.name         = name
        self._data        = data
        self._allow       = (
            data.get('permissions', {}).get('allow', [])
        )
        self._deny        = (
            data.get('permissions', {}).get('deny', [])
        )
        self._constraints = data.get('constraints', {})
        self._roles       = data.get('roles', [])

    def is_allowed(self, action: str, resource: str) -> bool:
        """
        Check if action on resource is permitted.
        Deny rules checked first — deny always wins.
        Default is deny (zero-trust).
        """
        for rule in self._deny:
            if self._matches(rule, action, resource):
                return False
        for rule in self._allow:
            if self._matches(rule, action, resource):
                return True
        return False

    def _matches(
        self, rule: dict, action: str, resource: str
    ) -> bool:
        ra = rule.get('action',   '')
        rr = rule.get('resource', '')
        return (
            ra in (action, '*', 'any') and
            rr in (resource, '*', 'any')
        )

    def get_constraint(self, key: str, default=None):
        return self._constraints.get(key, default)

    @property
    def allowed_actions(self) -> List[str]:
        return [r.get('action', '') for r in self._allow]

    @property
    def denied_actions(self) -> List[str]:
        return [r.get('action', '') for r in self._deny]

    @property
    def roles(self) -> list:
        return self._roles

    def __repr__(self) -> str:
        return (
            f"Policy(name={self.name}, "
            f"allow={len(self._allow)}, "
            f"deny={len(self._deny)})"
        )


class PolicyLoader:
    """Loads all IAM policy YAML files from policies/."""

    def __init__(self, iam_dir: str = IAM_DIR):
        self._iam_dir  = iam_dir
        self._policies: Dict[str, Policy] = {}
        self._load_all()
        print(
            f"  [PolicyLoader] Loaded "
            f"{len(self._policies)} policies"
        )

    def _load_all(self) -> None:
        policies_dir = os.path.join(
            self._iam_dir, 'policies'
        )
        if not os.path.exists(policies_dir):
            logging.warning(
                f"[PolicyLoader] Policies dir not found: "
                f"{policies_dir}"
            )
            return

        for filename in sorted(os.listdir(policies_dir)):
            if not filename.endswith('.yaml'):
                continue
            path = os.path.join(policies_dir, filename)
            try:
                self._load_file(path)
            except Exception as e:
                logging.error(
                    f"[PolicyLoader] Failed {filename}: {e}"
                )

    def _load_file(self, path: str) -> Policy:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        if not data:
            raise PolicyLoadError(f"Empty: {path}")

        policy_meta = data.get('policy', {})
        name        = policy_meta.get(
            'name',
            os.path.basename(path).replace('.yaml', '')
        )
        policy = Policy(name=name, data=data)
        self._policies[name] = policy

        logging.info(
            f"[PolicyLoader] Loaded: {name} "
            f"({len(policy.allowed_actions)} allow, "
            f"{len(policy.denied_actions)} deny)"
        )
        return policy

    def get(self, policy_name: str) -> Optional[Policy]:
        return self._policies.get(policy_name)

    def get_for_role(self, role: str) -> Optional[Policy]:
        role_map = {
            'car_producer':  'car_node_policy',
            'relay':         'relay_node_policy',
            'fia_validator': 'validator_node_policy',
        }
        name = role_map.get(role)
        return self.get(name) if name else None

    def is_action_allowed(
        self,
        policy_name: str,
        action:      str,
        resource:    str,
    ) -> bool:
        policy = self.get(policy_name)
        if policy is None:
            logging.warning(
                f"[PolicyLoader] Policy not found: "
                f"{policy_name}. Defaulting to DENY."
            )
            return False
        return policy.is_allowed(action, resource)

    @property
    def loaded_policies(self) -> list:
        return list(self._policies.keys())


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  PolicyLoader — Self Test")
    print("="*55)

    loader = PolicyLoader()
    print(f"\n  Loaded: {loader.loaded_policies}")

    # Car node
    car = loader.get('car_node_policy')
    assert car is not None
    assert car.is_allowed('telemetry.produce', 'own_telemetry')
    assert not car.is_allowed('network.transmit', 'validator_node')
    print(f"\n  Car policy: ✅")

    # Relay node
    relay = loader.get('relay_node_policy')
    assert relay is not None
    assert relay.is_allowed('telemetry.receive', 'car_nodes')
    assert not relay.is_allowed('telemetry.sign', 'any_packets')
    print(f"  Relay policy: ✅")

    # Validator node
    val = loader.get('validator_node_policy')
    assert val is not None
    assert val.is_allowed('signature.verify', 'all_packets')
    assert not val.is_allowed('telemetry.produce', 'any')
    print(f"  Validator policy: ✅")

    # Role lookup
    p = loader.get_for_role('car_producer')
    assert p.name == 'car_node_policy'
    print(f"  Role lookup: ✅")

    # Unknown policy defaults to deny
    assert not loader.is_action_allowed(
        'unknown_policy', 'any.action', 'any'
    )
    print(f"  Unknown policy deny: ✅")

    print(f"\n✅ PolicyLoader self-test complete.")