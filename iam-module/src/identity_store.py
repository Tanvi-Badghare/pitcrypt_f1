import os
import sys
import yaml
import logging
from typing import Dict, Optional
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT     = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
IAM_DIR  = os.path.join(ROOT, 'iam-module')
CFG_PATH = os.path.join(IAM_DIR, 'config', 'iam.yaml')

"""
identity_store.py

Node identity registry for PitCrypt-F1 zero-trust IAM.

Maintains the authoritative registry of:
    - Node identities (car, relay, validator)
    - Node roles
    - Node policy assignments
    - Node public keys (Ed25519)
    - Node registration timestamps

In zero-trust architecture every node must be
explicitly registered before it can participate
in the pipeline. Unknown nodes are rejected.
"""


class NodeIdentity:
    """Represents a registered node identity."""

    def __init__(
        self,
        node_id:          str,
        role:             str,
        team:             Optional[str]   = None,
        policy:           Optional[str]   = None,
        public_key_bytes: Optional[bytes] = None,
    ):
        self.node_id          = node_id
        self.role             = role
        self.team             = team
        self.policy           = policy
        self.public_key_bytes = public_key_bytes
        self.registered_at    = datetime.now(
            timezone.utc
        ).isoformat()
        self.active           = True

    def to_dict(self) -> dict:
        return {
            'node_id':        self.node_id,
            'role':           self.role,
            'team':           self.team,
            'policy':         self.policy,
            'has_public_key': self.public_key_bytes is not None,
            'registered_at':  self.registered_at,
            'active':         self.active,
        }

    def __repr__(self) -> str:
        return (
            f"NodeIdentity("
            f"id={self.node_id}, "
            f"role={self.role}, "
            f"team={self.team})"
        )


class IdentityStore:
    """
    Zero-trust node identity registry.
    All nodes must be explicitly registered.
    """

    def __init__(self, config_path: str = CFG_PATH):
        self._nodes:  Dict[str, NodeIdentity] = {}
        self._config  = {}

        if os.path.exists(config_path):
            self._load_from_config(config_path)
            logging.info(
                f"[IdentityStore] Loaded: {config_path}"
            )
        else:
            logging.warning(
                f"[IdentityStore] Config not found: "
                f"{config_path}. Starting empty."
            )

        print(
            f"  [IdentityStore] Initialised — "
            f"{len(self._nodes)} nodes registered"
        )

    def _load_from_config(self, path: str) -> None:
        """Load node definitions from iam.yaml."""
        with open(path, 'r') as f:
            cfg = yaml.safe_load(f)

        self._config = cfg
        nodes_cfg    = (
            cfg.get('iam', {}).get('nodes', {}) or
            cfg.get('nodes', {})
        )

        for node_id, node_cfg in nodes_cfg.items():
            identity = NodeIdentity(
                node_id=node_id,
                role=node_cfg.get('role', 'unknown'),
                team=node_cfg.get('team'),
                policy=node_cfg.get('policy'),
            )
            self._nodes[node_id] = identity

    # ── Registration ─────────────────────────────────────────────

    def register(
        self,
        node_id:          str,
        role:             str,
        team:             Optional[str]   = None,
        policy:           Optional[str]   = None,
        public_key_bytes: Optional[bytes] = None,
    ) -> NodeIdentity:
        """Register a new node identity."""
        identity = NodeIdentity(
            node_id=node_id,
            role=role,
            team=team,
            policy=policy,
            public_key_bytes=public_key_bytes,
        )
        self._nodes[node_id] = identity
        logging.info(
            f"[IdentityStore] Registered: {node_id} "
            f"(role={role})"
        )
        return identity

    def register_public_key(
        self,
        node_id:          str,
        public_key_bytes: bytes,
    ) -> None:
        """Register or update a node's Ed25519 public key."""
        if node_id not in self._nodes:
            raise KeyError(
                f"Node '{node_id}' not registered. "
                f"Call register() first."
            )
        self._nodes[node_id].public_key_bytes = (
            public_key_bytes
        )
        logging.info(
            f"[IdentityStore] Public key registered: "
            f"{node_id}"
        )

    def deregister(self, node_id: str) -> None:
        """Deactivate a node identity."""
        if node_id in self._nodes:
            self._nodes[node_id].active = False
            logging.info(
                f"[IdentityStore] Deregistered: {node_id}"
            )

    # ── Lookup ───────────────────────────────────────────────────

    def get(self, node_id: str) -> Optional[NodeIdentity]:
        return self._nodes.get(node_id)

    def get_role(self, node_id: str) -> Optional[str]:
        identity = self._nodes.get(node_id)
        return identity.role if identity else None

    def get_policy(self, node_id: str) -> Optional[str]:
        identity = self._nodes.get(node_id)
        return identity.policy if identity else None

    def is_registered(self, node_id: str) -> bool:
        identity = self._nodes.get(node_id)
        return identity is not None and identity.active

    def get_nodes_by_role(self, role: str) -> list:
        return [
            n for n in self._nodes.values()
            if n.role == role and n.active
        ]

    def get_car_nodes(self) -> list:
        return self.get_nodes_by_role('car_producer')

    def get_relay_nodes(self) -> list:
        return self.get_nodes_by_role('relay')

    def get_validator_nodes(self) -> list:
        return self.get_nodes_by_role('fia_validator')

    # ── Properties ───────────────────────────────────────────────

    @property
    def all_nodes(self) -> list:
        return list(self._nodes.values())

    @property
    def active_nodes(self) -> list:
        return [n for n in self._nodes.values() if n.active]

    @property
    def node_count(self) -> int:
        return len(self._nodes)


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  IdentityStore — Self Test")
    print("="*55)

    store = IdentityStore()

    print(f"\n[Test 1] Nodes from config")
    print(f"  Node count: {store.node_count}")
    for node in store.active_nodes:
        print(f"  {node}")
    assert store.node_count >= 4

    print(f"\n[Test 2] Register new node")
    identity = store.register(
        node_id='test_car',
        role='car_producer',
        team='mercedes',
        policy='car_node_policy',
    )
    assert store.is_registered('test_car')
    print(f"  Registered: {identity} ✅")

    print(f"\n[Test 3] Register public key")
    fake_key = os.urandom(32)
    store.register_public_key('test_car', fake_key)
    assert store.get('test_car').public_key_bytes == fake_key
    print(f"  Public key registered: ✅")

    print(f"\n[Test 4] Role lookup")
    role = store.get_role('mercedes_car')
    assert role == 'car_producer'
    print(f"  mercedes_car role: {role} ✅")

    print(f"\n[Test 5] Get nodes by role")
    cars = store.get_car_nodes()
    print(f"  Car nodes: {[n.node_id for n in cars]}")
    assert len(cars) >= 2
    print(f"  Car nodes: ✅")

    print(f"\n[Test 6] Deregister node")
    store.deregister('test_car')
    assert not store.is_registered('test_car')
    print(f"  Deregistered: ✅")

    print(f"\n✅ IdentityStore self-test complete.")