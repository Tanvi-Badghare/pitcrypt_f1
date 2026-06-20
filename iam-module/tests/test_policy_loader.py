import os
import sys
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
IAM_SRC = os.path.join(ROOT, 'iam-module', 'src')
sys.path.insert(0, IAM_SRC)

from policy_loader  import PolicyLoader, Policy, PolicyLoadError
from identity_store import IdentityStore


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def loader():
    return PolicyLoader()

@pytest.fixture(scope='module')
def car_policy(loader):
    return loader.get('car_node_policy')

@pytest.fixture(scope='module')
def relay_policy(loader):
    return loader.get('relay_node_policy')

@pytest.fixture(scope='module')
def validator_policy(loader):
    return loader.get('validator_node_policy')


# ── PolicyLoader tests ────────────────────────────────────────────

class TestPolicyLoader:

    def test_loads_all_three_policies(self, loader):
        assert len(loader.loaded_policies) == 3

    def test_car_policy_loaded(self, loader):
        assert loader.get('car_node_policy') is not None

    def test_relay_policy_loaded(self, loader):
        assert loader.get('relay_node_policy') is not None

    def test_validator_policy_loaded(self, loader):
        assert loader.get('validator_node_policy') is not None

    def test_unknown_policy_returns_none(self, loader):
        assert loader.get('nonexistent_policy') is None

    def test_get_for_car_role(self, loader):
        p = loader.get_for_role('car_producer')
        assert p is not None
        assert p.name == 'car_node_policy'

    def test_get_for_relay_role(self, loader):
        p = loader.get_for_role('relay')
        assert p is not None
        assert p.name == 'relay_node_policy'

    def test_get_for_validator_role(self, loader):
        p = loader.get_for_role('fia_validator')
        assert p is not None
        assert p.name == 'validator_node_policy'

    def test_get_for_unknown_role_returns_none(
        self, loader
    ):
        p = loader.get_for_role('unknown_role')
        assert p is None

    def test_unknown_policy_defaults_to_deny(self, loader):
        result = loader.is_action_allowed(
            'nonexistent', 'any.action', 'any'
        )
        assert result is False

    def test_known_policy_allow(self, loader):
        result = loader.is_action_allowed(
            'car_node_policy',
            'telemetry.produce',
            'own_telemetry',
        )
        assert result is True

    def test_known_policy_deny(self, loader):
        result = loader.is_action_allowed(
            'car_node_policy',
            'network.transmit',
            'validator_node',
        )
        assert result is False


# ── Policy object tests ───────────────────────────────────────────

class TestPolicyObject:

    def test_policy_has_name(self, car_policy):
        assert car_policy.name == 'car_node_policy'

    def test_policy_has_allowed_actions(self, car_policy):
        assert len(car_policy.allowed_actions) > 0

    def test_policy_has_denied_actions(self, car_policy):
        assert len(car_policy.denied_actions) > 0

    def test_policy_repr(self, car_policy):
        r = repr(car_policy)
        assert 'car_node_policy' in r

    def test_policy_get_constraint(self, car_policy):
        rate = car_policy.get_constraint(
            'max_packet_rate_hz'
        )
        assert rate == 150

    def test_policy_get_missing_constraint(
        self, car_policy
    ):
        val = car_policy.get_constraint(
            'nonexistent', default='fallback'
        )
        assert val == 'fallback'


# ── Car policy permission tests ───────────────────────────────────

class TestCarPolicy:

    def test_produce_own_telemetry_allowed(
        self, car_policy
    ):
        assert car_policy.is_allowed(
            'telemetry.produce', 'own_telemetry'
        )

    def test_sign_own_packets_allowed(self, car_policy):
        assert car_policy.is_allowed(
            'telemetry.sign', 'own_packets'
        )

    def test_encrypt_own_packets_allowed(
        self, car_policy
    ):
        assert car_policy.is_allowed(
            'telemetry.encrypt', 'own_packets'
        )

    def test_key_exchange_relay_allowed(self, car_policy):
        assert car_policy.is_allowed(
            'key.exchange', 'relay_node'
        )

    def test_transmit_relay_allowed(self, car_policy):
        assert car_policy.is_allowed(
            'network.transmit', 'relay_node'
        )

    def test_transmit_validator_denied(self, car_policy):
        assert not car_policy.is_allowed(
            'network.transmit', 'validator_node'
        )

    def test_read_other_team_denied(self, car_policy):
        assert not car_policy.is_allowed(
            'telemetry.read', 'other_team_telemetry'
        )

    def test_audit_read_denied(self, car_policy):
        assert not car_policy.is_allowed(
            'audit.read', 'audit_log'
        )

    def test_configure_relay_denied(self, car_policy):
        assert not car_policy.is_allowed(
            'relay.configure', 'relay_node'
        )

    def test_unknown_action_denied(self, car_policy):
        assert not car_policy.is_allowed(
            'unknown.action', 'some_resource'
        )


# ── Relay policy permission tests ─────────────────────────────────

class TestRelayPolicy:

    def test_receive_from_cars_allowed(
        self, relay_policy
    ):
        assert relay_policy.is_allowed(
            'telemetry.receive', 'car_nodes'
        )

    def test_decrypt_car_packets_allowed(
        self, relay_policy
    ):
        assert relay_policy.is_allowed(
            'telemetry.decrypt', 'car_packets'
        )

    def test_reencrypt_allowed(self, relay_policy):
        assert relay_policy.is_allowed(
            'telemetry.reencrypt', 'validator_packets'
        )

    def test_forward_to_validator_allowed(
        self, relay_policy
    ):
        assert relay_policy.is_allowed(
            'telemetry.forward', 'validator_node'
        )

    def test_anomaly_filter_allowed(self, relay_policy):
        assert relay_policy.is_allowed(
            'anomaly.filter', 'telemetry_values'
        )

    def test_sign_any_packets_denied(self, relay_policy):
        assert not relay_policy.is_allowed(
            'telemetry.sign', 'any_packets'
        )

    def test_store_plaintext_denied(self, relay_policy):
        assert not relay_policy.is_allowed(
            'telemetry.store', 'plaintext_data'
        )

    def test_read_audit_denied(self, relay_policy):
        assert not relay_policy.is_allowed(
            'audit.read', 'audit_log'
        )

    def test_modify_payload_denied(self, relay_policy):
        assert not relay_policy.is_allowed(
            'telemetry.modify', 'packet_payload'
        )

    def test_read_validator_keys_denied(
        self, relay_policy
    ):
        assert not relay_policy.is_allowed(
            'key.read', 'validator_keys'
        )


# ── Validator policy permission tests ─────────────────────────────

class TestValidatorPolicy:

    def test_verify_signature_allowed(
        self, validator_policy
    ):
        assert validator_policy.is_allowed(
            'signature.verify', 'all_packets'
        )

    def test_verify_sequence_allowed(
        self, validator_policy
    ):
        assert validator_policy.is_allowed(
            'sequence.verify', 'all_packets'
        )

    def test_verify_zkp_allowed(self, validator_policy):
        assert validator_policy.is_allowed(
            'zkp.verify', 'all_packets'
        )

    def test_write_audit_allowed(self, validator_policy):
        assert validator_policy.is_allowed(
            'audit.write', 'audit_log'
        )

    def test_read_audit_allowed(self, validator_policy):
        assert validator_policy.is_allowed(
            'audit.read', 'audit_log'
        )

    def test_export_audit_allowed(self, validator_policy):
        assert validator_policy.is_allowed(
            'audit.export', 'audit_log'
        )

    def test_accept_packets_allowed(
        self, validator_policy
    ):
        assert validator_policy.is_allowed(
            'packet.accept', 'verified_packets'
        )

    def test_reject_packets_allowed(
        self, validator_policy
    ):
        assert validator_policy.is_allowed(
            'packet.reject', 'invalid_packets'
        )

    def test_produce_telemetry_denied(
        self, validator_policy
    ):
        assert not validator_policy.is_allowed(
            'telemetry.produce', 'any'
        )

    def test_modify_packets_denied(
        self, validator_policy
    ):
        assert not validator_policy.is_allowed(
            'telemetry.modify', 'any_packets'
        )

    def test_transmit_to_cars_denied(
        self, validator_policy
    ):
        assert not validator_policy.is_allowed(
            'network.transmit', 'car_nodes'
        )


# ── Deny overrides allow tests ────────────────────────────────────

class TestDenyOverridesAllow:

    def test_deny_wins_over_allow(self):
        """
        Deny rules always override allow rules.
        This is the zero-trust baseline.
        """
        loader = PolicyLoader()
        car    = loader.get('car_node_policy')

        # validator_node is in deny list for car
        # even if somehow added to allow, deny wins
        assert not car.is_allowed(
            'network.transmit', 'validator_node'
        )

    def test_default_deny_for_unknown_action(self):
        loader = PolicyLoader()
        car    = loader.get('car_node_policy')
        # No rule matches — defaults to deny
        assert not car.is_allowed(
            'completely.unknown', 'unknown_resource'
        )


# ── IdentityStore tests ───────────────────────────────────────────

class TestIdentityStore:

    def test_nodes_loaded_from_config(self):
        store = IdentityStore()
        assert store.node_count >= 4

    def test_mercedes_car_registered(self):
        store = IdentityStore()
        assert store.is_registered('mercedes_car')

    def test_redbull_car_registered(self):
        store = IdentityStore()
        assert store.is_registered('redbull_car')

    def test_relay_registered(self):
        store = IdentityStore()
        assert store.is_registered('relay_01')

    def test_validator_registered(self):
        store = IdentityStore()
        assert store.is_registered('fia_validator')

    def test_unknown_node_not_registered(self):
        store = IdentityStore()
        assert not store.is_registered('unknown_car')

    def test_mercedes_car_role(self):
        store = IdentityStore()
        assert store.get_role('mercedes_car') == 'car_producer'

    def test_relay_role(self):
        store = IdentityStore()
        assert store.get_role('relay_01') == 'relay'

    def test_validator_role(self):
        store = IdentityStore()
        assert store.get_role('fia_validator') == 'fia_validator'

    def test_car_policy_assignment(self):
        store = IdentityStore()
        assert store.get_policy('mercedes_car') == \
               'car_node_policy'

    def test_register_new_node(self):
        store    = IdentityStore()
        identity = store.register(
            node_id='test_node',
            role='car_producer',
            team='mercedes',
            policy='car_node_policy',
        )
        assert store.is_registered('test_node')
        assert identity.role == 'car_producer'
        store.deregister('test_node')

    def test_deregister_node(self):
        store = IdentityStore()
        store.register(
            node_id='temp_node',
            role='relay',
            policy='relay_node_policy',
        )
        store.deregister('temp_node')
        assert not store.is_registered('temp_node')

    def test_register_public_key(self):
        store    = IdentityStore()
        fake_key = os.urandom(32)
        store.register(
            node_id='key_test_node',
            role='car_producer',
        )
        store.register_public_key(
            'key_test_node', fake_key
        )
        assert store.get(
            'key_test_node'
        ).public_key_bytes == fake_key
        store.deregister('key_test_node')

    def test_register_key_unknown_node_raises(self):
        store = IdentityStore()
        with pytest.raises(KeyError):
            store.register_public_key(
                'nonexistent', os.urandom(32)
            )

    def test_get_car_nodes(self):
        store = IdentityStore()
        cars  = store.get_car_nodes()
        assert len(cars) >= 2
        assert all(
            n.role == 'car_producer' for n in cars
        )

    def test_get_relay_nodes(self):
        store  = IdentityStore()
        relays = store.get_relay_nodes()
        assert len(relays) >= 1
        assert all(n.role == 'relay' for n in relays)

    def test_get_validator_nodes(self):
        store      = IdentityStore()
        validators = store.get_validator_nodes()
        assert len(validators) >= 1

    def test_node_identity_to_dict(self):
        store    = IdentityStore()
        identity = store.get('mercedes_car')
        d        = identity.to_dict()
        assert 'node_id'       in d
        assert 'role'          in d
        assert 'registered_at' in d
        assert 'active'        in d

    def test_active_nodes_excludes_deregistered(self):
        store = IdentityStore()
        store.register(
            node_id='inactive_node',
            role='relay',
        )
        initial_active = len(store.active_nodes)
        store.deregister('inactive_node')
        assert len(store.active_nodes) == initial_active - 1