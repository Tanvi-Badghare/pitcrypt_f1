import os
import sys
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
IAM_SRC = os.path.join(ROOT, 'iam-module', 'src')
sys.path.insert(0, IAM_SRC)

from rbac_engine    import RBACEngine, AccessDecision
from identity_store import IdentityStore
from policy_loader  import PolicyLoader


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def engine():
    return RBACEngine(enforcement='strict')


@pytest.fixture(scope='module')
def fresh_engine():
    """Fresh engine for tests that need clean state."""
    return RBACEngine(enforcement='strict')


# ── AccessDecision tests ──────────────────────────────────────────

class TestAccessDecision:

    def test_allowed_decision(self):
        d = AccessDecision(
            allowed=True,
            node_id='mercedes_car',
            action='telemetry.produce',
            resource='own_telemetry',
            reason='policy_allow',
        )
        assert d.allowed is True

    def test_denied_decision(self):
        d = AccessDecision(
            allowed=False,
            node_id='mercedes_car',
            action='network.transmit',
            resource='validator_node',
            reason='policy_deny',
        )
        assert d.allowed is False

    def test_to_dict_structure(self):
        d = AccessDecision(
            allowed=True,
            node_id='test',
            action='test.action',
            resource='test_resource',
            reason='test',
        )
        result = d.to_dict()
        assert 'allowed'    in result
        assert 'node_id'    in result
        assert 'action'     in result
        assert 'resource'   in result
        assert 'reason'     in result
        assert 'decided_at' in result

    def test_repr_shows_allow(self):
        d = AccessDecision(
            allowed=True,
            node_id='node',
            action='act',
            resource='res',
            reason='ok',
        )
        assert 'ALLOW' in repr(d)

    def test_repr_shows_deny(self):
        d = AccessDecision(
            allowed=False,
            node_id='node',
            action='act',
            resource='res',
            reason='denied',
        )
        assert 'DENY' in repr(d)

    def test_has_timestamp(self):
        d = AccessDecision(
            allowed=True,
            node_id='n',
            action='a',
            resource='r',
            reason='ok',
        )
        assert d.decided_at is not None


# ── Car node permission tests ─────────────────────────────────────

class TestCarNodePermissions:

    def test_car_can_produce_telemetry(self, engine):
        d = engine.check(
            'mercedes_car',
            'telemetry.produce',
            'own_telemetry',
        )
        assert d.allowed is True

    def test_car_can_sign_packets(self, engine):
        d = engine.check(
            'mercedes_car',
            'telemetry.sign',
            'own_packets',
        )
        assert d.allowed is True

    def test_car_can_encrypt_packets(self, engine):
        d = engine.check(
            'mercedes_car',
            'telemetry.encrypt',
            'own_packets',
        )
        assert d.allowed is True

    def test_car_can_exchange_keys_with_relay(self, engine):
        d = engine.check(
            'mercedes_car',
            'key.exchange',
            'relay_node',
        )
        assert d.allowed is True

    def test_car_can_transmit_to_relay(self, engine):
        d = engine.check(
            'mercedes_car',
            'network.transmit',
            'relay_node',
        )
        assert d.allowed is True

    def test_car_cannot_transmit_to_validator(self, engine):
        d = engine.check(
            'mercedes_car',
            'network.transmit',
            'validator_node',
        )
        assert d.allowed is False

    def test_car_cannot_read_other_team_telemetry(
        self, engine
    ):
        d = engine.check(
            'mercedes_car',
            'telemetry.read',
            'other_team_telemetry',
        )
        assert d.allowed is False

    def test_car_cannot_read_audit_log(self, engine):
        d = engine.check(
            'mercedes_car',
            'audit.read',
            'audit_log',
        )
        assert d.allowed is False

    def test_car_cannot_configure_relay(self, engine):
        d = engine.check(
            'mercedes_car',
            'relay.configure',
            'relay_node',
        )
        assert d.allowed is False

    def test_redbull_car_same_permissions(self, engine):
        d = engine.check(
            'redbull_car',
            'telemetry.produce',
            'own_telemetry',
        )
        assert d.allowed is True

    def test_redbull_car_same_restrictions(self, engine):
        d = engine.check(
            'redbull_car',
            'network.transmit',
            'validator_node',
        )
        assert d.allowed is False


# ── Relay node permission tests ───────────────────────────────────

class TestRelayNodePermissions:

    def test_relay_can_receive_from_cars(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.receive',
            'car_nodes',
        )
        assert d.allowed is True

    def test_relay_can_decrypt(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.decrypt',
            'car_packets',
        )
        assert d.allowed is True

    def test_relay_can_reencrypt(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.reencrypt',
            'validator_packets',
        )
        assert d.allowed is True

    def test_relay_can_forward(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.forward',
            'validator_node',
        )
        assert d.allowed is True

    def test_relay_can_filter_anomalies(self, engine):
        d = engine.check(
            'relay_01',
            'anomaly.filter',
            'telemetry_values',
        )
        assert d.allowed is True

    def test_relay_cannot_sign_packets(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.sign',
            'any_packets',
        )
        assert d.allowed is False

    def test_relay_cannot_store_plaintext(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.store',
            'plaintext_data',
        )
        assert d.allowed is False

    def test_relay_cannot_read_audit_log(self, engine):
        d = engine.check(
            'relay_01',
            'audit.read',
            'audit_log',
        )
        assert d.allowed is False

    def test_relay_cannot_modify_payload(self, engine):
        d = engine.check(
            'relay_01',
            'telemetry.modify',
            'packet_payload',
        )
        assert d.allowed is False


# ── Validator node permission tests ──────────────────────────────

class TestValidatorNodePermissions:

    def test_validator_can_verify_signatures(self, engine):
        d = engine.check(
            'fia_validator',
            'signature.verify',
            'all_packets',
        )
        assert d.allowed is True

    def test_validator_can_verify_sequences(self, engine):
        d = engine.check(
            'fia_validator',
            'sequence.verify',
            'all_packets',
        )
        assert d.allowed is True

    def test_validator_can_verify_zkp(self, engine):
        d = engine.check(
            'fia_validator',
            'zkp.verify',
            'all_packets',
        )
        assert d.allowed is True

    def test_validator_can_write_audit(self, engine):
        d = engine.check(
            'fia_validator',
            'audit.write',
            'audit_log',
        )
        assert d.allowed is True

    def test_validator_can_read_audit(self, engine):
        d = engine.check(
            'fia_validator',
            'audit.read',
            'audit_log',
        )
        assert d.allowed is True

    def test_validator_can_export_audit(self, engine):
        d = engine.check(
            'fia_validator',
            'audit.export',
            'audit_log',
        )
        assert d.allowed is True

    def test_validator_can_accept_packets(self, engine):
        d = engine.check(
            'fia_validator',
            'packet.accept',
            'verified_packets',
        )
        assert d.allowed is True

    def test_validator_can_reject_packets(self, engine):
        d = engine.check(
            'fia_validator',
            'packet.reject',
            'invalid_packets',
        )
        assert d.allowed is True

    def test_validator_cannot_produce_telemetry(
        self, engine
    ):
        d = engine.check(
            'fia_validator',
            'telemetry.produce',
            'any',
        )
        assert d.allowed is False

    def test_validator_cannot_modify_packets(self, engine):
        d = engine.check(
            'fia_validator',
            'telemetry.modify',
            'any_packets',
        )
        assert d.allowed is False

    def test_validator_cannot_contact_cars(self, engine):
        d = engine.check(
            'fia_validator',
            'network.transmit',
            'car_nodes',
        )
        assert d.allowed is False


# ── Unknown node tests ────────────────────────────────────────────

class TestUnknownNode:

    def test_unknown_node_denied(self, engine):
        d = engine.check(
            'unknown_attacker',
            'telemetry.read',
            'any',
        )
        assert d.allowed is False

    def test_unknown_node_reason(self, engine):
        d = engine.check(
            'unknown_attacker',
            'telemetry.read',
            'any',
        )
        assert d.reason == 'node_not_registered'

    def test_unknown_node_increments_deny(self, engine):
        initial = engine.deny_count
        engine.check(
            'another_unknown',
            'anything',
            'anything',
        )
        assert engine.deny_count > initial


# ── Enforcement tests ─────────────────────────────────────────────

class TestEnforcement:

    def test_enforce_allows_valid_action(self, engine):
        result = engine.enforce(
            'mercedes_car',
            'telemetry.produce',
            'own_telemetry',
        )
        assert result is True

    def test_enforce_raises_on_denied(self, engine):
        with pytest.raises(PermissionError):
            engine.enforce(
                'mercedes_car',
                'network.transmit',
                'validator_node',
            )

    def test_enforce_raises_for_unknown_node(self, engine):
        with pytest.raises(PermissionError):
            engine.enforce(
                'unknown_node',
                'telemetry.read',
                'any',
            )

    def test_permission_error_message(self, engine):
        try:
            engine.enforce(
                'mercedes_car',
                'network.transmit',
                'validator_node',
            )
        except PermissionError as e:
            assert 'mercedes_car' in str(e)
            assert 'validator_node' in str(e)


# ── Stats tests ───────────────────────────────────────────────────

class TestStats:

    def test_allow_count_increments(self):
        e       = RBACEngine()
        initial = e.allow_count
        e.check('mercedes_car', 'telemetry.produce',
                'own_telemetry')
        assert e.allow_count == initial + 1

    def test_deny_count_increments(self):
        e       = RBACEngine()
        initial = e.deny_count
        e.check('mercedes_car', 'network.transmit',
                'validator_node')
        assert e.deny_count == initial + 1

    def test_total_decisions_increments(self):
        e       = RBACEngine()
        initial = e.total_decisions
        e.check('mercedes_car', 'telemetry.produce',
                'own_telemetry')
        e.check('relay_01', 'telemetry.receive', 'car_nodes')
        assert e.total_decisions == initial + 2

    def test_query_by_node(self, engine):
        decisions = engine.get_decisions(
            node_id='mercedes_car'
        )
        assert all(
            d.node_id == 'mercedes_car'
            for d in decisions
        )

    def test_query_allowed_only(self, engine):
        allowed = engine.get_decisions(allowed=True)
        assert all(d.allowed for d in allowed)

    def test_query_denied_only(self, engine):
        denied = engine.get_decisions(allowed=False)
        assert all(not d.allowed for d in denied)


# ── Cross-role tests ──────────────────────────────────────────────

class TestCrossRole:

    def test_car_cannot_do_relay_actions(self, engine):
        d = engine.check(
            'mercedes_car',
            'anomaly.filter',
            'telemetry_values',
        )
        assert d.allowed is False

    def test_relay_cannot_do_validator_actions(
        self, engine
    ):
        d = engine.check(
            'relay_01',
            'signature.verify',
            'all_packets',
        )
        assert d.allowed is False

    def test_validator_cannot_do_car_actions(self, engine):
        d = engine.check(
            'fia_validator',
            'telemetry.sign',
            'own_packets',
        )
        assert d.allowed is False