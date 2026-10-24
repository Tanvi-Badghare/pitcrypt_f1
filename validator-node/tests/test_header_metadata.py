
import os
import sys
from unittest.mock import Mock

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VAL_SRC = os.path.join(ROOT, "validator-node", "src")
CAR_SRC = os.path.join(ROOT, "car_producer", "src")
REL_SRC = os.path.join(ROOT, "relay-node", "src")

# Ensure validator-node/src takes precedence over other main.py files.
for path in (REL_SRC, CAR_SRC, VAL_SRC):
    if path in sys.path:
        sys.path.remove(path)
    sys.path.insert(0, path)

from main import ValidatorNode
from crypto_engine import CryptoEngine
from sensor_simulator import SensorSimulator
from packet_builder import PacketBuilder
from signer import PacketSigner
from encryptor import PacketEncryptor
from decryptor import RelayDecryptor
from reencryptor import RelayReencryptor

ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
VAL_SRC = os.path.join(ROOT, "validator-node", "src")
CAR_SRC = os.path.join(ROOT, "car_producer", "src")
REL_SRC = os.path.join(ROOT, "relay-node", "src")

for path in (VAL_SRC, CAR_SRC, REL_SRC):
    if path not in sys.path:
        sys.path.insert(0, path)

from main import ValidatorNode
from crypto_engine import CryptoEngine
from sensor_simulator import SensorSimulator
from packet_builder import PacketBuilder
from signer import PacketSigner
from encryptor import PacketEncryptor
from decryptor import RelayDecryptor
from reencryptor import RelayReencryptor


@pytest.fixture
def validator_pipeline(tmp_path):
    """Build a real car-to-relay-to-validator encrypted packet path."""
    sim = SensorSimulator(
        team="mercedes",
        race="Bahrain",
        session="R",
        add_noise=False,
        inject_anomalies=False,
    )
    builder = PacketBuilder(team="mercedes", session="R")
    signer = PacketSigner(node_id="mercedes_car")

    # Car <-> relay handshake.
    car_engine = CryptoEngine(node_id="mercedes_car")
    relay_engine = CryptoEngine(node_id="relay_01")

    car_pub = car_engine.new_session()
    relay_pub = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Relay <-> validator handshake.
    relay_val_engine = CryptoEngine(node_id="relay_val")
    relay_val_pub = relay_val_engine.new_session()

    validator = ValidatorNode({
        "node": {"id": "fia_validator"},
        "sequence": {"check_timestamps": False},
        "audit": {
            "log_to_file": False,
            "alert_on_reject": False,
        },
    })
    validator_pub = validator.setup_relay_session(relay_val_pub)
    relay_val_engine.complete_handshake(validator_pub)
    validator.register_car_node(
        "mercedes_car", signer.public_key_bytes
    )

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id="mercedes_car",
    )
    decryptor = RelayDecryptor(node_id="relay_01")
    decryptor.register_session("mercedes_car", relay_engine)

    reencryptor = RelayReencryptor(node_id="relay_01")
    reencryptor.register_validator_session(relay_val_engine)

    frame = sim.get_next_frame()
    packet = builder.build(frame)
    signed_packet = signer.sign_packet(packet)
    encrypted_packet = encryptor.encrypt_packet(signed_packet)
    relay_plaintext = decryptor.decrypt(encrypted_packet)
    validator_packet = reencryptor.reencrypt(relay_plaintext)

    # Ensure the test reaches header consistency checking rather than
    # failing earlier because of encryption/session/signature setup.
    assert validator_packet.get("header") is not None
    assert validator_packet.get("sequence_no") is not None

    yield validator, validator_packet

    validator.audit.close() if hasattr(validator.audit, "close") else None


def test_header_metadata_sequence_mismatch_is_rejected(
    validator_pipeline,
):
    validator, packet = validator_pipeline

    header_fields = PacketBuilder.parse_header(packet["header"])
    header_sequence = header_fields["sequence_no"]

    # Change only the outer metadata; leave the authenticated binary
    # header and encrypted contents untouched.
    packet["sequence_no"] = header_sequence + 1

    validator.seq_checker.check = Mock(
        side_effect=AssertionError(
            "Sequence checker must not run after header mismatch"
        )
    )
    validator.zkp_verifier.verify_packet = Mock(
        side_effect=AssertionError(
            "ZKP verifier must not run after header mismatch"
        )
    )

    result = validator.process_packet(packet)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0
    assert validator._stats["flagged"] == 0

    validator.seq_checker.check.assert_not_called()
    validator.zkp_verifier.verify_packet.assert_not_called()

    rejects = validator.audit.get_reject_events()
    assert len(rejects) == 1
    assert rejects[0].reason == "header_metadata_mismatch"
