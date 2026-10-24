
import os
import sys

import pytest

ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

VAL_SRC = os.path.join(ROOT, "validator-node", "src")
CAR_SRC = os.path.join(ROOT, "car_producer", "src")
REL_SRC = os.path.join(ROOT, "relay-node", "src")

# Ensure validator-node/src wins over other directories containing main.py.
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


@pytest.fixture
def validator_pipeline():
    sim = SensorSimulator(
        team="mercedes",
        race="Bahrain",
        session="R",
        add_noise=False,
        inject_anomalies=False,
    )

    builder = PacketBuilder(team="mercedes", session="R")
    signer = PacketSigner(node_id="mercedes_car")

    # Car -> relay session.
    car_engine = CryptoEngine(node_id="mercedes_car")
    relay_engine = CryptoEngine(node_id="relay_01")

    car_pub = car_engine.new_session()
    relay_pub = relay_engine.new_session()

    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Relay -> validator session.
    relay_val_engine = CryptoEngine(node_id="relay_val")
    relay_val_pub = relay_val_engine.new_session()

    validator = ValidatorNode(
        {
            "node": {"id": "fia_validator"},
            "sequence": {"check_timestamps": False},
            "audit": {
                "log_to_file": False,
                "alert_on_reject": False,
            },
        }
    )

    validator_pub = validator.setup_relay_session(relay_val_pub)
    relay_val_engine.complete_handshake(validator_pub)

    validator.register_car_node(
        "mercedes_car",
        signer.public_key_bytes,
    )

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id="mercedes_car",
    )

    decryptor = RelayDecryptor(node_id="relay_01")
    decryptor.register_session("mercedes_car", relay_engine)

    reencryptor = RelayReencryptor(node_id="relay_01")
    reencryptor.register_validator_session(relay_val_engine)

    # Construct a packet through the same pipeline used by the tests.
    frame = sim.get_next_frame()
    packet = builder.build(frame)
    signed_packet = signer.sign_packet(packet)
    encrypted_packet = encryptor.encrypt_packet(signed_packet)
    relay_plaintext = decryptor.decrypt(encrypted_packet)
    validator_packet = reencryptor.reencrypt(relay_plaintext)

    assert validator_packet.get("header") is not None
    assert validator_packet.get("sequence_no") is not None

    yield validator, validator_packet

@pytest.fixture
def validator_multi_packet_pipeline():
    """Create a validator and two independently generated telemetry packets."""
    sim = SensorSimulator(
        team="mercedes",
        race="Bahrain",
        session="R",
        add_noise=False,
        inject_anomalies=False,
    )

    builder = PacketBuilder(team="mercedes", session="R")
    signer = PacketSigner(node_id="mercedes_car")

    # Car -> relay encryption session.
    car_engine = CryptoEngine(node_id="mercedes_car")
    relay_engine = CryptoEngine(node_id="relay_01")

    car_pub = car_engine.new_session()
    relay_pub = relay_engine.new_session()

    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Relay -> validator encryption session.
    relay_val_engine = CryptoEngine(node_id="relay_val")
    relay_val_pub = relay_val_engine.new_session()

    validator = ValidatorNode(
        {
            "node": {"id": "fia_validator"},
            "sequence": {
                "check_timestamps": False,
                "strict_ordering": True,
            },
            "audit": {
                "log_to_file": False,
                "alert_on_reject": False,
            },
        }
    )

    validator_pub = validator.setup_relay_session(relay_val_pub)
    relay_val_engine.complete_handshake(validator_pub)

    validator.register_car_node(
        "mercedes_car",
        signer.public_key_bytes,
    )

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id="mercedes_car",
    )

    decryptor = RelayDecryptor(node_id="relay_01")
    decryptor.register_session("mercedes_car", relay_engine)

    reencryptor = RelayReencryptor(node_id="relay_01")
    reencryptor.register_validator_session(relay_val_engine)

    def make_packet():
        frame = sim.get_next_frame()
        packet = builder.build(frame)
        signed_packet = signer.sign_packet(packet)
        encrypted_packet = encryptor.encrypt_packet(signed_packet)
        relay_plaintext = decryptor.decrypt(encrypted_packet)
        return reencryptor.reencrypt(relay_plaintext)

    packet1 = make_packet()
    packet2 = make_packet()

    yield validator, packet1, packet2
