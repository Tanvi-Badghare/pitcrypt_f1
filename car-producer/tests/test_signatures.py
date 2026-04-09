import os
import sys
import pytest

# ── Path setup ───────────────────────────────────────────────────
SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'src')
)
sys.path.insert(0, SRC)

from signer import PacketSigner, SignatureVerifier
from packet_builder import PacketBuilder
from sensor_simulator import SensorSimulator
from cryptography.exceptions import InvalidSignature


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def simulator():
    return SensorSimulator(
        team='mercedes',
        race='Bahrain',
        session='R',
        add_noise=False,
    )

@pytest.fixture
def builder():
    return PacketBuilder(
        team='mercedes',
        session='R',
    )

@pytest.fixture
def signer():
    return PacketSigner(node_id='mercedes_car_test')

@pytest.fixture
def verifier(signer):
    v = SignatureVerifier()
    v.register_node('mercedes_car_test', signer.public_key_bytes)
    return v

@pytest.fixture
def signed_packet(simulator, builder, signer):
    frame  = simulator.get_next_frame()
    packet = builder.build(frame)
    return signer.sign_packet(packet)


# ── PacketSigner tests ────────────────────────────────────────────

class TestPacketSigner:

    def test_generates_32_byte_public_key(self, signer):
        assert len(signer.public_key_bytes) == 32

    def test_generates_32_byte_private_key(self, signer):
        assert len(signer.private_key_bytes) == 32

    def test_two_signers_have_different_keys(self):
        s1 = PacketSigner(node_id='node1')
        s2 = PacketSigner(node_id='node2')
        assert s1.public_key_bytes != s2.public_key_bytes

    def test_sign_packet_adds_signature(self, signed_packet):
        assert 'signature' in signed_packet
        assert len(signed_packet['signature']) == 128  # hex

    def test_sign_packet_adds_signature_bytes(
        self, signed_packet
    ):
        assert 'signature_bytes' in signed_packet
        assert len(signed_packet['signature_bytes']) == 64

    def test_sign_packet_adds_node_id(self, signed_packet):
        assert signed_packet['signer_node_id'] == \
               'mercedes_car_test'

    def test_sign_packet_adds_signed_at(self, signed_packet):
        assert 'signed_at' in signed_packet

    def test_sign_packet_preserves_header(
        self, signed_packet, simulator, builder
    ):
        frame   = simulator.get_next_frame()
        packet  = builder.build(frame)
        signed  = PacketSigner(
            node_id='test'
        ).sign_packet(packet)
        assert signed['header'] == packet['header']

    def test_sign_packet_preserves_payload(
        self, signed_packet, simulator, builder
    ):
        frame   = simulator.get_next_frame()
        packet  = builder.build(frame)
        signed  = PacketSigner(
            node_id='test'
        ).sign_packet(packet)
        assert signed['payload'] == packet['payload']

    def test_sign_count_increments(
        self, signer, simulator, builder
    ):
        for _ in range(5):
            frame  = simulator.get_next_frame()
            packet = builder.build(frame)
            signer.sign_packet(packet)
        assert signer.sign_count == 5

    def test_missing_header_raises(self, signer):
        with pytest.raises(ValueError):
            signer.sign_packet({'payload': b'test'})

    def test_missing_payload_raises(self, signer):
        with pytest.raises(ValueError):
            signer.sign_packet({'header': b'test'})

    def test_sign_bytes_returns_64_bytes(self, signer):
        sig = signer.sign_bytes(b'test data')
        assert len(sig) == 64

    def test_deterministic_signing(self, signer):
        """Ed25519 is deterministic — same data = same sig."""
        data = b'test payload data'
        sig1 = signer.sign_bytes(data)
        sig2 = signer.sign_bytes(data)
        assert sig1 == sig2


# ── SignatureVerifier tests ───────────────────────────────────────

class TestSignatureVerifier:

    def test_register_node(self, signer):
        v = SignatureVerifier()
        v.register_node('test_node', signer.public_key_bytes)
        assert v.is_registered('test_node')

    def test_invalid_key_length_raises(self):
        v = SignatureVerifier()
        with pytest.raises(ValueError):
            v.register_node('test', b'tooshort')

    def test_unregistered_node_raises(
        self, signed_packet
    ):
        v = SignatureVerifier()
        with pytest.raises(ValueError, match="Unknown"):
            v.verify_packet(signed_packet)

    def test_valid_signature_returns_true(
        self, signed_packet, verifier
    ):
        result = verifier.verify_packet(signed_packet)
        assert result is True

    def test_tampered_payload_raises(
        self, signed_packet, verifier
    ):
        tampered = dict(signed_packet)
        payload  = bytearray(signed_packet['payload'])
        payload[5] ^= 0xFF
        tampered['payload'] = bytes(payload)
        with pytest.raises(InvalidSignature):
            verifier.verify_packet(tampered)

    def test_tampered_header_raises(
        self, signed_packet, verifier
    ):
        tampered = dict(signed_packet)
        header   = bytearray(signed_packet['header'])
        header[8] ^= 0xFF
        tampered['header'] = bytes(header)
        with pytest.raises(InvalidSignature):
            verifier.verify_packet(tampered)

    def test_wrong_signature_raises(
        self, signed_packet, verifier
    ):
        tampered = dict(signed_packet)
        tampered['signature_bytes'] = os.urandom(64)
        with pytest.raises(InvalidSignature):
            verifier.verify_packet(tampered)

    def test_missing_node_id_raises(
        self, signed_packet, verifier
    ):
        tampered = dict(signed_packet)
        del tampered['signer_node_id']
        with pytest.raises(ValueError):
            verifier.verify_packet(tampered)

    def test_verify_count_increments(
        self, signed_packet, verifier,
        simulator, builder, signer
    ):
        for _ in range(3):
            frame  = simulator.get_next_frame()
            packet = builder.build(frame)
            sp     = signer.sign_packet(packet)
            verifier.verify_packet(sp)
        assert verifier.verify_count == 3

    def test_fail_count_increments(
        self, signed_packet, verifier
    ):
        tampered = dict(signed_packet)
        payload  = bytearray(signed_packet['payload'])
        payload[0] ^= 0xFF
        tampered['payload'] = bytes(payload)
        try:
            verifier.verify_packet(tampered)
        except InvalidSignature:
            pass
        assert verifier.fail_count == 1

    def test_registered_nodes_list(self, verifier):
        assert 'mercedes_car_test' in verifier.registered_nodes

    def test_multiple_nodes_registered(self, signer):
        v  = SignatureVerifier()
        s2 = PacketSigner(node_id='redbull_car')
        v.register_node('mercedes_car', signer.public_key_bytes)
        v.register_node('redbull_car',  s2.public_key_bytes)
        assert len(v.registered_nodes) == 2

    def test_cross_node_signature_rejected(
        self, signed_packet
    ):
        """Mercedes packet rejected by Red Bull verifier."""
        rbr_signer   = PacketSigner(node_id='redbull_car')
        rbr_verifier = SignatureVerifier()
        rbr_verifier.register_node(
            'redbull_car', rbr_signer.public_key_bytes
        )
        with pytest.raises(ValueError, match="Unknown"):
            rbr_verifier.verify_packet(signed_packet)

    def test_verify_bytes_valid(self, signer):
        v    = SignatureVerifier()
        v.register_node('test_node', signer.public_key_bytes)
        data = b'test raw bytes'
        sig  = signer.sign_bytes(data)
        result = v.verify_bytes('test_node', sig, data)
        assert result is True

    def test_verify_bytes_tampered_raises(self, signer):
        v    = SignatureVerifier()
        v.register_node('test_node', signer.public_key_bytes)
        data = b'test raw bytes'
        sig  = signer.sign_bytes(data)
        with pytest.raises(InvalidSignature):
            v.verify_bytes('test_node', sig, b'tampered data')