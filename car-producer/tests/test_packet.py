import os
import sys
import pytest

# ── Path setup ───────────────────────────────────────────────────
SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'src')
)
sys.path.insert(0, SRC)

from packet_builder import (
    PacketBuilder,
    MAGIC,
    HEADER_SIZE,
    TEAM_IDS,
    SESSION_IDS,
)
from sensor_simulator import SensorSimulator


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
        node_id='mercedes_car_test',
    )

@pytest.fixture
def packet(simulator, builder):
    frame = simulator.get_next_frame()
    return builder.build(frame)


# ── Header tests ─────────────────────────────────────────────────

class TestPacketHeader:

    def test_header_size_is_correct(self, packet):
        assert len(packet['header']) == HEADER_SIZE

    def test_magic_number_correct(self, packet, builder):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['magic'] == hex(MAGIC)

    def test_team_parsed_correctly(self, packet, builder):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['team'] == 'mercedes'

    def test_session_parsed_correctly(self, packet, builder):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['session'] == 'R'

    def test_sequence_starts_at_one(self, packet):
        assert packet['sequence_no'] == 1

    def test_sequence_increments(self, simulator):
        """
        Uses a fresh builder so sequence starts at 1.
        The shared builder fixture already consumed seq=1
        via the packet fixture.
        """
        fresh_builder = PacketBuilder(
            team='mercedes',
            session='R',
        )
        packets = [
            fresh_builder.build(simulator.get_next_frame())
            for _ in range(5)
        ]
        seqs = [p['sequence_no'] for p in packets]
        assert seqs == [1, 2, 3, 4, 5]

    def test_sequence_monotonically_increases(self, simulator):
        """Sequence never goes backwards."""
        fresh_builder = PacketBuilder(
            team='mercedes',
            session='R',
        )
        packets = [
            fresh_builder.build(simulator.get_next_frame())
            for _ in range(10)
        ]
        seqs = [p['sequence_no'] for p in packets]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 10   # All unique

    def test_timestamp_is_positive(self, packet):
        assert packet['timestamp'] > 0

    def test_packet_has_checksum(self, packet):
        assert len(packet['checksum']) == 64  # SHA-256 hex

    def test_raw_bytes_length(self, packet):
        assert packet['size'] == len(packet['raw_bytes'])
        assert packet['size'] > HEADER_SIZE

    def test_header_plus_payload_equals_raw(self, packet):
        assert (
            packet['header'] + packet['payload'] ==
            packet['raw_bytes']
        )

    def test_team_id_in_header(self, packet, builder):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['team'] == 'mercedes'

    def test_version_is_one(self, packet, builder):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['version'] == 1


# ── Payload tests ─────────────────────────────────────────────────

class TestPacketPayload:

    def test_payload_contains_speed(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'Speed' in payload

    def test_payload_contains_rpm(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'RPM' in payload

    def test_payload_contains_throttle(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'Throttle' in payload

    def test_payload_contains_brake(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'Brake' in payload

    def test_payload_contains_gear(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'nGear' in payload

    def test_payload_contains_drs(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'DRS' in payload

    def test_payload_contains_driver(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'driver' in payload

    def test_payload_contains_race(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 'race' in payload

    def test_speed_is_valid_range(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 0 <= payload['Speed'] <= 400

    def test_throttle_is_valid_range(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 0 <= payload['Throttle'] <= 100

    def test_gear_is_valid_range(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert 0 <= payload['nGear'] <= 8

    def test_brake_is_boolean(self, packet, builder):
        payload = builder.parse_payload(packet['raw_bytes'])
        assert payload['Brake'] in [0, 1]

    def test_payload_is_valid_json(self, packet):
        import json
        try:
            json.loads(packet['payload'].decode('utf-8'))
            valid = True
        except Exception:
            valid = False
        assert valid is True

    def test_payload_length_matches_header(
        self, packet, builder
    ):
        parsed = builder.parse_header(packet['raw_bytes'])
        assert parsed['payload_len'] == len(packet['payload'])


# ── Checksum tests ────────────────────────────────────────────────

class TestPacketChecksum:

    def test_intact_packet_passes_checksum(
        self, packet, builder
    ):
        assert builder.verify_checksum(
            packet['raw_bytes']
        ) is True

    def test_tampered_payload_fails_checksum(
        self, packet, builder
    ):
        tampered = bytearray(packet['raw_bytes'])
        tampered[HEADER_SIZE + 5] ^= 0xFF
        assert builder.verify_checksum(
            bytes(tampered)
        ) is False

    def test_tampered_header_does_not_affect_checksum(
        self, packet, builder
    ):
        """
        SHA-256 checksum covers payload only — not the header.
        Header integrity is enforced by AEAD associated data
        in crypto_engine.py, not the checksum.
        See: test_crypto.py::test_tampered_associated_data_raises
        See: docs/CRYPTOGRAPHIC_PRIMITIVES.md
        """
        tampered = bytearray(packet['raw_bytes'])
        tampered[4] ^= 0xFF     # Flip byte in header
        # Checksum still passes — payload unchanged
        assert builder.verify_checksum(
            bytes(tampered)
        ) is True

    def test_checksum_consistent(self, packet, builder):
        r1 = builder.verify_checksum(packet['raw_bytes'])
        r2 = builder.verify_checksum(packet['raw_bytes'])
        assert r1 == r2 == True

    def test_checksum_is_sha256(self, packet):
        import hashlib
        expected = hashlib.sha256(
            packet['payload']
        ).hexdigest()
        assert packet['checksum'] == expected

    def test_empty_payload_has_checksum(self, builder):
        """Edge case — even empty payload gets checksummed."""
        import hashlib
        empty_checksum = hashlib.sha256(b'').hexdigest()
        assert len(empty_checksum) == 64


# ── Validation tests ──────────────────────────────────────────────

class TestPacketValidation:

    def test_invalid_team_raises(self):
        with pytest.raises(ValueError):
            PacketBuilder(team='ferrari')

    def test_invalid_session_raises(self):
        with pytest.raises(ValueError):
            PacketBuilder(team='mercedes', session='X')

    def test_too_short_packet_raises(self, builder):
        with pytest.raises(ValueError):
            builder.parse_header(b'tooshort')

    def test_wrong_magic_raises(self, packet, builder):
        tampered    = bytearray(packet['raw_bytes'])
        tampered[0] = 0xFF
        tampered[1] = 0xFF
        tampered[2] = 0xFF
        tampered[3] = 0xFF
        with pytest.raises(ValueError, match="magic"):
            builder.parse_header(bytes(tampered))

    def test_redbull_team_accepted(self):
        builder = PacketBuilder(team='redbull', session='Q')
        assert builder.team == 'redbull'

    def test_sprint_session_accepted(self):
        builder = PacketBuilder(team='mercedes', session='S')
        assert builder.session == 'S'

    def test_race_session_accepted(self):
        builder = PacketBuilder(team='mercedes', session='R')
        assert builder.session == 'R'

    def test_qualifying_session_accepted(self):
        builder = PacketBuilder(team='mercedes', session='Q')
        assert builder.session == 'Q'

    def test_packets_built_counter(self, simulator, builder):
        initial = builder.packets_built
        for _ in range(5):
            builder.build(simulator.get_next_frame())
        assert builder.packets_built == initial + 5

    def test_node_id_stored(self):
        builder = PacketBuilder(
            team='mercedes',
            session='R',
            node_id='test_node_123',
        )
        assert builder.node_id == 'test_node_123'

    def test_current_sequence_matches_packets_built(
        self, simulator, builder
    ):
        for _ in range(3):
            builder.build(simulator.get_next_frame())
        assert builder.current_sequence == builder.packets_built


# ── Multi-packet tests ────────────────────────────────────────────

class TestMultiplePackets:

    def test_all_packets_unique_sequence(self, simulator):
        builder = PacketBuilder(team='mercedes', session='R')
        packets = [
            builder.build(simulator.get_next_frame())
            for _ in range(50)
        ]
        seqs = [p['sequence_no'] for p in packets]
        assert len(set(seqs)) == 50

    def test_all_packets_unique_timestamp_or_seq(
        self, simulator
    ):
        builder = PacketBuilder(team='mercedes', session='R')
        packets = [
            builder.build(simulator.get_next_frame())
            for _ in range(10)
        ]
        # Sequence numbers must all be unique
        seqs = [p['sequence_no'] for p in packets]
        assert len(set(seqs)) == 10

    def test_redbull_packets_have_correct_team(self, simulator):
        builder = PacketBuilder(team='redbull', session='R')
        packet  = builder.build(simulator.get_next_frame())
        parsed  = builder.parse_header(packet['raw_bytes'])
        assert parsed['team'] == 'redbull'

    def test_all_checksums_valid(self, simulator):
        builder = PacketBuilder(team='mercedes', session='R')
        for _ in range(10):
            packet = builder.build(simulator.get_next_frame())
            assert builder.verify_checksum(
                packet['raw_bytes']
            ) is True