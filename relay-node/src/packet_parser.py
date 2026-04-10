import os
import sys
import json
import struct
import hashlib
import logging
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))

from packet_builder import (
    MAGIC,
    HEADER_FORMAT,
    HEADER_SIZE,
    TEAM_IDS,
    SESSION_IDS,
)

"""
packet_parser.py

Deserializes and validates incoming packets at the relay node.

Responsibilities:
    1. Receive raw bytes from car producer
    2. Parse and validate header fields
    3. Verify magic number and protocol version
    4. Extract payload length and checksum
    5. Validate structural integrity before decryption
    6. Return structured packet dict for downstream processing

What it does NOT do:
    - Decrypt payload (decryptor.py)
    - Verify Ed25519 signature (integrity_checker.py)
    - Check sequence ordering (integrity_checker.py)
    - Filter anomalies (anomaly_filters.py)
"""

# ── Supported protocol versions ──────────────────────────────────
SUPPORTED_VERSIONS = {0x01}

# ── Supported packet types ───────────────────────────────────────
SUPPORTED_PACKET_TYPES = {0x01}   # 0x01 = telemetry


class PacketParseError(Exception):
    """Raised when a packet cannot be parsed."""
    pass


class PacketParser:
    """
    Parses and validates raw packet bytes at the relay node.
    First stage of relay processing pipeline.
    """

    def __init__(self, node_id: str = 'relay'):
        self.node_id          = node_id
        self._parsed_count    = 0
        self._rejected_count  = 0

        print(f"  [PacketParser] Initialised: {node_id}")

    def parse(self, raw_bytes: bytes) -> dict:
        """
        Parse raw bytes into a structured packet dict.

        Args:
            raw_bytes: Full binary packet from car producer

        Returns:
            Structured packet dict with fields:
                raw_bytes, header, payload_bytes,
                magic, version, team, session,
                sequence_no, timestamp_ms,
                payload_len, checksum,
                is_valid, parse_errors

        Raises:
            PacketParseError: If packet is malformed
        """
        errors = []

        # ── Length check ─────────────────────────────────────────
        if len(raw_bytes) < HEADER_SIZE:
            self._rejected_count += 1
            raise PacketParseError(
                f"Packet too short: {len(raw_bytes)} bytes. "
                f"Minimum: {HEADER_SIZE}."
            )

        # ── Unpack header ────────────────────────────────────────
        try:
            (
                magic, version, team_id, session_id,
                packet_type, sequence_no, timestamp_ms,
                payload_len, checksum, reserved
            ) = struct.unpack(
                HEADER_FORMAT, raw_bytes[:HEADER_SIZE]
            )
        except struct.error as e:
            self._rejected_count += 1
            raise PacketParseError(
                f"Header unpack failed: {e}"
            )

        # ── Magic number ─────────────────────────────────────────
        if magic != MAGIC:
            self._rejected_count += 1
            raise PacketParseError(
                f"Invalid magic: {hex(magic)}. "
                f"Expected: {hex(MAGIC)}"
            )

        # ── Protocol version ─────────────────────────────────────
        if version not in SUPPORTED_VERSIONS:
            errors.append(
                f"Unsupported version: {version}"
            )

        # ── Packet type ──────────────────────────────────────────
        if packet_type not in SUPPORTED_PACKET_TYPES:
            errors.append(
                f"Unsupported packet type: {packet_type}"
            )

        # ── Team ID ──────────────────────────────────────────────
        team = next(
            (k for k, v in TEAM_IDS.items() if v == team_id),
            None
        )
        if team is None:
            errors.append(f"Unknown team ID: {team_id}")

        # ── Session ID ───────────────────────────────────────────
        session = next(
            (k for k, v in SESSION_IDS.items()
             if v == session_id),
            None
        )
        if session is None:
            errors.append(f"Unknown session ID: {session_id}")

        # ── Payload extraction ───────────────────────────────────
        payload_bytes = raw_bytes[
            HEADER_SIZE: HEADER_SIZE + payload_len
        ]

        if len(payload_bytes) != payload_len:
            errors.append(
                f"Payload length mismatch: "
                f"got {len(payload_bytes)}, "
                f"expected {payload_len}"
            )

        # ── Checksum validation ──────────────────────────────────
        actual_checksum = hashlib.sha256(payload_bytes).digest()
        checksum_valid  = actual_checksum == checksum

        if not checksum_valid:
            errors.append("SHA-256 checksum mismatch")

        # ── Sequence number ──────────────────────────────────────
        if sequence_no == 0:
            errors.append("Sequence number cannot be zero")

        # ── Timestamp ────────────────────────────────────────────
        if timestamp_ms == 0:
            errors.append("Timestamp cannot be zero")

        is_valid = len(errors) == 0

        if is_valid:
            self._parsed_count += 1
        else:
            self._rejected_count += 1
            logging.warning(
                f"[PacketParser] Packet errors: {errors}"
            )

        return {
            'raw_bytes':       raw_bytes,
            'header':          raw_bytes[:HEADER_SIZE],
            'payload_bytes':   payload_bytes,
            'magic':           hex(magic),
            'version':         version,
            'team':            team,
            'session':         session,
            'packet_type':     packet_type,
            'sequence_no':     sequence_no,
            'timestamp_ms':    timestamp_ms,
            'payload_len':     payload_len,
            'checksum':        checksum.hex(),
            'checksum_valid':  checksum_valid,
            'is_valid':        is_valid,
            'parse_errors':    errors,
        }

    def parse_json_packet(self, json_bytes: bytes) -> dict:
        """
        Parse a JSON-encoded encrypted packet received
        over the network from the car producer.

        This is the transmission format used by
        car-producer/src/main.py _send_packet().

        Args:
            json_bytes: JSON-encoded packet bytes

        Returns:
            Parsed transmission packet dict
        """
        try:
            data = json.loads(json_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PacketParseError(
                f"Invalid JSON packet: {e}"
            )

        required = [
            'nonce', 'ciphertext', 'header_hex',
            'signature', 'sequence_no', 'timestamp',
            'team', 'session', 'node_id',
        ]
        missing = [f for f in required if f not in data]
        if missing:
            raise PacketParseError(
                f"Missing required fields: {missing}"
            )

        # Convert hex strings back to bytes
        data['nonce_bytes']      = bytes.fromhex(data['nonce'])
        data['ciphertext_bytes'] = bytes.fromhex(
            data['ciphertext']
        )
        data['header']           = bytes.fromhex(
            data['header_hex']
        )

        self._parsed_count += 1
        return data

    def validate_json_packet(self, packet: dict) -> list:
        """
        Validate a parsed JSON packet dict.
        Returns list of validation errors (empty = valid).
        """
        errors = []

        # Team validation
        if packet.get('team') not in ['mercedes', 'redbull']:
            errors.append(
                f"Unknown team: {packet.get('team')}"
            )

        # Session validation
        if packet.get('session') not in ['R', 'Q', 'S']:
            errors.append(
                f"Unknown session: {packet.get('session')}"
            )

        # Sequence validation
        seq = packet.get('sequence_no', 0)
        if not isinstance(seq, int) or seq <= 0:
            errors.append(
                f"Invalid sequence: {seq}"
            )

        # Nonce size
        nonce = packet.get('nonce_bytes', b'')
        if len(nonce) != 12:
            errors.append(
                f"Invalid nonce size: {len(nonce)}"
            )

        # Node ID
        if not packet.get('node_id'):
            errors.append("Missing node_id")

        return errors

    # ── Properties ───────────────────────────────────────────────

    @property
    def parsed_count(self) -> int:
        return self._parsed_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    sys.path.insert(
        0, os.path.join(ROOT, 'car-producer', 'src')
    )
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor
    from crypto_engine    import CryptoEngine

    print("\n" + "="*55)
    print("  PacketParser — Self Test")
    print("="*55)

    # Setup
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    car_engine   = CryptoEngine(node_id='mercedes_car')
    relay_engine = CryptoEngine(node_id='relay_01')
    car_pub      = car_engine.new_session()
    relay_pub    = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id='mercedes_car',
    )
    parser = PacketParser(node_id='relay_01')

    # ── Test 1: Parse valid binary packet ───────────────────────
    print("\n[Test 1] Parse valid binary packet")
    frame     = sim.get_next_frame()
    packet    = builder.build(frame)
    signed    = signer.sign_packet(packet)
    encrypted = encryptor.encrypt_packet(signed)

    parsed = parser.parse(signed['raw_bytes'])
    print(f"  Team:     {parsed['team']}")
    print(f"  Session:  {parsed['session']}")
    print(f"  Seq:      {parsed['sequence_no']}")
    print(f"  Valid:    {parsed['is_valid']}")
    print(f"  Errors:   {parsed['parse_errors']}")
    assert parsed['is_valid'] is True
    print(f"  Parse valid packet: ✅")

    # ── Test 2: Parse JSON encrypted packet ─────────────────────
    print("\n[Test 2] Parse JSON encrypted packet")
    import json as _json
    json_data = {
        'nonce':       encrypted['nonce'],
        'ciphertext':  encrypted['ciphertext'],
        'header_hex':  encrypted['header_hex'],
        'signature':   encrypted['signature'],
        'sequence_no': encrypted['sequence_no'],
        'timestamp':   encrypted['timestamp'],
        'team':        encrypted['team'],
        'session':     encrypted['session'],
        'node_id':     encrypted['node_id'],
    }
    json_bytes = _json.dumps(json_data).encode()
    parsed_json = parser.parse_json_packet(json_bytes)
    errors = parser.validate_json_packet(parsed_json)

    print(f"  Team:    {parsed_json['team']}")
    print(f"  Seq:     {parsed_json['sequence_no']}")
    print(f"  Errors:  {errors}")
    assert errors == []
    print(f"  Parse JSON packet: ✅")

    # ── Test 3: Reject malformed packet ─────────────────────────
    print("\n[Test 3] Reject malformed packet")
    try:
        parser.parse(b'this is not a valid packet')
        print("  ❌ FAIL — should have raised")
    except PacketParseError as e:
        print(f"  Rejected: {e} ✅")

    # ── Test 4: Detect checksum mismatch ────────────────────────
    print("\n[Test 4] Detect checksum mismatch")
    tampered = bytearray(signed['raw_bytes'])
    tampered[HEADER_SIZE + 3] ^= 0xFF
    result = parser.parse(bytes(tampered))
    assert result['checksum_valid'] is False
    print(f"  Checksum mismatch detected: ✅")

    print(f"\n  Parsed:   {parser.parsed_count}")
    print(f"  Rejected: {parser.rejected_count}")
    print(f"\n✅ PacketParser self-test complete.")