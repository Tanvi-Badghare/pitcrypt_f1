import os
import json
import struct
import hashlib
import time
import sys
from datetime import datetime, timezone
from typing import Optional

# ── Root path ────────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)

# ── Protocol constants ───────────────────────────────────────────
MAGIC           = 0x50435246        # ASCII: PCRF (PitCrypt-F1)
PROTOCOL_VER    = 0x01
PACKET_TYPE_TEL = 0x01

TEAM_IDS = {
    'mercedes': 0x01,
    'redbull':  0x02,
}

SESSION_IDS = {
    'R': 0x01,
    'Q': 0x02,
    'S': 0x03,
}

HEADER_FORMAT = '!IBBBBQQI32sI'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)


class PacketBuilder:

    def __init__(
        self,
        team:    str,
        session: str = 'R',
        node_id: str = None,
    ):
        self.team    = team.lower()
        self.session = session.upper()
        self.node_id = node_id or f"{self.team}_{self.session}_node"

        if self.team not in TEAM_IDS:
            raise ValueError(
                f"Invalid team: '{team}'. "
                f"Use 'mercedes' or 'redbull'."
            )
        if self.session not in SESSION_IDS:
            raise ValueError(
                f"Invalid session: '{session}'. "
                f"Use 'R', 'Q', or 'S'."
            )

        self._sequence      = 0
        self._packets_built = 0
        self._start_time    = datetime.now(timezone.utc)

        print(f"  [PacketBuilder] Team:    {self.team.upper()}")
        print(f"  [PacketBuilder] Session: {self.session}")
        print(f"  [PacketBuilder] Node:    {self.node_id}")
        print(f"  [PacketBuilder] Header:  {HEADER_SIZE} bytes")

    # ── Private ──────────────────────────────────────────────────

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _timestamp_ms(self) -> int:
        return int(time.time() * 1000)

    def _build_payload(self, frame: dict) -> bytes:
        payload_data = {
            'driver':      frame.get('driver',      'UNK'),
            'lap':         frame.get('lap',          0),
            'race':        frame.get('race',         ''),
            'frame_index': frame.get('frame_index',  0),
            'Speed':       frame.get('Speed',        0.0),
            'RPM':         frame.get('RPM',          0.0),
            'Throttle':    frame.get('Throttle',     0.0),
            'Brake':       frame.get('Brake',        0),
            'nGear':       frame.get('nGear',        0),
            'DRS':         frame.get('DRS',          0),
        }
        return json.dumps(
            payload_data, separators=(',', ':')
        ).encode('utf-8')

    def _compute_checksum(self, payload: bytes) -> bytes:
        return hashlib.sha256(payload).digest()

    def _build_header(
        self,
        sequence_no:  int,
        timestamp_ms: int,
        payload:      bytes,
        checksum:     bytes,
    ) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            MAGIC,
            PROTOCOL_VER,
            TEAM_IDS[self.team],
            SESSION_IDS[self.session],
            PACKET_TYPE_TEL,
            sequence_no,
            timestamp_ms,
            len(payload),
            checksum,
            0,
        )

    # ── Public ───────────────────────────────────────────────────

    def build(self, frame: dict) -> dict:
        seq      = self._next_sequence()
        ts       = self._timestamp_ms()
        payload  = self._build_payload(frame)
        checksum = self._compute_checksum(payload)
        header   = self._build_header(seq, ts, payload, checksum)
        raw      = header + payload

        self._packets_built += 1

        return {
            'raw_bytes':   raw,
            'header':      header,
            'payload':     payload,
            'sequence_no': seq,
            'timestamp':   ts,
            'checksum':    checksum.hex(),
            'team':        self.team,
            'session':     self.session,
            'node_id':     self.node_id,
            'size':        len(raw),
        }

    def parse_header(self, raw_bytes: bytes) -> dict:
        if len(raw_bytes) < HEADER_SIZE:
            raise ValueError(
                f"Packet too short: {len(raw_bytes)} bytes. "
                f"Minimum: {HEADER_SIZE}."
            )

        (
            magic, version, team_id, session_id,
            packet_type, sequence_no, timestamp_ms,
            payload_len, checksum, reserved
        ) = struct.unpack(HEADER_FORMAT, raw_bytes[:HEADER_SIZE])

        if magic != MAGIC:
            raise ValueError(
                f"Invalid magic: {hex(magic)}. "
                f"Expected: {hex(MAGIC)}"
            )

        # Reverse lookup names
        team = next(
            (k for k, v in TEAM_IDS.items()    if v == team_id),
            'unknown'
        )
        session = next(
            (k for k, v in SESSION_IDS.items() if v == session_id),
            'unknown'
        )

        return {
            'magic':        hex(magic),
            'version':      version,
            'team':         team,
            'session':      session,
            'packet_type':  packet_type,
            'sequence_no':  sequence_no,
            'timestamp_ms': timestamp_ms,
            'payload_len':  payload_len,
            'checksum':     checksum.hex(),
        }

    def parse_payload(self, raw_bytes: bytes) -> dict:
        header        = self.parse_header(raw_bytes)
        payload_bytes = raw_bytes[
            HEADER_SIZE: HEADER_SIZE + header['payload_len']
        ]
        return json.loads(payload_bytes.decode('utf-8'))

    def verify_checksum(self, raw_bytes: bytes) -> bool:
        header  = self.parse_header(raw_bytes)
        payload = raw_bytes[
            HEADER_SIZE: HEADER_SIZE + header['payload_len']
        ]
        return (
            hashlib.sha256(payload).hexdigest() == header['checksum']
        )

    @property
    def packets_built(self) -> int:
        return self._packets_built

    @property
    def current_sequence(self) -> int:
        return self._sequence


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    # Add src to path so sensor_simulator can be imported
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sensor_simulator import SensorSimulator

    print("\n" + "="*50)
    print("  PacketBuilder — Self Test")
    print("="*50)

    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')

    print(f"\n[Test 1] Build 5 packets")
    for i in range(5):
        frame  = sim.get_next_frame()
        packet = builder.build(frame)
        print(
            f"  Packet {i+1}: "
            f"seq={packet['sequence_no']} | "
            f"size={packet['size']} bytes | "
            f"checksum={packet['checksum'][:12]}..."
        )

    print(f"\n[Test 2] Parse header")
    frame   = sim.get_next_frame()
    packet  = builder.build(frame)
    parsed  = builder.parse_header(packet['raw_bytes'])
    payload = builder.parse_payload(packet['raw_bytes'])

    print(f"  Magic:    {parsed['magic']}")
    print(f"  Team:     {parsed['team']}")
    print(f"  Session:  {parsed['session']}")
    print(f"  Sequence: {parsed['sequence_no']}")
    print(f"  Speed:    {payload['Speed']} km/h")
    print(f"  RPM:      {payload['RPM']}")

    print(f"\n[Test 3] Checksum verification")
    intact = builder.verify_checksum(packet['raw_bytes'])
    print(f"  Intact:   {intact} (should be True)")

    tampered      = bytearray(packet['raw_bytes'])
    tampered[HEADER_SIZE + 5] ^= 0xFF
    tampered_result = builder.verify_checksum(bytes(tampered))
    print(f"  Tampered: {tampered_result} (should be False)")

    print(f"\n  Total built: {builder.packets_built}")
    print(f"\n✅ PacketBuilder self-test complete.")