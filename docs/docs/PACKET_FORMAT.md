# Packet Format Specification

**Document:** PACKET_FORMAT.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## Overview

Every telemetry packet in PitCrypt-F1 follows a
fixed binary format consisting of a fixed-size header
and a variable-length JSON payload. The format is
designed to be:

- **Compact** — minimise bandwidth at 100Hz rates
- **Self-describing** — header contains all routing
  metadata without payload inspection
- **Tamper-evident** — SHA-256 checksum in header
  covers payload bytes
- **Authenticated** — AEAD authentication tag covers
  both header and payload

---

## Packet Structure
┌─────────────────────────────────────────────────────────────┐
│                     HEADER (64 bytes)                       │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│  Magic   │ Version  │ Team ID  │ Session  │  Packet Type    │
│ 4 bytes  │ 1 byte   │ 1 byte   │ 1 byte   │  1 byte         │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│                   Sequence Number                           │
│                      8 bytes                                │
├─────────────────────────────────────────────────────────────┤
│                     Timestamp (UTC ms)                      │
│                      8 bytes                                │
├─────────────────────────────────────────────────────────────┤
│                    Payload Length                           │
│                      4 bytes                                │
├─────────────────────────────────────────────────────────────┤
│                  SHA-256 Checksum                           │
│                     32 bytes                                │
├─────────────────────────────────────────────────────────────┤
│                    Reserved                                 │
│                     4 bytes                                 │
├─────────────────────────────────────────────────────────────┤
│                   PAYLOAD (variable)                        │
│              JSON-encoded telemetry data                    │
│         Speed · RPM · Throttle · Brake · Gear · DRS        │
└─────────────────────────────────────────────────────────────┘
**Total minimum size:** 64 bytes (header only)  
**Typical total size:** 180–220 bytes (header + payload)

---

## Header Field Definitions

### Magic Number (4 bytes, big-endian uint32)
Value: 0x50435246
ASCII: P C R F  (PitCrypt-F1)
First field validated on receipt. Any packet with
incorrect magic is immediately rejected without
further processing. This prevents garbage data
and mis-routed packets from consuming pipeline
resources.

### Protocol Version (1 byte, uint8)
Current: 0x01
Enables forward compatibility. Future protocol
changes increment this version. Receivers reject
unsupported versions.

### Team ID (1 byte, uint8)
0x01 = Mercedes AMG Petronas
0x02 = Red Bull Racing
Identifies the originating constructor. Used by
relay and validator to:
- Route packets to correct session key
- Apply team-specific anomaly thresholds
- Enforce IAM policy for the node

### Session Type (1 byte, uint8)
0x01 = Race (R)
0x02 = Qualifying (Q)
0x03 = Sprint (S)

Determines which session's telemetry context
applies. Sprint sessions have different packet
rate expectations than Race sessions.

### Packet Type (1 byte, uint8)
0x01 = Telemetry packet
Reserved for future packet types (key exchange
messages, heartbeat packets, control messages).
Currently only telemetry packets are defined.

### Sequence Number (8 bytes, big-endian uint64)

Monotonically increasing counter starting at 1.
Never resets during a session. Used by:

- `integrity_checker.py` at relay — detect
  out-of-order and replayed packets
- `sequence_checker.py` at validator — independent
  replay detection

The 64-bit field supports approximately
18.4 quintillion packets — no practical overflow
risk even at sustained 100Hz for the lifetime
of the sport.

### Timestamp (8 bytes, big-endian uint64)

UTC milliseconds since Unix epoch at packet
creation time on the car node. Used for:

- Timestamp freshness validation (30-second
  window at relay, 60-second at validator)
- Future timestamp anomaly detection
- Audit log correlation

### Payload Length (4 bytes, big-endian uint32)

Byte count of the payload section. Receivers
allocate exactly this many bytes after the
header. Mismatch between declared and actual
length triggers rejection.

### SHA-256 Checksum (32 bytes)
Covers the payload only — not the header.
Header integrity is protected separately by
the AEAD authentication tag.

The separation exists because:
- Checksum is computed before encryption
- AEAD tag covers both header and ciphertext
  after encryption
- Two independent integrity checks at
  different pipeline stages

### Reserved (4 bytes)

Zero-padded. Reserved for future use.
Receivers must not reject packets based on
reserved field content — forward compatibility.

---

## Struct Format String

The header is packed and unpacked using Python's
`struct` module with the format string:

```python
HEADER_FORMAT = '!IBBBBQQI32sI'
```

Field mapping:
! = big-endian network byte order
I = uint32  (magic)
B = uint8   (version)
B = uint8   (team_id)
B = uint8   (session_id)
B = uint8   (packet_type)
Q = uint64  (sequence_no)
Q = uint64  (timestamp_ms)
I = uint32  (payload_len)
32s = bytes (checksum, 32 bytes)
I = uint32  (reserved)
Computed header size:

```python
import struct
HEADER_SIZE = struct.calcsize('!IBBBBQQI32sI')  # = 64 bytes
```

---

## Payload Format

The payload is a compact JSON object with no
whitespace (uses `separators=(',', ':')` in
Python's `json.dumps`).

### Telemetry Payload Schema

```json
{
  "driver":      "RUS",
  "lap":         42,
  "race":        "Bahrain",
  "frame_index": 184320,
  "Speed":       287.4,
  "RPM":         12500.0,
  "Throttle":    98.2,
  "Brake":       0,
  "nGear":       7,
  "DRS":         12
}
```

### Field Definitions

| Field | Type | Unit | Range | Description |
|---|---|---|---|---|
| `driver` | string | — | 3-char code | Driver abbreviation |
| `lap` | int | — | 1–100 | Current lap number |
| `race` | string | — | — | Grand Prix name |
| `frame_index` | int | — | 1–∞ | Monotonic frame counter |
| `Speed` | float | km/h | -5 to 400 | Car speed |
| `RPM` | float | RPM | 0–15500 | Engine RPM |
| `Throttle` | float | % | 0–100 | Throttle position |
| `Brake` | int | — | 0 or 1 | Brake applied |
| `nGear` | int | — | 0–8 | Current gear |
| `DRS` | int | — | 0–14 | DRS state encoding |

### DRS State Encoding

FastF1 encodes DRS state as an integer:
0  = DRS disabled
8  = DRS eligible
10 = DRS detected
12 = DRS open
14 = DRS open + confirmed
---

## Encrypted Packet Format

After signing and encryption, the transmitted
packet has a different structure:
┌──────────────────────────────────────────────┐
│              Transmission Packet              │
├──────────────────────────────────────────────┤
│  nonce          (12 bytes, hex-encoded)       │
│  ciphertext     (payload + 16-byte auth tag)  │
│  header_hex     (64 bytes, hex-encoded)       │
│  signature      (64 bytes, hex-encoded)       │
│  sequence_no    (integer)                     │
│  timestamp      (integer, UTC ms)             │
│  team           (string)                      │
│  session        (string)                      │
│  node_id        (string)                      │
└──────────────────────────────────────────────┘
This JSON-encoded format is used for network
transmission. The relay and validator reconstruct
binary fields from hex strings on receipt.

---

## Packet Lifecycle

## Packet Lifecycle
Car Node
│
├─ sensor_simulator.py   → telemetry dict
├─ packet_builder.py     → binary header + JSON payload
├─ signer.py             → Ed25519 sign(header + payload)
├─ encryptor.py          → ChaCha20 encrypt(payload, aad=header)
└─ main.py               → JSON encode + TCP transmit
│
▼
Relay Node
├─ packet_parser.py      → parse + validate JSON
├─ decryptor.py          → AEAD decrypt(ciphertext, nonce, header)
├─ integrity_checker.py  → sequence + replay check
├─ anomaly_filters.py    → statistical bounds check
└─ reencryptor.py        → re-encrypt for validator leg
│
▼
Validator Node
├─ main.py               → AEAD decrypt(relay leg)
├─ signature_verifier.py → Ed25519 verify(header + payload)
├─ sequence_checker.py   → final replay defence
├─ zkp_verifier.py       → commitment verification
└─ audit_logger.py       → ACCEPT/REJECT/FLAG + log
---

## Source Reference

Implementation: `car-producer/src/packet_builder.py`  
Constants: `MAGIC`, `HEADER_FORMAT`, `HEADER_SIZE`,
`TEAM_IDS`, `SESSION_IDS`