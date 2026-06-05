# Protocol Specification — PitCrypt-F1

**Document:** PROTOCOL_SPEC.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## Overview

This document specifies the PitCrypt-F1 wire
protocol — the exact sequence of messages,
fields, and cryptographic operations that occur
between pipeline nodes.

The protocol operates over TCP with JSON-encoded
messages. Binary fields are hex-encoded for
transmission and decoded to bytes at each node.

---

## Protocol Phases
Phase 1: Key Exchange       ← ECDH handshake per pipeline leg
Phase 2: Session Active     ← Packet stream at up to 100Hz
Phase 3: Key Rotation       ← New ECDH exchange (transparent)
Phase 4: Session Teardown   ← End of session
---

## Phase 1 — Key Exchange

### 1.1 Car → Relay Handshake

Performed once per session before telemetry begins.
Both nodes generate fresh X25519 keypairs.

**Step 1 — Car generates keypair:**
```python
private_key  = X25519PrivateKey.generate()
public_key   = private_key.public_key()
car_pub_bytes = public_key.public_bytes(
    encoding=Raw,
    format=Raw,
)   # 32 bytes
```

**Step 2 — Car sends public key to relay:**
```json
{
  "type":       "key_exchange",
  "node_id":    "mercedes_car",
  "public_key": "<32-byte hex>",
  "team":       "mercedes",
  "session":    "R"
}
```

**Step 3 — Relay generates keypair, responds:**
```json
{
  "type":       "key_exchange_response",
  "node_id":    "relay_01",
  "public_key": "<32-byte hex>"
}
```

**Step 4 — Both derive shared secret:**
```python
# Car side
shared_secret = car_private.exchange(relay_public)

# Relay side
shared_secret = relay_private.exchange(car_public)

# Both sides now have same 32-byte shared secret
# via Diffie-Hellman — secret never transmitted
```

**Step 5 — Both derive session key via HKDF:**
```python
session_key = HKDF(
    algorithm=SHA256(),
    length=32,
    salt=None,
    info=b"pitcrypt-f1-encryption-v1",
).derive(shared_secret)
```

### 1.2 Relay → Validator Handshake

Identical protocol on relay → validator leg.
Produces an independent session key — completely
separate from car → relay key.

---

## Phase 2 — Session Active (Packet Protocol)

### 2.1 Packet Construction (Car Node)

For each telemetry frame:

**Step 1 — Build binary header (64 bytes):**
Struct format: !IBBBBQQI32sI
Field        Size  Value
─────────────────────────────────────────────
magic        4B    0x50435246 ("PCRF")
version      1B    0x01
team_id      1B    0x01=Mercedes, 0x02=Red Bull
session_id   1B    0x01=R, 0x02=Q, 0x03=S
packet_type  1B    0x01=telemetry
sequence_no  8B    monotonic uint64 starting at 1
timestamp    8B    UTC milliseconds since epoch
payload_len  4B    byte length of JSON payload
checksum    32B    SHA-256(payload_bytes)
reserved     4B    0x00000000
─────────────────────────────────────────────
Total:      64B
**Step 2 — Build JSON payload:**
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

Serialised with `separators=(',', ':')` — no
whitespace for compactness.

**Step 3 — Sign header + payload:**
```python
signed_data = header_bytes + payload_bytes
signature   = ed25519_private_key.sign(signed_data)
# signature: 64 bytes
```

**Step 4 — Generate ZKP commitment:**
```python
nonce      = os.urandom(32)
commitment = sha256(payload_bytes + nonce).hexdigest()
```

**Step 5 — Encrypt payload:**
```python
nonce_12   = os.urandom(12)
chacha     = ChaCha20Poly1305(session_key)
ciphertext = chacha.encrypt(
    nonce_12,
    payload_bytes,
    associated_data=header_bytes,  # authenticated, not encrypted
)
# ciphertext: len(payload) + 16 bytes (Poly1305 tag)
```

### 2.2 Transmission Format (Car → Relay)

JSON-encoded over TCP:

```json
{
  "nonce":       "<12-byte hex>",
  "ciphertext":  "<(payload_len + 16)-byte hex>",
  "header_hex":  "<64-byte hex>",
  "signature":   "<64-byte hex>",
  "sequence_no": 42,
  "timestamp":   1718200000000,
  "team":        "mercedes",
  "session":     "R",
  "node_id":     "mercedes_car"
}
```

**Note:** `zkp_commitment` and `zkp_nonce` are
transmitted as separate fields in the full
implementation and attached to the packet dict
before validator processing.

### 2.3 Relay Processing

**Step 1 — Parse and validate:**
```python
parsed = parser.parse_json_packet(raw_bytes)
errors = parser.validate_json_packet(parsed)
# Checks: required fields, valid team, valid session
# Reject if errors
```

**Step 2 — Decrypt car → relay leg:**
```python
plaintext = chacha.decrypt(
    nonce_bytes,
    ciphertext_bytes,
    associated_data=header_bytes,
)
# Raises InvalidTag if tampered — packet dropped
```

**Step 3 — Integrity check:**
sequence_no > last_seen_sequence  →  pass
sequence_no in seen_set           →  REJECT (replay)
signature present                 →  pass
signature absent                  →  REJECT

**Step 4 — Anomaly filter:**
Speed ∈ [-5, 400]    →  pass / REJECT if outside
RPM   ∈ [0, 16000]   →  pass / REJECT if outside
Throttle ∈ [0, 100]  →  pass / REJECT if outside
nGear ∈ [0, 8]       →  pass / REJECT if outside
Statistical threshold →  FLAG if outside bounds
**Step 5 — Re-encrypt for validator:**
```python
new_nonce  = os.urandom(12)
chacha_val = ChaCha20Poly1305(validator_session_key)
new_ct     = chacha_val.encrypt(
    new_nonce,
    plaintext,
    associated_data=header_bytes,
)
```

### 2.4 Transmission Format (Relay → Validator)

```json
{
  "nonce":           "<12-byte hex>",
  "ciphertext":      "<hex>",
  "header":          "<64-byte raw bytes>",
  "header_hex":      "<64-byte hex>",
  "signature":       "<64-byte hex>",
  "signature_bytes": "<64-byte raw bytes>",
  "sequence_no":     42,
  "timestamp":       1718200000000,
  "team":            "mercedes",
  "session":         "R",
  "node_id":         "mercedes_car",
  "original_node":   "mercedes_car",
  "reencrypted":     true,
  "zkp_commitment":  "<64-char hex>",
  "zkp_nonce":       "<64-char hex>"
}
```

### 2.5 Validator Processing

**Step 1 — Decrypt relay → validator leg:**
```python
plaintext = chacha.decrypt(
    nonce_bytes,
    ciphertext_bytes,
    associated_data=header_bytes,
)
```

**Step 2 — Verify Ed25519 signature:**
```python
# Signature was computed on original header + payload
# by the car. Verify against car's registered public key.
ed25519_public_key.verify(
    signature_bytes,
    header_bytes + plaintext,
)
# Raises InvalidSignature if tampered
```

**Step 3 — Sequence check:**
sequence_no > last_seq[node_id]    →  pass
sequence_no ≤ last_seq[node_id]    →  REJECT (out of order)
sequence_no in seen_seqs[node_id]  →  REJECT (replay)
**Step 4 — ZKP commitment verify:**
```python
nonce_bytes = bytes.fromhex(zkp_nonce)
computed    = sha256(plaintext + nonce_bytes).hexdigest()
computed == zkp_commitment   →  PASS
computed != zkp_commitment   →  REJECT (commitment mismatch)
```

**Step 5 — Audit log:**
```json
{
  "timestamp":   "2025-06-15T14:23:07Z",
  "decision":    "ACCEPT",
  "sequence_no": 42,
  "node_id":     "mercedes_car",
  "team":        "mercedes",
  "session":     "R",
  "reason":      "all_checks_passed",
  "details": {
    "sig":      "valid",
    "sequence": "valid",
    "zkp":      "commitment_valid"
  }
}
```

---

## Phase 3 — Key Rotation

Key rotation is transparent to the packet stream.
No session interruption.

### Rotation Trigger Conditions
IF session_age_seconds >= 300:
trigger rotation (reason: "age_exceeded")
ELIF packet_count >= 10000:
trigger rotation (reason: "count_exceeded")
Checked every 5 seconds by background thread.

### Rotation Protocol
Car Node                         Relay Node
│                                │
│  [trigger: age or count]       │
│  generate new X25519 keypair   │
│                                │
│──── new_public_key ───────────►│
│                                │  generate new keypair
│◄─── new_public_key ────────────│
│                                │
│  derive new shared secret      │  derive new shared secret
│  HKDF → new session key        │  HKDF → new session key
│                                │
│  discard old private key       │  discard old private key
│  discard old session key       │  discard old session key
│                                │
│  [continue sending packets     │
│   with new session key]        │
Identical protocol on relay → validator leg,
triggered by the same scheduler.

---

## Phase 4 — Session Teardown

No explicit teardown message defined in v1.0.
Sessions end when:
- Race session completes
- Node process exits
- Connection drops (TCP RST)

All session keys are garbage collected on
process exit — never persisted to disk.

---

## Error Handling

### Relay Error Responses

| Error | Condition | Action |
|---|---|---|
| `PacketParseError` | Invalid JSON or missing fields | Drop packet |
| `DecryptionError` | Unknown node_id | Drop packet |
| `InvalidTag` | AEAD tag mismatch (tampered) | Drop packet |
| Integrity REJECT | Replay or out-of-order | Drop packet |
| Anomaly REJECT | Physical impossibility | Drop packet |
| Anomaly FLAG | Statistical threshold | Forward with flag |

### Validator Error Responses

| Error | Condition | Action |
|---|---|---|
| `SignatureVerificationError` | Unknown node | REJECT + audit |
| `InvalidSignature` | Bad Ed25519 signature | REJECT + audit |
| Sequence REJECT | Replay or out-of-order | REJECT + audit |
| ZKP REJECT | Commitment mismatch | REJECT + audit |
| All pass | Valid packet | ACCEPT + audit |

---

## Protocol Versioning

Current protocol version: **1.0**

Version field in packet header (`0x01`) allows
future protocol evolution. Receivers must reject
unsupported versions. Version negotiation not
defined in v1.0 — handled by deployment
coordination.

---

## Protocol Constants

```python
MAGIC           = 0x50435246   # "PCRF"
VERSION         = 0x01
HEADER_SIZE     = 64           # bytes
NONCE_SIZE      = 12           # bytes (ChaCha20)
TAG_SIZE        = 16           # bytes (Poly1305)
SIGNATURE_SIZE  = 64           # bytes (Ed25519)
PUBLIC_KEY_SIZE = 32           # bytes (X25519 / Ed25519)
SESSION_KEY_SIZE = 32          # bytes (ChaCha20)

TEAM_IDS = {
    'mercedes': 0x01,
    'redbull':  0x02,
}

SESSION_IDS = {
    'R': 0x01,  # Race
    'Q': 0x02,  # Qualifying
    'S': 0x03,  # Sprint
}

PACKET_TYPES = {
    'telemetry': 0x01,
}
```

---

## See Also

- `docs/PACKET_FORMAT.md` — Binary packet format
- `docs/CRYPTOGRAPHIC_PRIMITIVES.md` — Primitive parameters
- `docs/KEY_MANAGEMENT.md` — Key lifecycle
- `car-producer/src/packet_builder.py` — Header implementation
- `car-producer/src/crypto_engine.py` — ECDH implementation
- `car-producer/src/encryptor.py` — Encryption implementation
- `relay-node/src/decryptor.py` — Decryption implementation
- `validator-node/src/main.py` — Full validator protocol