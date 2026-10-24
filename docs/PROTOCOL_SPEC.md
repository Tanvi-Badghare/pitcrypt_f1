# Protocol Specification — PitCrypt-F1

**Document:** `docs/PROTOCOL_SPEC.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Implementation-aligned specification; integration gaps documented  
**Last updated:** 24 October 2026

---

## 1. Overview

This document describes the intended communication protocol between the PitCrypt-F1 producer, relay, and validator components. It covers the packet lifecycle, cryptographic operations, envelope representation, validation behavior, session management, error handling, and protocol versioning.

The design uses a binary telemetry header and JSON-encoded encrypted packet envelopes. Binary fields are represented as hexadecimal strings where required by the envelope.

This specification distinguishes three levels of behavior:

- **Confirmed:** Supported by source code reviewed to date.
- **Configurable:** Implemented behavior whose activation depends on configuration.
- **Unverified:** Behavior described by the original protocol design that still requires confirmation against the relevant implementation and integration tests.

PitCrypt-F1 is a research prototype. This document does not establish production deployment, FIA approval, or compliance with motorsport regulations.

## 2. Protocol Phases

The intended protocol lifecycle consists of four phases.

| Phase | Purpose | Status |
|---|---|---|
| Phase 1 — Key exchange | Establish independent cryptographic sessions for the producer-to-relay and relay-to-validator legs | Session setup methods and X25519-related components are present; exact wire handshake remains to be verified |
| Phase 2 — Active packet processing | Build, sign, encrypt, validate, filter, and forward telemetry | Core producer and relay processing components are present |
| Phase 3 — Key rotation | Refresh session keys according to age or packet-count policy | Rotation thresholds and transparent end-to-end operation require verification |
| Phase 4 — Session teardown | End sessions and release associated resources | Explicit teardown protocol and cleanup guarantees require verification |

The phases describe the intended architecture. They should not be interpreted as proof that every lifecycle transition is implemented end to end.

---

## 3. Phase 1 — Key Exchange

### 3.1 Cryptographic design

The intended design establishes a separate cryptographic session for each communication leg:

1. Producer to relay.
2. Relay to validator.

The project contains `CryptoEngine` components and session-setup methods that exchange public-key material and register session engines with the appropriate encryptor or decryptor.

The reviewed relay source includes:

- `setup_car_session()`
- `setup_validator_session()`
- `_simulate_sessions()`

These methods establish or simulate cryptographic sessions. The simulation method creates local engines, exchanges public keys, completes handshakes, and registers the resulting engines with the relay's decryption and re-encryption components.

**Implementation qualification:** The existence of these methods does not establish the complete TCP handshake protocol, including message framing, message authentication, error responses, timeout behavior, or interoperability between independently running processes.

### 3.2 Intended key-exchange algorithm

The protocol design specifies X25519 for Diffie–Hellman key agreement.

Conceptually, each endpoint generates a private/public keypair and exchanges its public key. Both endpoints then calculate the same shared secret:

```python
shared_secret = private_key.exchange(peer_public_key)
```

The shared secret is not transmitted directly.

The exact key-generation calls, public-key serialization, validation of received public keys, and handshake-message format must be confirmed against the active `crypto_engine.py` implementation before this section is treated as a complete wire-level specification.

### 3.3 Session-key derivation

The original protocol design specifies HKDF-SHA256 to derive a 32-byte session key, using the following parameters:

```python
HKDF(
    algorithm=SHA256(),
    length=32,
    salt=None,
    info=b"pitcrypt-f1-encryption-v1",
)
```

These parameters describe the intended derivation, but they should be treated as **unverified until matched to the actual implementation**.

A complete implementation-aligned specification should document:

- The actual HKDF algorithm and output length.
- The salt value or salt-generation strategy.
- The `info` context string.
- Whether both communication legs use distinct derivation contexts.
- How session identifiers and peer identities are bound to the derived key.
- What happens if key exchange or derivation fails.

Do not assume that separate session-engine instances automatically guarantee cryptographic domain separation.

### 3.4 Producer-to-relay handshake

The intended exchange is:

1. The producer generates its ephemeral public/private keypair.
2. The producer sends its public key and associated identity/session metadata.
3. The relay generates its own keypair.
4. The relay returns its public key.
5. Both sides derive and register the session key.

The original design uses message types such as `key_exchange` and `key_exchange_response`.

The exact JSON message fields and the actual network handling of these messages remain to be verified. They must not be treated as authoritative wire-format definitions until the handshake sender and receiver code has been inspected.

### 3.5 Relay-to-validator handshake

The intended relay-to-validator exchange follows the same general key-agreement model but establishes a separate session for the second communication leg.

The relay source contains `setup_validator_session()` and simulation logic for registering a validator-side session with the re-encryptor.

The exact key-exchange messages, derivation parameters, authentication of the peer, and failure behavior remain open verification items.

---

## 4. Phase 2 — Active Packet Processing

### 4.1 End-to-end packet lifecycle

The intended telemetry lifecycle is:

1. Obtain a telemetry frame.
2. Serialize the telemetry payload.
3. Construct the binary header.
4. Sign the header and plaintext payload.
5. Encrypt the payload with the header as authenticated associated data.
6. Serialize the encrypted packet into a JSON envelope.
7. Deliver the envelope to the relay.
8. Parse and validate the envelope.
9. Decrypt the payload.
10. Perform relay integrity and sequence checks.
11. Apply anomaly filtering.
12. Re-encrypt packets that pass the relay policy.
13. Deliver the resulting packet to the validator.
14. Apply validator-side signature, sequence, and any configured commitment checks.
15. Record the resulting decision where the audit path is invoked.

The producer and relay components support important parts of this lifecycle. The exact end-to-end validator ordering and all wire-level integration details remain to be confirmed.

### 4.2 Binary header

The producer defines the header using:

```python
HEADER_FORMAT = '!IBBBBQQI32sI'
HEADER_SIZE = 64
```

The header is 64 bytes long and uses network byte order.

| Field | Size | Description |
|---|---:|---|
| `magic` | 4 bytes | Protocol identifier `0x50435246` (`PCRF`) |
| `protocol_version` | 1 byte | Current version identifier `0x01` |
| `team_id` | 1 byte | Encoded team identifier |
| `session_id` | 1 byte | Encoded session identifier |
| `packet_type` | 1 byte | Telemetry packet type `0x01` |
| `sequence_no` | 8 bytes | Packet sequence number |
| `timestamp_ms` | 8 bytes | Producer timestamp in Unix epoch milliseconds |
| `payload_len` | 4 bytes | Serialized payload length |
| `checksum` | 32 bytes | SHA-256 digest of the serialized payload |
| `reserved` | 4 bytes | Reserved field, currently packed as zero |
| **Total** | **64 bytes** | |

The complete numeric mappings for team and session identifiers must be maintained against the producer's `TEAM_IDS` and `SESSION_IDS` constants.

Refer to `docs/PACKET_FORMAT.md` for the detailed field layout and payload specification.

### 4.3 Telemetry payload

The payload is serialized as compact JSON. The documented fields include:

- `driver`
- `lap`
- `race`
- `frame_index`
- `Speed`
- `RPM`
- `Throttle`
- `Brake`
- `nGear`
- `DRS`

Additional fields may be present in newer telemetry configurations.

The precise payload schema is determined by the current producer and telemetry-channel configuration. Do not assume the field list above is exhaustive unless the implementation enforces it.

### 4.4 Packet signing

The reviewed producer signer constructs the signing input as:

```python
signed_data = header_bytes + payload_bytes
```

The packet is signed using Ed25519. The resulting signature is 64 bytes.

Signature verification must use the exact original header and serialized plaintext payload bytes, along with the corresponding trusted public key.

The signature covers the header and payload. It does not independently authenticate the key-exchange messages or prove that a public key belongs to a trusted team; those properties depend on the key-registration and identity-binding design.

### 4.5 Payload encryption

The producer encryptor uses a ChaCha20-Poly1305 AEAD interface.

The intended operation is:

```python
ciphertext = chacha.encrypt(
    nonce_12,
    payload_bytes,
    associated_data=header_bytes,
)
```

The reviewed producer implementation supplies the header as associated data.

Consequently:

- The payload is encrypted.
- The header is authenticated as associated data but is not encrypted by this operation.
- The ciphertext includes the AEAD authentication tag.
- The nonce is 12 bytes for the reviewed ChaCha20-Poly1305 usage.
- The authentication tag is 16 bytes.

Nonce uniqueness under a given key is a security requirement. A production guarantee requires an explicit nonce and key lifecycle strategy that addresses concurrent producers, process restarts, and key changes.

### 4.6 Checksum limitation

The producer stores a SHA-256 digest of the payload in the binary header. The relay's binary parser recomputes and compares that checksum.

However, the reviewed relay `process_packet()` method processes the incoming JSON envelope using `parse_json_packet()` and `validate_json_packet()`. It does not call the binary `parse()` method on reconstructed packet bytes.

Therefore, this specification does not claim that checksum verification is performed for every packet on the active envelope-processing path. That behavior must be confirmed or explicitly implemented and tested.

---

## 5. Phase 2 — Car-to-Relay Envelope

### 5.1 JSON representation

The reviewed relay parser expects an encrypted JSON envelope containing fields such as:

```json
{
  "nonce": "<12-byte hex>",
  "ciphertext": "<hex-encoded ciphertext and authentication tag>",
  "header_hex": "<64-byte header encoded as hex>",
  "signature": "<64-byte signature encoded as hex>",
  "sequence_no": 42,
  "timestamp": 1718200000000,
  "team": "mercedes",
  "session": "R",
  "node_id": "mercedes_car"
}
```

This is an illustrative envelope shape based on the reviewed parser fields. The exact required fields, accepted encodings, and validation rules are determined by `PacketParser.parse_json_packet()` and `PacketParser.validate_json_packet()`.

The binary header is 64 bytes; its hexadecimal representation contains 128 hexadecimal characters, excluding any prefix.

The signature is 64 bytes; its hexadecimal representation contains 128 hexadecimal characters, excluding any prefix.

The nonce is 12 bytes; its hexadecimal representation contains 24 hexadecimal characters, excluding any prefix.

### 5.2 Commitment metadata

The original protocol design describes `zkp_commitment` and `zkp_nonce` fields.

The current Python commitment check described in project source context recomputes a SHA-256-based commitment from payload and nonce material and compares the result with a supplied value.

**Terminology:** This operation is a commitment comparison, not a zero-knowledge proof. The fields should only be documented as part of the active wire envelope if the producer, relay, and validator integration confirms that they are transmitted and preserved in the live path.

The complete field encoding and validation requirements for these commitment values remain to be verified.

---

## 6. Phase 2 — Relay Processing

### 6.1 Processing sequence

The reviewed `RelayNode.process_packet()` implementation performs these stages:

1. Increments the received-packet counter.
2. Parses the JSON envelope using `parse_json_packet()`.
3. Validates the parsed envelope using `validate_json_packet()`.
4. Drops the packet if envelope validation reports errors.
5. Decrypts the packet using the relay decryptor.
6. Drops the packet when a caught `InvalidTag` or `DecryptionError` occurs.
7. Calls `IntegrityChecker.check()` on the decrypted packet.
8. Drops the packet if the integrity result fails.
9. Calls `AnomalyFilter.check_and_annotate()`.
10. Drops packets marked as anomaly-rejected.
11. Allows anomaly-flagged packets to continue, with a warning.
12. Re-encrypts packets that pass the preceding stages.
13. Drops the packet if a caught `ReencryptionError` occurs.
14. Returns the re-encrypted packet and increments the forwarded counter.

This describes the reviewed method, not every possible exception or behavior in the wider network service.

### 6.2 Integrity checks

The relay `IntegrityChecker` supports sequence ordering, replay detection, timestamp checks, and signature-presence checks.

The reviewed constructor defaults are:

| Setting | Default |
|---|---:|
| `max_timestamp_age_ms` | `30000` |
| `max_sequence_gap` | `100` |
| `check_timestamps` | `True` |
| `check_signatures` | `True` |

The effective values may be overridden by `relay.yaml`.

The fallback configuration in the reviewed `main.py` explicitly sets `check_timestamps` to `False`. Therefore, the actual timestamp behavior depends on the configuration loaded at startup.

The relay's signature-presence check is not equivalent to Ed25519 signature verification.

### 6.3 Anomaly filtering

The relay applies the anomaly filter to the decrypted packet.

The documented policy distinguishes:

- **Clean:** No anomaly was detected.
- **Flagged:** A statistical or other configured condition was detected, but the packet is allowed to continue.
- **Rejected:** The anomaly filter marks the packet as unacceptable, and the relay drops it.

Exact physical bounds, statistical thresholds, and rejection policies must be maintained against the active anomaly-filter implementation and threshold configuration.

Do not describe illustrative thresholds as universal protocol constants unless the current configuration confirms them.

### 6.4 Re-encryption

The relay calls `RelayReencryptor.reencrypt(annotated)` for packets that pass integrity and anomaly rejection checks.

The intended design encrypts the packet for the relay-to-validator session using a new nonce and the validator-side session key.

The relay's decryptor and re-encryptor are separate components. The exact output envelope fields, preservation of signature and commitment metadata, and associated-data bytes used by the re-encryptor must be confirmed against `relay-node/src/reencryptor.py`.

The original producer signature should not be assumed to change during relay re-encryption. If the signature remains over the original header and plaintext payload, the validator must verify those same bytes.

---

## 7. Phase 2 — Relay-to-Validator Envelope

The relay is intended to forward a re-encrypted packet containing enough information for the validator to recover the plaintext and perform the required verification.

The exact outgoing envelope must be documented from the current `RelayReencryptor.reencrypt()` implementation and the validator's packet-receiving code.

Fields that may need to be carried include:

- `nonce`
- `ciphertext`
- `header_hex`
- `signature`
- `sequence_no`
- `timestamp`
- `team`
- `session`
- `node_id`
- Any required source-node or forwarding metadata.
- Commitment-related fields, if they are actually generated and consumed by the active pipeline.

Do not declare `header`, `signature_bytes`, `original_node`, `reencrypted`, `zkp_commitment`, or `zkp_nonce` mandatory wire fields merely because they appear in an earlier design example. Confirm which fields are serialized, required, and consumed by the current implementation.

The relay-to-validator envelope must be compatible with the validator's actual parser and decryptor.

---

## 8. Phase 2 — Validator Processing

### 8.1 Intended responsibilities

The validator is intended to perform the checks required before accepting a packet, including:

1. Decrypting the relay-to-validator ciphertext.
2. Verifying the original producer's Ed25519 signature.
3. Checking packet sequence and replay state.
4. Applying timestamp freshness checks when enabled.
5. Performing commitment verification if the feature is integrated into the active path.
6. Recording the decision and relevant context where audit logging is invoked.

### 8.2 Signature verification

The intended signature verification operation uses the producer's registered public key and the original header and plaintext payload:

```python
public_key.verify(
    signature_bytes,
    header_bytes + plaintext,
)
```

The reviewed project contains a validator-side signature-verification component. The exact order in which the active validator entry point performs signature verification, sequence-state mutation, commitment checks, and audit logging must be confirmed against `validator-node/src/main.py`.

A successful signature verifies the signed bytes relative to the public key supplied to the verifier. Trust in that key depends on the key-registration and identity-binding mechanisms.

### 8.3 Sequence and replay checks

The validator's `ValidatorSequenceChecker` supports sequence ordering, replay detection, and optional timestamp freshness checks.

The reviewed validator main entry point invokes the sequence checker. Its defaults include:

| Setting | Default |
|---|---:|
| `max_timestamp_age_ms` | `60000` |
| `max_sequence_gap` | `1000` |
| `check_timestamps` | `False` |
| `strict_ordering` | Enabled by default in the checker |

The active configuration may override these values.

**Important:** Timestamp freshness is disabled by default in the reviewed validator main entry point. The presence of a 60,000 ms threshold does not mean that the validator enforces that threshold unless timestamp checking is enabled.

### 8.4 Commitment verification

The current Python commitment-check description is:

1. Recover the plaintext payload.
2. Decode the commitment nonce.
3. Recompute the SHA-256 commitment using the implementation's defined byte sequence.
4. Compare the computed value with the received commitment.
5. Report a match or mismatch.

The exact byte concatenation, encoding, field names, and active validator call site must be confirmed against the implementation.

This is a hash-based commitment comparison. It must not be called zero-knowledge proof verification unless a genuine proof protocol is implemented and integrated.

### 8.5 Acceptance and rejection

The validator should accept a packet only after all required checks have succeeded and reject packets that fail mandatory validation.

The exact active ordering and failure propagation must be verified against the validator entry point and integration tests. In particular, confirm that a rejected packet cannot be accepted through a later path and that failed signature verification does not incorrectly advance sequence state.

---

## 9. Phase 3 — Key Rotation

### 9.1 Intended policy

The original protocol design proposes rotation when either condition is reached:

- Session age reaches 300 seconds.
- Packet count reaches 10,000.

It also proposes checking the rotation conditions every five seconds.

These values are **proposed design parameters until the active scheduler and rotation implementation confirm them**. They are not established here as guaranteed runtime behavior.

### 9.2 Intended rotation procedure

The intended rotation process is:

1. Determine that the configured age or packet-count threshold has been reached.
2. Initiate a fresh key exchange for the affected communication leg.
3. Derive a new session key.
4. Register the new key with the relevant encryptor or decryptor.
5. Coordinate the transition between the two endpoints.
6. Retire the previous key according to a defined policy.
7. Continue packet processing using the new session.

The exact transition protocol must define what happens to packets already in flight, failed handshakes, simultaneous rotation requests, and packets received under an old key.

### 9.3 Seamless rotation is not assumed

The original draft describes rotation as transparent and without interruption. That behavior has not been established by the reviewed processing code.

Do not claim uninterrupted packet delivery, automatic recovery, or guaranteed forward secrecy without implementation evidence and tests that exercise the complete rotation lifecycle.

### 9.4 Verification requirements

Before marking rotation as implemented, confirm:

- The scheduler exists and is started.
- Age and packet-count thresholds are enforced.
- Both endpoints participate in the exchange.
- New session keys are derived with the intended parameters.
- Encryption and decryption switch keys consistently.
- In-flight packets are handled safely.
- Old keys are retired as specified.
- Rotation failures do not cause silent acceptance or unrecoverable desynchronization.
- Integration tests cover age-triggered and count-triggered rotation.

---

## 10. Phase 4 — Session Teardown

The original design does not define an explicit teardown message.

Potential session-ending conditions include:

- Completion of the telemetry session.
- Explicit application shutdown.
- Network connection closure or failure.
- Session expiration.
- Failed or abandoned key rotation.

These are possible lifecycle conditions, not a complete implemented teardown specification.

Python object cleanup or process termination should not be described as guaranteed secure key erasure. A stronger claim would require a documented cleanup strategy and evidence that key material is not retained in persistent storage, logs, dumps, or other copies.

A future teardown specification should define:

- Whether an explicit teardown message exists.
- How peers confirm termination.
- How session keys and associated state are retired.
- How reconnection and session resumption work.
- How incomplete or interrupted sessions are handled.

---

## 11. Error Handling

### 11.1 Relay errors

The reviewed relay processing method handles the following conditions:

| Condition | Observed behavior in `process_packet()` |
|---|---|
| Envelope parsing raises `PacketParseError` | Log error, increment dropped count, return `None` |
| Envelope validation returns errors | Log warning, increment dropped count, return `None` |
| Caught `InvalidTag` or `DecryptionError` | Log error, increment dropped count, return `None` |
| Integrity result fails | Log errors, increment integrity-failed and dropped counts, return `None` |
| Anomaly filter rejects packet | Log violations, increment rejected and dropped counts, return `None` |
| Anomaly filter flags but does not reject | Log warning and continue processing |
| Caught `ReencryptionError` | Log error, increment dropped count, return `None` |
| Packet passes the reviewed stages | Re-encrypt, increment forwarded count, return result |

This table reflects the supplied `RelayNode.process_packet()` implementation. It does not describe every exception that could arise outside the listed catch blocks.

### 11.2 Validator errors

The intended validator policy is to reject packets that fail mandatory cryptographic, sequence, or commitment checks and record the relevant outcome where audit logging is integrated.

The exact exception types, error responses, and audit behavior must be documented against the current validator code. Do not assume that every illustrative error name in the original draft corresponds to an actual exception class.

### 11.3 Network behavior

The relay source defines network configuration fields, including listen host/port, validator host/port, timeout, and maximum connections. The reviewed `process_packet()` method itself receives raw bytes and returns a result; it does not show the complete socket receive/send framing protocol.

A complete TCP protocol specification must separately define:

- Message framing, such as length prefixes or another explicit boundary scheme.
- Maximum accepted message size.
- Behavior for incomplete or concatenated messages.
- Connection timeouts and idle connections.
- Handling of malformed UTF-8/JSON.
- Backpressure and queue behavior.
- Send failures and retry policy.
- Connection closure and reconnection behavior.

TCP is a byte stream and does not inherently preserve application message boundaries. Do not assume that one socket read corresponds to exactly one JSON envelope.

---

## 12. Protocol Versioning

The current header protocol-version field is `0x01`.

The receiver's version-handling behavior must be verified against the active parser. The presence of a version field does not by itself prove that unsupported versions are rejected.

The original design does not define a version-negotiation protocol. Until one is implemented, compatibility may need to be managed through coordinated deployment and explicit receiver-side version checks.

A future versioning policy should define:

- Supported protocol versions.
- Required behavior for unknown versions.
- Backward-compatibility rules.
- Migration and deployment coordination.
- Whether negotiation occurs during key exchange or through a separate message.

---

## 13. Protocol Constants

The following values are supported by the reviewed header and cryptographic-format information.

```python
MAGIC = 0x50435246          # "PCRF"
VERSION = 0x01
HEADER_SIZE = 64            # bytes
NONCE_SIZE = 12              # bytes
TAG_SIZE = 16                # bytes
SIGNATURE_SIZE = 64          # bytes
```

The protocol design also specifies:

```python
SESSION_KEY_SIZE = 32        # bytes
PUBLIC_KEY_SIZE = 32         # X25519 public-key representation
```

These key-size values should be confirmed against the active `CryptoEngine` and key-serialization code before being treated as implementation-verified constants.

The original design proposes the following mappings:

```python
TEAM_IDS = {
    "mercedes": 0x01,
    "redbull":  0x02,
}

SESSION_IDS = {
    "R": 0x01,  # Race
    "Q": 0x02,  # Qualifying
    "S": 0x03,  # Sprint
}

PACKET_TYPES = {
    "telemetry": 0x01,
}
```

**Verification note:** Confirm these exact mappings against `car_producer/src/packet_builder.py` before relying on them as authoritative. The producer's current constants are the source of truth.

---

## 14. Security Considerations

The following security properties require correct implementation and configuration:

- **Confidentiality:** Depends on AEAD encryption and appropriate session-key protection.
- **Message integrity:** Depends on AEAD authentication, correct handling of authentication failures, and the checks actually invoked on the active path.
- **Sender authenticity:** Depends on signature verification and trusted public-key registration.
- **Replay resistance:** Depends on sequence checking and correct state management.
- **Freshness:** Depends on timestamp checks being enabled and clocks behaving within the configured tolerance.
- **Key separation:** Depends on appropriate session derivation and distinct cryptographic contexts for each communication leg.
- **Nonce safety:** Depends on avoiding nonce reuse under the same key.
- **Auditability:** Depends on audit logging being invoked and logs being protected against loss or tampering.
- **Commitment integrity:** Depends on consistent commitment generation, encoding, and verification.
- **Zero-knowledge properties:** Cannot be inferred from a SHA-256 commitment comparison alone.

No individual mechanism guarantees the security of the entire protocol. End-to-end guarantees require tests of the integrated pipeline, including error paths and configuration-dependent behavior.

---

## 15. Implementation References

| File | Responsibility |
|---|---|
| `docs/PACKET_FORMAT.md` | Binary header, payload, checksum, signature, encryption, and envelope format |
| `car_producer/src/packet_builder.py` | Header construction and payload serialization |
| `car_producer/src/signer.py` | Producer signature generation and verification helpers |
| `car_producer/src/encryptor.py` | Payload encryption and envelope creation |
| `car_producer/src/crypto_engine.py` | Cryptographic session and key-agreement implementation; verify exact path and parameters |
| `relay-node/src/main.py` | Relay session setup and active packet-processing flow |
| `relay-node/src/packet_parser.py` | Binary parser and JSON-envelope parsing/validation |
| `relay-node/src/decryptor.py` | Relay-side decryption |
| `relay-node/src/reencryptor.py` | Relay-side re-encryption and outgoing envelope; verify exact fields |
| `relay-node/src/integrity_checker.py` | Relay sequence, replay, and optional timestamp checks |
| `relay-node/src/anomaly_filters.py` | Telemetry anomaly detection and filtering |
| `validator-node/src/main.py` | Validator processing flow and sequence-check invocation |
| `validator-node/src/signature_verifier.py` | Validator signature-verification component |
| `validator-node/src/sequence_checker.py` | Validator sequence/replay and optional timestamp checks |

Update these references if the repository structure changes.

---

## 16. Verification Checklist

### Confirmed from reviewed source

- [x] Binary header format is `!IBBBBQQI32sI`.
- [x] Header size is 64 bytes.
- [x] Magic value is `0x50435246`.
- [x] Producer signs the header and serialized payload bytes.
- [x] Producer encrypts the payload using the header as AEAD associated data.
- [x] Relay parses and validates a JSON envelope before decryption.
- [x] Relay calls `IntegrityChecker.check()` on the decrypted packet.
- [x] Relay applies anomaly filtering before re-encryption.
- [x] Relay drops packets for the explicitly handled failures described in Section 11.
- [x] Relay has session-setup methods and a local session-simulation method.
- [x] Validator main invokes `ValidatorSequenceChecker.check()`.
- [x] Validator timestamp checking defaults to disabled in the reviewed main entry point.
- [x] Binary checksum verification exists in `PacketParser.parse()`.

### Still to verify

- [ ] Exact X25519 key-generation, public-key encoding, and handshake message formats.
- [ ] Exact HKDF parameters used by the active implementation.
- [ ] Whether handshake messages are exchanged over the live network path.
- [ ] Authentication and identity binding for exchanged public keys.
- [ ] Exact producer-to-relay and relay-to-validator envelope schemas.
- [ ] Whether the active relay envelope path performs checksum verification.
- [ ] Whether duplicated envelope metadata is compared against the decoded header.
- [ ] Exact fields preserved by `RelayReencryptor.reencrypt()`.
- [ ] Exact validator processing order for signature verification and sequence-state mutation.
- [ ] Whether commitment fields are generated, transmitted, preserved, and verified in the active path.
- [ ] Whether any genuine zero-knowledge proof system is integrated.
- [ ] Whether key rotation is scheduled and operates end to end.
- [ ] Whether old keys are safely retired and in-flight packets are handled.
- [ ] Whether explicit teardown and resource cleanup are implemented.
- [ ] Whether unsupported protocol versions are rejected.
- [ ] Actual TCP framing, size limits, timeout, retry, and reconnection behavior.
- [ ] Numeric team/session mappings and all key-size assumptions against source.
- [ ] Integration tests for malformed messages, invalid signatures, replay, timestamp failures, tampering, key rotation, and network interruptions.

---

## 17. Change Control

Update this document whenever any of the following changes:

- Key-exchange messages or algorithms.
- Key derivation parameters or session separation.
- Header fields, mappings, or protocol version.
- Payload schema or serialization.
- Checksum, signature, or encryption behavior.
- JSON envelope fields or encoding.
- Relay or validator processing order.
- Timestamp, replay, or anomaly-check configuration.
- Key rotation and session teardown behavior.
- Network framing or error-handling rules.
- Commitment verification or proof-system integration.

The protocol specification and its integration tests should be maintained together.

**Authority rule:** Do not mark this document *Authoritative* until the outstanding wire-format, key-management, rotation, and validator-integration checks have been resolved against the active source code. Where behavior remains unimplemented or unverified, preserve that qualification rather than documenting the intended design as a guaranteed runtime property.
