# PitCrypt-F1 Packet Format Specification

**Version:** 1.3  
**Status:** Implementation-aligned specification; open integration gaps documented  
**Last updated:** 24 October 2026  
**Scope:** Telemetry packet header, payload, cryptographic protection, transmission envelope, and relay/validator processing behavior

---

## 1. Purpose and Scope

This document describes the packet format used by PitCrypt-F1, a prototype telemetry-security framework designed to explore authenticated telemetry processing, integrity checking, replay detection, anomaly filtering, and audit logging in a motorsport-inspired environment.

It distinguishes between:

- The binary telemetry packet.
- The signed packet representation.
- The encrypted JSON transmission envelope.
- The checks implemented by individual components.
- The checks actually invoked by the active relay and validator processing paths.
- Configurable behavior and integration gaps that remain to be verified.

**Project status:** PitCrypt-F1 is a research and portfolio prototype. This specification does not establish FIA approval, production deployment, or regulatory compliance.

## 2. Packet Architecture

The intended logical lifecycle is:

1. The producer serializes telemetry into a payload.
2. The producer constructs a fixed-width binary header containing metadata and a payload checksum.
3. The producer signs the header and payload bytes.
4. The producer encrypts the payload and authenticates the header as associated data.
5. The producer serializes the encrypted packet into a JSON envelope.
6. The relay parses and validates the JSON envelope.
7. The relay decrypts the payload.
8. The relay applies integrity/sequence checks and telemetry anomaly filtering.
9. The relay re-encrypts the packet for the validator.
10. The validator applies its configured verification and sequence checks.

The reviewed relay entry point confirms that it parses the JSON envelope, decrypts it, runs `IntegrityChecker.check()`, applies anomaly filtering, and re-encrypts packets that pass these stages.

**Important limitation:** The relay's active `process_packet()` path calls `parse_json_packet()` and `validate_json_packet()`. It does not call the binary `PacketParser.parse()` method on reconstructed binary packet bytes. The SHA-256 checksum comparison exists in the binary parser implementation, but its execution on the active encrypted-envelope path has not been established.

## 3. Binary Header

### 3.1 Header layout

The producer defines the header using:

```python
HEADER_FORMAT = '!IBBBBQQI32sI'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 64 bytes
```

The `!` prefix specifies network byte order (big-endian) and standard field sizes.

| Offset | Size | Field | Description |
|---:|---:|---|---|
| 0 | 4 bytes | `magic` | Protocol identifier `0x50435246` (`PCRF`) |
| 4 | 1 byte | `protocol_version` | Protocol version `0x01` |
| 5 | 1 byte | `team_id` | Encoded team identifier |
| 6 | 1 byte | `session_id` | Encoded session identifier |
| 7 | 1 byte | `packet_type` | Telemetry packet type `0x01` |
| 8 | 8 bytes | `sequence_no` | Packet sequence number |
| 16 | 8 bytes | `timestamp_ms` | Producer timestamp in Unix epoch milliseconds |
| 24 | 4 bytes | `payload_len` | Serialized payload length in bytes |
| 28 | 32 bytes | `checksum` | SHA-256 digest of the serialized payload |
| 60 | 4 bytes | `reserved` | Reserved field, currently packed as zero |
| **Total** | **64 bytes** | | |

The field order and total size are defined by the producer's `HEADER_FORMAT`.

### 3.2 Magic, version, and identifiers

- **Magic:** `0x50435246`, corresponding to `PCRF`.
- **Protocol version:** `0x01`.
- **Telemetry packet type:** `0x01`.
- **Team and session mappings:** Defined by `TEAM_IDS` and `SESSION_IDS` in the producer implementation.

Maintain the numeric mappings against the actual source constants. The full mappings should be added to this document once verified against the current code.

### 3.3 Sequence number

The `sequence_no` field is an unsigned 64-bit integer.

The relay's `IntegrityChecker` and validator's `ValidatorSequenceChecker` implement sequence-ordering and replay-related checks. Replay protection depends on these checkers being invoked correctly and maintaining appropriate state; the sequence field alone does not prevent replay.

### 3.4 Timestamp

The producer generates timestamps using:

```python
int(time.time() * 1000)
```

This represents Unix epoch milliseconds. It is a wall-clock timestamp, not a monotonic clock reading.

The reviewed relay entry point constructs `IntegrityChecker` with these defaults:

| Setting | Default |
|---|---:|
| `max_timestamp_age_ms` | `30000` |
| `max_sequence_gap` | `100` |
| `check_timestamps` | `True` |
| `check_signatures` | `True` |

These defaults apply when the corresponding configuration keys are absent.

The relay's built-in fallback configuration in `main.py`, used when `relay.yaml` cannot be found, explicitly sets `check_timestamps` to `False`. Therefore, the actual relay timestamp behavior depends on the configuration loaded at startup.

The validator's reviewed main entry point defaults `check_timestamps` to `False`, with a configured timestamp-age threshold of `60000` ms.

Both checkers contain timestamp-freshness logic, but **support for a check is not the same as the check being enabled**.

The checker implementations also support warnings for timestamps more than five seconds in the future. Do not describe timestamp freshness as a universal end-to-end guarantee.

## 4. Payload

### 4.1 Serialization

The producer serializes telemetry into compact JSON. The serialized byte sequence is used as the input to the checksum, signature, and encryption operations.

Cryptographic operations must use the exact serialized bytes, rather than independently reserializing an equivalent JSON object.

### 4.2 Documented telemetry fields

The project documentation identifies fields including:

| Field | Purpose |
|---|---|
| `driver` | Driver identifier |
| `lap` | Lap number |
| `race` | Event or race identifier |
| `frame_index` | Frame/sample index |
| `Speed` | Vehicle speed |
| `RPM` | Engine speed |
| `Throttle` | Throttle measurement |
| `Brake` | Brake measurement |
| `nGear` | Selected gear |
| `DRS` | DRS representation |

Additional fields, including spatial coordinates and distance, may be used by newer telemetry configurations or test fixtures. The current producer schema and channel configuration remain the source of truth.

The DRS values documented by the project include `0`, `8`, `10`, `12`, and `14`. Their interpretation should be confirmed against the current telemetry source and preprocessing rules.

## 5. Payload Checksum

The producer calculates the checksum using:

```python
hashlib.sha256(payload).digest()
```

The resulting 32-byte digest is stored in the binary header.

The binary parser in `relay-node/src/packet_parser.py`:

1. Extracts the payload bytes using the header's payload length.
2. Computes SHA-256 over the extracted bytes.
3. Compares the computed digest with the checksum stored in the header.
4. Reports `checksum_valid`, `is_valid`, and parsing errors.
5. Adds `SHA-256 checksum mismatch` when the values differ.

### Active-pipeline status

The reviewed relay `process_packet()` method performs:

```python
parsed = self.parser.parse_json_packet(raw_data)
errors = self.parser.validate_json_packet(parsed)
```

It subsequently decrypts the parsed envelope and invokes `self.integrity.check(decrypted)`.

It does **not** invoke `self.parser.parse()` on the binary packet in this method. Consequently:

- Binary checksum verification is implemented.
- The reviewed active JSON-envelope processing path does not demonstrate that the binary checksum comparison is executed.
- The call to `validate_json_packet()` validates the envelope according to its implementation, but its name alone does not establish that it verifies the payload checksum.

**Documentation status:** Do not claim that every packet passing through the active relay is checksum-verified until the checksum is explicitly checked on that path or an equivalent check is confirmed elsewhere.

A SHA-256 checksum is also not a keyed authentication mechanism. Sender authenticity depends on the signature and key-validation mechanisms.

## 6. Digital Signature

### 6.1 Algorithm and signed data

The producer signer uses Ed25519. The reviewed producer code constructs the signed data as:

```python
data_to_sign = packet['header'] + packet['payload']
```

The signature therefore covers the exact binary header bytes followed by the serialized plaintext payload bytes.

The producer-side verification helper uses the same header-plus-payload construction. The Ed25519 signature is 64 bytes.

### 6.2 Verification requirements

Correct verification requires:

- The exact header bytes used during signing.
- The exact serialized payload bytes used during signing.
- The corresponding trusted public key.
- The signature associated with the packet.

The signature authenticates the signed bytes relative to the verification key. It does not, by itself, establish that the telemetry is physically plausible or that the key is correctly associated with a trusted team.

The active relay's `IntegrityChecker` has a signature-presence check. That check should not be confused with Ed25519 cryptographic verification. The validator has a separate signature-verification component.

The exact point at which the validator invokes signature verification relative to sequence-state changes should be confirmed against its active processing method before documenting a definitive ordering guarantee.

## 7. Encryption and Authenticated Data

### 7.1 Algorithm

The producer encryptor and relay decryptor use a ChaCha20-Poly1305 AEAD interface.

The producer encryptor supplies the payload as plaintext and the header as associated data:

```python
ciphertext = engine.encrypt(
    plaintext=payload,
    associated_data=header
)
```

The relay decryptor supplies the received header as associated data during decryption.

### 7.2 Encryption coverage

The payload is encrypted. The header is provided as **additional authenticated data (AAD)**, so it is authenticated by the AEAD operation but is not encrypted by that operation.

The receiver must use the same header bytes as AAD and reject authentication failures. The header's presence in the envelope does not make it confidential.

### 7.3 Nonce and authentication tag

- **Nonce:** 12 bytes.
- **Ciphertext:** Encrypted payload plus the AEAD authentication tag.
- **Authentication tag:** 16 bytes for ChaCha20-Poly1305.

Nonce uniqueness under a given key is essential. The source shows nonce generation and validates nonce length in the envelope parser, but a production guarantee would require verification of uniqueness across concurrent producers, process restarts, sessions, and key changes.

### 7.4 Decryption failure

The relay's active processing method catches `InvalidTag` and `DecryptionError`, increments the dropped-packet counter, and returns `None`.

Thus, the reviewed `process_packet()` path does not continue to integrity checking or re-encryption when those caught decryption failures occur.

Other unexpected exception types are not covered by that particular catch block; do not claim that every possible failure is handled identically.

## 8. Encrypted JSON Envelope

The encrypted transmission representation is a JSON envelope, separate from the 64-byte binary header.

The reviewed parser expects fields including:

| Field | Representation | Purpose |
|---|---|---|
| `nonce` | Hex-encoded bytes | AEAD nonce |
| `ciphertext` | Encoded bytes | Encrypted payload and authentication tag |
| `header_hex` | Hex-encoded bytes | Original header representation |
| `signature` | Hex-encoded bytes | Digital signature |
| `sequence_no` | Integer | Sequence metadata |
| `timestamp` | Integer | Timestamp metadata |
| `team` | String | Team metadata |
| `session` | String | Session metadata |
| `node_id` | String | Source-node identifier |

The producer may also retain internal fields such as `nonce_bytes`, `ciphertext_bytes`, `encrypted_at`, and size information. These should not automatically be treated as required wire-protocol fields.

### 8.1 Metadata consistency

The envelope duplicates values represented in the header, including sequence and timestamp information.

The active relay calls `validate_json_packet()` before decryption. However, the code excerpt reviewed here does not establish which duplicated metadata fields are compared against the decoded header or whether every mismatch is rejected.

This remains an explicit verification task.

### 8.2 Binary and envelope representations are distinct

The binary `parse()` method and JSON-envelope parsing method serve different representations. A test that demonstrates checksum detection in the binary parser does not, by itself, prove checksum detection in the active JSON-envelope path.

The protocol documentation must keep this distinction until the active path explicitly verifies the checksum.

## 9. Relay Processing

The reviewed `RelayNode.process_packet()` implementation follows this sequence:

1. **Receive:** Increment the received counter.
2. **Parse envelope:** Call `parse_json_packet(raw_data)`.
3. **Validate envelope:** Call `validate_json_packet(parsed)` and drop the packet if it returns errors.
4. **Decrypt:** Call the relay decryptor; drop the packet on caught AEAD or decryption errors.
5. **Integrity check:** Call `IntegrityChecker.check(decrypted)`; drop the packet if the result fails.
6. **Anomaly filter:** Call `AnomalyFilter.check_and_annotate(decrypted)`; drop rejected anomalies.
7. **Re-encrypt:** Call `RelayReencryptor.reencrypt(annotated)`; drop the packet on a caught `ReencryptionError`.
8. **Return:** Return the re-encrypted packet and increment the forwarded counter.

Flagged-but-not-rejected anomalies are logged and forwarded with a flag. The exact behavior is controlled by the anomaly filter's result.

### 9.1 Integrity-check configuration

When a configuration key is absent, `RelayNode.__init__()` defaults to:

- `check_timestamps=True`
- `check_signatures=True`
- `max_timestamp_age_ms=30000`
- `max_sequence_gap=100`

However, the fallback configuration defined in the `__main__` block sets `check_timestamps=False`. When `relay.yaml` exists, the values in that file can override the constructor defaults.

Therefore, the effective behavior must be documented from the configuration actually used to launch the relay, not inferred solely from constructor defaults.

### 9.2 Checksum integration gap

The active `process_packet()` path does not call the binary parser's `parse()` method. No checksum verification is visible in the supplied `process_packet()` code between envelope parsing, decryption, integrity checking, anomaly filtering, and re-encryption.

This is an **integration gap to resolve or document explicitly**, not proof that no other code path can verify the checksum.

## 10. Validator Processing

The validator has separate components for signature verification and sequence/replay checking.

The reviewed validator main entry point invokes `ValidatorSequenceChecker.check()` and defaults timestamp checking to disabled.

Its configured sequence-check settings include:

| Setting | Default |
|---|---:|
| `max_timestamp_age_ms` | `60000` |
| `max_sequence_gap` | `1000` |
| `check_timestamps` | `False` |
| `strict_ordering` | Enabled by default in the checker |

The actual validator behavior depends on configuration and processing order.

Before documenting the validator as providing end-to-end verification, confirm that its active processing path:

1. Verifies the Ed25519 signature over the original header and plaintext payload.
2. Rejects signature failures before accepting the packet.
3. Applies sequence and replay checks.
4. Enables timestamp checks when required by the intended policy.
5. Prevents rejected packets from being accepted through a later stage.
6. Records the relevant decision and reason.

The exact ordering of signature verification, sequence-state mutation, commitment checks, and audit logging must be established from the active validator method and tests.

## 11. Commitment Verification

The project includes a Python commitment-verification component that recomputes a SHA-256-based commitment using payload and nonce material and compares it with a supplied commitment.

This is a commitment comparison. **It is not, by itself, a zero-knowledge proof.**

A zero-knowledge proof system requires a defined statement and witness, proof generation, verification, and appropriate security properties. A separate Rust proof-system module must not be described as integrated into the active packet pipeline unless that integration is demonstrated by source and tests.

Use *commitment verification* or *SHA-256 commitment check* for the current Python behavior unless a genuine proof protocol is confirmed.

## 12. Rejection and Error Handling

The reviewed relay method explicitly drops packets for:

- JSON-envelope parsing or validation errors.
- Caught decryption/authentication failures.
- Failed relay integrity checks.
- Anomaly-filter rejection.
- Caught re-encryption failures.

The binary parser separately detects malformed binary packets and checksum mismatches.

These are distinct facts: a rejection behavior in one parser or test path does not automatically prove that the same check executes on the active envelope path.

Integration tests should verify the complete path, including that invalid packets are not forwarded and that rejected packets do not incorrectly modify sequence state.

## 13. Implementation References

| File | Responsibility |
|---|---|
| `car_producer/src/packet_builder.py` | Header constants, serialization, timestamp generation, checksum computation |
| `car_producer/src/signer.py` | Producer signature generation and verification helpers |
| `car_producer/src/encryptor.py` | Payload encryption, nonce handling, header as AAD |
| `relay-node/src/packet_parser.py` | Binary packet parsing, binary checksum verification, JSON-envelope parsing and validation |
| `relay-node/src/decryptor.py` | Payload decryption and AEAD authentication |
| `relay-node/src/integrity_checker.py` | Relay integrity, sequence, replay, and optional timestamp checks |
| `relay-node/src/anomaly_filters.py` | Telemetry anomaly detection and result annotation |
| `relay-node/src/main.py` | Active relay pipeline and effective integrity-check configuration |
| `validator-node/src/signature_verifier.py` | Validator-side signature verification |
| `validator-node/src/sequence_checker.py` | Validator sequence, replay, and optional timestamp checks |
| `validator-node/src/main.py` | Active validator processing and sequence-check configuration |

## 14. Verification Checklist

### Confirmed from reviewed source

- [x] Header format is `!IBBBBQQI32sI`.
- [x] Header size is 64 bytes.
- [x] Magic value is `0x50435246`.
- [x] Producer timestamps are generated in Unix epoch milliseconds.
- [x] Producer computes SHA-256 over serialized payload bytes.
- [x] Binary relay parser recomputes and compares the payload checksum.
- [x] Producer signs `header + payload`.
- [x] Producer supplies the header as AEAD associated data.
- [x] Envelope validation checks nonce length in the reviewed parser implementation.
- [x] Relay main invokes `IntegrityChecker.check()` on the decrypted packet.
- [x] Relay main drops packets when its integrity result fails.
- [x] Relay main drops caught decryption/authentication failures.
- [x] Relay main drops anomaly-filter rejections.
- [x] Relay main drops caught re-encryption failures.
- [x] Relay constructor defaults timestamp checking to enabled if no configuration overrides it.
- [x] Relay fallback self-test configuration explicitly disables timestamp checking.
- [x] Validator main invokes `ValidatorSequenceChecker.check()`.
- [x] Validator main defaults timestamp checking to disabled.

### Still to verify

- [ ] Whether the active relay envelope path performs checksum verification after decryption or through another invoked component.
- [ ] Whether every duplicated envelope metadata field is compared with its corresponding header value.
- [ ] Whether validator signature verification occurs before sequence-state mutation.
- [ ] Whether all validator rejection conditions stop subsequent acceptance.
- [ ] Whether commitment verification is invoked on the active validator path.
- [ ] The exact team/session numeric mappings.
- [ ] The current complete payload schema and DRS representation.
- [ ] Effective settings in the actual `relay.yaml` and validator configuration.
- [ ] Nonce uniqueness assumptions across concurrent producers, restarts, and key changes.
- [ ] End-to-end tests for malformed envelopes, altered metadata, invalid signatures, replay, stale timestamps, checksum mismatch, and AEAD failures.

## 15. Security Limitations

PitCrypt-F1 is a prototype, not a certified or production-ready motorsport telemetry protocol.

In particular:

- SHA-256 checksum storage is not a substitute for sender authentication.
- Binary checksum verification is not yet demonstrated on the active relay envelope path.
- AEAD protection depends on correct nonce handling, key management, and AAD consistency.
- Signature verification depends on correct public-key registration and identity binding.
- Replay protection depends on sequence-state handling and correct failure propagation.
- Timestamp freshness is configurable and may be disabled.
- A commitment comparison is not automatically a zero-knowledge proof.
- Application-level logging should not be described as immutable or tamper-proof without additional controls and evidence.
- Passing tests establish only the behaviors exercised under their test conditions; they do not prove production deployment, regulatory approval, or resistance to every attack.

## 16. Change Control

Review this document whenever the following change:

- Header layout, field widths, byte order, or protocol version.
- Team/session/packet-type mappings.
- Payload schema or serialization.
- Checksum algorithm or covered bytes.
- Signature algorithm or signed bytes.
- Encryption algorithm, nonce format, or associated data.
- Envelope encoding or metadata-consistency rules.
- Relay or validator processing order.
- Default timestamp, sequence, replay, or anomaly configuration.
- Commitment or proof-verification behavior.

Update the specification and tests together. Do not label this document authoritative until the active-pipeline verification tasks in Section 14 are resolved or explicitly accepted as limitations.
