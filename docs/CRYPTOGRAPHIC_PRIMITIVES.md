# Cryptographic Primitives

**Project:** PitCrypt-F1  
**Document version:** 1.0  
**Status:** Prototype implementation reference  
**Last reviewed:** 24 October 2026

## 1. Purpose

This document records the cryptographic primitives used or referenced by PitCrypt-F1, explains their intended roles in the telemetry pipeline, and identifies implementation details that must be verified before making stronger security claims.

PitCrypt-F1 is a prototype for securing and validating motorsport telemetry. Its cryptographic components are intended to support confidentiality, message authentication, producer identity verification, key derivation, and integrity checks.

This document is not a cryptographic certification, a formal security proof, or evidence of compliance with FIA regulations or an industry security standard.

## 2. Implementation status and terminology

The following distinctions apply throughout this document:

- **Implemented:** The primitive or related logic exists in the prototype code.
- **Configuration-dependent:** The behaviour depends on runtime configuration or the selected execution path.
- **Requires verification:** The intended behaviour is documented, but the relevant execution path, key lifecycle, or failure handling must be checked before claiming it is reliably enforced.
- **Planned:** A proposed enhancement, not a claim about current runtime behaviour.

A primitive being present in the code does not establish that it is correctly integrated into every pipeline path or that the overall protocol is secure.

## 3. Primitive inventory

| Primitive | Intended role | Status and limitations |
|---|---|---|
| X25519 | Elliptic-curve Diffie–Hellman key agreement | Implemented in the session setup path; authentication of the exchanged public keys must be assessed separately. |
| HKDF-SHA256 | Derive cryptographic keys from shared secret material | Used by the key-derivation design; verify the exact salt, context, output lengths, and per-direction key separation in the implementation. |
| ChaCha20-Poly1305 | Authenticated encryption with associated data (AEAD) | Used for telemetry encryption and authentication. Nonce uniqueness under each key is essential. |
| Ed25519 | Digital signatures and signature verification | Used for signing and verifying signed telemetry data. Public-key identity binding and verification failure handling remain important. |
| SHA-256 | Hashing and checksum/commitment calculations | Used for integrity-related calculations. A hash alone does not authenticate its sender or prove a statement without revealing the underlying data. |
| HMAC | Message authentication in the SecureCAN project | Separate project component; do not assume it is part of PitCrypt-F1's telemetry packet protocol unless the integration is confirmed. |

**Important:** The presence of these algorithms does not imply that every key is generated, stored, exchanged, rotated, or destroyed securely. Those properties depend on the implementation and operational procedures.

## 4. X25519 key agreement

### 4.1 Purpose

X25519 allows two parties to derive a shared secret using their private keys and the other party's public key. PitCrypt-F1 uses this mechanism in session setup between telemetry pipeline components.

The shared secret is key-agreement material. It should not be used directly as an encryption key without an appropriate key-derivation step.

### 4.2 Intended use in PitCrypt-F1

The prototype contains session setup paths for establishing cryptographic sessions between:

- A producer/car node and the relay.
- The relay and the validator.

The relay setup code includes calls that complete a handshake using a peer public key and register the resulting session with the relevant encryption or decryption component. The local simulation also establishes sessions in process.

These code paths establish the presence of session-setup functionality; they do **not**, by themselves, prove that a complete authenticated handshake protocol is implemented over a network.

### 4.3 Authentication limitation

X25519 provides key agreement, not peer identity authentication on its own. If an attacker can substitute a public key during an unauthenticated exchange, the parties may establish a secret with the wrong peer.

A production-oriented design should define how public keys are authenticated and bound to identities, for example through a properly verified signature, trusted key registry, or authenticated protocol.

The project must not claim that X25519 alone prevents man-in-the-middle attacks.

### 4.4 Verification requirements

Verify that the implementation:

- Rejects malformed or invalid peer public-key input.
- Authenticates or otherwise securely binds peer public keys to expected identities.
- Uses a key-derivation function on the shared secret.
- Separates keys by session, purpose, and direction where required.
- Handles failed or incomplete handshakes without registering an unusable session.
- Does not expose private keys or shared secrets in logs, dashboard output, or exception messages.

## 5. HKDF-SHA256 key derivation

### 5.1 Purpose

HKDF is a key-derivation function based on HMAC. It converts input keying material into derived key material suitable for specified cryptographic purposes.

In PitCrypt-F1, HKDF-SHA256 is intended to derive session keys from key-agreement material produced by X25519.

### 5.2 Required properties

The implementation and protocol documentation should identify:

- The input keying material.
- The salt, including whether it is fixed, random, or absent.
- The `info` context used to distinguish the protocol, session, participants, and key purpose.
- The output length of each derived key.
- Whether separate keys are derived for different communication directions or cryptographic functions.

These values should be consistent between communicating components and should not be guessed from this document.

### 5.3 Security considerations

- Do not treat the raw X25519 shared secret as an application encryption key.
- Do not reuse one derived key across unrelated protocols or purposes without an explicit design justification.
- Do not assume that deriving keys automatically authenticates the participants.
- Ensure that both endpoints derive matching keys and that tests detect mismatched contexts or session parameters.

The exact HKDF parameters must be confirmed against the current `CryptoEngine` implementation before this document is treated as a complete implementation-level specification.

## 6. ChaCha20-Poly1305 authenticated encryption

### 6.1 Purpose

ChaCha20-Poly1305 is an authenticated-encryption-with-associated-data (AEAD) construction. It provides confidentiality and authentication of encrypted plaintext, together with authentication of any associated data supplied to the operation.

PitCrypt-F1 uses ChaCha20-Poly1305 to protect telemetry payloads in the pipeline.

### 6.2 Nonce requirements

The prototype's encrypted-packet validation expects a **12-byte nonce**.

A nonce is not necessarily a secret. Its uniqueness requirement is nevertheless critical: a nonce must not be reused with the same ChaCha20-Poly1305 key.

Nonce reuse can compromise confidentiality and authentication. A 12-byte nonce check alone does not establish that nonce reuse is prevented.

The implementation should be tested for:

- Nonce generation and uniqueness under each key.
- Behaviour during concurrent packet production.
- Behaviour when sessions are restarted or keys are reused.
- Rejection of malformed nonce lengths.
- Safe handling of AEAD authentication failures.

### 6.3 Associated data and packet headers

The packet design uses a fixed-size header of 64 bytes with the format:

`!IBBBBQQI32sI`

The design uses header fields alongside the encrypted payload and signature. Whether the complete header, selected fields, or another representation is supplied as AEAD associated data must be verified against the encryption and decryption calls.

Do not claim that the header is authenticated as AEAD associated data unless the code confirms that the same bytes are supplied to both encryption and decryption.

If a receiver relies on header values for routing, sequencing, or validation, the protocol must define exactly how those values are authenticated and compared.

### 6.4 Decryption failures

If AEAD authentication fails, the receiver must reject the packet and must not pass unauthenticated plaintext into downstream processing.

Tests should confirm that authentication failures:

- Do not produce accepted telemetry.
- Do not trigger downstream processing using partial or unauthenticated data.
- Produce an appropriate audit event without logging secret key material or sensitive plaintext.

## 7. Ed25519 digital signatures

### 7.1 Purpose

Ed25519 is used for signing and verifying telemetry-related data. Digital signatures allow a verifier with the correct public key to check that a signature corresponds to a message and private key.

A valid signature alone does not prove that a message is truthful, that its sensor data is physically accurate, or that the signing key belongs to the expected producer.

### 7.2 Signed data

The packet design specifies a signature over:

`header + payload`

The exact byte representation, including serialization, encoding, field order, and whether the payload refers to plaintext or another representation, must match the actual signing and verification code.

The current design describes the signature over the header and payload; the implementation should be checked to ensure both sides use precisely the same canonical byte sequence.

### 7.3 Public-key trust

Signature verification is meaningful only when the public key is correctly associated with the expected producer identity.

The project should define:

- How producer public keys are provisioned and registered.
- How a verifier selects the expected key for a given producer.
- How unknown, revoked, or replaced keys are handled.
- How public-key changes are audited.
- Whether the relay's re-encryption or packet-transformation path changes the signed bytes and, if so, how the resulting packet is authenticated.

Do not describe signature verification as proof of FIA authorization or official team identity unless a trusted identity-provisioning process actually establishes that relationship.

### 7.4 Verification failure

An invalid signature should cause rejection at the relevant verification stage. Tests should include altered headers, altered payloads, wrong public keys, malformed signatures, and missing signatures.

## 8. SHA-256 hashing, checksums, and commitments

### 8.1 SHA-256

SHA-256 maps input data to a fixed-length digest. PitCrypt-F1 uses SHA-256 for integrity-related calculations, including a checksum field in the packet design and a commitment-like value in the prototype validator.

A SHA-256 digest is not encryption. It does not conceal its input by itself, and it does not authenticate the origin of data without an appropriate authentication mechanism.

### 8.2 Payload checksum

The packet design describes a SHA-256 checksum over the plaintext payload.

The binary packet parser contains checksum-verification logic. However, the relay's JSON-envelope processing path parses and validates the JSON packet, decrypts it, and then runs integrity and anomaly checks. The binary parser's checksum validation must **not** be assumed to execute in that JSON processing path.

Before claiming that every live-path packet has its plaintext checksum verified, confirm that the checksum is recomputed and compared after decryption in the actual JSON-envelope path, and that a mismatch results in rejection.

A checksum is useful for detecting accidental or deliberate changes only when it is recomputed and checked against a trusted or authenticated value. It should not replace AEAD authentication or signature verification.

### 8.3 Commitment-like verification

The active Python validator's commitment check recomputes a value based on:

`SHA256(payload + nonce)`

and compares it with the supplied commitment.

This is a hash-based consistency check. **It is not a zero-knowledge proof (ZKP).** It does not, by itself, establish a formal zero-knowledge property, provide a proof of knowledge, or demonstrate that a statement is true without revealing the witness.

A separate Rust module involving Pedersen commitments or Bulletproofs must be treated as a separate component unless its integration into the active telemetry path is demonstrated and tested.

Use terms such as **hash commitment check** or **commitment-like integrity check** for the active Python path. Do not describe the live pipeline as ZKP-protected on this basis.

## 9. Cryptographic processing in the pipeline

The prototype's intended processing sequence is broadly:

1. A producer creates telemetry and packet metadata.
2. Packet data is encrypted using the configured session cryptography.
3. The packet carries signature and integrity-related fields according to the packet format.
4. The relay parses and validates the JSON envelope, decrypts the payload, and performs configured integrity and anomaly checks.
5. The relay re-encrypts telemetry for the next stage according to the session configuration.
6. The validator performs its configured signature, sequence/replay, and commitment-related checks.
7. Accepted or rejected outcomes are reflected in processing results and audit events.

This is a high-level description, not a guarantee that all checks execute for every packet in every configuration. The exact order of checks, signed bytes, header authentication, and error paths must be confirmed against the current source.

In particular, a relay that decrypts and re-encrypts a packet must not be assumed to preserve an original producer signature over the same bytes. If packet contents change, the protocol must specify how the original producer's signature is retained and verified, or how the relay authenticates the transformed packet.

## 10. Cryptographic error handling

Cryptographic failures should fail closed: a packet that cannot be authenticated or validated must not be accepted as trusted telemetry.

Relevant failure cases include:

- Failed key agreement or key derivation.
- Unknown or unauthenticated peer public keys.
- AEAD tag verification failure.
- Invalid signature or unexpected signing key.
- Invalid nonce length or detected nonce reuse.
- Malformed header or envelope.
- Checksum or commitment mismatch.
- Invalid sequence or replay detection.
- Missing session key or expired/revoked key.

Error handling should avoid exposing secrets, private keys, shared secrets, raw key material, or sensitive plaintext in logs and dashboard messages.

## 11. Required security tests

Before describing the cryptographic layer as production-ready, test and record the following:

- [ ] X25519 session establishment succeeds with valid inputs and fails safely with invalid inputs.
- [ ] Peer identity is authenticated or bound to a trusted public key.
- [ ] HKDF parameters and derived-key lengths are documented and tested.
- [ ] Session keys are separated by purpose and direction where required.
- [ ] ChaCha20-Poly1305 rejects modified ciphertext, associated data, and tags.
- [ ] Nonces are not reused with the same key.
- [ ] Ed25519 rejects modified messages, malformed signatures, and incorrect public keys.
- [ ] The signed byte sequence is identical at the signer and verifier.
- [ ] Plaintext checksum verification is confirmed in every intended processing path.
- [ ] Commitment checks reject incorrect values without being misrepresented as ZKPs.
- [ ] Cryptographic exceptions do not expose secrets or result in packet acceptance.
- [ ] Tests cover session restart, key replacement, and invalid or expired key handling.

Test results should be reported only when supported by executed tests, logs, or reproducible evidence.

## 12. Standards and references

The following specifications describe the primitives referenced in this document:

- **RFC 7748** — Elliptic Curves for Security, including X25519.
- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- **RFC 8439** — ChaCha20 and Poly1305 for IETF Protocols.
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA), including Ed25519.
- **FIPS PUB 180-4** — Secure Hash Standard, including SHA-256.

Referencing these specifications does not mean that PitCrypt-F1 has been independently validated against them or that the full system meets a particular compliance standard.

## 13. Maintenance

Update this document when:

- Cryptographic algorithms or libraries change.
- Packet signing or encryption formats change.
- Key derivation, nonce generation, or session setup changes.
- The Rust commitment module is integrated into the active pipeline.
- Tests establish previously unverified behaviour.
- A security review identifies new limitations or required controls.

The implementation and its tests are the source of truth for claims about current behaviour. Where documentation and code differ, record and resolve the discrepancy rather than assuming either one is correct.
