# ADR 001 — Cryptographic Primitive Selection

**Status:** Accepted, subject to implementation verification  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review  
**Project:** PitCrypt-F1

---

## 1. Context

PitCrypt-F1 requires cryptographic primitives for three primary purposes:

1. **Key agreement:** Establishing shared session secret material between the producer, relay, and validator without sending the secret directly over the network.
2. **Encryption and message integrity:** Protecting telemetry confidentiality and detecting unauthorised modification in transit.
3. **Digital signatures:** Authenticating producer-originated packet content so that the validator can verify it independently of the relay's encryption session.

The intended environment includes telemetry processing at sustained packet rates, potentially on software-based systems without guaranteed hardware acceleration. Cryptographic operations must therefore be evaluated for correctness, implementation security, resource use, and end-to-end latency.

The project also considers network interception, malicious packet modification, replay, compromised components, and exposure of sensitive telemetry.

This ADR records the selected cryptographic primitives and the rationale for selecting them. It does not, by itself, establish that the implementation is correctly integrated, benchmarked under production load, independently audited, or approved for use in real FIA infrastructure.

---

## 2. Decision Summary

| Purpose | Selected primitive | Primary role |
|---|---|---|
| Key agreement | X25519 | Establish shared secret material |
| Symmetric authenticated encryption | ChaCha20-Poly1305 | Protect payload confidentiality and integrity |
| Digital signatures | Ed25519 | Authenticate producer-signed packet content |
| Key derivation | HKDF-SHA256 | Derive session keys from shared secret material |
| Hashing / commitment check | SHA-256 | Hashing and the prototype's hash-based commitment check |

The SHA-256-based commitment check is **not a zero-knowledge proof**. Any requirement for zero-knowledge proofs or hiding commitments must be addressed by a separately specified, reviewed, and integrated protocol.

---

## 3. Key Agreement: X25519

**Selected:** X25519 elliptic-curve Diffie–Hellman key agreement, specified in RFC 7748.

### Rationale

- X25519 produces compact public keys and shared secret output.
- It is widely supported by established cryptographic libraries.
- It is designed for efficient software implementation.
- It can establish shared secret material without transmitting the resulting secret directly.
- It is suitable as the key-agreement primitive within a broader authenticated session-establishment protocol.

### Alternatives considered

| Alternative | Reason not selected for this design |
|---|---|
| ECDH over NIST P-256 | Not selected for the initial prototype; could be considered where ecosystem or policy requirements favour it |
| ECDH over P-384 | Larger parameters and output than needed for the current design target |
| RSA-based key transport | Not selected; does not provide the same design model as ephemeral Diffie–Hellman key agreement |

These are design choices, not claims that the alternatives are inherently insecure.

### Security requirements and limitations

X25519 key agreement alone does **not** authenticate the remote peer. An attacker may attempt a man-in-the-middle attack if public keys are not authenticated and bound to the expected identities.

The complete protocol must therefore specify:

- How peer public keys are provisioned and validated.
- How peer identities are bound to the handshake.
- How downgrade, replay, and session-confusion attacks are prevented.
- How ephemeral private keys and derived secrets are handled.
- How session termination, rotation, and key compromise are managed.

X25519 is not post-quantum secure.

**Implementation requirement:** Use a maintained cryptographic library rather than a custom implementation, and test the full authenticated session-establishment path.

---

## 4. Symmetric Encryption: ChaCha20-Poly1305

**Selected:** ChaCha20-Poly1305 authenticated encryption with associated data (AEAD), specified in RFC 8439.

### Rationale

- It combines encryption and authentication in a single AEAD construction.
- It can authenticate unencrypted metadata, such as a packet header, when the exact header bytes are supplied as associated data.
- It has efficient software implementations and is widely available in established cryptographic libraries.
- It avoids the need to design a separate encryption-and-MAC composition for this use case.

### Alternatives considered

| Alternative | Reason not selected for the initial design |
|---|---|
| AES-256-GCM | A valid AEAD alternative; comparative performance depends on platform and implementation |
| AES-128-GCM | A valid alternative where policy and security requirements permit it |
| AES-CBC with HMAC | Not selected because it requires careful composition, authentication ordering, and error handling |

The selection of ChaCha20-Poly1305 is not based on a universal claim that AES-GCM is slower. On systems with suitable hardware acceleration, AES-GCM may be faster. The appropriate choice should be confirmed by measurements on the target platform.

### Nonce requirements

ChaCha20-Poly1305 requires nonce uniqueness for a given key. Reusing a nonce with the same key can seriously compromise confidentiality and authentication.

The protocol must define how nonces are generated, validated, and associated with sessions. A statement that a fresh nonce is generated per packet is not sufficient unless the implementation and failure behaviour are verified.

### Associated data and packet integrity

In the intended packet design, the header is not encrypted but is authenticated as associated data. The receiver must use the exact corresponding associated data during decryption.

Authenticated encryption does not prevent an attacker from dropping, delaying, or replaying a previously valid packet. Replay defence requires additional protocol state and validation.

**Implementation requirement:** Use a vetted library, preserve exact associated-data encoding, enforce nonce uniqueness, and test rejection of modified ciphertext, tag, and authenticated header.

---

## 5. Digital Signatures: Ed25519

**Selected:** Ed25519 digital signatures, specified in RFC 8032.

### Rationale

- Ed25519 uses compact public keys and signatures.
- Signing is deterministic, avoiding the need for a fresh random signing nonce for every signature.
- It is supported by established cryptographic libraries.
- Its asymmetric model permits the validator to verify producer signatures using public keys without possessing the producers' private signing keys.

### Alternatives considered

| Alternative | Reason not selected for the initial design |
|---|---|
| ECDSA over P-256 | Not selected for the initial prototype; remains a valid alternative with correct implementation and nonce handling |
| RSA-PSS | Not selected because of its larger key and signature sizes relative to the chosen design |
| HMAC | Not selected for producer-origin authentication because every verifier holding the shared MAC key could also generate valid MACs |

These alternatives have different operational and cryptographic trade-offs; the decision does not imply that all are insecure.

### Signature coverage

The protocol design intends the producer signature to cover the original header and payload bytes. The exact byte encoding, canonicalisation rules, and validator verification path must remain consistent.

The relay's outgoing encryption is a separate security layer. Re-encrypting telemetry for the validator does not replace the producer signature or grant the relay the authority to sign as the producer.

### Security requirements and limitations

- Protect producer private keys.
- Bind each public key to the correct producer identity.
- Define key revocation and replacement.
- Reject malformed signatures and mismatched signed content.
- Record verification results without exposing private key material.

A valid signature proves that the signed bytes validate under a particular public key. It does not independently prove that the physical telemetry is accurate or that a specific human operated the signing system.

**Implementation requirement:** Use a maintained cryptographic library, verify the original signed content at the validator, and test that modified payloads are rejected.

---

## 6. Key Derivation: HKDF-SHA256

**Selected:** HKDF with SHA-256, specified in RFC 5869.

### Rationale

Raw key-agreement output should not be used directly as an application encryption key without an appropriate key-derivation process. HKDF provides extract-and-expand operations for deriving key material from shared secret input.

The intended design uses HKDF-SHA256 to derive session encryption key material.

A documented information string is:

`pitcrypt-f1-encryption-v1`

The exact salt, input key material, output length, and any additional context values must be defined by the implementation and protocol specification.

### Domain separation

If the system derives multiple keys for different directions, purposes, or protocol versions, the derivation inputs should distinguish those contexts. For example, producer-to-relay and relay-to-validator key material should not accidentally be interchangeable.

The precise labels and derivation rules must match the implementation; this ADR does not assume that all desired context separation has already been implemented.

### Security requirements

- Never expose raw shared secrets through logs or diagnostics.
- Define the derivation context and output length.
- Keep keys for distinct purposes separate.
- Ensure both peers derive the same intended key.
- Test that session and direction boundaries cannot be confused.

---

## 7. Hashing and Commitment Semantics

SHA-256 is used for hashing and for the prototype's hash-based commitment/check.

A SHA-256 hash or hash-based commitment comparison must not be described as a zero-knowledge proof. It does not, by itself, prove a statement while concealing the witness.

The security properties of a commitment depend on its exact construction, input encoding, randomisation, and verification protocol. A deterministic hash over predictable telemetry values may permit guessing attacks and does not provide the hiding property of a properly constructed Pedersen commitment.

If PitCrypt-F1 requires zero-knowledge verification or hiding commitments, that requirement must be specified independently and supported by a reviewed implementation integrated into the active processing path.

---

## 8. Performance Requirements

The project targets sustained telemetry processing and must evaluate cryptographic overhead alongside parsing, serialization, anomaly detection, network transport, and audit logging.

The nominal packet-rate target is a design objective, not a benchmark result.

Performance evaluation should record:

- End-to-end packet-processing latency.
- Median and p95 latency.
- Throughput under sustained load.
- CPU and memory usage.
- Packet rejection rates.
- Behaviour during malformed-input and replay floods.
- Performance on representative target hardware.

Measurements should distinguish local in-process simulation from networked testing. Results should include the hardware, software versions, configuration, packet sizes, workload, and test duration.

No specific throughput or latency guarantee is established by this ADR.

---

## 9. Security Consequences

### Positive consequences

- The selected primitives are specified in established standards.
- AEAD provides confidentiality and integrity protection within the defined message boundary.
- Asymmetric signatures separate producer signing authority from validator verification.
- Key derivation provides a defined mechanism for deriving session keys from shared secret material.
- Compact keys and signatures can reduce protocol overhead.

### Negative consequences and trade-offs

- Secure operation depends on correct nonce management, key provisioning, and session handling.
- X25519 and Ed25519 do not provide post-quantum security.
- Performance depends on implementation, workload, and hardware.
- A relay that decrypts telemetry can access plaintext during processing.
- Cryptographic integrity does not establish sensor accuracy or prevent denial of service.
- Additional protocol and operational controls are required for replay protection, audit integrity, and key compromise response.

### Implementation risks

- Incorrect associated-data encoding can break or weaken packet authentication.
- Incorrect signature coverage can leave fields unauthenticated or cause legitimate packets to fail verification.
- Incorrect key or nonce reuse can compromise security.
- Incorrect peer authentication can permit man-in-the-middle attacks.
- Incorrect error handling can leak information or cause service disruption.
- A separate cryptographic module does not provide security benefits to the active pipeline unless it is integrated and tested.

---

## 10. Implementation and Verification Requirements

Before describing this decision as fully implemented, verify:

1. X25519 peer keys are authenticated and correctly associated with identities.
2. HKDF inputs, salt, labels, and output lengths match the documented protocol.
3. ChaCha20-Poly1305 nonces are unique for each key and encryption operation.
4. The header is authenticated as associated data on both encryption legs where intended.
5. Ed25519 signs and verifies the same original header and payload bytes.
6. The validator rejects altered signed content.
7. Replay and sequence controls are active in the relevant execution path.
8. Key rotation, revocation, and replacement behave as documented.
9. No secret key material is written to logs or ordinary configuration output.
10. Security tests and performance measurements are reproducible.

The verification record should include the reviewed commit, relevant tests, configuration, known limitations, and any deviations from this ADR.

---

## 11. References

- RFC 7748 — Elliptic Curves for Security, including X25519.
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

These references specify the respective algorithms or constructions. Their existence does not certify PitCrypt-F1's implementation or deployment.

---

## 12. Review Conditions

Revisit this ADR when:

- The protocol changes its key agreement, encryption, signature, or derivation design.
- The active implementation diverges from the documented algorithms or parameters.
- A security review identifies an implementation weakness.
- Deployment constraints or performance measurements materially change.
- Post-quantum requirements become relevant.
- A commitment or zero-knowledge protocol is integrated.

**Decision summary:** X25519, ChaCha20-Poly1305, Ed25519, and HKDF-SHA256 are the selected primitives for the prototype. Their security depends on correct implementation, authenticated peer identity, sound key lifecycle management, and verification of the complete data path.
