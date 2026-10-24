# Key Management

**Project:** PitCrypt-F1  
**Document version:** 1.0  
**Status:** Prototype key-management reference  
**Last reviewed:** 24 October 2026

## 1. Purpose

This document describes the key types, responsibilities, lifecycle requirements, and operational safeguards relevant to cryptographic keys in PitCrypt-F1.

Key management is a security-critical part of the telemetry pipeline. Strong cryptographic algorithms cannot compensate for exposed private keys, unauthenticated public-key exchange, incorrect key reuse, inadequate access controls, or an unsafe key-replacement process.

PitCrypt-F1 is a prototype. This document distinguishes existing session-setup functionality from operational controls that require verification or future implementation. It does not assert that production key-management infrastructure is deployed.

## 2. Scope

This document covers:

- Long-term signing key pairs.
- X25519 key-agreement key pairs.
- Derived session keys.
- Key provisioning and peer identity binding.
- Session creation, replacement, expiry, and termination.
- Key exposure, revocation, and recovery.
- Key-related audit events and security testing.

This document does not define a complete network handshake protocol or claim that a hardware security module (HSM), cloud key-management service (KMS), certificate authority, or centralized production key registry is integrated into the prototype.

## 3. Current implementation status

The project includes X25519-based session setup, HKDF-SHA256 key derivation in the cryptographic design, ChaCha20-Poly1305 encryption, and Ed25519 signatures.

The relay's session setup code includes paths for establishing sessions with a car/producer node and a validator. The local simulation can establish these sessions in process.

The following limitations must remain explicit:

- The existence of session setup does not prove that public keys are authenticated over a network.
- A complete wire-level handshake and key-provisioning protocol must be verified separately.
- The exact storage, lifetime, replacement, and cleanup behaviour of each key must be checked against the current implementation.
- Production KMS/HSM integration and durable key custody must not be claimed without evidence.
- Secure memory erasure cannot be assumed merely because a session ends or a process exits.
- Automatic key rotation intervals must not be presented as implemented unless the relevant code and tests confirm them.

## 4. Key inventory

| Key or material | Purpose | Management requirements |
|---|---|---|
| Ed25519 private signing key | Signs producer telemetry or other defined messages | Restrict access, protect storage, define identity ownership, and revoke or replace if exposed. |
| Ed25519 public verification key | Verifies signatures | Bind to a trusted producer identity; validate key selection and replacement. |
| X25519 private key | Participates in session key agreement | Keep private, limit its lifetime where appropriate, and prevent disclosure through logs or APIs. |
| X25519 public key | Shared with a peer for key agreement | Authenticate or securely bind it to the expected peer identity. |
| X25519 shared secret | Intermediate key-agreement material | Do not log, transmit unnecessarily, or use directly as an application encryption key. |
| HKDF-derived session key | Protects telemetry using the configured cryptographic session | Scope to a session and purpose; prevent unintended reuse and define replacement behaviour. |
| ChaCha20-Poly1305 nonce | Ensures uniqueness of an AEAD encryption operation under a key | Enforce the required 12-byte format and prevent reuse under the same key. |
| SHA-256 checksum or commitment value | Supports defined integrity or consistency checks | Do not treat as a secret key or as a substitute for authentication. |

The table describes intended roles. Confirm the precise key ownership, generation, storage, and use of each item in the current code before treating the inventory as an exhaustive implementation record.

## 5. Key-management principles

### 5.1 Least privilege

Components should access only the key material needed for their responsibilities. Private keys and session secrets should not be exposed to dashboards, unrelated modules, users, or diagnostic interfaces.

In a production deployment, access should be restricted through explicit identities and authorization policies. The presence of prototype IAM/RBAC logic alone does not establish that all key access is centrally enforced.

### 5.2 Separation of duties

Signing, key agreement, encryption, and verification serve different purposes. Avoid using one key for unrelated cryptographic operations.

Where the protocol requires separate keys for producer-to-relay and relay-to-validator traffic, derive or provision them independently according to a documented key schedule.

### 5.3 Key identity and trust

A public key is not trustworthy merely because it was received from a peer. The protocol must define how the public key is associated with a specific producer, relay, or validator.

Possible production approaches include authenticated provisioning, a trusted registry, certificates, or a correctly implemented authenticated handshake. These are design options, not claims about the current prototype.

### 5.4 Confidentiality

Never include private keys, shared secrets, or derived encryption keys in:

- Application logs.
- Audit events.
- Dashboard output.
- Error messages.
- Example packet captures committed to source control.
- Public repositories, screenshots, or documentation.

Public keys may be shared where required by the protocol, but their authenticity and identity association still need to be protected.

### 5.5 Explicit lifecycle

Every key type should have a defined creation, use, replacement, revocation, and retirement process. The lifecycle must specify which component owns the key and what happens when a session or identity is no longer trusted.

## 6. Key generation and provisioning

### 6.1 Generation

Keys should be generated using a cryptographically secure random source and the relevant cryptographic library's supported key-generation interface.

The project should document:

- Which component generates each key pair.
- Whether keys are generated at startup, during session setup, or provisioned beforehand.
- Whether a key persists across process restarts.
- How generation failures are handled.
- Whether a key is shared across simulated nodes or unique to each identity.

Do not assume that each simulated producer has an independent long-term identity key unless this is verified in the code and configuration.

### 6.2 Provisioning

The project should define how a producer, relay, and validator obtain the public keys needed to communicate.

A secure provisioning process should authenticate the source of public keys and prevent unauthorized replacement. If keys are exchanged through a network handshake, the handshake must protect against public-key substitution.

For the current prototype, the existence of in-process session setup does not establish that provisioning is secure in a distributed deployment.

### 6.3 Configuration and secrets

Keep secrets separate from ordinary configuration wherever practical. Do not commit private keys or reusable production secrets to the repository.

For local development:

- Use dedicated test keys.
- Do not reuse real credentials.
- Exclude secret files from version control.
- Use clearly labelled development configuration.
- Ensure test fixtures do not contain real private key material.

Environment variables can reduce the need to place secrets in source files, but they are not, by themselves, a complete secrets-management solution.

## 7. Session key lifecycle

### 7.1 Establishment

The prototype contains session setup paths that use X25519 key agreement and register session cryptographic state with the relevant components.

The intended lifecycle is:

1. Identify the communicating peers.
2. Obtain the appropriate peer public key.
3. Establish key-agreement material.
4. Derive the required session key material using the documented key-derivation procedure.
5. Register the session with the appropriate cryptographic component.
6. Reject or fail safely if establishment cannot be completed.

This is a logical lifecycle description, not a claim that all six steps are implemented as a complete authenticated network protocol.

### 7.2 Session isolation

Session keys should be scoped to the intended peers, session, direction, and purpose. A session must not accidentally inherit another session's cryptographic state.

Tests should verify that:

- Different sessions do not unintentionally share derived keys.
- A failed handshake does not leave a partially registered session.
- Unknown or unexpected peers cannot use an unrelated session.
- Session state is associated with the correct producer and validator.
- A session cannot continue to be used after it has been invalidated, where invalidation is supported.

### 7.3 Session expiry and termination

The project should define what happens when a session expires, a peer disconnects, a key is revoked, or the process terminates.

At minimum, the design should address:

- Removing the session from active lookup structures.
- Preventing new operations from using an invalidated session.
- Clearing references to key material when no longer required.
- Avoiding secret leakage in shutdown diagnostics.
- Re-establishing a session only through the approved setup process.

Removing references does not guarantee physical erasure of key material from process memory. Secure erasure should not be claimed unless it is supported by the relevant runtime, cryptographic library, and implementation.

## 8. Key rotation

### 8.1 Current status

Do not treat any proposed rotation interval—such as a fixed number of seconds or packets—as an implemented guarantee unless the active code and tests confirm it.

Key rotation should be described as **implemented**, **configuration-dependent**, or **planned** only after the applicable behaviour has been verified.

### 8.2 Rotation requirements

A complete rotation design should define:

- Which keys rotate: long-term identity keys, ephemeral key-agreement keys, session keys, or some combination.
- What triggers rotation, such as expiry, packet count, session restart, suspected exposure, or administrative action.
- How both parties transition to the new key.
- How packets associated with the old session are handled during the transition.
- How failed rotation is detected and recovered from.
- How the previous key is invalidated and retired.
- How rotation events are recorded without exposing secret material.

### 8.3 Forward secrecy

Using X25519 does not, on its own, establish forward secrecy for the deployed protocol.

Forward secrecy depends on the full key-establishment design, including ephemeral key handling, authentication, key derivation, and destruction or unavailability of the relevant private key material after use.

Do not claim forward secrecy until the implemented handshake and key lifecycle have been reviewed and tested against that property.

## 9. Revocation and compromise response

### 9.1 Triggers

Consider a key compromised when there is credible evidence of unauthorized access, accidental publication, unexpected signing activity, unauthorized key replacement, or a failure of the intended trust boundary.

A suspected compromise should be handled promptly even when the full extent of exposure is unknown.

### 9.2 Response procedure

1. **Identify:** Determine the affected identity, key type, session, and time window.
2. **Contain:** Prevent further use of the affected key or session where the system supports this.
3. **Preserve evidence:** Retain relevant logs and configuration snapshots without copying exposed secrets into incident records.
4. **Assess impact:** Identify potentially affected packets, sessions, signatures, and downstream decisions.
5. **Replace:** Generate or provision replacement key material through a trusted process.
6. **Re-establish trust:** Verify the replacement public key and associated identity before accepting new traffic.
7. **Validate:** Test that the old key or session is no longer accepted where revocation is supported.
8. **Document:** Record the event, scope, decisions, recovery steps, and remaining limitations.

A response procedure in documentation does not mean the prototype automatically revokes a key or performs these steps. Manual intervention may be necessary.

### 9.3 Revocation requirements

The project should define how a verifier learns that a key is no longer trusted. Possible mechanisms include a trusted registry, a revocation list, or an authenticated control channel.

Until such a mechanism is implemented and tested, do not claim immediate, network-wide revocation.

## 10. Key storage and deployment

### 10.1 Current prototype

The project must accurately document where keys are stored in the current execution path—for example, in process memory, configuration, test fixtures, or files. This must be determined from the code and deployment configuration rather than assumed.

No production KMS or HSM should be described as integrated unless the repository and deployment evidence demonstrate that integration.

### 10.2 Production-oriented controls

A future deployment should evaluate:

- A dedicated secrets manager or KMS for supported key types.
- An HSM or equivalent protected storage for high-value long-term private keys where appropriate.
- Restricted service identities and explicit access policies.
- Separation between development, testing, and production keys.
- Key-access monitoring and administrative audit trails.
- Backup and recovery procedures that do not create uncontrolled key copies.
- Documented ownership and responsibility for key replacement.
- Secure handling of secrets in CI/CD pipelines.

These are recommended controls for a more mature deployment, not current implementation claims.

## 11. Key-related audit events

Audit events should record lifecycle and security-relevant outcomes without storing private key material or derived secrets.

Useful event types include:

- Session establishment succeeded or failed.
- Unexpected peer or public key was rejected.
- Key replacement or rotation was initiated or completed.
- A session was invalidated.
- A signature verification failed.
- AEAD authentication failed.
- A revoked or unknown key was rejected.
- Key-related configuration changed.
- A key compromise was reported and contained.

Where available, an event may include a timestamp, event type, node identity, session identifier, outcome, and reason. Avoid logging raw secrets or sensitive cryptographic state.

The prototype's audit logger supports in-memory events and optional JSONL output. This does not by itself provide immutable storage, tamper-proof records, centralized monitoring, or a guaranteed durable audit trail.

## 12. Testing and acceptance checklist

Before making production-oriented key-management claims, verify and record the following:

- [ ] Key-generation sources and ownership are documented.
- [ ] Private-key storage locations and access paths are known.
- [ ] Public keys are bound to trusted peer identities.
- [ ] Session establishment fails safely for invalid inputs.
- [ ] Session keys are derived with documented HKDF parameters.
- [ ] Keys are separated by session, purpose, and direction where required.
- [ ] AEAD nonces are not reused with the same key.
- [ ] Key material is not written to logs or dashboard output.
- [ ] Session expiry and invalidation behaviour is tested.
- [ ] Rotation triggers and transition behaviour are verified, if implemented.
- [ ] Replacement keys are authenticated and old keys are rejected where revocation is supported.
- [ ] Restart and recovery behaviour is documented.
- [ ] Compromise-response steps are tested or clearly identified as manual procedures.
- [ ] Any external KMS/HSM integration is supported by implementation and configuration evidence.
- [ ] Key-management claims are consistent with reproducible tests.

Record the test environment, relevant configuration, test cases, and observed results. Do not mark a control as verified solely because it appears in this document.

## 13. Open implementation questions

Resolve these questions against the current source before finalizing production-oriented documentation:

1. Where are Ed25519 and X25519 private keys generated and stored?
2. Are long-term identity keys distinct from session key-agreement keys?
3. What exact HKDF salt, context, and output lengths are used?
4. How are peer public keys authenticated and bound to node identities?
5. Is session establishment implemented only in the local simulation, or is there a complete network handshake path?
6. How are session keys replaced, expired, and removed?
7. Is automatic rotation implemented? If so, what triggers it and how is the transition synchronized?
8. What happens to existing sessions after a key is suspected to be compromised?
9. Are secrets ever included in exceptions, debug logs, or telemetry dumps?
10. What evidence supports any claim of secure key erasure or forward secrecy?

Until these questions are resolved, state the relevant limitations explicitly.

## 14. Maintenance

Update this document whenever key generation, session setup, key derivation, storage, rotation, revocation, or deployment architecture changes.

When an intended control is implemented, update the status only after verifying the corresponding source path and tests. Keep implementation status separate from recommended production controls so that this document remains an accurate reference for PitCrypt-F1.
