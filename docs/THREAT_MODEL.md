# Threat Model — PitCrypt-F1

**Document:** `THREAT_MODEL.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Classification:** Security Architecture  
**Status:** Implementation-aligned draft  
**Last reviewed:** 24 October 2026

---

## 1. Executive Summary

PitCrypt-F1 is a prototype security framework for protecting telemetry as it moves through a logical car producer → relay → validator pipeline. It combines packet encryption, digital signatures, integrity checks, sequence validation, anomaly detection, access-control components, and audit logging.

The intended security model assumes that network paths may be exposed to interception, replay, modification, impersonation, and denial-of-service attacks. It also considers compromised nodes, malicious insiders, and unauthorised access to telemetry or cryptographic material.

This threat model uses STRIDE to identify threats, document the controls intended to address them, and highlight residual risks.

**Important scope limitation:** PitCrypt-F1 is a research and engineering prototype, not a deployed FIA telemetry security system. Its local simulation invokes pipeline components in-process; this does not by itself demonstrate security under real network conditions. The existence of a security component or simulation does not establish that its control is active in every execution path.

The document distinguishes between:

- **Implemented mechanism:** A relevant mechanism exists in the codebase.
- **Partial or configuration-dependent:** A mechanism exists, but its coverage, configuration, or integration requires verification.
- **Proposed production control:** A design recommendation that must not be treated as deployed functionality.
- **Not demonstrated:** Available evidence is insufficient to claim the threat is mitigated.

No claim of FIA approval, regulatory compliance, production readiness, or complete threat elimination is made.

---

## 2. System Architecture and Scope

### 2.1 Logical architecture

```text
┌──────────────────────┐
│ Car Producer         │
│                      │
│ Telemetry generation │
│ Packet construction  │
│ Signing and encrypt. │
└──────────┬───────────┘
           │
           │ Car → Relay session
           │ Untrusted transport in intended deployment
           ▼
┌──────────────────────┐
│ Relay Node           │
│                      │
│ Parse envelope       │
│ Decrypt and inspect  │
│ Integrity checks     │
│ Anomaly processing   │
│ Re-encrypt and relay │
└──────────┬───────────┘
           │
           │ Relay → Validator session
           │ Untrusted transport in intended deployment
           ▼
┌──────────────────────┐
│ Validator            │
│                      │
│ Decrypt and verify   │
│ Signature checks     │
│ Sequence/replay      │
│ Commitment checks    │
│ Audit decision       │
└──────────────────────┘
```

This diagram represents the **logical security pipeline**, not proof that each component runs as a separate network service in every configuration.

The local simulation serializes a JSON envelope and calls the relay processing function directly. A complete deployed transport, handshake protocol, service authentication, and network security configuration must be assessed separately.

### 2.2 Assets requiring protection

| Asset | Security objective | Potential consequence of compromise |
|---|---|---|
| Telemetry payload | Confidentiality and integrity | Exposure or manipulation of vehicle-performance data |
| Packet header | Integrity and correct interpretation | Incorrect sequence, timestamp, or routing metadata |
| Car identity private keys | Confidentiality and authenticity | Forged telemetry attributed to a legitimate car |
| Session keys | Confidentiality | Exposure of traffic protected by the affected session |
| Sequence and replay state | Integrity and availability | Duplicate, stale, or incorrectly ordered packets being accepted |
| Commitment values | Integrity of the associated check | Failure to detect certain payload inconsistencies |
| Audit records | Integrity, availability, and traceability | Loss or alteration of evidence |
| Access-control policies | Least privilege | Unauthorised actions or cross-team data access |
| Telemetry processing capacity | Availability | Delayed or missing telemetry decisions |

### 2.3 Trust boundaries

**Car producer:** Intended origin of telemetry and its associated signature. The prototype does not, by itself, establish that a real vehicle ECU or hardware root of trust is trusted.

**Relay:** Intermediate processing component. It decrypts the incoming leg, performs configured checks and anomaly processing, and prepares outgoing telemetry. A compromised relay can inspect plaintext while processing it.

**Validator:** Intended authoritative decision point. Its acceptance or rejection is only as trustworthy as its verification logic, key configuration, sequence state, and audit implementation.

**Transport:** Must be treated as untrusted in the threat model. The local in-process simulation does not reproduce all network threats.

**Configuration and key distribution:** Separate trust dependencies. Incorrect public-key mapping, compromised configuration, or insecure provisioning can undermine cryptographic protections even when the underlying algorithms work correctly.

**Audit storage:** A separate trust boundary is required if audit evidence must remain trustworthy after compromise of the application or host.

### 2.4 Assumptions

This assessment assumes:

1. Attackers may observe, delay, replay, reorder, drop, or modify network traffic.
2. Attackers may submit malformed envelopes or excessive numbers of requests.
3. An attacker may compromise one component without immediately compromising every component.
4. Private keys and session keys are security-sensitive assets.
5. Configuration, key provisioning, and verification-key mappings must be correct.
6. Telemetry may contain commercially sensitive information.
7. Prototype behaviour may differ from intended production behaviour because of configuration, missing integrations, or execution-path differences.

This assessment does not assume that the relay is unable to see plaintext. In the current logical design, the relay decrypts incoming telemetry for inspection.

---

## 3. STRIDE Methodology

STRIDE groups threats into six categories:

- **S — Spoofing:** Impersonating a legitimate identity or component.
- **T — Tampering:** Modifying data, configuration, or evidence without authorisation.
- **R — Repudiation:** Denying an action where adequate evidence is unavailable.
- **I — Information Disclosure:** Exposing confidential data or secrets.
- **D — Denial of Service:** Preventing legitimate processing or access.
- **E — Elevation of Privilege:** Performing actions beyond the intended permissions.

The likelihood ratings below are preliminary qualitative assessments, not measured probabilities. Actual risk depends on deployment architecture, network exposure, attacker capability, configuration, and the value of the protected telemetry.

### Status definitions

| Status | Meaning |
|---|---|
| Implemented mechanism | Relevant code exists; deployment effectiveness still requires testing |
| Partial / configuration-dependent | Coverage or configuration is incomplete or needs verification |
| Proposed | Recommended control not established as active in the prototype |
| Not demonstrated | Current evidence does not support a mitigation claim |

---

## 4. S — Spoofing

Spoofing threats concern false claims about the identity of a car, relay, validator, or other participant.

### S1 — Car identity spoofing

**Target:** Validator  
**Attack vector:** An attacker creates a packet claiming to originate from a recognised car, such as a Mercedes or Red Bull telemetry producer.

**Impact:** Fabricated telemetry may be attributed to a legitimate source if identity and signature verification are absent, incorrectly configured, or bypassed.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Ed25519 signatures provide a mechanism for authenticating signed packet content.
- The validator-side signature-verification component is intended to verify the original producer signature.
- Verification must use the public key correctly associated with the claimed producer identity.

**Implementation status:** Implemented mechanism; end-to-end identity binding and key provisioning require verification.

**Residual risk:**

- A compromised producer signing key permits signatures that appear valid.
- A public-key registry that maps identities incorrectly can undermine source authentication.
- A valid signature does not prove that the sensor data itself is physically accurate.
- A compromised producer can sign fabricated data using its legitimate key.

**Recommended production controls:** Use authenticated key provisioning, protected private-key storage, key revocation, identity-to-key binding, and documented key-compromise procedures. AWS KMS/HSM integration is a production option, not an assumed property of the local prototype.

### S2 — Relay impersonation

**Target:** Car producer  
**Attack vector:** An attacker presents a rogue relay key or endpoint and attempts to establish a session with the producer.

**Impact:** Telemetry could be disclosed to an attacker or diverted away from the intended relay if the producer accepts an unauthenticated endpoint.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The codebase includes X25519 session setup functionality.
- Key agreement can establish shared secret material, but key agreement alone does not establish the identity of the peer.
- The intended design relies on correctly provisioning and authenticating relay public keys.

**Implementation status:** Partial / configuration-dependent.

**Residual risk:** The existence of X25519 handshake functions does not establish a complete authenticated wire-level handshake. Peer authentication, public-key distribution, and resistance to man-in-the-middle attacks must be demonstrated end to end.

**Recommended production controls:** Authenticate handshake messages, bind peer identities to public keys, validate keys against a trusted registry, and use an authenticated provisioning channel.

### S3 — Validator impersonation

**Target:** Relay  
**Attack vector:** A malicious endpoint claims to be the validator and attempts to receive forwarded telemetry.

**Impact:** Confidential telemetry may be disclosed, or the relay may send data to an unauthorised destination.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The relay contains separate session-setup functionality for its validator-facing leg.
- X25519 can establish session key material.
- ChaCha20-Poly1305 can protect messages when the correct key and associated data are used.

**Implementation status:** Partial / configuration-dependent.

**Residual risk:** Encryption does not independently authenticate the intended validator. The end-to-end identity binding and network handshake must be verified.

**Recommended production controls:** Authenticate the validator endpoint, validate its provisioned identity, restrict permitted destinations, and test rogue-endpoint and man-in-the-middle scenarios.

### S4 — Unknown-node injection

**Target:** Relay and validator  
**Attack vector:** An unrecognised node submits telemetry or attempts a privileged operation.

**Impact:** Unauthorised data may enter the pipeline, or an attacker may access functions outside its intended role.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The repository contains an IAM/RBAC module intended to apply role-based permissions and default-deny decisions.
- Packet parsing, cryptographic checks, and access-control checks may reject invalid input, depending on the path used.

**Implementation status:** Partial / integration-dependent.

**Residual risk:** The presence of an RBAC engine does not establish that every network request is authenticated and authorised before processing. Simulation results do not prove universal enforcement across every entry point.

**Recommended production controls:** Enforce identity and authorisation at every externally reachable entry point, test default-deny behaviour, and verify that unknown identities cannot establish sessions or submit accepted telemetry.

---

## 5. T — Tampering

Tampering threats involve unauthorised changes to telemetry, metadata, configuration, or audit evidence.

### T1 — In-transit payload modification

**Target:** Encrypted telemetry  
**Attack vector:** A man-in-the-middle modifies ciphertext, an authentication tag, or other protected packet data.

**Impact:** The packet may be corrupted or an attacker may attempt to inject altered telemetry.

**Preliminary likelihood:** Medium

**Relevant controls:**

- ChaCha20-Poly1305 provides authenticated encryption with associated data.
- The relay decryption path handles authentication failures, including invalid AEAD tags.
- The intended design uses the header as associated data, authenticating it without encrypting it.

**Implementation status:** Implemented mechanism; end-to-end coverage depends on the envelope and encryption/decryption paths.

**Residual risk:** AEAD protects data only when the receiver uses the correct key, nonce, ciphertext, and associated data. It does not prevent packet dropping, delay, or replay by itself.

**Evidence required:** Confirm that a modified ciphertext or tag is rejected by the actual relay processing path, and retain reproducible test output.

### T2 — Header manipulation

**Target:** Packet header, including sequence number, timestamp, team identifier, and payload metadata  
**Attack vector:** An attacker alters header bytes to change packet interpretation or bypass sequence and freshness checks.

**Impact:** Incorrect metadata may be processed, or integrity controls may fail if the header is not authenticated consistently.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The packet format specifies a fixed binary header.
- In the intended AEAD design, header bytes are supplied as associated data.
- Header authentication is effective only when the receiver authenticates the exact header bytes associated with the ciphertext.

**Implementation status:** Partial / path-dependent.

**Residual risk:** The local relay processing path uses a JSON envelope containing `header_hex`; it calls JSON parsing and validation before decryption. The complete relationship between the JSON fields, header bytes, and AEAD associated data must be checked across the relevant functions.

**Recommended verification:** Modify individual header fields and the encoded header independently, then verify that inconsistent metadata and authenticated data are rejected.

### T3 — Relay-side payload modification

**Target:** Decrypted telemetry at the relay  
**Attack vector:** A compromised relay modifies speed, RPM, throttle, braking, gear, or position values before forwarding the packet.

**Impact:** Altered data may reach the validator.

**Preliminary likelihood:** Medium if the relay is compromised

**Relevant controls:**

- The original producer signature is intended to cover the original header and payload.
- The relay re-encrypts the forwarded telemetry for the validator-facing session.
- The validator is intended to verify the producer signature.

**Implementation status:** Implemented mechanism; verification of the exact re-encryption and signature-verification path is required.

**Residual risk:** Re-encryption is not equivalent to a new producer signature. If the relay modifies signed bytes, verification should fail provided that the validator verifies the original signature against the original signed content. A compromised relay can still drop, delay, selectively forward, or inspect plaintext.

**Recommended verification:** Modify a signed payload field at the relay, forward it, and verify that the validator rejects the modified content while a legitimate unmodified packet remains acceptable.

### T4 — Audit record tampering

**Target:** Validator audit records  
**Attack vector:** An attacker modifies, deletes, reorders, or fabricates audit records after a decision.

**Impact:** Incident investigation, traceability, and dispute resolution become less reliable.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The project contains an audit logger that records decision-related information.
- The logger can maintain records in memory and optionally write JSONL output.

**Implementation status:** Partial.

**Residual risk:** An in-memory list or ordinary JSONL file is not inherently immutable, append-only in the security sense, or tamper-evident. A compromised host or sufficiently privileged process may alter or delete records. CloudTrail is not assumed to be configured or integrated.

**Recommended production controls:**

- Export audit events to a separately administered logging service.
- Restrict modification and deletion privileges.
- Use integrity protection, access monitoring, retention policies, and independent backups.
- Test whether records can be altered by a compromised application or host.

### T5 — Commitment manipulation

**Target:** Payload commitment or associated hash value  
**Attack vector:** An attacker replaces the commitment, modifies the payload, or exploits inconsistent commitment computation.

**Impact:** A payload-consistency check may fail to detect an alteration if the expected value is not authenticated or recomputed correctly.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The active Python verification path uses a SHA-256-based commitment/check derived from the payload and nonce.
- The validator-side verifier recomputes the value and compares it with the supplied commitment, according to the implemented scheme.
- The producer signature and AEAD protections provide separate integrity mechanisms when correctly applied.

**Implementation status:** Partial / implementation-dependent.

**Residual risk:**

- A SHA-256 hash-based commitment is **not a zero-knowledge proof**.
- Its security depends on the exact input encoding, nonce handling, binding of the commitment to the signed packet, and comparison performed by the verifier.
- A hash commitment without an appropriate secret randomisation scheme does not provide the hiding guarantees of a properly designed Pedersen commitment.
- A commitment does not prove that telemetry is physically correct.

**Recommended verification:** Test payload alteration, commitment alteration, nonce alteration, malformed values, and inconsistent encodings. Document the active Python verifier separately from any Rust cryptographic module that is not integrated into the live path.

---

## 6. R — Repudiation

Repudiation threats concern a participant denying an action when the system lacks sufficient trustworthy evidence to establish what happened.

### R1 — Producer denies sending a packet

**Target:** Incident investigation and validator decision process  
**Attack vector:** A team disputes that it generated or transmitted a particular packet.

**Impact:** Attribution may be contested during an investigation.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Ed25519 signatures can provide evidence that a packet was signed by the holder of a particular private key.
- Validator audit records can associate decisions with packet metadata.

**Implementation status:** Partial.

**Residual risk:** A valid signature is evidence of key use, not conclusive proof of which person or process operated the key. Key compromise, shared credentials, incorrect identity mapping, or incomplete audit records weaken attribution. The term “non-repudiation” should not be treated as an unconditional guarantee.

**Recommended production controls:** Protect signing keys, record key identifiers and verification outcomes, maintain key-lifecycle records, and preserve audit evidence independently.

### R2 — Relay denies receiving or forwarding a packet

**Target:** Delivery-chain investigation  
**Attack vector:** A relay operator denies receiving, inspecting, or forwarding a packet.

**Impact:** Investigators may be unable to determine where telemetry was delayed, dropped, or altered.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The original producer signature can help preserve attribution of signed content.
- Validator records may establish that a packet was received and processed.

**Implementation status:** Partial.

**Residual risk:** A validator record can establish receipt at the validator only to the extent that the record itself is trustworthy. It does not independently prove that the relay received every missing packet or explain why a packet was not forwarded.

**Recommended production controls:** Generate authenticated receive/forward events at each stage, correlate them with packet identifiers and sequence numbers, and export records to an independently administered audit system.

### R3 — Validator disputes or misrepresents a decision

**Target:** Audit and incident review  
**Attack vector:** A validator operator disputes an earlier decision, or an attacker modifies records to make the decision appear different.

**Impact:** Investigators may be unable to reconstruct whether a packet was accepted, rejected, or flagged.

**Preliminary likelihood:** Low to medium

**Relevant controls:**

- The audit logger records decision-related fields, including timestamps, sequence numbers, node identity, and reasons where supplied.
- JSONL export can support later review.

**Implementation status:** Partial.

**Residual risk:** A JSONL log is not automatically immutable. A log record alone also does not prove that the decision was correct or that all decisions were recorded.

**Recommended production controls:** Use independently protected audit storage, record software/configuration versions, retain rejection details, and test log completeness and tamper detection.

---

## 7. I — Information Disclosure

Information-disclosure threats concern exposure of telemetry, cryptographic secrets, or operational metadata.

### I1 — Telemetry interception

**Target:** Telemetry in transit  
**Attack vector:** An attacker passively captures car-to-relay or relay-to-validator traffic.

**Impact:** Vehicle-performance information or other commercially sensitive telemetry may be exposed.

**Preliminary likelihood:** High where transport is exposed and encryption is absent or incorrectly configured

**Relevant controls:**

- ChaCha20-Poly1305 is used as the intended authenticated-encryption mechanism.
- X25519 and HKDF-SHA256 are present in the session-cryptography design.
- Separate sessions are intended for the two pipeline legs.

**Implementation status:** Implemented mechanisms; complete deployment coverage and key exchange authentication require verification.

**Residual risk:**

- Headers and other envelope metadata may remain visible.
- A relay decrypts incoming telemetry for inspection and can therefore access plaintext during processing.
- Encryption does not protect data after it reaches a compromised endpoint.
- Forward secrecy must not be claimed solely because ephemeral key agreement or key rotation exists. It depends on the complete handshake, key lifecycle, and erasure behaviour.

**Recommended production controls:** Authenticate the handshake, protect endpoints, minimise plaintext retention, and test traffic capture on both legs.

### I2 — Session-key exposure

**Target:** Session encryption keys  
**Attack vector:** An attacker obtains a memory dump, compromises a process, or accesses secrets through an insecure debugging or deployment interface.

**Impact:** Traffic protected by the exposed key may be decrypted or forged, depending on the key and session design.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The design derives session cryptographic material from key agreement.
- Session keys are intended to be maintained in memory during processing.

**Implementation status:** Partial / lifecycle-dependent.

**Residual risk:** The duration and scope of exposure depend on key reuse, rotation, session separation, memory handling, and whether old keys remain accessible. Secure memory erasure and effective rotation have not been established by the architectural description alone.

**Recommended production controls:** Minimise key lifetime, restrict process access, avoid secret logging, validate rotation behaviour, and use a secure key-management facility where appropriate.

### I3 — Producer identity-key exposure

**Target:** Ed25519 private keys  
**Attack vector:** An attacker extracts a signing key from application memory, local files, deployment secrets, or a compromised host.

**Impact:** The attacker may create signatures that validate under the compromised public key.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Ed25519 signatures provide authenticity when private keys remain protected.
- External key-management services or hardware-backed storage may reduce private-key exposure in production.

**Implementation status:** Key protection is a production requirement; AWS KMS/HSM integration is not assumed to be implemented.

**Residual risk:** A key stored in application memory or accessible local storage may be exposed by host or process compromise. Key revocation and replacement must be supported operationally.

**Recommended production controls:** Use protected signing-key storage, limit signing permissions, rotate and revoke compromised keys, and audit signing requests.

### I4 — Commitment-based privacy failure

**Target:** Telemetry values and commitment metadata  
**Attack vector:** An attacker or unauthorised recipient guesses telemetry values from a commitment, especially when values come from a small, predictable range.

**Impact:** A value intended to remain confidential may be inferred.

**Preliminary likelihood:** Medium, depending on the commitment construction and the attacker's knowledge

**Relevant controls:**

- The active Python path uses a SHA-256-based commitment/check.
- A properly implemented Pedersen commitment can provide hiding properties when used with appropriate randomisation and correct parameter handling.

**Implementation status:** Partial.

**Residual risk:** The active hash-based check does not provide the privacy guarantees of a hiding zero-knowledge commitment scheme. The existence of a separate Rust module does not establish that its cryptographic protocol is integrated into the live packet pipeline.

**Recommended production controls:** Define the precise privacy objective, use a reviewed commitment or proof protocol if confidentiality of committed values is required, and verify that the deployed verifier uses it.

### I5 — Metadata and configuration disclosure

**Target:** Packet metadata, configuration files, logs, and diagnostic output  
**Attack vector:** An attacker obtains visible header fields, session metadata, internal endpoints, debug output, or configuration values.

**Impact:** Information may assist traffic analysis, reconnaissance, or subsequent attacks.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Payload encryption can protect telemetry content.
- Logging and configuration access can be restricted through host and application permissions.

**Implementation status:** Partial / deployment-dependent.

**Residual risk:** Encryption of the payload does not automatically conceal headers, traffic timing, packet volume, team identifiers, or operational configuration.

**Recommended production controls:** Minimise sensitive logging, remove secrets from configuration output, restrict diagnostic interfaces, and assess metadata exposure from captured traffic.

---

## 8. D — Denial of Service

Denial-of-service threats attempt to degrade the availability, responsiveness, or throughput of telemetry processing.

### D1 — Packet-flood attack

**Target:** Relay and validator processing capacity  
**Attack vector:** An attacker submits excessive valid-looking or malformed packets.

**Impact:** CPU or memory exhaustion, queue growth, increased latency, or loss of legitimate telemetry.

**Preliminary likelihood:** High for an exposed, insufficiently rate-limited endpoint

**Relevant controls:**

- The relay validates JSON envelopes before decrypting them in its processing path.
- Parse failures and other errors can cause packets to be rejected.
- Network settings and queue limits may be available in parts of the project.

**Implementation status:** Partial / deployment-dependent.

**Residual risk:** Cheap rejection does not eliminate the cost of parsing, connection handling, memory allocation, cryptographic operations, or logging. A configured queue limit is not proof that every live execution path enforces bounded resource use.

**Recommended production controls:** Apply per-identity and per-source rate limits, bound packet and connection sizes, enforce queue and timeout limits, use backpressure, and monitor resource exhaustion.

### D2 — Cryptographic processing exhaustion

**Target:** Relay decryption and validator verification  
**Attack vector:** An attacker submits many packets that trigger repeated parsing, decryption, signature verification, or other expensive operations.

**Impact:** Processing capacity is consumed and legitimate telemetry is delayed or dropped.

**Preliminary likelihood:** Medium

**Relevant controls:**

- AEAD authentication rejects modified ciphertext when decryption is performed with the correct key and associated data.
- Parsing and envelope validation can reject malformed inputs before later processing stages.

**Implementation status:** Partial.

**Residual risk:** Invalid packets still consume resources before rejection. Authentication-tag checking is not a universal zero-cost filter, and constant-time primitive implementations do not prevent denial of service caused by request volume.

**Recommended production controls:** Bound input sizes, apply admission control and rate limiting, monitor cryptographic workload, and benchmark under adversarial traffic.

### D3 — Key-rotation disruption

**Target:** Session establishment and key lifecycle  
**Attack vector:** An attacker exploits session churn, repeated handshake requests, or poorly coordinated key changes to disrupt packet processing.

**Impact:** Session failures, packet rejection, increased latency, or loss of continuity.

**Preliminary likelihood:** Medium if rotation is implemented without safe coordination

**Relevant controls:**

- The project contains session setup and cryptographic components.
- Rotation policy and scheduler behaviour must be evaluated against the actual execution path.

**Implementation status:** Not demonstrated as a complete end-to-end control by the currently reviewed relay processing path.

**Residual risk:** A proposed rotation interval does not prove that rotation is active, non-blocking, rate-limited, or resistant to attacker-triggered session churn.

**Recommended production controls:** Coordinate session transitions, authenticate rekey requests, limit handshake frequency, test overlapping key lifetimes where appropriate, and preserve clear failure behaviour.

### D4 — Replay and sequence-state exhaustion

**Target:** Sequence checker and replay state  
**Attack vector:** An attacker repeatedly submits captured packets or produces many distinct sequence values to consume state or trigger expensive checks.

**Impact:** Memory growth, excessive rejection logging, or disruption of legitimate packet processing.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Relay and validator components include sequence/integrity checking.
- Configurable sequence-gap limits are used by the processing components.

**Implementation status:** Partial / configuration-dependent.

**Residual risk:** Sequence checking can reject duplicates without providing a bounded-memory guarantee. A rolling window of a particular size must not be assumed unless its implementation and eviction behaviour have been verified.

**Recommended production controls:** Bound replay-state memory, define sequence-reset and session-transition behaviour, rate-limit repeated failures, and test sustained replay floods.

---

## 9. E — Elevation of Privilege

Elevation-of-privilege threats occur when a component or user gains permissions beyond its intended role.

### E1 — Car producer gains validator privileges

**Target:** IAM/RBAC enforcement  
**Attack vector:** A car identity attempts to read validator records, perform privileged verification operations, or change security policy.

**Impact:** A producer could access restricted data or influence decisions outside its intended responsibilities.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The project includes an RBAC engine with role and permission checks.
- The intended security policy follows least privilege and default deny.

**Implementation status:** Partial / integration-dependent.

**Residual risk:** An RBAC simulation does not establish that every real entry point invokes the policy engine. Permission names and resource scopes must also match the actual operations being protected.

**Recommended production controls:** Enforce authorisation at each service boundary, test negative permissions, and audit policy changes.

### E2 — Relay forges producer telemetry

**Target:** Producer identity and signature-verification boundary  
**Attack vector:** A compromised relay modifies telemetry and attempts to make it appear as if the car signed the altered data.

**Impact:** The validator may accept fabricated telemetry if it does not verify the original producer signature correctly.

**Preliminary likelihood:** Medium if the relay is compromised

**Relevant controls:**

- The original producer signature is intended to be preserved through relay processing.
- The validator is intended to verify that signature against the producer's public key.
- Relay encryption for the next session is distinct from producer signing.

**Implementation status:** Implemented mechanism; end-to-end test required.

**Residual risk:** The relay can access plaintext during processing and may drop, delay, or selectively forward data. The signature check only prevents undetected changes to the signed content when correctly implemented and enforced.

**Recommended production controls:** Keep producer signing authority separate from relay permissions, verify original signed content at the validator, and test relay compromise scenarios.

### E3 — Cross-team telemetry access

**Target:** Team isolation  
**Attack vector:** A producer or operator attempts to read another team's telemetry or reuse another team's session context.

**Impact:** Competitor data may be disclosed, undermining confidentiality and trust.

**Preliminary likelihood:** Medium

**Relevant controls:**

- Separate sessions are intended for different pipeline legs and car identities.
- The IAM module contains role and resource permission checks.
- Encryption can prevent access by parties that do not possess the relevant session key.

**Implementation status:** Partial / configuration-dependent.

**Residual risk:** Session separation does not by itself prove that application buffers, logs, APIs, or shared process memory enforce team isolation. A compromised relay may see decrypted telemetry in the current design.

**Recommended production controls:** Bind identities, teams, sessions, and keys explicitly; enforce team-level authorisation; minimise shared state; and test cross-team access at each interface.

### E4 — Configuration or dependency compromise

**Target:** Security configuration and software supply chain  
**Attack vector:** An attacker modifies configuration, replaces a dependency, or compromises a build or deployment process.

**Impact:** Security checks may be disabled, keys may be redirected, or malicious code may execute with application privileges.

**Preliminary likelihood:** Medium

**Relevant controls:**

- The project uses configuration-driven processing behaviour.
- Tests can provide evidence for specific expected behaviours.

**Implementation status:** Additional controls required for production.

**Residual risk:** Passing tests does not prove the integrity of deployment artefacts or runtime configuration. A secure cryptographic design can be undermined by a malicious dependency or altered configuration.

**Recommended production controls:** Pin and review dependencies, scan and verify build artefacts, protect deployment credentials, restrict configuration changes, and record the version and configuration associated with each run.

---

## 10. STRIDE Summary Matrix

The statuses below describe the current evidence level, not a guarantee that the corresponding attack is impossible.

| ID | Threat | Category | Preliminary likelihood | Main control | Assessment |
|---|---|---|---|---|---|
| S1 | Car identity spoofing | Spoofing | Medium | Ed25519 and trusted key mapping | Partial / key lifecycle |
| S2 | Relay impersonation | Spoofing | Medium | X25519 session setup and peer authentication | Partial / handshake verification |
| S3 | Validator impersonation | Spoofing | Medium | Validator-facing session and peer authentication | Partial / handshake verification |
| S4 | Unknown-node injection | Spoofing | Medium | Identity validation and RBAC | Partial / integration |
| T1 | Payload modification | Tampering | Medium | ChaCha20-Poly1305 AEAD | Mechanism implemented; path testing required |
| T2 | Header manipulation | Tampering | Medium | Header as AEAD associated data | Partial / path-dependent |
| T3 | Relay payload modification | Tampering | Medium | Original producer signature verification | End-to-end test required |
| T4 | Audit record tampering | Tampering | Medium | Audit logging and restricted storage | Partial / external protection required |
| T5 | Commitment manipulation | Tampering | Medium | SHA-256 commitment/check | Partial / not a ZKP |
| R1 | Producer denies sending | Repudiation | Medium | Signature and audit evidence | Partial / key attribution |
| R2 | Relay denies forwarding | Repudiation | Medium | Stage-specific audit events | Partial / independent evidence |
| R3 | Validator disputes decision | Repudiation | Low–Medium | Decision logging | Partial / tamper resistance |
| I1 | Telemetry interception | Information disclosure | High if unencrypted | AEAD and session keys | Partial / deployment coverage |
| I2 | Session-key exposure | Information disclosure | Medium | Session lifecycle and key protection | Partial / erasure and rotation |
| I3 | Identity-key exposure | Information disclosure | Medium | Private-key protection | Production control required |
| I4 | Commitment privacy failure | Information disclosure | Medium | Commitment construction | Partial / hash is not hiding |
| I5 | Metadata disclosure | Information disclosure | Medium | Minimise exposed metadata | Partial |
| D1 | Packet flood | Denial of service | High if exposed | Input validation and resource limits | Partial / rate limits required |
| D2 | Cryptographic exhaustion | Denial of service | Medium | Input bounds and admission control | Partial |
| D3 | Rotation disruption | Denial of service | Medium | Coordinated, authenticated rekeying | Not demonstrated end to end |
| D4 | Replay-state exhaustion | Denial of service | Medium | Sequence checking and bounded state | Partial / memory bounds required |
| E1 | Producer gains validator privileges | Elevation of privilege | Medium | RBAC and least privilege | Partial / integration |
| E2 | Relay forges producer telemetry | Elevation of privilege | Medium | Producer signature verification | End-to-end test required |
| E3 | Cross-team data access | Elevation of privilege | Medium | Session isolation and authorisation | Partial |
| E4 | Configuration/dependency compromise | Elevation of privilege | Medium | Supply-chain and configuration controls | Production controls required |

---

## 11. Residual Risks and Security Limitations

### RR1 — Incomplete network-level assurance

The local simulation exercises components in-process and does not establish realistic network latency, packet loss, jitter, connection abuse, or transport-level authentication.

**Priority:** High before any networked deployment.

**Required action:** Validate the complete producer-to-relay-to-validator path under realistic network and adversarial conditions.

### RR2 — Key provisioning and peer authentication

Key agreement is not sufficient if the identity of the peer is not authenticated. The full handshake and key-provisioning lifecycle must be documented and tested.

**Priority:** High before claiming protection against man-in-the-middle attacks.

**Required action:** Define the handshake messages, identity binding, public-key trust model, rotation process, revocation process, and failure handling.

### RR3 — Key rotation and forward secrecy

A documented rotation interval is not evidence that rotation runs in the active pipeline. Forward secrecy depends on the actual handshake, ephemeral key handling, and deletion of old secrets.

**Priority:** High for production confidentiality.

**Required action:** Verify rotation triggers and session transitions in code and test whether compromise of current keys exposes previously captured traffic.

### RR4 — Commitment terminology and privacy

The active Python SHA-256-based commitment/check must not be described as a zero-knowledge proof. Hashing alone does not establish a hiding commitment or prove a statement without revealing its witness.

**Priority:** High for accurate security claims.

**Required action:** Document the exact commitment construction and determine whether a separate proof protocol is required. Verify that any Rust implementation is integrated before claiming its guarantees for the active pipeline.

### RR5 — Audit integrity

Memory-backed logging and ordinary JSONL output do not independently provide immutable or tamper-evident records.

**Priority:** High if audit records are used as regulatory or incident evidence.

**Required action:** Implement independently protected storage, integrity validation, retention controls, and tests for modification or deletion.

### RR6 — Relay plaintext access

The relay decrypts telemetry to perform integrity and anomaly processing. A compromised relay can potentially inspect plaintext even if it cannot create a valid producer signature for altered content.

**Priority:** High for confidentiality architecture.

**Required action:** Document the relay trust assumption, minimise plaintext exposure and retention, and evaluate whether the intended privacy requirements permit a plaintext-processing relay.

### RR7 — Checksum validation across packet paths

The binary packet parser includes checksum-validation functionality, but the reviewed relay processing function uses JSON-envelope parsing and validation before decryption. That path does not itself demonstrate that the header checksum is recomputed against the decrypted payload.

**Priority:** High for implementation consistency.

**Required action:** Trace checksum generation and verification through the exact JSON-envelope path and add a test that modifies the checksum independently of the payload.

### RR8 — Timestamp freshness and replay configuration

Timestamp freshness checks are configuration-dependent. The relay's constructor and fallback configuration use different defaults, while the validator's timestamp-check default is disabled in the reviewed configuration path. Sequence checking is also affected by configured limits and state management.

**Priority:** High for stale-packet and replay defence.

**Required action:** Document effective settings for each supported run mode and test duplicate, stale, out-of-order, and excessive-gap packets.

### RR9 — Cryptographic implementation and operational security

Correct algorithm selection does not establish secure key storage, safe deployment, dependency integrity, or resistance to side-channel attacks.

**Priority:** High before production.

**Required action:** Review implementation details, dependencies, secret handling, deployment configuration, and cryptographic library usage. Avoid unsupported claims about nanosecond rejection or universal constant-time behaviour.

### RR10 — Quantum resistance

The X25519 and Ed25519 algorithms used in the design are not post-quantum cryptographic schemes. A sufficiently capable cryptographically relevant quantum computer could threaten their security.

**Priority:** Long-term strategic risk; not a basis for a precise quantum-computing timeline.

**Required action:** Track applicable NIST post-quantum standards and evaluate a migration strategy when project requirements justify it. Do not assume a specific future timeline.

### RR11 — Telemetry truthfulness

Cryptographic integrity establishes whether data has been altered relative to the authenticated content; it does not establish that the original sensor reading was correct.

**Priority:** High for any use involving performance decisions or regulatory review.

**Required action:** Consider sensor plausibility checks, source calibration, independent measurements, and domain-specific validation alongside cryptographic controls.

---

## 12. Verification Plan

Before describing a threat as mitigated, retain reproducible evidence from the relevant execution path.

| Test | Expected security property | Evidence to retain |
|---|---|---|
| Modify ciphertext | AEAD authentication failure prevents successful processing | Test output and rejection reason |
| Modify authentication tag | Packet is rejected | Test output |
| Modify authenticated header | Inconsistent authenticated data is rejected | Test output for each altered field |
| Modify signed payload | Original producer signature fails verification | Validator test output |
| Submit invalid signature | Packet is rejected without incorrectly advancing trusted sequence state | Regression test output |
| Replay an accepted packet | Duplicate is rejected according to the configured replay policy | Test output and state assertions |
| Submit out-of-order sequence | Behaviour matches documented sequence policy | Test output for boundary cases |
| Submit stale timestamp | Behaviour matches the effective timestamp configuration | Configuration and test output |
| Modify checksum | The relevant packet path detects mismatch if checksum validation is part of its contract | Test output for binary and JSON-envelope paths |
| Modify commitment | Commitment comparison fails when expected | Test output and verifier details |
| Send malformed envelope | Input is rejected without an unhandled failure | Test output and error handling |
| Flood the processing path | Resource use remains bounded under the defined test load | CPU, memory, latency, and rejection metrics |
| Attempt cross-team access | Unauthorised reads or operations are denied | RBAC test output |
| Alter audit output | Tampering is detected or prevented by the deployed audit design | Integrity-validation test output |
| Impersonate a peer | Untrusted endpoint cannot complete an authenticated session | Handshake integration test |
| Exercise key rotation | Session transition behaves as documented | Rotation logs and regression tests |

A passing unit test demonstrates only the tested behaviour under its test conditions. It does not, by itself, establish production deployment effectiveness or comprehensive threat mitigation.

---

## 13. Implementation References

The following files are candidate implementation references. Each should be reviewed against the active call path before a security claim is attributed to it.

| Security area | Candidate reference |
|---|---|
| Producer signing | `car_producer/src/signer.py` |
| Producer encryption and session cryptography | `car_producer/src/crypto_engine.py` |
| Relay processing pipeline | `relay-node/src/main.py` |
| Relay decryption | `relay-node/src/decryptor.py` |
| Relay re-encryption | `relay-node/src/reencryptor.py` |
| Relay parsing | `relay-node/src/packet_parser.py` |
| Relay integrity checks | `relay-node/src/integrity_checker.py` |
| Validator signature verification | `validator-node/src/signature_verifier.py` |
| Validator sequence checks | `validator-node/src/sequence_checker.py` |
| Validator commitment verification | `validator-node/src/zkp_verifier.py` |
| Audit logging | `validator-node/src/audit_logger.py` |
| IAM/RBAC policy | `iam-module/src/rbac_engine.py` |
| Key scheduling | `car_producer/src/key_scheduler.py` |
| Tampering simulations | `simulations/tampering_sim.py` |
| Replay simulations | `simulations/replay_attack_sim.py` |
| IAM breach simulations | `simulations/iam_breach_sim.py` |

**Reference note:** File existence does not prove that a component is invoked by the live or simulated processing path. In particular, key scheduling, the Rust commitment module, external audit services, and network handshake enforcement should be described as active controls only after their integration has been verified.

---

## 14. Review and Maintenance

Review this threat model whenever any of the following changes:

- Packet header or envelope format.
- Cryptographic algorithms, signing coverage, or associated-data construction.
- Handshake, session establishment, or key rotation.
- Replay, sequence, timestamp, or checksum validation.
- Relay processing or plaintext-handling behaviour.
- IAM/RBAC policies or identity-to-key mapping.
- Audit storage, retention, or integrity controls.
- Network deployment, external services, or trust boundaries.
- Dependencies or security-sensitive configuration.

For each review, record the date, commit or version reviewed, tests executed, unresolved risks, and any claims that have changed from proposed to implemented.

---

## 15. Related Documents

- `docs/ARCHITECTURE_OVERVIEW.md` — Logical components and data flow.
- `docs/PROTOCOL_SPEC.md` — Packet processing and protocol behaviour.
- `docs/PACKET_FORMAT.md` — Header, payload, and envelope format.
- `docs/NETWORK_TOPOLOGY.md` — Network and deployment assumptions.
- `docs/AUDIT_TRAIL.md` — Audit events, fields, and storage limitations.
- `docs/COMPLIANCE.md` — Preliminary security-framework alignment.
- `docs/FIA_REGULATION_MAPPING.md` — Preliminary regulatory mapping.
- `docs/FIA_DATA_PRIVACY_MODEL.md` — Telemetry privacy considerations.
- `docs/FORENSIC_ANALYSIS.md` — Forensic investigation approach.
- `docs/THREAT_INTELLIGENCE.md` — Threat intelligence context.
- `docs/MITRE_ATTACK_MAPPING.md` — ATT&CK technique mapping.
- `docs/INCIDENT_RESPONSE.md` — Incident response procedures, if present.
- `architecture/adr/001-crypto-choice.md` — Cryptographic design rationale, if present.

---

**Document status:** This threat model is an implementation-aligned assessment of a prototype. Controls marked partial, proposed, or not demonstrated must not be represented as fully mitigated until the corresponding implementation and verification evidence is available.
