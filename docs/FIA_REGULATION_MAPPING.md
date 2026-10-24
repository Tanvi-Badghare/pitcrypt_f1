# FIA Regulation Mapping — PitCrypt-F1

**Document:** `FIA_REGULATION_MAPPING.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Preliminary regulatory-alignment analysis — not an official compliance assessment

---

## 1. Overview

This document describes how PitCrypt-F1's proposed and implemented security controls relate to telemetry integrity, confidentiality, access control, replay prevention, and auditability concerns in a Formula 1-style environment.

PitCrypt-F1 is a research and portfolio prototype that uses recorded telemetry, cryptographic packet protection, a relay/validator pipeline, IAM components, and security simulations to explore these concerns.

**This document does not establish compliance with FIA regulations, the FIA International Sporting Code, the Formula One Technical or Sporting Regulations, the Concorde Agreement, or any FIA cybersecurity requirement.** The exact applicability and wording of the regulatory provisions referenced below must be checked against the relevant official documents and their applicable editions before this mapping is used as a formal compliance claim.

The `REG-001` through `REG-008` identifiers are project-defined control categories, not official FIA regulation identifiers.

### Status terminology

- **Prototype control present:** The project contains a component or mechanism intended to address the stated concern.
- **Test evidence reported:** A test or simulation result has been reported, but the underlying execution evidence should be checked before making a quantified claim.
- **Requires verification:** The code, configuration, integration, or external regulatory reference needs further review.
- **Planned:** A proposed enhancement that must not be described as implemented.
- **Regulatory status:** No formal compliance determination has been made.

---

## 2. Regulatory Reference Scope

The original draft identifies the following regulatory topics. Their exact article numbers, wording, applicability, and interpretation have **not been independently verified for this document**.

| Reference in the original draft | Topic to investigate | Verification required |
|---|---|---|
| Formula One Technical Regulations, Article 8 | Electronic systems, sensors, and data logging | Check the applicable edition and exact provision |
| Technical Regulations, Article 8.2 | Data logging and data availability | Verify the cited requirement and scope |
| Technical Regulations, Article 8.3 | Homologation-related data | Verify the provision and its relevance to the telemetry channels discussed |
| Technical Regulations, Article 9 | Transmission systems | Verify whether the article addresses the specific wireless transmission claims in the original draft |
| Formula One Sporting Regulations, Article 34 | Car monitoring and FIA access to data | Check the applicable edition and exact wording |
| Sporting Regulations, Article 34.4 | Data integrity | Verify that this provision exists in the applicable edition and supports the stated interpretation |
| Sporting Regulations, Article 44 | Data retention | Verify the provision, retention obligation, and applicable timeframe |
| Concorde Agreement, Article 8 | Confidentiality obligations | Verify the relevant agreement, edition, clause, and applicability |
| FIA cybersecurity guidance, stated as 2023 | Access control and encryption | Identify the exact publication and supporting passage |

The project should not infer a specific encryption requirement, mandatory retention period, zero-knowledge proof requirement, or cybersecurity control solely from a general reference to FIA regulation or guidance.

Until the references are checked, the mappings below should be read as **engineering-control mappings against the concerns described in the original draft**, not as statements of legal or regulatory obligation.

---

## 3. Regulation-to-Control Mapping

### REG-001: Authentic Telemetry Transmission

**Control objective:** Authenticate the origin of a packet and detect unauthorised changes to the signed packet data.

**Regulatory reference in the original draft:** Sporting Regulations, Article 34.4 — exact reference and interpretation require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Ed25519 signing | `car_producer/src/signer.py` | The design uses a producer signature. Confirm the exact bytes signed and signing coverage in the implementation. |
| Signature verification | `validator-node/src/signature_verifier.py` | Validator-side signature verification has been exercised by reported regression tests. |
| Signature evidence | Packet signature and verification result | A valid signature supports verification of signed bytes under the relevant public key; identity binding and key provisioning remain important assumptions. |
| Tamper detection | ChaCha20-Poly1305 and Ed25519 | AEAD authentication failures can detect changes to protected ciphertext or associated data. The signature independently protects the bytes it covers. |

**Alignment assessment:** The project contains mechanisms intended to authenticate packet origin and detect changes to signed data. Their effectiveness depends on correct key management, byte-level consistency, and the precise validation path.

**Reported test evidence:** The project documentation reports that seven of seven tampering scenarios were detected in `simulations/tampering_sim.py`. This result should be treated as a reported simulation outcome until the attack definitions, output, and execution command have been reviewed.

**Important qualification:** Ed25519 signatures can provide evidence that a message was signed by the holder of the corresponding private key. They do not, by themselves, prove a legal identity or guarantee non-repudiation in every operational or legal context.

---

### REG-002: Confidentiality Between Teams

**Control objective:** Prevent unauthorised parties, including other teams, from reading telemetry protected by the project's communication links.

**Regulatory reference in the original draft:** Concorde Agreement, Article 8. The specific confidentiality obligation and its applicability require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Session-key separation | `car_producer/src/crypto_engine.py` | The architecture describes separate link-session contexts. Confirm how keys are derived and associated with teams and peers. |
| Cross-team access policies | `iam-module/policies/` | Policy files exist as part of the described design; enforcement and the relevant policy rules require verification. |
| Encryption in transit | ChaCha20-Poly1305 | The architecture specifies authenticated encryption on both pipeline legs. Confirm the actual encryption paths and key/nonce lifecycle. |
| Relay plaintext exposure | Relay decryption and re-encryption components | The relay processes plaintext after decryption. The architecture does not establish that plaintext is never retained or exposed to other components. |

**Alignment assessment:** Link encryption and access-control policies can support a confidentiality objective when correctly configured and enforced. The existence of these mechanisms does not establish compliance with a particular confidentiality obligation.

**Requires verification:**

- Whether each team's traffic is cryptographically and logically isolated.
- Whether a key associated with one team can be used to decrypt another team's traffic.
- Whether IAM decisions are enforced in the actual packet-processing path.
- How plaintext is handled in memory, logs, exceptions, and debugging output.

**Reported test evidence:** The project documentation reports seven of seven IAM-breach simulation scenarios defended in `simulations/iam_breach_sim.py`. The precise tested attacks and enforcement paths should be reviewed before making a broader claim about cross-team isolation.

---

### REG-003: Data Availability and Authorised Review

**Control objective:** Make relevant packet-decision evidence available for authorised review.

**Regulatory reference in the original draft:** Sporting Regulations, Article 34. The exact data-access obligation and applicability require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Validator endpoint | `validator-node/src/main.py` | Represents the final processing stage in the prototype; does not establish connectivity to an FIA system. |
| Packet-decision records | `validator-node/src/audit_logger.py` | The logger records structured decisions, subject to the actual execution path. |
| Audit export | `AuditLogger.export_jsonl()` if present in the current implementation | The existence and behaviour of this method must be confirmed against the code. |
| Record availability | In-memory and optional JSONL logging | Availability depends on persistence, process lifecycle, file permissions, and operational configuration. |

**Alignment assessment:** Structured records and export functionality can support review of the prototype's decisions. They do not establish that the FIA can access the system on demand, that records are complete, or that an applicable regulatory deadline is met.

**Requires verification:**

- Whether every relevant accept/reject path produces a record.
- Whether records survive restarts and failures.
- Whether export is implemented, tested, and access-controlled.
- Whether records can be searched and interpreted by an authorised reviewer.
- Whether the system records sufficient evidence for the particular investigation being considered.

The prototype's validator is a logical endpoint, not an actual FIA endpoint.

---

### REG-004: Integrity Across the Pipeline

**Control objective:** Preserve the integrity of the packet data that the producer signs and detect unauthorised modification during processing and transmission.

**Regulatory reference in the original draft:** Technical Regulations, Article 8.2. The cited article and the claim that it imposes the specific integrity requirement described here require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Producer signature | `car_producer/src/signer.py` | The design signs the header and payload bytes. Confirm the actual signing input. |
| Independent verification | `validator-node/src/signature_verifier.py` | Reported tests exercise validator-side signature rejection. |
| Link-level authenticated encryption | Car-to-relay and relay-to-validator encryption components | Provides protection for each configured encrypted link when correctly implemented. |
| Commitment consistency check | `validator-node/src/zkp_verifier.py` | The documented Python implementation recomputes a SHA-256-based commitment; this is not a zero-knowledge proof. |
| Relay access policy | IAM policy configuration | The claim that the relay is explicitly denied permission to modify telemetry requires verification against the current policy and enforcement code. |

**Alignment assessment:** A producer signature verified independently by the validator can detect changes to the signed bytes, provided the validator uses the correct trusted public key and verifies the same bytes that were originally signed. AEAD adds protection to each encrypted link.

**Important qualification:** The phrase “cryptographic proof that data arrives unmodified” is too broad. These mechanisms provide specific integrity and authenticity checks; they do not guarantee correct sensor readings, prevent all denial-of-service attacks, or establish that every processing path preserves the original data.

**Commitment limitation:** The Python SHA-256 commitment check must not be labelled a ZKP. Its security properties depend on the commitment construction and how its inputs are handled. The existence of this check does not establish a regulatory requirement for zero-knowledge proofs.

---

### REG-005: Replay and Sequence Protection

**Control objective:** Detect repeated or incorrectly ordered packets under the project's sequence/replay policy.

**Regulatory reference in the original draft:** An inferred relationship to the data-integrity concern described under Article 34.4. The exact provision and interpretation require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Relay sequence checking | `relay-node/src/integrity_checker.py` | The architecture describes relay-side sequence/replay checks; verify the current rules and state handling. |
| Validator sequence checking | `validator-node/src/sequence_checker.py` | Independent validator-side checks are part of the described design and have reported regression coverage. |
| Sequence generation | Packet-building component | Confirm sequence generation, reset conditions, and binding between header metadata and transport fields. |
| Timestamp freshness | Relay or validator timestamp checks, if enabled | Timestamp checking has previously been reported as disabled; do not claim stale-packet rejection is active until verified. |

**Alignment assessment:** Independent sequence checks can provide defence in depth against replay within the limits of their state and acceptance policies. They do not, by themselves, establish that every packet corresponds to the car's current physical state.

**Reported test evidence:** Earlier project documentation reports four of five replay attack scenarios detected. One scenario was described as a dictionary-level sequence override that did not modify the corresponding header. That limitation should be reported accurately alongside the test result.

**Requires verification:**

- Whether replay state is scoped by producer, session, or another identifier.
- How sequence gaps and out-of-order packets are handled.
- Whether state survives restarts.
- Whether sequence numbers are validated against authenticated packet contents.
- Whether timestamp freshness is enabled and enforced.
- Whether a replay can be forwarded by the relay but rejected by the validator.

Do not describe the system as providing complete replay prevention until the relevant attack cases and limitations have been reviewed.

---

### REG-006: Audit Records for Investigation

**Control objective:** Record packet-processing decisions in a form that can support subsequent debugging, review, and investigation.

**Regulatory reference in the original draft:** Sporting Regulations, Article 44, and post-event investigation requirements. The exact retention obligation and applicable timeframe require verification.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Structured audit events | `validator-node/src/audit_logger.py` | The described logger records structured event fields. |
| Per-packet decision details | `AuditEvent.to_dict()` if present in the current implementation | Confirm the actual schema and which paths emit events. |
| Timestamp field | Audit event timestamp | A timestamp field does not establish clock accuracy or synchronisation. |
| Signature evidence | Packet-verification result and related event details, if recorded | The current audit schema must be checked before claiming the full signature is stored. |
| JSONL persistence/export | Audit logger | The described implementation supports in-memory events and optional JSONL output; durability and export behaviour require verification. |

**Alignment assessment:** Structured audit records can support investigation when they are sufficiently complete, correctly timestamped, retained, protected from unauthorised modification, and retrievable by authorised personnel.

**Integrity limitation:** JSONL is a file format, not an immutability guarantee. An in-memory event list or ordinary append-only file can be altered or lost. The current implementation should be described as structured audit-event recording unless stronger integrity and retention controls are implemented and tested.

#### Illustrative audit event

The following is an **illustrative schema example**, not a claim that this exact event was generated during a real F1 event.

```json
{
  "timestamp": "2025-06-15T14:23:07.123456+00:00",
  "decision": "ACCEPT",
  "sequence_no": 8432,
  "node_id": "mercedes_car",
  "team": "mercedes",
  "session": "R",
  "reason": "all_checks_passed",
  "details": {
    "sig": "valid",
    "sequence": "valid",
    "commitment": "valid"
  }
}
```

The example uses `commitment` rather than `zkp` to avoid incorrectly labelling the Python hash-based check as a zero-knowledge proof. The field names and values must be aligned with the actual `AuditEvent` schema before this example is presented as a literal output sample.

---

### REG-007: Access Control for the Telemetry System

**Control objective:** Restrict system actions according to configured identities and roles, and record access-control decisions.

**Regulatory reference in the original draft:** FIA cybersecurity guidance described as published in 2023. The specific publication and its requirements must be identified before this reference can support a regulatory claim.

| Control | Project component | Evidence and limitations |
|---|---|---|
| Role-based policy evaluation | `iam-module/src/rbac_engine.py` | IAM engine is part of the documented architecture; enforcement at each relevant operation requires verification. |
| Role separation | Car-producer, relay, and validator roles | Logical role separation is described in the design. |
| Access-decision logging | `iam-module/src/access_auditor.py` | Confirm which decisions are recorded and whether all relevant execution paths invoke the auditor. |
| Unknown-node denial | Identity and policy components | Verify actual default-deny behaviour for unknown identities, missing roles, and malformed configuration. |
| Repeated-denial detection | Access auditor | Three consecutive denials have been documented as an intended alert threshold; active enforcement and alert behaviour require verification. |

**Alignment assessment:** The IAM module provides components for evaluating access requests. The existence of a policy engine is not sufficient to establish that every operation is protected by it.

**Reported test evidence:** The project documentation reports seven of seven IAM-breach simulation scenarios defended. This result should be retained as a measured claim only after confirming the specific attacks, expected outcomes, and code paths exercised.

---

### REG-008: Encryption in Transit

**Control objective:** Protect telemetry confidentiality and integrity while packets travel over configured communication links.

**Regulatory reference in the original draft:** A general reference to FIA cybersecurity guidance. The exact requirement and its applicability to this prototype remain unverified.

| Control | Project component | Technical reference |
|---|---|---|
| Car-to-relay authenticated encryption | ChaCha20-Poly1305 | RFC 8439 |
| Relay-to-validator authenticated encryption | ChaCha20-Poly1305 | RFC 8439 |
| Key agreement | X25519 | RFC 7748 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Session-key length | 32-byte key, where configured | Verify key length and derivation in code |

**Alignment assessment:** These cryptographic mechanisms are suitable building blocks for protected communication when used with correct key management, nonce handling, peer association, and protocol design.

**Security qualification:** A 32-byte key does not, on its own, establish the security of the complete protocol. The effective security also depends on the cryptographic algorithm, key derivation, implementation, authentication model, and operational environment.

The claim that session keys are never transmitted should be checked against the actual handshake and key-management code. X25519 derives shared secret material through key agreement; the complete protocol still needs appropriate peer authentication and session handling.

No regulatory compliance determination follows solely from selecting these algorithms.

---

## 4. Preliminary Control Summary

The matrix below summarises the current **engineering-alignment assessment**, not formal regulatory compliance.

| Control ID | Control objective | Current assessment | Principal evidence or gap |
|---|---|---|---|
| REG-001 | Packet authenticity and tamper detection | Prototype controls present; scope requires verification | Ed25519 verification and reported tampering simulation |
| REG-002 | Confidentiality between teams | Design controls present; isolation requires verification | Link encryption, session association, IAM policy enforcement |
| REG-003 | Data availability for authorised review | Partial capability; operational access unverified | Validator model and audit-record/export behaviour |
| REG-004 | Integrity across the pipeline | Prototype controls present; end-to-end guarantees require verification | Signature verification, AEAD, commitment-check limitations |
| REG-005 | Replay and sequence protection | Partial capability; known test limitation | Independent sequence checks; timestamp enforcement unverified |
| REG-006 | Audit records for investigation | Structured logging described; immutability and retention unestablished | In-memory/JSONL logging and event completeness |
| REG-007 | Access control | IAM components present; full enforcement requires verification | RBAC engine, policies, access auditing, simulation evidence |
| REG-008 | Encryption in transit | Cryptographic design specified; integration requires verification | ChaCha20-Poly1305, X25519, HKDF-SHA256 |

**Overall status: Preliminary alignment only.** No item in this table should be interpreted as an official FIA compliance finding.

---

## 5. Gaps and Planned Improvements

### GAP-001: Commitment Scheme and Privacy Claims

**Current state:** The described Python verifier recomputes a SHA-256-based commitment from a payload and nonce and compares it with the transmitted commitment. This is not a zero-knowledge proof. If the nonce and commitment are available to an observer, the construction should not be assumed to hide low-entropy telemetry values from guessing attacks.

**Required next step:** Document the exact commitment construction, threat model, input encoding, nonce handling, and intended security properties. Determine whether the project actually needs a commitment scheme, a zero-knowledge proof, or a different mechanism for its stated privacy objective.

**Potential enhancement:** Integrate and test the planned Rust Pedersen/Bulletproofs implementation if zero-knowledge functionality is a genuine project requirement.

**Priority:** To be determined after the threat model and requirements are reviewed.

**Timeline:** Previously proposed for version 1.1; not a delivery commitment.

**Important:** A zero-knowledge proof is not automatically required for regulatory alignment with data integrity. The relevant requirement must first be established.

### GAP-002: Post-Quantum Cryptography

**Current state:** X25519 and Ed25519 are classical elliptic-curve cryptographic mechanisms and would not provide their usual security assumptions against a sufficiently capable cryptographically relevant quantum computer.

**Potential enhancement:** Evaluate a migration or hybrid approach using standardised post-quantum key-establishment and digital-signature mechanisms, including the relevant NIST standards and their current implementation maturity.

**Priority:** Requires a threat-model and lifecycle assessment.

**Timeline:** No fixed threat timeline or migration date is asserted in this document.

**Required next step:** Identify the assets' confidentiality lifetime, anticipated system lifecycle, interoperability requirements, and migration constraints before assigning priority.

### GAP-003: Live-Network and Operational Validation

**Current state:** The project has been developed and tested as a prototype. The available evidence does not establish validation under real Formula 1 trackside network conditions.

**Required next step:** Use a controlled test environment to investigate realistic latency, jitter, packet loss, reordering, connection failure, and recovery. Document the test environment and distinguish simulation results from measurements on an actual operational network.

**Important limitation:** Tests on localhost or synthetic network conditions cannot establish performance or reliability under a live trackside RF environment. No access to an actual F1 team's operational network is claimed.

### GAP-004: Audit Integrity and Retention

**Current state:** The described audit logger supports structured events in memory and optional JSONL persistence.

**Required next step:** Define the audit threat model, required retention period, access controls, durability requirements, and integrity-verification mechanism. Test behaviour under process crashes, storage errors, missing events, and unauthorised changes.

**Priority:** Dependent on the intended investigation and operational requirements.

### GAP-005: Key Lifecycle and Peer Authentication

**Current state:** The architecture describes X25519 key agreement, HKDF-derived session keys, and proposed time/packet-count rotation thresholds.

**Required next step:** Verify peer authentication, key-to-identity binding, nonce uniqueness, key rotation under active traffic, session expiry, failure recovery, and key disposal. Confirm whether the documented rotation thresholds are active in the code.

**Important limitation:** Forward secrecy must not be claimed solely because ephemeral key agreement or a key scheduler exists. The protocol and key lifecycle must be assessed as a whole.

### GAP-006: Regulatory Reference Verification

**Current state:** The original mapping cites specific FIA articles, a Concorde Agreement clause, and general cybersecurity guidance. Their exact wording and applicability have not been established in this document.

**Required next step:**

1. Identify the official regulatory documents and their applicable editions.
2. Confirm the article numbers and quoted or paraphrased requirements.
3. Record the precise source for each mapping.
4. Distinguish mandatory requirements from engineering recommendations and inferred objectives.
5. Review the completed mapping with an appropriately qualified regulatory or compliance specialist before using it as a formal compliance assessment.

**Priority:** High if the document is to be described as a regulatory mapping rather than a preliminary engineering study.

---

## 6. Evidence and Change Control

For each future claim of regulatory alignment, record:

- The exact regulatory document, edition, article, and relevant passage.
- The control objective derived from that passage.
- The project component intended to implement the control.
- The specific test or inspection supporting the claim.
- The result, limitations, and known failure cases.
- The implementation status and date of the evidence.

Test results should be reproducible from the repository. A passing pytest suite is evidence about the tests that ran; it is not a substitute for checking the applicability of a regulation or evaluating the complete system against it.

Changes to the implementation, policy configuration, or regulatory reference should trigger a review of the corresponding mapping.

---

## 7. See Also

- `docs/ARCHITECTURE_OVERVIEW.md` — System architecture and component responsibilities
- `docs/THREAT_MODEL.md` — Threat analysis and trust boundaries
- `docs/NETWORK_TOPOLOGY.md` — Pipeline and network design
- `docs/PACKET_FORMAT.md` — Packet header and payload specification
- `docs/PROTOCOL_SPEC.md` — Communication and cryptographic protocol
- `docs/FIA_DATA_PRIVACY_MODEL.md` — Privacy architecture, if present in the current repository
- `docs/COMPLIANCE.md` — ISO 27001 / NIST CSF mapping, if present in the current repository
- `docs/AUDIT_TRAIL.md` — Audit logging specification, if present in the current repository
- `simulations/tampering_sim.py` — Tampering simulation
- `simulations/replay_attack_sim.py` — Replay simulation
- `simulations/iam_breach_sim.py` — IAM-breach simulation

**Document conclusion:** PitCrypt-F1 explores technical controls relevant to telemetry authenticity, integrity, confidentiality, replay protection, access control, and auditability. Its components and reported simulations provide a basis for further engineering evaluation. Formal regulatory alignment remains unverified until the cited obligations, implementation paths, and supporting evidence are checked against the applicable requirements.