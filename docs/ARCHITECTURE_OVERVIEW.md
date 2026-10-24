# Architecture Overview — PitCrypt-F1

**Document:** `ARCHITECTURE_OVERVIEW.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Architecture reference — implementation and verification status identified below

---

## 1. System Purpose

PitCrypt-F1 is a prototype security framework for protecting Formula 1 telemetry as it moves through a simulated car-producer, relay, and validator pipeline. It combines cryptographic protection, packet-integrity checks, replay detection, access-control components, anomaly analysis, and structured audit events.

The project uses telemetry obtained through the FastF1 API to investigate how security controls can be integrated into a motorsport-style telemetry pipeline. It is a research and portfolio prototype; it is **not an FIA-approved, FIA-deployed, or production-certified system**.

The architecture is designed to address three primary questions:

1. **Who sent this packet?** — Ed25519 signature verification.
2. **Has the protected data been altered?** — ChaCha20-Poly1305 authenticated encryption and signature verification, with a separate hash-based commitment check where configured.
3. **Has this packet already been received or delivered out of order?** — Sequence and replay checks at multiple pipeline stages.

These mechanisms address different security properties. Authenticated encryption protects a particular encrypted link, while the Ed25519 signature allows the validator to verify the car producer's signed data independently of the relay. Sequence checks address replay and ordering. The hash-based commitment check provides an additional consistency check; it is not a zero-knowledge proof.

### Implementation status terminology

This document uses the following distinctions:

- **Implemented:** a component or mechanism is part of the described project implementation, based on the current project information.
- **Tested:** a test result has been reported for the current test suite. Passing tests do not establish every possible security property.
- **Requires verification:** the precise implementation, integration, configuration, or guarantee must be checked before it is described as an established capability.
- **Planned:** a proposed extension that should not be represented as a current, integrated feature.

---

## 2. Design Principles

### 2.1 Zero trust

The architecture avoids treating the relay as sufficient authority to establish that a packet originated from a legitimate car producer. The validator independently verifies the original car signature and applies its own sequence checks.

**Implementation status:** Independent validator-side signature and sequence validation are present in the described pipeline. The broader claim that every node boundary and every action is enforced by IAM policy requires a separate integration review.

### 2.2 Defence in depth

The pipeline places checks at more than one stage. The relay performs link decryption and integrity-related checks, while the validator independently performs cryptographic signature verification and replay/sequence validation.

A compromised relay should not be able to forge a valid Ed25519 signature for a car producer merely by re-encrypting a packet. This does not mean that relay compromise cannot affect availability, confidentiality of plaintext processed by the relay, or packet delivery.

### 2.3 Cryptographic separation of responsibilities

The design uses separate mechanisms for different purposes:

- **Ed25519:** signing and verification of car-producer packets.
- **X25519:** key agreement for pipeline-link sessions.
- **HKDF-SHA256:** derivation of session keys from shared secret material.
- **ChaCha20-Poly1305:** authenticated encryption of data on a pipeline link.
- **SHA-256 commitment check:** consistency verification using a payload and nonce.

These mechanisms are complementary and should not be described as interchangeable security controls.

### 2.4 Least privilege

The IAM module defines roles for car producers, relays, and validators, together with policy evaluation components.

**Implementation status:** The IAM components and policy model are documented in the project. Enforcement at every pipeline boundary, strict default-deny behaviour in every execution path, and the inability of a node to perform unauthorised network operations require verification against the actual call sites and configuration.

### 2.5 Auditability

The validator records structured packet-decision events, with fields such as timestamp, decision, sequence number, node identity, team, session, reason, and additional details.

**Implementation status:** The current `AuditLogger` is described as maintaining a thread-safe in-memory event list and optionally writing JSONL. This supports structured event recording, but it is not inherently immutable, tamper-proof, or guaranteed to survive process termination.

---

## 3. Three-Tier Pipeline Architecture

The system is organised around three logical stages.

```text
┌────────────────────┐
│    CAR PRODUCER    │
│                    │
│ Load telemetry     │
│ Build packet       │
│ Sign packet        │
│ Encrypt car link   │
└─────────┬──────────┘
          │ Encrypted packet
          ▼
┌────────────────────┐
│     RELAY NODE     │
│                    │
│ Parse packet       │
│ Decrypt car link   │
│ Check integrity    │
│ Apply anomaly rules│
│ Re-encrypt packet  │
└─────────┬──────────┘
          │ Encrypted packet
          ▼
┌────────────────────┐
│   FIA VALIDATOR    │
│                    │
│ Decrypt relay link │
│ Verify car sig.    │
│ Check sequence     │
│ Verify commitment  │
│ Record decision    │
└────────────────────┘
```

The validator is called the **FIA validator** in the project’s logical model. This name describes the prototype's intended role; it does not imply that the software is operated, endorsed, or certified by the FIA.

### Pipeline link protection

The design uses separate cryptographic sessions for the car-to-relay and relay-to-validator links. Each link has its own encryption context and session key.

**Requires verification:** The current code and configuration should be checked to confirm how each handshake is performed, how keys are associated with peer identities, how nonce uniqueness is enforced, and what happens when a session expires or key rotation fails.

---

## 4. Tier 1 — Car Producer

### Responsibility

Load telemetry, assemble packets, authenticate the producer's data, and protect the car-to-relay transmission.

### 4.1 `SensorSimulator` — `sensor_simulator.py`

The sensor simulator supplies telemetry frames to the packet-production pipeline. The project uses FastF1-derived telemetry and supports analysis across multiple circuits and session types.

Documented data sources include Mercedes and Red Bull telemetry obtained through FastF1.

**Requires verification:**

- The precise number of source rows and retained rows.
- Which seasons, circuits, drivers, teams, and session types are available locally.
- Whether every frame in a live demonstration comes directly from recorded telemetry or from synthetic data derived from it.
- The configured frame-emission rate and behaviour under missing or invalid fields.

The repository notes have contained different row-count figures. The definitive dataset count should be reconciled with the actual files and the data-loading pipeline before a single total is published here.

FastF1-derived historical telemetry should be described as recorded telemetry being replayed or processed by a simulator, rather than as a live feed from an F1 car.

### 4.2 `PacketBuilder` — `packet_builder.py`

The packet builder assembles a binary header and a serialised telemetry payload.

The documented header format is:

```python
!IBBBBQQI32sI
```

This format has a packed size of 64 bytes.

The header is intended to carry packet metadata, including identifiers, sequence/timing information, payload-length information, and integrity-related fields.

**Requires verification:** The exact mapping of every struct field to its semantic name, the checksum's purpose, and the validation performed on each field should match the implementation and the dedicated packet-format specification. Header size alone does not establish that all fields are validated correctly.

### 4.3 `PacketSigner` — `signer.py`

The packet signer uses Ed25519 to sign the packet data.

The documented design signs:

```text
header_bytes || payload_bytes
```

The resulting Ed25519 signature is 64 bytes.

The validator uses the car producer's public key to verify the signature after the relay has processed and forwarded the packet.

**Security boundary:** Verification is meaningful only if the verifier uses the correct trusted public key and the exact original bytes covered by the signature.

**Requires verification:** Public-key provisioning, identity-to-key binding, key replacement/revocation, and persistence across process restarts should be documented according to the actual implementation. Out-of-band registration is part of the intended trust model only if the project implements and operationally defines that procedure.

### 4.4 `PacketEncryptor` — `encryptor.py`

The packet encryptor uses ChaCha20-Poly1305 to protect data on the car-to-relay link.

The documented design uses an HKDF-derived session key and a 12-byte nonce. The packet header is supplied as associated authenticated data (AAD), meaning the header is authenticated by the AEAD operation but is not encrypted by that operation.

**Requires verification:**

- That the header passed as AAD is byte-for-byte the header expected by the receiver.
- That nonce reuse under a given key is prevented.
- That malformed packets and AEAD authentication failures are rejected.
- That the encryption and signing operations use consistent packet bytes and metadata.

### 4.5 `CryptoEngine` — `crypto_engine.py`

The crypto engine manages the X25519 key-agreement lifecycle and derives session keys through HKDF-SHA256.

The architecture uses separate engine/session contexts for the car-to-relay and relay-to-validator links.

**Requires verification:** The handshake, peer authentication, key lifetime, error handling, and session-state transitions must be reviewed before claiming that the full protocol provides forward secrecy.

### 4.6 `KeyScheduler` — `key_scheduler.py`

The architecture documents a scheduler intended to trigger key rotation when either a time threshold or a packet-count threshold is reached.

The proposed thresholds are 300 seconds or 10,000 packets.

**Status: requires verification.** These values are documented design parameters, not proof that rotation is successfully integrated into both pipeline legs. Claims that rotation is non-blocking or guarantees forward secrecy should be made only after checking the implementation and testing the effects of rotation on active traffic, failed handshakes, and old-key disposal.

### Car-producer data flow

```text
Telemetry source
      │
      ▼
SensorSimulator.get_next_frame()
      │
      ▼
PacketBuilder.build()
      │
      ├── Header bytes
      └── Payload bytes
                │
                ▼
PacketSigner.sign_packet()
                │
                ▼
Commitment generation (when enabled)
                │
                ▼
PacketEncryptor.encrypt_packet()
                │
                ▼
Encrypted packet
                │
                ▼
          Relay node
```

The exact serialisation and order of commitment generation, signing, and encryption must remain consistent with the actual packet contract.

---

## 5. Tier 2 — Relay Node

### Responsibility

Receive car-producer packets, decode their transport representation, decrypt the car link, apply configured integrity and anomaly checks, re-encrypt accepted packets for the validator link, and forward them.

The relay is treated as a semi-trusted processing stage in the architecture. It can process plaintext after successful decryption; therefore, the system must not claim that the relay never sees plaintext.

### 5.1 `PacketParser` — `packet_parser.py`

The parser deserialises the transport representation and converts encoded binary fields, such as nonces, headers, ciphertext, and signatures, back into bytes.

**Requires verification:** Required-field validation, type checks, identifier validation, maximum packet sizes, and malformed-input handling should be confirmed against the parser implementation.

### 5.2 `RelayDecryptor` — `decryptor.py`

The relay decryptor processes the car-to-relay encrypted link using the corresponding session context.

An AEAD authentication failure should cause the packet to be rejected rather than passed to downstream processing.

The decryptor's session registry and error handling should be checked for correct peer/session association and safe handling of unknown or expired sessions.

### 5.3 `IntegrityChecker` — `integrity_checker.py`

The relay's integrity checker provides an early validation stage. The documented design includes sequence-state tracking and replay-related checks.

The architecture also describes out-of-order delivery and timestamp-staleness checks.

**Requires verification:** The current timestamp-checking path has previously been reported as disabled. Timestamp staleness must therefore not be presented as an enforced protection until the implementation and configuration are confirmed.

The precise replay-window policy, handling of gaps, treatment of out-of-order packets, and sequence-state reset behaviour should match the current code.

### 5.4 `AnomalyFilter` — `anomaly_filters.py`

The anomaly filter evaluates telemetry against configured physical bounds and statistical thresholds.

Documented examples include:

- Rejecting physically invalid values under configured rules.
- Flagging statistical deviations for further inspection.
- Using calibrated telemetry baselines to inform threshold selection.

The architecture has used speed above 400 km/h and negative RPM as examples of physical-bound checks. These should be treated as configured prototype rules, not universal FIA limits.

**Requires verification:** The exact rules, units, boundary inclusivity, missing-value handling, and distinction between rejection and flagging should be confirmed in code. Threshold calibration should be reproducible from the documented baseline dataset.

### 5.5 `RelayReencryptor` — `reencryptor.py`

The relay re-encrypts the forwarded packet for the relay-to-validator link using a separate session context.

The design preserves the original car producer's Ed25519 signature so that the validator can verify the producer's signed data independently of the relay.

The relay's ability to forward a packet does not itself establish the packet's authenticity. That decision belongs to the validator's verification stage.

### Relay data flow

```text
Encrypted packet from car producer
                 │
                 ▼
       PacketParser.parse_json_packet()
                 │
                 ▼
          RelayDecryptor.decrypt()
                 │
                 ▼
          IntegrityChecker.check()
                 │
                 ▼
       AnomalyFilter.check_and_annotate()
                 │
                 ▼
        RelayReencryptor.reencrypt()
                 │
                 ▼
       Encrypted packet to validator
```

A packet may be dropped, flagged, or forwarded depending on the configured checks. The precise decision path and annotation format should be described in the relay implementation and protocol specification.

---

## 6. Tier 3 — Validator Node

### Responsibility

Perform final packet verification, maintain validator-side sequence state, evaluate the configured commitment check, and record packet decisions.

The validator is the final decision-making stage in the prototype. It should not accept a packet merely because the relay forwarded it.

### 6.1 `ValidatorSignatureVerifier` — `signature_verifier.py`

The signature verifier checks the Ed25519 signature using the public key associated with the car producer.

The documented signature input is:

```text
header_bytes || payload_bytes
```

The validator should reject invalid signatures and unknown or untrusted identities according to its configured trust policy.

**Test evidence:** The reported regression coverage includes adversarial signature-pipeline tests and a case in which an invalid signature is rejected without advancing sequence state, allowing a subsequent legitimate packet to be processed. The full test suite has also been reported to pass.

These tests provide evidence for the exercised cases; they do not prove the absence of all signature-verification or identity-management vulnerabilities.

### 6.2 `ValidatorSequenceChecker` — `sequence_checker.py`

The validator performs its own sequence/replay validation independently of the relay's earlier checks.

The architecture has documented a rolling replay window of 50,000 entries.

**Requires verification:** Confirm the current configured window, whether state is maintained per producer/session, the handling of sequence gaps and out-of-order delivery, and whether state persists across restarts. The configured value should not be treated as an implemented guarantee until it has been checked against the code and tests.

### 6.3 `ZKPVerifier` — `zkp_verifier.py`

The currently described Python verification mechanism recomputes a SHA-256 hash from the payload and a supplied nonce, then compares the result with the transmitted commitment.

This is a **hash-based commitment consistency check, not a zero-knowledge proof**. It does not, by itself, establish a zero-knowledge property or prove that a hidden statement is true without revealing it.

The current design notes also describe packets without a commitment being skipped.

**Security implication:** If a missing commitment causes verification to be skipped, the system must not claim that every accepted packet passes the commitment check. The behaviour for missing, malformed, or invalid commitments should be explicit and tested.

A Rust-based Pedersen commitment and Bulletproofs implementation is a planned or separate development item unless and until its integration into the live Python pipeline is demonstrated.

### 6.4 `AuditLogger` — `audit_logger.py`

The audit logger records packet decisions and associated metadata. The described fields include:

- Timestamp
- Decision
- Sequence number
- Node identity
- Team and session
- Rejection or decision reason
- Additional decision details

The current implementation has been described as maintaining an in-memory list and optionally writing JSONL events.

**Limitations:** Ordinary JSONL files and in-memory lists are not inherently immutable, tamper-evident, access-controlled, or durable. A process failure may also affect in-memory events that have not been persisted.

The appropriate claim is that the prototype provides structured audit-event recording. Stronger guarantees would require additional controls, such as protected storage, integrity verification, access restrictions, and tested retention/recovery behaviour.

### Validator data flow

```text
Encrypted packet from relay
              │
              ▼
      Decrypt relay link
              │
              ▼
ValidatorSignatureVerifier.verify()
              │
              ▼
ValidatorSequenceChecker.check()
              │
              ▼
       ZKPVerifier.verify_packet()
              │
              ▼
      AuditLogger records decision
              │
              ▼
       ACCEPT / REJECT / FLAG
```

This is a conceptual flow. The exact order of checks, early-return paths, counters, and audit calls must follow the implementation in `validator-node/src/`. In particular, a rejected packet should be audited consistently where applicable, and failed verification should not accidentally advance trusted sequence state.

---

## 7. IAM Module

### Responsibility

Provide identity and role-based policy components for evaluating whether a node may perform an action on a resource.

### 7.1 `IdentityStore` — `identity_store.py`

The identity store represents registered nodes and their associated identities, roles, policies, or public-key information, according to the current configuration.

### 7.2 `PolicyLoader` — `policy_loader.py`

The policy loader reads policy configuration from the IAM module's policy directory.

The documented policy model includes allow/deny evaluation and a default-deny principle.

**Requires verification:** Confirm the exact precedence rules, handling of malformed policies, and behaviour when a node, role, action, or resource is not defined.

### 7.3 `RBACEngine` — `rbac_engine.py`

The RBAC engine evaluates whether a particular node may perform an action on a resource.

Strict mode is documented as raising `PermissionError` when an action is denied.

**Requires verification:** Confirm that relevant pipeline operations actually call the engine and enforce its decision. A policy engine existing in the repository is not equivalent to access control being enforced at every boundary.

### 7.4 `AccessAuditor` — `access_auditor.py`

The access auditor records IAM decisions to JSONL and is documented as detecting consecutive denial patterns.

The stated threshold is an alert after three consecutive denials from the same node.

**Requires verification:** Confirm the current alert implementation, reset conditions, persistence behaviour, and whether alerts are generated in the live execution path.

### Three-role model

| Role | Intended responsibilities |
|---|---|
| `car_producer` | Produce, sign, encrypt, and transmit telemetry to the relay |
| `relay` | Receive, decrypt, process, re-encrypt, and forward telemetry |
| `fia_validator` | Receive, decrypt, verify, and record packet decisions |

These are logical responsibilities, not proof that network-level permissions are technically restricted to those operations.

---

## 8. Forensic Analysis Module

### Responsibility

Analyse recorded telemetry, compute statistical baselines, and support the calibration of anomaly-detection thresholds.

### Components

- **`fetch_telemetry.py`** — Retrieves telemetry through FastF1 for the configured teams, events, and sessions.
- **`forensic_analysis.py`** — Computes statistical summaries and baselines for the available telemetry. The documented workflow includes per-team and per-session analysis and Z-score-based anomaly detection.
- **`calibrate_thresholds.py`** — Uses baseline statistics to help derive configured bounds for channels such as Speed, RPM, Throttle, Brake, `nGear`, and DRS.
- **`visualise_telemetry.py`** — Produces visualisations for inspecting telemetry distributions and relationships, including speed, throttle, channel statistics, anomaly counts, and DRS usage.

Expected baseline outputs have included `mercedes_baseline.csv` and `redbull_baseline.csv`.

**Requires verification:** The actual dataset scope, row counts, filtering rules, missing-value treatment, baseline generation process, and threshold outputs should be reproducible. Statistical deviation from a historical baseline is not automatically a safety-critical anomaly; the usefulness of a threshold depends on the channel, session context, and intended detection task.

---

## 9. Simulation and Adversarial Testing

The repository documents a simulation suite for exploring packet-security and pipeline-reliability scenarios.

```text
simulations/
├── replay_attack_sim.py
├── tampering_sim.py
├── iam_breach_sim.py
├── packet_loss_sim.py
├── jitter_sim.py
└── results/
```

The documented purposes are:

| Simulation | Intended investigation |
|---|---|
| Replay attack | Whether previously observed packets are detected or rejected |
| Tampering | Whether altered packets fail integrity or authentication checks |
| IAM breach | Whether unauthorised actions are denied |
| Packet loss | How the pipeline behaves when packets are dropped |
| Jitter | How variable packet timing affects latency and throughput |

Earlier project documentation reported the following simulation outcomes:

- Tampering: 7 of 7 attack cases detected.
- Replay: 4 of 5 attack cases detected, with one reported limitation.
- IAM breach: 7 of 7 cases defended.
- Packet loss: recovery reported across the tested scenarios.
- Jitter: latency and throughput measurements reported.

**Evidence status:** These are previously documented simulation claims, not independently established by the overall pytest pass count. They should be retained as verified results only when the corresponding simulation scripts, result files, attack definitions, expected outcomes, and execution commands support them. The replay limitation should be described precisely rather than obscured by an overall detection percentage.

Simulation results should distinguish between:

1. An attack being generated successfully.
2. The intended security control detecting the attack.
3. The packet being rejected or contained.
4. The pipeline recovering and continuing to process legitimate traffic.

These are separate outcomes and should be measured separately.

---

## 10. Key Technical Decisions

The project records architectural decisions in `architecture/adr/`.

| ADR | Documented decision |
|---|---|
| ADR-001 | X25519, ChaCha20-Poly1305, and Ed25519 |
| ADR-002 | Pedersen commitments and Bulletproofs |
| ADR-003 | Time- and packet-count-based key rotation |
| ADR-004 | RBAC rather than ABAC for IAM |
| ADR-005 | AWS KMS / CloudHSM for production key management |

An ADR records the rationale and intended direction of a decision. It does not establish that the selected mechanism is fully implemented.

**Implementation distinction:**

- The Python hash-based commitment check must not be represented as an integrated Pedersen/Bulletproofs zero-knowledge proof.
- The documented key-rotation thresholds must be distinguished from verified rotation behaviour.
- AWS KMS / CloudHSM must be labelled as planned unless the live implementation is demonstrably integrated with the service.
- The choice of RBAC does not prove that every relevant operation is currently protected by an enforced policy check.

Each ADR should identify whether its decision is implemented, partially implemented, or planned, and link to the relevant code or tests where possible.

---

## 11. Technology Stack

| Layer | Technology / status |
|---|---|
| Primary language | Python |
| Cryptographic library | PyCA `cryptography` |
| Key agreement | X25519 |
| Key derivation | HKDF-SHA256 |
| Packet authentication | Ed25519 |
| Authenticated encryption | ChaCha20-Poly1305 |
| Telemetry source | FastF1 API |
| Data processing | pandas, NumPy |
| Visualisation | Streamlit dashboard and plotting libraries used by the relevant modules |
| Testing | pytest |
| Commitment verification | Python SHA-256 commitment check |
| Advanced ZKP | Rust/Pedersen/Bulletproofs — planned or separate unless integration is verified |
| Production key management | AWS KMS / CloudHSM — planned unless integration is verified |
| Audit events | In-memory events with optional JSONL persistence |
| CI | GitHub Actions, if configured and active in the current repository |

The exact Python version and dependency constraints should be taken from the repository's environment and dependency files. The documentation previously specified Python 3.11, while a recent reported test environment used Python 3.13.14. The supported version range should be confirmed rather than assuming either version is the sole supported environment.

---

## 12. Testing Status

The latest reported full-suite execution was:

```powershell
python -m pytest -q --tb=short
```

**Reported result: 438 passed in 539.88 seconds.**

Additional reported executions included:

| Test scope | Reported result |
|---|---:|
| Full pytest suite | 438 passed |
| Validator-node suite | 107 passed |
| Focused sequence, replay, header, audit, and adversarial tests | 37 passed |
| Standalone validator replay regression test | 1 passed |

These counts come from overlapping test runs and must not be added together.

The 438-pass result establishes that the tests in that execution completed successfully in the tested environment. It does not prove that every feature described in this document is integrated, that every attack is detected, that the system meets production reliability requirements, or that the implementation has been independently security-audited.

After documentation edits, the test suite should be rerun if implementation files or test configuration change. Documentation-only edits do not themselves demonstrate new runtime behaviour.

---

## 13. Performance and Reliability Evaluation

The architecture is intended to support performance evaluation as well as security testing.

When benchmark results are published, record the test conditions alongside the measurements. Useful metrics include:

- **End-to-end latency:** time between the defined packet-generation and packet-decision events.
- **Median and p95 latency:** typical and tail latency across a stated sample.
- **Throughput:** packets processed per second over a stated interval.
- **Packet loss:** generated packets not delivered or processed, with the measurement point explicitly defined.
- **Rejection rate:** packets rejected, separated by rejection reason.
- **Anomaly counts:** packets flagged or rejected by each configured rule.
- **Cryptographic overhead:** time spent on signing, verification, encryption, and decryption, measured separately where feasible.
- **Recovery behaviour:** whether legitimate traffic resumes after the specified fault or attack scenario.

Every published result should identify the dataset or fixture, hardware and software environment, packet rate, sample size, warm-up procedure, and whether the run uses synthetic fixtures or recorded telemetry.

No numerical latency, throughput, or reliability guarantee is asserted by this architecture document without a corresponding reproducible benchmark result.

---

## 14. Limitations and Scope

PitCrypt-F1 is a prototype for investigating secure telemetry processing. The following boundaries should be kept explicit:

1. **Recorded telemetry is not a live F1 car feed.** FastF1-derived data supports replay, analysis, and simulation; it does not establish access to a real car's live telemetry infrastructure.
2. **A passing test suite is not a security certification.** The tests cover implemented scenarios and can still leave untested paths or assumptions.
3. **The Python commitment check is not a ZKP.** A genuine zero-knowledge implementation requires a separate protocol and proof-system implementation with explicit verification and security assumptions.
4. **JSONL is not inherently immutable.** Strong audit integrity requires controls beyond appending records to a file.
5. **Cryptographic primitives do not automatically establish protocol security.** Key provisioning, peer authentication, nonce management, session lifecycle, error handling, and trust boundaries matter.
6. **Detection is not prevention or recovery.** Simulation reports should distinguish the attack being detected from its containment and the pipeline's subsequent recovery.
7. **A documented policy is not necessarily an enforced policy.** IAM claims require evidence that the policy engine is invoked and its decisions are enforced by the relevant operations.
8. **The prototype is not FIA-approved or production-certified.** No such status is claimed.

---

## 15. Repository Structure

The documented high-level repository layout is:

```text
pitcrypt_f1/
├── car_producer/
│   ├── src/
│   └── tests/
├── relay-node/
│   ├── src/
│   ├── config/
│   └── tests/
├── validator-node/
│   ├── src/
│   ├── config/
│   └── tests/
├── iam-module/
│   ├── src/
│   ├── policies/
│   └── config/
├── forensic/
├── simulations/
│   └── results/
├── benchmarks/
├── architecture/
│   └── adr/
├── docs/
├── zkp-module/
└── data/
```

This is a conceptual overview. Directory names and contents should be checked against the current repository before this structure is treated as an exhaustive file inventory. Local datasets may be gitignored and regenerated through the documented data-loading workflow.

---

## 16. Summary

PitCrypt-F1 combines a multi-stage telemetry pipeline with cryptographic packet protection, independent validator-side verification, replay/sequence checks, IAM components, forensic analysis, adversarial simulations, and telemetry visualisation.

Its central architectural principle is that the relay's decision to forward a packet must not replace independent verification by the validator. The project is strongest when its security properties are connected to reproducible tests, clearly defined trust boundaries, and measured system behaviour.

The implementation status of each component should remain explicit. Features described in architecture decisions, proposed production integrations, and future proof-system work must not be presented as completed capabilities until the corresponding implementation and verification evidence is available.
