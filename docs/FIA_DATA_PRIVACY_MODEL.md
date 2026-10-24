# FIA Data Privacy Model — PitCrypt-F1

**Document:** `FIA_DATA_PRIVACY_MODEL.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Prototype privacy model — not a compliance certification  
**Last reviewed:** 24 October 2026

---

## 1. Overview

PitCrypt-F1 is a prototype for protecting and validating motorsport telemetry as it moves through a logical producer → relay → validator pipeline.

Telemetry may contain commercially sensitive engineering information and driver performance data. Depending on its content, context, and association with an identifiable person, some telemetry may also qualify as personal data under applicable data protection law.

The project explores several privacy and security objectives:

- Protect telemetry confidentiality during transmission.
- Authenticate telemetry and detect specified forms of tampering.
- Limit unnecessary disclosure of telemetry values.
- Separate packet processing from validation and audit functions where feasible.
- Minimise sensitive information in logs.
- Establish a foundation for evaluating privacy controls in a motorsport-inspired environment.

**PitCrypt-F1 is not an FIA-approved telemetry system and has not been demonstrated to comply with FIA regulations or GDPR.** This document describes the prototype's privacy objectives, known implementation characteristics, limitations, and future requirements. It does not establish legal rights, regulatory obligations, or compliance status.

## 2. Scope and implementation status

This model covers telemetry payloads, packet metadata, cryptographic processing, audit events, and access to telemetry within the prototype.

The following terms distinguish implementation evidence from intended design:

- **Implemented:** Relevant functionality exists in the prototype code.
- **Configuration-dependent:** Behaviour depends on runtime settings or the execution path.
- **Requires verification:** The relevant code path, storage behaviour, or control has not been established sufficiently to support a stronger claim.
- **Proposed:** A future control or deployment capability, not a claim about current behaviour.

The local simulation uses in-process component calls. A logical producer, relay, and validator architecture does not by itself establish separate machines, isolated memory, network-level access controls, or independent administrative trust boundaries.

## 3. Data classification

### 3.1 Class 1 — Telemetry used for validation

Examples of telemetry fields in the prototype include:

- Speed
- RPM
- Throttle
- Brake
- Gear (`nGear`)
- DRS
- Lap and frame information
- Track coordinates and distance (`X`, `Y`, `Distance`)
- Driver, race, team, and session identifiers where supplied

These fields support telemetry visualisation, analysis, integrity checks, and simulation of validation decisions.

Their presence in the project does **not** establish that every field is legally required by the FIA or that PitCrypt-F1 implements the FIA's complete telemetry reporting requirements. Such claims require an authoritative, applicable regulatory source and a field-by-field mapping.

**Privacy objective:** Protect telemetry during transmission and expose only the information needed by each intended recipient.

**Current limitations:** The relay decrypts telemetry during processing. The exact persistence, logging, and downstream disclosure behaviour must be assessed against each active processing path.

### 3.2 Class 2 — Proprietary or competitively sensitive data

Potential examples include:

- Engine mode and calibration settings
- Fuel-consumption information
- Cooling configurations
- Energy deployment strategies
- Tyre temperature models
- Other detailed engineering or performance parameters

These examples describe a possible classification for future extensions. They should not be interpreted as proof that all such fields are currently collected, transmitted, or processed by PitCrypt-F1.

**Privacy objective:** Exclude unnecessary proprietary fields from the transmitted schema and protect any sensitive information that is deliberately introduced into the pipeline.

The project should use an explicit schema and field allowlist. Any future addition of proprietary fields should require a documented purpose, access policy, retention rule, and threat assessment.

### 3.3 Class 3 — Processing and audit metadata

Examples include:

- Packet sequence numbers
- Timestamps
- Node, team, and session identifiers
- Signature verification outcomes
- Acceptance or rejection decisions
- Anomaly flags and reason codes
- Relevant access-control decisions, where recorded

Metadata can reveal operational patterns even when it excludes the full telemetry payload. Timestamps, sequence information, session identifiers, and rejection patterns may disclose information about activity or system behaviour.

**Privacy objective:** Record only metadata needed for debugging, security monitoring, validation, and the project's stated research purposes.

The prototype includes an audit logger that maintains events in memory and can optionally write JSONL output. This does not establish a central FIA audit log, S3 storage, immutable records, or a particular retention period.

## 4. Privacy architecture and trust boundaries

### 4.1 Logical pipeline

The intended pipeline is:

`Producer → Relay → Validator`

- **Producer:** Creates telemetry and associated packet data.
- **Relay:** Parses incoming data, decrypts it, performs configured integrity and anomaly checks, and re-encrypts data for the next stage.
- **Validator:** Performs configured validation checks and produces acceptance or rejection outcomes.

The pipeline uses cryptographic components including ChaCha20-Poly1305, Ed25519, and X25519-based session setup. The exact protections available to each stage depend on the active code path, key configuration, and protocol integration.

### 4.2 Relay plaintext access

The relay decrypts telemetry in order to inspect values and run integrity and anomaly checks. Therefore, the relay is a plaintext-processing component and must be treated as part of the trusted computing boundary for those operations.

Encryption on either side of the relay does not prevent the relay process itself from accessing the decrypted values.

The prototype does not establish a guaranteed maximum plaintext-access window of one millisecond, nor does it demonstrate cryptographic deletion of plaintext from memory immediately after processing.

A production implementation would need to evaluate:

- Which relay components can access plaintext.
- Whether plaintext is copied into additional objects or buffers.
- Whether exceptions, debugging, or logging expose payload values.
- Whether crash dumps or memory snapshots can contain telemetry.
- Whether processing state persists beyond an individual packet.
- What operating-system and deployment controls limit access to the relay process.

### 4.3 Relay retention

The intended design is to avoid unnecessary retention of decrypted telemetry at the relay.

This is a design objective, not a verified guarantee. An IAM policy that denies a hypothetical `telemetry.store` action does not itself prevent arbitrary code from retaining plaintext in memory or writing it through an unmediated filesystem or logging path.

The repository's actual data paths, configuration, and storage operations must be inspected before claiming that the relay cannot retain telemetry.

### 4.4 Validator access

The validator receives telemetry through the pipeline and performs configured verification and consistency checks. Its actual access to plaintext, decrypted values, and packet metadata depends on the implementation.

This document does not establish that the validator is operated by the FIA, that only FIA-authorised personnel can access its data, or that validator records are stored permanently.

A production deployment would require authenticated identities, documented authorization boundaries, controlled administrative access, and evidence that the controls are enforced.

## 5. Cryptographic privacy properties

### 5.1 Confidentiality in transit

ChaCha20-Poly1305 is used for authenticated encryption in the prototype. It is intended to protect telemetry from parties that do not possess the appropriate session key.

Confidentiality depends on correct key management, nonce uniqueness, authenticated session setup, and correct handling of authentication failures. The use of encryption does not protect plaintext from a component that legitimately decrypts it.

### 5.2 Signatures and integrity

Ed25519 is used for digital signatures and verification. Signatures can help establish that a message corresponds to a signing key and has not been altered relative to the signed representation.

A signature does not independently prove that telemetry is physically accurate, that a driver or team identity is genuine, or that a public key is trusted. Those properties require additional validation and identity-binding controls.

### 5.3 Hash commitment check

The active Python commitment check recomputes a value based on:

`SHA256(payload + nonce)`

and compares it with the supplied commitment.

This is a hash-based consistency check. It is **not a zero-knowledge proof** and does not establish that a verifier can validate a property of hidden telemetry without access to the underlying value.

A party able to recompute the commitment needs the relevant payload and nonce. A party given only the commitment cannot infer the intended validation property from the commitment alone.

### 5.4 Proposed privacy-preserving proofs

Pedersen commitments and range proofs could be explored for future privacy-preserving validation. For example, an appropriately constructed proof might establish that a value lies within a permitted range without disclosing the exact value.

Such a design would require a defined statement, commitment scheme, proof protocol, verifier, soundness assumptions, parameter handling, and tests.

A separate Rust module or design document does not establish that these proofs are integrated into the active telemetry pipeline.

Until integration and verification are demonstrated, PitCrypt-F1 must not claim that its current live pipeline provides zero-knowledge verification of proprietary telemetry.

## 6. Purpose limitation and data minimisation

The prototype should process telemetry only for documented project functions, including telemetry visualisation, validation, security testing, and performance analysis.

For a real deployment, the data controller or other responsible organisation would need to identify and document the applicable purposes and legal basis for each processing activity.

The following are design recommendations rather than verified system-wide guarantees:

- Use a defined telemetry schema and explicit field allowlist.
- Exclude fields that are not needed for the stated purpose.
- Avoid free-form payload fields unless their necessity and handling are assessed.
- Do not log full telemetry payloads by default.
- Limit dashboard access to the data needed for its intended function.
- Document any export, analytics, or secondary use.
- Review changes to fields, recipients, and processing purposes before deployment.

The relay's anomaly filter processes decrypted values. Whether individual packet values appear in logs depends on the actual logging paths and configuration and should be verified rather than assumed.

## 7. Stakeholder access model

The roles below are conceptual responsibilities for a possible deployment. They do not establish actual FIA, team, or operator permissions in the prototype.

### 7.1 Regulatory or validation authority

**Potential responsibilities:**

- Define the validation rules applicable to the deployment.
- Review validation outcomes and relevant audit evidence.
- Investigate suspected integrity or compliance issues.
- Authorize access to data under the applicable governance framework.

**Privacy limitations and requirements:**

- Access should be limited to data and metadata needed for authorized purposes.
- Access to proprietary information should be explicitly governed.
- Data sharing and retention should follow applicable legal and contractual requirements.

PitCrypt-F1 does not establish that an FIA endpoint is connected or that FIA-specific permissions and data-sharing restrictions are enforced.

### 7.2 Constructor or team

**Potential responsibilities:**

- Generate or supply telemetry.
- Maintain appropriate records of submitted telemetry.
- Review available processing outcomes.
- Support investigations using authorized evidence.

**Privacy limitations and requirements:**

- A team should not gain access to another team's telemetry without authorization.
- Session separation alone does not prove that cross-team access is impossible.
- Audit evidence should be protected from unauthorized modification.
- Historical-data deletion and export requests should follow applicable retention and legal requirements.

### 7.3 Relay operator

**Potential responsibilities:**

- Operate the relay service.
- Process telemetry in transit.
- Execute configured integrity and anomaly checks.
- Investigate operational failures.

**Privacy limitations and requirements:**

- Plaintext access should be limited to necessary processing functions.
- Payload values should not be logged unnecessarily.
- Administrative access should be restricted and audited.
- Retention, disclosure, and incident-response procedures should be documented.

The relay is not cryptographically prevented from accessing plaintext during its processing path. The actual operator's access and retention capabilities depend on deployment controls.

## 8. GDPR and data protection considerations

This section is a preliminary engineering assessment, not legal advice or a determination that GDPR applies to every use of the prototype.

### 8.1 Personal data assessment

Telemetry may constitute personal data when it relates to an identified or identifiable natural person. Driver-linked performance records may therefore require assessment under applicable data protection law.

Whether a specific dataset qualifies depends on its contents, identifiability, context, and processing.

### 8.2 Legal basis

A real deployment must identify an appropriate legal basis for each processing purpose and document it with the responsible controller or legal adviser.

Article 6(1)(c) of the GDPR concerns processing necessary for compliance with a legal obligation applicable to the controller. Whether a particular FIA rule creates such an obligation for a specific organisation and processing activity requires legal analysis; it must not be assumed from the existence of a technical regulation alone.

Article 6(1)(f) concerns legitimate interests, subject to the applicable necessity and balancing assessment. Protecting commercially sensitive information may be relevant to a legitimate-interest analysis, but encryption and access control do not themselves establish a lawful basis.

### 8.3 Data protection by design

Article 25 addresses data protection by design and by default. The prototype's use of encryption, defined packet fields, and limited audit metadata can support design objectives relevant to privacy.

However, the presence of these features is not sufficient to conclude that the system complies with Article 25. Compliance assessment would also need to consider the full processing context, roles, defaults, access, retention, security, and demonstrable safeguards.

### 8.4 Erasure and retention

Article 17 concerns the right to erasure, subject to applicable conditions and exceptions. This document does not establish a universal FIA requirement to retain all telemetry for a minimum of 12 months, nor does it establish that deletion requests must be granted after a particular date.

Retention periods and erasure decisions must be based on verified legal, regulatory, contractual, and operational requirements for the specific deployment.

### 8.5 Data portability

Article 20 provides a right to data portability in specified circumstances and subject to its conditions. It does not establish a general right for every team to export all telemetry in JSON or CSV from this prototype.

Any export functionality should be defined by the application's requirements and the applicable legal framework.

### 8.6 Additional assessment

Before deployment involving personal data, the responsible organisation should assess whether it needs documented controller/processor roles, a lawful-basis analysis, notices, retention schedules, procedures for data-subject requests, security controls, and a data protection impact assessment.

## 9. Data retention and deletion

The following table separates design intentions from verified guarantees.

| Data type | Intended handling | Current status and limitation |
|---|---|---|
| Encrypted telemetry at relay | Keep only as long as needed for processing | Actual buffers, copies, and persistence require verification. |
| Decrypted telemetry at relay | Use for necessary validation and anomaly checks; avoid unnecessary retention | Plaintext exists during processing. A fixed one-millisecond limit and immediate secure deletion are not established. |
| Validator audit events | Retain enough evidence for debugging and validation | Audit logger supports in-memory events and optional JSONL output. No fixed retention period or S3 deployment is established. |
| Access-control events | Record relevant authorization decisions where supported | Exact event coverage, persistence, and retention require verification. |
| Public keys | Keep available while needed to validate trusted identities | Registry implementation, persistence, and deregistration behaviour require verification. |
| Session keys | Keep available only for their intended active sessions | Exact expiry, rotation, cleanup, and secure-erasure behaviour require verification. |
| Exported telemetry or logs | Store only under an approved purpose and retention schedule | Requires deployment-specific controls and procedures. |

No universal retention duration is specified by this prototype document. A production deployment should establish retention periods by data category and document the basis for each period.

Deletion procedures should address application storage, exported files, backups, logs, and any other locations in which data may persist. Deleting an in-memory reference is not the same as verified secure erasure from every storage medium.

## 10. Privacy risk assessment

The ratings below are preliminary qualitative assessments for the prototype. They are not results of a formal risk assessment or measured incident probabilities.

| Risk | Potential impact | Relevant controls or next steps |
|---|---|---|
| Relay exposes decrypted telemetry | Disclosure of sensitive performance information | Minimise plaintext access; inspect copies, logs, dumps, and process permissions. |
| Telemetry intercepted in transit | Disclosure or manipulation of data | Verify AEAD usage, nonce uniqueness, session establishment, and key protection. |
| Public key is substituted or misbound | Peer impersonation or incorrect trust decisions | Authenticate peer identities and test key-substitution scenarios. |
| Audit records disclose operational patterns | Exposure of timing, session, or driver-related information | Minimise fields, restrict access, and define retention. |
| Audit records are modified or lost | Reduced ability to investigate events | Define persistence, integrity protection, access controls, and recovery procedures. |
| Proprietary data is added without review | Unintended disclosure of competitive information | Require schema review, purpose documentation, and an access/retention assessment. |
| Commitment is mistaken for a zero-knowledge proof | Incorrect privacy assurances | Use accurate terminology and integrate a formally defined proof system only if required. |
| Logs or debugging output contain plaintext | Persistent disclosure beyond the intended processing path | Review logging and exception paths and test with sensitive fixture values. |
| Retention or deletion claims are inaccurate | Legal, contractual, or operational exposure | Define verified retention rules and test the full data lifecycle. |
| Cross-team access is incorrectly assumed impossible | Unauthorized disclosure | Test authorization and session isolation under adversarial conditions. |

The existence of a mitigation in this table does not establish that it is already implemented or effective.

## 11. Verification checklist

Before claiming that privacy controls are enforced, verify the following against the source code, configuration, and tests:

- [ ] Document all telemetry fields actually emitted by the producer.
- [ ] Identify every component that can access plaintext.
- [ ] Inspect relay processing for copies, logs, exception messages, and persistence.
- [ ] Verify encryption and authentication behaviour in each active packet path.
- [ ] Verify peer identity binding and session isolation.
- [ ] Confirm which integrity and anomaly checks execute in the JSON-envelope path.
- [ ] Confirm which payload fields, if any, are recorded in audit events.
- [ ] Identify all storage destinations and the lifecycle of in-memory data.
- [ ] Verify that claimed access restrictions are enforced by actual code or deployment controls.
- [ ] Confirm whether any external storage, KMS, HSM, or centralized logging service is integrated.
- [ ] Test cross-team access and unauthorized session use.
- [ ] Establish documented retention and deletion behaviour.
- [ ] Correctly classify the Python commitment check as a hash-based consistency check, not a ZKP.
- [ ] Review any future Pedersen commitment or range-proof integration independently.
- [ ] Obtain legal and regulatory review before making formal compliance claims.

Record test results and evidence before marking a control as verified.

## 12. Conclusion

PitCrypt-F1 explores cryptographic protection, telemetry validation, and data-minimisation concepts for a motorsport-inspired pipeline. Its encryption and signature mechanisms can contribute to confidentiality and integrity when correctly implemented and configured.

The relay's need to decrypt telemetry, the prototype's current hash-based commitment check, the limitations of the audit logger, and the need to verify key and access-control lifecycles impose important boundaries on the privacy claims that can currently be made.

The project should be described as a **privacy- and security-oriented prototype**, not as a proven FIA-compliant or GDPR-compliant system. Stronger claims should follow only after implementation review, reproducible testing, deployment-specific controls, and appropriate legal or regulatory assessment.

## 13. Related documents

- `docs/FIA_REGULATION_MAPPING.md` — Preliminary regulatory mapping; not proof of compliance.
- `docs/KEY_MANAGEMENT.md` — Key lifecycle and management requirements.
- `docs/CRYPTOGRAPHIC_PRIMITIVES.md` — Cryptographic primitives and their limitations.
- `docs/PROTOCOL_SPEC.md` — Packet and protocol behaviour.
- `docs/PACKET_FORMAT.md` — Packet representation and fields.
- `docs/AUDIT_TRAIL.md` — Audit event structure and logging limitations.
- `docs/THREAT_MODEL.md` — Threats, trust boundaries, and mitigations.
- `architecture/adr/002-zkp-commitments.md` — Proposed commitment design, if this file exists and remains applicable.
- `iam-module/policies/relay_node_policy.yaml` — Policy file, if present; its existence or enforcement must be verified before relying on it.
