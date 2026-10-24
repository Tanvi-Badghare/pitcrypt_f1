# Security Framework Alignment

**Project:** PitCrypt-F1  
**Document:** `docs/COMPLIANCE.md`  
**Version:** 1.0  
**Status:** Preliminary framework mapping — not a certification or compliance assessment

## 1. Purpose

This document maps the security objectives and controls implemented or planned in PitCrypt-F1 to relevant themes in:

- **ISO/IEC 27001:2022**, particularly its information security management requirements and Annex A control themes.
- **NIST Cybersecurity Framework (CSF) 2.0**, including its Govern, Identify, Protect, Detect, Respond, and Recover functions.

PitCrypt-F1 is an educational and engineering prototype for protecting and validating motorsport telemetry. These mappings are intended to guide development, testing, and documentation. They do not establish that the project, its developer, or any organization using it is certified or compliant with either framework.

## 2. Scope and assumptions

The scope of this mapping is the prototype's telemetry processing pipeline and related security components:

- Telemetry packet construction and cryptographic protection.
- Relay-side packet processing and anomaly checks.
- Validator-side signature, sequence, metadata, and commitment checks.
- Identity and role-based access-control components.
- Security-event and audit logging.
- Simulated attack scenarios and test coverage.
- Key-management and operational-security design considerations.

The mapping does not assess an actual Formula One team's infrastructure, FIA systems, production trackside networks, organizational security management system, or contractual obligations.

### 2.1 Evidence classifications

Each mapping should be interpreted using the following classifications:

| Classification | Meaning |
|---|---|
| Implemented — evidence required | A control or component exists in the prototype, but the relevant code, tests, and execution evidence must be reviewed before claiming effectiveness. |
| Partially implemented | Some relevant functionality exists, but coverage or integration is incomplete. |
| Planned | A design objective or future improvement, not a current capability. |
| Not assessed | Available project evidence is insufficient to determine implementation or effectiveness. |
| Not applicable to prototype scope | The control concerns organizational or operational requirements that this software prototype does not independently implement. |

These labels describe engineering status, not certification status.

## 3. ISO/IEC 27001:2022 alignment

ISO/IEC 27001 is an organizational information security management system (ISMS) standard. A software project alone cannot demonstrate organizational conformity with the standard. Annex A controls are selected and applied in the context of an organization's risks, scope, and Statement of Applicability.

The following table identifies potentially relevant control themes. It is not an exhaustive Annex A checklist or a claim that any control has been formally assessed.

| ISO 27001:2022 theme | Relevance to PitCrypt-F1 | Current evidence and limitations |
|---|---|---|
| Access control (Annex A 5.15) | Restrict access to telemetry, identities, and security-sensitive operations. | An IAM/RBAC module exists in the project. End-to-end enforcement across all interfaces and operations must be verified. |
| Identity management (A 5.16) | Manage identities used by pipeline components and users. | Identity-related components exist. Lifecycle, uniqueness, provisioning, revocation, and identity-proofing controls require review. |
| Authentication information (A 5.17) | Protect authentication material and key-related information. | Cryptographic authentication is used in the telemetry pipeline. Secure secret storage, rotation, backup, and recovery are not established merely by using cryptographic libraries. |
| Access rights (A 5.18) | Define, review, and revoke permissions. | RBAC and policy-loading components exist. Administrative workflows and periodic access reviews are not demonstrated by their existence alone. |
| Cryptography (A 8.24) | Protect telemetry confidentiality and authenticity. | The design uses Ed25519 signatures and ChaCha20-Poly1305 AEAD, with X25519 and HKDF-SHA256 for key establishment/derivation. Correctness depends on implementation, key handling, nonce discipline, and tests. |
| Logging (A 8.15) | Record security-relevant events and decisions. | An audit logger supports in-memory events and optional JSONL output. Log completeness, access restrictions, retention, and operational monitoring need separate validation. |
| Monitoring activities (A 8.16) | Detect suspicious activity and security-relevant deviations. | The prototype includes sequence/replay checks and anomaly-related components. Detection coverage, false-positive rates, and production monitoring are not established. |
| Information deletion (A 8.10) | Manage the lifecycle of telemetry and audit data. | A formal retention and deletion policy has not been established by the current prototype documentation. |
| Configuration management (A 8.9) | Control security-sensitive settings and component configurations. | Configuration and policy files require review for versioning, validation, secure defaults, and change control. |
| Secure development lifecycle (A 8.25) | Integrate security requirements and testing into development. | Security-focused regression tests exist. A formal organizational secure-development lifecycle, approvals, release gates, and vulnerability-management process have not been demonstrated. |
| Security testing in development and acceptance (A 8.29) | Test security controls before accepting changes. | The reported test suite includes validator, replay, signature, sequence, metadata, and audit tests. Passing tests do not establish comprehensive security assurance. |
| Protection of records (A 5.33) | Protect records from loss, unauthorized access, and improper modification. | Audit events can be serialized to JSONL, but the file is not inherently immutable or tamper-evident. Additional storage and integrity controls are needed. |
| Incident management (A 5.24–5.28 themes) | Prepare for, assess, respond to, and learn from security incidents. | Simulated attacks and audit events support experimentation. An organizational incident-response process, escalation policy, and evidence-handling procedure are outside the demonstrated prototype scope. |

**Assessment:** PitCrypt-F1 contains mechanisms relevant to selected information-security control themes. This table does not demonstrate ISO/IEC 27001 conformity. Organizational policies, risk assessment, governance, documented procedures, evidence of operational effectiveness, and an appropriately scoped assessment would be needed for a formal claim.

## 4. NIST Cybersecurity Framework 2.0 alignment

NIST CSF 2.0 organizes cybersecurity outcomes into six functions. The mapping below uses those functions as a way to organize the prototype's capabilities and gaps.

### 4.1 Govern (GV)

**Objective:** Establish accountability, policy, roles, and risk oversight.

Potential project relevance:
- Document the prototype's intended scope and trust boundaries.
- Define which component is responsible for packet validation, key handling, and audit generation.
- Maintain an explicit distinction between current capabilities and planned controls.
- Record limitations, unresolved security questions, and test evidence.

**Status:** Partially addressed through technical documentation and architecture decisions. Organizational governance, formal risk ownership, policy approval, and supplier or third-party risk management are not demonstrated by the prototype.

### 4.2 Identify (ID)

**Objective:** Understand the assets, systems, dependencies, and risks that need protection.

Potential project relevance:
- Identify telemetry payloads, packet metadata, signing keys, session keys, identity records, and audit events as security-relevant assets.
- Document the producer, relay, and validator trust boundaries.
- Maintain an inventory of cryptographic dependencies and pipeline components.
- Use a threat model to document spoofing, tampering, replay, unauthorized access, and availability risks.

**Status:** Partially addressed through the architecture and threat-model documentation. A maintained asset inventory, dependency inventory, and formal risk-assessment process require verification.

### 4.3 Protect (PR)

**Objective:** Implement safeguards to reduce the likelihood and impact of cybersecurity incidents.

Potential project relevance:
- Ed25519 signing and verification for packet authenticity.
- ChaCha20-Poly1305 authenticated encryption for confidentiality and integrity protection.
- X25519 and HKDF-SHA256 for key establishment and derivation.
- RBAC-related components for access decisions.
- Sequence checks to reject packets that violate expected ordering or replay rules.

**Status:** Relevant mechanisms exist in the prototype. Their exact coverage, correct configuration, key lifecycle, and resistance to misuse must be established through code review and tests. A hash-based commitment check must not be described as a zero-knowledge proof.

### 4.4 Detect (DE)

**Objective:** Identify potentially adverse cybersecurity events.

Potential project relevance:
- Signature-verification failures.
- Invalid metadata and packet-header inconsistencies.
- Sequence violations and replay attempts.
- Anomaly-related checks and security audit events.

**Status:** Detection mechanisms and related tests exist. Detection completeness, sensitivity, false positives, and performance under realistic workloads remain to be evaluated. Any claimed detection rates should identify the precise scenario, sample size, test method, and result.

### 4.5 Respond (RS)

**Objective:** Take action when a cybersecurity event is detected.

Potential project relevance:
- Rejecting packets that fail validation.
- Recording rejection reasons.
- Preserving diagnostic context for subsequent analysis.
- Using simulated attacks to test expected rejection paths.

**Status:** Packet rejection and audit-event generation are part of the described pipeline. Automated incident escalation, coordinated response procedures, operator notification, and recovery workflows have not been established as complete operational capabilities.

### 4.6 Recover (RC)

**Objective:** Restore capabilities and improve resilience after an incident.

Potential project relevance:
- Reinitializing affected test runs and validating recovery behavior.
- Measuring the effect of packet loss, jitter, and invalid traffic.
- Documenting recovery expectations and limitations.

**Status:** Simulation scenarios may help evaluate resilience, but a complete recovery process, persistent state restoration, key compromise recovery, and tested service restoration are not established by the available project evidence.

## 5. Cross-framework control matrix

| Security objective | ISO 27001 theme | NIST CSF 2.0 function | Prototype evidence to collect |
|---|---|---|---|
| Authenticate telemetry packets | Cryptography; secure development | Protect | Signature tests, negative tests, code review, key-handling review |
| Reject replay or invalid sequences | Logging; monitoring; secure development | Protect, Detect | Sequence/replay tests, state-transition evidence, defined test cases |
| Restrict access | Access control; identity management; access rights | Govern, Protect | Policy tests, role matrix, denied-access tests, integration review |
| Record validation decisions | Logging; protection of records | Detect, Respond | Audit tests, sample events, failure-path coverage, storage review |
| Detect anomalous traffic | Monitoring activities | Detect | Defined datasets, detection metrics, false-positive analysis |
| Manage cryptographic keys | Authentication information; cryptography | Protect | Key lifecycle design, rotation tests, nonce review, secret-storage assessment |
| Handle security incidents | Incident-management themes | Respond, Recover | Rejection behavior, incident playbook, escalation and recovery tests |
| Maintain trustworthy project configuration | Configuration management; secure development | Govern, Identify, Protect | Version-controlled configuration, dependency inventory, change review |

## 6. Evidence required before making stronger claims

Before presenting the project as aligned with particular controls, retain evidence for the specific claim:

1. **Implementation evidence:** Relevant source files, configuration, and an explanation of where the control is enforced.
2. **Test evidence:** Reproducible test commands, expected behavior, actual output, and negative cases.
3. **Integration evidence:** Confirmation that the control is exercised by the complete pipeline rather than only in an isolated unit test.
4. **Operational evidence:** Where applicable, evidence for key rotation, log retention, access restrictions, monitoring, and recovery.
5. **Scope statement:** A clear description of the environments and assumptions covered by the test.
6. **Limitations:** Known bypasses, disabled checks, untested failure paths, and functionality that is planned rather than implemented.

A passing automated test demonstrates the behavior covered by that test. It does not independently prove compliance with an entire framework or control family.

## 7. Known limitations and open work

The following points must be resolved or explicitly retained as limitations:

- **No formal certification:** PitCrypt-F1 has not been established as ISO/IEC 27001 certified or formally assessed for conformity.
- **No organizational CSF assessment:** The NIST mapping is a technical self-assessment, not an organizational CSF profile or independent evaluation.
- **Audit integrity:** In-memory and JSONL logging do not inherently prevent alteration or deletion.
- **Key lifecycle:** Rotation, revocation, compromise handling, secure storage, and recovery require explicit evidence.
- **Control integration:** The existence of IAM, anomaly-detection, or cryptographic modules does not prove enforcement at every relevant boundary.
- **Telemetry freshness:** Timestamp-based freshness protection must not be claimed as active unless implementation and tests establish it.
- **Commitment verification:** The Python SHA-256 commitment check is not a zero-knowledge proof. Any separate Rust proof-of-concept must be assessed independently and must not be represented as integrated without evidence.
- **Production readiness:** No claim is made that the prototype has been validated on a live trackside network or deployed by an F1 team.

## 8. Review checklist

- [ ] Confirm the exact ISO/IEC 27001 edition and control wording used in any external report.
- [ ] Review the NIST CSF 2.0 categories and subcategories before assigning specific identifiers.
- [ ] Link each claimed control to the actual implementation and relevant tests.
- [ ] Verify the complete packet path, including rejection and error-handling paths.
- [ ] Document key management and audit-log integrity limitations.
- [ ] Remove any unsupported “compliant,” “certified,” “immutable,” or “production-ready” claim.
- [ ] Reassess the mapping when the architecture or implementation changes.

## 9. Conclusion

PitCrypt-F1 is a security-oriented telemetry prototype with mechanisms that are relevant to several ISO 27001 control themes and NIST CSF 2.0 functions. The mapping is intended to make the engineering work auditable and to identify missing evidence. It is not a declaration of formal compliance, certification, or operational readiness.

## Related documentation

- `ARCHITECTURE_OVERVIEW.md` — system architecture and component responsibilities.
- `THREAT_MODEL.md` — threats, trust boundaries, and security assumptions.
- `PROTOCOL_SPEC.md` — protocol behavior and security checks.
- `PACKET_FORMAT.md` — packet structure and field definitions.
- `AUDIT_TRAIL.md` — audit-event schema and logging limitations.
- `FIA_REGULATION_MAPPING.md` — separate preliminary analysis of motorsport-regulatory references; not an official FIA compliance assessment.