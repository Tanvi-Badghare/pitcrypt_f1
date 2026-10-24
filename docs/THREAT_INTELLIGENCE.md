# Threat Intelligence — PitCrypt-F1

**Document:** `THREAT_INTELLIGENCE.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Prototype threat intelligence assessment  
**Last reviewed:** 24 October 2026

---

## 1. Overview

This document identifies threat scenarios relevant to PitCrypt-F1, a prototype that explores telemetry confidentiality, cryptographic authentication, integrity validation, anomaly detection, and audit logging.

The assessment considers threats from external attackers, competing organisations, insiders, compromised software, and opportunistic actors. It also considers how an attacker might attempt to intercept, replay, modify, or disclose telemetry.

The scenarios are informed by general cybersecurity threat models and the competitive sensitivity of motorsport engineering data. They are not evidence that a specific actor has targeted PitCrypt-F1 or that a particular attack has occurred against a Formula 1 team.

**Scope limitation:** PitCrypt-F1 is a prototype, not a deployed FIA telemetry system. Its local simulation uses in-process component calls. Production network segmentation, cloud monitoring, SSH hardening, immutable storage, and other infrastructure controls must not be assumed to exist unless deployment evidence confirms them.

The purpose of this document is to guide testing, prioritise mitigations, and identify security assumptions that require validation.

## 2. Threat assessment methodology

Threat scenarios are organised by likely motivation, access, capabilities, and potential impact.

The assessment considers:

- Confidentiality of telemetry and engineering information.
- Integrity of telemetry values, packet metadata, and validation decisions.
- Authentication of producers and other pipeline components.
- Availability of telemetry processing.
- Trustworthiness and availability of audit evidence.
- Exposure through dependencies, configuration, and development practices.

The actor categories below are qualitative threat profiles, not verified intelligence assessments or a ranking of actual Formula 1 threats.

## 3. Threat actor landscape

### TA1 — Well-resourced espionage actors

**Profile:** An organisation or individual with substantial resources, persistence, and an interest in valuable engineering information.

**Potential motivation:** Obtain confidential performance, powertrain, vehicle-development, or operational information.

**Possible tactics:**

- Spear-phishing personnel with access to development systems.
- Stealing credentials or compromising endpoints.
- Exploiting vulnerable software or misconfigured infrastructure.
- Compromising a software dependency or development pipeline.
- Seeking access to stored telemetry, logs, or cryptographic keys.

**Potential relevance to PitCrypt-F1:** A public source repository may reveal implementation details, dependencies, data formats, and potential weaknesses. This is not inherently a security failure; public documentation can support review and reproducibility. It does mean that the project should not rely on the secrecy of its design as a security control.

**Mitigations and open questions:**

- Protect private keys and credentials.
- Review dependencies and pin or constrain versions appropriately.
- Test authentication and authorization boundaries.
- Minimise sensitive data in logs and repository artifacts.
- Review the impact of relay, validator, and development-environment compromise.

Do not claim that the prototype's current controls defeat a sophisticated persistent attacker without evidence from an appropriately scoped assessment.

### TA2 — Competitor or commercial espionage

**Profile:** An actor seeking a competitive advantage through unauthorised access to engineering or operational information.

**Potential motivation:** Obtain another organisation's confidential telemetry, performance characteristics, or strategy-related information.

The 2007 McLaren–Ferrari espionage controversy is a historical example of the competitive sensitivity of Formula 1 technical information. It does not establish that modern telemetry systems are being attacked in the same manner or that PitCrypt-F1's threat scenarios have occurred.

**Possible tactics:**

- Misuse of legitimately held credentials.
- Unauthorised copying of telemetry or reports.
- Insider-assisted disclosure.
- Attempted access to another team's session or data.
- Exploitation of shared systems or improperly separated identities.

**Potential relevance to PitCrypt-F1:** A system that handles multiple team identities must verify that sessions, keys, routing, and authorization decisions are associated with the correct team.

**Mitigations and open questions:**

- Verify key-to-identity binding.
- Test cross-team session isolation.
- Test unauthorized session reuse and identity substitution.
- Restrict access to telemetry exports and audit events.
- Establish how key revocation and access removal work.
- Review administrative privileges and potential insider access.

Separate session keys can help isolate encrypted traffic when correctly implemented. They do not, by themselves, guarantee that applications, logs, memory, or authorization paths cannot expose another team's data.

### TA3 — Opportunistic attackers

**Profile:** An actor using readily available scanning tools, exploit code, or credential attacks without requiring specialised motorsport knowledge.

**Potential motivation:** Find exposed services, steal information, disrupt processing, or exploit a vulnerable host.

**Possible tactics:**

- Port scanning.
- Credential stuffing or password guessing.
- Exploiting unpatched dependencies.
- Sending malformed packets to a parser.
- Flooding a service or exhausting processing resources.

**Potential relevance to PitCrypt-F1:** Any future network-facing deployment may expose packet parsers, session setup, administrative interfaces, or monitoring services to untrusted inputs.

The current local simulation does not establish which network services, if any, are exposed in a separate deployment.

**Mitigations and open questions:**

- Validate untrusted inputs and enforce size limits.
- Test malformed and truncated packet handling.
- Apply appropriate authentication to administrative interfaces.
- Define rate limits and resource limits for network-facing services.
- Keep dependencies updated and assess relevant advisories.
- Verify network exposure from the actual deployment configuration.

Do not claim that unknown nodes are automatically blocked by IAM or that a cryptographic handshake precedes every packet unless those behaviours are implemented and tested in the relevant execution path.

### TA4 — Insider or compromised trusted component

**Profile:** A person with legitimate access, a compromised account, or malicious code running inside a trusted component.

**Potential motivation:** Disclose telemetry, manipulate validation outcomes, disable monitoring, or alter security configuration.

**Possible tactics:**

- Copy telemetry from memory or logs.
- Modify anomaly thresholds or validation settings.
- Replace a trusted public key or alter a registry.
- Tamper with audit files.
- Use administrative privileges to change application behaviour.
- Introduce malicious code through a development or deployment workflow.

**Potential relevance to PitCrypt-F1:** The relay decrypts telemetry during processing. A compromised relay process may therefore access plaintext while it is available to that component. Cryptographic protection of traffic does not prevent an authorised or compromised endpoint from inspecting its plaintext.

**Mitigations and open questions:**

- Minimise plaintext access and unnecessary copies.
- Restrict configuration changes.
- Record security-relevant administrative actions where supported.
- Protect key material and deployment credentials.
- Test whether modified thresholds can silently change decisions.
- Assess audit-log integrity and recovery.
- Define key replacement and incident-response procedures.

Do not describe session keys as ephemeral, automatically rotated, or bounded to a particular lifetime unless the active implementation and tests establish those properties.

## 4. Threats to cryptographic and protocol components

### 4.1 Public-key substitution and peer impersonation

**Scenario:** An attacker substitutes a public key or tricks a component into associating a key with the wrong producer identity.

**Potential impact:** A component may establish a session with an unintended peer or accept data under an incorrect identity assumption.

**Relevant controls:**

- Authenticated key provisioning.
- Explicit binding between public keys and peer identities.
- Verification of the expected identity during session establishment.
- Rejection of unknown or unauthorised keys.
- Tests for public-key substitution and unexpected peer identities.

**Current limitation:** X25519 provides key agreement; it does not authenticate the peer by itself. The presence of session setup functions does not establish that the complete handshake is authenticated or that a wire-level handshake is implemented.

### 4.2 Telemetry modification

**Scenario:** An attacker changes a packet's payload, metadata, or encrypted representation.

**Potential impact:** Altered telemetry may be accepted, processing may fail, or downstream analysis may become misleading.

**Relevant controls:**

- ChaCha20-Poly1305 authenticated encryption.
- Ed25519 signature verification.
- Header and payload consistency checks.
- Explicit failure handling.
- Tests that mutate individual packet fields and verify the resulting decision.

**Current limitation:** The exact signed byte sequence, associated-data usage, and behaviour of the relay's decrypt/re-encrypt path must be verified. The presence of cryptographic primitives alone does not establish that every field is authenticated in every path.

### 4.3 Replay attacks

**Scenario:** An attacker resends a previously observed packet or attempts to reuse sequence information.

**Potential impact:** Duplicate, stale, or out-of-order telemetry may be processed as new data.

**Relevant controls:**

- Sequence-number validation.
- Replay detection.
- Session binding.
- Timestamp freshness checks where correctly configured.
- Tests for duplicate, reordered, stale, and cross-session packets.

**Current limitation:** Replay protection depends on the active sequence checker, its state and reset rules, and the relevant configuration. Timestamp checking is configuration-dependent: the validator's default configuration has timestamp checking disabled unless enabled. A replay-control component existing in the code does not prove that all replay scenarios are blocked.

### 4.4 Key exposure

**Scenario:** An attacker obtains a private key, shared secret, or derived session key.

**Potential impact:** Depending on the key type and protocol design, an attacker may impersonate a peer, decrypt affected traffic, or forge messages.

**Relevant controls:**

- Restricted access to secret material.
- Separation of signing and session keys.
- Key replacement and revocation procedures.
- Avoidance of secrets in logs and source control.
- Defined session lifetimes and key lifecycle tests.

**Current limitation:** The implemented key storage, rotation, revocation, and secure-erasure behaviour must be verified. Do not claim forward secrecy solely because X25519 is used.

### 4.5 Commitment misuse

**Scenario:** A hash-based commitment check is described or relied upon as if it were a formal zero-knowledge proof.

**Potential impact:** Stakeholders may receive incorrect privacy assurances or assume a validation property that the implementation does not establish.

**Relevant controls:**

- Correctly document the active `SHA256(payload + nonce)` check.
- Define what the verifier actually learns and checks.
- Keep proposed Pedersen commitments and range proofs separate from the active Python path.
- Require a defined proof protocol and tests before making zero-knowledge claims.

**Current limitation:** The active Python commitment check is not, by itself, a zero-knowledge proof.

### 4.6 Malformed input and parser attacks

**Scenario:** An attacker supplies malformed, oversized, inconsistent, or unexpected packet data.

**Potential impact:** Processing errors, resource exhaustion, application crashes, incorrect parsing, or bypass of intended validation.

**Relevant controls:**

- Strict envelope and field validation.
- Length and type checks.
- Bounded resource consumption.
- Safe exception handling.
- Fuzzing or systematic malformed-input tests.
- Clear rejection behaviour.

**Current limitation:** The breadth of parser testing and resource limits must be established from the source and test suite.

### 4.7 Availability attacks

**Scenario:** An attacker floods the pipeline, repeatedly triggers expensive cryptographic operations, or sends packets designed to exhaust CPU, memory, or queues.

**Potential impact:** Increased latency, dropped telemetry, service interruption, or incomplete records.

**Relevant controls:**

- Input size limits.
- Bounded queues and buffers.
- Rate limits where appropriate.
- Resource monitoring.
- Defined overload and recovery behaviour.
- Tests under sustained and malformed traffic.

**Current limitation:** Do not claim production rate limiting, a specific queue capacity, or guaranteed throughput without verified implementation and measurements.

### 4.8 Audit integrity and disclosure

**Scenario:** An attacker or insider modifies, deletes, or reads sensitive audit information.

**Potential impact:** Loss of investigative evidence, disclosure of operational patterns, or misleading records.

**Relevant controls:**

- Restrict access to audit outputs.
- Minimise sensitive fields.
- Protect stored files and backups.
- Record security-relevant changes.
- Evaluate integrity protection and independent storage controls.
- Test recovery from accidental deletion or corruption.

**Current limitation:** The prototype audit logger maintains events in memory and can optionally write JSONL output. It is not inherently immutable or tamper-proof. AWS CloudTrail, S3 retention controls, and external monitoring must not be claimed unless deployed and verified.

## 5. Vulnerability intelligence and dependency management

### 5.1 Applicability principles

A published CVE does not automatically apply to PitCrypt-F1 because its description mentions a cryptographic algorithm, library, operating system, or network service.

Applicability depends on:

- The affected product and component.
- The exact installed version.
- Whether the vulnerable code path is used.
- The operating system and deployment environment.
- Available configuration and mitigations.
- The advisory's stated affected and fixed versions.

The project's dependencies should be inventoried before assigning vulnerability status.

### 5.2 Historical CVEs require verification

The original version of this document listed CVE-2019-15847, CVE-2020-1967, CVE-2022-21449, CVE-2016-7434, CVE-2021-3449, and CVE-2023-38408.

Those identifiers should not be treated as verified findings against PitCrypt-F1 merely because they appeared in an earlier draft. Before restoring any entry, validate its official advisory, affected products and versions, technical description, severity, and relevance to the actual dependency inventory.

In particular:

- A vulnerability in GnuPG does not automatically establish exposure in a Python application using a different cryptographic interface.
- A Java signature-verification vulnerability does not establish that a Python Ed25519 implementation is affected.
- A vulnerability in OpenSSL or a TLS implementation does not establish exposure if the affected component and code path are absent.
- A vulnerability in OpenSSH matters only when the relevant software and vulnerable configuration exist in the deployment.
- A vulnerability in a time service matters only after the time source, implementation, and security assumptions are identified.

Do not infer that a library is unaffected merely because the application uses a different high-level API. Establish the actual dependency chain and the library versions in use.

### 5.3 Dependency inventory

Maintain a reproducible inventory of:

- Python version.
- Installed Python packages and versions.
- Cryptographic library versions and their relevant native dependencies.
- Rust dependencies and lockfile versions, if applicable.
- Operating system and runtime versions.
- Network services included in a particular deployment.
- Build and deployment tooling.

Use the repository's dependency manifests and lockfiles as the starting point. Verify the actual installed environment where possible.

### 5.4 Vulnerability review workflow

For each relevant advisory:

1. Record the CVE or vendor advisory identifier.
2. Consult the authoritative advisory and affected-version information.
3. Identify whether the affected component is present.
4. Determine whether the vulnerable code path is used.
5. Record the installed and fixed versions.
6. Assess exposure, impact, and available mitigations.
7. Create an update or mitigation task where required.
8. Retest and record the outcome.

Do not assign a severity or mark a vulnerability as fixed based solely on an unverified statement in project documentation.

## 6. Adversarial attack lifecycle

The following lifecycle is an analysis aid based on common attack-lifecycle concepts. It is not evidence that every stage occurs in every incident, and the prototype does not implement a complete defence at every stage.

### Phase 1 — Reconnaissance

**Attacker objective:** Identify components, trust boundaries, dependencies, and potential entry points.

**Possible activity:**

- Review public repository code and dependency files.
- Identify exposed services in a real deployment.
- Study packet formats and validation rules.
- Target personnel or accounts with access to the environment.

**Defensive priorities:**

- Remove secrets and credentials from source control.
- Document the intended attack surface.
- Keep public technical documentation accurate.
- Verify actual network exposure in the deployed environment.

A public repository is not inherently insecure. Security should not depend on hiding cryptographic design details.

### Phase 2 — Preparation

**Attacker objective:** Prepare tooling or an exploit for a suspected weakness.

**Possible activity:**

- Construct malformed or replayed packets.
- Prepare credential attacks.
- Investigate known dependency vulnerabilities.
- Build test traffic intended to trigger resource exhaustion.

**Defensive priorities:**

- Test the parser with malformed inputs.
- Maintain a dependency inventory.
- Validate the cryptographic protocol and error handling.
- Establish repeatable negative tests.

### Phase 3 — Delivery

**Attacker objective:** Deliver malicious input or gain access to a component.

**Possible activity:**

- Submit packets to an exposed endpoint.
- Compromise a workstation or account.
- Exploit an exposed administrative interface.
- Introduce malicious code through a compromised build or dependency.

**Defensive priorities:**

- Authenticate untrusted peers.
- Restrict access to administrative services.
- Validate all external inputs.
- Protect development and deployment credentials.

The current local simulation does not establish that the same network delivery paths exist in a separate deployment.

### Phase 4 — Exploitation

**Attacker objective:** Trigger a weakness or bypass an intended check.

**Possible activity:**

- Replay packets.
- Modify packet fields or ciphertext.
- Supply an invalid signature or malformed envelope.
- Exploit a vulnerable dependency.
- Trigger resource exhaustion.

**Defensive priorities:**

- Verify AEAD authentication and signature checks.
- Test sequence and replay detection.
- Ensure invalid packets fail safely.
- Exercise resource limits and error paths.

These are required defensive properties to test, not guarantees that every attack is currently blocked.

### Phase 5 — Persistence or privileged access

**Attacker objective:** Maintain access or alter trusted processing.

**Possible activity:**

- Modify configuration or threshold files.
- Change a key registry.
- Tamper with application code.
- Obtain access to a privileged process or account.

**Defensive priorities:**

- Restrict configuration and deployment changes.
- Review key provisioning and replacement.
- Test the impact of compromised components.
- Record relevant administrative actions where supported.

Do not claim that relay compromise is harmless. A compromised relay may be able to inspect telemetry while it is decrypted and may influence processing or availability, depending on its privileges.

### Phase 6 — Control and continued access

**Attacker objective:** Continue interacting with a compromised environment or evade detection.

**Possible activity:**

- Use compromised credentials.
- Send repeated malicious requests.
- Modify configuration to reduce visibility.
- Exploit available outbound connectivity.

**Defensive priorities:**

- Define appropriate monitoring and access restrictions.
- Inspect real deployment network rules.
- Review unexpected changes to processes and configuration.
- Establish incident-response and containment procedures.

VPC flow logs, CloudTrail, security groups, and outbound-connection restrictions are deployment-specific controls. They are not current prototype guarantees.

### Phase 7 — Impact

**Attacker objective:** Disclose data, corrupt processing, interrupt service, or undermine trust in records.

**Possible activity:**

- Extract decrypted telemetry.
- Submit malicious or misleading inputs.
- Cause packet loss or processing failures.
- Alter or delete audit output.
- Exploit access to change validation configuration.

**Defensive priorities:**

- Minimise plaintext exposure.
- Validate data at appropriate trust boundaries.
- Protect configuration and keys.
- Preserve available evidence.
- Exercise the incident-response procedure.
- Assess the impact of compromised producers, relays, validators, and operators separately.

Cryptographic controls can reduce certain risks, but they do not guarantee that a compromised endpoint or privileged insider cannot affect the system.

## 7. Mapping threats to project controls

| Threat | Relevant project capability | Remaining verification or limitation |
|---|---|---|
| Packet interception | ChaCha20-Poly1305 encryption | Verify key establishment, nonce handling, and correct AEAD integration. |
| Packet modification | AEAD authentication and Ed25519 signatures | Verify authenticated fields and exact signed bytes. |
| Replay | Sequence and replay checks | Test duplicate, stale, out-of-order, and cross-session cases. |
| Peer impersonation | X25519 session setup and public-key cryptography | Verify trusted identity binding and authenticated key exchange. |
| Telemetry outliers | Statistical baselines and anomaly filtering | Measure false positives and false negatives; an outlier is not proof of an attack. |
| Malformed packet | Parser and envelope validation | Test malformed input, resource limits, and safe rejection. |
| Key compromise | Key-management design | Verify storage, rotation, revocation, and recovery behaviour. |
| Insider disclosure | Intended access restrictions and data minimisation | Verify actual authorization boundaries and plaintext/log exposure. |
| Audit tampering | Audit logger | In-memory and JSONL logging do not provide immutability by themselves. |
| Dependency exploitation | Dependency inventory and vulnerability review | Verify versions, advisories, exposure, and remediation. |
| Denial of service | Input validation and proposed resource controls | Measure and test rate limits, bounded resources, and overload behaviour. |
| Configuration tampering | Configuration and access-control mechanisms | Verify file protection, authorization, and detection of changes. |

## 8. Intelligence sources and validation

Threat information should be obtained from sources appropriate to the question being assessed. Relevant source categories include:

- MITRE ATT&CK Enterprise knowledge base.
- National Vulnerability Database (NVD) and relevant vendor advisories.
- NIST cybersecurity guidance.
- ENISA threat landscape publications.
- Automotive Information Sharing and Analysis Center (Auto-ISAC) publications where relevant.
- Official technical and regulatory documents where a regulatory claim is made.
- Reputable public records for historical incidents.

The existence of a source in this list does not mean that every claim in this document has been verified against it. Record the exact advisory, publication, version, and access date when a finding depends on a specific external source.

Threat actor profiles and attack scenarios should be updated when credible evidence changes the assessment. Avoid attributing incidents to a named actor without reliable supporting evidence.

## 9. Recommended priorities

The following priorities focus on validating the prototype's actual security properties:

1. **Cryptographic integration:** Verify the signed byte sequence, AEAD parameters, key derivation, and authentication-failure behaviour.
2. **Identity and session isolation:** Test key-to-identity binding and cross-session or cross-team access.
3. **Replay and freshness:** Confirm which checks run in the active relay and validator paths, including configuration defaults.
4. **Parser robustness:** Test malformed packets, unexpected types, oversized inputs, and failure handling.
5. **Key lifecycle:** Establish actual storage, replacement, expiry, revocation, and cleanup behaviour.
6. **Audit reliability:** Document persistence and integrity limitations; test how evidence can be lost or altered.
7. **Dependency security:** Inventory the actual environment and validate relevant advisories against installed versions.
8. **Configuration integrity:** Test whether unauthorized threshold or policy changes can affect decisions.
9. **Availability:** Measure behaviour under sustained traffic and resource-exhaustion scenarios.
10. **Privacy:** Verify whether telemetry values appear in logs, exported files, exceptions, or other unintended destinations.

Record findings with reproducible test cases and distinguish implemented controls from planned improvements.

## 10. Related documents

- `docs/THREAT_MODEL.md` — STRIDE-based threat analysis.
- `docs/MITRE_ATTACK_MAPPING.md` — Mapping of project scenarios to ATT&CK techniques.
- `docs/INCIDENT_RESPONSE.md` — Prototype incident-response plan.
- `docs/CRYPTOGRAPHIC_PRIMITIVES.md` — Cryptographic primitives and limitations.
- `docs/KEY_MANAGEMENT.md` — Key lifecycle and management requirements.
- `docs/FIA_DATA_PRIVACY_MODEL.md` — Data classification, privacy objectives, and limitations.
- `docs/AUDIT_TRAIL.md` — Audit event structure and logging limitations.
- `docs/NETWORK_TOPOLOGY.md` — Logical architecture and proposed deployment topology.
- `docs/CLOUD_HARDENING.md` — Include only if this document exists and describes a relevant deployment.

## 11. Maintenance

Review this document when:

- Cryptographic or protocol code changes.
- New network-facing services are introduced.
- Dependencies or deployment environments change.
- New test results alter the risk assessment.
- A credible vulnerability affects a component actually used by the project.
- An incident or review identifies a new attack path.

Threat intelligence should guide testing and prioritisation, not substitute for evidence. Claims about mitigations should be upgraded from proposed to verified only when supported by the relevant implementation, configuration, and reproducible test results.
