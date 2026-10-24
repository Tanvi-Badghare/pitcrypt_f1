# Incident Response Plan — PitCrypt-F1

**Document:** `INCIDENT_RESPONSE.md`  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Classification:** Security Operations  
**Status:** Prototype incident-response plan  
**Last reviewed:** 24 October 2026

---

## 1. Purpose

This document defines a repeatable process for identifying, containing, investigating, recovering from, and learning from security incidents involving PitCrypt-F1.

The plan covers the logical telemetry pipeline:

**Car Producer → Relay Node → Validator**

It addresses cryptographic failures, suspicious telemetry, replay attempts, compromised keys, unauthorised access, audit-record tampering, denial of service, and security configuration errors.

PitCrypt-F1 is a prototype. This document specifies recommended response procedures; it does not claim that a staffed security operations centre, production incident-management platform, cloud logging service, hardware security module, or live FIA response process is deployed.

## 2. Scope and Objectives

The incident-response process aims to:

1. Protect the confidentiality and integrity of telemetry.
2. Prevent continued unauthorised access or malicious packet processing.
3. Preserve available evidence for investigation.
4. Determine the scope and likely cause of an incident.
5. Restore service using verified configurations and keys.
6. Record findings and implement corrective actions.

### 2.1 In-scope incidents

- Suspected producer, relay, or validator identity compromise.
- Cryptographic authentication or signature failures.
- Packet replay, sequence anomalies, or suspicious timestamp behaviour.
- Unauthorised telemetry access or disclosure.
- Suspicious payload or packet-header modification.
- Audit-record alteration or unexplained gaps.
- Denial-of-service or resource exhaustion.
- Access-control bypass or cross-team data exposure.
- Compromised dependencies, altered configuration, or unauthorised code changes.
- Unexpected key rotation, session failures, or cryptographic configuration errors.

### 2.2 Out of scope

This document is not a substitute for:

- A real-world FIA incident reporting procedure.
- A team's operational race-control or safety procedures.
- A legal or regulatory breach-notification assessment.
- A production disaster-recovery plan.
- A formal digital-forensics chain-of-custody policy.

If the prototype is later connected to real operational systems, those procedures must be established with the relevant organisations before deployment.

---

## 3. Incident Roles and Responsibilities

Roles may be assigned to the same person in a small project. Responsibilities should nevertheless remain explicit.

| Role | Responsibility |
|---|---|
| Incident coordinator | Declares the incident, coordinates response, tracks decisions, and approves closure |
| Technical investigator | Examines packet processing, cryptographic failures, logs, tests, and code changes |
| Key custodian | Coordinates key disablement, revocation, replacement, and secure provisioning |
| System operator | Isolates affected processes, preserves system state, and restores service |
| Evidence custodian | Records evidence sources, hashes, collection times, and access history |
| Stakeholder liaison | Communicates verified impact and escalation needs to affected stakeholders |

**Prototype note:** These are assigned responsibilities, not evidence of existing staffed roles or automated operational processes.

## 4. Incident Severity

Use the highest applicable severity. Reassess it as new evidence becomes available.

| Severity | Description | Examples | Initial response target |
|---|---|---|---|
| SEV-1 — Critical | Confirmed or strongly suspected compromise of a trusted identity, key, or critical decision path | Producer signing-key compromise; widespread telemetry manipulation; validator compromise affecting decisions | Immediate triage and containment |
| SEV-2 — High | Significant integrity, confidentiality, or availability risk affecting a pipeline component or team | Confirmed cross-team data exposure; persistent replay acceptance; major audit integrity failure | Prompt investigation and containment |
| SEV-3 — Moderate | Limited suspicious activity or a contained failure without confirmed broad impact | Repeated invalid signatures; isolated anomalous packets; configuration drift | Investigate and remediate promptly |
| SEV-4 — Low | Informational or low-impact event requiring tracking | A single malformed packet rejected as expected; non-reproducible alert with no supporting evidence | Record, review, and close when justified |

These are proposed internal response targets, not externally guaranteed service levels. A production deployment should define explicit on-call coverage and time-based escalation requirements.

### 4.1 Security event versus incident

A rejected invalid packet is not automatically a security incident. Classify events based on context, volume, repetition, impact, and evidence.

Examples:

- One invalid signature that is rejected as expected: potentially a routine security event.
- A sudden increase in invalid signatures from an unknown source: potentially an incident.
- A verified producer key used by an unauthorised party: a security incident.
- An audit file that cannot be verified after suspected host compromise: a potential evidence-integrity incident.

---

## 5. Incident-Response Lifecycle

### Phase 1 — Detection and reporting

Potential sources include:

- Relay parsing, decryption, integrity, and anomaly results.
- Validator signature, sequence, commitment, and decision outcomes.
- Audit records and application errors.
- Unexpected changes in packet volume, latency, rejection rate, or memory usage.
- IAM/RBAC denials and access-policy changes.
- Reports from developers, operators, or affected stakeholders.

For each suspected incident, record:

- Incident identifier.
- Detection time and timezone.
- Reporter or detection source.
- Affected component and execution mode.
- Relevant packet sequence numbers and session identifiers, where available.
- Observed symptoms and exact error messages.
- Initial severity and rationale.

Do not place private keys, session keys, credentials, or unnecessary sensitive telemetry in the incident report.

### Phase 2 — Triage

1. Confirm that the event is reproducible or supported by available evidence.
2. Identify affected nodes, sessions, teams, packet sequences, and software versions.
3. Determine whether the incident affects confidentiality, integrity, availability, or evidence reliability.
4. Check whether the behaviour is explained by configuration, malformed input, a software defect, or suspected hostile activity.
5. Assign severity and an incident coordinator.
6. Decide whether processing should be paused, isolated, or restricted.

Avoid treating an alert as proof of malicious intent until evidence supports that conclusion.

### Phase 3 — Containment

Choose the least disruptive action that adequately limits harm.

Possible actions include:

- Isolating an affected process or test environment.
- Rejecting traffic from a confirmed malicious source.
- Disabling an affected identity or key through an established and verified mechanism.
- Pausing forwarding if telemetry integrity cannot be trusted.
- Restricting access to affected logs, configuration, and secrets.
- Disabling a vulnerable integration or reverting a confirmed bad configuration.
- Preserving a copy of relevant state before restarting or rebuilding a component, when safe and practical.

**Safety rule:** Do not silently accept unverified telemetry as trustworthy merely to maintain availability. If the prototype is ever connected to a real operational environment, service-continuity decisions must be coordinated with the responsible operational authority.

### Phase 4 — Evidence preservation

Preserve evidence before making changes that could destroy useful state, unless immediate containment is necessary to prevent ongoing harm.

Collect, as applicable:

- Relevant application logs and audit output.
- Original packet envelopes and associated headers.
- Sequence numbers, timestamps, session identifiers, and decision reasons.
- Configuration files and configuration hashes.
- Relevant source commit, build identifier, dependency versions, and test results.
- Process and system observations, if available.
- Details of containment actions and their timestamps.

For each collected item, record:

| Field | Description |
|---|---|
| Evidence ID | Unique identifier |
| Source | Component, file, process, or system |
| Collector | Person or process collecting the evidence |
| Collection time | Timestamp with timezone |
| Integrity hash | Cryptographic hash of the collected copy, where appropriate |
| Storage location | Restricted evidence location |
| Access history | Subsequent access or transfer, where tracked |
| Notes | Collection method, limitations, and relevant context |

A hash can help detect later changes to a collected file; it does not prove that the original file was truthful before collection.

Do not alter original evidence when analysing it. Work from a verified copy wherever possible.

### Phase 5 — Investigation and root-cause analysis

Investigators should establish:

1. What happened and when?
2. Which component and execution path were involved?
3. Which assets, identities, sessions, and telemetry records were affected?
4. Was the event caused by hostile activity, software failure, configuration error, or an unknown cause?
5. Which controls operated as expected?
6. Which controls failed, were bypassed, or were not active?
7. Is there evidence of persistence, repeated access, or additional compromise?
8. What evidence supports the findings, and what remains uncertain?

Use controlled reproduction tests when possible. Do not run attack simulations against production systems without authorisation.

### Phase 6 — Eradication and recovery

Recovery actions may include:

- Removing malicious code or unauthorised configuration changes.
- Rebuilding an affected component from a trusted source.
- Revoking and replacing compromised keys.
- Re-establishing sessions using verified peer identities.
- Restoring configuration from a reviewed version.
- Fixing the relevant validation, authorisation, or resource-control defect.
- Running regression and security tests.
- Confirming that audit collection is functioning before restoring normal operation.

Do not declare recovery complete merely because the process starts successfully. Confirm the security properties relevant to the incident.

### Phase 7 — Closure and lessons learned

Before closure:

- Document the root cause or clearly state that it remains unknown.
- Record confirmed impact and any uncertainty.
- List containment, eradication, and recovery actions.
- Link test results, code changes, and evidence records.
- Assign owners and due dates to corrective actions.
- Update the threat model and relevant protocol documentation.
- Identify any stakeholder or legal reporting requirements.

For significant incidents, conduct a blameless review focused on improving system design, observability, and response procedures.

---

## 6. Incident-Specific Playbooks

### 6.1 Suspected producer signing-key compromise

**Trigger:** Evidence suggests that a producer's Ed25519 private key has been accessed or used without authorisation.

**Immediate actions:**

1. Declare at least SEV-1 if unauthorised signing is credible.
2. Preserve relevant signed packets, verification results, and key-use records.
3. Identify the affected key identifier, producer identity, and time interval.
4. Disable or revoke the affected key through the configured trust mechanism, if available.
5. Prevent the compromised identity from being treated as trustworthy until its status is resolved.
6. Determine which packets were signed during the suspected compromise window.
7. Generate and provision a replacement key using the approved key-management procedure.
8. Update trusted public-key mappings and test verification with the replacement key.
9. Document how historical packets signed by the compromised key will be evaluated.

**Do not assume:** AWS KMS/HSM, automated revocation, or a production key registry is available in the current prototype.

**Recovery criterion:** The compromised key is no longer trusted for new processing, the replacement identity is correctly provisioned, and affected telemetry has been assessed.

### 6.2 Suspected session-key exposure or peer impersonation

**Trigger:** A session key may have been exposed, or a car, relay, or validator may have communicated with an unauthorised peer.

**Immediate actions:**

1. Identify the affected pipeline leg and session.
2. Preserve handshake messages, key identifiers, endpoint information, and relevant packet captures, where available.
3. Restrict or terminate the affected session using a verified mechanism.
4. Validate the identities and public keys of both endpoints.
5. Investigate whether the handshake was authenticated and whether traffic could have been intercepted.
6. Establish a replacement session only after the peer's identity and key provisioning are trusted.
7. Test that old or unauthorised session material cannot be used to process new packets.

**Recovery criterion:** The affected session is no longer trusted, peer identity has been verified, and a new session is established through a tested process.

### 6.3 Tampered telemetry or signature-verification failure

**Trigger:** A packet fails AEAD authentication, a signature check fails, or evidence indicates a payload was modified.

**Immediate actions:**

1. Preserve the original envelope, header, ciphertext, signature, and relevant decoded metadata.
2. Record the component and stage at which the failure occurred.
3. Check whether the failure is isolated or repeated across the same identity or session.
4. Do not manually modify a failed packet to make it pass validation.
5. Determine whether the cause is packet corruption, a malformed envelope, inconsistent associated data, a software defect, or suspected malicious modification.
6. Test a known-good packet and a deliberately modified test packet in a controlled environment.
7. If the original producer signature fails after relay processing, investigate whether signed content was changed or reconstructed inconsistently.
8. Review the handling of related packets before and after the affected sequence.

**Recovery criterion:** The failure is understood or contained, verification behaviour is tested, and no affected packet is accepted without the required checks.

### 6.4 Replay or sequence anomaly

**Trigger:** Duplicate sequence numbers, suspiciously old timestamps, unexpected sequence gaps, or repeated packets are detected.

**Immediate actions:**

1. Preserve the packet, session identifier, sequence number, timestamp, and relevant checker state.
2. Check the effective timestamp and sequence configuration for the execution mode.
3. Determine whether the packet is a duplicate, out-of-order legitimate packet, stale packet, or suspected replay.
4. Review whether rejected packets changed replay state.
5. Check for repeated attempts or an unusual volume of sequence failures.
6. Avoid resetting sequence state without recording the action and understanding its effect.
7. Reproduce the behaviour using controlled duplicate, stale, and out-of-order test packets.

**Recovery criterion:** Replay behaviour matches the documented policy, relevant configuration is confirmed, and any state inconsistency has been corrected.

### 6.5 Suspected telemetry disclosure

**Trigger:** Evidence indicates that an unauthorised party may have accessed plaintext telemetry, packet captures, logs, or session secrets.

**Immediate actions:**

1. Identify the disclosed data, recipients, time interval, and affected teams.
2. Restrict further access to the affected files, endpoints, or sessions.
3. Determine whether the exposure involved ciphertext, visible metadata, plaintext, or cryptographic keys.
4. Preserve access logs, packet captures, and relevant system state.
5. Rotate or revoke exposed secrets where necessary and supported.
6. Review whether the relay, endpoint, or logging system retained plaintext unnecessarily.
7. Escalate to affected stakeholders and follow applicable reporting obligations if real data is involved.

**Recovery criterion:** The disclosure path is contained, exposed credentials or keys have been addressed, and the scope of known and potential exposure is documented.

### 6.6 Denial of service or resource exhaustion

**Trigger:** Abnormal packet volume, connection churn, memory growth, CPU saturation, excessive processing latency, or a sustained increase in rejection rates.

**Immediate actions:**

1. Capture resource metrics, timestamps, request volume, and error rates.
2. Determine whether the issue is malformed traffic, legitimate load, a software defect, or suspected deliberate flooding.
3. Apply available rate limits, connection limits, input-size restrictions, or network controls.
4. Preserve a representative sample of rejected inputs without collecting unnecessary sensitive data.
5. Avoid logging every repeated failure if doing so would further exhaust resources.
6. Test the suspected issue in an isolated environment.
7. Verify that recovery does not bypass authentication or integrity checks.

**Recovery criterion:** Resource usage returns to an acceptable level, legitimate processing works, and the underlying cause is addressed or appropriately mitigated.

### 6.7 Audit-record integrity failure

**Trigger:** Audit records are missing, unexpectedly altered, inconsistent with application behaviour, or unavailable after a suspected compromise.

**Immediate actions:**

1. Preserve the affected audit files and their current hashes.
2. Record the location, collection time, file metadata, and known access history.
3. Restrict write access to the affected records.
4. Compare available records with other evidence sources, such as packet captures and application outputs.
5. Determine whether the failure arose from ordinary logging loss, a software defect, storage failure, or possible tampering.
6. Do not reconstruct missing events as though they were original records.
7. Document gaps and uncertainty explicitly.

**Recovery criterion:** A trustworthy logging path has been restored, evidence gaps are recorded, and the required integrity protections are tested.

### 6.8 IAM/RBAC bypass or cross-team access

**Trigger:** An identity performs an unauthorised operation or accesses telemetry belonging to another team.

**Immediate actions:**

1. Restrict the affected identity and access path.
2. Preserve the identity, requested action, target resource, policy version, and decision result.
3. Determine whether the policy engine was invoked and whether its decision was enforced.
4. Check for additional unauthorised operations.
5. Correct the policy or enforcement point and test both allowed and denied actions.
6. Review whether data was copied or disclosed before containment.

**Recovery criterion:** Unauthorised access is blocked, the affected data and actions have been assessed, and negative authorisation tests pass.

### 6.9 Compromised dependency or configuration

**Trigger:** An unexpected dependency change, unauthorised source modification, suspicious build artefact, or security-sensitive configuration change is detected.

**Immediate actions:**

1. Identify the affected commit, package, configuration, and build.
2. Preserve the relevant source, dependency lock files, build outputs, and configuration.
3. Restrict deployment of the affected artefact.
4. Compare against a known trusted version.
5. Rebuild from reviewed source with verified dependencies.
6. Run the relevant regression and security tests.
7. Review access to source control, package registries, build credentials, and deployment credentials.

**Recovery criterion:** The affected artefact or configuration has been replaced with a verified version and the relevant security tests pass.

---

## 7. Evidence Handling and Retention

Evidence should be stored with access limited to authorised investigators.

Recommended practices:

- Preserve original files and create working copies for analysis.
- Calculate hashes for collected evidence where appropriate.
- Record timestamps with timezone information.
- Keep an evidence register and document transfers.
- Avoid exposing private keys, passwords, or session secrets in reports.
- Retain evidence according to an approved retention policy.
- Record when evidence is unavailable, incomplete, or potentially altered.

The prototype's in-memory and JSONL audit mechanisms do not, by themselves, provide a complete evidence-preservation system. Independent storage, access control, and integrity verification are production requirements where forensic reliability matters.

---

## 8. Communications and Escalation

Communications should distinguish verified facts from hypotheses.

Incident updates should include:

- Severity and current status.
- Affected components and known impact.
- Actions taken and actions pending.
- Whether telemetry integrity or confidentiality can be trusted.
- Known evidence gaps and uncertainties.
- The next decision or escalation required.

Do not disclose cryptographic secrets, unnecessary telemetry, or unverified accusations in incident communications.

If real motorsport team data, personal data, or operational systems are involved, notify the appropriate system owner and obtain legal, contractual, and regulatory advice where necessary. Do not assume that this prototype's documentation defines FIA notification requirements.

---

## 9. Post-Incident Review

For SEV-1 and SEV-2 incidents, conduct a structured review. For lower-severity incidents, record findings proportionately.

The review should document:

1. Incident summary and timeline.
2. Root cause, or why the cause remains unknown.
3. Impact and affected assets.
4. Detection and containment effectiveness.
5. Controls that worked as expected.
6. Controls that failed or were absent.
7. Evidence quality and investigation limitations.
8. Corrective and preventive actions.
9. Action owners and target dates.
10. Updates required to the threat model, protocol specification, tests, and operational documentation.

Corrective actions should be tracked to completion rather than left only in the incident report.

---

## 10. Incident Record Template

Use the following template for each incident.

### Incident metadata

- **Incident ID:**
- **Date/time detected:**
- **Reported by / detection source:**
- **Severity:**
- **Incident coordinator:**
- **Affected component(s):**
- **Affected execution mode:** Local simulation / networked test / production, if applicable
- **Status:** Open / Contained / Recovering / Closed

### Summary

- **Observed behaviour:**
- **Potential security impact:**
- **Confirmed impact:**
- **Affected identities, sessions, or sequences:**
- **Initial hypothesis:**

### Timeline

| Time and timezone | Event or action | Person/process | Evidence reference |
|---|---|---|---|
| | | | |

### Investigation

- **Root cause or current hypothesis:**
- **Evidence collected:**
- **Evidence integrity checks:**
- **Tests performed and results:**
- **Unresolved questions:**

### Response

- **Containment actions:**
- **Eradication actions:**
- **Recovery actions:**
- **Communications and escalation:**

### Closure

- **Final impact assessment:**
- **Root cause status:** Confirmed / Probable / Unknown
- **Corrective actions and owners:**
- **Documentation updated:**
- **Closure approved by:**
- **Closure date:**

---

## 11. Testing the Response Plan

The response plan should be exercised in a controlled environment before being relied on operationally.

Recommended tabletop or simulation exercises:

- Producer signing-key compromise.
- Invalid AEAD tag and modified payload.
- Replay of a previously accepted packet.
- Sustained malformed-packet flood.
- Attempted cross-team access.
- Audit-file alteration.
- Incorrect session or timestamp configuration.

For each exercise, record the scenario, expected action, observed result, time to contain, evidence preserved, and improvement actions.

Never execute disruptive tests against a real operational environment without explicit authorisation and an approved safety plan.

---

## 12. Review and Maintenance

Review this plan whenever there is a material change to:

- The producer, relay, or validator architecture.
- Key provisioning, rotation, or revocation.
- Packet verification and replay controls.
- Audit logging or evidence storage.
- IAM/RBAC policy enforcement.
- Network deployment and external integrations.
- Incident ownership or escalation requirements.

The document owner should record the date, reviewed version, changes made, and unresolved operational dependencies.

---

## 13. Related Documents

- `docs/THREAT_MODEL.md` — Threat identification and residual risks.
- `docs/PROTOCOL_SPEC.md` — Packet and session-processing behaviour.
- `docs/PACKET_FORMAT.md` — Packet structure and envelope fields.
- `docs/NETWORK_TOPOLOGY.md` — Network and deployment assumptions.
- `docs/AUDIT_TRAIL.md` — Audit events and storage limitations.
- `docs/FORENSIC_ANALYSIS.md` — Investigation and forensic methods.
- `docs/THREAT_INTELLIGENCE.md` — Threat intelligence context.
- `docs/MITRE_ATTACK_MAPPING.md` — ATT&CK technique mapping.

**Document status:** This is a prototype incident-response plan. Operational procedures, staffing, production integrations, external reporting requirements, and evidence-retention controls must be validated before real-world deployment.
