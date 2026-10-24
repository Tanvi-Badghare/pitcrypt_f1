# Audit Trail and Security Event Logging

**Project:** PitCrypt-F1  
**Document:** `docs/AUDIT_TRAIL.md`  
**Version:** 1.1  
**Status:** Implementation-oriented specification  
**Last reviewed:** 25 October 2026

---

## 1. Purpose

This document describes the audit trail used by PitCrypt-F1, a prototype for protecting and validating motorsport telemetry.

It defines the intended purpose of security-event logging, the known event fields, useful event categories, storage limitations, and verification requirements.

The audit trail supports debugging, security testing, event reconstruction, and analysis of simulated attacks. It is not, by itself, proof that telemetry came from a particular physical car or that an event record has remained unaltered.

The document distinguishes the logger's known implementation model from behaviours that still require source-code inspection or testing.

## 2. Scope

The logical pipeline consists of three components:

1. **Producer:** Constructs telemetry packets and applies cryptographic protection.
2. **Relay:** Parses and processes incoming packets, performs applicable checks, and forwards telemetry.
3. **Validator:** Performs applicable authenticity, metadata, sequence, and commitment checks before making a decision.

The project also contains IAM/RBAC and forensic-analysis components. Their audit coverage and integration must be assessed separately.

This document does not assume that every component emits every event type, that logs are centrally collected, or that the system is deployed on a real trackside network.

## 3. Audit objectives

The audit trail should support:

- **Accountability:** Record security-relevant decisions.
- **Traceability:** Associate events with available packet, node, team, and session metadata.
- **Diagnostics:** Preserve useful rejection reasons and error context.
- **Consistency:** Use a predictable structure suitable for parsing and analysis.
- **Data minimisation:** Avoid unnecessary payload content, secrets, and sensitive information.
- **Integrity awareness:** Distinguish ordinary application logs from independently protected evidence.
- **Testability:** Make it possible to check whether expected events are emitted on success and failure paths.

These are design objectives. Their implementation status depends on the current source code and execution paths.

## 4. Current implementation model

The described `AuditLogger` provides:

- A thread-safe in-memory event collection.
- Optional JSON Lines (JSONL) output.
- Structured fields including `timestamp`, `decision`, `sequence_no`, `node_id`, `team`, `session`, `reason`, and `details`.

The exact field types, serialization, timestamp format, write ordering, persistence behaviour, and error handling must be confirmed against the source code currently under review.

### 4.1 In-memory mode

In-memory records are generally lost when the process exits or its state is reset. They may also be lost following a crash or unexpected termination.

A thread-safe collection does not automatically guarantee durable storage, global event ordering, or complete audit coverage.

### 4.2 JSONL mode

JSON Lines stores one serialized JSON object per line. It is useful for local inspection, streaming, and downstream analysis.

Ordinary JSONL output does not inherently provide:

- Cryptographic tamper evidence.
- Protection against deletion, truncation, or reordering.
- Protection against modification by a user with sufficient filesystem privileges.
- Guaranteed durability after a crash.
- A trusted or synchronized timestamp.
- Centralized collection or independent backup.
- Proof that every relevant event was successfully written.

Unless additional protections have been implemented and verified, describe the logger as a **structured application audit logger with optional JSONL persistence**.

## 5. Event schema

The following fields are known from the described implementation model. Their required/optional status, types, defaults, and exact serialization remain subject to source verification.

| Field | Intended meaning | Considerations |
|---|---|---|
| `timestamp` | Time associated with an event | Document the clock source, timezone, and precision. Do not assume the host clock is trusted. |
| `decision` | Outcome or action | Confirm actual values and distinguish validation decisions from operational events. |
| `sequence_no` | Associated packet sequence number | May be unavailable if parsing fails before sequence extraction. |
| `node_id` | Logical node or component | Use consistent identifiers where the implementation supports them. |
| `team` | Team context associated with telemetry | Contextual metadata, not independent proof of identity. |
| `session` | Associated session context | Define the field consistently across components. |
| `reason` | Explanation of a decision | Prefer stable reason codes where practical. |
| `details` | Additional diagnostic context | Minimise sensitive data and avoid secrets or unnecessary payload content. |

### 5.1 Illustrative event

The following is a documentation example, not a captured production event or a guarantee of the logger's exact output.

```json
{
  "timestamp": "2026-10-25T12:00:00Z",
  "decision": "rejected",
  "sequence_no": 42,
  "node_id": "validator",
  "team": "example_team",
  "session": "example_session",
  "reason": "signature_invalid",
  "details": {
    "component": "signature_verifier"
  }
}
```

All values are illustrative. Real events may omit fields that cannot be safely or reliably extracted.

### 5.2 Schema evolution

When the event structure changes:

1. Update this document and dependent parsers.
2. Add or update tests for changed fields.
3. Preserve compatibility where practical.
4. Document renamed or removed fields.
5. Avoid silently changing an existing field's meaning.

A schema-version field may be useful if multiple versions must coexist. Do not claim it exists until it has been implemented.

## 6. Event categories

The categories below describe useful audit coverage. They are not a claim that every event is currently emitted.

### 6.1 Packet acceptance

Record a successful validation decision at the appropriate acceptance point.

Useful context may include the available sequence number, validating node, team and session metadata, and relevant validation outcome.

An acceptance event should not be emitted before all checks required by the implemented acceptance policy have completed.

### 6.2 Packet rejection

Record rejected packets with a reason that identifies the failed check where possible.

Potential reason codes include:

- `signature_invalid`
- `metadata_invalid`
- `sequence_invalid`
- `replay_detected`
- `commitment_invalid`
- `decryption_failed`
- `malformed_packet`

These are suggested examples, not a definitive list of implemented reason strings. Extract the actual values from source code and normalise them before treating them as a stable interface.

### 6.3 Cryptographic validation failures

Where supported, record failures involving signature verification, authenticated decryption, or commitment verification.

Do not log private keys, session keys, authentication secrets, or unnecessary sensitive payload data.

A cryptographic failure should be distinguishable from an internal software exception. An exception does not automatically prove malicious activity.

### 6.4 Sequence and replay events

Record sequence violations and replay-related rejections when the applicable checker detects them.

Where possible, distinguish:

- A repeated sequence number.
- An unexpected sequence transition.
- A malformed or missing sequence field.
- An out-of-order packet, if the protocol supports out-of-order delivery.

Timestamp freshness checks must not be described as active unless the effective configuration and test results establish that they are enabled.

### 6.5 Access-control decisions

Where IAM/RBAC integration emits audit events, record relevant authorisation decisions, including denied operations and applicable resource or action information when safe.

Verify:

- Whether access-control events reach the audit logger.
- Whether denied requests are logged consistently.
- Whether identity and role information is recorded without exposing credentials.
- Whether authorisation failures can be distinguished from internal errors.

The existence of `IdentityStore`, `PolicyLoader`, `RBACEngine`, or `AccessAuditor` does not by itself establish complete audit integration.

### 6.6 Key-management events

Key creation, rotation, revocation, expiration, and failures are useful audit events if those operations are implemented.

Do not claim comprehensive lifecycle logging until the relevant operations and event paths have been tested. Key material must never be included in event details.

### 6.7 Operational and simulation events

Controlled tests may record:

- Simulation start and completion.
- Attack-scenario identifiers.
- Test-run identifiers.
- Packet-loss or jitter parameters.
- Aggregate outcomes and error counts.

Keep test-generated events distinguishable from normal pipeline events. Simulated attack results must not be presented as real-world incidents.

## 7. Event lifecycle and ordering

The logical validator flow includes packet processing, cryptographic verification, metadata validation, sequence/replay checks, commitment verification, and a final decision.

The intended audit behaviour is to capture safely available context, record relevant failures, avoid reporting a rejected packet as accepted, and record acceptance only after the required checks succeed.

The exact event ordering must follow the implementation rather than this conceptual sequence.

### 7.1 Signature failure and sequence state

The project notes report a regression test in which an invalid-signature packet is rejected and a legitimate original packet can subsequently be accepted. This is evidence for that particular scenario if the test still passes against the current revision.

It does not prove that every failure path leaves all state unchanged. Sequence advancement, replay-state updates, and event emission should be tested across other rejection paths.

### 7.2 Logging failures

Verify what happens when an audit write fails:

- Does packet processing continue if JSONL output fails?
- Is the in-memory event retained if persistence fails?
- Are logging errors surfaced?
- Can the system distinguish rejection of a packet from failure to record the rejection?

For a security-sensitive deployment, loss of audit capability may require fail-closed behaviour or a documented degraded mode. The appropriate policy depends on system requirements and must not be assumed for this prototype.

## 8. Integrity, authenticity, and trust limitations

Structured records are not inherently immutable or independently trustworthy.

An attacker or faulty process with sufficient access may modify, delete, truncate, reorder, or suppress records. An application timestamp may also be inaccurate if the host clock is incorrect or manipulated.

Potential enhancements include:

- Restricting read and write permissions.
- Separating log-writer privileges from ordinary application users.
- Exporting events to independently administered storage.
- Applying authenticated integrity protection to batches of records.
- Using sequence numbers or hash chains to detect some forms of alteration.
- Signing or externally anchoring periodic log digests.
- Monitoring gaps, unexpected restarts, and failures to emit events.
- Defining retention, backup, and recovery procedures.

These mechanisms provide different guarantees. A local hash chain without a trusted external checkpoint may still be replaced and recomputed by an attacker able to rewrite the entire log. Any integrity mechanism should document its threat assumptions.

## 9. Confidentiality and data minimisation

Audit records can reveal operational details and sensitive telemetry context.

The implementation and operating procedures should:

- Avoid logging cryptographic secrets or key material.
- Avoid recording full telemetry payloads unless required for a documented test.
- Avoid unnecessary personal information.
- Restrict access to logs and diagnostic exports.
- Sanitize externally supplied strings before displaying them in dashboards or reports.
- Prevent untrusted input from creating misleading downstream log entries.
- Review whether team, session, and packet metadata are necessary for each event type.

Redaction should preserve sufficient context for the audit purpose and must not silently remove evidence required to interpret a security decision.

## 10. Retention, access, and export

A formal retention policy is not established by the logger alone.

Before using the audit trail beyond local development, define:

- Which events are retained.
- Where in-memory and persistent records are stored.
- Who may read, export, or delete records.
- Retention periods and deletion procedures.
- Backup and recovery arrangements.
- How exported logs are authenticated and associated with a test run.
- How access to the logging system itself is audited.

An exported JSONL file must not be represented as complete, immutable, or independently authenticated unless additional controls establish those properties.

No specific FIA-mandated retention period is asserted by this document.

## 11. Testing and verification

Project notes previously reported a full-suite result of **438 passed** at a particular checkpoint. This is a historical result, not proof that the current working tree has been tested unchanged or that all requirements in this document are satisfied. Re-run the suite and record the relevant commit before using that count as current evidence.

### 11.1 Event correctness

- [ ] Successful validation produces the expected acceptance record.
- [ ] Signature failure produces the expected rejection record.
- [ ] Metadata and sequence failures are distinguishable.
- [ ] Replay rejection is recorded when detected by the checker.
- [ ] Commitment failure is distinguishable from other failures.
- [ ] Missing or malformed fields do not produce misleading acceptance records.

### 11.2 State and ordering

- [ ] A rejected packet is not also reported as accepted for the same decision.
- [ ] Invalid-signature rejection does not advance sequence state if that is the intended protocol behaviour.
- [ ] Concurrent events remain structurally valid.
- [ ] Event ordering is interpreted according to the logger's actual concurrency guarantees.
- [ ] Retries and repeated events can be distinguished where necessary.

### 11.3 Persistence and failure handling

- [ ] In-memory mode behaves as documented.
- [ ] JSONL output contains one valid JSON object per line.
- [ ] Write failures are handled predictably.
- [ ] Restart behaviour and data loss are understood.
- [ ] Output paths and file permissions are reviewed.
- [ ] Sensitive values do not appear in logs.

### 11.4 Integrity and access

- [ ] Unauthorised users cannot access logs beyond their permissions.
- [ ] Tampering and truncation limitations are documented.
- [ ] If integrity protection is added, alteration, deletion, reordering, and missing-record scenarios are tested.
- [ ] Audit access and export permissions are tested.
- [ ] Retention and deletion behaviour is verified once implemented.

### 11.5 Reproducibility

For each test used as evidence, retain the test name, command, date, result, and code revision. For manual or simulation-based tests, document the setup, inputs, expected outcome, actual outcome, and limitations.

## 12. Known limitations

1. In-memory storage and optional JSONL output are not inherently immutable.
2. The known field list does not establish a versioned schema or universal required fields.
3. Centralised collection, secure retention, and independently protected storage are not established.
4. Audit coverage across IAM, key management, relay, and producer operations requires verification.
5. Trusted timestamp and clock-synchronisation guarantees are not established.
6. Handling of audit-write failures requires verification.
7. Tests provide evidence only for the scenarios actually exercised.
8. A valid audit record does not independently prove the truth of every field it contains.
9. The active Python SHA-256-based commitment/check is not a zero-knowledge proof.
10. The audit trail does not by itself demonstrate FIA approval, ISO/IEC 27001 conformity, NIST CSF conformity, or production readiness.

## 13. Recommended implementation priorities

### Priority 1 — Document actual behaviour

- Extract event fields and reason codes from the current source.
- Confirm which components call the logger.
- Confirm logging order relative to validation and state updates.
- Add examples taken from controlled test output, with sensitive values removed.

### Priority 2 — Improve consistency

- Standardise event categories and reason codes.
- Define field types and required/optional status.
- Introduce schema versioning if multiple schema versions need to coexist.
- Add a test or run identifier for controlled experiments where useful.

### Priority 3 — Verify persistence and failure handling

- Test JSONL serialisation, write errors, restart behaviour, and concurrent access.
- Document the expected response when audit persistence is unavailable.
- Establish access and retention rules for any shared test environment.

### Priority 4 — Add stronger integrity controls where required

- Define the attacker model and required tamper-evidence guarantees.
- Select and test an integrity mechanism that meets those requirements.
- Consider independently controlled storage or external integrity checkpoints.
- Test alteration, deletion, truncation, reordering, and missing-record scenarios.

## 14. Conclusion

PitCrypt-F1's audit trail is intended to provide structured evidence of telemetry-validation decisions and security-relevant events. Its value depends on event completeness, correct integration, reliable persistence, and careful interpretation.

At the documented implementation level, describe it as a structured application audit logger with optional JSONL persistence. Claims about immutability, tamper evidence, complete forensic preservation, or operational compliance require additional implementation and verification.

## Related documentation

- `docs/ARCHITECTURE_OVERVIEW.md` — Pipeline architecture and component responsibilities.
- `docs/PROTOCOL_SPEC.md` — Protocol validation and rejection behaviour.
- `docs/PACKET_FORMAT.md` — Packet header and telemetry fields.
- `docs/THREAT_MODEL.md` — Adversaries, trust boundaries, and attack scenarios.
- `docs/COMPLIANCE.md` — Preliminary security-framework alignment.
- `docs/FIA_REGULATION_MAPPING.md` — Preliminary regulatory mapping, not an official compliance assessment.