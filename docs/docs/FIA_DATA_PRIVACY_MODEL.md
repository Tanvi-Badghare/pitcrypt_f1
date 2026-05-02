# FIA Data Privacy Model — PitCrypt-F1

**Document:** FIA_DATA_PRIVACY_MODEL.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## Overview

This document specifies how PitCrypt-F1 handles
the privacy of Formula 1 telemetry data in
compliance with FIA regulations and applicable
data protection law.

F1 telemetry occupies a unique privacy space:
it is simultaneously regulated data (FIA has
a right to receive it) and proprietary data
(teams have a legitimate interest in protecting
it from competitors). PitCrypt-F1 resolves
this tension through cryptographic separation
of verification from disclosure.

---

## Data Classification

### Class 1 — Regulated Telemetry (FIA Mandatory)

Data the FIA is legally entitled to receive
under the Technical Regulations:
Speed           ← Required for track limit enforcement
RPM             ← Required for engine homologation checks
Throttle        ← Required for driver aid compliance
Brake           ← Required for driver aid compliance
nGear           ← Required for gearbox compliance
DRS             ← Required for DRS zone compliance
Lap number      ← Required for race distance verification
Session type    ← Required for classification
**Privacy treatment:** Transmitted to FIA validator
in encrypted form. Decrypted only at authoritative
FIA endpoint. Not accessible to relay node in
persistent form — ephemeral during processing only.

### Class 2 — Proprietary Team Data (Protected)

Data teams have a legitimate interest in protecting
from competitors:
Engine mode settings    ← Competitive advantage
Fuel consumption rates  ← Strategy intelligence
Cooling configurations  ← Development data
ERS deployment patterns ← Performance data
Tyre temperature models ← Engineering data
**Privacy treatment:** Not transmitted by
PitCrypt-F1 in v1.0. If added in future versions,
Pedersen commitments allow FIA to verify ranges
without reading values — see ZKP design.

### Class 3 — Audit Metadata (Internal)
Packet sequence numbers
Transmission timestamps
Signature verification results
Anomaly detection flags
IAM access decisions
**Privacy treatment:** Stored in validator audit
log. Accessible to FIA for regulatory review.
Not shared with other teams.

---

## Privacy Architecture

### Principle 1 — Cryptographic Separation

The relay node sits between the car and the FIA
validator. It must process telemetry for integrity
checking but must not retain it. This is enforced
cryptographically and by IAM policy:
Car Node         Relay Node              FIA Validator
│                 │                        │
│  Encrypt A      │                        │
│────────────────►│                        │
│                 │  Decrypt A             │
│                 │  [plaintext exists     │
│                 │   for ~1ms max]        │
│                 │  Encrypt B             │
│                 │────────────────────────►
│                 │                        │ Decrypt B
│                 │  Plaintext DELETED      │ [plaintext
│                 │  from memory            │  exists here
│                 │                        │  permanently]
**IAM enforcement:**
```yaml
# relay_node_policy.yaml
deny:
  - action: "telemetry.store"
    resource: "plaintext_data"
    description: "Cannot store decrypted telemetry"
```

### Principle 2 — Zero-Knowledge Verification

For proprietary data that FIA stewards need to
verify without reading, PitCrypt-F1 implements
ZKP commitments:

**Hash commitment (current):**
```python
commitment = SHA256(payload_bytes + nonce)
```

FIA can verify: "did the payload produce this
commitment?" without reading the payload values.

**Pedersen commitment (production):**
C = rG + mH
FIA can verify range proofs ("speed is within
0-400 km/h") without learning the actual speed
value. This is the privacy-preserving verification
model described in ADR-002.

### Principle 3 — Purpose Limitation

Telemetry data is collected exclusively for
FIA regulatory compliance. The system does not:

- Share telemetry with other constructors
- Retain telemetry beyond the session at relay
- Make telemetry available for commercial use
- Enable cross-session profiling

IAM policy enforces purpose limitation at the
access control layer — no node can access data
beyond its assigned function.

### Principle 4 — Data Minimisation

Only the fields required for FIA compliance
are transmitted. The payload schema is fixed
and does not include free-form fields that could
carry additional data.

Relay anomaly filter operates on decrypted values
but does not log individual packet values —
only aggregate statistics and violation events.

---

## Stakeholder Privacy Rights

### FIA (Regulator)

**Rights:**
- Receive all Class 1 regulated telemetry
- Audit validator decision log
- Investigate suspected regulation violations
- Export audit log for post-race review

**Limits:**
- Cannot access Class 2 proprietary data
  (enforced by not transmitting it)
- Cannot share telemetry with competitors
- Must retain audit logs per FIA data retention
  policy

### Constructor Teams

**Rights:**
- Know what data is transmitted to FIA
- Receive confirmation of accepted/rejected packets
- Challenge FIA audit decisions with evidence
  from car-side logs
- Request deletion of historical data after
  regulatory period expires

**Limits:**
- Cannot access competitor telemetry
  (enforced by separate ECDH sessions + IAM)
- Cannot modify audit log
- Cannot decrypt validator-stored data

### Relay Operator

**Rights:**
- Process telemetry in transit
- Run anomaly detection on values during processing
- Log processing events (not values)

**Limits:**
- Cannot retain decrypted telemetry
- Cannot read audit log
- Cannot share data with third parties
- Plaintext access window bounded to processing duration

---

## GDPR Considerations

While telemetry data is primarily technical and
not directly identifying, driver performance data
may constitute personal data under GDPR Article 4(1)
when linked to a named driver.

### Legal Basis

Processing of F1 telemetry data relies on:

**Article 6(1)(c) — Legal obligation:**
FIA Technical Regulations create a legal obligation
for teams to transmit telemetry to the FIA.

**Article 6(1)(f) — Legitimate interests:**
Teams have a legitimate interest in protecting
proprietary telemetry from competitors —
justifying the encryption and access control model.

### Data Subject Rights

**Article 17 — Right to erasure:**
Telemetry data is not erasable during the
regulatory retention period (minimum 12 months
post-season for FIA audit purposes). After
retention period, data may be deleted on request.

**Article 20 — Data portability:**
Teams may request export of their own telemetry
data in machine-readable format (JSON/CSV).

**Article 25 — Data protection by design:**
PitCrypt-F1 implements privacy by design:
encryption by default, data minimisation,
purpose limitation, and access controls
aligned with GDPR Article 25 requirements.

---

## Data Retention Policy

| Data Type | Retention Period | Storage | Deletion |
|---|---|---|---|
| Encrypted telemetry (relay) | Session duration only | Memory | On rotation/exit |
| Decrypted telemetry (relay) | Processing window (~1ms) | Memory | Immediate |
| Validator audit log | 12 months minimum | S3 + local JSONL | Secure deletion |
| IAM access log | 12 months minimum | S3 | Secure deletion |
| Ed25519 public keys | Duration of registration | Validator registry | On deregistration |
| ECDH session keys | Per rotation window | Memory only | On rotation |

---

## Privacy Impact Assessment Summary

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Relay retains plaintext | Low | High | IAM deny + ephemeral design |
| Competitor intercepts telemetry | Medium | High | ChaCha20 encryption |
| FIA shares data with competitors | Low | High | Contractual + no-access-by-design |
| Audit log leaks timing data | Low | Medium | Log minimisation |
| ZKP commitment brute-forced | Medium (hash) / Low (Pedersen) | Medium | Pedersen in production |

---

## See Also

- `docs/FIA_REGULATION_MAPPING.md` — Regulatory compliance
- `docs/KEY_MANAGEMENT.md` — Key lifecycle and retention
- `architecture/adr/002-zkp-commitments.md` — ZKP privacy
- `iam-module/policies/relay_node_policy.yaml` — Retention enforcement