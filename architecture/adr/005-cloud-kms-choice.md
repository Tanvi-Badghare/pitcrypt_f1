# ADR 005 — Key Management: External KMS vs Self-Managed

**Status:** Accepted  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review

---

## Context

PitCrypt-F1 generates and uses several categories
of cryptographic key material:

1. **Ed25519 identity keypairs** — long-lived car
   node signing keys. Compromise means an attacker
   can forge packets from that car indefinitely.
2. **ECDH session keypairs** — ephemeral, rotated
   every 300 seconds or 10,000 packets. Low value
   after rotation.
3. **HKDF-derived session keys** — symmetric,
   derived from ECDH shared secrets. Ephemeral.

The critical question is how Ed25519 identity private
keys are stored, protected, and rotated. These are
the highest-value key material in the system — their
compromise breaks authentication for an entire
car node.

Two approaches were evaluated:

**External KMS (AWS KMS, Azure Key Vault):**
Keys stored in a managed hardware security module.
Application never sees private key material.
Signing operations performed inside the HSM.

**Self-managed:** Keys generated and stored in
application memory or encrypted key files on disk.
Application holds private key material directly.

---

## Decision

### Production: External KMS (AWS KMS / Azure Key Vault)

**For production deployment with FIA-regulated data.**

**Rationale:**

Ed25519 identity keys represent persistent car node
identity. A compromised identity key allows an
attacker to sign arbitrary packets as a legitimate
car node — bypassing the authentication layer
entirely. The key must be protected at a level
commensurate with this risk.

Hardware Security Modules (HSMs) provide:

**Key non-extractability.** Private keys generated
inside an HSM cannot be exported — the key material
never exists in application memory. Even a complete
compromise of the application host cannot extract
the signing key.

**Audit trail.** Every signing operation performed
by the HSM is logged — providing evidence of key
usage for FIA compliance.

**FIPS 140-2 Level 3 certification.** AWS KMS and
Azure Key Vault HSMs are certified to FIPS 140-2
Level 3 — the standard required for government and
regulated industry key storage.

AWS KMS was evaluated as the primary option due to
F1's existing AWS infrastructure relationship and
CloudHSM availability in all F1 operating regions.

Azure Key Vault is the secondary option for teams
with Azure-primary infrastructure.

### Current Implementation: Self-Managed

**For simulation and development.**

The current `signer.py` implementation generates
Ed25519 keys in application memory using the PyCA
`cryptography` library. This is appropriate for:
- Development and testing
- Simulation pipeline
- Academic research demonstration

In production, the `PacketSigner` class would be
extended with a `KMSSigner` subclass that delegates
`sign()` operations to AWS KMS or Azure Key Vault
via their respective SDKs, while the private key
never leaves the HSM.

### ECDH Session Keys: Self-Managed (All Environments)

ECDH session keypairs are intentionally ephemeral —
they are generated fresh per session and discarded
on rotation. There is no value in HSM storage for
ephemeral keys:

1. The security value of a session key drops to
   zero after rotation — the exposure window is
   bounded regardless of storage security
2. HSM operations add 1-10ms latency per call —
   at 100Hz with per-packet ECDH operations this
   would be catastrophic
3. Forward secrecy is provided by key rotation,
   not by HSM non-extractability

---

## Cloud Deployment Security Model

When deployed on AWS, the full hardening model
is documented in `docs/CLOUD_HARDENING.md`:

**VPC isolation:** Each node type (car simulator,
relay, validator) runs in a separate subnet with
security group rules permitting only required
traffic flows.

**KMS key policies:** IAM roles for car nodes
permit only `kms:Sign` — they cannot list keys,
rotate keys, or perform any administrative operation.

**CloudTrail:** All KMS API calls logged to
CloudTrail with integrity validation — provides
tamper-evident record of all signing operations.

**Secrets Manager:** Non-key secrets (endpoint
configurations, threshold parameters) stored in
AWS Secrets Manager rather than environment
variables or config files.

---

## Consequences

### Positive
- Ed25519 identity keys never exposed in application
  memory in production
- FIPS 140-2 Level 3 certified HSM for key storage
- Complete audit trail of all signing operations
- Compromise of application host does not expose
  identity keys
- Aligns with FIA data security requirements

### Negative
- KMS API calls add 1-10ms latency per signing
  operation — acceptable for identity keys,
  unacceptable for session keys
- External KMS dependency introduces availability
  risk — mitigated by KMS SLA (99.999%)
- Added operational complexity vs self-managed

### Risks
- KMS API throttling under high signing volume —
  mitigated by request batching and caching
- Cross-region KMS latency if car and KMS in
  different regions — mitigated by regional
  KMS deployment

---

## Alternatives Considered

| Option | Rejected Reason |
|---|---|
| Self-managed files | Private key extractable from disk — insufficient for identity keys |
| HSM appliance (on-premises) | Operational complexity, no cloud integration |
| Azure Key Vault only | Limits deployment flexibility |
| Per-packet KMS signing | Latency unacceptable at 100Hz |
| Symmetric MAC keys in KMS | Does not provide non-repudiation |