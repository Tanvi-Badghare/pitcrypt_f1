# ADR 004 — IAM Access Control Model: RBAC vs ABAC

**Status:** Accepted  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review

---

## Context

PitCrypt-F1 operates a zero-trust architecture where
no node is implicitly trusted regardless of network
location. Every access request — a car node producing
telemetry, a relay decrypting packets, a validator
reading audit logs — must be explicitly authorised.

Two primary access control models were evaluated:

**RBAC (Role-Based Access Control):** Permissions
assigned to roles. Nodes assigned to roles.
Permissions evaluated against role.

**ABAC (Attribute-Based Access Control):** Permissions
evaluated against arbitrary attributes of the subject,
object, action, and environment at request time.

---

## Decision

### Role-Based Access Control (RBAC)

**Chosen over:** ABAC, DAC (Discretionary),
MAC (Mandatory), plain ACLs

**Rationale:**

**Predictability and auditability.** In a regulated
FIA environment, access control decisions must be
explainable and auditable. RBAC decisions are
deterministic — given a role and an action, the
outcome is always the same. ABAC decisions depend
on runtime attribute evaluation and are harder to
audit after the fact.

**Simplicity matches problem complexity.** The
PitCrypt-F1 node topology is well-defined with three
distinct roles: car producer, relay, and FIA validator.
There are no dynamic role assignments, no time-of-day
restrictions, and no context-dependent permissions that
would require ABAC's attribute evaluation engine.

**Policy transparency.** RBAC policies are expressed
as simple YAML files that can be reviewed by FIA
security auditors without requiring understanding
of attribute expression languages. This directly
supports the compliance requirements in
`docs/COMPLIANCE.md`.

**Performance.** RBAC evaluation is O(1) lookup
against a pre-compiled permission table. ABAC requires
attribute collection and policy expression evaluation
at request time — unacceptable overhead at 100Hz
packet rates where IAM checks occur per packet.

### Three-Role Model
car_producer  → can produce, sign, encrypt, transmit to relay
relay         → can receive, decrypt, reencrypt, forward to validator
fia_validator → can receive, decrypt, verify, audit log
Each role has an explicit allow list and explicit
deny list. The evaluation order is:

1. Check deny rules — deny always wins
2. Check allow rules — explicit allow required
3. Default deny — zero-trust baseline

This mirrors the principle of least privilege: nodes
have exactly the permissions required for their
function, nothing more.

### Policy Files

Policies are expressed as YAML for human readability
and stored in `iam-module/policies/`. Each policy
file defines the role's permissions independently,
enabling per-role audit without reviewing a monolithic
access control matrix.

---

## Consequences

### Positive
- Simple, auditable, FIA-explainable permission model
- O(1) policy evaluation — no runtime overhead
- YAML policies reviewable by non-engineers
- Explicit deny rules enforce zero-trust default
- Three-role model maps cleanly to pipeline topology

### Negative
- Less flexible than ABAC — cannot express
  context-dependent rules without policy changes
- Role proliferation risk if topology grows —
  mitigated by current three-role sufficiency

### Risks
- Policy misconfiguration could grant unintended
  permissions — mitigated by explicit deny rules
  and policy review requirement

---

## Why Not ABAC

ABAC was rejected primarily because the system does
not require attribute-based decisions. There are no
requirements such as:

- "Allow access only between 14:00 and 16:00"
- "Allow access if car is in pit lane"
- "Allow access if session is Race but not Qualifying"

All such context is already captured in the packet
structure and handled by anomaly filters and sequence
checkers. Adding ABAC would introduce evaluation
complexity without corresponding security benefit.

---

## Alternatives Considered

| Model | Rejected Reason |
|---|---|
| ABAC | Over-engineered for static three-role topology |
| DAC | No owner-based delegation in pipeline architecture |
| MAC | Security labels unnecessary for this threat model |
| Plain ACLs | Not scalable to policy changes — RBAC abstracts roles |