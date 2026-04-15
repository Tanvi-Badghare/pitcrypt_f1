# ADR 002 — Zero-Knowledge Proof Commitment Scheme

**Status:** Accepted (Rust module in progress)  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review

---

## Context

FIA stewards require the ability to verify that
telemetry data was not modified after transmission
without gaining access to proprietary team telemetry
values. This creates a privacy-preserving integrity
verification requirement:

> "Prove the data is intact without revealing the data."

Standard message authentication codes (MACs) and
digital signatures solve the integrity problem but
not the privacy problem — a verifier with the
authentication key or public key can verify integrity
but the payload is still transmitted in plaintext
to the verifier.

In the real FIA data governance model, stewards
receive telemetry only for specific investigated
incidents. For routine verification, they should be
able to confirm packet integrity without accessing
team strategic data.

---

## Decision

### Commitment Scheme: Pedersen Commitments

**Chosen over:** Hash commitments, HMAC commitments,
Merkle proofs, simple checksums

**Rationale:**

A Pedersen commitment `C = r*G + m*H` binds the
prover to a message `m` using a random blinding
factor `r` over an elliptic curve group. It provides:

**Binding:** Once committed, the prover cannot open
the commitment to a different message without solving
the discrete logarithm problem.

**Hiding:** The commitment reveals nothing about the
message — computationally indistinguishable from a
random curve point to anyone without the blinding
factor.

Hash commitments (`C = SHA256(m || nonce)`) provide
binding but not perfect hiding — a verifier who can
guess the message can verify it by hashing. For
telemetry values with bounded ranges (speed 0-400
km/h, RPM 0-15500), a brute-force preimage attack
is feasible against hash commitments.

Pedersen commitments over Curve25519 prevent this
attack entirely.

### Proof System: Bulletproofs (Range Proofs)

For the specific case of proving telemetry values
are within valid physical ranges without revealing
the values, Bulletproofs provide logarithmic-size
range proofs without a trusted setup.

A range proof `π` proves `m ∈ [0, 2^n)` without
revealing `m`. Applied to F1 telemetry:
Prove: Speed ∈ [0, 400] without revealing Speed
Prove: RPM ∈ [0, 15500] without revealing RPM
This allows the FIA validator to confirm sensor
readings are physically plausible — ruling out
obviously fabricated data — without reading the
actual values.

### Non-Interactive: Fiat-Shamir Heuristic

Interactive ZKP protocols require a challenge-response
round between prover and verifier — incompatible with
100Hz packet rates. The Fiat-Shamir heuristic converts
interactive proofs to non-interactive by replacing the
verifier challenge with a hash of the transcript.

The `merlin` crate provides a structured transcript
for Fiat-Shamir that prevents transcript malleability
attacks.

### Implementation: Rust Module

The ZKP module is implemented in Rust using:
- `curve25519-dalek` — elliptic curve arithmetic
- `bulletproofs` — Pedersen commitments and range proofs
- `merlin` — Fiat-Shamir transcript

Rust is mandatory for this module because:
1. Constant-time arithmetic is guaranteed by
   `curve25519-dalek`'s conditional move operations
2. Python's arbitrary-precision integers are not
   constant-time — Python ZKP would leak timing
   information about secret values
3. Proof generation at 100Hz requires native
   performance

A Python hash commitment fallback is provided in
`validator-node/src/zkp_verifier.py` for environments
where the Rust module is not yet compiled.

---

## Consequences

### Positive
- FIA stewards can verify integrity without accessing
  proprietary team data
- Binding property prevents post-transmission
  data modification
- Hiding property protects strategic telemetry values
- Bulletproofs require no trusted setup — eliminates
  ceremony risk
- Logarithmic proof size scales well with packet rate

### Negative
- Pedersen commitment generation adds latency per
  packet — benchmarked at ~2ms on reference hardware
- Rust module introduces build complexity
- Python fallback uses hash commitments — binding
  but not perfectly hiding

### Risks
- Bulletproofs security relies on discrete log
  hardness — not post-quantum secure
- Fiat-Shamir security relies on random oracle model
- Proof generation must complete within packet
  transmission window

---

## Why Not MACs

MACs were rejected for the privacy-preserving use
case for a fundamental reason: MAC verification
requires the verifier to hold the MAC key. If the
FIA validator holds a MAC key, it can generate valid
MACs for fabricated telemetry — defeating the
non-repudiation property.

ZKP commitments allow a computationally unbounded
prover (car node) to convince a verifier (FIA
validator) that a statement is true without
revealing any witness.

---

## Alternatives Considered

| Scheme | Rejected Reason |
|---|---|
| Hash commitments | Not perfectly hiding — brute-forceable for bounded telemetry values |
| HMAC | Verifier holds key — breaks non-repudiation |
| Merkle proofs | Integrity only — no privacy |
| zk-SNARKs | Trusted setup required — unacceptable for FIA |
| STARK proofs | Proof size too large for 100Hz rate |