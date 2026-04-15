# ADR 001 — Cryptographic Primitive Selection

**Status:** Accepted  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review

---

## Context

PitCrypt-F1 requires cryptographic primitives for three
distinct purposes:

1. **Key exchange** — establishing shared session keys
   between car nodes, relay, and validator without
   transmitting the key over the network
2. **Encryption** — protecting telemetry payload
   confidentiality in transit
3. **Authentication** — proving packet origin and
   detecting tampering

The system operates at approximately 100Hz packet rates
under real F1 telemetry conditions. Cryptographic
overhead must be minimal enough to sustain this rate
without degrading pipeline latency beyond acceptable
bounds. The system runs in software without guaranteed
hardware acceleration.

Additionally, F1 telemetry infrastructure operates in
adversarial environments — trackside networks, relay
bridges, and shared FIA data streams — where timing
side-channel attacks are a realistic threat vector.

---

## Decision

### Key Exchange: X25519 (Curve25519 ECDH)

**Chosen over:** ECDH P-256, ECDH P-384, RSA-2048 key exchange

**Rationale:**

X25519 was designed by Daniel Bernstein specifically to
resist implementation errors and timing side channels.
Unlike P-256, which requires careful scalar clamping and
point validation that is frequently misimplemented,
X25519 has a fully defined and safe API — any 32-byte
input is a valid scalar.

The 32-byte public key and 32-byte shared secret are
compact relative to RSA equivalents, reducing packet
overhead. Key generation and exchange complete in
microseconds on modern hardware without AES-NI
dependency.

RFC 7748 standardisation ensures long-term
interoperability with FIA validator infrastructure.

### Symmetric Encryption: ChaCha20-Poly1305

**Chosen over:** AES-256-GCM, AES-128-GCM, AES-CBC+HMAC

**Rationale:**

ChaCha20-Poly1305 provides authenticated encryption
with associated data (AEAD) in a single primitive,
eliminating the encrypt-then-MAC composition errors
that plague AES-CBC+HMAC implementations.

The critical advantage over AES-GCM in this deployment
is the absence of hardware acceleration dependency.
AES-GCM performance degrades significantly on platforms
without AES-NI instructions — trackside relay hardware
cannot be assumed to have this capability.
ChaCha20-Poly1305 is a software-optimised cipher with
constant-time guarantees that do not depend on hardware
features.

Nonce reuse in AES-GCM is catastrophic — it completely
breaks confidentiality and authentication. ChaCha20
uses a 96-bit nonce generated fresh per packet, and
the consequences of accidental reuse, while still
serious, are less severe than GCM's complete failure
mode.

RFC 8439 standardisation provides formal specification
for implementation verification.

### Digital Signatures: Ed25519

**Chosen over:** ECDSA P-256, RSA-PSS, HMAC-based MACs

**Rationale:**

Ed25519 produces 64-byte signatures from 32-byte keys —
the most compact signature scheme providing equivalent
security to RSA-3072. At 100Hz packet rates, signature
size directly contributes to bandwidth consumption.

Unlike ECDSA, Ed25519 signing is deterministic — it does
not require a random nonce per signature. ECDSA nonce
reuse (the Sony PlayStation 3 vulnerability) leads to
complete private key recovery. Ed25519 eliminates this
entire class of implementation vulnerability.

Ed25519 verification is faster than RSA verification
and comparable to ECDSA P-256 on modern hardware.

HMAC-based authentication was rejected because MACs
require shared secret distribution — every verifier
needs the signing key. Ed25519's asymmetric design
allows the FIA validator to verify car signatures
without holding any car secret material.

RFC 8032 standardisation.

---

## Key Derivation: HKDF-SHA256

Raw ECDH output is not uniformly random and must not
be used directly as a symmetric key. HKDF-SHA256 is
used to extract and expand the raw shared secret into
a 256-bit session key, following RFC 5869.

Separate HKDF info strings are used for encryption
and authentication contexts to ensure domain separation:
HKDF(secret, salt, info="pitcrypt-f1-encryption-v1")
---

## Consequences

### Positive
- Constant-time implementations eliminate timing
  side-channel risk
- Compact keys and signatures minimise packet overhead
- Single AEAD primitive handles both confidentiality
  and integrity — no composition errors
- Deterministic Ed25519 eliminates nonce-reuse
  vulnerabilities
- All primitives are RFC-standardised and
  independently audited

### Negative
- ChaCha20-Poly1305 is slower than AES-GCM on hardware
  with AES-NI — acceptable given deployment constraints
- X25519 does not provide post-quantum security —
  acceptable for 2025 deployment horizon

### Risks
- Implementation must use vetted libraries (PyCA
  cryptography, libsodium) — custom implementations
  are explicitly prohibited
- Nonce uniqueness for ChaCha20 must be enforced
  at the application layer — one fresh nonce per packet

---

## Alternatives Considered

| Primitive | Rejected Reason |
|---|---|
| AES-256-GCM | Hardware dependency, nonce reuse catastrophic |
| ECDSA P-256 | Nonce reuse → key recovery, larger signatures |
| RSA-2048 | Large keys/signatures, slow generation |
| P-256 ECDH | Implementation complexity, timing risks |
| AES-CBC+HMAC | Composition errors, no AEAD |