# Threat Model — PitCrypt-F1

**Document:** THREAT_MODEL.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Classification:** Security Architecture  
**Status:** Authoritative

---

## Executive Summary

PitCrypt-F1 protects Formula 1 telemetry streams
transmitted from car nodes to the FIA validator
across an untrusted relay network. The system
operates in an adversarial environment where:

- Trackside networks are physically accessible
  to non-authorised personnel
- Commercial off-the-shelf radio equipment can
  intercept unencrypted telemetry
- Insider threats exist at all three pipeline tiers
- Nation-state actors have demonstrated interest
  in motorsport intellectual property

This document applies the STRIDE threat model to
every component of the PitCrypt-F1 pipeline and
maps identified threats to implemented mitigations.

---

## System Architecture Overview
┌─────────────────────────────────────────────────────┐
│                  TRUST BOUNDARY                     │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │  Car     │    │  Relay   │    │  FIA         │  │
│  │  Node    │───►│  Node    │───►│  Validator   │  │
│  │          │    │          │    │              │  │
│  │ Mercedes │    │ relay_01 │    │ fia_validator │  │
│  │ Red Bull │    │          │    │              │  │
│  └──────────┘    └──────────┘    └──────────────┘  │
│                                                     │
│   Untrusted Network       Untrusted Network         │
│   ◄─────────────────────────────────────────────►   │
└─────────────────────────────────────────────────────┘
**Assets protected:**
- Telemetry payload (Speed, RPM, Throttle, DRS, Gear)
- Session cryptographic keys
- Ed25519 identity private keys
- Audit log integrity
- Packet sequence and ordering

**Trust boundaries:**
- Car node — trusted origin, untrusted network path
- Relay node — semi-trusted processor, cannot be
  given plaintext retention privilege
- Validator — fully trusted, authoritative endpoint
- Network between nodes — untrusted, adversarial

---

## STRIDE Threat Matrix

STRIDE stands for: **S**poofing · **T**ampering ·
**R**epudiation · **I**nformation Disclosure ·
**D**enial of Service · **E**levation of Privilege

---

### S — Spoofing

Spoofing threats involve an attacker impersonating
a legitimate node in the pipeline.

---

#### S1 — Car Node Identity Spoofing

**Target:** FIA Validator  
**Vector:** Attacker crafts packets claiming to
originate from `mercedes_car` or `redbull_car`  
**Impact:** FIA accepts fabricated telemetry as
genuine — race results corrupted  
**Likelihood:** Medium — requires knowledge of
packet format and network access  

**Mitigation:**
Ed25519 digital signatures on every packet.
Each car node has a unique keypair. The validator
holds only public keys — signatures cannot be
forged without the car's private key. Implemented
in `car-producer/src/signer.py` and verified in
`validator-node/src/signature_verifier.py`.

**Residual risk:** Private key compromise enables
spoofing. Mitigated by AWS KMS HSM storage in
production — private key never leaves HSM.

---

#### S2 — Relay Node Impersonation

**Target:** Car Node  
**Vector:** Attacker sets up rogue relay node,
intercepts car → relay handshake  
**Impact:** Car encrypts telemetry to attacker's
key instead of legitimate relay  
**Likelihood:** Medium — requires network-level
access between car and relay  

**Mitigation:**
X25519 ECDH ephemeral key exchange. Relay public
key is pre-distributed to car node out-of-band.
Car verifies relay identity before completing
handshake. Session keys are ephemeral — compromise
of one session does not expose others.

**Residual risk:** Pre-distribution channel must
be secured. Mitigated by out-of-band secure channel
for initial public key exchange.

---

#### S3 — Validator Impersonation

**Target:** Relay Node  
**Vector:** Attacker impersonates FIA validator,
receives re-encrypted telemetry  
**Impact:** Telemetry delivered to attacker instead
of FIA — data theft  
**Likelihood:** Low — requires access to relay →
validator network segment  

**Mitigation:**
X25519 ECDH for relay → validator leg. Validator
public key pre-distributed to relay out-of-band.
Separate ECDH session for each pipeline leg.

---

#### S4 — Unknown Node Injection

**Target:** Relay Node / Validator  
**Vector:** Completely unknown node attempts to
inject packets into pipeline  
**Impact:** Fabricated telemetry accepted  
**Likelihood:** Low — immediately rejected  

**Mitigation:**
IAM zero-trust default deny. Unknown nodes
rejected before any packet processing. Implemented
in `iam-module/src/rbac_engine.py`. Tested in
`simulations/iam_breach_sim.py` — 100% of unknown
node attempts blocked.

---

### T — Tampering

Tampering threats involve modification of data
in transit or at rest.

---

#### T1 — In-Transit Payload Modification

**Target:** Telemetry payload  
**Vector:** Man-in-the-middle intercepts encrypted
packet, flips bits in ciphertext  
**Impact:** Corrupted telemetry reaches FIA —
false race data  
**Likelihood:** Medium — network access sufficient  

**Mitigation:**
ChaCha20-Poly1305 AEAD authentication tag covers
both ciphertext and associated data (header).
Any modification to ciphertext produces tag
mismatch — `InvalidTag` raised at relay decryption.
Demonstrated in `simulations/tampering_sim.py`
Attack 1 (payload bit flip) — ✅ detected at relay.

---

#### T2 — Header Manipulation

**Target:** Packet header (sequence, timestamp,
team ID)  
**Vector:** Attacker modifies header bytes to
alter routing or sequence metadata  
**Impact:** Sequence validation bypassed, packets
re-routed  
**Likelihood:** Medium  

**Mitigation:**
Header bytes are AEAD associated data — authenticated
but not encrypted. Any header modification detected
by Poly1305 tag. Demonstrated in tampering sim
Attack 5 (header AEAD) — ✅ detected at relay.

---

#### T3 — Relay-Side Payload Modification

**Target:** Decrypted payload at relay  
**Vector:** Compromised relay modifies telemetry
values after decryption, before re-encryption  
**Impact:** FIA receives falsified telemetry
with valid relay signature  
**Likelihood:** Low — requires relay compromise  

**Mitigation:**
Ed25519 signature covers original header + payload
bytes from car. Signature is preserved through
relay unchanged. Validator verifies original car
signature — relay cannot modify payload without
invalidating the car's signature. Demonstrated in
tampering sim Attack 2 (speed injection) — ✅
detected at validator via signature failure.

---

#### T4 — Audit Log Tampering

**Target:** `validator_audit.jsonl`  
**Vector:** Attacker modifies or deletes audit
records after the fact  
**Impact:** Evidence of attack lost, compliance
violated  
**Likelihood:** Low — requires validator access  

**Mitigation:**
Audit log is append-only JSONL. In production,
CloudTrail provides tamper-evident logging with
cryptographic integrity validation. IAM policy
explicitly denies audit write access to all nodes
except `fia_validator`. Tested in IAM breach sim
Attack 6 — relay audit log write attempt blocked.

---

#### T5 — ZKP Commitment Manipulation

**Target:** ZKP commitment in packet  
**Vector:** Attacker replaces valid commitment
with fake value to hide payload changes  
**Impact:** Payload modification undetected  
**Likelihood:** Low — requires commitment knowledge  

**Mitigation:**
ZKP commitment is SHA256(payload + nonce) — cannot
be forged without knowing the payload. Validator
recomputes commitment and compares. Demonstrated
in tampering sim Attack 4 — ✅ ZKP mismatch detected.

---

### R — Repudiation

Repudiation threats involve a node denying that
it performed an action.

---

#### R1 — Car Node Denies Sending Packet

**Target:** FIA audit process  
**Vector:** Car team claims they never transmitted
a particular telemetry packet  
**Impact:** Cannot prove regulatory violation —
FIA stewards cannot act  
**Likelihood:** Medium — plausible in race disputes  

**Mitigation:**
Ed25519 non-repudiation. Car's private key signs
every packet. FIA validator holds car's public key.
Validator audit log records accepted packets with
signature verification timestamp. Car cannot deny
a packet bearing its valid signature without claiming
key compromise — which triggers incident response.

---

#### R2 — Relay Denies Forwarding

**Target:** FIA pipeline audit  
**Vector:** Relay operator claims packet was never
received or forwarded  
**Impact:** Cannot establish packet delivery chain  
**Likelihood:** Low  

**Mitigation:**
Original car signature preserved through relay.
Validator audit log provides evidence of receipt.
CloudTrail records all validator API calls.

---

#### R3 — Validator Denies Decision

**Target:** Team disputing penalty  
**Vector:** FIA validator claims it accepted or
rejected a packet that it didn't  
**Impact:** Regulatory dispute cannot be resolved  
**Likelihood:** Very low  

**Mitigation:**
Immutable JSONL audit log records every ACCEPT/
REJECT/FLAG decision with timestamp, sequence
number, node identity, and decision reason.
Log exported for FIA review. CloudTrail provides
external validation of validator activity.

---

### I — Information Disclosure

Information disclosure threats involve
unintended exposure of sensitive data.

---

#### I1 — Telemetry Interception

**Target:** Telemetry payload in transit  
**Vector:** Passive eavesdropping on car → relay
or relay → validator network  
**Impact:** Team strategy exposed — tyre choices,
fuel loads, engine modes  
**Likelihood:** High — radio interception trivial  

**Mitigation:**
ChaCha20-Poly1305 256-bit encryption on both
pipeline legs. Session keys derived via HKDF
from ECDH shared secret — not transmitted.
Even with full network capture, decryption
requires session private key. Forward secrecy
via key rotation ensures past captures remain
encrypted after key rotation.

---

#### I2 — Session Key Exposure

**Target:** ChaCha20 session key  
**Vector:** Memory dump or side-channel attack
on relay node  
**Impact:** Current session decryptable — all
packets under that key exposed  
**Likelihood:** Low — requires physical or
remote access  

**Mitigation:**
Key rotation every 300 seconds or 10,000 packets.
Forward secrecy — past sessions protected after
rotation. Keys exist only in memory, never persisted.
Exposure window bounded by rotation policy.

---

#### I3 — Identity Key Exposure

**Target:** Ed25519 private key  
**Vector:** Application memory dump or HSM bypass  
**Impact:** Attacker can forge packets indefinitely  
**Likelihood:** Very low in production  

**Mitigation:**
AWS KMS HSM storage in production — private key
non-extractable. Application never holds private
key material. All signing delegated to KMS API.
Compromise response: immediate key deregistration.

---

#### I4 — ZKP Privacy Violation

**Target:** Telemetry values in ZKP proofs  
**Vector:** Brute-force preimage attack on hash
commitments for bounded telemetry values  
**Impact:** Telemetry values revealed to FIA
stewards without team consent  
**Likelihood:** Low against Pedersen commitments,
medium against hash fallback  

**Mitigation:**
Production Pedersen commitments (Rust module)
provide perfect hiding — brute-force infeasible.
Hash commitment fallback is binding but not
perfectly hiding. Production deployment requires
Rust ZKP module for full privacy guarantee.

---

### D — Denial of Service

Denial of service threats target pipeline
availability and throughput.

---

#### D1 — Packet Flood Attack

**Target:** Relay node  
**Vector:** Attacker floods relay with invalid
packets — exhausting processing capacity  
**Impact:** Legitimate telemetry dropped —
race data unavailable to FIA  
**Likelihood:** Medium — trivial to execute  

**Mitigation:**
Relay queue has configurable maximum size
(`max_queue_size: 1000`). Invalid packets
rejected at parse stage before decryption
attempt — computationally cheap. IAM policy
blocks unknown node connections. Rate limiting
in production deployment.

---

#### D2 — Cryptographic DoS

**Target:** Relay decryption pipeline  
**Vector:** Attacker sends crafted packets
designed to maximise AEAD decryption cost  
**Impact:** Relay CPU saturated — latency spikes  
**Likelihood:** Low  

**Mitigation:**
ChaCha20-Poly1305 authentication tag checked
before decryption — invalid packets rejected
in nanoseconds without full decryption.
Poly1305 is constant-time — no timing oracle.

---

#### D3 — Key Rotation DoS

**Target:** Key rotation scheduler  
**Vector:** Attacker triggers excessive rotation
events — disrupting pipeline continuity  
**Impact:** Packets lost during rotation transitions  
**Likelihood:** Low  

**Mitigation:**
Key rotation runs in background thread — does
not block packet pipeline. Rotation events logged.
Minimum rotation interval enforced.

---

#### D4 — Replay Flood

**Target:** Validator sequence checker  
**Vector:** Attacker replays thousands of captured
packets — filling seen-sequence set  
**Impact:** Memory exhaustion at validator  
**Likelihood:** Low  

**Mitigation:**
Rolling replay window of 50,000 sequences.
Oldest entries evicted when window full.
Memory bounded regardless of attack volume.

---

### E — Elevation of Privilege

Elevation of privilege threats involve nodes
gaining capabilities beyond their assigned role.

---

#### E1 — Car Node Privilege Escalation

**Target:** IAM RBAC engine  
**Vector:** Car node attempts validator actions —
signature verification, audit access  
**Impact:** Car team can verify/accept own packets  
**Likelihood:** Low — requires RBAC bypass  

**Mitigation:**
Zero-trust RBAC. Car node policy explicitly denies
all validator actions. Default deny for any action
not explicitly allowed. Tested in IAM breach sim
Attack 5 — 8/8 privilege escalation attempts blocked.

---

#### E2 — Relay Signing Packets

**Target:** Ed25519 authentication  
**Vector:** Relay node forges car signatures on
modified packets  
**Impact:** Validator accepts relay-fabricated data  
**Likelihood:** Low — requires relay compromise  

**Mitigation:**
Relay IAM policy explicitly denies `telemetry.sign`
on `any_packets`. Relay holds no Ed25519 signing
key — it has no private key material to sign with.
Validator verifies against car's public key only —
relay signature would fail verification.

---

#### E3 — Cross-Team Data Access

**Target:** Competitor telemetry  
**Vector:** Mercedes car node reads Red Bull
telemetry from relay buffer  
**Impact:** Strategic data stolen — race outcome
manipulated  
**Likelihood:** Low — requires relay access  

**Mitigation:**
Separate ECDH sessions per car node. Red Bull
telemetry encrypted with Red Bull session key —
unreadable by Mercedes engine. IAM policy denies
`telemetry.read` on `other_team_telemetry`.
Tested in IAM breach sim Attack 2 — blocked.

---

## STRIDE Summary Matrix

| Threat | Category | Likelihood | Mitigation | Status |
|---|---|---|---|---|
| S1 Car spoofing | Spoofing | Medium | Ed25519 + KMS | ✅ Mitigated |
| S2 Relay impersonation | Spoofing | Medium | ECDH + OOB key dist | ✅ Mitigated |
| S3 Validator impersonation | Spoofing | Low | ECDH + OOB key dist | ✅ Mitigated |
| S4 Unknown node injection | Spoofing | Low | IAM zero-trust deny | ✅ Mitigated |
| T1 Payload modification | Tampering | Medium | ChaCha20-Poly1305 AEAD | ✅ Mitigated |
| T2 Header manipulation | Tampering | Medium | AEAD associated data | ✅ Mitigated |
| T3 Relay payload modify | Tampering | Low | Ed25519 car signature | ✅ Mitigated |
| T4 Audit log tampering | Tampering | Low | Append-only + IAM deny | ✅ Mitigated |
| T5 ZKP commitment swap | Tampering | Low | Commitment recompute | ✅ Mitigated |
| R1 Car denies packet | Repudiation | Medium | Ed25519 non-repudiation | ✅ Mitigated |
| R2 Relay denies forward | Repudiation | Low | Audit log + car sig | ✅ Mitigated |
| R3 Validator denies decision | Repudiation | Very Low | Immutable JSONL audit | ✅ Mitigated |
| I1 Telemetry interception | Info Disclosure | High | ChaCha20 256-bit enc | ✅ Mitigated |
| I2 Session key exposure | Info Disclosure | Low | Rotation + forward secrecy | ✅ Mitigated |
| I3 Identity key exposure | Info Disclosure | Very Low | AWS KMS HSM | ✅ Mitigated |
| I4 ZKP privacy violation | Info Disclosure | Medium | Pedersen commitments | ⚠️ Partial* |
| D1 Packet flood | DoS | Medium | Queue limit + IAM | ✅ Mitigated |
| D2 Crypto DoS | DoS | Low | Tag-first rejection | ✅ Mitigated |
| D3 Key rotation DoS | DoS | Low | Background thread | ✅ Mitigated |
| D4 Replay flood | DoS | Low | Rolling window | ✅ Mitigated |
| E1 Car privilege escalation | Elevation | Low | RBAC explicit deny | ✅ Mitigated |
| E2 Relay signs packets | Elevation | Low | No signing key + IAM | ✅ Mitigated |
| E3 Cross-team data access | Elevation | Low | Separate sessions + IAM | ✅ Mitigated |

*I4 Partial: Hash commitment fallback used in current Python
implementation. Full Pedersen commitment privacy requires
Rust `zkp-module/` compilation.

---

## Residual Risks

### RR1 — Post-Quantum Cryptography
X25519 and Ed25519 are broken by Shor's algorithm
on a sufficiently powerful quantum computer.
Timeline for cryptographically relevant quantum
computers: estimated 10-15 years.
Migration path: CRYSTALS-Kyber (key exchange) and
CRYSTALS-Dilithium (signatures) when NIST PQC
standards mature.

### RR2 — Python ZKP Fallback
Current hash commitment fallback is not perfectly
hiding for bounded telemetry values. Full privacy
requires Rust `zkp-module/` Pedersen commitments.
Priority: Complete before production deployment.

### RR3 — Simulation vs Production Network
Current simulations run on localhost with no actual
network latency. Production deployment requires
validation under real F1 trackside network conditions
with packet loss, jitter, and interference.

---

## Implementation References

| Threat | Implementation File |
|---|---|
| Ed25519 signing | `car-producer/src/signer.py` |
| Ed25519 verification | `validator-node/src/signature_verifier.py` |
| AEAD encryption | `car-producer/src/crypto_engine.py` |
| AEAD decryption | `relay-node/src/decryptor.py` |
| Replay detection | `relay-node/src/integrity_checker.py` |
| Sequence defence | `validator-node/src/sequence_checker.py` |
| ZKP commitment | `validator-node/src/zkp_verifier.py` |
| IAM zero-trust | `iam-module/src/rbac_engine.py` |
| Audit log | `validator-node/src/audit_logger.py` |
| Key rotation | `car-producer/src/key_scheduler.py` |

---

## See Also

- `docs/THREAT_INTELLIGENCE.md` — APT groups and CVEs
- `docs/MITRE_ATTACK_MAPPING.md` — ATT&CK technique mapping
- `docs/INCIDENT_RESPONSE.md` — Compromise response runbook
- `architecture/adr/001-crypto-choice.md` — Primitive rationale
- `simulations/tampering_sim.py` — Tamper detection evidence
- `simulations/replay_attack_sim.py` — Replay defence evidence
- `simulations/iam_breach_sim.py` — IAM breach defence evidence