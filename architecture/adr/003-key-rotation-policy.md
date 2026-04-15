# ADR 003 — Session Key Rotation Policy

**Status:** Accepted  
**Date:** 2025  
**Author:** PitCrypt-F1 Architecture Team  
**Deciders:** Security Architecture Review

---

## Context

ECDH session keys in PitCrypt-F1 protect the
confidentiality of all telemetry packets in transit.
A compromised session key exposes all packets
encrypted under that key — both past (if recorded)
and future.

Key rotation limits the damage window: if a session
key is compromised, only packets from the current
rotation window are exposed. Rotation also provides
forward secrecy — past session keys are discarded
and cannot be reconstructed.

The question is: how frequently should keys rotate?

Two competing constraints:
1. **Security** — rotate as frequently as possible
   to minimise exposure window
2. **Performance** — each rotation requires an ECDH
   key exchange, adding latency and coordination
   overhead between car and relay nodes

---

## Decision

### Dual-Trigger Rotation

Keys rotate when EITHER condition is met:

**Time-based trigger:** 300 seconds (5 minutes)
**Count-based trigger:** 10,000 packets

**Rationale:**

Time-based rotation alone is insufficient in
high-traffic scenarios — at 100Hz, 10,000 packets
arrive in 100 seconds, well before the 5-minute
time trigger. An attacker recording traffic has
a large ciphertext corpus under a single key.

Count-based rotation alone is insufficient in
low-traffic scenarios — during safety car periods,
packet rates drop significantly. A key established
before a 2-hour red flag could survive the entire
remaining race under count-based rotation alone.

The dual-trigger ensures rotation is bounded by
both time and volume regardless of traffic patterns.

### Threshold Values

**300 seconds** was chosen based on:
- Typical F1 pit stop window (20-40 seconds) —
  key rotation should not interfere with critical
  pit window data
- Typical safety car period (5-15 minutes) —
  rotation provides at least one rotation per
  safety car deployment
- Cryptographic recommendation: NIST SP 800-57
  recommends session key lifetimes of minutes
  to hours for symmetric keys

**10,000 packets** was chosen based on:
- At 100Hz: 10,000 packets = 100 seconds of data
- Limits ciphertext corpus under any single key
  to approximately 1.5MB of encrypted telemetry
- Exceeds typical F1 stint length at sustained
  maximum rate — rotation always occurs before
  stint completion

### Background Thread Implementation

Key rotation runs in a background thread
(`key_scheduler.py`) that checks conditions every
5 seconds. This is non-blocking — the main packet
pipeline is never paused for rotation.

On rotation:
1. New ECDH keypair generated
2. New public key transmitted to peer
3. Peer completes handshake
4. Old session key immediately discarded
5. New session key used for subsequent packets

Packets in-flight during rotation use the old key —
the receiver buffers briefly to handle the transition.

### Forward Secrecy

Each rotation generates a fresh ephemeral keypair.
The private key is never persisted — it exists only
in memory for the duration of the session. On
rotation the old private key is overwritten.

This provides forward secrecy: compromise of a
current session key reveals nothing about past
sessions whose keys have been rotated.

---

## Consequences

### Positive
- Limits exposure window to max(300s, 10,000 packets)
- Provides forward secrecy — past sessions protected
- Dual trigger handles both high and low traffic
- Non-blocking rotation — no pipeline interruption
- Background thread adds minimal overhead

### Negative
- Rotation requires coordination between car and relay
  — brief handshake latency
- Packets in-flight during rotation may fail
  decryption — handled by retry logic
- Adds implementation complexity vs static keys

### Risks
- Rotation timing must be synchronised between
  car and relay — clock skew can cause packet loss
- If rotation callback fails, old key continues
  in use — monitored by KeyScheduler.rotation_count

---

## Alternatives Considered

| Policy | Rejected Reason |
|---|---|
| Static session keys | No forward secrecy, unlimited exposure window |
| Per-packet rotation | ECDH overhead at 100Hz is prohibitive |
| Time-only (5min) | Insufficient for high-traffic bursts |
| Count-only (10,000) | Insufficient for low-traffic periods |
| Manual rotation | Operator error risk, no automation |