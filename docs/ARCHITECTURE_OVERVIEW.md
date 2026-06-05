# Architecture Overview — PitCrypt-F1

**Document:** ARCHITECTURE_OVERVIEW.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## System Purpose

PitCrypt-F1 is a zero-trust cryptographic security
framework for Formula 1 telemetry streams regulated
by the Fédération Internationale de l'Automobile
(FIA). It protects the confidentiality, integrity,
and authenticity of telemetry data transmitted from
car nodes to the FIA validator across an untrusted
trackside network.

The system answers three security questions for
every packet:

1. **Who sent this?** — Ed25519 signature verification
2. **Was it modified?** — ChaCha20-Poly1305 AEAD + ZKP
3. **Is this a replay?** — Dual-tier sequence checking

---

## Design Principles

**Zero Trust:** No node is implicitly trusted
regardless of network location. Every packet must
be cryptographically authenticated before acceptance.
Every access request is evaluated against explicit
IAM policy.

**Defence in Depth:** Security controls operate at
multiple independent tiers. Compromise of one tier
does not compromise the system — relay compromise
does not bypass validator verification.

**Forward Secrecy:** Session keys are ephemeral.
Compromise of a current key does not expose past
sessions. Key rotation is automated and non-blocking.

**Least Privilege:** Each pipeline node has the
minimum permissions required for its function.
Car nodes cannot contact the validator. Relay nodes
cannot sign packets or retain plaintext.

**Auditability:** Every packet decision is logged
to an immutable audit trail. All cryptographic
operations are traceable.

---

## Three-Tier Pipeline Architecture
╔══════════════════════════════════════════════════════════════╗
║                    PitCrypt-F1 Pipeline                      ║
╠══════════════╦═══════════════════════╦════════════════════════╣
║  CAR NODE    ║     RELAY NODE        ║   FIA VALIDATOR        ║
║              ║                       ║                        ║
║  Real F1     ║  Decrypt              ║  Decrypt relay leg     ║
║  telemetry   ║  Integrity check      ║  Verify Ed25519 sig    ║
║  from FastF1 ║  Anomaly filter       ║  Check sequence        ║
║              ║  Re-encrypt           ║  Verify ZKP            ║
║  Sign        ║  Forward              ║  Audit log             ║
║  Encrypt     ║                       ║  Accept / Reject       ║
║  Transmit    ║                       ║                        ║
╠══════════════╬═══════════════════════╬════════════════════════╣
║  Ed25519     ║  ChaCha20-Poly1305    ║  Ed25519 verify        ║
║  sign        ║  decrypt (car leg)    ║  Sequence check        ║
║              ║  ChaCha20-Poly1305    ║  ZKP verify            ║
║  ChaCha20    ║  re-encrypt (val leg) ║  Audit JSONL           ║
║  encrypt     ║                       ║                        ║
╠══════════════╩═══════════════════════╩════════════════════════╣
║         X25519 ECDH key exchange on both pipeline legs       ║
╚══════════════════════════════════════════════════════════════╝
---

## Tier 1 — Car Node

### Responsibility
Produce, sign, and encrypt real F1 telemetry packets.

### Components

**SensorSimulator** (`sensor_simulator.py`)
Loads real 2025 F1 telemetry from FastF1 API.
Supports Mercedes AMG and Red Bull Racing across
13 circuits. Streams frames at configurable rate
with optional noise injection and anomaly simulation.
Data: 1,814,537 rows across Race, Qualifying,
and Sprint sessions.

**PacketBuilder** (`packet_builder.py`)
Assembles binary packet header (64 bytes) and
JSON payload. Header contains magic number,
version, team ID, session type, sequence number,
timestamp, payload length, SHA-256 checksum.
Struct format: `!IBBBBQQI32sI`

**PacketSigner** (`signer.py`)
Generates Ed25519 keypair on initialisation.
Signs `header_bytes + payload_bytes` — both
fields authenticated by signature. Signature
is 64 bytes. Public key registered with FIA
validator out-of-band before race weekend.

**PacketEncryptor** (`encryptor.py`)
Encrypts JSON payload using ChaCha20-Poly1305
with HKDF-derived session key. Header passed
as AEAD associated data — authenticated but
not encrypted. Fresh 12-byte nonce per packet.

**KeyScheduler** (`key_scheduler.py`)
Background thread monitoring session age and
packet count. Triggers ECDH key rotation when
either threshold exceeded (300s or 10,000 pkts).
Non-blocking — does not interrupt packet pipeline.
Forward secrecy guaranteed — old keys discarded.

**CryptoEngine** (`crypto_engine.py`)
Manages X25519 ECDH session lifecycle. Generates
ephemeral keypairs, performs handshake, derives
session key via HKDF-SHA256. One engine per
pipeline leg (car→relay, relay→validator).

### Data Flow — Car Node
FastF1 CSV data
│
▼
SensorSimulator.get_next_frame()
│  telemetry dict
▼
PacketBuilder.build()
│  header (64 bytes) + payload (JSON bytes)
▼
PacketSigner.sign_packet()
│  + Ed25519 signature (64 bytes)
▼
ZKPVerifier.generate_commitment()
│  + commitment + nonce
▼
PacketEncryptor.encrypt_packet()
│  nonce (12B) + ciphertext + header_hex + signature
▼
TCP transmit → Relay Node
---

## Tier 2 — Relay Node

### Responsibility
Receive encrypted car telemetry, validate structural
and statistical integrity, re-encrypt for the
validator leg, and forward. The relay is semi-trusted
— it processes plaintext briefly but cannot retain
it or impersonate the car.

### Components

**PacketParser** (`packet_parser.py`)
Deserialises JSON transmission packet. Validates
required fields, converts hex-encoded nonce,
header, ciphertext, and signature to bytes.
Validates team and session identifiers.

**RelayDecryptor** (`decryptor.py`)
Decrypts car → relay AEAD ciphertext. Maintains
per-car-node session registry. Raises `InvalidTag`
on any tampering — packet dropped immediately.

**IntegrityChecker** (`integrity_checker.py`)
Per-node sequence state machine. Detects:
replay attacks (seen sequence set), out-of-order
delivery, timestamp staleness, signature presence.
First line of replay defence — independent of
validator checker.

**AnomalyFilter** (`anomaly_filters.py`)
Statistical and physical bounds validation.
Physical impossibilities (speed > 400 km/h,
RPM < 0) → REJECT. Statistical threshold
violations → FLAG (forwarded with annotation).
Thresholds calibrated from real F1 telemetry
via `forensic/calibrate_thresholds.py`.

**RelayReencryptor** (`reencryptor.py`)
Re-encrypts decrypted payload for the relay →
validator leg using a separate ECDH session key.
Preserves original car Ed25519 signature — validator
verifies the car's signature, not the relay's.
Fresh nonce per re-encryption.

### Data Flow — Relay Node
TCP receive ← Car Node
│  JSON packet
▼
PacketParser.parse_json_packet()
│  validated + bytes-decoded fields
▼
RelayDecryptor.decrypt()          ← AEAD decrypt car leg
│  plaintext payload + metadata
▼
IntegrityChecker.check()          ← replay + sequence
│  pass or drop
▼
AnomalyFilter.check_and_annotate() ← bounds checking
│  pass / flag / reject
▼
RelayReencryptor.reencrypt()      ← AEAD encrypt val leg
│  new nonce + ciphertext + preserved car signature
▼
TCP transmit → FIA Validator
---

## Tier 3 — FIA Validator

### Responsibility
Final authoritative verification of all telemetry
packets. Every decision — accept, reject, flag —
is logged to an immutable audit trail. No packet
is accepted without passing all checks.

### Components

**ValidatorSignatureVerifier** (`signature_verifier.py`)
Ed25519 verification against registered car node
public keys. Verifies original car signature on
`header_bytes + payload_bytes`. Signature preserved
through relay unchanged. Unknown nodes rejected.

**ValidatorSequenceChecker** (`sequence_checker.py`)
Second independent sequence and replay check.
Strict monotonic ordering enforced per car node.
Rolling 50,000-entry replay window. Operates
independently of relay IntegrityChecker —
defence in depth.

**ZKPVerifier** (`zkp_verifier.py`)
Commitment verification: recomputes SHA256(payload
+ nonce) and compares to transmitted commitment.
Packets without commitment are skipped (graceful
degradation). Rust Pedersen commitment module
planned for production (perfect hiding property).

**AuditLogger** (`audit_logger.py`)
Thread-safe JSONL audit trail. Records every
ACCEPT, REJECT, and FLAG decision with timestamp,
sequence number, node identity, team, session,
reason, and decision details. Append-only.
Exported for FIA review.

### Data Flow — Validator Node
---

## Tier 3 — FIA Validator

### Responsibility
Final authoritative verification of all telemetry
packets. Every decision — accept, reject, flag —
is logged to an immutable audit trail. No packet
is accepted without passing all checks.

### Components

**ValidatorSignatureVerifier** (`signature_verifier.py`)
Ed25519 verification against registered car node
public keys. Verifies original car signature on
`header_bytes + payload_bytes`. Signature preserved
through relay unchanged. Unknown nodes rejected.

**ValidatorSequenceChecker** (`sequence_checker.py`)
Second independent sequence and replay check.
Strict monotonic ordering enforced per car node.
Rolling 50,000-entry replay window. Operates
independently of relay IntegrityChecker —
defence in depth.

**ZKPVerifier** (`zkp_verifier.py`)
Commitment verification: recomputes SHA256(payload
+ nonce) and compares to transmitted commitment.
Packets without commitment are skipped (graceful
degradation). Rust Pedersen commitment module
planned for production (perfect hiding property).

**AuditLogger** (`audit_logger.py`)
Thread-safe JSONL audit trail. Records every
ACCEPT, REJECT, and FLAG decision with timestamp,
sequence number, node identity, team, session,
reason, and decision details. Append-only.
Exported for FIA review.

### Data Flow — Validator Node
TCP receive ← Relay Node
│  re-encrypted packet
▼
CryptoEngine.decrypt()            ← AEAD decrypt relay leg
│  plaintext payload
▼
ValidatorSignatureVerifier.verify() ← Ed25519 check
│  pass or reject
▼
ValidatorSequenceChecker.check()  ← replay + ordering
│  pass or reject
▼
ZKPVerifier.verify_packet()       ← commitment check
│  pass or reject
▼
AuditLogger.log_accept/reject()   ← immutable log
│
▼
ACCEPT / REJECT / FLAG
---

## IAM Module

### Responsibility
Zero-trust access control enforced at every node
boundary. Explicit RBAC policy evaluation for every
action. Default deny for unknown nodes and undefined
actions.

### Components

**IdentityStore** (`identity_store.py`)
Node identity registry loaded from `iam.yaml`.
Maintains node_id → role → policy mapping.
Public key registration for Ed25519 keys.

**PolicyLoader** (`policy_loader.py`)
Loads YAML policy files from `iam-module/policies/`.
Evaluates allow/deny rules — deny always wins.
Default deny for any uncovered action.

**RBACEngine** (`rbac_engine.py`)
Combines IdentityStore + PolicyLoader. Answers:
"Is node X allowed to do action Y on resource Z?"
Raise `PermissionError` on denial in strict mode.

**AccessAuditor** (`access_auditor.py`)
Records all IAM decisions to JSONL. Detects
consecutive denial patterns — alert after 3
consecutive denials from same node.

### Three-Role Model
car_producer  → produce, sign, encrypt, transmit to relay
relay         → receive, decrypt, reencrypt, forward
fia_validator → receive, decrypt, verify, audit log
---

## Forensic Analysis Module

### Responsibility
Statistical baseline computation and anomaly
threshold calibration from real F1 telemetry.

### Components

**fetch_telemetry.py** — Downloads race data via
FastF1 for Mercedes AMG and Red Bull Racing.

**forensic_analysis.py** — Computes per-team,
per-session statistical baselines. Z-score
anomaly detection. Produces `mercedes_baseline.csv`
and `redbull_baseline.csv`.

**calibrate_thresholds.py** — Derives anomaly
filter thresholds from baselines. Per-team
lower/upper bounds for Speed, RPM, Throttle,
Brake, nGear, DRS.

**visualise_telemetry.py** — Generates five
matplotlib visualisations: speed distribution,
throttle vs speed, channel statistics,
anomaly counts, DRS usage patterns.

---

## Simulation Suite
simulations/
├── replay_attack_sim.py    ← 5 replay attack vectors
├── tampering_sim.py        ← 7 tamper attack vectors
├── iam_breach_sim.py       ← 7 IAM breach vectors
├── packet_loss_sim.py      ← 5 loss scenarios
├── jitter_sim.py           ← 5 jitter scenarios
└── results/                ← JSON/CSV output
**Detection results:**
- Tampering: 7/7 attacks detected
- Replay: 4/5 detected (1 simulation limitation)
- IAM breach: 7/7 defended
- Packet loss: Pipeline recovers after all scenarios
- Jitter: Latency benchmarked, throughput baseline established

---

## Key Technical Decisions

All major decisions are documented as Architecture
Decision Records in `architecture/adr/`:

| ADR | Decision |
|---|---|
| ADR-001 | X25519 + ChaCha20-Poly1305 + Ed25519 |
| ADR-002 | Pedersen commitments + Bulletproofs |
| ADR-003 | Dual-trigger key rotation 300s/10K |
| ADR-004 | RBAC over ABAC for IAM |
| ADR-005 | AWS KMS HSM for identity keys |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Crypto | PyCA `cryptography` ≥41.0 |
| F1 Data | FastF1 API |
| Data | pandas, numpy |
| Visualisation | matplotlib |
| Testing | pytest |
| ZKP (planned) | Rust, curve25519-dalek, bulletproofs |
| Production KMS | AWS KMS CloudHSM |
| Audit | JSONL append-only |
| CI | GitHub Actions |

---

## Repository Structure
pitcrypt_f1/
├── car-producer/
│   ├── src/              ← Pipeline components
│   └── tests/            ← pytest test suite
├── relay-node/
│   ├── src/
│   ├── config/
│   └── tests/
├── validator-node/
│   ├── src/
│   ├── config/
│   └── tests/
├── iam-module/
│   ├── src/
│   ├── policies/         ← YAML RBAC policies
│   └── config/
├── forensic/             ← Telemetry analysis
├── simulations/          ← Attack simulations
├── benchmarks/           ← Performance benchmarks
├── architecture/
│   └── adr/              ← Decision records
├── docs/                 ← All documentation
├── zkp-module/           ← Rust ZKP (planned)
└── data/                 ← Gitignored — regenerate locally