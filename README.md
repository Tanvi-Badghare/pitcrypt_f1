# PitCrypt-F1 🏎️🔐

> **A Zero-Trust Cryptographic Security Framework for FIA-Regulated Formula 1 Telemetry Streams**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-ZKP_Module-orange?logo=rust)](https://rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active_Development-yellow)]()
[![Data](https://img.shields.io/badge/Data-Mercedes_AMG_%26_Red_Bull_2025-red)]()

---

## Overview

Formula 1 telemetry is among the most sensitive real-time data in professional
sport. A single race generates millions of data points — throttle position,
brake pressure, tyre temperatures, fuel loads, DRS state, and GPS coordinates
— transmitted live to pit walls, race engineers, and FIA stewards simultaneously.

The **2007 Stepneygate scandal** (780 pages of stolen Ferrari IP) and the
**2024 Red Bull Copygate allegations** demonstrated that this data is a
high-value espionage target with catastrophic consequences when compromised.
Yet no public cryptographic security architecture for F1 telemetry exists.

**PitCrypt-F1** fills that gap — a research-grade security framework modelling
what a cryptographically rigorous, FIA-compliant telemetry protection system
looks like in practice, built on real 2025 Mercedes AMG and Red Bull Racing
telemetry data via the FastF1 API.

---

## Architecture
[Mercedes Car Node] ──ECDH+AEAD──► [Relay Node] ──re-encrypt──► [FIA Validator]
[Red Bull Car Node] ──ECDH+AEAD──► [Relay Node] ──re-encrypt──► [FIA Validator]
│                                │                              │
Ed25519 sign                   anomaly filter                 ZKP verify
ZKP commit                     sequence check                 audit log
RBAC enforce                   RBAC enforce                   RBAC enforce

Every packet travels through three cryptographically distinct trust zones.
No node trusts any other by default. Every claim is verified.
Every decision is logged.

---

## Core Security Stack

| Component | Technology | Purpose |
|---|---|---|
| Key Exchange | ECDH (Curve25519) | Session key negotiation per node pair |
| Encryption | AES-256-GCM / ChaCha20-Poly1305 | AEAD per-packet encryption |
| Authentication | Ed25519 signatures | Car-origin packet authentication |
| Integrity Proofs | ZKP Pedersen Commitments (Rust) | Tamper-proof packet integrity |
| Key Rotation | Time + packet-count based | Hard expiry on all session keys |
| Access Control | RBAC (Zero-Trust) | Per-node permission enforcement |
| Threat Model | STRIDE + MITRE ATT&CK | Structured adversarial analysis |
| Compliance | ISO 27001 + NIST CSF | Security control mapping |

---

## Real F1 Data

This project uses **real 2025 Formula 1 telemetry** sourced via the
[FastF1](https://github.com/theOehrly/Fast-F1) Python library from the
official F1 timing API.

| Detail | Info |
|---|---|
| **Teams** | Mercedes AMG Petronas · Red Bull Racing |
| **Races** | Australia · Japan · Bahrain · Saudi Arabia · Monaco · Silverstone · Netherlands · Monza · Baku · Singapore · São Paulo · Qatar · Abu Dhabi |
| **Sessions** | Race (R) · Qualifying (Q) · Sprint (S) |
| **Channels** | Speed · RPM · Throttle · Brake · DRS · Gear · GPS |
| **Total files** | 56 CSV files across 13 circuits |

Telemetry values are used as packet payloads flowing through the secure
pipeline. Anomaly detection thresholds are calibrated empirically from
real observed data ranges — not synthetic assumptions.

---

## Project Structure
PitCrypt-F1/
├── docs/                    # Architecture, threat model, protocol spec, compliance
├── architecture/            # Diagrams and Architecture Decision Records (ADRs)
├── forensic/                # Real telemetry analysis and anomaly calibration
├── data/                    # Processed telemetry and anomaly records
├── car-producer/            # Telemetry packet generation and encryption node
├── relay-node/              # Middle-tier relay with anomaly filtering
├── validator-node/          # FIA endpoint — verification and audit logging
├── iam-module/              # RBAC-enforced zero-trust identity layer
├── zkp-module/              # Rust — Pedersen commitments and ZKP proof system
├── simulations/             # Replay, tamper, IAM breach attack simulations
├── benchmarks/              # Latency, throughput, ZKP timing benchmarks
├── dashboard/               # Streamlit live pipeline visualization
└── paper/                   # LaTeX research paper

---

## Threat Model Summary

| Attack | Simulation | Defence |
|---|---|---|
| Replay Attack | `replay_attack_sim.py` | Sequence numbers + timestamp windows |
| Packet Tampering | `tampering_sim.py` | AEAD auth tag + ZKP proof verification |
| Identity Spoofing | `iam_breach_sim.py` | RBAC enforcement + Ed25519 node identity |
| Man-in-the-Middle | Relay interception model | Re-encryption + trust boundary enforcement |
| Key Compromise | Key rotation stress test | Hard session key expiry + ECDH renegotiation |
| Timing Attack | `jitter_sim.py` | Timestamp validation windows |

Full STRIDE matrix → [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

MITRE ATT&CK mapping → [`docs/MITRE_ATTACK_MAPPING.md`](docs/MITRE_ATTACK_MAPPING.md)

---

## Documentation

| Document | Description |
|---|---|
| [ARCHITECTURE_OVERVIEW](docs/ARCHITECTURE_OVERVIEW.md) | End-to-end system design |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | STRIDE matrix and mitigations |
| [THREAT_INTELLIGENCE](docs/THREAT_INTELLIGENCE.md) | APT groups, CVEs, kill chain |
| [PROTOCOL_SPEC](docs/PROTOCOL_SPEC.md) | Formal protocol and state machine |
| [KEY_MANAGEMENT](docs/KEY_MANAGEMENT.md) | Key hierarchy and rotation policy |
| [ZKP_DESIGN](docs/ZKP_DESIGN.md) | Zero-knowledge proof design |
| [FIA_REGULATION_MAPPING](docs/FIA_REGULATION_MAPPING.md) | 2025 FIA regs mapped to architecture |
| [FORENSIC_ANALYSIS](docs/FORENSIC_ANALYSIS.md) | Real telemetry anomaly findings |
| [COMPLIANCE](docs/COMPLIANCE.md) | ISO 27001 and NIST CSF mapping |
| [INCIDENT_RESPONSE](docs/INCIDENT_RESPONSE.md) | Post-tamper escalation runbook |
| [CLOUD_HARDENING](docs/CLOUD_HARDENING.md) | AWS/Azure deployment security model |
| [SECURITY_BASELINES](docs/SECURITY_BASELINES.md) | Cipher suites and rotation rationale |

---

## Getting Started

### Prerequisites
- Python 3.11+
- Rust (for ZKP module)
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/Tanvi-Badghare/pitcrypt_f1
cd pitcrypt-f1

# Create and activate virtual environment
python -m venv f1env

# Windows
f1env\Scripts\activate.bat

# Mac/Linux
source f1env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download real F1 telemetry data
python fetch_telemetry.py

# Run forensic analysis
python forensic/forensic_analysis.py
python forensic/calibrate_thresholds.py
python forensic/visualize_telemetry.py
```

### Run Attack Simulations
```bash
python simulations/replay_attack_sim.py
python simulations/tampering_sim.py
python simulations/iam_breach_sim.py
```

### Launch Live Dashboard
```bash
streamlit run dashboard/app.py
```

---

## Build Status

| Component | Status |
|---|---|
| Data pipeline (FastF1) | ✅ Complete |
| Forensic analysis | ✅ Complete |
| Anomaly calibration | ✅ Complete |
| Telemetry visualisation | ✅ Complete |
| Crypto engine | 🔄 In Progress |
| Car producer node | 🔄 In Progress |
| Relay node | ⏳ Planned |
| Validator node | ⏳ Planned |
| IAM module | ⏳ Planned |
| ZKP module (Rust) | ⏳ Planned |
| Attack simulations | ⏳ Planned |
| Live dashboard | ⏳ Planned |
| Research paper | ⏳ Planned |

---

## Motivation

> *"As an F1 fan who has watched live telemetry shape race strategy from
> the pit wall, I became curious about a question nobody discusses publicly
> — what actually protects that data? The 2007 Stepneygate scandal and
> 2024 Red Bull Copygate allegations demonstrated that F1 telemetry is a
> high-value espionage target with inadequate public security research.
> PitCrypt-F1 is my attempt to model what a cryptographically rigorous
> answer looks like — not as a fan exercise, but as a serious security
> architecture problem with real regulatory, cryptographic, and
> operational dimensions."*

---

## References

- [FastF1 Library](https://github.com/theOehrly/Fast-F1)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [FIA Formula 1 Technical Regulations 2025](https://www.fia.com)
- Bernstein, D.J. — Curve25519 (2006)
- Bünz et al. — Bulletproofs (2018)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with real F1 data. Designed for real threats.*