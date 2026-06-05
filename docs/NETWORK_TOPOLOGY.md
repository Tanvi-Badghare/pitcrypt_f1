# Network Topology — PitCrypt-F1

**Document:** NETWORK_TOPOLOGY.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Status:** Authoritative

---

## Overview

This document describes the network topology of
PitCrypt-F1 in both simulation and production
deployment configurations.

---

## Simulation Topology

In simulation mode all three nodes run on localhost.
Network communication is simulated via in-process
function calls — no actual TCP sockets used in
`run_simulation()` methods.
localhost
│
├── car-producer (in-process)
│   Port: N/A (simulation mode)
│   node_id: mercedes_car / redbull_car
│
├── relay-node (in-process)
│   Port: 9001 (live mode)
│   node_id: relay_01
│
└── validator-node (in-process)
Port: 9002 (live mode)
node_id: fia_validator

**ECDH sessions in simulation:**
mercedes_car ←──── X25519 ECDH ────► relay_01
Session Key A
relay_01     ←──── X25519 ECDH ────► fia_validator
Session Key B
Session Key A ≠ Session Key B
Two independent trust zones
---

## Production Topology — AWS Deployment
┌─────────────────────────────────────────────────────────────┐
│                        AWS VPC                              │
│                   CIDR: 10.0.0.0/16                         │
│                                                             │
│  ┌──────────────────┐    ┌──────────────────┐              │
│  │  Public Subnet   │    │  Private Subnet  │              │
│  │  10.0.1.0/24     │    │  10.0.2.0/24     │              │
│  │                  │    │                  │              │
│  │  ┌────────────┐  │    │  ┌────────────┐  │              │
│  │  │ Car Node   │  │    │  │  Relay     │  │              │
│  │  │ Simulator  │  │    │  │  Node      │  │              │
│  │  │            │──┼────┼─►│            │  │              │
│  │  │ EC2 t3.med │  │    │  │ EC2 t3.med │  │              │
│  │  │ Port: 9001 │  │    │  │ Port: 9001 │  │              │
│  │  └────────────┘  │    │  │ Port: 9002 │  │              │
│  │                  │    │  └──────┬─────┘  │              │
│  └──────────────────┘    │         │        │              │
│                          └─────────┼────────┘              │
│                                    │                        │
│  ┌─────────────────────────────────▼──────────────────┐    │
│  │              Isolated Subnet  10.0.3.0/24           │    │
│  │                                                     │    │
│  │  ┌──────────────────────────────────────────────┐   │    │
│  │  │          FIA Validator Node                  │   │    │
│  │  │                                              │   │    │
│  │  │  EC2 t3.medium                               │   │    │
│  │  │  Port: 9002 (inbound from relay only)        │   │    │
│  │  │  KMS: arn:aws:kms:eu-west-1:...:key/...      │   │    │
│  │  └──────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Supporting Services                    │   │
│  │                                                      │   │
│  │  AWS KMS         ← Ed25519 identity key HSM storage  │   │
│  │  CloudTrail      ← API audit logging                 │   │
│  │  CloudWatch      ← Metrics and alerting              │   │
│  │  S3              ← Audit log backup                  │   │
│  │  Secrets Manager ← Configuration secrets             │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
---

## Security Group Rules

### Car Node Security Group
Inbound:
None — car node does not accept inbound connections
Outbound:
TCP port 9001 → Relay Node IP only
HTTPS 443     → AWS KMS endpoint (signing)
DNS 53        → VPC resolver only
### Relay Node Security Group
Inbound:
TCP port 9001 → Car Node IP only
Outbound:
TCP port 9002 → Validator Node IP only
DNS 53        → VPC resolver only
### Validator Node Security Group
Inbound:
TCP port 9002 → Relay Node IP only
Outbound:
HTTPS 443     → AWS KMS endpoint (key registration)
HTTPS 443     → S3 endpoint (audit log backup)
HTTPS 443     → CloudWatch endpoint (metrics)
DNS 53        → VPC resolver only
**Default outbound rule:** DENY ALL — only
explicitly listed destinations permitted.

---

## Network Flow Diagram
Car Node                 Relay Node            FIA Validator
│                        │                       │
│  TCP:9001              │                       │
│─── ECDH handshake ────►│                       │
│◄── relay pub key ──────│                       │
│                        │  TCP:9002             │
│                        │─── ECDH handshake ───►│
│                        │◄── validator pub key ─│
│                        │                       │
│  [Session established] │  [Session established]│
│                        │                       │
│  Packet 1:             │                       │
│  nonce+ciphertext+sig  │                       │
│───────────────────────►│                       │
│                        │  parse+decrypt+check  │
│                        │  re-encrypt           │
│                        │─────────────────────► │
│                        │                       │ verify
│                        │                       │ log
│                        │                       │ ACCEPT
│                        │                       │
│  Packet 2...N          │                       │
│───────────────────────►│─────────────────────►│
│                        │                       │
│  [Key rotation at 300s or 10K packets]         │
│───── new pub key ──────►│                      │
│◄──── new pub key ───────│                      │
│                        │──── new pub key ─────►│
│                        │◄─── new pub key ──────│
---

## Port Reference

| Port | Protocol | Direction | Service |
|---|---|---|---|
| 9001 | TCP | Car → Relay | Telemetry ingestion |
| 9002 | TCP | Relay → Validator | Telemetry forwarding |
| 443 | HTTPS | Nodes → AWS | KMS, S3, CloudWatch |
| 53 | UDP/TCP | Nodes → VPC | DNS resolution |

---

## Latency Budget

At 100Hz packet rate the pipeline has 10ms per
packet budget. Cryptographic overhead measured
in simulation:

| Operation | Typical Latency |
|---|---|
| Ed25519 sign | ~0.2ms |
| ChaCha20 encrypt (140B) | ~0.05ms |
| ECDH handshake | ~1.5ms (one-time) |
| Ed25519 verify | ~0.2ms |
| ChaCha20 decrypt | ~0.05ms |
| ZKP commitment | ~0.3ms |
| **Total per packet** | **~0.8ms** |

Pipeline operates well within 10ms budget.
Key rotation adds ~1.5ms one-time overhead
per 300-second window.

---

## Data Volume

At sustained 100Hz with 180-byte average packet:
Per second:    100 × 180B  = 18,000 bytes = 18 KB/s
Per minute:    60 × 18KB   = 1.08 MB/min
Per race:      ~90min       = ~97 MB
Per season:    ~23 races    = ~2.2 GB
Network bandwidth well within standard ethernet
capacity. FastF1 data confirms actual F1 telemetry
is approximately 50-150Hz depending on session type.

---

## DNS and Service Discovery

In production, nodes discover each other via
private Route 53 DNS:
car.pitcrypt.internal     → 10.0.1.10
relay.pitcrypt.internal   → 10.0.2.10
validator.pitcrypt.internal → 10.0.3.10
DNS resolution restricted to VPC resolver —
no public DNS for internal endpoints.

---

## See Also

- `docs/ARCHITECTURE_OVERVIEW.md` — Component architecture
- `docs/CLOUD_HARDENING.md` — AWS security configuration
- `relay-node/config/relay.yaml` — Relay network config
- `validator-node/config/validator.yaml` — Validator config