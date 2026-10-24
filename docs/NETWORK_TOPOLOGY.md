# Network Topology — PitCrypt-F1

**Document:** `docs/NETWORK_TOPOLOGY.md`  
**Version:** 1.1  
**Project:** PitCrypt-F1  
**Status:** Architecture reference — simulation behavior distinguished from proposed deployment

---

## 1. Purpose

This document describes the logical network topology of PitCrypt-F1, a prototype for securing and validating motorsport telemetry.

It separates two configurations:

1. **Local simulation:** Components communicate through in-process calls where the simulation implementation does not use TCP sockets.
2. **Proposed network deployment:** A possible producer-to-relay-to-validator deployment using TCP endpoints and network-level isolation.

The AWS configuration in this document is a reference design, not evidence of an existing cloud deployment. IP addresses, ports, security groups, managed services, and DNS records are illustrative until configured and verified.

## 2. Topology and trust boundaries

PitCrypt-F1 uses a three-stage logical pipeline:

- **Car producer:** Constructs telemetry packets and applies the configured cryptographic protections.
- **Relay node:** Receives packets, processes and checks them, and forwards accepted data using the relay-to-validator protection context.
- **Validator node:** Performs validation checks, enforces applicable sequence rules, verifies the configured commitment, and records acceptance or rejection decisions.

The producer-to-relay and relay-to-validator links represent separate logical trust zones. The cryptographic protection applied to each link is intended to limit the consequences of compromise or unauthorized access in another part of the pipeline.

Separate session keys do not, by themselves, establish complete isolation. The security of each zone also depends on key lifecycle, endpoint authentication, access controls, process isolation, and the correctness of the implementation.

### 2.1 Logical topology

```text
┌──────────────────┐
│   Car Producer   │
│                  │
│ Telemetry source │
│ Packet creation  │
│ Signing/encrypt. │
└────────┬─────────┘
         │
         │ Producer ↔ Relay
         │ Session A
         ▼
┌──────────────────┐
│    Relay Node    │
│                  │
│ Parse/decrypt    │
│ Validate/filter  │
│ Re-encrypt       │
└────────┬─────────┘
         │
         │ Relay ↔ Validator
         │ Session B
         ▼
┌──────────────────┐
│  Validator Node  │
│                  │
│ Verify signature │
│ Check sequence   │
│ Verify commitment│
│ Audit decision   │
└──────────────────┘
```

This diagram represents logical component relationships. It does not establish physical machine boundaries, network routes, firewall rules, or a deployed FIA endpoint.

## 3. Local simulation topology

### 3.1 Configuration

In the documented simulation configuration, the producer, relay, and validator execute within the local application environment. Simulation communication is performed through in-process function calls rather than actual TCP sockets.

```text
Local host / Python process environment
│
├── Car producer
│   ├── Example node IDs: mercedes_car, redbull_car
│   └── Port: not applicable to in-process calls
│
├── Relay node
│   └── Logical node ID: relay_01
│
└── Validator node
    └── Logical node ID: fia_validator
```

The node identifiers are logical labels. They do not prove that the corresponding nodes are deployed on separate hosts or that a real FIA system is involved.

### 3.2 Simulation trust zones

The intended cryptographic model uses separate protection contexts for the two pipeline links:

```text
Car producer
    │
    │ X25519 key agreement
    │ + configured key derivation
    ▼
Relay node
    │
    │ X25519 key agreement
    │ + configured key derivation
    ▼
Validator node

Session A: producer ↔ relay
Session B: relay ↔ validator
```

The design uses X25519 for key agreement and HKDF-SHA256 for key derivation. The resulting keys are intended to be independent for the two links.

The following details must be verified against the actual execution path before being treated as guarantees:

- Whether each session performs a fresh key agreement or reuses previously established material.
- How peer public keys are authenticated.
- How session identifiers and key context are bound to the handshake.
- How nonces are generated and managed.
- How key expiration, rotation, and revocation work.
- Whether compromise of one endpoint can expose keys or plaintext from another link.

In-process simulation does not provide the same isolation or network-failure characteristics as separate machines communicating over a real network.

### 3.3 Ports in simulation mode

Ports `9001` and `9002` may be used by a networked or live-mode configuration, but they are not applicable to a path that uses only in-process function calls.

Do not infer that TCP listeners are active merely because a configuration file or document mentions these ports.

## 4. Proposed network deployment topology

### 4.1 Status and assumptions

The following AWS design is a proposed deployment pattern for future network-level testing.

It assumes:
- A VPC with private addressing.
- Separate network segments for producer, relay, and validator roles.
- Explicitly restricted security-group rules.
- Private access to required AWS services where supported.
- Independent configuration of identity, key management, logging, monitoring, and storage.

The example CIDRs and instance types are placeholders. They must be adapted to actual requirements, deployment constraints, and cost considerations.

### 4.2 Illustrative AWS layout

```text
┌───────────────────────────────────────────────────────────┐
│                       AWS VPC                              │
│                 Example: 10.0.0.0/16                       │
│                                                           │
│  ┌────────────────────┐  ┌─────────────────────────────┐  │
│  │ Producer subnet    │  │ Relay subnet                │  │
│  │ 10.0.1.0/24        │  │ 10.0.2.0/24                 │  │
│  │                    │  │                             │  │
│  │ Car producer       │  │ Relay node                  │  │
│  │ instance/service   │─►│ instance/service            │  │
│  │                    │  │                             │  │
│  │ No public inbound  │  │ Restricted ingress/egress   │  │
│  └────────────────────┘  └──────────────┬──────────────┘  │
│                                         │                 │
│                                         ▼                 │
│                          ┌─────────────────────────────┐  │
│                          │ Validator subnet            │  │
│                          │ 10.0.3.0/24                 │  │
│                          │                             │  │
│                          │ Validator service           │  │
│                          │ Restricted ingress          │  │
│                          └─────────────────────────────┘  │
│                                                           │
│  Supporting services, if deployed:                         │
│  ├── Key-management service                               │
│  ├── Centralized logging and monitoring                   │
│  └── Protected audit-log storage                          │
└───────────────────────────────────────────────────────────┘
```

This is a conceptual diagram, not an AWS-generated infrastructure diagram. A subnet being private or isolated does not automatically guarantee isolation: route tables, network ACLs, security groups, service endpoints, IAM policies, and administrative access must all be configured appropriately.

### 4.3 Proposed network segmentation

| Segment | Example CIDR | Intended role | Required restriction |
|---|---|---|---|
| Producer subnet | `10.0.1.0/24` | Telemetry generation and transmission | No unsolicited inbound access; allow only necessary destinations |
| Relay subnet | `10.0.2.0/24` | Packet processing and forwarding | Accept traffic only from authorized producers and required administrative sources |
| Validator subnet | `10.0.3.0/24` | Final validation and audit generation | Accept telemetry only from authorized relay endpoints |
| Supporting services | Service-dependent | Key management, logging, monitoring, and storage | Permit only the API calls and identities required for each service |

The proposed design should avoid public IP addresses for components that do not need public reachability. Administrative access should use a controlled mechanism with strong authentication and auditable authorization.

## 5. Proposed security-group rules

These rules describe the intended policy, not an existing AWS configuration. Security groups are stateful, so response traffic for permitted connections is generally handled by the security group. Actual reachability also depends on routing, network ACLs, endpoint policies, and host-level controls.

### 5.1 Producer security group

**Inbound**
- No application ingress by default.
- Add narrowly scoped administrative access only if required.

**Outbound**
- Permit the configured telemetry destination and port on the relay.
- Permit DNS queries to the configured resolver as required.
- Permit only the key-management or other service endpoints actually used by the producer.
- Do not allow general outbound internet access unless a documented requirement exists.

### 5.2 Relay security group

**Inbound**
- Permit the configured producer-to-relay port only from the authorized producer security group or narrowly scoped source addresses.

**Outbound**
- Permit the configured relay-to-validator port only to the authorized validator.
- Permit required DNS resolution.
- Permit necessary service access only if the relay actually uses those services.

### 5.3 Validator security group

**Inbound**
- Permit the configured validator port only from the authorized relay security group or narrowly scoped source addresses.
- Do not expose the validator port publicly.

**Outbound**
- Permit DNS and only the service endpoints required for validator operation.
- Permit audit-storage and monitoring destinations only if the implementation uses them.
- Permit key-management access only if required by the selected key-management design.

### 5.4 Default-deny policy

The proposed policy is to deny unnecessary ingress and egress and allow only documented flows.

A statement such as “default outbound deny all” must be verified in the actual security-group, routing, and host configuration. It should not be described as deployed merely because it appears in this document.

## 6. Network flow and protocol boundaries

### 6.1 Proposed producer-to-relay flow

```text
Car Producer                         Relay
     │                                │
     │ Establish authenticated        │
     │ session using the configured   │
     │ key-agreement protocol         │
     │───────────────────────────────►│
     │                                │
     │ Protected telemetry packets    │
     │───────────────────────────────►│
     │                                │ Parse and validate
     │                                │ applicable checks
```

The design uses X25519 and HKDF-SHA256 for key establishment and derivation, and ChaCha20-Poly1305 for authenticated encryption. Ed25519 is used for signatures in the documented cryptographic design.

The exact handshake message format, authentication of exchanged public keys, wire framing, connection lifecycle, and error handling must be specified and verified against the network-mode implementation.

### 6.2 Proposed relay-to-validator flow

```text
Relay                              Validator
  │                                    │
  │ Establish authenticated            │
  │ session using the configured       │
  │ key-agreement protocol             │
  │───────────────────────────────────►│
  │                                    │
  │ Protected forwarded packet         │
  │───────────────────────────────────►│
  │                                    │ Decrypt as applicable
  │                                    │ Verify signature
  │                                    │ Validate metadata
  │                                    │ Check sequence/replay
  │                                    │ Verify commitment
  │                                    │ Record final decision
```

The relay-to-validator protection context is logically separate from the producer-to-relay context. The relay's processing and re-encryption behavior must be confirmed against the active implementation.

The logical validator is a project component. It must not be described as an actual FIA endpoint or FIA-operated infrastructure.

### 6.3 Packet rejection

Where implemented, validation failures should result in rejection and a suitable audit event. Possible failure categories include malformed packets, cryptographic verification failures, invalid metadata, sequence violations, and commitment mismatches.

The exact rejection reason codes and event behavior must be taken from the current code. Do not assume every category is supported in every component.

### 6.4 Connection security

A future networked deployment should define:
- Peer authentication and trust-anchor distribution.
- Handshake timeouts and connection failure behavior.
- Maximum frame and packet sizes.
- Input parsing limits.
- Connection and request rate limits where appropriate.
- Reconnection and session invalidation behavior.
- Key rotation and old-key rejection rules.
- Logging for connection failures and security-relevant events.

These requirements are deployment considerations, not evidence that the current simulation already implements them.

## 7. Port reference

The following ports are proposed for a networked configuration.

| Port | Protocol | Direction | Purpose | Status |
|---|---|---|---|---|
| `9001` | TCP | Producer → relay | Telemetry ingestion | Proposed; verify live-mode listener and client |
| `9002` | TCP | Relay → validator | Telemetry forwarding | Proposed; verify live-mode listener and client |
| `443` | HTTPS | Relevant node → service endpoint | AWS API access, if required | Conditional on selected services and implementation |
| `53` | DNS over UDP/TCP as configured | Node → configured resolver | Name resolution | Conditional on deployment DNS configuration |

Ports `9001` and `9002` do not establish that the local simulation opens network sockets. Port `443` does not establish that every component accesses AWS services, and DNS port `53` does not establish the use of Route 53.

## 8. Cryptographic and key-management considerations

### 8.1 Algorithms

The documented cryptographic design includes:

- **Ed25519:** Digital signatures.
- **X25519:** Key agreement.
- **HKDF-SHA256:** Key derivation.
- **ChaCha20-Poly1305:** Authenticated encryption.

The presence of these algorithms does not, by itself, guarantee secure end-to-end operation. Security also depends on correct protocol construction, authenticated peer identity, safe nonce use, key separation, error handling, and lifecycle management.

### 8.2 AWS KMS compatibility

AWS KMS must not be described as storing or directly using the project's Ed25519 signing key until the selected AWS service, key specification, supported operations, and integration have been confirmed.

If the existing implementation uses local Ed25519 keys, a proposed AWS deployment would need an explicitly designed key-management approach. Options should be evaluated against the actual cryptographic requirements rather than assuming that all key types are supported by every managed service.

Do not include real key ARNs, credentials, secrets, or other sensitive configuration values in this document.

### 8.3 Key rotation

A rotation policy should specify:
- The event or interval that triggers rotation.
- Which component initiates and participates in rotation.
- How new key material is authenticated and distributed.
- How in-flight packets and overlapping sessions are handled.
- How old keys are invalidated.
- How rotation failures are logged and recovered from.

The earlier design described rotation at 300 seconds or 10,000 packets. Those thresholds must be treated as proposed until the active implementation and tests confirm the trigger, behavior, and guarantees.

No fixed rotation interval or seamless/nonblocking rotation guarantee is made by this document.

## 9. Latency and performance budget

### 9.1 Workload assumptions

For an illustrative 100 Hz workload:

\[
T_{\text{interval}} = \frac{1}{100}\text{ s} = 10\text{ ms}
\]

This is the interval between generated packets under that assumed rate. It is not automatically a proven end-to-end latency deadline for the application.

A networked system's observed latency may include:

- Packet serialization and parsing.
- Cryptographic operations.
- Relay processing and re-encryption.
- Queueing and scheduling.
- Network transport and retransmission behavior.
- Validator processing.
- Audit logging and persistence.

### 9.2 Measurement status

No per-operation or end-to-end latency figures are asserted in this document.

Previously proposed values for signature, encryption, decryption, handshake, commitment verification, and rotation must be treated as unverified until reproducible benchmark results are available.

A valid benchmark should identify:
- Hardware and operating system.
- Python and dependency versions.
- Packet size and telemetry workload.
- Packet rate and concurrency.
- Warm-up and measurement duration.
- Median, p95, and p99 end-to-end latency.
- Throughput, packet loss, rejection counts, and errors.
- Whether audit persistence and key rotation were enabled.

The Python SHA-256 commitment check is not a zero-knowledge proof. No ZKP latency or proof-generation claim is made here.

A conclusion that the pipeline meets a 10 ms target should only be made after measuring end-to-end behavior under a documented workload.

## 10. Data volume and bandwidth

The following calculations are illustrative and use an assumed fixed packet size and packet rate. They are not measured telemetry characteristics.

Assumptions:
- Packet rate: 100 packets/second.
- Average packet size: 180 bytes.
- Session duration: 90 minutes.
- Number of races per season: 23.

| Metric | Calculation | Approximate result |
|---|---|---:|
| Data rate | 100 × 180 bytes/second | 18,000 bytes/second |
| Per minute | 18,000 × 60 bytes | 1.08 MB/minute |
| Per 90-minute session | 18,000 × 5,400 bytes | 97.2 MB |
| Per 23 sessions | 97.2 × 23 MB | 2.24 GB |

These estimates exclude additional transport overhead, retransmissions, connection setup, audit records, metadata outside the assumed packet size, backups, and replication.

Actual volume depends on the encoded packet format, telemetry sampling, number of channels, session duration, packet loss, and whether logs or raw telemetry are also stored.

Any statement about real F1 telemetry frequencies or actual data rates should be supported by a separately documented dataset analysis or authoritative source.

## 11. DNS and service discovery

### 11.1 Proposed private DNS

A networked deployment may use private DNS names for service discovery. For example:

| Illustrative hostname | Intended role | Example address |
|---|---|---|
| `car.pitcrypt.internal` | Producer | `10.0.1.10` |
| `relay.pitcrypt.internal` | Relay | `10.0.2.10` |
| `validator.pitcrypt.internal` | Validator | `10.0.3.10` |

These records are examples only. They do not establish that a private hosted zone exists or that these addresses are assigned.

### 11.2 DNS security

A proposed deployment should:
- Use a controlled resolver and explicitly defined private DNS configuration.
- Avoid exposing internal service names unnecessarily.
- Restrict DNS egress to the intended resolver where feasible.
- Validate that resolved addresses belong to expected network ranges.
- Avoid treating DNS resolution as proof of peer identity.
- Use cryptographic peer authentication independently of DNS.

Private DNS reduces reliance on public name resolution for internal services, but it does not replace endpoint authentication or network access controls.

## 12. Monitoring and audit services

The proposed architecture may use managed services for monitoring and audit retention. These integrations are optional until configured and tested.

| Service | Proposed purpose | Verification required |
|---|---|---|
| AWS KMS or another suitable key-management system | Managed key operations where compatible | Key type, supported operations, access policy, and application integration |
| AWS CloudTrail | Record applicable AWS API activity | Account configuration, trail scope, retention, and access controls |
| Amazon CloudWatch | Collect metrics and logs and configure alarms | Instrumentation, metric definitions, alarm thresholds, and delivery |
| Amazon S3 | Store audit exports or backups | Bucket policy, encryption, versioning, retention, and deletion protections |
| AWS Secrets Manager | Store supported application secrets | Secret inventory, access policies, rotation, and application integration |
| Amazon Route 53 private hosted zone | Resolve internal service names | Zone configuration, records, resolver behavior, and access scope |

CloudTrail records applicable AWS account and API activity; it does not automatically capture every application-level packet-validation event. Application audit events require explicit instrumentation and delivery.

Similarly, S3 storage alone does not make application logs immutable. Stronger retention or tamper-resistance guarantees require appropriate configuration and independent verification.

## 13. Network failure and resilience considerations

A networked deployment should be tested for:
- Relay or validator unavailability.
- Connection resets and timeouts.
- Packet loss and delayed delivery.
- Duplicate or reordered packets.
- Invalid or truncated frames.
- Oversized packets and malformed input.
- Reconnection and session re-establishment.
- Key-rotation failure during an active session.
- Audit-storage or monitoring endpoint unavailability.

The design should explicitly define whether each failure causes rejection, retry, buffering, a degraded mode, or shutdown.

Retries must not accidentally bypass replay protection or produce duplicate acceptance decisions. Buffering and retry policies should have bounded memory usage and documented ordering semantics.

Local simulation results do not establish the behavior of a distributed deployment under real network faults.

## 14. Security assumptions and limitations

The proposed topology depends on assumptions that must be verified before deployment:

1. **Endpoint identity:** Public keys and peer identities are authenticated through a documented trust mechanism.
2. **Network isolation:** Security groups, routing, host firewalls, and administrative access are configured and tested.
3. **Key lifecycle:** Key generation, rotation, revocation, and compromise handling are defined.
4. **Transport behavior:** Network framing, timeouts, reconnection, and malformed input are handled safely.
5. **Audit protection:** Application events are retained and protected according to a defined policy.
6. **Monitoring:** Required metrics and alerts are actually generated and delivered.
7. **Performance:** Throughput and latency are measured under representative loads.
8. **Deployment scope:** No real F1 trackside deployment, FIA-operated endpoint, or production approval is implied.

The architecture should not be described as production-ready until these assumptions have been evaluated against the actual deployment.

## 15. Deployment verification checklist

Before treating the networked topology as implemented, verify the following.

### Application and transport
- [ ] Confirm whether the selected execution mode uses in-process calls or TCP sockets.
- [ ] Confirm that the expected TCP listeners and client connections exist.
- [ ] Verify actual bind addresses, ports, and frame formats.
- [ ] Test timeouts, malformed frames, oversized packets, and connection failures.
- [ ] Confirm that network-mode peer authentication matches the documented protocol.

### Network configuration
- [ ] Confirm actual VPC and subnet CIDRs.
- [ ] Review route tables and network ACLs.
- [ ] Verify inbound and outbound security-group rules.
- [ ] Confirm that public reachability is disabled unless required.
- [ ] Verify the configured DNS resolver and any private hosted zones.
- [ ] Test allowed and denied flows from each component.

### Cryptography and keys
- [ ] Confirm the active cryptographic algorithms and their implementation.
- [ ] Verify public-key authentication and session-key derivation.
- [ ] Review nonce uniqueness and key separation.
- [ ] Confirm key rotation and revocation behavior.
- [ ] Verify that any proposed managed key service supports the required key type and operations.

### Observability and storage
- [ ] Confirm which application events are logged.
- [ ] Verify monitoring instrumentation and alarm behavior.
- [ ] Verify audit-export permissions and retention.
- [ ] Test behavior when logging or storage becomes unavailable.
- [ ] Confirm the integrity guarantees, if any, of retained records.

### Performance
- [ ] Benchmark the complete pipeline with a documented workload.
- [ ] Record throughput, median latency, p95 latency, packet loss, and rejection counts.
- [ ] Repeat tests with logging enabled and representative failure conditions.
- [ ] Document the hardware, software versions, configuration, and measurement procedure.

## 16. Related documentation

- `ARCHITECTURE_OVERVIEW.md` — logical architecture and component responsibilities.
- `PROTOCOL_SPEC.md` — protocol behavior and validation checks.
- `PACKET_FORMAT.md` — packet header and telemetry fields.
- `THREAT_MODEL.md` — threats, trust boundaries, and security assumptions.
- `AUDIT_TRAIL.md` — audit events, storage behavior, and logging limitations.
- `COMPLIANCE.md` — preliminary ISO 27001 and NIST CSF alignment.
- `FIA_REGULATION_MAPPING.md` — preliminary motorsport-regulatory analysis; not an official compliance assessment.

---

## 17. Summary

PitCrypt-F1 currently has a documented logical producer-to-relay-to-validator pipeline and a local simulation mode that uses in-process communication. A TCP-based, segmented AWS topology is described here as a possible future deployment, not as an existing production environment.

All deployment-specific claims—including network rules, cloud integrations, key rotation, DNS records, and performance guarantees—must be supported by configuration, implementation, and reproducible test evidence before this document is labelled authoritative for a deployed system.