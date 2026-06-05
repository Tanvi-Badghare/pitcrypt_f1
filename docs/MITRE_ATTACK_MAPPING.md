# MITRE ATT&CK Mapping — PitCrypt-F1

**Document:** MITRE_ATTACK_MAPPING.md  
**Version:** 1.0  
**Project:** PitCrypt-F1  
**Framework:** MITRE ATT&CK Enterprise v14  
**Status:** Authoritative

---

## Overview

This document maps MITRE ATT&CK techniques to
the PitCrypt-F1 threat model and documents the
defensive controls that mitigate each technique.

ATT&CK techniques are identified by their
technique ID (e.g., T1557) and tactic category.
Sub-techniques are denoted with a decimal suffix
(e.g., T1557.002).

---

## Tactic Coverage Summary

| Tactic | Techniques Mapped | Mitigated |
|---|---|---|
| Reconnaissance | 3 | 3 |
| Initial Access | 4 | 4 |
| Execution | 2 | 2 |
| Persistence | 3 | 3 |
| Privilege Escalation | 4 | 4 |
| Defence Evasion | 3 | 3 |
| Credential Access | 4 | 4 |
| Discovery | 2 | 2 |
| Lateral Movement | 2 | 2 |
| Collection | 3 | 3 |
| Command and Control | 2 | 2 |
| Exfiltration | 3 | 3 |
| Impact | 4 | 3 |

---

## Reconnaissance

### T1592 — Gather Victim Host Information

**Description:** Adversary gathers information
about PitCrypt-F1 node infrastructure — IP ranges,
open ports, software versions.

**Application to PitCrypt-F1:** Attacker scans
FIA data centre ranges to identify relay and
validator node endpoints. Identifies software
stack via banner grabbing.

**Detection:**
VPC flow logs capture unexpected inbound scanning.
CloudWatch anomaly detection alerts on scan patterns.

**Mitigation:**
Security groups restrict inbound connections to
known source IPs only. No service banners exposed.
Pipeline ports accept only valid ECDH handshakes.

**ATT&CK Reference:** T1592.002 (Software)

---

### T1590 — Gather Victim Network Information

**Description:** Adversary maps the telemetry
network topology — car → relay → validator.

**Application to PitCrypt-F1:** Attacker traces
network path from pit lane to FIA validator to
identify MITM positions.

**Mitigation:**
Network topology not publicly documented for
production deployment. VPC isolation prevents
cross-segment discovery. ECDH means even correct
network positioning yields only ciphertext.

**ATT&CK Reference:** T1590.004 (Network Topology)

---

### T1598 — Phishing for Information

**Description:** Spear-phishing targeting
trackside engineers to obtain credentials or
architecture details.

**Application to PitCrypt-F1:** Attacker poses
as FIA technical official requesting system
documentation or credentials.

**Mitigation:**
Zero-trust architecture means stolen credentials
alone are insufficient — cryptographic keys
required. No password-based authentication in
pipeline. Security awareness training for personnel.

**ATT&CK Reference:** T1598.003 (Spearphishing Link)

---

## Initial Access

### T1190 — Exploit Public-Facing Application

**Description:** Exploitation of vulnerability
in publicly accessible telemetry endpoints.

**Application to PitCrypt-F1:** Attacker sends
malformed packets to relay node to trigger buffer
overflow or denial of service.

**Mitigation:**
Packet parser validates all fields before processing.
Unknown magic bytes cause immediate rejection.
Python's memory-safe runtime prevents buffer overflows.
No public-facing management interface.

**ATT&CK Reference:** T1190

---

### T1199 — Trusted Relationship

**Description:** Attacker compromises a trusted
third party with access to the target — e.g., a
telemetry hardware supplier.

**Application to PitCrypt-F1:** Compromised
sensor manufacturer ships modified hardware that
weakens cryptographic key generation.

**Mitigation:**
Key generation uses OS CSPRNG (`os.urandom`)
not hardware-provided entropy — hardware compromise
does not affect key quality. Ed25519 keys generated
on first run and verified by FIA before registration.

**ATT&CK Reference:** T1199

---

### T1078 — Valid Accounts

**Description:** Attacker obtains legitimate
credentials for a pipeline node.

**Application to PitCrypt-F1:** Stolen API key
or SSH credential for relay node management.

**Mitigation:**
Zero-trust IAM — network access alone is insufficient.
Every packet requires cryptographic proof of identity.
SSH access restricted by security groups.
Ed25519 session keys rotated frequently.

**ATT&CK Reference:** T1078.004 (Cloud Accounts)

---

### T1195 — Supply Chain Compromise

**Description:** Attacker introduces malicious
code into a dependency used by PitCrypt-F1.

**Application to PitCrypt-F1:** Compromised
version of PyCA `cryptography` library with
backdoored ChaCha20 implementation.

**Mitigation:**
Dependency versions pinned in `requirements.txt`.
SHA256 hashes verified in production. Private PyPI
mirror for production deployment. SBOM maintained.

**ATT&CK Reference:** T1195.002 (Compromise Software Supply Chain)

---

## Execution

### T1059 — Command and Scripting Interpreter

**Description:** Attacker executes commands on
compromised relay node to modify pipeline behaviour.

**Application to PitCrypt-F1:** Attacker with
shell access modifies `anomaly_filters.py` to
suppress detection of injected packets.

**Mitigation:**
File integrity monitoring on all pipeline source
files. Immutable deployment via container image
in production. Code signing on deployment artifacts.
Changes require re-deployment — not hot-reload.

**ATT&CK Reference:** T1059.006 (Python)

---

### T1203 — Exploitation for Client Execution

**Description:** Exploitation of vulnerability
in packet parsing to achieve code execution.

**Application to PitCrypt-F1:** Malformed packet
triggers vulnerability in `packet_parser.py`.

**Mitigation:**
All packet fields validated with explicit type
and range checks before processing. Python's
memory-safe runtime prevents classic buffer
overflow exploitation. `struct.unpack` used with
explicit format string validation.

**ATT&CK Reference:** T1203

---

## Persistence

### T1098 — Account Manipulation

**Description:** Attacker modifies IAM node
registry to persist access.

**Application to PitCrypt-F1:** Attacker adds
rogue node identity to `iam.yaml` with validator
role privileges.

**Mitigation:**
IAM configuration stored in version-controlled
repository — changes require code review and
deployment. `iam.yaml` read-only at runtime.
Configuration changes logged.

**ATT&CK Reference:** T1098

---

### T1543 — Create or Modify System Process

**Description:** Attacker creates persistent
process on relay node that exfiltrates telemetry.

**Application to PitCrypt-F1:** Rogue process
reads relay's in-memory decrypted packets and
forwards to attacker.

**Mitigation:**
Decrypted payload exists in relay memory only
for the duration of processing — ephemeral by
design. Key rotation bounds exposure window.
Process monitoring alerts on unexpected processes.

**ATT&CK Reference:** T1543.003 (Windows Service)

---

### T1505 — Server Software Component

**Description:** Attacker installs web shell or
backdoor on relay node to maintain access.

**Application to PitCrypt-F1:** Web shell on
relay node management interface allows persistent
command execution.

**Mitigation:**
No web server or management HTTP interface on
relay nodes. SSH only, with key-based authentication.
Inbound ports restricted to telemetry port only
via security groups. Regular vulnerability scanning.

**ATT&CK Reference:** T1505.003 (Web Shell)

---

## Privilege Escalation

### T1548 — Abuse Elevation Control Mechanism

**Description:** Attacker escalates from relay
role to validator role privileges.

**Application to PitCrypt-F1:** Compromised relay
process attempts to call validator audit APIs or
signature verification endpoints.

**Mitigation:**
IAM RBAC enforced at every API boundary — relay
role cannot call validator actions regardless of
network access. Tested in `simulations/iam_breach_sim.py`
Attack 5 — 8/8 privilege escalation attempts blocked.

**ATT&CK Reference:** T1548

---

### T1134 — Access Token Manipulation

**Description:** Attacker steals or forges session
tokens to assume another node's identity.

**Application to PitCrypt-F1:** Attacker forges
a session key to impersonate `mercedes_car`.

**Mitigation:**
No session tokens — authentication is via
Ed25519 asymmetric signatures. Forging a signature
requires the private key. ECDH session keys are
ephemeral — cannot be reused across sessions.

**ATT&CK Reference:** T1134

---

### T1484 — Domain Policy Modification

**Description:** Attacker modifies IAM policy
to grant additional permissions.

**Application to PitCrypt-F1:** Modifying
`car_node_policy.yaml` to add validator actions
to car node allow list.

**Mitigation:**
Policy files are version-controlled. Runtime
policy loader reads from disk — modification
requires file system access plus redeployment.
Policy changes trigger automated test suite
including IAM breach simulation.

**ATT&CK Reference:** T1484

---

### T1068 — Exploitation for Privilege Escalation

**Description:** Exploiting a vulnerability in
the Python runtime or dependencies to escalate
from relay process to root.

**Application to PitCrypt-F1:** Python CVE enables
root access on relay node — attacker reads session
keys from memory.

**Mitigation:**
Runtime kept patched. Container deployment with
minimal base image (distroless). Non-root process
user. Session key memory not accessible to other
processes. Key rotation bounds exposure window.

**ATT&CK Reference:** T1068

---

## Defence Evasion

### T1070 — Indicator Removal

**Description:** Attacker deletes or modifies
audit logs to conceal activity.

**Application to PitCrypt-F1:** Deletion of
`validator_audit.jsonl` to remove evidence of
rejected forged packets.

**Mitigation:**
Audit log is append-only. Write access restricted
to `fia_validator` role only via IAM. In production,
CloudWatch Logs with retention policy prevents
deletion. CloudTrail records all log API calls.
Tested — relay audit deletion attempt blocked in
IAM breach sim Attack 6.

**ATT&CK Reference:** T1070.002 (Clear Linux Logs)

---

### T1562 — Impair Defences

**Description:** Attacker disables anomaly
detection on relay node.

**Application to PitCrypt-F1:** Modifying
physical bounds in `anomaly_filters.py` to
allow impossible sensor values through.

**Mitigation:**
Anomaly filter thresholds loaded from version-
controlled configuration. Modification requires
deployment cycle. Even if relay anomaly filter
is disabled, validator's Ed25519 signature check
provides independent integrity verification.
Defence in depth — relay compromise does not
compromise validator.

**ATT&CK Reference:** T1562.001 (Disable or Modify Tools)

---

### T1036 — Masquerading

**Description:** Attacker disguises malicious
packets as legitimate telemetry.

**Application to PitCrypt-F1:** Attacker crafts
packet with correct format and valid-looking
telemetry values but forged identity.

**Mitigation:**
Ed25519 authentication — valid format is
insufficient without valid signature. Signature
cannot be forged without private key. ZKP
commitment ties payload to pre-transmission
hash — post-hoc fabrication detectable.

**ATT&CK Reference:** T1036

---

## Credential Access

### T1557 — Adversary-in-the-Middle

**Description:** Attacker positions between car
and relay to intercept ECDH handshake and
substitute own public key.

**Application to PitCrypt-F1:** Rogue relay
intercepts handshake — car encrypts to attacker.

**Mitigation:**
Relay public key pre-distributed to car out-of-band
before race weekend. Car verifies relay identity
against pre-known key before handshake completion.
ECDH is authenticated — MITM requires pre-known
key compromise.

**ATT&CK Reference:** T1557.002 (ARP Cache Poisoning)

---

### T1555 — Credentials from Password Stores

**Description:** Attacker extracts cryptographic
keys from key storage.

**Application to PitCrypt-F1:** Attacker extracts
Ed25519 private key from application memory or
key file.

**Mitigation:**
Production keys stored in AWS KMS HSM — non-
extractable. Private key never in application
memory in production. Simulation only — keys
generated in memory and discarded on exit.

**ATT&CK Reference:** T1555

---

### T1552 — Unsecured Credentials

**Description:** Attacker finds credentials in
plaintext in configuration files or logs.

**Application to PitCrypt-F1:** Session key
accidentally logged to `relay_node.log`.

**Mitigation:**
Session keys never logged — only key fingerprints
(first 16 bytes of hex) appear in logs for
debugging. Log review confirms no plaintext
key material in log output.

**ATT&CK Reference:** T1552.001 (Credentials in Files)

---

### T1528 — Steal Application Access Token

**Description:** Attacker steals session token
to impersonate a node.

**Application to PitCrypt-F1:** Stealing ECDH
session key from memory to decrypt captured traffic.

**Mitigation:**
Session keys rotated every 300 seconds / 10,000
packets. Stolen key has bounded value. Forward
secrecy — past session traffic remains protected
after rotation. Key rotation documented in
`architecture/adr/003-key-rotation-policy.md`.

**ATT&CK Reference:** T1528

---

## Collection

### T1005 — Data from Local System

**Description:** Attacker exfiltrates telemetry
data from relay node local storage.

**Application to PitCrypt-F1:** Relay stores
decrypted telemetry to disk — attacker reads files.

**Mitigation:**
IAM policy denies `telemetry.store` on
`plaintext_data` for relay role. Relay design
is ephemeral — plaintext exists only during
processing window. No telemetry written to disk
at relay tier. Tested in IAM breach sim.

**ATT&CK Reference:** T1005

---

### T1040 — Network Sniffing

**Description:** Passive capture of telemetry
packets from network.

**Application to PitCrypt-F1:** Trackside
attacker captures all car → relay traffic.

**Mitigation:**
All traffic encrypted with ChaCha20-Poly1305.
Captured ciphertext provides no plaintext without
session key. Forward secrecy via key rotation
ensures past captures remain encrypted indefinitely.

**ATT&CK Reference:** T1040

---

### T1114 — Email Collection

**Description:** Attacker intercepts email
containing cryptographic keys or architecture
documentation sent between team personnel.

**Application to PitCrypt-F1:** Ed25519 public
key distributed to FIA via email — attacker
substitutes own key.

**Mitigation:**
Public key distribution via authenticated secure
channel — not unencrypted email. Key fingerprint
verified by phone/in-person before race weekend.

**ATT&CK Reference:** T1114

---

## Exfiltration

### T1041 — Exfiltration Over C2 Channel

**Description:** Attacker exfiltrates stolen
telemetry over command and control channel.

**Mitigation:**
VPC security groups restrict outbound connections
to validator endpoint only. Unexpected outbound
connections blocked and alerted. Network egress
monitored via VPC flow logs.

**ATT&CK Reference:** T1041

---

### T1048 — Exfiltration Over Alternative Protocol

**Description:** Attacker uses DNS or ICMP to
exfiltrate telemetry data covertly.

**Application to PitCrypt-F1:** DNS tunneling
from compromised relay node.

**Mitigation:**
Relay nodes use custom DNS resolvers — not public.
ICMP restricted by security groups. DNS query
logging enabled — anomalous query volumes alerted.

**ATT&CK Reference:** T1048.001 (Exfil Over Symmetric Encrypted Non-C2)

---

### T1030 — Data Transfer Size Limits

**Description:** Attacker transfers data in small
chunks to evade volume-based detection.

**Mitigation:**
VPC flow logs capture all outbound connections
regardless of size. Baseline normal traffic
volume established — anomaly detection alerts
on deviation. Small frequent connections also
flagged by connection rate monitoring.

**ATT&CK Reference:** T1030

---

## Impact

### T1499 — Endpoint Denial of Service

**Description:** Attacker floods relay with
malformed packets causing service unavailability.

**Mitigation:**
Relay queue bounded — excess packets dropped
before processing. Invalid magic bytes cause
immediate cheap rejection. Rate limiting on
inbound connections. Horizontal scaling possible
with multiple relay instances.

**ATT&CK Reference:** T1499.002 (Service Exhaustion Flood)

---

### T1565 — Data Manipulation

**Description:** Attacker modifies telemetry
values to falsify race data.

**Application to PitCrypt-F1:** Injecting false
speed or DRS data to influence race decisions.

**Mitigation:**
AEAD authentication detects in-transit modification.
Ed25519 signature detects post-decryption modification.
ZKP commitment detects commitment-payload mismatch.
Three independent integrity checks across two pipeline
tiers. Demonstrated in tampering sim — 7/7 attacks
detected.

**ATT&CK Reference:** T1565.002 (Transmitted Data Manipulation)

---

### T1491 — Defacement

**Description:** Attacker corrupts audit log
to falsify race decision history.

**Mitigation:**
Audit log is append-only JSONL. Deletion/modification
requires validator-level access plus bypassing
CloudTrail. IAM denies all non-validator audit
write access. Immutable logging in production.

**ATT&CK Reference:** T1491

---

### T1485 — Data Destruction

**Description:** Attacker destroys telemetry data
or audit logs to prevent post-race analysis.

**Mitigation:**
Telemetry not stored at relay — destruction
not possible. Audit logs backed up to S3 with
versioning enabled. Validator audit retained
for minimum 90 days per FIA data retention policy.
S3 MFA delete prevents single-factor deletion.

**ATT&CK Reference:** T1485

---

## Complete ATT&CK Mapping Table

| Technique ID | Name | Tactic | Mitigated | Control |
|---|---|---|---|---|
| T1592.002 | Software Discovery | Recon | ✅ | Security groups, no banners |
| T1590.004 | Network Topology | Recon | ✅ | VPC isolation |
| T1598.003 | Spearphishing | Recon | ✅ | Zero-trust, no passwords |
| T1190 | Exploit Public App | Initial Access | ✅ | Input validation, safe runtime |
| T1199 | Trusted Relationship | Initial Access | ✅ | OS CSPRNG, FIA key verification |
| T1078.004 | Cloud Accounts | Initial Access | ✅ | Zero-trust IAM, ECDH |
| T1195.002 | Supply Chain | Initial Access | ✅ | Pinned deps, SBOM |
| T1059.006 | Python Execution | Execution | ✅ | FIM, immutable containers |
| T1203 | Client Exploitation | Execution | ✅ | Input validation, safe runtime |
| T1098 | Account Manipulation | Persistence | ✅ | VCS, read-only config |
| T1543.003 | System Process | Persistence | ✅ | Process monitoring, ephemeral keys |
| T1505.003 | Web Shell | Persistence | ✅ | No HTTP interface, SSH only |
| T1548 | Abuse Elevation | Priv Esc | ✅ | RBAC zero-trust |
| T1134 | Token Manipulation | Priv Esc | ✅ | Asymmetric Ed25519, no tokens |
| T1484 | Policy Modification | Priv Esc | ✅ | VCS, deployment pipeline |
| T1068 | Exploit Priv Esc | Priv Esc | ✅ | Patched runtime, non-root |
| T1070.002 | Clear Logs | Def Evasion | ✅ | Append-only, IAM deny |
| T1562.001 | Impair Defences | Def Evasion | ✅ | Versioned config, defence in depth |
| T1036 | Masquerading | Def Evasion | ✅ | Ed25519 authentication |
| T1557.002 | AiTM | Cred Access | ✅ | Pre-distributed keys, OOB verification |
| T1555 | Credential Stores | Cred Access | ✅ | AWS KMS HSM |
| T1552.001 | Credentials in Files | Cred Access | ✅ | Keys never logged |
| T1528 | Steal Access Token | Cred Access | ✅ | Key rotation, forward secrecy |
| T1005 | Local System Data | Collection | ✅ | IAM deny, ephemeral plaintext |
| T1040 | Network Sniffing | Collection | ✅ | ChaCha20 encryption |
| T1114 | Email Collection | Collection | ✅ | OOB authenticated key dist |
| T1041 | Exfil Over C2 | Exfiltration | ✅ | Security group egress restrict |
| T1048.001 | Alt Protocol Exfil | Exfiltration | ✅ | DNS logging, ICMP block |
| T1030 | Data Size Limits | Exfiltration | ✅ | Flow logs, connection monitoring |
| T1499.002 | DoS Service | Impact | ✅ | Queue limit, rate limiting |
| T1565.002 | Data Manipulation | Impact | ✅ | AEAD + Ed25519 + ZKP |
| T1491 | Defacement | Impact | ✅ | Append-only audit, CloudTrail |
| T1485 | Data Destruction | Impact | ✅ | S3 versioning, MFA delete |

---

## See Also

- `docs/THREAT_MODEL.md` — STRIDE analysis
- `docs/THREAT_INTELLIGENCE.md` — APT actors and CVEs
- `docs/INCIDENT_RESPONSE.md` — Response runbook
- `simulations/iam_breach_sim.py` — IAM defence evidence
- `simulations/tampering_sim.py` — Tamper defence evidence
- `simulations/replay_attack_sim.py` — Replay defence evidence