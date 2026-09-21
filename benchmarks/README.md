# PitCrypt-F1 Benchmarks

Performance benchmarks for PitCrypt-F1's three-tier telemetry pipeline:

**car producer → relay node → validator**

This folder measures the **pure-Python reference pipeline** included here,
covering signing, encryption, anomaly checking, re-encryption, signature
verification, sequence checking, and commitment verification.

The benchmark suite measures both **end-to-end performance** and
**individual pipeline-stage performance**, using reproducible workloads and
machine-readable output.

> **Scope:** These benchmarks measure the Python reference pipeline. The
> separate Rust `zkp-module` is not currently integrated into this pipeline
> and is therefore benchmarked separately.

---

## What's here

| File | Purpose |
|---|---|
| `metrics.py` | Generic timing, statistics, and result-persistence utilities. Contains no F1-specific logic. |
| `telemetry_metrics.py` | F1-domain data definitions, constructors, circuits, channel ranges, and telemetry packet generation. Uses cached FastF1 telemetry when available, with synthetic fallback. |
| `benchmark_latency.py` | Reference `PitCryptPipeline` implementation and per-stage + end-to-end latency benchmark. |
| `benchmark_throughput.py` | Single-car sustained and multi-car concurrent throughput benchmarks, reusing the reference pipeline. |
| `results/` | Generated benchmark results. Created/populated when benchmarks are run. |

---

# Pipeline under test

Every packet passes through the following seven stages, in order:

1. **`sign`** — car signs the telemetry payload using Ed25519.
2. **`encrypt`** — car encrypts the payload and signature for the relay using AES-256-GCM.
3. **`anomaly_check`** — relay decrypts the packet and checks telemetry values against configured channel ranges.
4. **`re_encrypt`** — relay re-encrypts the validated packet for the validator using AES-256-GCM with a fresh key/nonce.
5. **`verify_signature`** — validator decrypts the packet and verifies the car's Ed25519 signature.
6. **`sequence_check`** — validator checks that the packet sequence number is exactly `last + 1`.
7. **`commitment_verify`** — validator recomputes and verifies a SHA-256 hash commitment.

The reference pipeline uses **fail-fast processing**: if a packet fails a
stage, that packet is rejected and subsequent stages are not executed.

> **Reference-pipeline note:** This behavior represents the fail-fast model
> implemented by the benchmark pipeline; it should not be interpreted as a
> claim about a production FIA system.

---

## ZKP status

The `commitment_verify` stage currently uses a **SHA-256 hash commitment
as a benchmark placeholder**.

It is **not** the project's actual zero-knowledge proof implementation.

The actual combined integrity + sequence-correctness ZK proof is implemented
in the separate Rust `zkp-module`, using:

- Pedersen commitments
- a Fiat–Shamir/Sigma-protocol construction
- Ristretto255
- Merlin transcripts

The Rust ZKP module is currently tested separately and is **not yet part of
the Python packet-processing benchmark path**.

Once a Python/Rust integration layer exists, such as a PyO3 binding or
compiled CLI bridge, `commitment_verify` can be replaced with the real ZKP
verification call.

The rest of the benchmark structure can remain unchanged.

---

# Setup

The benchmark pipeline requires the Python `cryptography` package.

```bash
pip install cryptography