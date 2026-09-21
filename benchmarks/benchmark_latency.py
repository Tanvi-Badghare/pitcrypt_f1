"""
benchmark_latency.py
---------------------
Reference implementation of PitCrypt-F1's seven-stage packet pipeline
(sign -> encrypt -> anomaly-check -> re-encrypt -> verify-signature ->
sequence-check -> commitment-verify), plus a benchmark that measures
both the per-stage latency breakdown and the end-to-end total.

This is a *pure-Python* reference pipeline so the benchmark suite runs
standalone. The `commitment_verify` stage is a SHA-256 hash-commitment
placeholder, not the real zero-knowledge proof - the actual combined
integrity+sequence ZK proof lives in the Rust `zkp-module` crate and is
not yet wired into this Python pipeline (see that crate's README for the
PyO3/CLI integration point). Swap `_commitment_verify` for a call into
that crate once bound, without touching anything else here.

Run:
    python benchmark_latency.py --iterations 2000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import metrics
import telemetry_metrics as tm

STAGES = [
    "sign",
    "encrypt",
    "anomaly_check",
    "re_encrypt",
    "verify_signature",
    "sequence_check",
    "commitment_verify",
]


@dataclass
class StageResult:
    name: str
    duration_s: float
    success: bool
    detail: str = ""


@dataclass
class PacketResult:
    sequence: int
    success: bool
    failed_stage: str | None
    stages: list[StageResult] = field(default_factory=list)
    total_latency_s: float = 0.0


class PitCryptPipeline:
    """One car-producer/relay-node/FIA-validator pipeline instance.

    A single instance holds the long-lived key material (car's Ed25519
    signing keypair, car<->relay and relay<->validator AES-256-GCM
    session keys) and the last-accepted sequence number per car, exactly
    as the validator would in production.
    """

    def __init__(self) -> None:
        self._car_signing_key = Ed25519PrivateKey.generate()
        self._car_verify_key: Ed25519PublicKey = self._car_signing_key.public_key()
        self._car_to_relay_key = AESGCM(AESGCM.generate_key(bit_length=256))
        self._relay_to_validator_key = AESGCM(AESGCM.generate_key(bit_length=256))
        self._last_sequence: dict[str, int] = {}

    # -- packet construction (done by the car, before stage 1) ----------

    def _build_packet(self, sample: tm.TelemetrySample) -> bytes:
        """Serialize telemetry + sequence and attach a hash commitment
        with a random salt. Everything from here on (sign/encrypt/...)
        operates on this single JSON blob.
        """
        salt = secrets.token_hex(16)
        core = {
            "car_id": sample.car_id,
            "sequence": sample.sequence,
            "telemetry": {
                "speed_kph": sample.speed_kph,
                "throttle_pct": sample.throttle_pct,
                "brake_pct": sample.brake_pct,
                "rpm": sample.rpm,
                "gear": sample.gear,
                "drs": sample.drs,
                "x": sample.x,
                "y": sample.y,
            },
        }
        core_bytes = json.dumps(core, sort_keys=True).encode("utf-8")
        commitment = hashlib.sha256(salt.encode() + core_bytes).hexdigest()
        packet = {**core, "salt": salt, "commitment": commitment}
        return json.dumps(packet, sort_keys=True).encode("utf-8")

    # -- the seven benchmarked stages -----------------------------------

    def _sign(self, payload: bytes) -> bytes:
        return self._car_signing_key.sign(payload)

    def _encrypt(self, payload: bytes, signature: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        envelope = json.dumps(
            {"payload": payload.decode("utf-8"), "signature": signature.hex()}
        ).encode("utf-8")
        ciphertext = self._car_to_relay_key.encrypt(nonce, envelope, None)
        return nonce + ciphertext

    def _anomaly_check(self, ciphertext_with_nonce: bytes) -> tuple[bool, str, bytes]:
        """Relay decrypts to inspect telemetry ranges. Returns
        (ok, detail, envelope_bytes) so the caller can re-encrypt the
        same envelope on success without re-deriving it.
        """
        nonce, ciphertext = ciphertext_with_nonce[:12], ciphertext_with_nonce[12:]
        envelope = self._car_to_relay_key.decrypt(nonce, ciphertext, None)
        payload = json.loads(json.loads(envelope)["payload"])
        t = payload["telemetry"]
        checks = {
            "speed_kph": t["speed_kph"],
            "throttle_pct": t["throttle_pct"],
            "brake_pct": t["brake_pct"],
            "rpm": t["rpm"],
            "gear": t["gear"],
            "drs": t["drs"],
        }
        for channel, value in checks.items():
            lo, hi = tm.CHANNEL_RANGES[channel]
            if not (lo <= value <= hi):
                return False, f"{channel}={value} outside [{lo}, {hi}]", envelope
        return True, "", envelope

    def _re_encrypt(self, envelope: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        ciphertext = self._relay_to_validator_key.encrypt(nonce, envelope, None)
        return nonce + ciphertext

    def _verify_signature(self, ciphertext_with_nonce: bytes) -> tuple[bool, str, dict]:
        nonce, ciphertext = ciphertext_with_nonce[:12], ciphertext_with_nonce[12:]
        envelope = json.loads(self._relay_to_validator_key.decrypt(nonce, ciphertext, None))
        payload_str = envelope["payload"]
        signature = bytes.fromhex(envelope["signature"])
        try:
            self._car_verify_key.verify(signature, payload_str.encode("utf-8"))
        except InvalidSignature:
            return False, "signature verification failed", {}
        return True, "", json.loads(payload_str)

    def _sequence_check(self, car_id: str, sequence: int) -> tuple[bool, str]:
        last = self._last_sequence.get(car_id, sequence - 1)
        if sequence != last + 1:
            return False, f"expected sequence {last + 1}, got {sequence}"
        self._last_sequence[car_id] = sequence
        return True, ""

    def _commitment_verify(self, payload: dict) -> tuple[bool, str]:
        salt = payload["salt"]
        commitment = payload["commitment"]
        core = {k: v for k, v in payload.items() if k not in ("salt", "commitment")}
        core_bytes = json.dumps(core, sort_keys=True).encode("utf-8")
        recomputed = hashlib.sha256(salt.encode() + core_bytes).hexdigest()
        if recomputed != commitment:
            return False, "commitment mismatch"
        return True, ""

    # -- orchestration ----------------------------------------------------

    def process_packet(self, sample: tm.TelemetrySample) -> PacketResult:
        """Run one packet through all seven stages, recording per-stage
        timing. Stops at the first failing stage, matching production
        behaviour (the FIA validator never processes later stages for a
        rejected packet).
        """
        result = PacketResult(sequence=sample.sequence, success=True, failed_stage=None)
        payload_bytes = self._build_packet(sample)  # not benchmarked: car-side prep

        with metrics.timer() as t:
            signature = self._sign(payload_bytes)
        result.stages.append(StageResult("sign", t.seconds, True))

        with metrics.timer() as t:
            car_to_relay = self._encrypt(payload_bytes, signature)
        result.stages.append(StageResult("encrypt", t.seconds, True))

        with metrics.timer() as t:
            ok, detail, envelope = self._anomaly_check(car_to_relay)
        result.stages.append(StageResult("anomaly_check", t.seconds, ok, detail))
        if not ok:
            result.success, result.failed_stage = False, "anomaly_check"
            result.total_latency_s = sum(s.duration_s for s in result.stages)
            return result

        with metrics.timer() as t:
            relay_to_validator = self._re_encrypt(envelope)
        result.stages.append(StageResult("re_encrypt", t.seconds, True))

        with metrics.timer() as t:
            ok, detail, payload = self._verify_signature(relay_to_validator)
        result.stages.append(StageResult("verify_signature", t.seconds, ok, detail))
        if not ok:
            result.success, result.failed_stage = False, "verify_signature"
            result.total_latency_s = sum(s.duration_s for s in result.stages)
            return result

        with metrics.timer() as t:
            ok, detail = self._sequence_check(payload["car_id"], payload["sequence"])
        result.stages.append(StageResult("sequence_check", t.seconds, ok, detail))
        if not ok:
            result.success, result.failed_stage = False, "sequence_check"
            result.total_latency_s = sum(s.duration_s for s in result.stages)
            return result

        with metrics.timer() as t:
            ok, detail = self._commitment_verify(payload)
        result.stages.append(StageResult("commitment_verify", t.seconds, ok, detail))
        if not ok:
            result.success, result.failed_stage = False, "commitment_verify"

        result.total_latency_s = sum(s.duration_s for s in result.stages)
        return result


def run_latency_benchmark(iterations: int, warmup: int, circuit: str) -> tuple[dict, dict]:
    pipeline = PitCryptPipeline()
    car_id = "RBR-01"
    stream = list(
        tm.generate_packet_stream(
            iterations + warmup, car_ids=[car_id], circuit=circuit, anomaly_rate=0.0
        )
    )

    for sample in stream[:warmup]:
        pipeline.process_packet(sample)

    per_stage: dict[str, list[float]] = {s: [] for s in STAGES}
    end_to_end: list[float] = []
    failures = 0

    for sample in stream[warmup:]:
        result = pipeline.process_packet(sample)
        if not result.success:
            failures += 1
            continue
        end_to_end.append(result.total_latency_s)
        for stage in result.stages:
            per_stage[stage.name].append(stage.duration_s)

    stage_stats = {name: metrics.summarize(vals) for name, vals in per_stage.items() if vals}
    end_to_end_stats = metrics.summarize(end_to_end)
    return stage_stats, {"end_to_end": end_to_end_stats, "failures": failures}


def main() -> None:
    parser = argparse.ArgumentParser(description="PitCrypt-F1 pipeline latency benchmark")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--circuit", type=str, default=tm.CIRCUITS[0])
    parser.add_argument("--output-json", type=str, default="results/latency.json")
    parser.add_argument("--output-csv", type=str, default="results/latency_stages.csv")
    args = parser.parse_args()

    stage_stats, summary = run_latency_benchmark(args.iterations, args.warmup, args.circuit)
    end_to_end: metrics.LatencyStats = summary["end_to_end"]

    print(f"\nPitCrypt-F1 latency benchmark  ({args.iterations} packets, circuit={args.circuit})\n")
    rows = [
        [name, f"{s.mean_ms:.3f}", f"{s.p95_ms:.3f}", f"{s.p99_ms:.3f}", f"{s.max_s * 1000:.3f}"]
        for name, s in stage_stats.items()
    ]
    rows.append(
        [
            "END-TO-END",
            f"{end_to_end.mean_ms:.3f}",
            f"{end_to_end.p95_ms:.3f}",
            f"{end_to_end.p99_ms:.3f}",
            f"{end_to_end.max_s * 1000:.3f}",
        ]
    )
    metrics.print_table(["stage", "mean_ms", "p95_ms", "p99_ms", "max_ms"], rows)
    if summary["failures"]:
        print(f"\n{summary['failures']} packet(s) failed and were excluded from stats.")

    run = metrics.BenchmarkRun(
        benchmark="benchmark_latency",
        scenario="per_stage_and_end_to_end",
        parameters=vars(args),
        results={
            "stages": {k: vars(v) for k, v in stage_stats.items()},
            "end_to_end": vars(end_to_end),
            "failures": summary["failures"],
        },
    )
    metrics.save_json(run, args.output_json)
    metrics.save_stage_csv(stage_stats, args.output_csv)
    print(f"\nSaved: {args.output_json}, {args.output_csv}")


if __name__ == "__main__":
    main()