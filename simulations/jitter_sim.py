import os
import sys
import json
import time
import random
import statistics
import logging
from datetime import datetime, timezone


# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

CAR_SRC = os.path.join(ROOT, "car-producer", "src")
REL_SRC = os.path.join(ROOT, "relay-node", "src")
VAL_SRC = os.path.join(ROOT, "validator-node", "src")

for path in [CAR_SRC, REL_SRC, VAL_SRC]:
    if path not in sys.path:
        sys.path.insert(0, path)


from crypto_engine import CryptoEngine
from sensor_simulator import SensorSimulator
from packet_builder import PacketBuilder
from signer import PacketSigner
from encryptor import PacketEncryptor
from decryptor import RelayDecryptor
from reencryptor import RelayReencryptor
from sequence_checker import ValidatorSequenceChecker
from signature_verifier import (
    ValidatorSignatureVerifier,
    SignatureVerificationError,
)
from zkp_verifier import ZKPVerifier

from cryptography.exceptions import InvalidSignature


logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s",
)


"""
jitter_sim.py

PitCrypt-F1 network timing and packet-order resilience evaluation.

Experiments
-----------

1. Low time-based jitter
2. Medium time-based jitter
3. High time-based jitter
4. Low packet reordering
5. Medium packet reordering
6. High packet reordering
7. End-to-end pipeline latency
8. No-jitter baseline

Important distinction
---------------------

Time-based jitter:
    Simulates variable network delivery delay.

Packet reordering:
    Deliberately changes packet delivery order.

These are separate network behaviours and are reported separately.

The simulation does not modify the underlying PitCrypt packet,
cryptographic, relay, or validator implementations.

Results
-------

Saved to:

    simulations/results/jitter_results.json
"""


RESULTS_DIR = os.path.join(
    ROOT,
    "simulations",
    "results",
)

os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Configuration ────────────────────────────────────────────────

RANDOM_SEED = 42

TEAM = "mercedes"
RACE = "Bahrain"
SESSION = "R"

CAR_NODE = "mercedes_car"
RELAY_NODE = "relay_01"
RELAY_VAL_NODE = "relay_val"
VALIDATOR_NODE = "validator"

N_TIME_JITTER_PACKETS = 100
N_REORDER_PACKETS = 30
N_LATENCY_PACKETS = 50

# Packets are conceptually generated every 5 ms.
# This makes larger jitter windows capable of causing
# realistic delivery-order changes in the simulation.
SEND_INTERVAL_MS = 5.0

BASE_NETWORK_DELAY_MS = 10.0

TIME_JITTER_LEVELS_MS = [
    1.0,
    5.0,
    10.0,
]

REORDER_WINDOWS = [
    2,
    5,
    10,
]


# ── Pipeline construction ────────────────────────────────────────

def build_pipeline():
    """Build the complete car → relay → validator pipeline."""

    sim = SensorSimulator(
        team=TEAM,
        race=RACE,
        session=SESSION,
        add_noise=False,
        inject_anomalies=False,
    )

    builder = PacketBuilder(
        team=TEAM,
        session=SESSION,
        node_id=CAR_NODE,
    )

    signer = PacketSigner(
        node_id=CAR_NODE,
    )

    # -------------------------------------------------------------
    # Car → Relay ECDH
    # -------------------------------------------------------------

    car_engine = CryptoEngine(
        node_id=CAR_NODE,
    )

    relay_engine = CryptoEngine(
        node_id=RELAY_NODE,
    )

    car_public = car_engine.new_session()
    relay_public = relay_engine.new_session()

    car_engine.complete_handshake(relay_public)
    relay_engine.complete_handshake(car_public)

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id=CAR_NODE,
    )

    decryptor = RelayDecryptor(
        node_id=RELAY_NODE,
    )

    decryptor.register_session(
        CAR_NODE,
        relay_engine,
    )

    # -------------------------------------------------------------
    # Relay → Validator ECDH
    # -------------------------------------------------------------

    relay_val_engine = CryptoEngine(
        node_id=RELAY_VAL_NODE,
    )

    validator_engine = CryptoEngine(
        node_id=VALIDATOR_NODE,
    )

    relay_val_public = relay_val_engine.new_session()
    validator_public = validator_engine.new_session()

    relay_val_engine.complete_handshake(validator_public)
    validator_engine.complete_handshake(relay_val_public)

    reencryptor = RelayReencryptor(
        node_id=RELAY_NODE,
    )

    reencryptor.register_validator_session(
        relay_val_engine,
    )

    # -------------------------------------------------------------
    # Validator security components
    # -------------------------------------------------------------

    signature_verifier = ValidatorSignatureVerifier(
        node_id="fia_validator",
    )

    signature_verifier.register_node(
        CAR_NODE,
        signer.public_key_bytes,
    )

    zkp = ZKPVerifier(
        node_id="fia_validator",
    )

    return {
        "sim": sim,
        "builder": builder,
        "signer": signer,
        "encryptor": encryptor,
        "decryptor": decryptor,
        "reencryptor": reencryptor,
        "validator_engine": validator_engine,
        "signature_verifier": signature_verifier,
        "zkp": zkp,
    }


# ── Packet construction ──────────────────────────────────────────

def make_val_packet(pipeline: dict) -> tuple[dict, float]:
    """
    Build one complete validator-bound packet.

    Returns:

        (validator_packet, processing_latency_ms)

    The latency measures the full reference pipeline:

        sensor
        → packet build
        → signature
        → encryption
        → relay decryption
        → relay re-encryption
        → validator decryption
        → packet assembly

    It is therefore pipeline latency, not network latency.
    """

    start = time.perf_counter()

    frame = pipeline["sim"].get_next_frame()

    if frame is None:
        pipeline["sim"].reset()
        frame = pipeline["sim"].get_next_frame()

    packet = pipeline["builder"].build(frame)

    signed = pipeline["signer"].sign_packet(packet)

    commitment = ZKPVerifier.generate_commitment(
        signed["payload"],
    )

    encrypted = pipeline["encryptor"].encrypt_packet(
        signed,
    )

    decrypted = pipeline["decryptor"].decrypt(
        encrypted,
    )

    reencrypted = pipeline["reencryptor"].reencrypt(
        decrypted,
    )

    plaintext = pipeline["validator_engine"].decrypt(
        nonce=reencrypted["nonce_bytes"],
        ciphertext=reencrypted["ciphertext_bytes"],
        associated_data=reencrypted["header"],
    )

    validator_packet = dict(reencrypted)

    validator_packet["payload_bytes"] = plaintext
    validator_packet["original_node"] = CAR_NODE
    validator_packet["zkp_commitment"] = commitment["commitment"]
    validator_packet["zkp_nonce"] = commitment["nonce"]

    latency_ms = (
        time.perf_counter() - start
    ) * 1000.0

    return validator_packet, latency_ms


# ── Validation ───────────────────────────────────────────────────

def validate_packet(
    pipeline: dict,
    packet: dict,
    checker: ValidatorSequenceChecker,
) -> dict:
    """
    Run validator-side signature, sequence, and commitment checks.
    """

    result = {
        "accepted": False,
        "signature_valid": False,
        "sequence_valid": False,
        "commitment_valid": False,
    }

    try:
        signature_result = pipeline[
            "signature_verifier"
        ].verify(packet)

        result["signature_valid"] = (
            signature_result["verified"]
        )

    except (
        InvalidSignature,
        SignatureVerificationError,
        Exception,
    ):
        result["signature_valid"] = False

    sequence_result = checker.check(packet)

    result["sequence_valid"] = (
        sequence_result.passed
    )

    commitment_result = pipeline[
        "zkp"
    ].verify_packet(packet)

    result["commitment_valid"] = (
        commitment_result.verified
    )

    result["accepted"] = (
        result["signature_valid"]
        and result["sequence_valid"]
        and result["commitment_valid"]
    )

    return result


# ── Statistics ───────────────────────────────────────────────────

def percentile(values: list[float], percentile_value: float) -> float:
    """Nearest-rank percentile suitable for small benchmark samples."""

    if not values:
        return 0.0

    ordered = sorted(values)

    index = int(
        round(
            (percentile_value / 100.0)
            * (len(ordered) - 1)
        )
    )

    index = max(
        0,
        min(index, len(ordered) - 1),
    )

    return ordered[index]


def latency_stats(values: list[float]) -> dict:
    """Compute latency distribution statistics."""

    if not values:
        return {}

    return {
        "count": len(values),
        "mean_ms": round(
            statistics.fmean(values),
            3,
        ),
        "median_ms": round(
            statistics.median(values),
            3,
        ),
        "min_ms": round(
            min(values),
            3,
        ),
        "max_ms": round(
            max(values),
            3,
        ),
        "p95_ms": round(
            percentile(values, 95),
            3,
        ),
        "p99_ms": round(
            percentile(values, 99),
            3,
        ),
        "stdev_ms": round(
            statistics.stdev(values)
            if len(values) > 1
            else 0.0,
            3,
        ),
    }


# ── Time-based jitter ────────────────────────────────────────────

def sim_time_jitter(
    pipeline: dict,
    jitter_ms: float,
) -> dict:
    """
    Simulate variable network delivery timing.

    A packet is assigned:

        send_time
        +
        base_network_delay
        +
        random jitter

    Delivery order is determined by the simulated delivery timestamp.

    No real sleep() is used.

    This measures simulated network timing variation separately from
    local packet-processing latency.
    """

    print(
        f"\n[Time Jitter] ±{jitter_ms:g} ms"
    )

    packets = []

    processing_latencies = []
    network_delays = []

    random.seed(
        RANDOM_SEED
        + int(jitter_ms * 100)
    )

    for index in range(N_TIME_JITTER_PACKETS):

        packet, processing_latency = (
            make_val_packet(pipeline)
        )

        jitter = random.uniform(
            -jitter_ms,
            jitter_ms,
        )

        network_delay = max(
            0.0,
            BASE_NETWORK_DELAY_MS + jitter,
        )

        send_time = (
            index * SEND_INTERVAL_MS
        )

        delivery_time = (
            send_time + network_delay
        )

        packets.append(
            {
                "packet": packet,
                "index": index,
                "send_time_ms": send_time,
                "network_delay_ms": network_delay,
                "delivery_time_ms": delivery_time,
                "processing_latency_ms": processing_latency,
            }
        )

        processing_latencies.append(
            processing_latency
        )

        network_delays.append(
            network_delay
        )

    # Network determines arrival order.
    delivered = sorted(
        packets,
        key=lambda item: (
            item["delivery_time_ms"],
            item["index"],
        ),
    )

    checker = ValidatorSequenceChecker(
        node_id=f"val_time_jitter_{int(jitter_ms)}",
        check_timestamps=False,
        strict_ordering=True,
    )

    accepted = 0
    rejected = 0
    out_of_order = 0

    last_sequence = None

    simulated_e2e = []

    for item in delivered:

        packet = item["packet"]

        sequence = packet.get(
            "sequence",
            packet.get("sequence_number"),
        )

        if (
            last_sequence is not None
            and sequence is not None
            and sequence <= last_sequence
        ):
            out_of_order += 1

        result = validate_packet(
            pipeline,
            packet,
            checker,
        )

        if result["accepted"]:
            accepted += 1
        else:
            rejected += 1

        if sequence is not None:
            if (
                last_sequence is None
                or sequence > last_sequence
            ):
                last_sequence = sequence

        simulated_e2e.append(
            item["network_delay_ms"]
            + item["processing_latency_ms"]
        )

    network_stats = latency_stats(
        network_delays
    )

    processing_stats = latency_stats(
        processing_latencies
    )

    e2e_stats = latency_stats(
        simulated_e2e
    )

    result = {
        "scenario": "time_jitter",
        "jitter_amplitude_ms": jitter_ms,
        "base_network_delay_ms": BASE_NETWORK_DELAY_MS,
        "send_interval_ms": SEND_INTERVAL_MS,
        "n_packets": N_TIME_JITTER_PACKETS,
        "accepted": accepted,
        "rejected": rejected,
        "out_of_order_packets": out_of_order,
        "sequence_gaps": checker.gap_count,
        "replay_detections": checker.replay_count,
        "network_delay": network_stats,
        "pipeline_processing_latency": processing_stats,
        "simulated_end_to_end_latency": e2e_stats,
    }

    print(
        f"  Accepted:       {accepted}/{N_TIME_JITTER_PACKETS}"
    )

    print(
        f"  Rejected:       {rejected}"
    )

    print(
        f"  Out of order:   {out_of_order}"
    )

    print(
        f"  Network delay:  "
        f"mean={network_stats['mean_ms']} ms "
        f"p95={network_stats['p95_ms']} ms"
    )

    print(
        f"  Simulated E2E:  "
        f"mean={e2e_stats['mean_ms']} ms "
        f"p95={e2e_stats['p95_ms']} ms"
    )

    return result


def run_time_jitter_scenarios(
    pipeline: dict,
) -> list:
    """Run low, medium, and high time-based jitter."""

    results = []

    for jitter_ms in TIME_JITTER_LEVELS_MS:
        results.append(
            sim_time_jitter(
                pipeline,
                jitter_ms,
            )
        )

    return results


# ── Packet reordering ────────────────────────────────────────────

def apply_reordering(
    packets: list,
    window: int,
) -> list:
    """
    Deliberately shuffle packets inside fixed-size windows.

    This is packet reordering, not time-based jitter.
    """

    reordered = list(packets)

    for start in range(
        0,
        len(reordered),
        window,
    ):
        chunk = reordered[
            start:start + window
        ]

        random.shuffle(chunk)

        reordered[
            start:start + window
        ] = chunk

    return reordered


def sim_packet_reordering(
    pipeline: dict,
    window: int,
) -> dict:
    """
    Measure strict sequence handling under packet reordering.
    """

    print(
        f"\n[Packet Reordering] window={window}"
    )

    packets = []
    processing_latencies = []

    for _ in range(N_REORDER_PACKETS):

        packet, latency = make_val_packet(
            pipeline
        )

        packets.append(packet)
        processing_latencies.append(latency)

    reordered = apply_reordering(
        packets,
        window,
    )

    checker = ValidatorSequenceChecker(
        node_id=f"val_reorder_{window}",
        check_timestamps=False,
        strict_ordering=True,
    )

    accepted = 0
    rejected = 0

    for packet in reordered:

        result = validate_packet(
            pipeline,
            packet,
            checker,
        )

        if result["accepted"]:
            accepted += 1
        else:
            rejected += 1

    stats = latency_stats(
        processing_latencies
    )

    result = {
        "scenario": "packet_reordering",
        "window": window,
        "n_packets": N_REORDER_PACKETS,
        "accepted": accepted,
        "rejected": rejected,
        "sequence_gaps": checker.gap_count,
        "replay_detections": checker.replay_count,
        "processing_latency": stats,
    }

    print(
        f"  Accepted: {accepted}/{N_REORDER_PACKETS}"
    )

    print(
        f"  Rejected: {rejected}"
    )

    print(
        f"  Mean pipeline latency: "
        f"{stats['mean_ms']} ms"
    )

    return result


def run_reordering_scenarios(
    pipeline: dict,
) -> list:
    """Run low, medium, and high packet reordering."""

    results = []

    for window in REORDER_WINDOWS:

        results.append(
            sim_packet_reordering(
                pipeline,
                window,
            )
        )

    return results


# ── Pipeline latency ──────────────────────────────────────────────

def sim_pipeline_latency(
    pipeline: dict,
) -> dict:
    """
    Measure the complete local packet-processing pipeline.

    This is deliberately called pipeline latency rather than
    cryptographic latency because the measurement includes sensor,
    packet, signing, encryption, relay, and validator-side decryption
    preparation.
    """

    print(
        "\n[Pipeline Latency Benchmark]"
    )

    latencies = []

    for _ in range(N_LATENCY_PACKETS):

        _, latency = make_val_packet(
            pipeline
        )

        latencies.append(latency)

    stats = latency_stats(latencies)

    total_seconds = (
        sum(latencies) / 1000.0
    )

    throughput = (
        N_LATENCY_PACKETS / total_seconds
        if total_seconds > 0
        else 0.0
    )

    result = {
        "scenario": "pipeline_latency",
        "n_packets": N_LATENCY_PACKETS,
        "latency": stats,
        "derived_throughput_pkt_s": round(
            throughput,
            1,
        ),
    }

    print(
        f"  Packets: {N_LATENCY_PACKETS}"
    )

    print(
        f"  Mean:    {stats['mean_ms']} ms"
    )

    print(
        f"  Median:  {stats['median_ms']} ms"
    )

    print(
        f"  P95:     {stats['p95_ms']} ms"
    )

    print(
        f"  P99:     {stats['p99_ms']} ms"
    )

    print(
        f"  Throughput from serial timing: "
        f"{throughput:.1f} pkt/s"
    )

    return result


# ── No-jitter baseline ───────────────────────────────────────────

def sim_no_jitter_baseline(
    pipeline: dict,
) -> dict:
    """
    Perfectly ordered baseline with no simulated network jitter.
    """

    print(
        "\n[Baseline] No jitter / perfect ordering"
    )

    checker = ValidatorSequenceChecker(
        node_id="val_baseline",
        check_timestamps=False,
        strict_ordering=True,
    )

    accepted = 0
    rejected = 0
    latencies = []

    start = time.perf_counter()

    for _ in range(N_LATENCY_PACKETS):

        packet, latency = make_val_packet(
            pipeline
        )

        latencies.append(latency)

        result = validate_packet(
            pipeline,
            packet,
            checker,
        )

        if result["accepted"]:
            accepted += 1
        else:
            rejected += 1

    elapsed = (
        time.perf_counter() - start
    )

    throughput = (
        N_LATENCY_PACKETS / elapsed
        if elapsed > 0
        else 0.0
    )

    stats = latency_stats(latencies)

    result = {
        "scenario": "no_jitter_baseline",
        "n_packets": N_LATENCY_PACKETS,
        "accepted": accepted,
        "rejected": rejected,
        "throughput_pkt_s": round(
            throughput,
            1,
        ),
        "latency": stats,
        "sequence_gaps": checker.gap_count,
        "replay_detections": checker.replay_count,
    }

    print(
        f"  Accepted: "
        f"{accepted}/{N_LATENCY_PACKETS}"
    )

    print(
        f"  Rejected: {rejected}"
    )

    print(
        f"  Throughput: "
        f"{throughput:.1f} pkt/s"
    )

    print(
        f"  Mean latency: "
        f"{stats['mean_ms']} ms"
    )

    return result


# ── Main ──────────────────────────────────────────────────────────

def main():

    print("\n" + "=" * 70)
    print(
        "  PitCrypt-F1 — Network Timing & "
        "Packet Ordering Evaluation"
    )
    print("=" * 70)

    print(
        "\n  Time-based jitter and packet reordering "
        "are evaluated separately."
    )

    random.seed(RANDOM_SEED)

    pipeline = build_pipeline()

    start = time.time()

    results = {
        "time_jitter": run_time_jitter_scenarios(
            pipeline
        ),
        "packet_reordering": run_reordering_scenarios(
            pipeline
        ),
        "pipeline_latency": sim_pipeline_latency(
            pipeline
        ),
        "no_jitter_baseline": sim_no_jitter_baseline(
            pipeline
        ),
    }

    elapsed = (
        time.time() - start
    )

    print("\n" + "=" * 70)
    print("  Summary")
    print("=" * 70)

    for group_name, group_results in results.items():

        if isinstance(group_results, list):

            for result in group_results:

                print(
                    f"  {group_name:<22} "
                    f"{result['scenario']:<25} "
                    f"accepted="
                    f"{result.get('accepted', '—')}/"
                    f"{result.get('n_packets', '—')}"
                )

        else:

            print(
                f"  {group_name:<22} "
                f"{group_results['scenario']}"
            )

    output = {
        "simulation": "network_timing_and_ordering",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "configuration": {
            "random_seed": RANDOM_SEED,
            "team": TEAM,
            "race": RACE,
            "session": SESSION,
            "base_network_delay_ms": (
                BASE_NETWORK_DELAY_MS
            ),
            "send_interval_ms": (
                SEND_INTERVAL_MS
            ),
        },
        "elapsed_s": round(
            elapsed,
            2,
        ),
        "results": results,
    }

    path = os.path.join(
        RESULTS_DIR,
        "jitter_results.json",
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
        )

    print(
        f"\nResults saved → {path}"
    )

    print(
        "\nNetwork timing evaluation complete."
    )

    return output


if __name__ == "__main__":
    main()