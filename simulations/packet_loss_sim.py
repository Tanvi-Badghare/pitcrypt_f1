"""
PitCrypt-F1 Packet Loss / Network Resilience Evaluation

=========================================================

Evaluates validator-side resilience under controlled network
conditions.

Scenarios
---------

1. Random packet loss

   0%, 1%, 5%, 10%, 20%


2. Burst packet loss

   3, 5, 10 consecutive packets


3. Selective packet loss

   Deterministic packet positions are dropped.


4. Recovery

   Normal traffic -> complete loss -> traffic restoration


5. High-load loss

   Larger workload under 5% random packet loss.


6. Duplicate packet / replay

   Previously accepted packets are deliberately delivered again.


Metrics
-------

- Configured loss rate
- Actual loss rate
- Packets generated
- Packets transmitted
- Packets dropped
- Packets accepted
- Packets rejected
- Sequence gaps detected
- Replay detections
- Signature failures
- Commitment failures
- Recovery timing
- Processing throughput
- Duplicate packets
- Duplicate packets rejected


Important
---------

This is an evaluation/simulation layer.

It does not modify the underlying PitCrypt packet,
cryptographic, relay, or validator implementations.
"""


import os
import sys
import json
import random
import time


# ================================================================
# PATH SETUP
# ================================================================

ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

for source_dir in [
    os.path.join(ROOT, "car-producer", "src"),
    os.path.join(ROOT, "relay-node", "src"),
    os.path.join(ROOT, "validator-node", "src"),
]:

    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)


# ================================================================
# IMPORTS
# ================================================================

from sensor_simulator import SensorSimulator
from packet_builder import PacketBuilder
from signer import PacketSigner
from encryptor import PacketEncryptor
from crypto_engine import CryptoEngine

from decryptor import RelayDecryptor
from reencryptor import RelayReencryptor

from sequence_checker import ValidatorSequenceChecker
from signature_verifier import ValidatorSignatureVerifier
from zkp_verifier import ZKPVerifier


# ================================================================
# CONFIGURATION
# ================================================================

RANDOM_SEED = 42

TEAM = "mercedes"
RACE = "Bahrain"
SESSION = "R"

CAR_NODE = "mercedes_car"
RELAY_NODE = "relay_01"

RELAY_VAL_NODE = "relay_val"
VALIDATOR_NODE = "validator"


RESULTS_DIR = os.path.join(
    os.path.dirname(__file__),
    "results",
)

RESULTS_FILE = os.path.join(
    RESULTS_DIR,
    "packet_loss_results.json",
)


# ================================================================
# PIPELINE
# ================================================================

class PitCryptPipeline:
    """
    Builds one complete:

        Sensor
          ↓
        PacketBuilder
          ↓
        Ed25519 Signer
          ↓
        Car encryption
          ↓
        Relay decrypt
          ↓
        Relay re-encryption
          ↓
        Validator decrypt
          ↓
        Signature verification
          ↓
        Sequence checking
          ↓
        Commitment verification

    pipeline.

    Network-loss and duplicate-packet simulations operate after
    packet construction.
    """

    def __init__(self):

        print("\n" + "=" * 65)
        print(
            "  Building PitCrypt-F1 evaluation pipeline"
        )
        print("=" * 65)

        # --------------------------------------------------------
        # Sensor
        # --------------------------------------------------------

        self.sensor = SensorSimulator(
            team=TEAM,
            race=RACE,
            session=SESSION,
            add_noise=False,
            inject_anomalies=False,
        )

        # --------------------------------------------------------
        # Packet builder
        # --------------------------------------------------------

        self.builder = PacketBuilder(
            team=TEAM,
            session=SESSION,
            node_id=CAR_NODE,
        )

        # --------------------------------------------------------
        # Car signing identity
        # --------------------------------------------------------

        self.signer = PacketSigner(
            node_id=CAR_NODE,
        )

        # --------------------------------------------------------
        # Car -> Relay ECDH
        # --------------------------------------------------------

        self.car_engine = CryptoEngine(
            node_id=CAR_NODE,
        )

        self.relay_engine = CryptoEngine(
            node_id=RELAY_NODE,
        )

        car_public = (
            self.car_engine.new_session()
        )

        relay_public = (
            self.relay_engine.new_session()
        )

        self.car_engine.complete_handshake(
            relay_public
        )

        self.relay_engine.complete_handshake(
            car_public
        )

        self.encryptor = PacketEncryptor(
            crypto_engine=self.car_engine,
            node_id=CAR_NODE,
        )

        self.decryptor = RelayDecryptor(
            node_id=RELAY_NODE,
        )

        self.decryptor.register_session(
            CAR_NODE,
            self.relay_engine,
        )

        # --------------------------------------------------------
        # Relay -> Validator ECDH
        # --------------------------------------------------------

        self.relay_val_engine = CryptoEngine(
            node_id=RELAY_VAL_NODE,
        )

        self.validator_engine = CryptoEngine(
            node_id=VALIDATOR_NODE,
        )

        relay_val_public = (
            self.relay_val_engine.new_session()
        )

        validator_public = (
            self.validator_engine.new_session()
        )

        self.relay_val_engine.complete_handshake(
            validator_public
        )

        self.validator_engine.complete_handshake(
            relay_val_public
        )

        self.reencryptor = RelayReencryptor(
            node_id=RELAY_NODE,
        )

        self.reencryptor.register_validator_session(
            self.relay_val_engine
        )

        # --------------------------------------------------------
        # Validator security components
        # --------------------------------------------------------

        self.signature_verifier = (
            ValidatorSignatureVerifier(
                node_id="fia_validator",
            )
        )

        self.signature_verifier.register_node(
            CAR_NODE,
            self.signer.public_key_bytes,
        )

        self.zkp_verifier = ZKPVerifier(
            node_id="fia_validator",
        )

        print("\n  Pipeline ready.\n")

    # ============================================================
    # CREATE VALIDATOR PACKET
    # ============================================================

    def create_validator_packet(self) -> dict:
        """
        Produce one fully processed validator-bound packet.
        """

        frame = self.sensor.get_next_frame()

        if frame is None:
            self.sensor.reset()
            frame = self.sensor.get_next_frame()

        packet = self.builder.build(frame)

        signed = self.signer.sign_packet(
            packet
        )

        commitment = (
            ZKPVerifier.generate_commitment(
                signed["payload"]
            )
        )

        encrypted = (
            self.encryptor.encrypt_packet(
                signed
            )
        )

        decrypted = (
            self.decryptor.decrypt(
                encrypted
            )
        )

        reencrypted = (
            self.reencryptor.reencrypt(
                decrypted
            )
        )

        plaintext = (
            self.validator_engine.decrypt(
                nonce=reencrypted["nonce_bytes"],
                ciphertext=reencrypted[
                    "ciphertext_bytes"
                ],
                associated_data=reencrypted[
                    "header"
                ],
            )
        )

        validator_packet = dict(
            reencrypted
        )

        validator_packet[
            "payload_bytes"
        ] = plaintext

        validator_packet[
            "original_node"
        ] = CAR_NODE

        validator_packet[
            "zkp_commitment"
        ] = commitment["commitment"]

        validator_packet[
            "zkp_nonce"
        ] = commitment["nonce"]

        return validator_packet

    # ============================================================
    # VALIDATE PACKET
    # ============================================================

    def validate_packet(
        self,
        packet: dict,
        sequence_checker: ValidatorSequenceChecker,
    ) -> dict:
        """
        Run validator-side checks.
        """

        result = {
            "accepted": False,
            "signature_valid": False,
            "sequence_valid": False,
            "commitment_valid": False,
            "sequence_warnings": [],
            "sequence_errors": [],
        }

        # --------------------------------------------------------
        # Signature
        # --------------------------------------------------------

        try:

            signature_result = (
                self.signature_verifier.verify(
                    packet
                )
            )

            result["signature_valid"] = (
                signature_result["verified"]
            )

        except Exception:

            result["signature_valid"] = False

        # --------------------------------------------------------
        # Sequence
        # --------------------------------------------------------

        sequence_result = (
            sequence_checker.check(
                packet
            )
        )

        result["sequence_valid"] = (
            sequence_result.passed
        )

        result["sequence_warnings"] = (
            sequence_result.warnings
        )

        result["sequence_errors"] = (
            sequence_result.errors
        )

        # --------------------------------------------------------
        # Commitment
        # --------------------------------------------------------

        commitment_result = (
            self.zkp_verifier.verify_packet(
                packet
            )
        )

        result["commitment_valid"] = (
            commitment_result.verified
        )

        # --------------------------------------------------------
        # Final decision
        # --------------------------------------------------------

        result["accepted"] = (
            result["signature_valid"]
            and result["sequence_valid"]
            and result["commitment_valid"]
        )

        return result


# ================================================================
# HELPERS
# ================================================================

def new_sequence_checker(
    max_sequence_gap: int = 1000,
) -> ValidatorSequenceChecker:
    """
    Create fresh validator sequence state.
    """

    return ValidatorSequenceChecker(
        node_id="fia_validator",
        max_sequence_gap=max_sequence_gap,
        check_timestamps=False,
        strict_ordering=True,
    )


def loss_rate(
    dropped: int,
    transmitted: int,
) -> float:

    total = dropped + transmitted

    if total == 0:
        return 0.0

    return dropped / total


def base_result(
    scenario: str,
) -> dict:

    return {
        "scenario": scenario,
        "generated": 0,
        "transmitted": 0,
        "dropped": 0,
        "accepted": 0,
        "rejected": 0,
        "actual_loss_rate": 0.0,
        "sequence_gaps_detected": 0,
        "replay_detections": 0,
        "signature_failures": 0,
        "commitment_failures": 0,
    }


# ================================================================
# SCENARIO 1 — RANDOM LOSS
# ================================================================

def scenario_random_loss(
    pipeline: PitCryptPipeline,
    packet_count: int = 200,
) -> list:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 1 — RANDOM PACKET LOSS"
    )
    print("=" * 65)

    results = []

    for configured_rate in [
        0.00,
        0.01,
        0.05,
        0.10,
        0.20,
    ]:

        print(
            f"\n  Testing configured loss: "
            f"{configured_rate * 100:.0f}%"
        )

        random.seed(
            RANDOM_SEED
            + int(configured_rate * 1000)
        )

        checker = new_sequence_checker(
            max_sequence_gap=1000
        )

        result = base_result(
            f"random_{int(configured_rate * 100)}pct"
        )

        result["configured_loss_rate"] = (
            configured_rate
        )

        result["packet_count"] = (
            packet_count
        )

        for _ in range(packet_count):

            packet = (
                pipeline.create_validator_packet()
            )

            result["generated"] += 1

            if (
                random.random()
                < configured_rate
            ):

                result["dropped"] += 1

                continue

            result["transmitted"] += 1

            validation = (
                pipeline.validate_packet(
                    packet,
                    checker,
                )
            )

            if validation["accepted"]:
                result["accepted"] += 1
            else:
                result["rejected"] += 1

            if not validation[
                "signature_valid"
            ]:
                result["signature_failures"] += 1

            if not validation[
                "commitment_valid"
            ]:
                result["commitment_failures"] += 1

        result["actual_loss_rate"] = (
            loss_rate(
                result["dropped"],
                result["transmitted"],
            )
        )

        result["sequence_gaps_detected"] = (
            checker.gap_count
        )

        result["replay_detections"] = (
            checker.replay_count
        )

        results.append(result)

        print(
            f"    Generated: "
            f"{result['generated']}"
        )

        print(
            f"    Dropped:   "
            f"{result['dropped']}"
        )

        print(
            f"    Accepted:  "
            f"{result['accepted']}"
        )

        print(
            f"    Rejected:  "
            f"{result['rejected']}"
        )

        print(
            f"    Actual loss: "
            f"{result['actual_loss_rate'] * 100:.2f}%"
        )

        print(
            f"    Gaps: "
            f"{result['sequence_gaps_detected']}"
        )

    return results


# ================================================================
# SCENARIO 2 — BURST LOSS
# ================================================================

def scenario_burst_loss(
    pipeline: PitCryptPipeline,
    packet_count: int = 100,
) -> list:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 2 — BURST PACKET LOSS"
    )
    print("=" * 65)

    results = []

    for burst_size in [3, 5, 10]:

        print(
            f"\n  Testing burst of "
            f"{burst_size} packets"
        )

        checker = new_sequence_checker(
            max_sequence_gap=1
        )

        result = base_result(
            f"burst_{burst_size}"
        )

        result["burst_size"] = (
            burst_size
        )

        result["packet_count"] = (
            packet_count
        )

        burst_start = 30
        burst_end = (
            burst_start + burst_size
        )

        for index in range(packet_count):

            packet = (
                pipeline.create_validator_packet()
            )

            result["generated"] += 1

            if (
                burst_start
                <= index
                < burst_end
            ):

                result["dropped"] += 1

                continue

            result["transmitted"] += 1

            validation = (
                pipeline.validate_packet(
                    packet,
                    checker,
                )
            )

            if validation["accepted"]:
                result["accepted"] += 1
            else:
                result["rejected"] += 1

            if not validation[
                "signature_valid"
            ]:
                result["signature_failures"] += 1

            if not validation[
                "commitment_valid"
            ]:
                result["commitment_failures"] += 1

        result["actual_loss_rate"] = (
            loss_rate(
                result["dropped"],
                result["transmitted"],
            )
        )

        result["sequence_gaps_detected"] = (
            checker.gap_count
        )

        result["replay_detections"] = (
            checker.replay_count
        )

        results.append(result)

        print(
            f"    Dropped: "
            f"{result['dropped']}"
        )

        print(
            f"    Accepted: "
            f"{result['accepted']}"
        )

        print(
            f"    Rejected: "
            f"{result['rejected']}"
        )

        print(
            f"    Gaps: "
            f"{result['sequence_gaps_detected']}"
        )

    return results


# ================================================================
# SCENARIO 3 — SELECTIVE LOSS
# ================================================================

def scenario_selective_loss(
    pipeline: PitCryptPipeline,
    packet_count: int = 100,
) -> dict:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 3 — SELECTIVE PACKET LOSS"
    )
    print("=" * 65)

    checker = new_sequence_checker(
        max_sequence_gap=1
    )

    drop_positions = {
        10,
        25,
        40,
        55,
        70,
        75,
        85,
        95,
    }

    result = base_result(
        "selective_loss"
    )

    result["packet_count"] = (
        packet_count
    )

    result["drop_positions"] = sorted(
        drop_positions
    )

    for index in range(packet_count):

        packet = (
            pipeline.create_validator_packet()
        )

        result["generated"] += 1

        if index in drop_positions:

            result["dropped"] += 1

            continue

        result["transmitted"] += 1

        validation = (
            pipeline.validate_packet(
                packet,
                checker,
            )
        )

        if validation["accepted"]:
            result["accepted"] += 1
        else:
            result["rejected"] += 1

        if not validation[
            "signature_valid"
        ]:
            result["signature_failures"] += 1

        if not validation[
            "commitment_valid"
        ]:
            result["commitment_failures"] += 1

    result["actual_loss_rate"] = (
        loss_rate(
            result["dropped"],
            result["transmitted"],
        )
    )

    result["sequence_gaps_detected"] = (
        checker.gap_count
    )

    result["replay_detections"] = (
        checker.replay_count
    )

    print(
        f"\n    Generated: "
        f"{result['generated']}"
    )

    print(
        f"    Dropped:   "
        f"{result['dropped']}"
    )

    print(
        f"    Accepted:  "
        f"{result['accepted']}"
    )

    print(
        f"    Rejected:  "
        f"{result['rejected']}"
    )

    print(
        f"    Gaps:      "
        f"{result['sequence_gaps_detected']}"
    )

    return result


# ================================================================
# SCENARIO 4 — RECOVERY
# ================================================================

def scenario_recovery(
    pipeline: PitCryptPipeline,
    phase_packets: int = 50,
) -> dict:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 4 — PACKET LOSS RECOVERY"
    )
    print("=" * 65)

    checker = new_sequence_checker(
        max_sequence_gap=1000
    )

    result = {
        "scenario": "recovery",
        "phase_packets": phase_packets,
        "normal": {
            "generated": 0,
            "transmitted": 0,
            "accepted": 0,
        },
        "loss": {
            "generated": 0,
            "transmitted": 0,
            "dropped": 0,
            "accepted": 0,
        },
        "recovery": {
            "generated": 0,
            "transmitted": 0,
            "accepted": 0,
        },
        "recovery_time_ms": None,
        "recovery_successful": False,
        "sequence_gaps_detected": 0,
    }

    # ------------------------------------------------------------
    # Phase 1 — normal
    # ------------------------------------------------------------

    print(
        "\n  Phase 1 — normal traffic"
    )

    for _ in range(phase_packets):

        packet = (
            pipeline.create_validator_packet()
        )

        result["normal"]["generated"] += 1
        result["normal"]["transmitted"] += 1

        validation = (
            pipeline.validate_packet(
                packet,
                checker,
            )
        )

        if validation["accepted"]:
            result["normal"]["accepted"] += 1

    # ------------------------------------------------------------
    # Phase 2 — complete loss
    # ------------------------------------------------------------

    print(
        "  Phase 2 — complete packet loss"
    )

    for _ in range(phase_packets):

        pipeline.create_validator_packet()

        result["loss"]["generated"] += 1
        result["loss"]["dropped"] += 1

    # ------------------------------------------------------------
    # Phase 3 — recovery
    # ------------------------------------------------------------

    print(
        "  Phase 3 — traffic recovery"
    )

    recovery_start = time.perf_counter()

    for _ in range(phase_packets):

        packet = (
            pipeline.create_validator_packet()
        )

        result["recovery"]["generated"] += 1
        result["recovery"]["transmitted"] += 1

        validation = (
            pipeline.validate_packet(
                packet,
                checker,
            )
        )

        if validation["accepted"]:

            result["recovery"]["accepted"] += 1

            if not result[
                "recovery_successful"
            ]:

                result[
                    "recovery_time_ms"
                ] = (
                    time.perf_counter()
                    - recovery_start
                ) * 1000.0

                result[
                    "recovery_successful"
                ] = True

    result["sequence_gaps_detected"] = (
        checker.gap_count
    )

    print(
        f"\n    Normal accepted: "
        f"{result['normal']['accepted']}"
    )

    print(
        f"    Lost packets: "
        f"{result['loss']['dropped']}"
    )

    print(
        f"    Recovery accepted: "
        f"{result['recovery']['accepted']}"
    )

    print(
        f"    Recovery successful: "
        f"{result['recovery_successful']}"
    )

    print(
        f"    Recovery time: "
        f"{result['recovery_time_ms']} ms"
    )

    print(
        f"    Sequence gaps: "
        f"{result['sequence_gaps_detected']}"
    )

    return result


# ================================================================
# SCENARIO 5 — HIGH LOAD
# ================================================================

def scenario_high_load(
    pipeline: PitCryptPipeline,
    packet_count: int = 1000,
    configured_loss: float = 0.05,
) -> dict:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 5 — HIGH-LOAD PACKET LOSS"
    )
    print("=" * 65)

    random.seed(
        RANDOM_SEED + 500
    )

    checker = new_sequence_checker(
        max_sequence_gap=1000
    )

    result = base_result(
        "high_load"
    )

    result["packet_count"] = packet_count

    result["configured_loss_rate"] = (
        configured_loss
    )

    start = time.perf_counter()

    for _ in range(packet_count):

        packet = (
            pipeline.create_validator_packet()
        )

        result["generated"] += 1

        if (
            random.random()
            < configured_loss
        ):

            result["dropped"] += 1

            continue

        result["transmitted"] += 1

        validation = (
            pipeline.validate_packet(
                packet,
                checker,
            )
        )

        if validation["accepted"]:
            result["accepted"] += 1
        else:
            result["rejected"] += 1

        if not validation[
            "signature_valid"
        ]:
            result["signature_failures"] += 1

        if not validation[
            "commitment_valid"
        ]:
            result["commitment_failures"] += 1

    elapsed = (
        time.perf_counter()
        - start
    )

    result["elapsed_seconds"] = (
        elapsed
    )

    result[
        "processing_rate_packets_per_second"
    ] = (
        result["generated"] / elapsed
        if elapsed > 0
        else 0.0
    )

    result[
        "transmitted_rate_packets_per_second"
    ] = (
        result["transmitted"] / elapsed
        if elapsed > 0
        else 0.0
    )

    result["actual_loss_rate"] = (
        loss_rate(
            result["dropped"],
            result["transmitted"],
        )
    )

    result["sequence_gaps_detected"] = (
        checker.gap_count
    )

    result["replay_detections"] = (
        checker.replay_count
    )

    print(
        f"\n    Generated: "
        f"{result['generated']}"
    )

    print(
        f"    Dropped: "
        f"{result['dropped']}"
    )

    print(
        f"    Accepted: "
        f"{result['accepted']}"
    )

    print(
        f"    Rejected: "
        f"{result['rejected']}"
    )

    print(
        f"    Actual loss: "
        f"{result['actual_loss_rate'] * 100:.2f}%"
    )

    print(
        f"    Processing rate: "
        f"{result['processing_rate_packets_per_second']:.1f} pkt/s"
    )

    print(
        f"    Sequence gaps: "
        f"{result['sequence_gaps_detected']}"
    )

    return result


# ================================================================
# SCENARIO 6 — DUPLICATE PACKETS / REPLAY
# ================================================================

def scenario_duplicate_packets(
    pipeline: PitCryptPipeline,
    packet_count: int = 100,
    duplicate_count: int = 10,
) -> dict:
    """
    Deliver selected packets twice.

    The first delivery should be accepted.

    The second delivery uses the exact same packet and sequence
    number and should therefore be rejected by sequence/replay
    protection.

    This tests the existing validator rather than implementing
    a second replay detector in the simulation.
    """

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 6 — DUPLICATE PACKETS / REPLAY"
    )
    print("=" * 65)

    checker = new_sequence_checker(
        max_sequence_gap=1000
    )

    duplicate_positions = {
        10,
        20,
        30,
        40,
        50,
        60,
        70,
        80,
        90,
        95,
    }

    duplicate_positions = {
        position
        for position in duplicate_positions
        if position < packet_count
    }

    if duplicate_count < len(
        duplicate_positions
    ):
        duplicate_positions = set(
            sorted(
                duplicate_positions
            )[:duplicate_count]
        )

    result = {
        "scenario": "duplicate_packets",
        "packet_count": packet_count,
        "duplicate_count": len(
            duplicate_positions
        ),
        "generated": packet_count,
        "original_transmitted": 0,
        "duplicate_transmitted": 0,
        "original_accepted": 0,
        "original_rejected": 0,
        "duplicates_accepted": 0,
        "duplicates_rejected": 0,
        "replay_detections": 0,
        "sequence_gaps_detected": 0,
        "duplicate_rejection_rate": 0.0,
        "replay_protection_successful": False,
    }

    for index in range(packet_count):

        packet = (
            pipeline.create_validator_packet()
        )

        # --------------------------------------------------------
        # Original delivery
        # --------------------------------------------------------

        result[
            "original_transmitted"
        ] += 1

        original_validation = (
            pipeline.validate_packet(
                packet,
                checker,
            )
        )

        if original_validation["accepted"]:

            result[
                "original_accepted"
            ] += 1

        else:

            result[
                "original_rejected"
            ] += 1

        # --------------------------------------------------------
        # Duplicate delivery
        # --------------------------------------------------------

        if index in duplicate_positions:

            result[
                "duplicate_transmitted"
            ] += 1

            duplicate_validation = (
                pipeline.validate_packet(
                    packet,
                    checker,
                )
            )

            if duplicate_validation[
                "accepted"
            ]:

                result[
                    "duplicates_accepted"
                ] += 1

            else:

                result[
                    "duplicates_rejected"
                ] += 1

    result[
        "replay_detections"
    ] = checker.replay_count

    result[
        "sequence_gaps_detected"
    ] = checker.gap_count

    duplicate_total = (
        result["duplicate_transmitted"]
    )

    if duplicate_total > 0:

        result[
            "duplicate_rejection_rate"
        ] = (
            result["duplicates_rejected"]
            / duplicate_total
        )

    result[
        "replay_protection_successful"
    ] = (
        duplicate_total > 0
        and result["duplicates_accepted"] == 0
        and result["duplicates_rejected"]
        == duplicate_total
    )

    print(
        f"\n    Originals transmitted: "
        f"{result['original_transmitted']}"
    )

    print(
        f"    Originals accepted:   "
        f"{result['original_accepted']}"
    )

    print(
        f"    Duplicates sent:      "
        f"{result['duplicate_transmitted']}"
    )

    print(
        f"    Duplicates rejected:  "
        f"{result['duplicates_rejected']}"
    )

    print(
        f"    Duplicates accepted:  "
        f"{result['duplicates_accepted']}"
    )

    print(
        f"    Replay detections:    "
        f"{result['replay_detections']}"
    )

    print(
        f"    Rejection rate:       "
        f"{result['duplicate_rejection_rate'] * 100:.1f}%"
    )

    print(
        f"    Replay protection:    "
        f"{result['replay_protection_successful']}"
    )

    return result


# ================================================================
# MAIN
# ================================================================

def main():

    random.seed(
        RANDOM_SEED
    )

    print("\n" + "=" * 70)
    print(
        "  PitCrypt-F1 Packet Loss / "
        "Network Resilience Evaluation"
    )
    print("=" * 70)

    print(
        f"\n  Team:    {TEAM}"
        f"\n  Race:    {RACE}"
        f"\n  Session: {SESSION}"
        f"\n  Seed:    {RANDOM_SEED}"
    )

    pipeline = PitCryptPipeline()

    # ============================================================
    # Run scenarios
    # ============================================================

    random_results = (
        scenario_random_loss(
            pipeline,
            packet_count=200,
        )
    )

    burst_results = (
        scenario_burst_loss(
            pipeline,
            packet_count=100,
        )
    )

    selective_result = (
        scenario_selective_loss(
            pipeline,
            packet_count=100,
        )
    )

    recovery_result = (
        scenario_recovery(
            pipeline,
            phase_packets=50,
        )
    )

    high_load_result = (
        scenario_high_load(
            pipeline,
            packet_count=1000,
            configured_loss=0.05,
        )
    )

    duplicate_result = (
        scenario_duplicate_packets(
            pipeline,
            packet_count=100,
            duplicate_count=10,
        )
    )

    # ============================================================
    # Assemble results
    # ============================================================

    results = {

        "metadata": {
            "project": "PitCrypt-F1",
            "experiment": (
                "packet_loss_network_resilience"
            ),
            "team": TEAM,
            "race": RACE,
            "session": SESSION,
            "random_seed": RANDOM_SEED,
            "generated_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
        },

        "scenarios": {

            "random_loss": random_results,

            "burst_loss": burst_results,

            "selective_loss": (
                selective_result
            ),

            "recovery": (
                recovery_result
            ),

            "high_load": (
                high_load_result
            ),

            "duplicate_packets": (
                duplicate_result
            ),
        },
    }

    # ============================================================
    # Save
    # ============================================================

    os.makedirs(
        RESULTS_DIR,
        exist_ok=True,
    )

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            results,
            file,
            indent=2,
        )

    # ============================================================
    # Summary
    # ============================================================

    print("\n" + "=" * 70)
    print(
        "  PACKET LOSS EVALUATION COMPLETE"
    )
    print("=" * 70)

    print(
        f"\n  Results saved to:"
        f"\n  {RESULTS_FILE}"
    )

    print("\n  Random loss:")

    for result in random_results:

        print(
            f"    "
            f"{result['configured_loss_rate'] * 100:>5.0f}% "
            f"configured → "
            f"{result['actual_loss_rate'] * 100:>5.2f}% actual | "
            f"accepted={result['accepted']:>3} | "
            f"rejected={result['rejected']:>3} | "
            f"gaps={result['sequence_gaps_detected']}"
        )

    print("\n  Burst loss:")

    for result in burst_results:

        print(
            f"    "
            f"{result['burst_size']:>2} packet burst → "
            f"dropped={result['dropped']:>2} | "
            f"accepted={result['accepted']:>3} | "
            f"gaps={result['sequence_gaps_detected']}"
        )

    print("\n  Selective loss:")

    print(
        f"    dropped="
        f"{selective_result['dropped']} | "
        f"accepted="
        f"{selective_result['accepted']} | "
        f"gaps="
        f"{selective_result['sequence_gaps_detected']}"
    )

    print("\n  Recovery:")

    print(
        f"    successful="
        f"{recovery_result['recovery_successful']} | "
        f"time="
        f"{recovery_result['recovery_time_ms']} ms"
    )

    print("\n  High load:")

    print(
        f"    "
        f"{high_load_result['processing_rate_packets_per_second']:.1f} pkt/s | "
        f"loss="
        f"{high_load_result['actual_loss_rate'] * 100:.2f}% | "
        f"accepted="
        f"{high_load_result['accepted']}"
    )

    print("\n  Duplicate / replay:")

    print(
        f"    duplicates="
        f"{duplicate_result['duplicate_transmitted']} | "
        f"rejected="
        f"{duplicate_result['duplicates_rejected']} | "
        f"accepted="
        f"{duplicate_result['duplicates_accepted']} | "
        f"replay detections="
        f"{duplicate_result['replay_detections']}"
    )

    print(
        f"    protection successful="
        f"{duplicate_result['replay_protection_successful']}"
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()