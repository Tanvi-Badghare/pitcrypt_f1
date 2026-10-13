"""
PitCrypt-F1 Key Rotation Evaluation
====================================

Evaluates the implemented KeyScheduler without modifying the
production scheduler.

Scenarios
---------

1. Manual forced rotation
2. Packet-count-triggered rotation

The experiment records:

- rotation event
- rotation reason
- rotation number
- previous packet count
- previous session age
- callback execution
- new public key generation
- scheduler counter reset


Important
---------

This benchmark validates key-rotation triggering.

It does NOT claim that a complete production car → relay
post-rotation ECDH re-handshake has been benchmarked.
"""


import os
import sys
import time
import json


# ================================================================
# PATH SETUP
# ================================================================

ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
    )
)

CAR_SRC = os.path.join(
    ROOT,
    "car_producer",
    "src",
)

if CAR_SRC not in sys.path:
    sys.path.insert(0, CAR_SRC)


# ================================================================
# IMPORTS
# ================================================================

from crypto_engine import CryptoEngine
from key_scheduler import KeyScheduler


# ================================================================
# CONFIGURATION
# ================================================================

RESULTS_DIR = os.path.join(
    ROOT,
    "simulations",
    "results",
)

RESULTS_FILE = os.path.join(
    RESULTS_DIR,
    "key_rotation_results.json",
)


# ================================================================
# HELPERS
# ================================================================

def rotation_event_to_dict(
    event,
    new_public_key: bytes,
) -> dict:
    """
    Convert a scheduler callback event into a JSON-safe record.
    """

    if hasattr(event, "to_dict"):

        record = event.to_dict()

    else:

        record = {
            "reason": getattr(
                event,
                "reason",
                None,
            ),
            "rotation_num": getattr(
                event,
                "rotation_num",
                None,
            ),
            "old_age": getattr(
                event,
                "old_age",
                None,
            ),
            "old_count": getattr(
                event,
                "old_count",
                None,
            ),
        }

    record["new_public_key_bytes"] = (
        len(new_public_key)
    )

    record["new_public_key_prefix"] = (
        new_public_key.hex()[:16]
    )

    return record


# ================================================================
# SCENARIO 1 — MANUAL ROTATION
# ================================================================

def scenario_manual_rotation() -> dict:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 1 — MANUAL KEY ROTATION"
    )
    print("=" * 65)

    engine = CryptoEngine(
        node_id="mercedes_car_rotation_test",
    )

    initial_public_key = (
        engine.new_session()
    )

    scheduler = KeyScheduler(
        crypto_engine=engine,
        max_age_seconds=9999,
        max_packets=99999,
        check_interval=1,
        node_id="mercedes_car_rotation_test",
    )

    callback_events = []

    def on_rotation(
        event,
        new_public_key,
    ):

        callback_events.append(
            rotation_event_to_dict(
                event,
                new_public_key,
            )
        )

    scheduler.on_rotation(
        on_rotation
    )

    # Simulate packets belonging to the old key.
    for _ in range(20):
        scheduler.record_packet()

    before = scheduler.status()

    start = time.perf_counter()

    scheduler.force_rotation()

    rotation_elapsed_ms = (
        time.perf_counter()
        - start
    ) * 1000.0

    after = scheduler.status()

    initial_key_hex = (
        initial_public_key.hex()
    )

    callback_count = len(
        callback_events
    )

    result = {
        "scenario": "manual_rotation",
        "initial_public_key_bytes": len(
            initial_public_key
        ),
        "initial_public_key_prefix": (
            initial_key_hex[:16]
        ),
        "before": before,
        "after": after,
        "callback_count": callback_count,
        "callback_events": callback_events,
        "rotation_elapsed_ms": round(
            rotation_elapsed_ms,
            3,
        ),
        "rotation_triggered": (
            scheduler.rotation_count == 1
        ),
        "packet_counter_reset": (
            scheduler.packet_count == 0
        ),
        "rotation_log_entries": len(
            scheduler.rotation_log
        ),
    }

    print(
        f"\n    Packets before rotation: "
        f"{before['packet_count']}"
    )

    print(
        f"    Rotation count: "
        f"{scheduler.rotation_count}"
    )

    print(
        f"    Callback count: "
        f"{callback_count}"
    )

    print(
        f"    Packet counter after: "
        f"{scheduler.packet_count}"
    )

    print(
        f"    Rotation trigger: "
        f"{result['rotation_triggered']}"
    )

    print(
        f"    Counter reset: "
        f"{result['packet_counter_reset']}"
    )

    print(
        f"    Rotation operation: "
        f"{result['rotation_elapsed_ms']} ms"
    )

    scheduler.stop()

    return result


# ================================================================
# SCENARIO 2 — PACKET COUNT ROTATION
# ================================================================

def scenario_packet_count_rotation() -> dict:

    print("\n" + "=" * 65)
    print(
        "  SCENARIO 2 — PACKET-COUNT KEY ROTATION"
    )
    print("=" * 65)

    engine = CryptoEngine(
        node_id="mercedes_car_count_rotation",
    )

    engine.new_session()

    scheduler = KeyScheduler(
        crypto_engine=engine,
        max_age_seconds=9999,
        max_packets=10,
        check_interval=0.01,
        node_id="mercedes_car_count_rotation",
    )

    callback_events = []

    def on_rotation(
        event,
        new_public_key,
    ):

        callback_events.append(
            rotation_event_to_dict(
                event,
                new_public_key,
            )
        )

    scheduler.on_rotation(
        on_rotation
    )

    scheduler.start()

    for _ in range(10):

        scheduler.record_packet()

    start = time.perf_counter()

    deadline = (
        time.perf_counter() + 2.0
    )

    while (
        scheduler.rotation_count == 0
        and time.perf_counter() < deadline
    ):

        time.sleep(0.005)

    elapsed_ms = (
        time.perf_counter()
        - start
    ) * 1000.0

    scheduler.stop()

    result = {
        "scenario": "packet_count_rotation",
        "configured_max_packets": 10,
        "packets_recorded_before_rotation": 10,
        "rotation_count": (
            scheduler.rotation_count
        ),
        "callback_count": len(
            callback_events
        ),
        "callback_events": callback_events,
        "rotation_wait_ms": round(
            elapsed_ms,
            3,
        ),
        "rotation_triggered": (
            scheduler.rotation_count >= 1
        ),
        "packet_counter_after_rotation": (
            scheduler.packet_count
        ),
        "counter_reset": (
            scheduler.packet_count == 0
        ),
    }

    print(
        f"\n    Packets recorded: 10"
    )

    print(
        f"    Rotation count: "
        f"{scheduler.rotation_count}"
    )

    print(
        f"    Callback count: "
        f"{len(callback_events)}"
    )

    print(
        f"    Rotation triggered: "
        f"{result['rotation_triggered']}"
    )

    print(
        f"    Counter reset: "
        f"{result['counter_reset']}"
    )

    return result


# ================================================================
# MAIN
# ================================================================

def main():

    print("\n" + "=" * 70)
    print(
        "  PitCrypt-F1 — Key Rotation Evaluation"
    )
    print("=" * 70)

    start = time.perf_counter()

    manual = (
        scenario_manual_rotation()
    )

    count_based = (
        scenario_packet_count_rotation()
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    output = {
        "simulation": "key_rotation",
        "timestamp": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(),
        ),
        "results": {
            "manual_rotation": manual,
            "packet_count_rotation": count_based,
        },
        "elapsed_s": round(
            elapsed,
            3,
        ),
    }

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
            output,
            file,
            indent=2,
        )

    print("\n" + "=" * 70)
    print(
        "  KEY ROTATION EVALUATION COMPLETE"
    )
    print("=" * 70)

    print(
        f"\n  Results saved → "
        f"{RESULTS_FILE}"
    )

    print(
        "\n  Manual rotation: "
        f"{manual['rotation_triggered']}"
    )

    print(
        "  Packet-count rotation: "
        f"{count_based['rotation_triggered']}"
    )

    print(
        "\n  Note: this validates rotation "
        "triggering and scheduler behaviour."
    )

    print(
        "  It does not benchmark a complete "
        "post-rotation peer re-handshake."
    )


if __name__ == "__main__":
    main()