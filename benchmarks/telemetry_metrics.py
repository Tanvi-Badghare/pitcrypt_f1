"""
telemetry_metrics.py
---------------------
F1-domain-specific data for the PitCrypt-F1 benchmark suite.

Provides:
  - five constructors
  - constructor/car identifiers
  - thirteen target circuits
  - FastF1 event mappings
  - realistic telemetry channel ranges
  - a common TelemetrySample packet shape
  - offline synthetic telemetry generation
  - optional cached FastF1 telemetry loading

Design goals:
  1. Benchmarks must remain runnable without network access.
  2. Cached FastF1 data must never be required for CI.
  3. Real-data loading must happen outside timed throughput work.
  4. Multi-car samples must retain the correct constructor/car identity.
  5. Synthetic data must remain deterministic for a given seed.
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Fixed domain constants
# ---------------------------------------------------------------------------

CONSTRUCTORS = [
    "Red Bull Racing",
    "Ferrari",
    "Mercedes",
    "McLaren",
    "Aston Martin",
]

# Stable short identifiers used by benchmark car IDs.
CONSTRUCTOR_CODES = {
    "Red Bull Racing": "RBR",
    "Ferrari": "FER",
    "Mercedes": "MER",
    "McLaren": "MCL",
    "Aston Martin": "AMR",
}

# Circuit names exposed to the rest of the project.
CIRCUITS = [
    "Bahrain International Circuit",
    "Jeddah Corniche Circuit",
    "Albert Park Circuit",
    "Suzuka Circuit",
    "Shanghai International Circuit",
    "Miami International Autodrome",
    "Circuit de Monaco",
    "Circuit de Barcelona-Catalunya",
    "Red Bull Ring",
    "Silverstone Circuit",
    "Circuit de Spa-Francorchamps",
    "Monza Circuit",
    "Circuit of the Americas",
]

# FastF1 is more reliable when resolving the corresponding event/Grand Prix
# rather than relying on a circuit-name alias. These are the 2025 event names
# associated with the benchmark circuits above.
FASTF1_EVENTS = {
    "Bahrain International Circuit": "Bahrain Grand Prix",
    "Jeddah Corniche Circuit": "Saudi Arabian Grand Prix",
    "Albert Park Circuit": "Australian Grand Prix",
    "Suzuka Circuit": "Japanese Grand Prix",
    "Shanghai International Circuit": "Chinese Grand Prix",
    "Miami International Autodrome": "Miami Grand Prix",
    "Circuit de Monaco": "Monaco Grand Prix",
    "Circuit de Barcelona-Catalunya": "Spanish Grand Prix",
    "Red Bull Ring": "Austrian Grand Prix",
    "Silverstone Circuit": "British Grand Prix",
    "Circuit de Spa-Francorchamps": "Belgian Grand Prix",
    "Monza Circuit": "Italian Grand Prix",
    "Circuit of the Americas": "United States Grand Prix",
}

# Approximate FastF1 car telemetry sampling rate.
#
# This is used for synthetic timestamps and domain realism. It is NOT a
# protocol constraint and does not limit benchmark processing throughput.
SAMPLE_RATE_HZ = 5.0

# Plausible telemetry channel ranges used by both:
#   - synthetic data generation
#   - anomaly checking in benchmark_latency.py
CHANNEL_RANGES = {
    "speed_kph": (0.0, 372.0),
    "throttle_pct": (0.0, 100.0),
    "brake_pct": (0.0, 100.0),
    "rpm": (0.0, 15000.0),
    "gear": (0, 8),
    "drs": (0, 1),
}


# ---------------------------------------------------------------------------
# Telemetry data model
# ---------------------------------------------------------------------------

@dataclass
class TelemetrySample:
    car_id: str
    constructor: str
    circuit: str
    sequence: int
    timestamp: float

    speed_kph: float
    throttle_pct: float
    brake_pct: float
    rpm: float
    gear: int
    drs: int

    x: float
    y: float

    def to_json_bytes(self) -> bytes:
        """
        Serialize the complete telemetry sample deterministically.

        sort_keys=True keeps benchmark serialization reproducible.
        """
        return json.dumps(
            {
                "car_id": self.car_id,
                "constructor": self.constructor,
                "circuit": self.circuit,
                "sequence": self.sequence,
                "timestamp": self.timestamp,
                "speed_kph": self.speed_kph,
                "throttle_pct": self.throttle_pct,
                "brake_pct": self.brake_pct,
                "rpm": self.rpm,
                "gear": self.gear,
                "drs": self.drs,
                "x": self.x,
                "y": self.y,
            },
            sort_keys=True,
        ).encode("utf-8")


def estimate_packet_size_bytes(sample: TelemetrySample) -> int:
    """
    Return the serialized telemetry payload size before cryptographic
    overhead.

    This is useful when translating packet throughput into approximate
    telemetry byte throughput.
    """
    return len(sample.to_json_bytes())


# ---------------------------------------------------------------------------
# Constructor / car identity helpers
# ---------------------------------------------------------------------------

def constructor_for_car(car_id: str) -> str:
    """
    Resolve a constructor from a benchmark car identifier.

    Expected examples:
        RBR-01 -> Red Bull Racing
        RBR-02 -> Red Bull Racing
        FER-01 -> Ferrari
        MER-02 -> Mercedes
        MCL-01 -> McLaren
        AMR-02 -> Aston Martin

    Falls back to "Red Bull Racing" for unknown IDs so malformed benchmark
    inputs remain deterministic rather than crashing the generator.
    """
    code = car_id.split("-", 1)[0].upper()

    for constructor, constructor_code in CONSTRUCTOR_CODES.items():
        if code == constructor_code:
            return constructor

    return CONSTRUCTORS[0]


def default_car_ids(n_cars: int) -> list[str]:
    """
    Generate benchmark car IDs in constructor order.

    For 10 cars this produces:

        RBR-01
        RBR-02
        FER-01
        FER-02
        MER-01
        MER-02
        MCL-01
        MCL-02
        AMR-01
        AMR-02
    """
    if n_cars <= 0:
        return []

    ids: list[str] = []

    for index in range(n_cars):
        constructor = CONSTRUCTORS[index % len(CONSTRUCTORS)]
        car_number = index // len(CONSTRUCTORS) + 1
        code = CONSTRUCTOR_CODES[constructor]
        ids.append(f"{code}-{car_number:02d}")

    return ids


# ---------------------------------------------------------------------------
# FastF1 loading
# ---------------------------------------------------------------------------

def _try_load_real_fastf1_sample(
    circuit: str,
    year: int = 2025,
) -> Optional[list[dict]]:
    """
    Attempt to load one fastest lap of cached FastF1 race telemetry.

    IMPORTANT:
    - This function never performs a live network fetch.
    - If FastF1 is unavailable, it returns None.
    - If the event/session cannot be loaded from cache, it returns None.
    - The circuit is explicitly mapped to a Grand Prix event name instead of
      passing the circuit alias directly to FastF1.

    Returning None is intentional: the benchmark layer can then fall back
    to deterministic synthetic telemetry.
    """
    try:
        import fastf1  # type: ignore
    except ImportError:
        return None

    event_name = FASTF1_EVENTS.get(circuit)

    if event_name is None:
        return None

    try:
        # Only read from FastF1's existing cache.
        #
        # No live network request is intentionally triggered here.
        session = fastf1.get_session(year, event_name, "R")

        session.load(
            telemetry=True,
            laps=True,
            weather=False,
            messages=False,
        )

        lap = session.laps.pick_fastest()

        if lap is None:
            return None

        car_data = lap.get_car_data()

        if car_data is None or len(car_data) == 0:
            return None

        return car_data.to_dict("records")  # type: ignore[no-any-return]

    except Exception:
        # Benchmarks must remain robust in environments where:
        #   - FastF1 is absent
        #   - cache is incomplete
        #   - a session is unavailable
        #   - telemetry loading fails
        return None


# ---------------------------------------------------------------------------
# Synthetic telemetry
# ---------------------------------------------------------------------------

def _synthetic_lap(
    n_samples: int,
    seed: int,
) -> list[dict]:
    """
    Generate deterministic, physically-plausible synthetic telemetry.

    The profile contains:
      - acceleration
      - braking
      - cornering
      - gear changes
      - RPM variation
      - DRS activation
      - X/Y track coordinates

    Synthetic generation is deliberately deterministic for reproducible
    benchmark comparisons.
    """
    rng = random.Random(seed)

    samples: list[dict] = []

    for i in range(n_samples):
        phase = (i / n_samples) * 2 * math.pi

        # Fast straights and slower corners.
        speed = max(
            40.0,
            200.0
            + 170.0 * math.sin(phase)
            + rng.uniform(-5.0, 5.0),
        )

        accelerating = math.cos(phase) > 0

        throttle = min(
            100.0,
            max(
                0.0,
                60.0
                + 40.0 * math.cos(phase)
                + rng.uniform(-3.0, 3.0),
            ),
        )

        if accelerating:
            brake = 0.0
        else:
            brake = min(
                100.0,
                max(
                    0.0,
                    40.0 - 40.0 * math.cos(phase),
                ),
            )

        gear = max(
            1,
            min(
                8,
                int(speed // 45) + 1,
            ),
        )

        rpm = min(
            15000.0,
            max(
                4000.0,
                (speed / 372.0) * 15000.0
                + rng.uniform(-200.0, 200.0),
            ),
        )

        drs = 1 if accelerating and speed > 280 else 0

        samples.append(
            {
                "Speed": speed,
                "Throttle": throttle,
                "Brake": brake,
                "nGear": gear,
                "RPM": rpm,
                "DRS": drs,
                "X": 1000.0 * math.cos(phase),
                "Y": 1000.0 * math.sin(phase),
            }
        )

    return samples


# ---------------------------------------------------------------------------
# Packet stream generation
# ---------------------------------------------------------------------------

def generate_packet_stream(
    n_packets: int,
    car_ids: Optional[list[str]] = None,
    circuit: Optional[str] = None,
    anomaly_rate: float = 0.0,
    use_real_data: bool = True,
    seed: int = 42,
) -> Iterator[TelemetrySample]:
    """
    Yield n_packets telemetry samples.

    Samples are distributed round-robin across car_ids.

    IMPORTANT SEQUENCE BEHAVIOUR
    -----------------------------
    Sequence numbers are maintained PER CAR.

    Example with two cars:

        RBR-01: 0, 1, 2, 3, ...
        RBR-02: 0, 1, 2, 3, ...

    This is required for the validator's per-car sequence checker and is
    especially important for the multi-car throughput benchmark.

    Data source:
        1. cached FastF1 telemetry when available and requested
        2. deterministic synthetic telemetry otherwise

    anomaly_rate:
        Fraction of packets for which one telemetry channel is deliberately
        pushed outside CHANNEL_RANGES.
    """
    if n_packets <= 0:
        return

    if car_ids is None:
        car_ids = default_car_ids(len(CONSTRUCTORS))

    if not car_ids:
        return

    circuit = circuit or CIRCUITS[0]

    if circuit not in CIRCUITS:
        raise ValueError(
            f"Unknown circuit '{circuit}'. "
            f"Expected one of: {', '.join(CIRCUITS)}"
        )

    if not 0.0 <= anomaly_rate <= 1.0:
        raise ValueError("anomaly_rate must be between 0.0 and 1.0")

    rng = random.Random(seed)

    # FastF1/synthetic loading happens before the first yielded packet.
    #
    # The throughput benchmark explicitly primes this generator before its
    # timed processing interval, so cache loading is not counted as packet
    # processing throughput.
    real = (
        _try_load_real_fastf1_sample(circuit)
        if use_real_data
        else None
    )

    lap = real if real else _synthetic_lap(
        max(n_packets, 200),
        seed,
    )

    if not lap:
        return

    start_time = time.time()

    # Per-car sequence state.
    #
    # Each car starts at sequence zero independently.
    sequences = {car_id: 0 for car_id in car_ids}

    for i in range(n_packets):
        car_id = car_ids[i % len(car_ids)]

        constructor = constructor_for_car(car_id)

        sequence = sequences[car_id]
        sequences[car_id] += 1

        row = lap[i % len(lap)]

        sample = TelemetrySample(
            car_id=car_id,
            constructor=constructor,
            circuit=circuit,
            sequence=sequence,
            timestamp=start_time + sequence / SAMPLE_RATE_HZ,
            speed_kph=float(row.get("Speed", 0.0)),
            throttle_pct=float(row.get("Throttle", 0.0)),
            brake_pct=float(row.get("Brake", 0.0)),
            rpm=float(row.get("RPM", 0.0)),
            gear=int(row.get("nGear", 1)),
            drs=int(bool(row.get("DRS", 0))),
            x=float(row.get("X", 0.0)),
            y=float(row.get("Y", 0.0)),
        )

        if rng.random() < anomaly_rate:
            channel = rng.choice(list(CHANNEL_RANGES.keys()))
            _, hi = CHANNEL_RANGES[channel]

            # Deliberately place the selected value outside the accepted
            # range so the anomaly-check stage has something to reject.
            setattr(
                sample,
                channel,
                hi * 3 + 1,
            )

        yield sample