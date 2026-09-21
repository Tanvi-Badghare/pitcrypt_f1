"""
benchmark_throughput.py
-----------------------

Throughput benchmark for PitCrypt-F1.

Scenarios:
    1. single_car - one car producer's sustained packet processing
       through the full PitCrypt reference pipeline.
    2. multi_car  - concurrent load across multiple car nodes using
       one OS process per car.

Important methodology:
    - FastF1 / telemetry preparation happens BEFORE the timed processing
      interval for each worker.
    - Only PitCrypt packet processing contributes to packets/sec.
    - Each worker measures its own CPU time and peak RSS.
    - The parent process aggregates worker resource measurements.
    - Results are automatically saved to a unique filename unless
      --output-json is supplied.

Examples:

    python benchmark_throughput.py ^
        --duration 5 ^
        --cars 1 ^
        --circuit "Silverstone Circuit" ^
        --synthetic

    python benchmark_throughput.py ^
        --duration 5 ^
        --cars 10 ^
        --circuit "Silverstone Circuit" ^
        --synthetic

    python benchmark_throughput.py ^
        --duration 5 ^
        --cars 10 ^
        --circuit "Silverstone Circuit"
"""

from __future__ import annotations

import argparse
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import metrics
import telemetry_metrics as tm
from benchmark_latency import PitCryptPipeline


# ---------------------------------------------------------------------------
# Resource measurement
# ---------------------------------------------------------------------------

def get_process_resources() -> dict:
    """
    Return resource information for the CURRENT process.

    psutil is used because the benchmark is primarily intended to run on
    Windows and psutil provides consistent process-level CPU/RSS metrics.

    Returns:
        {
            "cpu_time_s": float | None,
            "rss_mb": float | None,
        }
    """
    try:
        import psutil
    except ImportError:
        return {
            "cpu_time_s": None,
            "rss_mb": None,
        }

    try:
        process = psutil.Process(os.getpid())

        cpu_times = process.cpu_times()
        cpu_time_s = cpu_times.user + cpu_times.system

        rss_mb = process.memory_info().rss / (1024 * 1024)

        return {
            "cpu_time_s": cpu_time_s,
            "rss_mb": rss_mb,
        }

    except Exception:
        return {
            "cpu_time_s": None,
            "rss_mb": None,
        }


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _run_car_for_duration(
    car_id: str,
    circuit: str,
    duration_s: float,
    seed: int,
    use_real_data: bool,
) -> dict:
    """
    Run one car's packet pipeline for duration_s seconds.

    Telemetry preparation is deliberately completed before the timed
    processing interval so FastF1 loading does not contaminate the
    throughput measurement.

    Each worker returns its own resource measurements to the parent.
    """

    pipeline = PitCryptPipeline()

    stream = tm.generate_packet_stream(
        n_packets=1_000_000,
        car_ids=[car_id],
        circuit=circuit,
        anomaly_rate=0.0,
        use_real_data=use_real_data,
        seed=seed,
    )

    # ------------------------------------------------------------------
    # Prime the generator.
    #
    # This is important because FastF1 may perform substantial loading
    # work on the first next(stream). That work must not be counted as
    # packet-processing throughput.
    # ------------------------------------------------------------------

    try:
        first_sample = next(stream)
    except StopIteration:
        return {
            "car_id": car_id,
            "generated": 0,
            "accepted": 0,
            "rejected": 0,
            "duration_s": 0.0,
            "packets_per_sec": 0.0,
            "failure_stages": {},
            "cpu_time_s": 0.0,
            "peak_rss_mb": None,
        }

    # ------------------------------------------------------------------
    # Establish CPU baseline AFTER telemetry preparation.
    # ------------------------------------------------------------------

    resources_before = get_process_resources()
    cpu_before = resources_before["cpu_time_s"]

    # ------------------------------------------------------------------
    # Timed packet-processing interval
    # ------------------------------------------------------------------

    start = time.perf_counter()
    deadline = start + duration_s

    generated = 0
    accepted = 0
    rejected = 0

    failure_stages: dict[str, int] = {}

    # Process the primed packet.
    result = pipeline.process_packet(first_sample)
    generated += 1

    if result.success:
        accepted += 1
    else:
        rejected += 1
        stage = getattr(result, "failed_stage", None) or "unknown"
        failure_stages[stage] = failure_stages.get(stage, 0) + 1

    # Process remaining packets until the deadline.
    for sample in stream:
        if time.perf_counter() >= deadline:
            break

        result = pipeline.process_packet(sample)
        generated += 1

        if result.success:
            accepted += 1
        else:
            rejected += 1
            stage = getattr(result, "failed_stage", None) or "unknown"
            failure_stages[stage] = failure_stages.get(stage, 0) + 1

    elapsed = time.perf_counter() - start

    # ------------------------------------------------------------------
    # Resource measurement AFTER processing.
    # ------------------------------------------------------------------

    resources_after = get_process_resources()

    cpu_after = resources_after["cpu_time_s"]

    cpu_time_s = None

    if cpu_before is not None and cpu_after is not None:
        cpu_time_s = max(0.0, cpu_after - cpu_before)

    peak_rss_mb = resources_after["rss_mb"]

    return {
        "car_id": car_id,
        "generated": generated,
        "accepted": accepted,
        "rejected": rejected,
        "duration_s": elapsed,
        "packets_per_sec": (
            accepted / elapsed
            if elapsed > 0
            else 0.0
        ),
        "failure_stages": failure_stages,
        "cpu_time_s": cpu_time_s,
        "peak_rss_mb": peak_rss_mb,
    }


# ---------------------------------------------------------------------------
# Single-car benchmark
# ---------------------------------------------------------------------------

def run_single_car(
    duration_s: float,
    circuit: str,
    use_real_data: bool,
) -> dict:

    result = _run_car_for_duration(
        car_id="RBR-01",
        circuit=circuit,
        duration_s=duration_s,
        seed=1,
        use_real_data=use_real_data,
    )

    return {
        "cars": 1,
        "duration_s": result["duration_s"],
        "packets_generated": result["generated"],
        "packets_accepted": result["accepted"],
        "packets_rejected": result["rejected"],
        "packets_per_sec": result["packets_per_sec"],
        "packets_per_sec_per_car": result["packets_per_sec"],
        "failure_stages": result["failure_stages"],
        "cpu_time_s": result["cpu_time_s"],
        "peak_rss_mb": result["peak_rss_mb"],
        "per_car": [result],
    }


# ---------------------------------------------------------------------------
# Multi-car benchmark
# ---------------------------------------------------------------------------

def run_multi_car(
    n_cars: int,
    duration_s: float,
    circuit: str,
    use_real_data: bool,
) -> dict:

    car_ids = tm.default_car_ids(n_cars)

    # Parent wall-clock timer.
    #
    # This includes worker creation and scheduling overhead. The actual
    # packets/sec measurement inside each worker only covers packet
    # processing. We retain this parent timing separately so the result
    # clearly distinguishes processing throughput from orchestration cost.
    wall_start = time.perf_counter()

    per_car_results = []

    with ProcessPoolExecutor(max_workers=n_cars) as pool:

        futures = [
            pool.submit(
                _run_car_for_duration,
                car_id,
                circuit,
                duration_s,
                i + 1,
                use_real_data,
            )
            for i, car_id in enumerate(car_ids)
        ]

        for future in as_completed(futures):
            per_car_results.append(future.result())

    wall_elapsed = time.perf_counter() - wall_start

    # ------------------------------------------------------------------
    # Aggregate packet statistics.
    # ------------------------------------------------------------------

    total_generated = sum(
        result["generated"]
        for result in per_car_results
    )

    total_accepted = sum(
        result["accepted"]
        for result in per_car_results
    )

    total_rejected = sum(
        result["rejected"]
        for result in per_car_results
    )

    # ------------------------------------------------------------------
    # Aggregate failure stages.
    # ------------------------------------------------------------------

    failure_stages: dict[str, int] = {}

    for result in per_car_results:

        for stage, count in result["failure_stages"].items():

            failure_stages[stage] = (
                failure_stages.get(stage, 0) + count
            )

    # ------------------------------------------------------------------
    # Aggregate worker CPU time.
    #
    # This is SUM(worker CPU time), not CPU utilization.
    # ------------------------------------------------------------------

    cpu_times = [
        result["cpu_time_s"]
        for result in per_car_results
        if result["cpu_time_s"] is not None
    ]

    aggregate_cpu_time_s = (
        sum(cpu_times)
        if cpu_times
        else None
    )

    # ------------------------------------------------------------------
    # Worker memory.
    #
    # max = highest memory used by any individual worker.
    # sum = sum of each worker's RSS measurements.
    #
    # Sum is useful as a rough process-memory footprint, but RSS is not
    # necessarily fully additive because operating-system shared pages
    # may be counted in multiple processes.
    # ------------------------------------------------------------------

    memory_values = [
        result["peak_rss_mb"]
        for result in per_car_results
        if result["peak_rss_mb"] is not None
    ]

    max_worker_rss_mb = (
        max(memory_values)
        if memory_values
        else None
    )

    sum_worker_rss_mb = (
        sum(memory_values)
        if memory_values
        else None
    )

    # ------------------------------------------------------------------
    # CPU utilization estimate.
    #
    # Approximate utilization across the logical CPU pool:
    #
    #     aggregate CPU time
    #     ------------------
    #     wall time * CPUs
    #
    # This is an approximation and is intended for benchmark context,
    # not OS-level profiling.
    # ------------------------------------------------------------------

    logical_cpus = os.cpu_count() or 1

    aggregate_cpu_utilization_pct = None

    if (
        aggregate_cpu_time_s is not None
        and wall_elapsed > 0
        and logical_cpus > 0
    ):
        aggregate_cpu_utilization_pct = (
            aggregate_cpu_time_s
            / (wall_elapsed * logical_cpus)
            * 100.0
        )

    return {
        "cars": n_cars,

        # Parent-level wall-clock information.
        "wall_duration_s": wall_elapsed,

        # Aggregate worker processing results.
        "packets_generated": total_generated,
        "packets_accepted": total_accepted,
        "packets_rejected": total_rejected,

        # Throughput based on aggregate worker processing time.
        "packets_per_sec": (
            total_accepted / duration_s
            if duration_s > 0
            else 0.0
        ),

        "packets_per_sec_per_car": (
            total_accepted / duration_s / n_cars
            if duration_s > 0
            else 0.0
        ),

        "failure_stages": failure_stages,

        # CPU metrics.
        "logical_cpus": logical_cpus,
        "aggregate_cpu_time_s": aggregate_cpu_time_s,
        "aggregate_cpu_utilization_pct": (
            aggregate_cpu_utilization_pct
        ),

        # Memory metrics.
        "max_worker_rss_mb": max_worker_rss_mb,
        "sum_worker_rss_mb": sum_worker_rss_mb,

        # Individual worker measurements.
        "per_car": sorted(
            per_car_results,
            key=lambda result: result["car_id"],
        ),
    }


# ---------------------------------------------------------------------------
# Result filename
# ---------------------------------------------------------------------------

def build_output_path(
    requested_path: str | None,
    circuit: str,
    cars: int,
    duration_s: float,
    synthetic: bool,
) -> Path:

    if requested_path:
        return Path(requested_path)

    source = "synthetic" if synthetic else "fastf1"

    circuit_slug = (
        circuit
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("/", "_")
    )

    duration_slug = str(duration_s).replace(".", "p")

    filename = (
        f"throughput_{source}_"
        f"{circuit_slug}_"
        f"{cars}cars_"
        f"{duration_slug}s.json"
    )

    return Path("results") / filename


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_failure_stages(
    label: str,
    stages: dict[str, int],
) -> None:

    print(f"\n{label} failure stages:")

    if not stages:
        print("none")
        return

    for stage, count in sorted(stages.items()):
        print(f"{stage}: {count}")


def print_single_resources(result: dict) -> None:

    print("\nSingle-car resources:")

    cpu_time = result.get("cpu_time_s")
    memory = result.get("peak_rss_mb")

    if cpu_time is not None:
        print(f"CPU time: {cpu_time:.3f}s")
    else:
        print("CPU time: unavailable")

    if memory is not None:
        print(f"Peak RSS: {memory:.1f} MB")
    else:
        print("Peak RSS: unavailable")


def print_multi_resources(result: dict) -> None:

    print("\nMulti-car resources:")

    cpu_time = result.get("aggregate_cpu_time_s")
    max_rss = result.get("max_worker_rss_mb")
    sum_rss = result.get("sum_worker_rss_mb")
    cpu_util = result.get("aggregate_cpu_utilization_pct")
    logical_cpus = result.get("logical_cpus")

    if cpu_time is not None:
        print(
            f"Aggregate worker CPU time: "
            f"{cpu_time:.3f}s"
        )
    else:
        print(
            "Aggregate worker CPU time: unavailable"
        )

    if max_rss is not None:
        print(
            f"Peak RSS of any worker: "
            f"{max_rss:.1f} MB"
        )
    else:
        print(
            "Peak RSS of any worker: unavailable"
        )

    if sum_rss is not None:
        print(
            f"Sum of worker RSS measurements: "
            f"{sum_rss:.1f} MB"
        )
    else:
        print(
            "Sum of worker RSS measurements: unavailable"
        )

    if cpu_util is not None:
        print(
            f"Approx. aggregate CPU utilization: "
            f"{cpu_util:.1f}% "
            f"({logical_cpus} logical CPUs)"
        )
    else:
        print(
            "Approx. aggregate CPU utilization: "
            "unavailable"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description="PitCrypt-F1 pipeline throughput benchmark"
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="Processing duration per scenario in seconds",
    )

    parser.add_argument(
        "--cars",
        type=int,
        default=10,
        help="Concurrent cars for the multi-car scenario",
    )

    parser.add_argument(
        "--circuit",
        type=str,
        choices=tm.CIRCUITS,
        required=True,
        help="Circuit/workload to benchmark",
    )

    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Use synthetic telemetry instead of cached FastF1 telemetry",
    )

    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Explicit output path; otherwise a unique filename is generated",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Validate arguments.
    # ------------------------------------------------------------------

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    if args.cars <= 0:
        parser.error("--cars must be greater than zero")

    use_real_data = not args.synthetic

    data_source = (
        "synthetic"
        if args.synthetic
        else "cached FastF1 + synthetic fallback"
    )

    output_path = build_output_path(
        requested_path=args.output_json,
        circuit=args.circuit,
        cars=args.cars,
        duration_s=args.duration,
        synthetic=args.synthetic,
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------------
    # Header.
    # ------------------------------------------------------------------

    print(
        f"\nPitCrypt-F1 throughput benchmark "
        f"(circuit={args.circuit})"
    )

    print(f"Data source: {data_source}\n")

    # ------------------------------------------------------------------
    # Single-car scenario.
    # ------------------------------------------------------------------

    print(
        f"Running single-car scenario for "
        f"{args.duration:.1f}s ..."
    )

    single = run_single_car(
        duration_s=args.duration,
        circuit=args.circuit,
        use_real_data=use_real_data,
    )

    # ------------------------------------------------------------------
    # Multi-car scenario.
    # ------------------------------------------------------------------

    print(
        f"Running multi-car scenario "
        f"({args.cars} cars) for "
        f"{args.duration:.1f}s ..."
    )

    multi = run_multi_car(
        n_cars=args.cars,
        duration_s=args.duration,
        circuit=args.circuit,
        use_real_data=use_real_data,
    )

    # ------------------------------------------------------------------
    # Summary table.
    # ------------------------------------------------------------------

    rows = [
        [
            "single_car",
            "1",
            f"{single['packets_generated']}",
            f"{single['packets_accepted']}",
            f"{single['packets_rejected']}",
            f"{single['packets_per_sec']:.1f}",
            "-",
        ],
        [
            "multi_car",
            str(args.cars),
            f"{multi['packets_generated']}",
            f"{multi['packets_accepted']}",
            f"{multi['packets_rejected']}",
            f"{multi['packets_per_sec']:.1f}",
            f"{multi['packets_per_sec_per_car']:.1f}",
        ],
    ]

    metrics.print_table(
        [
            "scenario",
            "cars",
            "generated",
            "accepted",
            "rejected",
            "accepted pkt/s",
            "accepted pkt/s/car",
        ],
        rows,
    )

    # ------------------------------------------------------------------
    # Failure reporting.
    # ------------------------------------------------------------------

    print_failure_stages(
        "Single-car",
        single["failure_stages"],
    )

    print_failure_stages(
        "Multi-car",
        multi["failure_stages"],
    )

    # ------------------------------------------------------------------
    # Resource reporting.
    # ------------------------------------------------------------------

    print_single_resources(single)

    print_multi_resources(multi)

    # ------------------------------------------------------------------
    # Save result.
    # ------------------------------------------------------------------

    run = metrics.BenchmarkRun(
        benchmark="benchmark_throughput",
        scenario="single_and_multi_car",
        parameters={
            "duration": args.duration,
            "cars": args.cars,
            "circuit": args.circuit,
            "synthetic": args.synthetic,
            "data_source": data_source,
        },
        results={
            "single_car": single,
            "multi_car": multi,
        },
    )

    metrics.save_json(
        run,
        str(output_path),
    )

    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()