"""
metrics.py
----------
Generic, pipeline-agnostic benchmarking utilities used by every other
script in this folder: a timing context manager, latency-distribution
summaries, and result persistence (JSON + CSV) so runs can be diffed
across commits.

Nothing here knows about F1 telemetry or the PitCrypt-F1 pipeline
specifically - that lives in `telemetry_metrics.py` and the two
`benchmark_*.py` scripts. Keeping this file generic means it can also be
reused to benchmark the Rust `zkp-module` later (e.g. via a PyO3 binding
or subprocess) without modification.
"""

from __future__ import annotations

import csv
import json
import statistics
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator


@contextmanager
def timer() -> Iterator["_Elapsed"]:
    """Context manager that measures wall-clock time of its `with` block.

    Usage:
        with timer() as t:
            do_work()
        print(t.seconds)
    """
    elapsed = _Elapsed()
    start = time.perf_counter()
    try:
        yield elapsed
    finally:
        elapsed.seconds = time.perf_counter() - start


class _Elapsed:
    seconds: float = 0.0


@dataclass
class LatencyStats:
    """Summary statistics for a single distribution of latencies, in
    seconds. All benchmark scripts convert to milliseconds only at the
    point of printing/exporting, so stats stay in SI units internally.
    """

    count: int
    mean_s: float
    median_s: float
    stdev_s: float
    min_s: float
    max_s: float
    p95_s: float
    p99_s: float

    @property
    def mean_ms(self) -> float:
        return self.mean_s * 1000

    @property
    def p95_ms(self) -> float:
        return self.p95_s * 1000

    @property
    def p99_ms(self) -> float:
        return self.p99_s * 1000


def summarize(latencies_s: list[float]) -> LatencyStats:
    """Compute summary statistics for a list of latency samples (seconds).
    Falls back gracefully for tiny sample sizes (n < 2), which happens in
    quick smoke-test runs.
    """
    if not latencies_s:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    n = len(latencies_s)
    mean = statistics.fmean(latencies_s)
    median = statistics.median(latencies_s)
    stdev = statistics.stdev(latencies_s) if n > 1 else 0.0
    lo, hi = min(latencies_s), max(latencies_s)

    if n >= 100:
        quantiles = statistics.quantiles(latencies_s, n=100, method="inclusive")
        p95, p99 = quantiles[94], quantiles[98]
    elif n >= 2:
        # Not enough samples for stable 1%-resolution quantiles; fall
        # back to nearest-rank on the sorted sample so small smoke-test
        # runs still produce a sane (if coarse) number.
        ordered = sorted(latencies_s)
        p95 = ordered[min(n - 1, int(round(0.95 * (n - 1))))]
        p99 = ordered[min(n - 1, int(round(0.99 * (n - 1))))]
    else:
        p95 = p99 = latencies_s[0]

    return LatencyStats(n, mean, median, stdev, lo, hi, p95, p99)


@dataclass
class BenchmarkRun:
    """Container for one benchmark script's full output, ready to
    serialize. `scenario` distinguishes e.g. "single_car" vs
    "multi_car" throughput runs, or "per_stage" vs "end_to_end" latency
    breakdowns, within the same output file.
    """

    benchmark: str
    scenario: str
    parameters: dict
    results: dict
    timestamp_unix: float = field(default_factory=time.time)


def save_json(run: BenchmarkRun, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(asdict(run), f, indent=2, default=str)


def save_stage_csv(stage_stats: dict[str, LatencyStats], path: str | Path) -> None:
    """Write a per-stage latency table (one row per pipeline stage) to
    CSV - convenient for pulling straight into a spreadsheet or the
    Streamlit dashboard.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["stage", "count", "mean_ms", "median_ms", "stdev_ms", "min_ms", "max_ms", "p95_ms", "p99_ms"]
        )
        for stage, stats in stage_stats.items():
            writer.writerow(
                [
                    stage,
                    stats.count,
                    f"{stats.mean_ms:.4f}",
                    f"{stats.median_s * 1000:.4f}",
                    f"{stats.stdev_s * 1000:.4f}",
                    f"{stats.min_s * 1000:.4f}",
                    f"{stats.max_s * 1000:.4f}",
                    f"{stats.p95_ms:.4f}",
                    f"{stats.p99_ms:.4f}",
                ]
            )


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Minimal dependency-free table printer (no `tabulate` required)."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(row: list[str]) -> str:
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row(row))