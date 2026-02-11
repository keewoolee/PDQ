#!/usr/bin/env python3
"""
Benchmarking script for PDQ experiments.
Runs experiments multiple times and outputs formatted results with statistics.
"""

import subprocess
import re
import statistics
from dataclasses import dataclass

NUM_RUNS = 5

# Regex patterns for timing
TIME_PATTERNS = {
    "Match": r"Match time:\s*([\d.]+)sec",
    "Mask": r"Mask time:\s*([\d.]+)sec",
    "RingSwitch": r"RingSwitch time:\s*([\d.]+)sec",
    "Compress": r"Compress time:\s*([\d.]+)sec",
    "Decompress": r"Decompress time:\s*([\d.]+)ms",
}

# Regex patterns for communication sizes (deterministic, only need first run)
SIZE_PATTERNS = {
    "Digest": r"Digest size:\s*([\d.]+)\s*KB",
    "Query": r"Query size:\s*([\d.]+)\s*KB",
    "EvalKey": r"EvalKey size:\s*([\d.]+)\s*KB",
    "RotKey": r"RotKey size:\s*([\d.]+)\s*KB",
    "SwitchKey": r"SwitchKey size:\s*([\d.]+)\s*KB",
}


@dataclass
class Stats:
    mean: float
    std: float


def compute_stats(values: list[float]) -> Stats:
    return Stats(
        mean=statistics.mean(values),
        std=statistics.stdev(values) if len(values) > 1 else 0.0
    )


@dataclass
class BenchmarkResult:
    timing: dict[str, Stats]
    sizes: dict[str, float]


def run_benchmark(N: int, s: int) -> BenchmarkResult:
    """Run benchmark NUM_RUNS times and return timing stats and sizes."""

    cmd = ["./test", str(N), str(s)]
    time_results = {name: [] for name in TIME_PATTERNS}
    sizes = {}

    for run in range(NUM_RUNS):
        print(f"    Run {run + 1}/{NUM_RUNS}...", end=" ", flush=True)
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = proc.stdout

        # Check verification passed
        if "Verification: PASSED" not in output:
            raise RuntimeError(f"Run {run+1}: Verification FAILED")

        # Parse timing
        for name, pattern in TIME_PATTERNS.items():
            match = re.search(pattern, output)
            if not match:
                raise RuntimeError(f"Run {run+1}: Failed to parse '{name}' from output")
            time_results[name].append(float(match.group(1)))

        # Parse sizes (only on first run, they're deterministic)
        if run == 0:
            for name, pattern in SIZE_PATTERNS.items():
                match = re.search(pattern, output)
                if match:
                    sizes[name] = float(match.group(1))

        print("done")

    # Compute timing stats
    timing = {name: compute_stats(values) for name, values in time_results.items()}

    return BenchmarkResult(timing=timing, sizes=sizes)


# =============================================================================
# Experiment Definitions
# =============================================================================

EXPERIMENTS = {
    # Varying num_matching (N=16384)
    "(16384, 8)": (16384, 8),
    "(16384, 16)": (16384, 16),
    "(16384, 32)": (16384, 32),
    "(16384, 64)": (16384, 64),
    "(16384, 128)": (16384, 128),

    # Varying num_records (s=16)
    "(8192, 16)": (8192, 16),
    "(32768, 16)": (32768, 16),
    "(65536, 16)": (65536, 16),
    "(131072, 16)": (131072, 16),
    "(262144, 16)": (262144, 16),
    "(524288, 16)": (524288, 16),
}

FIGURES = {
    "Vary num_matching (N=16384)": [
        "(16384, 8)", "(16384, 16)", "(16384, 32)", "(16384, 64)", "(16384, 128)"
    ],
    "Vary num_records (s=16)": [
        "(8192, 16)", "(16384, 16)", "(32768, 16)", "(65536, 16)",
        "(131072, 16)", "(262144, 16)", "(524288, 16)"
    ],
}


# =============================================================================
# Output Formatting
# =============================================================================

def print_timing_table(results: dict[str, BenchmarkResult], exp_names: list[str]):
    """Print timing results table."""

    C = 13  # config column width
    W = 14  # data column width

    def fmt(stat: Stats) -> str:
        s = f"{stat.mean:.2f} ± {stat.std:.2f}"
        return f"{s:>{W}}"

    print()
    print(f"{'(N, s)':<{C}} {'Match (s)':>{W}} {'Mask (s)':>{W}} "
          f"{'RS (s)':>{W}} {'Comp (s)':>{W}} {'Decomp (ms)':>{W}}")
    print("-" * (C + 1 + (W + 1) * 5))

    for name in exp_names:
        if name not in results:
            continue
        t = results[name].timing
        print(f"{name:<{C}} {fmt(t['Match'])} {fmt(t['Mask'])} "
              f"{fmt(t['RingSwitch'])} {fmt(t['Compress'])} {fmt(t['Decompress'])}")


def print_comm_table(results: dict[str, BenchmarkResult], exp_names: list[str]):
    """Print communication costs table."""

    C = 13  # config column width
    W = 14  # data column width

    def fmt_kb(val: float) -> str:
        return f"{val:>{W}.0f}"

    def fmt_mb(val: float) -> str:
        return f"{val / 1024:>{W}.1f}"

    print()
    print(f"{'(N, s)':<{C}} {'Digest (KB)':>{W}} {'Query (MB)':>{W}} "
          f"{'EvalKey (MB)':>{W}} {'RotKey (MB)':>{W}} {'SwKey (MB)':>{W}}")
    print("-" * (C + 1 + (W + 1) * 5))

    for name in exp_names:
        if name not in results:
            continue
        s = results[name].sizes
        print(f"{name:<{C}} {fmt_kb(s.get('Digest', 0))} {fmt_mb(s.get('Query', 0))} "
              f"{fmt_mb(s.get('EvalKey', 0))} {fmt_mb(s.get('RotKey', 0))} "
              f"{fmt_mb(s.get('SwitchKey', 0))}")


def main():
    print(f"Running {len(EXPERIMENTS)} experiments with {NUM_RUNS} runs each...\n")
    results = {}

    for name, (N, s) in EXPERIMENTS.items():
        print(f"  N={N}, s={s}:")
        try:
            results[name] = run_benchmark(N, s)
        except Exception as e:
            print(f"    ERROR: {e}")
            continue

    print("\n" + "=" * 78)
    print("TIMING RESULTS")
    print("=" * 78)

    for fig_name, exp_names in FIGURES.items():
        relevant = [n for n in exp_names if n in results]
        if relevant:
            print(f"\n[{fig_name}]")
            print_timing_table(results, relevant)

    print("\n" + "=" * 78)
    print("COMMUNICATION COSTS")
    print("=" * 78)

    for fig_name, exp_names in FIGURES.items():
        relevant = [n for n in exp_names if n in results]
        if relevant:
            print(f"\n[{fig_name}]")
            print_comm_table(results, relevant)


if __name__ == "__main__":
    main()
