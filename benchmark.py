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

    # Add derived timing metrics
    match_mask = [m + k for m, k in zip(time_results["Match"], time_results["Mask"])]
    timing["Match+Mask"] = compute_stats(match_mask)

    rs_compress = [r + c for r, c in zip(time_results["RingSwitch"], time_results["Compress"])]
    timing["RingSwitch+Compress"] = compute_stats(rs_compress)

    server_total = [m + k + r + c for m, k, r, c in zip(
        time_results["Match"], time_results["Mask"],
        time_results["RingSwitch"], time_results["Compress"])]
    timing["Server Total"] = compute_stats(server_total)

    return BenchmarkResult(timing=timing, sizes=sizes)


# =============================================================================
# Experiment Definitions
# =============================================================================

EXPERIMENTS = {
    # Varying num_matching (N=16384)
    "PDQ_16384_8": (16384, 8),
    "PDQ_16384_16": (16384, 16),
    "PDQ_16384_32": (16384, 32),
    "PDQ_16384_64": (16384, 64),
    "PDQ_16384_128": (16384, 128),

    # Varying num_records (s=16)
    "PDQ_8192_16": (8192, 16),
    "PDQ_32768_16": (32768, 16),
    "PDQ_65536_16": (65536, 16),
    "PDQ_131072_16": (131072, 16),
    "PDQ_262144_16": (262144, 16),
    "PDQ_524288_16": (524288, 16),
}

FIGURES = {
    "Vary num_matching (N=16384)": [
        "PDQ_16384_8", "PDQ_16384_16", "PDQ_16384_32", "PDQ_16384_64", "PDQ_16384_128"
    ],
    "Vary num_records (s=16)": [
        "PDQ_8192_16", "PDQ_16384_16", "PDQ_32768_16", "PDQ_65536_16",
        "PDQ_131072_16", "PDQ_262144_16", "PDQ_524288_16"
    ],
}


# =============================================================================
# Output Formatting
# =============================================================================

def print_timing_table(results: dict[str, BenchmarkResult], exp_names: list[str]):
    """Print timing results table."""

    W = 16  # column width

    def fmt(stat: Stats) -> str:
        s = f"{stat.mean:.2f} ± {stat.std:.2f}"
        return f"{s:>{W}}"

    # Summary table
    print()
    print(f"{'Config':<16}  {'Server (s)':>{W}}  {'Match+Mask (s)':>{W}}  "
          f"{'RS+Comp (s)':>{W}}  {'Decomp (ms)':>{W}}")
    print("-" * (16 + 2 + (W + 2) * 4))

    for name in exp_names:
        if name not in results:
            continue
        t = results[name].timing
        print(f"{name:<16}  {fmt(t['Server Total'])}  {fmt(t['Match+Mask'])}  "
              f"{fmt(t['RingSwitch+Compress'])}  {fmt(t['Decompress'])}")

    # Detailed breakdown
    print()
    print(f"{'Config':<16}  {'Match (s)':>{W}}  {'Mask (s)':>{W}}  "
          f"{'RingSwitch (s)':>{W}}  {'Compress (s)':>{W}}")
    print("-" * (16 + 2 + (W + 2) * 4))

    for name in exp_names:
        if name not in results:
            continue
        t = results[name].timing
        print(f"{name:<16}  {fmt(t['Match'])}  {fmt(t['Mask'])}  "
              f"{fmt(t['RingSwitch'])}  {fmt(t['Compress'])}")


def print_comm_table(results: dict[str, BenchmarkResult], exp_names: list[str]):
    """Print communication costs table."""

    W = 16  # column width

    def fmt(val: float) -> str:
        return f"{val:>{W}.1f}"

    # Per-query costs
    print()
    print(f"{'Config':<16}  {'Digest (KB)':>{W}}  {'Query (KB)':>{W}}")
    print("-" * (16 + 2 + (W + 2) * 2))

    for name in exp_names:
        if name not in results:
            continue
        s = results[name].sizes
        print(f"{name:<16}  {fmt(s.get('Digest', 0))}  {fmt(s.get('Query', 0))}")

    # One-time setup costs
    print()
    print(f"{'Config':<16}  {'EvalKey (KB)':>{W}}  {'RotKey (KB)':>{W}}  "
          f"{'SwitchKey (KB)':>{W}}")
    print("-" * (16 + 2 + (W + 2) * 3))

    for name in exp_names:
        if name not in results:
            continue
        s = results[name].sizes
        print(f"{name:<16}  {fmt(s.get('EvalKey', 0))}  {fmt(s.get('RotKey', 0))}  "
              f"{fmt(s.get('SwitchKey', 0))}")


def main():
    print(f"Running {len(EXPERIMENTS)} experiments with {NUM_RUNS} runs each...\n")
    results = {}

    for name, (N, s) in EXPERIMENTS.items():
        print(f"  {name} (N={N}, s={s}):")
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
