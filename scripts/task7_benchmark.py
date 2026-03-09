"""
Task 7 — Performance Benchmarking of Hash Functions (10 pts)
=============================================================
Measures and compares throughput of SHA-1, SHA-256, and SHA-512 across
three file sizes (1 KB, 1 MB, 10 MB).

Each (algorithm × file-size) combination is run RUNS times and the
average real wall-clock time is reported.

Usage:
    python task7_benchmark.py [--runs 5]

Output:
    - Structured results table (time in seconds, throughput in MB/s)
    - Data also written to data/benchmark_results.txt
"""

import hashlib
import os
import time
import argparse

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

BENCH_OUT = os.path.join(DATA_DIR, "benchmark_results.txt")

ALGORITHMS = ["sha1", "sha256", "sha512"]

FILE_SIZES: dict[str, int] = {
    "1 KB" :   1_024,
    "1 MB" :   1_048_576,
    "10 MB":  10_485_760,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_data(size_bytes: int) -> bytes:
    """Return `size_bytes` of random data (generated once per size)."""
    return os.urandom(size_bytes)


def benchmark_hash(algorithm: str, data: bytes, runs: int) -> float:
    """
    Hash `data` using `algorithm` (hashlib name) `runs` times.
    Returns the average wall-clock time in seconds.
    """
    times: list[float] = []
    for _ in range(runs):
        start = time.perf_counter()
        hashlib.new(algorithm, data).hexdigest()
        times.append(time.perf_counter() - start)
    return sum(times) / len(times)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5,
                        help="Number of runs per (algorithm × size) (default: 5)")
    args = parser.parse_args()

    runs = args.runs

    print("=" * 72)
    print("Task 7 — Hash Function Performance Benchmarking")
    print(f"Runs per combination: {runs}")
    print("=" * 72)

    header = f"{'File Size':<10} {'Algorithm':<10} {'Avg Time (s)':>14} {'Throughput (MB/s)':>18}"
    print(header)
    print("-" * 72)

    results: list[tuple[str, str, float, float]] = []

    for label, size in FILE_SIZES.items():
        data      = generate_data(size)
        size_mb   = size / 1_048_576

        for algo in ALGORITHMS:
            avg_time   = benchmark_hash(algo, data, runs)
            throughput = size_mb / avg_time if avg_time > 0 else float("inf")
            results.append((label, algo, avg_time, throughput))
            print(f"{label:<10} {algo.upper():<10} {avg_time:>14.6f} {throughput:>17.2f}")

        print()

    # Save to file
    with open(BENCH_OUT, "w") as f:
        f.write("File Size,Algorithm,Avg Time (s),Throughput (MB/s)\n")
        for label, algo, t, tp in results:
            f.write(f"{label},{algo.upper()},{t:.6f},{tp:.2f}\n")

    print(f"Results saved → {BENCH_OUT}")
    print()


if __name__ == "__main__":
    main()
