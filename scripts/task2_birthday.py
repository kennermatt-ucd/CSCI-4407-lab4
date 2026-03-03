"""
Task 2 — Birthday Collision Simulation (15 pts)
===============================================
Demonstrates the birthday paradox using truncated SHA-256 digests.

For an n-bit hash space, collisions are expected after ~1.2 * 2^(n/2) random inputs.
We truncate SHA-256 to t bits (t ∈ {16, 20, 24}) to make collisions observable.

Usage:
    python task2_birthday.py [--bits 16|20|24] [--runs 20]

Output:
    - Per-run: collision digest, trial count, and the two colliding inputs
    - Summary: trial counts table, average q̄, theoretical estimate
"""

import hashlib
import os
import math
import argparse


# ---------------------------------------------------------------------------
# Truncated hash
# ---------------------------------------------------------------------------

def truncated_sha256(data: bytes, bits: int) -> int:
    """
    Compute SHA-256 of data and return only the first `bits` bits as an int.
    bits must be a multiple of 8 for clean byte-level truncation; we handle
    arbitrary bit counts by masking.
    """
    digest = hashlib.sha256(data).digest()
    # Read the first ceil(bits/8) bytes, then mask to exactly `bits` bits
    full_int = int.from_bytes(digest[:math.ceil(bits / 8)], "big")
    mask     = (1 << bits) - 1
    return full_int & mask


# ---------------------------------------------------------------------------
# Single collision-finding experiment
# ---------------------------------------------------------------------------

def find_collision(bits: int) -> tuple[int, bytes, bytes]:
    """
    Generate random inputs until two different inputs share the same
    truncated digest.

    Returns:
        (trial_count, input_a, input_b)
    """
    seen: dict[int, bytes] = {}
    count = 0

    while True:
        count += 1
        candidate = os.urandom(16)          # 16 random bytes as the "input"
        digest    = truncated_sha256(candidate, bits)

        if digest in seen and seen[digest] != candidate:
            return count, seen[digest], candidate

        seen[digest] = candidate


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Birthday collision simulation")
    parser.add_argument("--bits", type=int, default=16, choices=[16, 20, 24],
                        help="Number of bits to keep from SHA-256 (default: 16)")
    parser.add_argument("--runs", type=int, default=20,
                        help="Number of independent experiments (default: 20)")
    args = parser.parse_args()

    t    = args.bits
    runs = args.runs

    theoretical = round(1.2 * 2 ** (t / 2), 2)

    print("=" * 65)
    print(f"Task 2 — Birthday Collision Simulation  (t = {t} bits)")
    print("=" * 65)
    print(f"Theoretical estimate  q ≈ 1.2 × 2^(t/2) = {theoretical:.2f} trials")
    print()

    trial_counts: list[int] = []

    for i in range(1, runs + 1):
        count, a, b = find_collision(t)
        trial_counts.append(count)
        digest_a = truncated_sha256(a, t)
        print(f"Run {i:>2}: collision after {count:>6} trials | "
              f"digest=0x{digest_a:0{t//4}x} | "
              f"input_a={a.hex()[:12]}... input_b={b.hex()[:12]}...")

    q_bar = sum(trial_counts) / len(trial_counts)

    print()
    print("-" * 65)
    print(f"{'Run':<6} {'Trials':>8}")
    print("-" * 20)
    for idx, tc in enumerate(trial_counts, 1):
        print(f"{idx:<6} {tc:>8}")
    print("-" * 20)
    print(f"{'Average':} {q_bar:>8.2f}")
    print()
    print(f"Experimental average  q̄ = {q_bar:.2f}")
    print(f"Theoretical estimate   q = {theoretical:.2f}")
    print(f"Ratio (q̄ / q_theory)     = {q_bar / theoretical:.3f}  (expect ≈ 1.0)")
    print()
    print("Note: For full SHA-256 (256-bit), finding a collision would require")
    print("      approximately 2^128 trials — computationally infeasible.")


if __name__ == "__main__":
    main()
