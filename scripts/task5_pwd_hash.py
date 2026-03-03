"""
Task 5 — Password Hashing: Unsalted vs Salted vs PBKDF2 (15 pts)
=================================================================
Demonstrates why plain SHA-256 is insufficient for password storage and
how salting + key stretching (PBKDF2) raise the attacker's cost.

Writes to disk:
    data/unsalted_hash.txt   — stored_password:sha256_hex
    data/salted_hash.txt     — stored_password:salt_hex:sha256(salt||pwd)_hex
    data/pbkdf2_hash.txt     — stored_password:salt_hex:iterations:dk_hex

Usage:
    python task5_pwd_hash.py [--password <pwd>] [--iterations <n>]
"""

import hashlib
import os
import time
import argparse

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

UNSALTED_FILE = os.path.join(DATA_DIR, "unsalted_hash.txt")
SALTED_FILE   = os.path.join(DATA_DIR, "salted_hash.txt")
PBKDF2_FILE   = os.path.join(DATA_DIR, "pbkdf2_hash.txt")

SALT_BYTES  = 16
PBKDF2_ITER = 200_000   # NIST recommendation (adjust and document in report)


# ---------------------------------------------------------------------------
# Hashing functions
# ---------------------------------------------------------------------------

def hash_unsalted(password: str) -> tuple[str, float]:
    """SHA-256(password). Returns (hex_digest, elapsed_seconds)."""
    start  = time.perf_counter()
    digest = hashlib.sha256(password.encode()).hexdigest()
    return digest, time.perf_counter() - start


def hash_salted(password: str) -> tuple[str, str, float]:
    """SHA-256(salt || password). Returns (salt_hex, hex_digest, elapsed_seconds)."""
    salt   = os.urandom(SALT_BYTES)
    start  = time.perf_counter()
    digest = hashlib.sha256(salt + password.encode()).hexdigest()
    elapsed = time.perf_counter() - start
    return salt.hex(), digest, elapsed


def hash_pbkdf2(password: str, iterations: int = PBKDF2_ITER) -> tuple[str, str, float]:
    """PBKDF2-HMAC-SHA256. Returns (salt_hex, dk_hex, elapsed_seconds)."""
    salt  = os.urandom(SALT_BYTES)
    start = time.perf_counter()
    dk    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    elapsed = time.perf_counter() - start
    return salt.hex(), dk.hex(), elapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--password",   default="Winter2026!", help="Password to hash")
    parser.add_argument("--iterations", type=int, default=PBKDF2_ITER,
                        help=f"PBKDF2 iteration count (default: {PBKDF2_ITER})")
    args = parser.parse_args()

    pwd  = args.password
    itr  = args.iterations

    print("=" * 65)
    print("Task 5 — Password Hashing Analysis")
    print("=" * 65)
    print(f"Password : {pwd!r}")
    print()

    # --- Unsalted ---
    digest_u, t_u = hash_unsalted(pwd)
    print("[1] Unsalted SHA-256")
    print(f"    digest  : {digest_u}")
    print(f"    time    : {t_u*1e6:.3f} µs")
    rate_u = 1 / t_u if t_u > 0 else float("inf")
    print(f"    guesses/s ≈ {rate_u:,.0f}")
    with open(UNSALTED_FILE, "w") as f:
        f.write(f"{pwd}:{digest_u}\n")
    print(f"    saved → {UNSALTED_FILE}\n")

    # --- Salted ---
    salt_s, digest_s, t_s = hash_salted(pwd)
    print("[2] Salted SHA-256  (salt = 16 random bytes)")
    print(f"    salt    : {salt_s}")
    print(f"    digest  : {digest_s}")
    print(f"    time    : {t_s*1e6:.3f} µs")
    rate_s = 1 / t_s if t_s > 0 else float("inf")
    print(f"    guesses/s ≈ {rate_s:,.0f}")
    with open(SALTED_FILE, "w") as f:
        f.write(f"{pwd}:{salt_s}:{digest_s}\n")
    print(f"    saved → {SALTED_FILE}\n")

    # --- PBKDF2 ---
    salt_p, dk_p, t_p = hash_pbkdf2(pwd, itr)
    print(f"[3] PBKDF2-HMAC-SHA256  (iterations = {itr:,})")
    print(f"    salt    : {salt_p}")
    print(f"    dk      : {dk_p}")
    print(f"    time    : {t_p*1000:.3f} ms")
    rate_p = 1 / t_p if t_p > 0 else float("inf")
    print(f"    guesses/s ≈ {rate_p:,.1f}")
    with open(PBKDF2_FILE, "w") as f:
        f.write(f"{pwd}:{salt_p}:{itr}:{dk_p}\n")
    print(f"    saved → {PBKDF2_FILE}\n")

    # --- Comparison ---
    print("-" * 65)
    print(f"{'Method':<25} {'Time':>12} {'Guesses/s':>14}")
    print("-" * 65)
    print(f"{'SHA-256 (unsalted)':<25} {t_u*1e6:>10.3f} µs   {rate_u:>12,.0f}")
    print(f"{'SHA-256 (salted)':<25} {t_s*1e6:>10.3f} µs   {rate_s:>12,.0f}")
    print(f"{'PBKDF2 ('+str(itr//1000)+'K iters)':<25} {t_p*1000:>10.3f} ms   {rate_p:>12,.1f}")
    print()
    slowdown = rate_u / rate_p if rate_p > 0 else float("inf")
    print(f"PBKDF2 is ≈ {slowdown:,.0f}× slower than unsalted SHA-256 per guess.")


if __name__ == "__main__":
    main()
