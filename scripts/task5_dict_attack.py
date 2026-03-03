"""
Task 5 — Dictionary Attack Simulation (15 pts)
===============================================
Attempts to crack a stored password hash using a dictionary (pwds.txt).

Supports three modes:
    1. unsalted  — SHA-256(guess) compared to stored digest
    2. salted    — SHA-256(salt || guess) using stored salt
    3. pbkdf2    — PBKDF2-HMAC-SHA256 with stored salt and iterations

Usage:
    python task5_dict_attack.py --mode unsalted|salted|pbkdf2
"""

import hashlib
import time
import argparse
import os

DATA_DIR = "data"
DICT_FILE     = os.path.join(DATA_DIR, "pwds.txt")
UNSALTED_FILE = os.path.join(DATA_DIR, "unsalted_hash.txt")
SALTED_FILE   = os.path.join(DATA_DIR, "salted_hash.txt")
PBKDF2_FILE   = os.path.join(DATA_DIR, "pbkdf2_hash.txt")


# ---------------------------------------------------------------------------
# Attack modes
# ---------------------------------------------------------------------------

def attack_unsalted(target_digest: str, candidates: list[str]) -> tuple[str | None, int, float]:
    """SHA-256 dictionary attack (no salt)."""
    start  = time.perf_counter()
    for i, pwd in enumerate(candidates, 1):
        if hashlib.sha256(pwd.encode()).hexdigest() == target_digest:
            return pwd, i, time.perf_counter() - start
    return None, len(candidates), time.perf_counter() - start


def attack_salted(salt_hex: str, target_digest: str,
                  candidates: list[str]) -> tuple[str | None, int, float]:
    """SHA-256(salt || guess) dictionary attack."""
    salt  = bytes.fromhex(salt_hex)
    start = time.perf_counter()
    for i, pwd in enumerate(candidates, 1):
        digest = hashlib.sha256(salt + pwd.encode()).hexdigest()
        if digest == target_digest:
            return pwd, i, time.perf_counter() - start
    return None, len(candidates), time.perf_counter() - start


def attack_pbkdf2(salt_hex: str, iterations: int, target_dk: str,
                  candidates: list[str]) -> tuple[str | None, int, float]:
    """PBKDF2-HMAC-SHA256 dictionary attack."""
    salt  = bytes.fromhex(salt_hex)
    start = time.perf_counter()
    for i, pwd in enumerate(candidates, 1):
        dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, iterations, dklen=32)
        if dk.hex() == target_dk:
            return pwd, i, time.perf_counter() - start
    return None, len(candidates), time.perf_counter() - start


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Dictionary attack simulation")
    parser.add_argument("--mode", choices=["unsalted", "salted", "pbkdf2"],
                        default="unsalted", help="Attack mode (default: unsalted)")
    args = parser.parse_args()

    # Load dictionary
    with open(DICT_FILE) as f:
        candidates = [line.strip() for line in f if line.strip()]

    print("=" * 65)
    print(f"Task 5 — Dictionary Attack ({args.mode})")
    print("=" * 65)
    print(f"Dictionary : {DICT_FILE}  ({len(candidates)} entries)")
    print()

    if args.mode == "unsalted":
        with open(UNSALTED_FILE) as f:
            stored_pwd, stored_digest = f.read().strip().split(":", 1)
        print(f"Target digest : {stored_digest}")
        found, guesses, elapsed = attack_unsalted(stored_digest, candidates)

    elif args.mode == "salted":
        with open(SALTED_FILE) as f:
            parts = f.read().strip().split(":")
            stored_pwd, salt_hex, stored_digest = parts[0], parts[1], parts[2]
        print(f"Salt          : {salt_hex}")
        print(f"Target digest : {stored_digest}")
        found, guesses, elapsed = attack_salted(salt_hex, stored_digest, candidates)

    else:  # pbkdf2
        with open(PBKDF2_FILE) as f:
            parts = f.read().strip().split(":")
            stored_pwd, salt_hex, itr_str, stored_dk = parts[0], parts[1], parts[2], parts[3]
        itr = int(itr_str)
        print(f"Salt          : {salt_hex}")
        print(f"Iterations    : {itr:,}")
        print(f"Target dk     : {stored_dk}")
        found, guesses, elapsed = attack_pbkdf2(salt_hex, itr, stored_dk, candidates)

    # Report results
    print()
    rate = guesses / elapsed if elapsed > 0 else float("inf")
    if found:
        print(f"[+] Password RECOVERED : {found!r}")
    else:
        print("[-] Password NOT found in dictionary.")
    print(f"    Guesses attempted  : {guesses}")
    print(f"    Total elapsed time : {elapsed*1000:.4f} ms")
    print(f"    Guesses per second : {rate:,.1f}")


if __name__ == "__main__":
    main()
