# Lab 4 — Group 10 — Cryptographic Hash Functions Attacks

**Course:** CSCI/CSCY 4407 — Security & Cryptography
**Semester:** Spring 2026
**Date:** <!-- fill in submission date -->
**Group Members:** Cassius Kemp, Matthew Kenner, Jonathan Le

---

## Task 1 — Avalanche Effect Experiment (10 pts)

### Source Code

```python
import hashlib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_hex(message: str) -> str:
    """Return the SHA-256 digest of a UTF-8 encoded string as a hex string."""
    return hashlib.sha256(message.encode()).hexdigest()


def hex_to_bin(hex_str: str) -> str:
    """Convert a hex string to a zero-padded binary string."""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)


def count_bit_diff(hex1: str, hex2: str) -> tuple[int, float]:
    """
    Count the number of differing bits between two equal-length hex digests.

    Returns:
        (bits_different, percentage_different)
    """
    b1 = hex_to_bin(hex1)
    b2 = hex_to_bin(hex2)
    total = len(b1)
    diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
    return diff, round(diff / total * 100, 2)


# ---------------------------------------------------------------------------
# Trial definitions  — each pair differs by exactly one character
# ---------------------------------------------------------------------------

TRIALS: list[tuple[str, str, str]] = [
    # (label, msg1, msg2)
    ("Trial 1", "Hello world",  "Hello worle"),
    ("Trial 2", "CSCI4407Lab4", "CSCI4407Lab5"),
    ("Trial 3", "avalanche!",   "bvalanche!"),
    ("Trial 4", "security2026", "security2027"),
    ("Trial 5", "GroupTen",     "GroupTin"),
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_trials() -> None:
    print("=" * 70)
    print("Task 1 — Avalanche Effect Experiment")
    print("=" * 70)
    print(f"{'Trial':<10} {'Msg1':<20} {'Msg2':<20} {'Bits diff':>10} {'%':>8}")
    print("-" * 70)

    total_diff = 0
    total_pct  = 0.0

    for label, m1, m2 in TRIALS:
        d1 = sha256_hex(m1)
        d2 = sha256_hex(m2)
        diff, pct = count_bit_diff(d1, d2)
        total_diff += diff
        total_pct  += pct

        print(f"{label:<10} {m1:<20} {m2:<20} {diff:>10} {pct:>7}%")
        print(f"  SHA-256(msg1): {d1}")
        print(f"  SHA-256(msg2): {d2}")
        print()

    avg_diff = round(total_diff / len(TRIALS), 2)
    avg_pct  = round(total_pct  / len(TRIALS), 2)

    print("-" * 70)
    print(f"Average bits different : {avg_diff} / 256")
    print(f"Average percentage     : {avg_pct}%")
    print()
    print("Expected: ~128 bits (50%) for a well-designed hash function.")


if __name__ == "__main__":
    run_trials()
```

### Steps

```bash
cd /path/to/CSCI-4407-lab4
# Create message files
echo -n "Hello world" > m1.txt
echo -n "Hello worle" > m2.txt
ls -l m1.txt m2.txt

# Compute SHA-1 and SHA-256 with CLI tools
sha1sum m1.txt m2.txt
sha256sum m1.txt m2.txt

# Run avalanche script (5 trials, one-character difference each)
python scripts/task1_avalanche.py
```

### Screenshots

<!-- Insert screenshot: sha1sum / sha256sum output for m1.txt and m2.txt -->
![sha1 and sha256](Screenshots/Screenshot%202026-03-04%20132815.png)

<!-- Insert screenshot: task1_avalanche.py terminal output -->

![Task 1](Screenshots/task1.png)

### Results Table

| Trial | Msg 1           | Msg 2           | Bits Different | % Flipped |
|-------|-----------------|-----------------|:--------------:|:---------:|
| 1     | Hello world     | Hello worle     |     129         |    50.39      |
| 2     | CSCI4407Lab4    | CSCI4407Lab5    |      141       |        55.08   |
| 3     | avalanche!      | bvalanche!      |    131        |      51.17     |
| 4     | security2026    | security2027    |       127       |     49.61     |
| 5     | GroupTen        | GroupTin        |      119       |      46.48     |
|       | **Average**     |                 |    129.4       |     50.55      |

### Question 6.1.1

**Q:** Based on your results, does SHA-256 demonstrate the avalanche effect? (i) cite computed averages, (ii) explain why ~50% bit-flip is expected, (iii) discuss why multiple trials are necessary.

**A:** <!-- TODO: write answer after running the script -->

---

## Task 2 — Birthday Collision Simulation (15 pts)

### Source Code

```python
# See scripts/task2_birthday.py
```

### Steps

```bash
# Default: t=16 bits, 20 independent runs
python scripts/task2_birthday.py --bits 16 --runs 20

# Optional: repeat for t=20 and t=24
python scripts/task2_birthday.py --bits 20 --runs 20
python scripts/task2_birthday.py --bits 24 --runs 20
```

### Screenshots

<!-- Insert screenshot: terminal output showing 20 runs for t=16 -->

### Results Table (t = 16 bits)

| Run | Trials to Collision |
|----:|--------------------:|
|   1 |                     |
|   2 |                     |
|   3 |                     |
|   4 |                     |
|   5 |                     |
|   6 |                     |
|   7 |                     |
|   8 |                     |
|   9 |                     |
|  10 |                     |
|  11 |                     |
|  12 |                     |
|  13 |                     |
|  14 |                     |
|  15 |                     |
|  16 |                     |
|  17 |                     |
|  18 |                     |
|  19 |                     |
|  20 |                     |
| **Avg q̄** |            |

**Theoretical estimate:** q ≈ 1.2 × 2^(16/2) = 1.2 × 256 ≈ **307.2**

### Question 6.2.1

**Q:** Compare experimental q̄ with theoretical q ≈ 1.2 × 2^(t/2). How closely do results match? State t, report q̄, compute theoretical estimate, explain 2^128 for full SHA-256.

**A:** <!-- TODO: write answer after running the script -->

---

## Task 3 — Toy Merkle–Damgård Construction (15 pts)

### Source Code

```python
# See scripts/task3_toy_md.py
```

### Design Choices

| Parameter     | Value                        | Rationale                              |
|---------------|------------------------------|----------------------------------------|
| Block size    | 16 bytes                     | Small, clearly shows multiple blocks   |
| Digest bits   | 32 bits (4 bytes)            | Compact intermediate values            |
| IV            | `00000000` (4-byte all-zero) | Fixed, per-algorithm specification     |
| Compression   | `SHA-256(V \|\| Mi)[:4]`     | Uses standard hash as building block   |
| Padding       | Zero-pad to block boundary   | Toy-only — real SHA uses length suffix |

### Steps

```bash
python scripts/task3_toy_md.py
```

### Screenshots

<!-- Insert screenshot: intermediate chaining values V1, V2, ... for test message -->

<!-- Insert screenshot: chaining sensitivity demo (modified block 2 cascades) -->

### Sample Output (fill in after running)

```
Message: b'CSCI4407 Group10 Lab4 Hash Demo'
Block count: 2
V0 (IV): 00000000
V1      : ????????   (after block 1)
V2      : ????????   (after block 2)  ← final digest
```

### Chaining Sensitivity

| Block Modified | V1 changed? | V2 changed? | V3 changed? |
|:--------------:|:-----------:|:-----------:|:-----------:|
| Block 2        | No          | Yes         | Yes         |

### Question 6.3 (Answer Required)

**Q:** How do chaining values propagate changes across blocks? Why does modifying one block affect the final digest? Why does 32-bit truncation make the construction insecure?

**A:** <!-- TODO: write answer after running the script -->

---

## Task 4 — Length-Extension Vulnerability (20 pts)

### Provided Artifacts (Group 10)

| Artifact         | Value                                                                |
|------------------|----------------------------------------------------------------------|
| `message.txt`    | `user=student10&uid=10010&role=user&course=CSCI4407&nonce=d5f3a9ee839e90e2` |
| `tag.hex`        | `b1f5e54d1e8e72cadddb3d8034208b6afccf0581`                          |
| `keylen_hint.txt`| Key length: 8–32 bytes (inclusive)                                   |
| Extension goal   | `&role=admin`                                                        |

### Source Code

```python
# See scripts/task4_length_extension.py
```

### Steps

```bash
# Inspect artifacts
cat HashServer_Group_10_student/message.txt
cat HashServer_Group_10_student/tag.hex
cat HashServer_Group_10_student/keylen_hint.txt

# Run attack (tries all key lengths 8..32)
python scripts/task4_length_extension.py
```

### Screenshots

<!-- Insert screenshot: cat message.txt, cat tag.hex, cat keylen_hint.txt -->

<!-- Insert screenshot: task4_length_extension.py terminal output showing forged_tag candidates -->

<!-- Insert screenshot: forged_message.txt (hexdump or xxd) and forged_tag.hex -->

### Attack Output

| Key Length (tested) | Forged Tag                               | Forged Msg Size |
|:-------------------:|------------------------------------------|:---------------:|
| 8–32 (all)          | `4e1193fd0e9e1990e803b2d145ae1f0279823099` | 107–131 bytes  |

> **Note:** All 25 key-length candidates produce the same forged tag because
> `key_len + len(message) + SHA-1-padding` always falls in the same 128-byte
> block boundary for this message. The 25 candidate `forged_message_klenXX.txt`
> files are all written; the instructor's verifier will confirm which one passes.

**Forged message file:** `HashServer_Group_10_student/forged_message.txt` (+ `forged_message_klenXX.txt` for each key length 8–32)
**Forged tag file:** `HashServer_Group_10_student/forged_tag.hex` → `4e1193fd0e9e1990e803b2d145ae1f0279823099`

### How the Attack Works

The SHA-1 tag is computed as `SHA1(key || message)`. SHA-1 follows the Merkle–Damgård
construction: after processing each 512-bit block it exposes its internal state (h0–h4)
in the final digest. Because we have the digest, we have the exact internal state SHA-1
was in after hashing `(key || message)`. We can therefore:

1. Compute the SHA-1 padding that was appended to `(key || message)` to fill the last block.
2. Inject the known (h0–h4) state and continue hashing the extension `&role=admin`.
3. The resulting digest is a valid tag for `message || padding || &role=admin` under the
   same unknown key — without ever learning the key.

### Question 6.4.1

**Q:** Why does SHA1(k||m) fail to provide secure message authentication even though SHA-1 is a cryptographic hash? Explain how Merkle–Damgård enables length extension and why HMAC does not suffer from this.

**A:** <!-- TODO: write answer -->

The construction `SHA1(k||m)` is insecure because SHA-1's Merkle–Damgård structure
leaks its internal state in the output digest. An attacker who knows the tag (and can
guess or brute-force the key length) can resume the hash computation without knowing
the key, producing a valid tag for an extended message.

HMAC avoids this by computing `H(k_outer || H(k_inner || m))` — the outer hash wraps the
inner digest, so the attacker cannot inject their extension at the right point: they would
need to compute `H(k_outer || ...)` which requires knowing `k_outer`.

---

## Task 5 — Password Hashing Analysis (15 pts)

### Source Code

```python
# See scripts/task5_pwd_hash.py
# See scripts/task5_dict_attack.py
```

### Password Dictionary

`data/pwds.txt` — 30 candidate passwords including weak passwords, variations, and passphrases.

### Steps

```bash
# Generate all three stored hashes for password "Winter2026!"
python scripts/task5_pwd_hash.py --password "Winter2026!" --iterations 200000

# Dictionary attack — unsalted
python scripts/task5_dict_attack.py --mode unsalted

# Dictionary attack — salted
python scripts/task5_dict_attack.py --mode salted

# Dictionary attack — PBKDF2
python scripts/task5_dict_attack.py --mode pbkdf2
```

### Screenshots

<!-- Insert screenshot: task5_pwd_hash.py output (all three methods) -->

<!-- Insert screenshot: dict attack — unsalted (password found) -->

<!-- Insert screenshot: dict attack — PBKDF2 (slow, same password) -->

### Performance Comparison Table

| Method                     | Hash Time      | Guesses/sec (est.) |
|----------------------------|:--------------:|:------------------:|
| SHA-256 (unsalted)         |                |                    |
| SHA-256 (salted, 16-byte)  |                |                    |
| PBKDF2 (200,000 iterations)|                |                    |

### Question 6.5.1

**Q:** Which mechanism provided the greatest security increase: adding a salt or using PBKDF2? Explain why salts don't slow down guessing but still help. Explain why SHA-256 alone is inappropriate for passwords.

**A:** <!-- TODO: write answer after running the scripts -->

---

## Task 6 — File Integrity Verification (10 pts)

### Steps

```bash
# Create 1 MB random file and identical copy
head -c 1048576 /dev/urandom > fileA.bin
cp fileA.bin fileB.bin

# Compute initial hashes (should match)
sha1sum fileA.bin fileB.bin
sha256sum fileA.bin fileB.bin

# Modify one byte at offset 1000 in fileB
printf '\x00' | dd of=fileB.bin bs=1 seek=1000 count=1 conv=notrunc

# Recompute hashes (should differ)
sha1sum fileA.bin fileB.bin
sha256sum fileA.bin fileB.bin
```

### Screenshots

<!-- Insert screenshot: sha1sum/sha256sum before modification (matching digests) -->

<!-- Insert screenshot: sha1sum/sha256sum after 1-byte modification (different digests) -->

### Before / After Comparison

| File    | SHA-256 (before)          | SHA-256 (after)           |
|---------|---------------------------|---------------------------|
| fileA   |                           | (unchanged)               |
| fileB   |                           |                           |

### Question 6.6.1

**Q:** Why are hash functions highly sensitive to small input changes? Why does comparing hashes alone not guarantee authenticity without a trusted reference channel?

**A:** <!-- TODO: write answer -->

---

## Task 7 — Performance Benchmarking (10 pts)

### Source Code

```python
# See scripts/task7_benchmark.py
```

### Steps

```bash
# Generate benchmark datasets
head -c 1024      /dev/urandom > data_1KB.bin
head -c 1048576   /dev/urandom > data_1MB.bin
head -c 10485760  /dev/urandom > data_10MB.bin

# CLI timing (5 runs each, record real time)
for alg in sha1sum sha256sum sha512sum; do
  for f in data_1KB.bin data_1MB.bin data_10MB.bin; do
    echo "=== $alg $f ===" && for i in {1..5}; do time $alg $f > /dev/null; done
  done
done

# Automated benchmark script (records averages and throughput)
python scripts/task7_benchmark.py --runs 5
```

### Screenshots

<!-- Insert screenshot: CLI time output for 1 MB file, all three algorithms -->

<!-- Insert screenshot: task7_benchmark.py structured results table -->

### Results Table

| File Size | Algorithm | Avg Time (s) | Throughput (MB/s) |
|:---------:|:---------:|:------------:|:-----------------:|
| 1 KB      | SHA-1     |              |                   |
| 1 KB      | SHA-256   |              |                   |
| 1 KB      | SHA-512   |              |                   |
| 1 MB      | SHA-1     |              |                   |
| 1 MB      | SHA-256   |              |                   |
| 1 MB      | SHA-512   |              |                   |
| 10 MB     | SHA-1     |              |                   |
| 10 MB     | SHA-256   |              |                   |
| 10 MB     | SHA-512   |              |                   |

### Question 6.7.1

**Q:** Why do different algorithms exhibit different performance characteristics? Why can SHA-512 sometimes outperform SHA-256 on 64-bit systems? Why should performance alone not determine algorithm choice?

**A:** <!-- TODO: write answer after running benchmarks -->

---

## Summary

| Task | Description                       | Points | Status        |
|:----:|-----------------------------------|:------:|:-------------:|
| 1    | Avalanche Effect                  | 10     | <!-- TODO --> |
| 2    | Birthday Collision Simulation     | 15     | <!-- TODO --> |
| 3    | Toy Merkle–Damgård Construction   | 15     | <!-- TODO --> |
| 4    | Length-Extension Vulnerability    | 20     | <!-- TODO --> |
| 5    | Password Hashing & Dict Attack    | 15     | <!-- TODO --> |
| 6    | File Integrity Verification       | 10     | <!-- TODO --> |
| 7    | Performance Benchmarking          | 10     | <!-- TODO --> |
|      | Report Quality & Clarity          | 5      |               |
|      | Code Quality & Reproducibility    | 10     |               |
|      | **Total**                         | **100**|               |
