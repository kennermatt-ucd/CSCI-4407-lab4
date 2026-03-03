Source: Lab 4 Assignment PDF 

---

# CSCI 4407 — Lab 4

## Cryptographic Hash Function Attacks

Spring 2026

This repository contains code, experimental data, and report materials for **Lab 4: Cryptographic Hash Functions Attacks**.

All tasks follow the controlled academic guidelines described in the official lab document .

---

# Repository Structure

```
/scripts
  avalanche.py
  birthday.py
  toy_md.py
  pwd_hash.py
  dict_attack.py
  (task4 attack script if used)

/data
  pwds.txt
  forged_message.txt
  forged_tag.hex

/screens
  task1_*
  task2_*
  ...
  
/report
  Lab4_Report.pdf
```

All scripts are designed to run on a Linux-based VM (Kali/Ubuntu) using Python 3 and standard CLI tools.

---

# Task Summary + Required Questions

---

## Task 1 — Avalanche Effect

**Goal:** Demonstrate diffusion by measuring bit differences between nearly identical inputs.

### Deliverables

* `avalanche.py`
* 5-trial results table (bits flipped + % flipped)
* Screenshots of sha1sum + sha256sum
* 1–2 paragraph explanation

### Required Question

After computing averages across 5 trials:

1. Does SHA-256 demonstrate the avalanche effect?
2. What was your average number of flipped bits?
3. What was your average percentage flipped?
4. Why is ~50% bit change expected?
5. Why are multiple trials necessary instead of one?

---

## Task 2 — Birthday Collision Simulation

**Goal:** Empirically validate the birthday paradox using truncated SHA-256.

### Deliverables

* `birthday.py`
* Table of 20 runs
* Computed average collision point
* Comparison with theoretical estimate
* Short explanation

### Required Question

1. What value of `t` did you use?
2. What was your average collision point (q̄)?
3. What is the theoretical estimate `q ≈ 1.2·2^(t/2)`?
4. How closely did your results match theory?
5. Why would a full 256-bit hash require approximately 2¹²⁸ work to find collisions?

---

## Task 3 — Toy Merkle–Damgård Construction

**Goal:** Implement iterative compression + chaining.

### Deliverables

* `toy_md.py`
* Screenshot of intermediate chaining values
* Evidence of chaining sensitivity
* One-paragraph explanation

### Required Question

1. How do chaining values propagate changes across blocks?
2. Why does modifying one block affect the final digest?
3. Why is truncating to 32 bits insecure?

---

## Task 4 — Length-Extension Vulnerability

**Goal:** Demonstrate why `SHA1(k || m)` is insecure.

### Deliverables

* `forged_message.txt`
* `forged_tag.hex`
* Screenshot of original message + tag
* Screenshot of forged outputs
* 1–2 paragraph explanation

### Required Question

1. Why does `SHA1(k || m)` fail to provide secure authentication?
2. How does the Merkle–Damgård structure enable length extension?
3. Why does HMAC prevent this vulnerability?
4. Why is `HMAC(k,m) ≠ SHA1(k || m)`?

---

## Task 5 — Password Hashing Analysis

**Goal:** Compare unsalted SHA-256, salted SHA-256, and PBKDF2.

### Deliverables

* `pwd_hash.py`
* `dict_attack.py`
* `pwds.txt`
* Screenshots of cracking results
* 1–2 paragraph explanation

### Required Question

1. Which provided the greatest security increase: salting or PBKDF2?
2. Why do salts not directly slow down guessing?
3. Why are fast hashes like SHA-256 inappropriate for password storage?
4. How does key stretching increase attacker cost?

---

## Task 6 — File Integrity Verification

**Goal:** Show that 1-byte change drastically alters hash output.

### Deliverables

* Screenshots before modification
* Screenshots after modification
* Short explanation

### Required Question

1. Why are cryptographic hashes highly sensitive to small input changes?
2. Why does comparing hashes alone not guarantee authenticity?
3. Why must the reference hash come from a trusted source?
4. What happens if an attacker can modify both file and hash?

---

## Task 7 — Performance Benchmarking

**Goal:** Compare SHA-1, SHA-256, SHA-512 throughput.

### Deliverables

* Timing screenshots
* Results table (size, algorithm, avg time, MB/s)
* 1–2 paragraph analysis

### Required Question

1. Why do hash algorithms have different performance characteristics?
2. Why can SHA-512 outperform SHA-256 on 64-bit systems?
3. Why should performance not be the sole factor in choosing a hash?
4. How do these results relate to password hashing security?

---

# Reproducibility Requirements

The instructor must be able to:

* Re-run scripts
* Reproduce experimental results
* Verify Task 4 forgery
* Confirm benchmark calculations

All scripts must:

* Be readable
* Be commented
* Run without modification
* Include clear parameters and documentation

---
