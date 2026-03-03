"""
Task 4 — SHA-1 Length-Extension Attack (20 pts)
================================================
Demonstrates the length-extension vulnerability in the naive MAC construction:
    tag = SHA1(key || message)

Given:
    - message.txt  : original message m
    - tag.hex      : tag = SHA1(key || m)
    - keylen_hint  : key length is between 8 and 32 bytes (inclusive)

Goal:
    Produce a forged (m', t') such that:
        m' = m || SHA-1-padding(key || m) || "&role=admin"
        t' = SHA1(key || m')   (valid without knowing key)

Approach:
    For each candidate key length in [8..32]:
        1. Compute the SHA-1 padding that would follow (key || m) in a 512-bit block.
        2. Reconstruct the internal SHA-1 state from the known tag (h0..h4).
        3. Continue hashing "&role=admin" from that state.
        4. The resulting digest is t' — the forged tag.

Output files:
    data/forged_message.txt
    data/forged_tag.hex

IMPORTANT: This is a controlled academic demonstration.
           Do not deploy SHA1(key||message) constructions in real systems.
"""

import struct
import hashlib
import os

# ---------------------------------------------------------------------------
# Paths (relative to repo root; run from the CSCI-4407-lab4/ directory)
# ---------------------------------------------------------------------------

ARTIFACT_DIR = "HashServer_Group_10_student"   # read-only — provided by instructor
OUTPUT_DIR   = "data"                           # all student-generated outputs go here

MESSAGE_FILE = os.path.join(ARTIFACT_DIR, "message.txt")
TAG_FILE     = os.path.join(ARTIFACT_DIR, "tag.hex")
KEY_HINT     = (8, 32)             # inclusive range from keylen_hint.txt
EXTENSION    = b"&role=admin"

OUT_MSG      = os.path.join(OUTPUT_DIR, "forged_message.txt")
OUT_TAG      = os.path.join(OUTPUT_DIR, "forged_tag.hex")


# ---------------------------------------------------------------------------
# SHA-1 padding (Merkle–Damgård strengthening)
# ---------------------------------------------------------------------------

def sha1_padding(msg_len_bytes: int) -> bytes:
    """
    Return the padding bytes appended to a message of `msg_len_bytes` length
    before SHA-1 processes its final block.

    SHA-1 padding = 0x80 || 0x00... || 64-bit big-endian bit length
    Total padded length is a multiple of 64 bytes.
    """
    bit_len = msg_len_bytes * 8
    pad     = b"\x80"
    pad    += b"\x00" * ((55 - msg_len_bytes) % 64)
    pad    += struct.pack(">Q", bit_len)
    return pad


# ---------------------------------------------------------------------------
# SHA-1 continuation from a known internal state
# ---------------------------------------------------------------------------

def sha1_from_state(h_state: tuple[int, int, int, int, int],
                    data: bytes,
                    initial_length: int) -> str:
    """
    Continue SHA-1 hashing of `data` starting from the given internal state
    (h0, h1, h2, h3, h4), as if `initial_length` bytes had already been
    processed before this call.

    Returns the hex digest of SHA1(already_processed_data || data).

    This works because SHA-1 is stateless between blocks: we can inject any
    (h0..h4) tuple and resume processing additional message blocks.
    """
    # Use Python's _sha1 internal or reimplement the block compression.
    # We implement a pure-Python SHA-1 block compression here.

    h0, h1, h2, h3, h4 = h_state

    # Pad `data` as if it follows `initial_length` bytes already processed
    padded_len  = initial_length + len(data)
    data_padded = data + sha1_padding(padded_len)

    # Process each 512-bit (64-byte) chunk
    for chunk_start in range(0, len(data_padded), 64):
        chunk = data_padded[chunk_start : chunk_start + 64]
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 80):
            val = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w.append(((val << 1) | (val >> 31)) & 0xFFFFFFFF)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]
            temp &= 0xFFFFFFFF
            e = d
            d = c
            c = ((b << 30) | (b >> 2)) & 0xFFFFFFFF
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return "%08x%08x%08x%08x%08x" % (h0, h1, h2, h3, h4)


# ---------------------------------------------------------------------------
# Parse known tag into (h0, h1, h2, h3, h4)
# ---------------------------------------------------------------------------

def tag_to_state(tag_hex: str) -> tuple[int, int, int, int, int]:
    """Unpack a 40-char hex SHA-1 digest into five 32-bit words."""
    tag_hex = tag_hex.strip()
    assert len(tag_hex) == 40, f"Expected 40-char hex, got {len(tag_hex)}"
    words = struct.unpack(">5I", bytes.fromhex(tag_hex))
    return words  # (h0, h1, h2, h3, h4)


# ---------------------------------------------------------------------------
# Main attack loop
# ---------------------------------------------------------------------------

def run_attack() -> None:
    # Load artifacts
    with open(MESSAGE_FILE, "rb") as f:
        message = f.read().rstrip(b"\n")
    with open(TAG_FILE) as f:
        original_tag = f.read().strip()

    print("=" * 65)
    print("Task 4 — SHA-1 Length-Extension Attack")
    print("=" * 65)
    print(f"Original message : {message.decode()}")
    print(f"Original tag     : {original_tag}")
    print(f"Extension        : {EXTENSION.decode()}")
    print(f"Key length range : {KEY_HINT[0]} – {KEY_HINT[1]} bytes")
    print()

    state = tag_to_state(original_tag)

    # Track unique forged tags to understand how many distinct tags exist
    unique_tags: dict[str, int] = {}  # tag → first key_len that produced it

    for key_len in range(KEY_HINT[0], KEY_HINT[1] + 1):
        # The SHA-1 was computed over (key || message)
        prefix_len = key_len + len(message)
        padding    = sha1_padding(prefix_len)

        # The forged message visible to the server (everything after the key):
        #   m' = message || padding_for(key||message) || extension
        forged_message = message + padding + EXTENSION

        # The forged tag: SHA1 continued from the original state.
        # initial_length = number of bytes processed before &role=admin starts,
        # i.e., prefix_len (key + message) + len(padding) = next 64-byte boundary.
        initial_len_for_extension = prefix_len + len(padding)
        forged_tag = sha1_from_state(state, EXTENSION, initial_len_for_extension)

        if forged_tag not in unique_tags:
            unique_tags[forged_tag] = key_len

        # Write one candidate forged_message per key length
        candidate_file = os.path.join(OUTPUT_DIR, f"forged_message_klen{key_len}.txt")
        with open(candidate_file, "wb") as f:
            f.write(forged_message)

        print(f"  key_len={key_len:>2}: tag={forged_tag}  msg_bytes={len(forged_message)}")

    print()
    print(f"Unique forged tags found: {len(unique_tags)}")
    print("(Multiple key lengths can share a tag when they fall in the same SHA-1 block bucket)")
    print()

    # Write the primary submission files using the first candidate tag.
    # The instructor verifies against the actual hidden key; the correct
    # forged_message_klenXX.txt file will pass verification.
    best_tag  = next(iter(unique_tags))
    best_klen = unique_tags[best_tag]

    prefix_len     = best_klen + len(message)
    padding        = sha1_padding(prefix_len)
    forged_message = message + padding + EXTENSION
    forged_tag     = sha1_from_state(state, EXTENSION, prefix_len + len(padding))

    with open(OUT_MSG, "wb") as f:
        f.write(forged_message)

    with open(OUT_TAG, "w") as f:
        f.write(forged_tag + "\n")

    print(f"[Output] forged_tag.hex      : {forged_tag}")
    print(f"[Output] forged_message.txt  : {len(forged_message)} bytes  (klen={best_klen} candidate)")
    print(f"         + forged_message_klenXX.txt for each key length 8–32")
    print()
    print("Submission note: submit forged_tag.hex + the forged_message file that")
    print("matches the actual hidden key length.  The instructor's verifier will")
    print("confirm which one passes.")


if __name__ == "__main__":
    run_attack()
