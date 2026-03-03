"""
Task 3 — Toy Merkle–Damgård Hash Construction (15 pts)
=======================================================
Implements a simplified Merkle–Damgård hash to understand iterative
compression and chaining.

Construction:
    BLOCK_SIZE = 16 bytes
    IV         = b'\\x00' * 4  (32-bit initial value)
    h(V, Mi)   = SHA-256(V || Mi) truncated to 32 bits (DIGEST_BITS)

Usage:
    python task3_toy_md.py

Output:
    - Number of blocks
    - Intermediate chaining values V1, V2, ...
    - Final digest
    - Chaining sensitivity demonstration (one modified byte changes all subsequent Vi)
"""

import hashlib


# ---------------------------------------------------------------------------
# Parameters  — document your choices in the report
# ---------------------------------------------------------------------------

BLOCK_SIZE  = 16                  # bytes per message block
DIGEST_BITS = 32                  # bits kept from each SHA-256 application
DIGEST_BYTES = DIGEST_BITS // 8   # = 4
IV = b"\x00" * DIGEST_BYTES       # fixed initial value (all-zeros 32-bit word)


# ---------------------------------------------------------------------------
# Core construction
# ---------------------------------------------------------------------------

def compress(state: bytes, block: bytes) -> bytes:
    """
    Toy compression function: h(V, M) = first DIGEST_BYTES of SHA-256(V || M).

    NOT cryptographically secure — educational use only.
    """
    full = hashlib.sha256(state + block).digest()
    return full[:DIGEST_BYTES]


def pad_message(msg: bytes) -> bytes:
    """
    Toy zero-padding: extend msg to the next multiple of BLOCK_SIZE.
    (Real SHA uses Merkle–Damgård strengthening with length encoding.)
    """
    remainder = len(msg) % BLOCK_SIZE
    if remainder != 0:
        msg += b"\x00" * (BLOCK_SIZE - remainder)
    return msg


def split_blocks(msg: bytes) -> list[bytes]:
    """Split padded message into BLOCK_SIZE-byte blocks."""
    return [msg[i : i + BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]


def toy_hash(msg: bytes, verbose: bool = True) -> bytes:
    """
    Compute the toy Merkle–Damgård digest of msg.

    Returns:
        final digest as bytes (DIGEST_BYTES long)
    """
    padded = pad_message(msg)
    blocks = split_blocks(padded)
    state  = IV

    if verbose:
        print(f"  Message (raw)   : {msg}")
        print(f"  Message (padded): {padded.hex()}")
        print(f"  Block count     : {len(blocks)}")
        print(f"  V0 (IV)         : {state.hex()}")

    for i, block in enumerate(blocks, start=1):
        state = compress(state, block)
        if verbose:
            print(f"  V{i}              : {state.hex()}  (after block {i}: {block.hex()})")

    return state


# ---------------------------------------------------------------------------
# Chaining sensitivity demo
# ---------------------------------------------------------------------------

def chaining_sensitivity_demo(original_msg: bytes) -> None:
    """
    Show that modifying one byte in block 2 cascades to all subsequent Vi.
    """
    padded   = pad_message(original_msg)
    blocks   = split_blocks(padded)

    if len(blocks) < 2:
        print("  (message too short for multi-block demo; padding to 3 blocks)")
        original_msg = original_msg + b" " * (BLOCK_SIZE * 3 - len(original_msg))
        padded = pad_message(original_msg)
        blocks = split_blocks(padded)

    # Flip one byte in block index 1 (the second block, 0-indexed)
    modified_blocks = list(blocks)
    target_block    = bytearray(blocks[1])
    target_block[0] ^= 0xFF                      # flip all bits in first byte
    modified_blocks[1] = bytes(target_block)

    print(f"\n  Original  block[1]: {blocks[1].hex()}")
    print(f"  Modified  block[1]: {modified_blocks[1].hex()}")
    print()

    # Compute both chains
    orig_state = IV
    mod_state  = IV

    for i in range(len(blocks)):
        orig_state = compress(orig_state, blocks[i])
        mod_state  = compress(mod_state, modified_blocks[i])
        changed    = "  <-- CHANGED" if orig_state != mod_state else ""
        print(f"  V{i+1}  original: {orig_state.hex()}   modified: {mod_state.hex()}{changed}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 65)
    print("Task 3 — Toy Merkle–Damgård Hash Construction")
    print(f"  BLOCK_SIZE  = {BLOCK_SIZE} bytes")
    print(f"  DIGEST_BITS = {DIGEST_BITS} bits (output truncated from SHA-256)")
    print(f"  IV          = {IV.hex()}")
    print("=" * 65)

    test_message = b"CSCI4407 Group10 Lab4 Hash Demo"
    print(f"\n[A] Hashing: {test_message!r}\n")
    digest = toy_hash(test_message, verbose=True)
    print(f"\n  Final digest: {digest.hex()}")

    print("\n" + "-" * 65)
    print("[B] Chaining sensitivity: modifying block 2 cascades to all subsequent states\n")
    chaining_sensitivity_demo(test_message)

    print("\n" + "=" * 65)
    print("Observation: Changing one byte in block 2 alters all Vi for i >= 2,")
    print("showing that the Merkle–Damgård chaining propagates changes forward.")
    print()
    print("Security note: 32-bit truncation severely weakens the construction.")
    print("A brute-force collision search would need only ~2^16 trials (birthday)")
    print("compared to 2^128 for full SHA-256.")


if __name__ == "__main__":
    main()
