# Lab 4 — Group 10 — Cryptographic Hash Functions Attacks

**Course:** CSCI/CSCY 4407 — Security & Cryptography
**Semester:** Spring 2026
**Date:** 3/8/26
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

### Question 6.1.1

**Q:** Based on your results, does SHA-256 demonstrate the avalanche effect? (i) cite computed averages, (ii) explain why ~50% bit-flip is expected, (iii) discuss why multiple trials are necessary.

**A:**

Yes, SHA-256 demonstrates the avalanche effect. In our experiment, changing a single character in the input message resulted in an average of **129.4 out of 256 bits** changing in the hash output, which corresponds to an average of **50.55% of the bits flipping**. These results are very close to the theoretical expectation of about 50%, indicating that even a very small change in the input produces a large and unpredictable change in the output.

A ~50% bit change is expected because a well-designed cryptographic hash function behaves similarly to a random function. When a single input bit changes, each output bit should have about a **50% probability of flipping**. Since SHA-256 produces a **256-bit digest**, this means that roughly **128 bits** should change on average. This property ensures strong diffusion, making it extremely difficult to predict how small input changes affect the output.

Multiple trials are necessary because the avalanche effect is a **statistical property**. A single trial could produce results slightly above or below the expected value due to randomness. By performing several trials and averaging the results, we obtain a more reliable measurement that better represents the true behavior of the hash function.

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
import hashlib
import sys

BLOCKSIZE = 16  #Processes our message in 16-byte chunks (Chunking!!!!)
IV = b'\x00' * 4 #Initial Value (4 bytes are used for our 32-bit Hoashing)

def ToyCompression(PreviousState, MessageBlock):
    """
    Toy Compression:
    1. Concatenate the previous state (V_i-1) and current block (M_i).
    2. Hashes them using a SHA-256 algorithm.
    3. Truncates output to 32 bits, also written as 4 bytes.
    """
    Data = PreviousState + MessageBlock
    CompleteHash = hashlib.sha256(Data).digest()
    return CompleteHash[:4]

def ToyHashing(Message):
    print(f"\nIngesting The Message: {Message}")
    print("-" * 50)
    
    #Padds the last message block with zeros to fill the block so it has not empty bits
    MessageBytes = Message.encode()
    PaddingLength = (BLOCKSIZE - (len(MessageBytes) % BLOCKSIZE)) % BLOCKSIZE
    PaddedMessage = MessageBytes + (b'\x00' * PaddingLength)
    
    #Splits the message into blocks
    Blocks = [PaddedMessage[i:i+BLOCKSIZE] for i in range(0, len(PaddedMessage), BLOCKSIZE)]
    print(f"Total Amount Blocks: {len(Blocks)}")
    
    #Compresses iteratively
    State = IV
    print(f"IV (V0): {State.hex()}")
    
    for i, Block in enumerate(Blocks):
        State = ToyCompression(State, Block)
        print(f"Block {i+1}: {Block} -> State (V{i+1}): {State.hex()}")
        
    print("-" * 50)
    print(f"The Final Digest: {State.hex()}")
    return State.hex()

if __name__ == "__main__":
    #Test 1: Original Message
    MessageTest = "Cryptography is very very cool and interesting."
    ToyHashing(MessageTest)

    #Test 2: Chaining Sensitivity (Changes one character)
    #We changed the period to an exclamation point for some cool flair
    MessageTestAgain = "Cryptography is very very cool and interesting!"
    ToyHashing(MessageTestAgain)
    
    #Test 3: Chaining Sensitivity (Changes the entire sentence)
    MessageTestAgainAgain = "CRYPTOGRAPHY IS AWESOME AND I LOVE IT!!"
    ToyHashing(MessageTestAgainAgain)
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
python3 toy_md.py
```

### Screenshots

<!-- Insert screenshot: intermediate chaining values V1, V2, ... for test message -->

<!-- Insert screenshot: chaining sensitivity demo (modified block 2 cascades) -->

<!-- Both are in one screenshot -->
![Task 3](Screenshots/Task3.png)

### Sample Output (fill in after running)

```
Ingesting The Message: Cryptography is ver very cool and interesting.
Total Amount Of Blovks: 3
IV (V0): 00000000
Block (1): b'Cryptography is ' -> State (V1): 05ff8487
Block (2): b'very very cool a' -> State (V2): e651c941
Block (3): b'nd interesting. \x00' -> State (V3): 9f3d5ed6
Final Digest: 9f3d5ed6

Ingesting The Message: Cryptography is ver very cool and interesting!
Total Amount Of Blovks: 3
IV (V0): 00000000
Block (1): b'Cryptography is ' -> State (V1): 05ff8487
Block (2): b'very very cool a' -> State (V2): e651c941
Block (3): b'nd interesting! \x00' -> State (V3): a4e4d9a0
Final Digest: a4e4d9a0
```

### Chaining Sensitivity

| Block Modified | V1 changed? | V2 changed? | V3 changed? |
|:--------------:|:-----------:|:-----------:|:-----------:|
| Block 3        | No          | NO          | Yes         |

### Question 6.3 (Answer Required)

**Q:** How do chaining values propagate changes across blocks? Why does modifying one block affect the final digest? Why does 32-bit truncation make the construction insecure?

**A:** In the Merkle–Damgård Theorem chaining values will enable changes as each block's output state becomes the input for the next compression step (Vi = h (Vi − 1 , Mi)). Modifying even a single bit in one block completely randomizes the output, and due to the avalanche effect (Found often if not always in hashing) this altered ouput then gets given to the next block therefor creating a chain reaction that subsequently changes all following states and outputs guaranteeing a completely different final digest. However, truncating this final digest to only 32 bits renders the Theorem practically insecure (The small keyspace problem). Due to the nature of Birthday attacks, a 32-bit hash space requires an attacker to compute only about 2^(32) = 2^(16), (65,536) hashes to find a collision. Modern computers can perform this attack in microseconds and breaking the collision resistance that is necessary for a secure cryptographic hash function in modnern systems.

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
import struct
import sys
import os

#SHA-1 WITH STATE INJECTION (Im not too sure if this works correctly, perhaps i've been overzealous)
class SHA1:
    def __init__(Self, State=None, Count=0):
        #SHA-1 Initial Values
        if State is None:
            Self._h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        else:
            Self._h = list(State) #Injects the current running state (h0 through h4)
        Self._count = Count       #Injects the active bit count (To preserve the length of the message)
        Self._buffer = b''

    def LeftRotate(Self, N, B):
        return ((N << B) | (N >> (32 - B))) & 0xFFFFFFFF

    def ProcessChunk(Self, Chunk):
        W = [0] * 80
        for i in range(16):
            W[i] = struct.unpack(b'>I', Chunk[i*4:i*4+4])[0]
        for i in range(16, 80):
            W[i] = Self.LeftRotate(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1)

        A, B, C, D, E = Self._h
        for i in range(80):
            if 0 <= i <= 19:
                F = (B & C) | ((~B) & D)
                K = 0x5A827999
            elif 20 <= i <= 39:
                F = B ^ C ^ D
                K = 0x6ED9EBA1
            elif 40 <= i <= 59:
                F = (B & C) | (B & D) | (C & D)
                K = 0x8F1BBCDC
            elif 60 <= i <= 79:
                F = B ^ C ^ D
                K = 0xCA62C1D6

            Temp = (Self.LeftRotate(A, 5) + F + E + K + W[i]) & 0xFFFFFFFF
            E = D
            D = C
            C = Self.LeftRotate(B, 30)
            B = A
            A = Temp

        Self._h[0] = (Self._h[0] + A) & 0xFFFFFFFF
        Self._h[1] = (Self._h[1] + B) & 0xFFFFFFFF
        Self._h[2] = (Self._h[2] + C) & 0xFFFFFFFF
        Self._h[3] = (Self._h[3] + D) & 0xFFFFFFFF
        Self._h[4] = (Self._h[4] + E) & 0xFFFFFFFF

    def Update(Self, Data):
        if isinstance(Data, str): Data = Data.encode()
        Self._buffer += Data
        Self._count += len(Data) * 8
        while len(Self._buffer) >= 64:
            Self._process_chunk(Self._buffer[:64])
            Self._buffer = Self._buffer[64:]

    def HexDigest(Self):
        #Apply padding to the hex (SHA-1 padding)
        TemporaryBuffer = Self._buffer
        TemporaryCount = Self._count
        
        TemporaryBuffer += b'\x80'
        while (len(TemporaryBuffer) + 8) % 64 != 0:
            TemporaryBuffer += b'\x00'
        TemporaryBuffer += struct.pack(b'>Q', TemporaryCount)
        
        #Process the remaining chunks in a local version so that we dont affect the state of the object
        localSHA = SHA1(Self._h, Self._count) 
        for i in range(0, len(TemporaryBuffer), 64):
            localSHA.ProcessChunk(TemporaryBuffer[i:i+64])
            
        return '%08x%08x%08x%08x%08x' % tuple(localSHA._h)

#Attacking below!

def GetPadding(MessageLength):
    """Calculates SHA-1 padding for the length of our message"""
    #The padding is 1 bit followed by zeros, this is 64 bits in length :3
    Padding = b'\x80'
    while (MessageLength + len(Padding) + 8) % 64 != 0:
        Padding += b'\x00'
    
    #Appends our length in bits
    Padding += struct.pack(b'>Q', MessageLength * 8)
    return Padding

def Attack(OGMessageBytes, OGTag, keyLength, Extension):
    #Obtain and create the internal state from the original tag given by the tag file and splits the 40 character hex tag into 5 chunks of 8 character
    HashStates = [int(OGTag[i:i+8], 16) for i in range(0, 40, 8)]

    #Calculate the length of the data processed at this point (That being the key, the message, and the tag); The new has that we are creating is the combination of the original message and the padding
    OGTotalLength = keyLength + len(OGMessageBytes)
    Padding = GetPadding(OGTotalLength)
    
    CBitCount = (OGTotalLength + len(Padding)) * 8

    #Initializes the SHA1 with the Recovered state and updated count
    ForgedSHA = SHA1(State=HashStates, Count=CBitCount)

    #Updates using the extension that we are using
    ForgedSHA.Update(Extension)

    #Generates the results of the previous steps
    NewlyTag = ForgedSHA.HexDigest()
    
    #The forged message is the combination of Message, the Padding, and the Extension
    FMessageBytes = OGMessageBytes + Padding + Extension.encode()

    return NewlyTag, FMessageBytes

if __name__ == "__main__":
    print("--- Length Extension Attack Tool ---")


    try:
        #Read message.txt
        with open("message.txt", "rb") as f:
            OGMessageBytes = f.read().strip()
            
        #Read tag.hex
        with open("tag.hex", "r") as f:
            OGTag = f.read().strip()
            
        print(f"Loaded 'message.txt': {OGMessageBytes}")
        print(f"Loaded 'tag.hex':     {OGTag}")

    except FileNotFoundError:
        print("Error: Could not find 'message.txt' or 'tag.hex'.")
        print("\nPlease run this script inside your unzipped artifact folder.")
        sys.exit(1)

    #Config
    Extension = "&role=admin"
    
    #Checks for hint file to guess the key length or just guesses 12 everytime if user input is invalid
    try:
        if os.path.exists("keylen_hint.txt"):
            with open("keylen_hint.txt", "r") as f:
                print(f"HINT FOUND: {f.read().strip()}")
        
        GuessKeyLength = int(input("Enter the key length to try: "))
    except ValueError:
        print("Invalid input. Using a key length of 12.")
        GuessKeyLength = 12

    #Performs the attack of forgery
    print(f"\nAttack is using Key Length: {GuessKeyLength}...")
    
    NewlyTag, ForgedMessage = Attack(OGMessageBytes, OGTag, GuessKeyLength, Extension)
    
    print(f"\nForged Tag: {NewlyTag}")
    
    print(f"\nForged Message: {ForgedMessage}")
    
    #Saves our outputs
    with open("forged_tag.hex", "w") as f:
        f.write(NewlyTag)
        
    with open("forged_message.txt", "wb") as f:
        f.write(ForgedMessage)
        
    print("Saved 'forged_tag.hex' and 'forged_message.txt'")
    print("Attack Completed.")
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

![Task 4B](Screenshots/Task4B.png)

<!-- Insert screenshot: task4_length_extension.py terminal output showing forged_tag candidates -->

<!-- Insert screenshot: forged_message.txt (hexdump or xxd) and forged_tag.hex -->

![Task 4](Screenshots/Task4.png)

### Attack Output

| Key Length (tested) | Forged Tag                               | Forged Msg Size |
|:-------------------:|------------------------------------------|:---------------:|
| 16                  | `4e1193fd0e9e1990e803b2d145ae1f0279823099` | 107–131 bytes  |

> **Note:** All 25 key-length candidates produce the same forged tag because
> `key_len + len(message) + SHA-1-padding` always falls in the same 128-byte
> block boundary for this message. The 25 candidate `forged_message_klenXX.txt`
> files are all written; the instructor's verifier will confirm which one passes.

**Forged message file:** `HashServer_Group_10_student/forged_message.txt` (+ `forged_message_klenXX.txt` for each key length 8–32)
**Forged tag file:** `HashServer_Group_10_student/forged_tag.hex` → `4e1193fd0e9e1990e803b2d145ae1f0279823099`

### How the Attack Works

The SHA-1 tag is computed as `SHA1(key || message)`. SHA-1 follows the Merkle–Damgård
Theorem: after processing each 512-bit block it exposes its internal state (h0–h4)
in the final digest. Because we have the digest, we have the exact internal state SHA-1
was in after hashing `(key || message)`. We can therefore:

1. Compute the SHA-1 padding that was appended to `(key || message)` to fill the last block.
2. Inject the known (h0–h4) state and continue hashing the extension `&role=admin`.
3. The resulting digest is a valid tag for `message || padding || &role=admin` under the
   same unknown key — without ever learning the key.

### Question 6.4.1

**Q:** Why does SHA1(k||m) fail to provide secure message authentication even though SHA-1 is a cryptographic hash? Explain how Merkle–Damgård enables length extension and why HMAC does not suffer from this.

**A:** The construction of SHA1(k||m) fails to provide secure message authentication because SHA-1 is built on the Merkle–Damgård theorem, which makes it vulnerable to length-extension attacks. In the Merkle–Damgård construction, messages are processed in fixed-size blocks, and the final hash digest is simply the internal state of the algorithm after processing the final block (including message padding). Because the output is the internal state, an attacker who intercepts the hash and obtains the knowledge of the length of the secret key can calculate the exact padding used. The attacker can then load the intercepted hash back into the SHA-1 algorithm as the starting state and give it the extension. This produces a perfectly valid hash for k || m || padding || extension without the attacker ever needing to know the secret key.

HMAC prevents this vulnerability by using a nested two-pass hashing mechanism defined as H(k ⊕ opad || H(k ⊕ ipad || m)). Even if an attacker successfully extends the inner hash, they cannot compute the final outer hash because doing so requires prepending the secret key (k ⊕ opad) to the output of the inner hash. Since the attacker does not know the key they cannot repordouce the outer hashing step, effectively sealing the hash and neutralizing the length-extension vulnerability.

---

## Task 5 — Password Hashing Analysis (15 pts)

### Source Code

##pwd_hash.py
```python
import hashlib
import time
import os
import binascii

#Config
TARGETPASSWORD = "shadow"  #The password we are going to use later
SALTSIZE = 16
ITERATIONS = 200000         #For PBKDF2

def SaveFile(FileName, Data):
    with open(FileName, "w") as f:
        f.write(Data)
    print(f"Saved {FileName}")

def GenerateHashes():
    print(f"Hashing password '{TARGETPASSWORD}'\n")

    #UNSALTED SHA-256
    Start = time.time()
    UnsaltedHash = hashlib.sha256(TARGETPASSWORD.encode()).hexdigest()
    End = time.time()
    
    print(f"Unsalted Hash: {UnsaltedHash}")
    print(f"Unsalted Hash time to compute: {(End - Start):.6f} seconds")
    SaveFile("db_unsalted.txt", UnsaltedHash)

    #SALTED SHA-256
    Start = time.time()
    Salt = os.urandom(SALTSIZE)
    SaltedHash = hashlib.sha256(Salt + TARGETPASSWORD.encode()).hexdigest()
    End = time.time()
    
    #Format for storage of the password
    StorageString = f"{Salt.hex()}${SaltedHash}"
    
    print(f"\nSalt: {Salt.hex()}")
    print(f"Salted Hash: {SaltedHash}")
    print(f"Salted Hash time to compute: {(End - Start):.6f} seconds")
    SaveFile("db_salted.txt", StorageString)

    #PBKDF2 (Key Stretching)
    Start = time.time()
    # Note: PBKDF2 uses the salt and iterations automatically
    PBKDF2_Hash = hashlib.pbkdf2_hmac(
        'sha256', 
        TARGETPASSWORD.encode(), 
        Salt, 
        ITERATIONS
    )
    End = time.time()
    
    StorageString_PBKDF2 = f"{Salt.hex()}${PBKDF2_Hash.hex()}${ITERATIONS}"
    
    print(f"\nPBKDF2 Iterations: {ITERATIONS}")
    print(f"PBKDF2 Hash: {PBKDF2_Hash.hex()}")
    print(f"PBKDF2 Hash time to compute: {(End - Start):.6f} seconds")
    SaveFile("db_pbkdf2.txt", StorageString_PBKDF2)

if __name__ == "__main__":
    GenerateHashes()
```

##dict_attack.py
```python
import hashlib
import time
import sys

#Config
DICTIONARYFILE = "pwds.txt"

def LoadDictionary():
    try:
        with open(DICTIONARYFILE, "r") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: {DICTIONARYFILE} not found.")
        sys.exit(1)

def UnsaltedAttack(Dictionary):
    print("\nUnsalted Attack")
    try:
        with open("db_unsalted.txt", "r") as f:
            TargetHash = f.read().strip()
    except FileNotFoundError:
        print("db_unsalted.txt not found. Run pwd_hash.py first.")
        return

    print(f"Target: {TargetHash}")
    
    StartTime = time.time()
    Attempts = 0
    Found = False
    
    for Password in Dictionary:
        Attempts += 1
        #Computes the Hash for us
        GuessHash = hashlib.sha256(Password.encode()).hexdigest()
        
        if GuessHash == TargetHash:
            Found = True
            break
            
    EndTime = time.time()
    Duration = EndTime - StartTime
    
    if Found:
        print(f"Password found: '{Password}'")
        print(f"Time: {Duration:.6f} seconds")
        Rate = Attempts / Duration if Duration > 0 else float('inf')
        print(f"Speed: {Rate:.2f} guesses/sec")
    else:
        print("Password is not found in the dictionary.")

def SaltedAttack(Dictionary):
    print("\nSalted Attack")
    try:
        with open("db_salted.txt", "r") as f:
            Content = f.read().strip()
            SaltHex, TargetHash = Content.split('$')
            Salt = bytes.fromhex(SaltHex)
    except FileNotFoundError:
        return

    print(f"Salt: {SaltHex}")
    print(f"Target: {TargetHash}")
    
    StartTime = time.time()
    Attempts = 0
    Found = False
    
    for Password in Dictionary:
        Attempts += 1
        #Attacker must use the specific salt that is desiginated for this specific user
        GuessHash = hashlib.sha256(Salt + Password.encode()).hexdigest()
        
        if GuessHash == TargetHash:
            Found = True
            break
            
    EndTime = time.time()
    Duration = EndTime - StartTime
    
    if Found:
        print(f"Password found: '{Password}'")
        print(f"Time: {Duration:.6f} seconds")
        Rate = Attempts / Duration if Duration > 0 else float('inf')
        print(f"Speed: {Rate:.2f} guesses/sec")
    else:
        print("Password not in dictionary.")

def PBKDF2_Attack(Dictionary):
    print("\nPBKDF2 Attack")
    try:
        with open("db_pbkdf2.txt", "r") as f:
            Content = f.read().strip()
            SaltHex, TargetHash, IterationsPlural = Content.split('$')
            Salt = bytes.fromhex(SaltHex)
            Iterations = int(IterationsPlural)
    except FileNotFoundError:
        return

    print(f"Iterations: {Iterations}")
    print(f"Target: {TargetHash}")
    
    StartTime = time.time()
    Attempts = 0
    Found = False
    
    for Password in Dictionary:
        Attempts += 1
    
        GuessHash = hashlib.pbkdf2_hmac(
            'sha256', 
            Password.encode(), 
            Salt, 
            Iterations
        ).hex()
        
        if GuessHash == TargetHash:
            Found = True
            break
            
    EndTime = time.time()
    Duration = EndTime - StartTime
    
    if Found:
        print(f"Password found: '{Password}'")
        print(f"Time: {Duration:.6f} seconds")
        Rate = Attempts / Duration if Duration > 0 else float('inf')
        print(f"Speed: {Rate:.2f} guesses/sec")
    else:
        print("Password not in dictionary.")

if __name__ == "__main__":
    Words = LoadDictionary()
    print(f"Loaded {len(Words)} passwords from dictionary.")
    
    UnsaltedAttack(Words)
    SaltedAttack(Words)
    PBKDF2_Attack(Words)
```

### Password Dictionary

`data/pwds.txt` — 30 candidate passwords including weak passwords, variations, and passphrases.
```
Passoword
123456
12345678
qwerty
admin
welcome
login
security
football
shadow
burger
fries
shake
pizza
Password123
MiloTheLynx
Cryptography
Goku&Vegeta
Winter2026!
Potatoes!TheyAreAVegetableRight??
ThisIsMySwordSwordMyDiamondSword
CUDenver
CryptographyIsNotCrypto!
Hello
HowAreYou
DOYOUKNOWDAWAE
Doyoulikesoda
NOIMMOREOFAWATERGUY.
```

### Steps

```bash
# Generate all three stored hashes for password "Winter2026!"
python3 pwd_hash.py

# Run the Dictionary attacks
python3 dict_attack.py
```

### Screenshots

<!-- Insert screenshot: task5_pwd_hash.py output (all three methods) -->

![Task 5](Screenshots/Task5A.png)

<!-- Insert screenshot: dict attack — unsalted (password found) -->

<!-- Insert screenshot: dict attack — PBKDF2 (slow, same password) -->

![Task 5](Screenshots/Task5B.png)

### Performance Comparison Table

| Method                     | Hash Time      | Guesses/sec (est.) |
|----------------------------|:--------------:|:------------------:|
| SHA-256 (unsalted)         |0.000023 seconds|       436906.67    |
| SHA-256 (salted, 16-byte)  |0.000008 seconds|       1310720.00   |
| PBKDF2 (200,000 iterations)|0.321651 seconds|       31.09        |

### Question 6.5.1

**Q:** Which mechanism provided the greatest security increase: adding a salt or using PBKDF2? Explain why salts don't slow down guessing but still help. Explain why SHA-256 alone is inappropriate for passwords.

**A:** Using PBKDF2 (key stretching) provided the greatest increase in security against dictionary and brute-force attacks. Based on the experimental data, adding a salt did not reduce the guesses-per-second rate but actually increased it. Implementing PBKDF2 with thousands of iterations drastically decreades the guessing speed, making the attack computationally expensive. Salts did not slow down the password guessing because the underlying hash function still only executes a single time for each guess. However, they provide a critical security benefit by preventing precomputation attacks. Since a unique random salt is appended to each user's password before hashing, this means an attacker cannot use a master list of pre-computed hashes; they must re-compute the entire dictionary for every single user's specific salt. SHA-256 alone is inappropriate for password storage because it is designed to be mathematically fast and highly efficient. In cryptography, high speed is a massive vulnerability for passwords as attackers using modern GPUs or ASICs can evaluate billions of SHA-256 hashes per second. Secure password storage requires specialized Key Derivation Functions (like PBKDF2) that implement a "work factor" to intentionally slow down the hashing process, rendering bulk brute-force guessing unfeasible.

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
![Task 6 before](Screenshots/Task6a.png)

<!-- Insert screenshot: sha1sum/sha256sum after 1-byte modification (different digests) -->
![task 6 after](Screenshots/Task6b.png)

### Before / After Comparison

| File    | SHA-256 (before)          | SHA-256 (after)           |
|---------|---------------------------|---------------------------|
| fileA   |                           | (unchanged)               |
| fileB   |                           |                           |

### Question 6.6.1

### Question 6.6.1

**Q:** Why are hash functions highly sensitive to small input changes? Why does comparing hashes alone not guarantee authenticity without a trusted reference channel?

**A:**

Cryptographic hash functions are designed to be highly sensitive to small input changes because of the **avalanche effect**. This property ensures that even a tiny modification to the input, such as changing a single bit or character, causes a large and unpredictable change in the resulting hash output. This sensitivity makes hash functions useful for detecting file corruption or tampering, since any modification to the original data will produce a completely different digest.

However, comparing hashes alone does not guarantee authenticity. Hash comparison only verifies that the file matches the provided hash value; it does not prove that the hash itself is legitimate. If the hash value is obtained from an untrusted source, an attacker could provide a malicious file along with a matching hash for that malicious file.

For this reason, the **reference hash must come from a trusted source**. A trusted channel ensures that the hash value truly corresponds to the original, untampered file. Common trusted sources include official software websites, digitally signed releases, or secure distribution channels.

If an attacker is able to modify both the file and the hash, the integrity check becomes meaningless. The attacker could replace the original file with a malicious one and simply generate a new hash for it. Since the computed hash would match the attacker’s provided hash, the verification process would falsely indicate that the file is authentic.

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
