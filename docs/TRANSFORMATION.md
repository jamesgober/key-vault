# Key Transformation — Visual Walkthrough

> A step-by-step visual trace of what happens to a key as it passes through the 9 layers of `key-vault`.

---

## Starting key

```
INPUT KEY: "0fx03mmqrhxhrk13"
LENGTH:    16 bytes (ASCII)
```

We'll trace this exact key through every layer of transformation.

---

## Step 1: Key Normalization

> **Optional Layer 0** — applied if `key_normalization = "blake3"` is configured.

The raw input passes through BLAKE3 to produce a fixed-size byte stream. This destroys any structural cues (dashes, dots, varying lengths) that could leak information.

```
INPUT:        "0fx03mmqrhxhrk13"
               ↓ BLAKE3 hash
NORMALIZED:   [0xa1, 0x7d, 0xf3, 0xbc, 0x91, 0x4e, 0x22, 0x68,
               0x5a, 0xc0, 0xd1, 0xfd, 0x83, 0x57, 0xe6, 0x4f,
               0x09, 0xb2, 0x6e, 0xa4, 0x71, 0x35, 0xdb, 0xfc,
               0x82, 0x6a, 0x9e, 0x13, 0x47, 0x80, 0x65, 0x29]
LENGTH:       32 bytes (256 bits — post-quantum safe symmetric)
```

If normalization is disabled, the input bytes pass through unchanged. Format detection happens but the key bytes are preserved.

---

## Step 2: Fragmentation

> **Layer 3** — `StandardFragmenter` with default config (`frag_min=1`, `frag_max=4`).

The normalized key is split into variable-size chunks with randomized positions.

```
NORMALIZED:   [a1] [7d] [f3] [bc] [91] [4e] [22] [68]
              [5a] [c0] [d1] [fd] [83] [57] [e6] [4f]
              [09] [b2] [6e] [a4] [71] [35] [db] [fc]
              [82] [6a] [9e] [13] [47] [80] [65] [29]
              ↓ Fragmenter splits into variable chunks
FRAGMENTS:    F1: [a1, 7d]                  (2 bytes, position 0-1)
              F2: [f3, bc, 91]              (3 bytes, position 2-4)
              F3: [4e]                      (1 byte,  position 5)
              F4: [22, 68, 5a, c0]          (4 bytes, position 6-9)
              F5: [d1, fd]                  (2 bytes, position 10-11)
              F6: [83]                      (1 byte,  position 12)
              F7: [57, e6, 4f, 09]          (4 bytes, position 13-16)
              F8: [b2, 6e]                  (2 bytes, position 17-18)
              ...
              F14: [29]                     (1 byte,  position 31)
              
              ↓ Position map stored separately (protected memory)
POSITION MAP: {F1→0..2, F2→2..5, F3→5..6, F4→6..10, ...}
```

The fragments live in non-contiguous memory allocations. Each allocation is `mlock`-ed.

---

## Step 3: Shuffle

> **Layer 3 continued** — fragments are placed in random order in memory.

```
FRAGMENT INDEX (logical order):  F1, F2, F3, F4, F5, F6, F7, F8, ..., F14
                                  ↓ Random permutation
MEMORY ORDER:                     F7, F2, F11, F4, F1, F13, F6, F9, F3, F8, F12, F5, F10, F14
```

An attacker reading sequential memory sees fragments in this shuffled order. The position map (stored in protected memory separately) is required to put them back together.

---

## Step 4: Decoy Generation

> **Layer 4** — `SelfReferenceDecoy` (default, strongest variant).

Decoy bytes are generated from the key material itself, making them statistically identical to the real fragments.

```
REAL FRAGMENTS:  F1 [a1, 7d], F2 [f3, bc, 91], F3 [4e], ...
                  ↓
DECOY SOURCE:    Hash and re-cycle real fragment bytes
                 (e.g., D1 = BLAKE3(F2 ++ F5)[0..2] = [4e, a1]  ← contains bytes from real fragments!)
                  ↓
DECOY POOL:      D1: [4e, a1]      ← contains bytes seen in F3 and F1
                 D2: [bc, 7d]      ← contains bytes seen in F2 and F1
                 D3: [91, fd]      ← contains bytes seen in F2 and F5
                 D4: [68, 09]      ← contains bytes seen in F4 and F7
                 D5: [b2]
                 ...
```

The decoy bytes look like fragments of the key. An attacker reading raw memory sees both real and decoy bytes side-by-side and cannot distinguish them.

---

## Step 5: Interleave (Fragments + Decoy)

> **Layer 3 + 4 combined** — fragments and decoy bytes are interleaved into the final layout.

```
INTERLEAVED LAYOUT:
[D1] [F7] [D2] [F2] [D3] [F11] [D4] [F4] [D5] [F1] [D6] [F13] [D7] ...
 ↑    ↑    ↑    ↑    ↑    ↑     ↑    ↑    ↑    ↑    ↑    ↑     ↑
decoy real decoy real decoy real decoy real decoy real decoy real decoy
                                                                       ↓
TOTAL LENGTH:  256 bytes (configurable via frag_len)
                                                                       ↓
                                                              Stored in
                                                              fragmented
                                                              mlock'd
                                                              allocations
```

For a 32-byte key, the final output is 256 bytes (8x amplification with decoy). Real key bytes are ~12% of the storage; decoy bytes are ~88%.

---

## Step 6: Codex Transformation (Optional)

> **Layer 5** — `StaticCodex` with example swap table `[(h↔%), (k↔$), (0↔#)]`.

If the `codex` feature is enabled, every byte (real and decoy) passes through a transformation.

```
PRE-CODEX BYTE:   0x68 ('h')
                   ↓ codex.encode(0x68)
POST-CODEX BYTE:  0x25 ('%')

PRE-CODEX BYTE:   0x6b ('k')
                   ↓ codex.encode(0x6b)
POST-CODEX BYTE:  0x24 ('$')

PRE-CODEX BYTE:   0x30 ('0')
                   ↓ codex.encode(0x30)
POST-CODEX BYTE:  0x23 ('#')

PRE-CODEX BYTE:   0xa1
                   ↓ codex.encode(0xa1)  — not in swap table
POST-CODEX BYTE:  0xa1  — unchanged
```

The codex is an **involution** — applying it twice returns the original. So `decode` is the same operation as `encode`. No separate decode table is needed.

```
APPLIED TO STORAGE:
INTERLEAVED:     [4e] [57] [bc] [f3] [91] ... ← real and decoy mixed
                  ↓ codex applied to every byte
POST-CODEX:      [4e] [57] [bc] [f3] [91] ... ← potentially transformed
```

Note: in this example, the swap table only affects 'h', 'k', '0' (and their swap partners). Real cryptographic key bytes (typically high-byte values) are rarely affected. The codex is more useful for keys that pass through ASCII-printable forms (UTF-8 encoded secrets, environment variables, etc.).

---

## Step 7: Final Storage

The final layout is stored across multiple `mlock`-ed memory allocations:

```
ALLOCATION 1 (page 0x7fa1b2c3, mlock'd, PROT_READ):
    [D1, F7, D2, F2, D3, F11, D4, F4, ...]

ALLOCATION 2 (page 0x7fa1d800, mlock'd, PROT_READ):
    [D5, F1, D6, F13, D7, F6, D8, F9, ...]

ALLOCATION 3 (page 0x7fa1f100, mlock'd, PROT_READ):
    [D9, F3, D10, F8, D11, F12, D12, F5, ...]

POSITION MAP (page 0x7fa20000, mlock'd, PROT_READ — separate from data):
    F1 → Alloc 2 offset 8, length 2  (logical position 0..2)
    F2 → Alloc 1 offset 12, length 3 (logical position 2..5)
    F3 → Alloc 3 offset 8, length 1  (logical position 5..6)
    ...
```

The position map is mandatory for reassembly. It's stored separately (different page) with its own protections.

---

## Step 8: Reassembly (Defrag)

> **Hot path** — what happens when the application requests the key.

When `vault.get_key(handle)` is called:

```
STEP 1: Read position map (constant-time, no branching on map contents)
   Position map → logical fragment order

STEP 2: For each fragment in logical order:
   Fetch from allocation at recorded offset
   Apply codex.decode() to each byte (if codex enabled)
   Concatenate into output buffer (Zeroizing<Vec<u8>>)

STEP 3: Return KeyHandle pointing to output buffer
   The output buffer auto-zeroizes when dropped.

REASSEMBLY TIME: ~200-500ns for 32-byte key
ALLOCATION:      One temporary Zeroizing<Vec<u8>> (deallocated immediately after use)
```

```
INPUT (storage):
    F7, F2, F11, F4, F1, F13, F6, F9, F3, F8, F12, F5, F10, F14  (shuffled)
    Mixed with decoy in storage
                                  ↓
STEP A: Filter only real fragments using position map
                                  ↓
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14  (logical order)
                                  ↓
STEP B: Concatenate fragment bytes
                                  ↓
    [a1, 7d, f3, bc, 91, 4e, 22, 68, 5a, c0, d1, fd, 83, 57, ...]  (32 bytes)
                                  ↓
STEP C: Apply codex.decode() if codex enabled
                                  ↓
RECONSTRUCTED:  [a1, 7d, f3, bc, 91, ...]  ← identical to NORMALIZED in step 1
                                  ↓
              Hand to crypt-io for actual encryption work
                                  ↓
                       After use: zeroize() called
                                  ↓
                       Output buffer overwritten with 0x00
```

---

## Summary Table

| Stage | Operation | Output |
|-------|-----------|--------|
| Input | User-provided key | `"0fx03mmqrhxhrk13"` (16 bytes) |
| Step 1 | BLAKE3 normalize | 32 bytes |
| Step 2 | Fragment | 14 fragments, sizes 1-4 |
| Step 3 | Shuffle | Random fragment order |
| Step 4 | Decoy gen | 224 decoy bytes (self-referential) |
| Step 5 | Interleave | 256 bytes total |
| Step 6 | Codex (opt) | 256 bytes transformed |
| Step 7 | Storage | 3 allocations, mlock'd, PROT_READ |
| Hot path | Defrag | ~200-500ns, Zeroizing<Vec<u8>> |

---

## What an Attacker Sees

### Scenario 1: Process memory dump

```
ATTACKER DUMPS PROCESS MEMORY:

Allocation 1 contents:
4e 57 bc f3 91 a1 22 7d 68 4f c0 5a fd f3 83 91 ...
[238 more bytes]

Allocation 2 contents:
4e a1 25 7d c0 91 b2 68 a1 9e fd 47 22 4f 80 65 ...

Allocation 3 contents:
68 09 a1 fd 35 7d ... [256 bytes total]
```

The attacker sees high-entropy byte sequences. They look like random data. Or like encrypted data. Or like a key. Statistical analysis cannot distinguish.

The attacker does NOT know:
- Which bytes are real fragments
- Which bytes are decoy
- The order to reassemble fragments
- Whether codex transformation was applied
- The swap table if codex was applied

### Scenario 2: Attacker also dumps position map

If somehow the position map is also exposed:

```
POSITION MAP:
F1 → Alloc 2 offset 8, length 2
F2 → Alloc 1 offset 12, length 3
...
```

Now the attacker can reassemble fragments. But:
- They still must reverse the codex (Layer 5) if it was applied
- They face audit logging entries (Layer 9) showing their access
- Anomaly detection (Layer 8) likely fires alerts
- Page protection (Layer 10) may have blocked their read

### Scenario 3: Attacker has reverse-engineered the binary

If the attacker has the binary and has reverse-engineered all algorithms, they know:
- The fragment strategy
- The decoy strategy
- The codex transformation
- The position map format

They can now read all keys IF they get memory access. But this requires:
- A binary-level reverse engineering effort (significant work)
- Memory access (still restricted by OS protections, mlock, etc.)
- Avoiding detection (audit, monitor)

This is the most sophisticated attack scenario. It assumes you've shipped your binary to the attacker. For Hive DB shipped to enterprises, this is a relevant threat — and the codex layer specifically helps because Hive DB can ship with a private custom codex unique to each deployment.

---

## Code Example

```rust
use key_vault::{KeyVault, FragmentStrategy, DecoyStrategy, Codex, StaticCodex};

// Build a vault with all defenses enabled
let vault = KeyVault::builder()
    .fetcher(KeychainFetch::default())
    .normalize_with_blake3()
    .fragment_strategy(StandardFragmenter::default())
    .decoy_strategy(SelfReferenceDecoy::default())
    .codex(StaticCodex::from_swaps(&[
        (b'h', b'%'),
        (b'k', b'$'),
        (b'0', b'#'),
    ]))
    .mlock(true)
    .zeroize(true)
    .audit_enabled(true)
    .monitor(LogMonitor::default())
    .build()?;

// Acquire a key
let handle = vault.fetch_key("my-encryption-key")?;

// Use the key (defragmentation happens here, briefly)
{
    let plaintext = vault.defrag(&handle)?;  // Zeroizing<Vec<u8>>
    let ciphertext = crypt_io::encrypt(&plaintext, data)?;
    // plaintext dropped here → auto-zeroize
}

// The key remains in vault, fragmented, for next access
```

---

<sub>key-vault Key Transformation Walkthrough - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>