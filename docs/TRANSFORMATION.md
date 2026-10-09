# Key Transformation: Walkthrough

> What happens to a key between `KeyVault::register` and `KeyVault::with_key` in 1.0.x. Rewritten for 1.0.2 to match the code; the earlier version described layouts, APIs and protections the crate does not have.

For what each step does and does not protect against, read the threat model in [SECURITY.md](SECURITY.md) first. Short version: steps 2 to 5 are obfuscation. Everything needed to undo them is stored in the same process memory, so they do not stop anyone who can read that memory.

---

## The pipeline

```
RawKey (caller's bytes)
   │
   ▼  Step 1  BLAKE3 normalize            (default on)
   ▼  Step 2  codex.encode each byte      (only if with_codex was called)
   ▼  Step 3  split into 1-8 byte chunks  (always; StandardFragmenter)
   ▼  Step 4  add decoy chunks            (only if with_decoy was called)
   ▼  Step 5  shuffle, store each chunk and the layout in page-locked buffers
   │
Fragments, stored in the registry under a KeyHandle
```

`with_key` runs the pipeline backwards into a thread-local scratch buffer, calls your closure with a slice of it, and zeroes the buffer when the closure returns.

---

## Step 1: Normalization

```
INPUT:       "0fx03mmqrhxhrk13"           (16 bytes)
                ↓ BLAKE3 (unkeyed, unsalted)
NORMALIZED:  32 bytes, e.g. a1 7d f3 bc 91 4e 22 68 ...
```

The 32-byte digest replaces the key. It is what `with_key` returns later. It removes format cues such as PEM headers. It is not a password hash: a weak input stays weak, and the digest allows fast offline guessing of it. Turn normalization off with `normalize_with_blake3(false)` if you need the original bytes back.

---

## Step 2: Codex (optional)

Only when a codex is configured (`with_codex(DynamicCodex::new()?)` or a `StaticCodex`). Each byte is replaced through a 256-entry table:

```
CODEX TABLE (example):  h ↔ %,  k ↔ $,  0 ↔ #
PRE-CODEX:   0 f x 0 3 m m q r h x h r k 1 3
POST-CODEX:  # f x # 3 m m q r % x % r $ 1 3
```

The built-in tables are involutions, so decoding applies the same table. The table itself is stored in a page-locked buffer in the same process.

---

## Step 3: Fragmentation

`StandardFragmenter` (the only fragmenter the vault uses) cuts the bytes into chunks whose sizes are drawn from `[min, max]` (default 1 to 8):

```
BYTES:   a1 7d f3 bc 91 4e 22 68 5a c0 d1 fd 83 57 e6 4f ...   (32 bytes)
CHUNKS:  [a1 7d f3] [bc 91 4e 22 68] [5a] [c0 d1 fd 83 57 e6 4f 09] ...
OFFSET:   0          3                 8    9 ...
```

---

## Step 4: Decoy chunks (optional)

Only when a decoy strategy is configured (`with_decoy(SelfReferenceDecoy)` etc.). One decoy chunk is generated per real chunk, with sizes from the same range. `SelfReferenceDecoy` samples bytes from the key, so the decoys have the same byte statistics as the real chunks.

---

## Step 5: Shuffle and store

Real and decoy chunks are shuffled together (Fisher-Yates, OS CSPRNG). Each chunk is copied into its own `LockedBytes`: a separate heap allocation whose pages are `mlock`'d / `VirtualLock`'d (best effort) and which is zeroed on drop. The layout is one more `LockedBytes` holding one little-endian `u32` per chunk:

```
STORED CHUNK ORDER:  [D] [5a] [D] [a1 7d f3] [c0 d1 ...] [D] [bc 91 4e 22 68] ...
LAYOUT (u32 each):   MAX   8   MAX     0         9       MAX        3       ...
                     (u32::MAX marks a decoy chunk; any other value is the
                      chunk's offset in the key)
```

The chunks are separate allocations, but small allocations usually sit close together, often on the same page. Pages shared by several buffers stay locked until the last of them is dropped (reference counted since 1.0.2).

---

## Reassembly: `with_key`

```
1. Load the registry snapshot, clone the entry's Arc<Fragments>.
2. Grow the thread-local scratch buffer if needed (page-locked).
3. Arm a guard that zeroes the scratch on every exit path.
4. For each chunk: read its layout entry; skip u32::MAX; copy the
   chunk to scratch[offset..].
5. If a codex is configured, decode the scratch in place.
6. Call your closure with &scratch[..len].
7. Guard drops: scratch zeroed (also on error or panic).
```

No heap allocation happens on this path with the default `NoAudit` sink. The time depends on the chunk count; it is not constant-time.

---

## What an attacker sees

### A generic scan of a heap dump

A tool that looks for the key as a contiguous byte string, or for a PEM/DER header, finds nothing: the key is in pieces of 1-8 bytes, normalized, and optionally codex-encoded. Entropy-based scans see many small high-entropy allocations; with decoys, twice as many.

### Anyone who can read process memory and knows (or works out) this crate

They can find the registry, follow each entry to its `Fragments`, read the layout buffer, drop the chunks marked `u32::MAX`, put the rest at their offsets, and apply the codex table, which is also in memory. Every key can be rebuilt. Fragmentation, decoys and the codex do not stop this. Mlock does not stop it either; it only keeps the pages out of swap. The audit and monitor layers never see such a read, because it does not go through the API.

### Code inside the process

It calls `with_key`. Nothing in the vault can tell it apart from your application.

---

## Code example

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy};

fn main() -> Result<(), key_vault::Error> {
    let vault = KeyVaultBuilder::new()
        .normalize_with_blake3(true)          // step 1 (default)
        .with_codex(DynamicCodex::new()?)     // step 2 (opt-in)
        .with_decoy(SelfReferenceDecoy)       // step 4 (opt-in)
        .build();

    let handle = vault.register("db-key", RawKey::new(b"0fx03mmqrhxhrk13".to_vec()))?;

    let tag_len = vault.with_key(handle, |key| {
        // `key` is the 32-byte normalized key, valid only inside this closure.
        key.len()
    })?;
    assert_eq!(tag_len, 32);
    Ok(())
}
```

---

<sub>key-vault Key Transformation Walkthrough - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
