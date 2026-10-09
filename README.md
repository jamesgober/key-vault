<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>key-vault</b>
    <br>
    <sub>
        <sup>IN-MEMORY KEY VAULT</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/key-vault"><img src="https://img.shields.io/crates/v/key-vault.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/key-vault"><img alt="downloads" src="https://img.shields.io/crates/d/key-vault?color=%230099ff"></a>
    <a href="https://docs.rs/key-vault"><img src="https://docs.rs/key-vault/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</p>

<p align="center">
    <b>Page-Locked, Zero-On-Drop In-Memory Key Storage for Rust</b>
    <br>
    <i>mlock + zeroize + opaque handles + scoped access, with optional fragmentation, decoy and codex obfuscation, monitoring and audit hooks.</i>
</p>

<br>

<p>
    <strong>key-vault</strong> keeps cryptographic key material in process memory while your application runs. Keys live in page-locked (<code>mlock</code> / <code>VirtualLock</code>), zero-on-drop buffers. Callers get an opaque <code>KeyHandle</code> instead of a <code>Vec&lt;u8&gt;</code>, and the bytes are handed out only inside a scoped callback, from a buffer that is wiped when the callback returns.
</p>

<p>
    On top of that the vault splits each key into small shuffled fragments and can mix in decoy chunks and pass bytes through a codex. <b>These are obfuscation, not protection against a memory reader:</b> the layout map that reassembles the fragments and the codex table are stored in the same process memory, so anyone who can read that memory can rebuild every key. They make life harder for generic memory scans and heap-dump tooling; see the <a href="#threat-model">threat model</a>.
</p>

<p>
    Also included: atomic key rotation, named multi-key vaults, pluggable <b>key fetchers</b> (OS keychain, plaintext file, environment variable), caller-driven failure monitoring with an optional vault-wide lockout, audit hooks, master-key unlock, and informational TEE detection.
</p>


<hr>
<br>



## Layers

What each layer does in 1.0.x, plainly:

| Layer | What it is | Status in 1.0.x | Protects against | Does NOT protect against |
|-------|-----------|-----------------|------------------|--------------------------|
| **1** | Key acquisition (`KeyFetch`) | Keychain, plaintext file, env var. **`TpmFetch` is not implemented** (always errors) | Hardcoded keys | Anything once the key is in memory |
| **2** | Page locking (`mlock` / `VirtualLock`) | On, best effort (fails silently at `RLIMIT_MEMLOCK`), per-page reference counted | Keys written to swap | Memory readers, core / crash dumps |
| **3** | Fragmentation (1-8 byte shuffled chunks) | Always on (`StandardFragmenter`) | Scans for a contiguous key | Memory readers: the layout map is in the same memory |
| **4** | Decoy chunks | **Off** unless `with_decoy` is called | Statistical scans for key-like regions | Memory readers: the layout map marks every decoy |
| **5** | Codex (byte substitution table) | **Off** unless `with_codex` is called | Scans for the raw key bytes | Memory readers: the table is in the same memory. Not encryption |
| **6** | Constant-time comparison | Master-key digest check, handle equality | Timing on the master check | Timing of key lookup and reassembly (not constant-time) |
| **7** | Zero-on-drop (`zeroize`) | Every secret-bearing buffer the crate owns | Keys left in freed memory | Copies made by `std`, the OS or your own callback |
| **8** | Failure monitor + lockout | **Advisory**: counts only failures you report; lockout is vault-wide | Repeated failures you report | Memory readers; it never sees decryption failures itself |
| **9** | Audit hooks | One event per vault operation | Unnoticed API-level use | Tampering with your sink; reads below the API |
| **10** | Page protection toggling (`PROT_NONE`) | **Not implemented** | | |

Cargo features do not turn these layers on or off. Only `std`, the `fetcher-*` features and `monitor-tracing` change what is compiled; the other features (`mlock`, `zeroize`, `codex*`, `decoy-*`, `fragment-*`, `monitor`, `audit`, `tee-detect`, `post-quantum`, `preset-*`) are reserved and have **no effect in 1.0.x**. Decoys and the codex are enabled on the builder.

**Full details:** see [docs/SECURITY.md](docs/SECURITY.md) for each layer's limits.

**Walkthrough:** see [docs/TRANSFORMATION.md](docs/TRANSFORMATION.md) for what happens to a key between `register` and `with_key`.

<br>

### Performance targets (1.0 design — verified in 0.10.0)

Measured numbers from the reference machine (see [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for methodology and the full result tables):

| Target | Measured | Status |
|--------|----------|--------|
| Vault construction (empty) | ~165 ns | ✅ |
| `with_key` defrag, no codex, 16/32/64/256 B | 31 / 39 / 51 / 147 ns | ✅ all under 500 ns |
| `with_key` defrag, with codex, 16/32/64/256 B | 48 / 72 / 126 / 439 ns | ✅ all under 1 µs |
| Concurrent reads, 1 → 64 threads | scales out, no contention | ✅ lock-free |
| Memory overhead per key (Linux 1000-key RSS) | ~5 KiB | ✅ under 16 KiB |
| Allocations per `with_key` (default `NoAudit`) | **0** (dhat-measured over 100k iterations) | ✅ zero-alloc hot path |

Run `cargo bench --all-features` to reproduce on your hardware.


<br>


## Quick start

```toml
[dependencies]
key-vault = "1.0"
```

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy};

// Page locking, zero-on-drop and fragmentation are always on. Decoys and
// the codex are opt-in obfuscation and only apply when set here.
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true) // default: store BLAKE3(key), 32 bytes
    .with_codex(DynamicCodex::new().expect("codex"))
    .with_decoy(SelfReferenceDecoy)
    .build();

// Register a key and keep only the opaque handle.
let handle = vault
    .register("db-key", RawKey::new(b"my application key".to_vec()))
    .expect("register");

// Use the key inside a scoped callback. The slice is valid only for the
// call; the buffer behind it is zeroed when the callback returns.
let len = vault.with_key(handle, |key| key.len()).expect("with_key");
assert_eq!(len, 32); // normalized: BLAKE3 digest of the input
```

<hr>


## Threat model

key-vault helps against:

- **Keys written to swap**: buffers are page-locked (best effort).
- **Keys left in freed memory**: every buffer the crate owns is zeroized before it is freed.
- **Accidental exposure**: redacted `Debug` output, sanitized errors, opaque handles, scoped access instead of long-lived byte copies.
- **Generic memory scans and heap-dump tooling** that look for a contiguous key, a known key format, or a key-like region: fragmentation, normalization, and the opt-in decoys and codex make this harder. This is obfuscation.

key-vault does **NOT** protect against:

- **Anyone who can read the process's memory**: a debugger, a same-user process with `ptrace` / `ReadProcessMemory`, a full core or crash dump, malware in the process, the kernel. The fragments, the layout map (which also marks the decoys) and the codex table are all in the same address space, so such an attacker can rebuild every key.
- **Code running in your process**, which can call `with_key` like you do.
- **Offline guessing of weak keys**: normalization and the master-key digest are fast, unsalted BLAKE3. Feed the vault high-entropy keys, or run passphrases through a slow KDF first.
- **Hardware attacks** (DMA, cold boot) and **side channels in the crypto code** that uses the key.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Documentation

- **[docs/API.md](docs/API.md)** — Full public-API reference (every type, function, and method with examples)
- **[docs/SECURITY.md](docs/SECURITY.md)** — Threat model and per-layer limits
- **[docs/TRANSFORMATION.md](docs/TRANSFORMATION.md)** — Walkthrough of how a key is stored and read back
- **[docs/release/](docs/release/)** — Per-version release notes
- **[CHANGELOG.md](CHANGELOG.md)** — Full change log (Keep a Changelog format)

---

## Standards

- **REPS** (Rust Efficiency & Performance Standards) governs every decision. See [REPS.md](REPS.md).
- **MSRV:** Rust 1.85.
- **Edition:** 2024.
- **Cross-platform:** Linux, macOS, Windows.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.



<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>