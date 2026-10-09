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
    <i>mlock + dump exclusion + zeroize + opaque handles + scoped access, with optional page protection, lockout, fragmentation, decoy and codex obfuscation, and audit hooks. Works in no_std.</i>
</p>

<br>

<p>
    <strong>key-vault</strong> keeps cryptographic key material in process memory while your application runs. Keys live in page-locked (<code>mlock</code> / <code>VirtualLock</code>), dump-excluded, zero-on-drop buffers. Callers get an opaque <code>KeyHandle</code> instead of a <code>Vec&lt;u8&gt;</code>, and the bytes are handed out only inside a scoped callback, from a buffer that is wiped when the callback returns. Optionally each key lives in its own page-protected mapping that is inaccessible except while it is being read.
</p>

<p>
    On top of that the vault splits each key into small shuffled fragments and can mix in decoy chunks and pass bytes through a codex. <b>These are obfuscation, not protection against a memory reader:</b> the layout map that reassembles the fragments and the codex table are stored in the same process memory, so anyone who can read that memory can rebuild every key. They make life harder for generic memory scans and heap-dump tooling; see the <a href="#threat-model">threat model</a>.
</p>

<p>
    Also included: atomic key rotation, named multi-key vaults, pluggable <b>key fetchers</b> (OS keychain, plaintext file, environment variable), caller-driven failure monitoring with optional per-key and vault-wide lockout, master-key unlock with backoff, keyed normalization, audit hooks, informational TEE detection, and <code>no_std</code> + <code>alloc</code> support.
</p>


<hr>
<br>



## Layers

What each layer does in 1.1, plainly:

| Layer | What it is | Status in 1.1 | Protects against | Does NOT protect against |
|-------|-----------|---------------|------------------|--------------------------|
| **1** | Key acquisition (`KeyFetch`) | OS keychain, plaintext file, env var. **`TpmFetch` is not implemented** (always errors) | Hardcoded keys | Anything once the key is in memory |
| **2** | Page locking + dump exclusion | On, best effort, per-page reference counted. Dump exclusion on Linux, Android, FreeBSD and Windows (WER) | Keys written to swap; keys in core / WER crash dumps | Memory readers; dumps taken by debuggers; macOS core dumps |
| **3** | Fragmentation | `StandardFragmenter` by default; any strategy with `with_fragmenter` | Scans for a contiguous key | Memory readers: the layout map is in the same memory |
| **4** | Decoy chunks | **Off** unless `with_decoy` is called | Statistical scans for key-like regions | Memory readers: the layout map marks every decoy |
| **5** | Codex (byte substitution table) | **Off** unless `with_codex` is called | Scans for the raw key bytes | Memory readers: the table is in the same memory. Not encryption |
| **6** | Constant-time comparison | Master-key check, handle equality | Timing on the master check | Timing of key lookup and reassembly (not constant-time) |
| **7** | Zero-on-drop (`zeroize`) | Every secret-bearing buffer the crate owns | Keys left in freed memory | Copies made by `std`, the OS or your own callback |
| **8** | Monitor, lockout, backoff | **Advisory**: counts only failures you report. Vault-wide and per-key lockout, master-unlock backoff, all opt-in | Repeated failures you report; master guessing through the API | Memory readers; it never sees decryption failures itself |
| **9** | Audit hooks | One event per vault operation | Unnoticed API-level use | Tampering with your sink; reads below the API |
| **10** | Page protection (`PROT_NONE` / `PAGE_NOACCESS`) | **Opt-in**: `with_page_protection(true)` | Stray reads from inside the process between accesses | Kernel / debugger readers; the scratch copy while your callback runs |

Cargo features never change what `KeyVaultBuilder::new()` builds. The `fragment-*`, `decoy-*`, `codex*`, `monitor`, `audit` and `preset-*` features choose what `KeyVaultBuilder::from_features()` configures; `mlock`, `zeroize`, `tee-detect` and `post-quantum` are deprecated no-ops, because page locking and zeroization cannot be turned off.

**Full details:** see [docs/SECURITY.md](docs/SECURITY.md) for each layer's limits.

**Walkthrough:** see [docs/TRANSFORMATION.md](docs/TRANSFORMATION.md) for what happens to a key between `register` and `with_key`.

<br>

### Performance targets (1.0 design, re-measured for 1.1)

Measured on Linux (see [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for methodology and the full result tables, including the 1.0.2 comparison):

| Target | Measured (1.1.0) | Status |
|--------|------------------|--------|
| Vault construction (empty) | ~120 ns | ✅ |
| `with_key` defrag, no codex, 16/32/64/256 B | 34 / 41 / 55 / 157 ns | ✅ all under 500 ns |
| `with_key` defrag, with codex, 32/256 B | 67 / 432 ns | ✅ all under 1 µs |
| `register` 16 / 256 B | 1.0 / 16 µs (1.0.2: 5.4 / 100 µs) | ✅ |
| Concurrent reads, 1 → 64 threads | scales out, no contention | ✅ lock-free |
| Allocations per `with_key` (default `NoAudit`) | **0** (dhat-measured over 100k iterations) | ✅ zero-alloc hot path |
| `with_key` with page protection (opt-in) | ~1.4-1.6 µs | two `mprotect` calls per read |

Run `cargo bench --all-features` to reproduce on your hardware.


<br>


## Quick start

```toml
[dependencies]
key-vault = "1.1"
```

```rust
use key_vault::{DynamicCodex, KeyVaultBuilder, RawKey, SelfReferenceDecoy};

// Page locking, dump exclusion, zero-on-drop and fragmentation are always
// on. Decoys and the codex are opt-in obfuscation and only apply when set
// here.
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

### Opt-in protections

```rust
use std::time::Duration;
use key_vault::{KeyVaultBuilder, RawKey};

let vault = KeyVaultBuilder::new()
    // Each key in its own mapping, inaccessible except while it is read.
    .with_page_protection(true)
    // Five reported failures in a minute lock that key (only) for 5 minutes.
    .with_key_lockout(5, Duration::from_secs(60), Some(Duration::from_secs(300)))
    // Emergency unlock, rate limited: 1 s after a failure, doubling to 1 min.
    .with_master_key(RawKey::new(b"a long random master credential".to_vec()))
    .with_master_unlock_backoff(Duration::from_secs(1), Duration::from_secs(60))
    .build();
```

`with_keyed_normalization()` / `with_normalization_key(..)` store a keyed BLAKE3 output instead of plain BLAKE3, so a copy of the stored value cannot be used to guess the input offline. Read [docs/SECURITY.md](docs/SECURITY.md#key-normalization-blake3) before using the random-key mode: it changes the effective key every run.

### `no_std`

```toml
[dependencies]
key-vault = { version = "1.1", default-features = false }
```

Without `std` the crate needs only `alloc`. Build the vault with `build_with_clock(your_clock)` (there is no `build()`, so a missing clock is a compile error), and on targets without a `getrandom` backend register your hardware RNG with `key_vault::register_rng!(fill_fn)` (linking fails without one). The fetchers, `monitor-tracing` and TEE detection need `std`. On bare metal there is no swap or core dump, so page locking and dump exclusion do not apply. CI builds for `thumbv7em-none-eabihf`.

<hr>


## Threat model

key-vault helps against:

- **Keys written to swap**: buffers are page-locked (best effort).
- **Keys in crash and core dumps**: key pages are excluded on Linux, Android, FreeBSD and from Windows Error Reporting dumps. Not on macOS, and not from dumps a debugger takes.
- **Keys left in freed memory**: every buffer the crate owns is zeroized before it is freed.
- **Stray reads inside the process** (opt-in page protection): key pages fault unless they are being read.
- **Accidental exposure**: redacted `Debug` output, sanitized errors, opaque handles, scoped access instead of long-lived byte copies.
- **Guessing through the API** (opt-in): per-key and vault-wide lockout for failures you report, backoff on master unlock.
- **Generic memory scans and heap-dump tooling** that look for a contiguous key, a known key format, or a key-like region: fragmentation, normalization, and the opt-in decoys and codex make this harder. This is obfuscation.

key-vault does **NOT** protect against:

- **Anyone who can read the process's memory through the kernel or a debugger**: a same-user process with `ptrace` / `ReadProcessMemory`, `/proc/<pid>/mem`, a full-memory dump taken by such a tool, malware in the process, the kernel. The fragments, the layout map (which also marks the decoys) and the codex table are all in the same address space, so such an attacker can rebuild every key. Page protection does not stop them.
- **Code running in your process**, which can call `with_key` like you do.
- **Offline guessing of weak keys** with the default plain BLAKE3 normalization. Feed the vault high-entropy keys, use keyed normalization, or run passphrases through a slow KDF first.
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
- **Cross-platform:** Linux, macOS, Windows; `no_std` + `alloc` (CI builds `thumbv7em-none-eabihf`).

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