<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>key-vault</b>
    <br>
    <sub>
        <sup>ENTERPRISE-GRADE KEY MANAGEMENT VAULT</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/key-vault"><img src="https://img.shields.io/crates/v/key-vault.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/key-vault"><img alt="downloads" src="https://img.shields.io/crates/d/=%230099ff"></a>
    <a href="https://docs.rs/key-vault"><img src="https://docs.rs/key-vault/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml/badge.svg"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
    <b>Defense-in-depth in-memory key storage for Rust</b>
    <br>
    <i>Scattered storage with distortion patterns, mlock + zeroize, pluggable acquisition.</i>
</p>

<br>

<p>
    <strong>key-vault</strong> is an enterprise-grade key management vault built to keep cryptographic key material safe in memory while your application is running. Built from the ground up with a defense-in-depth philosophy, it combines memory page locking, scattered storage with self-referential distortion, zero-on-drop, and constant-time operations to make memory-resident keys hard to extract via memory analysis or scraping.
</p>

<p>
    Unlike libraries that hand you a `Vec<u8>` and trust you not to leak it, <strong>key-vault</strong> wraps key material in opaque `KeyHandle` references. The actual bytes never live contiguously in memory after the vault initializes; they're scattered across allocations with variable chunk sizes, randomized order, and filler bytes derived from the key itself. Reassembly happens only when explicitly requested, in protected scopes, and the temporary contiguous copy is immediately zeroized.
</p>

<p>
    <strong>key-vault</strong> ships with multiple distortion strategies (chunked shuffle, interleaved, fragmented, layered composition) and pluggable acquirers for fetching keys from hardware (TPM 2.0), OS keychains (macOS Keychain, Windows Credential Manager, Linux Secret Service), encrypted files, environment variables, or your own custom sources. Master key recovery is built in. Post-quantum safe symmetric defaults (256-bit minimum) future-proof you against the next decade of cryptographic landscape changes.
</p>

---

## Status

**Active development.** Scaffolded and on the path to 1.0. See [.dev/ROADMAP.md](.dev/ROADMAP.md) for milestone tracking.

The public API is not yet stable. Pin specific versions; expect changes pre-1.0.

---

## Features

### Defense-in-depth memory protection

- **Memory page locking** (`mlock` / `VirtualLock`) prevents key material from being swapped to disk
- **Scattered storage** splits keys into variable-sized chunks at non-contiguous addresses
- **Distortion patterns** use filler bytes derived from the key itself, defeating statistical entropy analysis
- **Randomized layout** — chunk sizes and counts vary per scatter, no detectable pattern
- **Zero-on-drop** via zeroize overwrites memory when keys leave scope
- **Constant-time comparisons** via subtle prevent timing attacks on key equality checks
- **No debug exposure** — KeyHandle Debug impl never reveals key bytes

### Pluggable key acquisition

- **TPM 2.0** hardware acquirer (Linux, Windows)
- **OS Keychain** (macOS Keychain, Windows Credential Manager, Linux Secret Service via keyring)
- **Encrypted file** with format-preserving file-system protection
- **Environment variables** for container deployments
- **Custom acquirers** via the KeyAcquirer trait — bring your own HSM, KMS client, or proprietary source

### Multiple scatter strategies

- **Standard** — chunked shuffle with filler bytes (the baseline)
- **Interleaved** — bytes interleaved with filler at fixed strides
- **Fragmented** — non-contiguous memory fragments at randomized offsets
- **Layered** — compose multiple strategies for stacked defense

Or define your own via the `ScatterStrategy` trait.

### Operational features

- **Master key recovery** — fallback path for hardware failure scenarios
- **Key rotation** — atomic swap to new key without dropping access
- **Multiple keys per vault** — named keys with independent lifecycles
- **Async-safe acquisition** — slow paths (hardware queries) don't block the runtime

### Performance targets

- **Key acquisition** — sub-second from hardware, sub-millisecond from keychain
- **Key access** (reassembly into temporary buffer) — sub-microsecond
- **Concurrent access** — lock-free reads after vault initialization
- **Memory overhead** — < 16 KiB per key (including scatter overhead)

> **Note on benchmark numbers:** detailed criterion-backed benchmark numbers will land with **v1.0.0**. Until then, performance claims should be treated as targets, not guarantees.

---

## Quick start

```toml
[dependencies]
key-vault = "0.1"
```

```rust
// Examples land as the public API stabilizes.
// See `examples/` and the rustdoc once 0.2 ships.
```

---

## Threat model

`key-vault` is designed to defend against:

- **Memory scraping by attackers with read access** — malware that walks process memory looking for high-entropy regions
- **Forensic memory analysis** — post-mortem analysis of swap files, hibernation files, crash dumps
- **Statistical pattern recognition** — entropy analysis, frequency analysis on memory regions
- **Use-after-free leakage** — keys persisting in memory after they should have been wiped

It does NOT defend against:

- **Code execution within your process** — an attacker who can execute Rust code in your process can call the reassembly logic and read the key
- **Hardware compromise** — if you need protection against this, use TPM/HSM/TEE features (which `key-vault` supports as acquirers)
- **Side-channel attacks on cryptographic operations** — that's the crypto library's job (see `crypt-io`)
- **Compromise of the master key itself** — the master key is the root of trust; protect it accordingly

---

## Standards

- **REPS** (Rust Efficiency & Performance Standards) governs every decision. See [REPS.md](REPS.md).
- **MSRV:** Rust 1.75.
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

---

<sub>Copyright &copy; 2026 <strong>James Gober</strong>. All rights reserved.</sub>