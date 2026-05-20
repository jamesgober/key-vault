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
    <a href="https://crates.io/crates/key-vault"><img alt="downloads" src="https://img.shields.io/crates/d/key-vault?color=%230099ff"></a>
    <a href="https://docs.rs/key-vault"><img src="https://docs.rs/key-vault/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/key-vault/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.75%2B-blue"></a>
</p>

<p align="center">
    <b>9-Layer Defense-in-Depth In-Memory Key Storage for Rust</b>
    <br>
    <i>Fragmentation + decoy bytes + codex transform + mlock + zeroize + constant-time + monitoring + audit + page protection.</i>
</p>

<br>

<p>
    <strong>key-vault</strong> is an enterprise-grade key management vault built to keep cryptographic key material safe in memory while your application is running. Built from the ground up with a <b>9-layer defense-in-depth philosophy</b>, it combines hardware-rooted acquisition, memory page locking, fragmentation with self-referential decoy bytes, codex transformation, zero-on-drop, constant-time operations, security event monitoring, and audit logging to make memory-resident keys hard to extract via memory analysis, scraping, or forensic recovery.
</p>

<p>
    Unlike libraries that hand you a <code>Vec&lt;u8&gt;</code> and trust you not to leak it, <strong>key-vault</strong> wraps key material in opaque <code>KeyHandle</code> references. The actual bytes never live contiguously in memory after the vault initializes; they're split into variable-size fragments scattered across non-contiguous mlock'd allocations, interleaved with self-referential decoy bytes that statistically match the key's entropy profile, optionally transformed through a codex layer, and reassembled only when explicitly requested in protected scopes. The temporary contiguous copy auto-zeroizes when dropped.
</p>

<p>
    <strong>key-vault</strong> ships with multiple <b>fragment strategies</b> (standard, interleaved, random, layered composition), <b>decoy strategies</b> (random, self-referential, key-derived), pluggable <b>key fetchers</b> (TPM 2.0 hardware, OS keychains, encrypted files, environment variables), and an <b>extensible security monitor</b> for failure detection and anomaly alerting. Master key recovery, atomic key rotation, multi-key vaults, and <b>TEE detection</b> are built in. <b>Post-quantum</b> safe symmetric defaults (256-bit minimum) future-proof you against the next decade of cryptographic landscape changes.
</p>

---

## 9-Layer Defense Architecture

The complete defense stack:

| Layer | Defense | Defends Against |
|-------|---------|-----------------|
| **1** | **Secure Acquisition** (TPM, Keychain, etc.) | Untrusted key sources |
| **2** | **Memory Page Locking** (mlock / VirtualLock) | Swap files, hibernation |
| **3** | **Fragment Strategy** (variable chunks, shuffle) | Pattern recognition, memory scraping |
| **4** | **Decoy Bytes** (self-referential filler) | Entropy/frequency analysis |
| **5** | **Codex Transformation** (byte swap) | Memory dump analysis |
| **6** | **Constant-Time Operations** | Timing side-channels |
| **7** | **Zero-On-Drop** | Use-after-free leakage |
| **8** | **Security Monitor** (failure detection) | Brute-force, anomalous access |
| **9** | **Audit Logging** | Forensic trail, compliance |
| **10** | (Bonus) Page Protection Toggling | Snapshot attacks |

**Full details:** see [docs/SECURITY.md](docs/SECURITY.md) for the comprehensive security architecture.

**Visual walkthrough:** see [docs/TRANSFORMATION.md](docs/TRANSFORMATION.md) for a step-by-step trace of what happens to a key as it passes through all the layers.

---

## Features

### Defense-in-depth memory protection

- **Memory page locking** (mlock / VirtualLock) prevents key material from being swapped to disk
- **Fragment storage** splits keys into variable-sized chunks at non-contiguous addresses
- **Self-referential decoy bytes** statistically indistinguishable from real key material
- **Codex transformation** (opt-in) adds byte-level obfuscation
- **Zero-on-drop** via zeroize overwrites memory when keys leave scope
- **Constant-time comparisons** via subtle prevent timing attacks
- **No debug exposure** — KeyHandle::Debug never reveals key bytes

### Pluggable key fetchers (KeyFetch trait)

- **TPM 2.0** hardware fetcher (Linux, Windows)
- **OS Keychain** (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Encrypted file** with format-preserving file-system protection
- **Environment variables** for container deployments
- **Custom fetchers** via the trait — bring your own HSM, KMS client, or proprietary source

### Multiple fragment strategies

- **Standard** — variable chunks + self-referential decoy (the baseline)
- **Interleaved** — bytes interleaved with decoy at randomized strides
- **Random** — non-contiguous fragments at randomized offsets
- **Layered** — compose multiple strategies for stacked defense
- **Custom** — implement the FragmentStrategy trait

### Decoy strategies

- **Random** — raw RNG bytes (fastest, weakest)
- **Self-Reference** — real key bytes used as filler (strongest, default)
- **Key-Derived** — hash-derived bytes that match key entropy profile

### Codex layer (Layer 5)

- **Static Codex** — build-time transformation table for private builds
- **Dynamic Codex** — per-vault randomized involution
- **Function Codex** — user-provided closure
- **Identity Codex** — no transformation (default, max performance)

### Security monitoring (Layer 8)

- **Failed decryption detection** — N failures in M seconds triggers configurable response
- **Anomalous access patterns** — detect sustained data exfiltration
- **Threshold lockout** — lock vault after threshold breach
- **Pluggable sinks** — log, metrics, webhook, custom

### Operational features

- **Master key recovery** — fallback path for hardware failure
- **Key rotation** — atomic swap to new key without dropping access
- **Multiple keys per vault** — named keys with independent lifecycles
- **TEE detection** — check for Intel SGX, AMD SEV, ARM TrustZone, Apple Secure Enclave, AWS Nitro
- **Key normalization** — BLAKE3 hash input to neutralize format-based pattern leaks

### Performance targets

- **Key acquisition** — sub-second from hardware, sub-millisecond from keychain
- **Key access** (defrag into temporary buffer) — sub-microsecond (~500ns including audit + monitor)
- **Concurrent access** — lock-free reads after vault initialization
- **Memory overhead** — < 16 KiB per key (including fragment + decoy overhead)
- **Zero allocations** on the hot path (after vault initialization)

> **Note on benchmark numbers:** detailed criterion-backed benchmark numbers will land with **v1.0.0**. Until then, performance claims should be treated as targets, not guarantees.

---

## Quick start

```toml
[dependencies]
key-vault = "0.1"
```


```rust
// Examples land as the public API stabilizes.
// See examples/ and the rustdoc once 0.2 ships.
```

---

## Threat model

key-vault is designed to defend against:

- **Memory scraping by attackers with read access** — malware, forensic tools
- **Forensic memory analysis** — swap files, hibernation files, crash dumps
- **Statistical pattern recognition** — entropy analysis, frequency analysis
- **Use-after-free leakage** — keys persisting after they should have been wiped
- **Brute-force decryption attempts** — failed attempts trigger alerts
- **Timing side-channels** — constant-time operations
- **Insider threats / forensic compliance** — full audit trail

It does NOT defend against:

- **Code execution within your process** — an attacker who can call your reassembly logic
- **Hardware-level memory access (DMA attacks)** — use IOMMU + hardware mitigations
- **Cold-boot attacks** — use full disk encryption + power-down protocol
- **Side-channel attacks on cryptographic operations** — that's crypt-io's job
- **Quantum computer attacks on asymmetric crypto** — use post-quantum algorithms (symmetric defaults are PQ-safe)

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model.

---

## Documentation

- **[docs/SECURITY.md](docs/SECURITY.md)** — Comprehensive 9-layer security architecture
- **[docs/TRANSFORMATION.md](docs/TRANSFORMATION.md)** — Visual walkthrough of key transformation
- **[.dev/ROADMAP.md](.dev/ROADMAP.md)** — Production roadmap to 1.0
- **[.dev/DIRECTIVES.md](.dev/DIRECTIVES.md)** — Engineering directives

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



<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>