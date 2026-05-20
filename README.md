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
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
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

## Current status

**`key-vault` is pre-1.0; the public API is not yet stable.** The 9-layer
architecture above is the **1.0 design target**. Each release lights up more
of it. The "Features" section below documents the 1.0 surface; the table here
records what is actually built today so you can match the README against the
shipped code.

| Component | Status as of 0.3.0 |
|-----------|--------------------|
| Public type system (`Error`, `Result`, `KeyHandle`, `KeyMetadata`, `RawKey`, `FetchContext`, `Fragments`) | shipped |
| Trait surfaces (`KeyFetch`, `FragmentStrategy`, `DecoyStrategy`, `Codex`, `SecurityMonitor`) | shipped |
| **Layer 2 — mlock / VirtualLock** (via internal `LockedBytes` wrapper) | **shipped** |
| **Layer 3 — `StandardFragmenter`** (variable chunks, shuffle, non-contiguous allocations) | **shipped** |
| Layer 5 — `IdentityCodex` + user-closure `FnCodex` | shipped |
| **Layer 6 — Constant-time `KeyHandle` equality** (via `subtle::ConstantTimeEq`) | **shipped** |
| **Layer 7 — Zero-on-drop** (every fragment + layout buffer + intermediate plaintext) | **shipped** |
| BLAKE3 key normalization (wired through `KeyVaultBuilder::normalize_with_blake3`) | **shipped** |
| TEE detection (`detect_tee_capabilities`) | shipped (real x86_64 + Apple SE + AWS Nitro probes) |
| `KeyVault::fragment` / `KeyVault::defragment` convenience methods | **shipped** |
| `KeyVaultBuilder::with_chunk_range` | **shipped** |
| Layer 3 — Interleaved/Random/Layered fragmenters | planned for 0.5.0 |
| Layer 4 — Decoy strategies | planned for 0.4.0 |
| Layer 5 — `StaticCodex` / `DynamicCodex` | planned for 0.6.0 |
| Layer 1 — built-in fetchers (Keychain, File, Env, TPM) | planned for 0.7.0 |
| Layer 8 — Monitor implementations | planned for 0.8.0 |
| Layer 9 — Audit logging | planned for 0.8.0 |
| Multi-key vaults, rotation, master recovery | planned for 0.9.0 |

Each phase's exit criteria, scope, and timeline are tracked in
[.dev/ROADMAP.md](.dev/ROADMAP.md).

---

## Features (the 1.0 design)

### Defense-in-depth memory protection (1.0 design)

- **Memory page locking** (mlock / VirtualLock) prevents key material from being swapped to disk
- **Fragment storage** splits keys into variable-sized chunks at non-contiguous addresses
- **Self-referential decoy bytes** statistically indistinguishable from real key material
- **Codex transformation** (opt-in) adds byte-level obfuscation
- **Zero-on-drop** via zeroize overwrites memory when keys leave scope
- **Constant-time comparisons** via subtle prevent timing attacks
- **No debug exposure** — `KeyHandle`'s `Debug` impl always prints `KeyHandle(<redacted>)` (shipped today)

### Pluggable key fetchers (1.0 design, `KeyFetch` trait shipped)

The `KeyFetch` trait is in place today. Built-in implementations arrive in 0.7.0:

- **TPM 2.0** hardware fetcher — detection-only in 1.0, full integration deferred to 1.x
- **OS Keychain** — macOS Keychain, Windows Credential Manager, Linux Secret Service
- **Encrypted file** with permission checks
- **Environment variables** for container deployments
- **Custom fetchers** via the trait — bring your own HSM, KMS client, or proprietary source

### Fragment strategies (1.0 design, `FragmentStrategy` trait shipped)

- **Standard** — variable chunks + Fisher-Yates shuffle, each chunk in its own mlock'd allocation — **shipped in 0.3.0**
- **Interleaved** — bytes interleaved with decoy at randomized strides — 0.5.0
- **Random** — non-contiguous fragments at randomized offsets — 0.5.0
- **Layered** — compose multiple strategies for stacked defense — 0.5.0
- **Custom** — implement the `FragmentStrategy` trait (available today)

### Decoy strategies (1.0 design, `DecoyStrategy` trait shipped)

- **Random** — raw RNG bytes (fastest, weakest) — 0.4.0
- **Self-Reference** — real key bytes used as filler (strongest, default) — 0.4.0
- **Key-Derived** — hash-derived bytes that match key entropy profile — 0.4.0

### Codex layer (Layer 5)

- **`IdentityCodex`** — no transformation (default, max performance) — **shipped**
- **`FnCodex`** — user-provided closure (involution-only) — **shipped**
- **`StaticCodex`** — build-time transformation table for private builds — 0.6.0
- **`DynamicCodex`** — per-vault randomized involution — 0.6.0

### Security monitoring (Layer 8, trait shipped)

- **Failed decryption detection** — N failures in M seconds triggers configurable response — 0.8.0
- **Anomalous access patterns** — detect sustained data exfiltration — 0.8.0
- **Threshold lockout** — lock vault after threshold breach — 0.8.0
- **Pluggable sinks** — log, metrics, webhook, custom — 0.8.0

### Operational features

- **Master key recovery** — fallback path for hardware failure — 0.9.0
- **Key rotation** — atomic swap to new key without dropping access — 0.9.0
- **Multiple keys per vault** — named keys with independent lifecycles — 0.9.0
- **TEE detection** — check for Intel SGX, Intel TDX, AMD SEV, AMD SEV-SNP, ARM TrustZone, Apple Secure Enclave, AWS Nitro — **shipped**
- **Key normalization** — BLAKE3 hash input to neutralize format-based pattern leaks — **shipped in 0.3.0**

### Performance targets (1.0 design — not yet measured)

- **Key acquisition** — sub-second from hardware, sub-millisecond from keychain
- **Key access** (defrag into temporary buffer) — sub-microsecond (~500ns including audit + monitor)
- **Concurrent access** — lock-free reads after vault initialization
- **Memory overhead** — < 16 KiB per key (including fragment + decoy overhead)
- **Zero allocations** on the hot path (after vault initialization)

> **Note on benchmark numbers:** detailed criterion-backed benchmark numbers will land with **v1.0.0** (Phase 0.10.0 in the roadmap). Until then, performance numbers are targets, not measurements.

---

## Quick start

```toml
[dependencies]
key-vault = "0.3"
```

```rust
use key_vault::{KeyVaultBuilder, RawKey};
use key_vault::tee::detect_tee_capabilities;

// Build a vault with the default Layer 2 + 3 + 6 + 7 stack
// (mlock / VirtualLock + StandardFragmenter + ConstantTimeEq + zero-on-drop).
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true) // default
    .build();

// Hand the vault some key material and get back an opaque, scattered,
// mlock'd, zeroed-on-drop representation.
let raw = RawKey::new(b"my application key".to_vec());
let frags = vault.fragment(&raw).expect("fragment");

// Reassemble when you need to use it. With BLAKE3 normalization on,
// the recovered bytes are the 32-byte hash of the input.
let recovered = vault.defragment(&frags).expect("defragment");
assert_eq!(recovered.len(), 32);

// Snapshot the host's TEE capabilities at startup:
let caps = detect_tee_capabilities();
println!("{caps}");
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