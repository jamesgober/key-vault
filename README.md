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


<hr>
<br>



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
use key_vault::tee::detect_tee_capabilities;

// Build a vault with the full default stack: Layer 2 (mlock/VirtualLock)
// + Layer 3 (StandardFragmenter) + Layer 4 (SelfReferenceDecoy — the
// strongest decoy) + Layer 5 (per-vault DynamicCodex involution)
// + Layer 6 (ConstantTimeEq) + Layer 7 (zero-on-drop).
let vault = KeyVaultBuilder::new()
    .normalize_with_blake3(true) // default
    .with_codex(DynamicCodex::new().expect("codex"))
    .with_decoy(SelfReferenceDecoy)
    .build();

// Hand the vault some key material and get back an opaque, scattered,
// mlock'd, zeroed-on-drop representation with decoy chunks mixed in.
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

<hr>


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

- **[docs/API.md](docs/API.md)** — Full public-API reference (every type, function, and method with examples)
- **[docs/SECURITY.md](docs/SECURITY.md)** — Comprehensive 9-layer security architecture
- **[docs/TRANSFORMATION.md](docs/TRANSFORMATION.md)** — Visual walkthrough of key transformation
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