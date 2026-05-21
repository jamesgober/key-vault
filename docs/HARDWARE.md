<h1 align="center">
    <b>key-vault — Hardware Integration</b>
    <br>
    <sub><sup>TPM · HSM · SECURE ENCLAVES · NITRO</sup></sub>
</h1>

<p align="center">
    <i>What the 1.0 release supports today, and the roadmap for full hardware-backed key acquisition.</i>
</p>

---

## Status at 1.0

| Hardware surface | 1.0 status | Notes |
|------------------|------------|-------|
| Intel SGX / TDX | Detection only | Reported by `tee::detect_tee_capabilities()` |
| AMD SEV / SEV-SNP | Detection only | Reported by `tee::detect_tee_capabilities()` |
| ARM TrustZone | Detection reports `Unknown` | Userspace cannot reliably probe TrustZone availability |
| Apple Secure Enclave | Detection only | `Detected` on Apple Silicon |
| AWS Nitro Enclaves | Detection only | Linux `/sys/devices/virtual/dmi/id/sys_vendor` check |
| TPM 2.0 | Detection only via `TpmFetch` | The fetcher returns `Error::Acquisition("detection-only")` on a `fetch` call |
| Generic HSM (PKCS#11 / KMIP) | Not present | Use a custom `KeyFetch` implementation |

The 1.0 contract for hardware is **detection, not acquisition**. The
`KeyFetch` trait is the extension point — any caller can implement
acquisition from a specific HSM or TEE today; the in-tree built-ins
expose the detection result so application code can branch on it.

---

## Why detection ships and acquisition doesn't

Three reasons hardware acquisition is post-1.0:

1. **API surface stability.** A serious HSM / TPM integration carries
   policy decisions (PCR binding, sealing under measurement, recovery
   under key migration) that downstream consumers will want to
   configure. Freezing a half-baked acquisition surface in 1.0 would
   force breaking changes later.
2. **Test infrastructure.** TPM 2.0 simulators, AWS Nitro local
   emulators, and Secure Enclave entitlements all require infrastructure
   that doesn't fit a single-machine CI matrix. The 0.11 fuzz harness
   exercises the *software* defense layers; hardware acquisition needs
   its own test rig.
3. **Crate dependency cost.** Pulling in `tss-esapi` (TPM),
   `aws-nitro-enclaves-attestation`, or platform-specific SE bindings
   would significantly expand the dependency tree. REPS forbids
   unjustified dependency accumulation; we wait until the integration
   is real before adding the dep.

---

## How to use detection today

```rust
use key_vault::tee::detect_tee_capabilities;

let caps = detect_tee_capabilities();
println!("{caps}");

if caps.sgx.is_detected() {
    // Caller's responsibility to use SGX-aware acquisition here.
    // key-vault detection only — full SGX integration is post-1.0.
}
```

Pattern for downstream applications that *do* have a hardware-backed
key path:

```rust
use key_vault::{KeyFetch, FetchContext, RawKey, Error, Result};

struct MyTpmFetcher;
impl KeyFetch for MyTpmFetcher {
    fn fetch(&self, _: &FetchContext) -> Result<RawKey> {
        // your acquisition logic — TPM unseal, HSM PKCS#11 unwrap,
        // KMIP fetch, etc. — produces the bytes.
        let bytes: Vec<u8> = todo!("acquire from hardware");
        Ok(RawKey::new(bytes))
    }
}
```

The custom fetcher then plugs into the vault the same way the in-tree
ones do:

```rust
use key_vault::{KeyVaultBuilder, FetchContext};

let fetcher = MyTpmFetcher;
let raw = fetcher.fetch(&FetchContext::new("session")).unwrap();
let vault = KeyVaultBuilder::new().build();
let handle = vault.register("session", raw).unwrap();
```

---

## Post-1.0 hardware roadmap

These are explicitly **out of scope for 1.0** but tracked in
`.dev/ROADMAP.md` for future minor releases.

### Phase 1.1 — TPM 2.0 first integration

- TPM-backed sealing via `tss-esapi`. The vault would accept a TPM
  handle + PCR policy at registration and unseal during `with_key`.
- PCR-binding so that the key is only available when the boot
  measurement matches.
- Hardware key migration via `TPM2_Duplicate` for backup paths.
- Cross-platform: Linux (Intel PTT / dedicated TPM), Windows (TPM
  Base Services).

### Phase 1.2 — Cloud KMS fetchers

- `AwsKmsFetch`: KMS `Decrypt` against a CMK, returns the plaintext
  data key.
- `GcpKmsFetch`: KMS `Decrypt` against a KEK.
- `AzureKeyVaultFetch`: Azure Key Vault `unwrapKey` operation.
- `HashicorpVaultFetch`: Transit engine `decrypt` operation.

All four would be feature-gated (`fetcher-aws-kms`, `fetcher-gcp-kms`,
…) so consumers only pay the dependency cost for the cloud they use.

### Phase 1.3 — Apple Secure Enclave / AWS Nitro full integration

- Apple SE: SecKeychain + LAContext biometric gate, sealed envelope
  storage under hardware-backed key.
- AWS Nitro: full attestation flow, KMS proxy integration via
  vsock.

### Out of scope forever

- `unsafe`-heavy TEE driver integration (e.g., raw SGX EPID
  attestation flows). Use a higher-level crate (e.g.,
  `enarx-shim-sgx`) and plug it in via `KeyFetch`.
- Vendor-specific PKCS#11 driver bindings. PKCS#11 is the standard;
  vendor extensions live in vendor crates.

---

## Hardware-adjacent guarantees the 1.0 release does provide

Even without full hardware acquisition, key-vault's software defenses
give hardware-backed callers real guarantees:

- **Page locking** keeps the unsealed key bytes out of swap
  (Layer 2, verified by `tests/mlock_verified.rs` on Linux).
- **Zero-on-drop** scrubs the bytes when the temporary `RawKey`
  exits scope (Layer 7, applied to every defragment buffer + the
  caller-owned `RawKey` returned by a custom `KeyFetch`).
- **Constant-time handle equality** keeps `KeyHandle` comparisons
  side-channel-safe (Layer 6, `subtle::ConstantTimeEq`).
- **Audit trail** records every register / read / rotate event for
  forensic correlation against hardware audit logs (Layer 9).

A typical hardware-backed deployment pattern:

```
┌───────────────────────────────┐
│  Application                  │
│  ┌─────────────────────────┐  │
│  │  custom KeyFetch impl    │  │  ← TPM / HSM / SE / KMS unseal
│  │  returns RawKey          │  │
│  └─────────────────────────┘  │
│             │                  │
│             ▼                  │
│  ┌─────────────────────────┐  │
│  │  KeyVault                │  │  ← page-lock + fragment + audit
│  │   (key-vault crate)      │  │
│  └─────────────────────────┘  │
└───────────────────────────────┘
```

The hardware lives outside the vault; key-vault is the runtime
protection layer that takes care of the bytes once they're in
memory.

---

<sub>key-vault Hardware Integration — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
