//! # key-vault
//!
//! In-memory key storage for Rust applications.
//!
//! `key-vault` keeps key material in page-locked, dump-excluded,
//! zero-on-drop buffers, hands out opaque [`KeyHandle`]s instead of byte
//! slices, gives the bytes back only inside a scoped callback
//! ([`KeyVault::with_key`]), and supports atomic rotation, per-key and
//! vault-wide lockout, master-unlock backoff, and audit hooks. Keys can
//! optionally live in page-protected mappings that are inaccessible
//! between reads. On top of that it can split keys into shuffled
//! fragments, mix in decoy chunks and pass bytes through a codex. Those
//! three are obfuscation, not encryption: see the threat model below.
//!
//! # Threat model
//!
//! **What it helps with**
//!
//! - Keys written to swap: buffers are `mlock`'d / `VirtualLock`'d
//!   (best effort; check `RLIMIT_MEMLOCK`).
//! - Keys in crash and core dumps: key pages are excluded with
//!   `MADV_DONTDUMP` on Linux and Android, `MADV_NOCORE` on FreeBSD, and
//!   from Windows Error Reporting dumps on Windows. macOS has no
//!   equivalent. Dumps taken by a debugger or another tool are not
//!   covered.
//! - Keys lingering in freed memory: every buffer the crate owns is
//!   zeroized before it is freed.
//! - Stray reads inside the process (with
//!   `KeyVaultBuilder::with_page_protection`): key pages are
//!   `PROT_NONE` / `PAGE_NOACCESS` except while being read.
//! - Accidental exposure through logs, `Debug` output, error messages and
//!   long-lived `Vec<u8>` copies in application code.
//! - Repeated failures you report, and guessing of the master credential
//!   through the API (per-key lockout, master-unlock backoff).
//! - Casual memory scans and heap dumps that search for a key as a
//!   contiguous run of bytes or for known key formats. Fragmentation,
//!   decoys and the codex make that harder.
//!
//! **What it does not protect against**
//!
//! - **Anyone who can read the process's memory** through the kernel or a
//!   debugger (`ptrace`, `ReadProcessMemory`, `/proc/<pid>/mem`, a full
//!   memory dump taken by such a tool, malware in the process, the
//!   kernel). The fragments, the layout map that says how to reassemble
//!   them and which chunks are decoys, and the codex table all live in
//!   the same process. An attacker with that access can rebuild every key;
//!   page protection does not stop it either, because such readers ignore
//!   or can change page permissions.
//! - Code running inside the process, which can simply call
//!   [`KeyVault::with_key`].
//! - Hardware attacks (DMA, cold boot) and side channels in the
//!   cryptographic code that uses the key.
//!
//! See `docs/SECURITY.md` for the per-layer details.
//!
//! # Layers
//!
//! 1. **Key acquisition** ([`KeyFetch`]): keychain, plaintext file and
//!    environment-variable fetchers (`std` only). Fetchers add no
//!    in-memory protection. `TpmFetch` is not implemented and always
//!    returns an error.
//! 2. **Page locking and dump exclusion**: best effort, with per-page
//!    reference counting so one buffer's drop never releases a page
//!    another live buffer uses.
//! 3. **Fragmentation** ([`FragmentStrategy`]): obfuscation.
//!    [`StandardFragmenter`] by default; any strategy through
//!    [`KeyVaultBuilder::with_fragmenter`].
//! 4. **Decoy chunks** ([`DecoyStrategy`]): obfuscation. Off unless set
//!    with [`KeyVaultBuilder::with_decoy`].
//! 5. **Codex** ([`Codex`]): obfuscation, a byte substitution whose table is
//!    stored next to the data. Off unless set with
//!    [`KeyVaultBuilder::with_codex`].
//! 6. **Constant-time comparison** (`subtle`): used for the master-key
//!    check and handle equality. Defragmentation itself is not
//!    constant-time.
//! 7. **Zero-on-drop** (`zeroize`): every secret-bearing buffer the crate
//!    allocates. Copies made inside `std`, the OS or your own callback are
//!    not covered.
//! 8. **Failure monitor and lockout** ([`SecurityMonitor`]): advisory. The
//!    vault only counts failures the caller reports. Lockout can be
//!    vault-wide ([`KeyVaultBuilder::with_failure_threshold`]) or per key
//!    ([`KeyVaultBuilder::with_key_lockout`]); master unlock can be
//!    rate-limited ([`KeyVaultBuilder::with_master_unlock_backoff`]).
//! 9. **Audit hooks** ([`AuditSink`]): one event per vault operation.
//! 10. **Page protection** (opt-in,
//!     `KeyVaultBuilder::with_page_protection`): each key in its own
//!     mapping, `PROT_NONE` / `PAGE_NOACCESS` between reads.
//!
//! # Cargo features
//!
//! `std` (default) builds the full crate. The `fetcher-*` features add
//! fetchers and `monitor-tracing` adds `LogMonitor` / `LogAudit`. The
//! `fragment-*`, `decoy-*`, `codex*`, `monitor`, `audit` and `preset-*`
//! features choose what [`KeyVaultBuilder::from_features`] configures;
//! they never change [`KeyVaultBuilder::new`]. `mlock`, `zeroize`,
//! `tee-detect` and `post-quantum` are deprecated no-ops: page locking and
//! zeroization are always on. See `docs/API.md` for the full table.
//!
//! See `docs/TRANSFORMATION.md` for a walkthrough of what happens to a
//! key as it is stored.
//!
//! # `no_std`
//!
//! With `default-features = false` (and without `std`) the crate is
//! `#![no_std]` and needs only `alloc`. The core vault works: registry,
//! fragmentation, decoys, codex, normalization, zeroization, lockout,
//! backoff and audit hooks. Differences:
//!
//! - Build the vault with [`KeyVaultBuilder::build_with_clock`] and your own
//!   [`Clock`]; `build` does not exist without `std`, so a missing clock is
//!   a compile error.
//! - Randomness comes from `getrandom`. On targets it has no backend for
//!   (bare metal), register a source with [`register_rng!`]; without one,
//!   linking fails.
//! - Fetchers, `monitor-tracing` and TEE detection need `std`.
//!   [`AuditEvent`] has no `thread_id`.
//! - On bare metal there is no swap and no core dump, so page locking and
//!   dump exclusion do not apply and page protection is not available. On
//!   a hosted Unix or Windows target they keep working without `std`.
//!
//! # License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

#![cfg_attr(not(feature = "std"), no_std)]
#![doc(html_root_url = "https://docs.rs/key-vault")]
#![cfg_attr(docsrs, feature(doc_cfg))]
// REPS §Code Quality canonical lint set. `#![deny(warnings)]` is
// intentionally NOT used at the crate root — new rustc versions can
// introduce lints that retroactively break downstream builds of a
// published crate. CI carries `RUSTFLAGS="-D warnings"` instead so the
// gate is enforced where the lint surface is pinned to the toolchain
// matrix.
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

pub mod audit;
pub mod clock;
pub mod codex;
pub mod decoy;
mod error;
pub mod fetcher;
pub mod fragment;
mod handle;
mod memory;
mod metadata;
pub mod monitor;
mod normalize;
mod rng;
mod sync;
#[cfg(feature = "std")]
pub mod tee;
#[cfg(test)]
mod test_util;
mod vault;

#[doc(hidden)]
pub use crate::rng::__private;

#[cfg(feature = "monitor-tracing")]
pub use crate::audit::LogAudit;
pub use crate::audit::{AccessKind, AuditEvent, AuditSink, NoAudit};
pub use crate::clock::Clock;
#[cfg(feature = "std")]
pub use crate::clock::StdClock;
pub use crate::codex::{Codex, DynamicCodex, IdentityCodex, StaticCodex};
pub use crate::decoy::{DecoyStrategy, KeyDerivedDecoy, RandomDecoy, SelfReferenceDecoy};
pub use crate::error::{Error, Result};
#[cfg(feature = "fetcher-env")]
pub use crate::fetcher::EnvFetch;
#[cfg(feature = "fetcher-file")]
pub use crate::fetcher::FileFetch;
#[cfg(feature = "fetcher-keychain")]
pub use crate::fetcher::KeychainFetch;
#[cfg(feature = "fetcher-tpm")]
pub use crate::fetcher::TpmFetch;
pub use crate::fetcher::{FetchContext, KeyFetch, RawKey};
pub use crate::fragment::{
    FragmentStrategy, Fragments, InterleavedFragmenter, LayeredFragmenter, RandomFragmenter,
    StandardFragmenter,
};
pub use crate::handle::{KeyHandle, KeyId};
pub use crate::metadata::{AlgorithmHint, KeyMetadata};
#[cfg(feature = "monitor-tracing")]
pub use crate::monitor::LogMonitor;
pub use crate::monitor::{
    AccessContext, CompositeMonitor, FailureContext, LockoutScope, NoMonitor, SecurityMonitor,
    ThresholdContext,
};
pub use crate::vault::{KeyVault, KeyVaultBuilder, VaultConfig};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
