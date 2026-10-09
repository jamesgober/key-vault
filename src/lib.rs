//! # key-vault
//!
//! In-memory key storage for Rust applications.
//!
//! `key-vault` keeps key material in page-locked, zero-on-drop buffers,
//! hands out opaque [`KeyHandle`]s instead of byte slices, gives the bytes
//! back only inside a scoped callback ([`KeyVault::with_key`]), and supports
//! atomic rotation, failure monitoring and audit hooks. On top of that it can
//! split keys into shuffled fragments, mix in decoy chunks and pass bytes
//! through a codex. Those three are obfuscation, not encryption: see the
//! threat model below.
//!
//! # Threat model
//!
//! **What it helps with**
//!
//! - Keys written to swap: buffers are `mlock`'d / `VirtualLock`'d
//!   (best effort; check `RLIMIT_MEMLOCK`).
//! - Keys lingering in freed memory: every buffer the crate owns is
//!   zeroized before it is freed.
//! - Accidental exposure through logs, `Debug` output, error messages and
//!   long-lived `Vec<u8>` copies in application code.
//! - Casual memory scans and heap dumps that search for a key as a
//!   contiguous run of bytes or for known key formats. Fragmentation,
//!   decoys and the codex make that harder.
//!
//! **What it does not protect against**
//!
//! - **Anyone who can read the process's memory** (a debugger, a
//!   same-user process with `ptrace` / `ReadProcessMemory`, a full core
//!   dump, malware in the process, the kernel). The fragments, the layout
//!   map that says how to reassemble them and which chunks are decoys, and
//!   the codex table all live in the same process memory. An attacker with
//!   read access can rebuild every key. Fragmentation, decoys and the
//!   codex only raise the effort for tools that do not know this crate's
//!   layout.
//! - Code running inside the process, which can simply call
//!   [`KeyVault::with_key`].
//! - Hardware attacks (DMA, cold boot) and side channels in the
//!   cryptographic code that uses the key.
//!
//! See `docs/SECURITY.md` for the per-layer details.
//!
//! # Layers in 1.0.x
//!
//! 1. **Key acquisition** ([`KeyFetch`]): keychain, plaintext file and
//!    environment-variable fetchers. Fetchers add no in-memory protection.
//!    `TpmFetch` is not implemented and always returns an error.
//! 2. **Page locking** (`mlock` / `VirtualLock`): best effort, with
//!    per-page reference counting so one buffer's drop never unlocks a page
//!    another live buffer uses.
//! 3. **Fragmentation** ([`FragmentStrategy`]): obfuscation. The vault
//!    always uses [`StandardFragmenter`].
//! 4. **Decoy chunks** ([`DecoyStrategy`]): obfuscation. Off unless set
//!    with [`KeyVaultBuilder::with_decoy`].
//! 5. **Codex** ([`Codex`]): obfuscation, a byte substitution whose table is
//!    stored next to the data. Off unless set with
//!    [`KeyVaultBuilder::with_codex`].
//! 6. **Constant-time comparison** (`subtle`): used for the master-key
//!    digest check and handle equality. Defragmentation itself is not
//!    constant-time.
//! 7. **Zero-on-drop** (`zeroize`): every secret-bearing buffer the crate
//!    allocates. Copies made inside `std`, the OS or your own callback are
//!    not covered.
//! 8. **Failure monitor and lockout** ([`SecurityMonitor`]): advisory. The
//!    vault only counts failures the caller reports; lockout is vault-wide.
//! 9. **Audit hooks** ([`AuditSink`]): one event per vault operation.
//!
//! Layer 10, page protection toggling (`PROT_NONE` / `PAGE_NOACCESS`
//! between accesses), is **not implemented** in 1.0.x.
//!
//! # Cargo features
//!
//! Only `std` (required), the `fetcher-*` features and `monitor-tracing`
//! change what is compiled. The other features (`mlock`, `zeroize`,
//! `codex`, `codex-dynamic`, `decoy-*`, `fragment-*`, `monitor`, `audit`,
//! `tee-detect`, `post-quantum`, `preset-*`) are reserved and have no
//! effect in 1.0.x. Page locking and zeroization are always on; decoys and
//! the codex are configured on [`KeyVaultBuilder`].
//!
//! See `docs/TRANSFORMATION.md` for a walkthrough of what happens to a
//! key as it is stored.
//!
//! # Standard library requirement
//!
//! key-vault requires the standard library. The `std` feature is on by
//! default and must stay enabled: a build without it stops with a
//! `compile_error!`. There is no `no_std` support today.
//!
//! # License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

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

// The crate uses `std` throughout (HashMap, Mutex, Instant, SystemTime,
// thread ids). The `std` feature is kept so existing feature lists stay
// valid, but turning it off is not supported.
#[cfg(not(feature = "std"))]
compile_error!("key-vault currently requires the `std` feature; no_std support is planned");

extern crate alloc;

pub mod audit;
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
pub mod tee;
mod vault;

#[cfg(feature = "monitor-tracing")]
pub use crate::audit::LogAudit;
pub use crate::audit::{AccessKind, AuditEvent, AuditSink, NoAudit};
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
    AccessContext, CompositeMonitor, FailureContext, NoMonitor, SecurityMonitor, ThresholdContext,
};
pub use crate::vault::{KeyVault, KeyVaultBuilder, VaultConfig};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
