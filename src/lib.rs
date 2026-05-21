//! # key-vault
//!
//! ENTERPRISE-GRADE KEY MANAGEMENT VAULT
//!
//! 9-layer defense-in-depth in-memory key storage. Fragmented across non-contiguous
//! mlock'd allocations, interleaved with self-referential decoy bytes, optionally
//! transformed through a codex layer, with constant-time operations, zero-on-drop,
//! security monitoring, and audit logging.
//!
//! # The 9 Layers (plus bonus Layer 10)
//!
//! 1. **Secure Acquisition** ([`KeyFetch`] trait — TPM/HSM/Keychain/File/Env)
//! 2. **Memory Page Locking** (`mlock` / `VirtualLock` — prevents swap)
//! 3. **Fragment Strategy** ([`FragmentStrategy`] — variable chunks, shuffled, non-contiguous)
//! 4. **Decoy Bytes** ([`DecoyStrategy`] — self-referential filler, statistically indistinguishable)
//! 5. **Codex Transformation** ([`Codex`] — byte swap via involution)
//! 6. **Constant-Time Operations** (`subtle::ConstantTimeEq`)
//! 7. **Zero-On-Drop** (`zeroize` crate)
//! 8. **Security Monitor** ([`SecurityMonitor`] — failed decrypt detection, threshold lockout)
//! 9. **Audit Logging** (every key access tracked)
//! 10. **(Bonus) Page Protection Toggling** (PROT_NONE when not in use)
//!
//! See `docs/SECURITY.md` for the full architecture and `docs/TRANSFORMATION.md`
//! for a visual walkthrough.
//!
//! # Status
//!
//! Phase 0.2.0 — foundation types defined. [`KeyHandle`], [`KeyVault`],
//! [`KeyVaultBuilder`], the five core traits, [`IdentityCodex`], and
//! [`tee::detect_tee_capabilities`] are in place. Real fragmentation, mlock,
//! decoy, and zeroize land in Phases 0.3 and 0.4. See `.dev/ROADMAP.md` for
//! the full milestone plan.
//!
//! # License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

#![doc(html_root_url = "https://docs.rs/key-vault")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

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
