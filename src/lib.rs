//! # key-vault
//!
//! ENTERPRISE-GRADE KEY MANAGEMENT VAULT
//!
//! Scattered in-memory key storage with multiple distortion strategies, mlock/zeroize protection, pluggable acquisition. Sub-microsecond access. Defense-in-depth for cryptographic key material.
//!
//! # Design philosophy
//!
//! $name is a focused primitive for keeping cryptographic key material safe in memory
//! while the application is running. It is deliberately **NOT**:
//!
//! - A cryptographic library (use crypt-io or similar for actual encryption)
//! - A secrets manager (use HashiCorp Vault for centralized secret distribution)
//! - A password manager (different problem domain)
//!
//! It **IS**:
//!
//! - A defense-in-depth in-memory key storage primitive
//! - A pluggable key acquisition framework
//! - A library for making memory-resident keys hard to extract via memory analysis
//!
//! # Defense layers
//!
//! $name employs multiple defense layers, configurable via features:
//!
//! 1. **Memory page locking** (mlock/VirtualLock) — prevents swap to disk
//! 2. **Zero on drop** (zeroize) — overwrites memory when keys are dropped
//! 3. **Scattered storage** — key bytes split across multiple non-contiguous allocations
//! 4. **Distortion patterns** — filler bytes derived from key material itself
//! 5. **Variable layout** — chunk sizes and counts randomized per scatter
//! 6. **Constant-time comparison** — subtle for all key-related equality checks
//!
//! These layers compose. Each adds friction for an attacker with memory access.
//! None are silver bullets; combined, they raise the bar significantly.
//!
//! # Threat model
//!
//! $name protects against:
//!
//! - **Memory scraping by code with read access** (some malware, forensic tools)
//! - **Swap file persistence** (mlock prevents swap)
//! - **Pattern recognition in memory dumps** (scatter + distortion defeats statistical analysis)
//! - **Use-after-free leakage** (zeroize on drop)
//!
//! It does NOT protect against:
//!
//! - **Code execution in your process** (an attacker running your code can call your reassemble logic)
//! - **Hardware compromise** (TPM/HSM/TEE provide different guarantees)
//! - **Side-channel attacks on the crypto layer** (separate concern, crypt-io's job)
//!
//! # Status
//!
//! Early scaffolding. Public API not yet defined. See [the repository](https://github.com/jamesgober/key-vault)
//! and .dev/ROADMAP.md for the milestone plan.
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

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");