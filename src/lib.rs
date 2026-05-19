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
//! 1. **Secure Acquisition** (`KeyFetch` trait — TPM/HSM/Keychain/File/Env)
//! 2. **Memory Page Locking** (`mlock` / `VirtualLock` — prevents swap)
//! 3. **Fragment Strategy** (variable chunks, shuffled, non-contiguous)
//! 4. **Decoy Bytes** (self-referential filler, statistically indistinguishable)
//! 5. **Codex Transformation** (byte swap via involution)
//! 6. **Constant-Time Operations** (subtle::ConstantTimeEq)
//! 7. **Zero-On-Drop** (zeroize crate)
//! 8. **Security Monitor** (failed decrypt detection, threshold lockout)
//! 9. **Audit Logging** (every key access tracked)
//! 10. **(Bonus) Page Protection Toggling** (PROT_NONE when not in use)
//!
//! See `docs/SECURITY.md` for the full architecture and `docs/TRANSFORMATION.md`
//! for a visual walkthrough.
//!
//! # Design philosophy
//!
//! `key-vault` is a focused primitive for keeping cryptographic key material safe in
//! memory while the application is running. It is deliberately **NOT**:
//!
//! - A cryptographic library (use `crypt-io` for actual encryption)
//! - A secrets manager (use HashiCorp Vault for centralized secret distribution)
//! - A password manager (different problem domain)
//!
//! It **IS**:
//!
//! - A defense-in-depth in-memory key storage primitive
//! - A pluggable key acquisition framework
//! - A library for making memory-resident keys hard to extract via memory analysis
//!
//! # Threat model
//!
//! `key-vault` protects against:
//!
//! - **Memory scraping by code with read access** (some malware, forensic tools)
//! - **Swap file persistence** (mlock prevents swap)
//! - **Pattern recognition in memory dumps** (fragment + decoy + codex defeats analysis)
//! - **Use-after-free leakage** (zeroize on drop)
//! - **Brute-force decryption attempts** (security monitor + threshold lockout)
//! - **Timing side-channels** (constant-time operations)
//! - **Insider threats / compliance** (audit logging)
//!
//! It does NOT protect against:
//!
//! - **Code execution in your process** (an attacker running your code can call defrag)
//! - **Hardware compromise** (TPM/HSM/TEE provide different guarantees)
//! - **Side-channel attacks on the crypto layer** (separate concern, `crypt-io`'s job)
//!
//! # Status
//!
//! Early scaffolding. Public API not yet defined. See [the repository](https://github.com/jamesgober/key-vault)
//! and `.dev/ROADMAP.md` for the milestone plan.
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