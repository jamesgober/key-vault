//! Layer 4 — Decoy bytes.
//!
//! Decoy strategies produce filler bytes that surround real key fragments in
//! storage. The goal is statistical indistinguishability: an attacker scraping
//! memory should not be able to tell which bytes are real and which are filler
//! without the position map.
//!
//! The strongest built-in strategy (`SelfReferenceDecoy`) lifts bytes from the
//! real key itself, so the filler is by definition drawn from the same
//! distribution as the secret. The weakest (`RandomDecoy`) uses raw CSPRNG
//! output, which is easy to compute but tends to stand out from key material
//! that has structure (DER-encoded RSA, ASCII-armored data, etc.).
//!
//! In this phase the trait surface is defined; implementations arrive in
//! Phase 0.4.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::Result;
use crate::fetcher::RawKey;

/// Strategy for producing decoy filler bytes.
///
/// # Implementor contract
///
/// - **Deterministic for a given seed but not for a given key.** Strategies
///   that derive filler from the key (`SelfReferenceDecoy`,
///   `KeyDerivedDecoy`) must use a per-vault random seed so that two vaults
///   holding the same key produce different decoy bytes.
/// - **No accidental key recovery.** A decoy strategy must never emit a
///   contiguous run of bytes that matches the real key — verify this in tests
///   for any implementation.
/// - **`Send + Sync`.** May be invoked from any thread.
pub trait DecoyStrategy: Send + Sync {
    /// Generate `output_len` bytes of decoy material derived (or not) from
    /// `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decoy`](crate::Error::Decoy) if `output_len` exceeds
    /// the strategy's supported maximum or if an upstream RNG fails.
    fn generate(&self, key: &RawKey, output_len: usize) -> Result<Vec<u8>>;

    /// Short identifier for audit and error attribution.
    fn describe(&self) -> Cow<'_, str>;
}
