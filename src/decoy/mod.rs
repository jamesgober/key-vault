//! Layer 4: decoy chunks.
//!
//! Decoy strategies produce filler chunks that are stored and shuffled
//! together with the real key fragments. The goal is that a scan which does
//! not know the vault's layout cannot tell real chunks from filler by their
//! byte statistics.
//!
//! This is **obfuscation**. The layout map that marks every decoy chunk is
//! stored in the same process memory as the chunks, so anyone who can read
//! process memory can separate them. No decoy is used unless one is passed
//! to [`KeyVaultBuilder::with_decoy`](crate::KeyVaultBuilder::with_decoy);
//! the `decoy-*` Cargo features are reserved and have no effect in 1.0.x.
//!
//! Three implementations ship:
//!
//! | Strategy                        | Output profile                | Statistical cover   |
//! |---------------------------------|-------------------------------|---------------------|
//! | [`RandomDecoy`]                 | Uniformly random              | Weakest, fastest    |
//! | [`KeyDerivedDecoy`]             | BLAKE3-XOF (CSPRNG-like)      | Medium              |
//! | [`SelfReferenceDecoy`]          | Drawn from the key itself     | Strongest           |
//!
//! The strongest built-in strategy ([`SelfReferenceDecoy`]) lifts bytes from
//! the real key, so the filler is by definition drawn from the same
//! distribution as the secret. The weakest ([`RandomDecoy`]) uses raw CSPRNG
//! output, which is easy to compute but tends to stand out from key material
//! that has structure (DER-encoded RSA, ASCII-armored data, etc.).

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::Result;
use crate::fetcher::RawKey;

mod key_derived;
mod random;
mod self_reference;

pub use self::key_derived::KeyDerivedDecoy;
pub use self::random::RandomDecoy;
pub use self::self_reference::SelfReferenceDecoy;

/// Strategy for producing decoy filler bytes.
///
/// # Implementor contract
///
/// - **Deterministic for a given seed but not for a given key.** Strategies
///   that derive filler from the key ([`SelfReferenceDecoy`],
///   [`KeyDerivedDecoy`]) must mix in fresh CSPRNG bytes per call so that
///   two consecutive `generate` calls on the same key produce different
///   output. Otherwise an attacker who recovers the key can confirm any
///   suspected fragmentation by recomputing the decoy.
/// - **No accidental key recovery.** A decoy strategy must never emit a
///   contiguous run of bytes that matches the real key — verify this in
///   tests for any implementation. `SelfReferenceDecoy` sidesteps this by
///   sampling with replacement instead of shuffling.
/// - **`Send + Sync`.** May be invoked from any thread.
pub trait DecoyStrategy: Send + Sync {
    /// Generate `output_len` bytes of decoy material derived (or not) from
    /// `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decoy`](crate::Error::Decoy) if the strategy cannot
    /// produce the requested output for this key (for example,
    /// [`SelfReferenceDecoy`] on an empty key has nothing to sample from).
    /// Returns [`Error::Internal`](crate::Error::Internal) on RNG failure.
    fn generate(&self, key: &RawKey, output_len: usize) -> Result<Vec<u8>>;

    /// Short identifier for audit and error attribution.
    fn describe(&self) -> Cow<'_, str>;
}
