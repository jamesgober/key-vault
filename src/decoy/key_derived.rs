//! [`KeyDerivedDecoy`] — BLAKE3-XOF derived decoy bytes.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use super::DecoyStrategy;
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;

/// Decoy strategy that produces bytes via BLAKE3's extendable-output (XOF)
/// mode, seeded by the key and a fresh CSPRNG nonce.
///
/// **Threat profile.** A middle ground between [`RandomDecoy`](super::RandomDecoy)
/// and [`SelfReferenceDecoy`](super::SelfReferenceDecoy):
///
/// - The output passes general statistical tests like a CSPRNG would, so
///   simple entropy/chi-squared distinguishers cannot tell decoy bytes from
///   `RandomDecoy` output.
/// - Because the seed includes the key, downstream cryptographic analysis
///   that looks for "uniform-random vs. structured" patterns sees the same
///   thing it sees for the real key (which is itself a hashed/derived blob in
///   most modern protocols).
/// - Less aggressive than `SelfReferenceDecoy` for keys with very
///   non-uniform byte distributions (e.g. DER-encoded RSA keys), but
///   strictly stronger than `RandomDecoy`.
///
/// Use `KeyDerivedDecoy` when you want CSPRNG-like output but seeded by the
/// real key so the resulting profile correlates with it.
///
/// # Examples
///
/// ```
/// use key_vault::decoy::{DecoyStrategy, KeyDerivedDecoy};
/// use key_vault::RawKey;
///
/// let key = RawKey::new(b"the key".to_vec());
/// let decoy = KeyDerivedDecoy.generate(&key, 32).unwrap();
/// assert_eq!(decoy.len(), 32);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyDerivedDecoy;

impl DecoyStrategy for KeyDerivedDecoy {
    fn generate(&self, key: &RawKey, output_len: usize) -> Result<Vec<u8>> {
        if output_len == 0 {
            return Ok(Vec::new());
        }
        // Mix in a per-call nonce so two consecutive `generate` calls with
        // the same key produce different output. Without the nonce the
        // strategy would be a pure function of the key, which would allow
        // an attacker who knows the key bytes to recompute the decoy and
        // confirm a fragmentation.
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Internal("OS RNG failed"))?;

        let mut hasher = blake3::Hasher::new();
        // `Hasher::update` returns `&mut Self` for chaining; we bind to `_`
        // to satisfy `#![deny(unused_results)]`.
        let _ = hasher.update(key.as_bytes());
        let _ = hasher.update(&nonce);

        let mut out = vec![0u8; output_len];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut out);

        // Scrub the nonce. The key bytes themselves belong to `key` and are
        // not our responsibility to wipe.
        // SAFETY: nonce is a fixed-size stack array we own; we write within
        // bounds.
        unsafe {
            let ptr = nonce.as_mut_ptr();
            for i in 0..nonce.len() {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        Ok(out)
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("key-derived")
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    fn raw(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn produces_requested_length() {
        let key = raw(b"k");
        for n in [0usize, 1, 7, 32, 256, 4096] {
            let out = KeyDerivedDecoy.generate(&key, n).unwrap();
            assert_eq!(out.len(), n, "wrong length for n = {n}");
        }
    }

    #[test]
    fn two_calls_with_same_key_produce_different_outputs() {
        // Without the per-call nonce this would be the SAME bytes both
        // times. With it, two outputs must differ.
        let key = raw(b"deterministic seed");
        let a = KeyDerivedDecoy.generate(&key, 64).unwrap();
        let b = KeyDerivedDecoy.generate(&key, 64).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_keys_produce_different_outputs() {
        let a = KeyDerivedDecoy.generate(&raw(b"key one"), 32).unwrap();
        let b = KeyDerivedDecoy.generate(&raw(b"key two"), 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_key_is_accepted() {
        // BLAKE3 of any input (including empty) is well-defined. Unlike
        // SelfReferenceDecoy this strategy does not need at least one source
        // byte.
        let out = KeyDerivedDecoy.generate(&raw(&[]), 32).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn describe_returns_key_derived() {
        assert_eq!(KeyDerivedDecoy.describe(), "key-derived");
    }
}
