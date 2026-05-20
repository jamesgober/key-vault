//! [`RandomDecoy`] — pure CSPRNG-derived decoy bytes.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use super::DecoyStrategy;
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;

/// Decoy strategy that produces uniformly-random bytes from the OS CSPRNG.
///
/// **Threat profile.** `RandomDecoy` is the fastest of the three built-in
/// strategies and the easiest to reason about, but it is also the *weakest*:
/// the byte distribution it produces is uniformly random, which is
/// distinguishable from key material that has visible structure (DER
/// envelopes, ASCII-armored data, PEM markers, MAC-based keys with header
/// bytes, etc.). For maximum indistinguishability prefer
/// [`SelfReferenceDecoy`](super::SelfReferenceDecoy).
///
/// Use `RandomDecoy` when:
///
/// - The keys you store are already uniformly random (256-bit symmetric keys
///   from a CSPRNG, for example) — there is nothing to distinguish.
/// - You want the lowest decoy-generation cost on the hot path.
///
/// # Examples
///
/// ```
/// use key_vault::decoy::{DecoyStrategy, RandomDecoy};
/// use key_vault::RawKey;
///
/// let key = RawKey::new(b"some key material".to_vec());
/// let decoy = RandomDecoy.generate(&key, 32).unwrap();
/// assert_eq!(decoy.len(), 32);
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct RandomDecoy;

impl DecoyStrategy for RandomDecoy {
    fn generate(&self, _key: &RawKey, output_len: usize) -> Result<Vec<u8>> {
        if output_len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; output_len];
        getrandom::getrandom(&mut buf).map_err(|_| Error::Internal("OS RNG failed"))?;
        Ok(buf)
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("random")
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
        let key = raw(b"anything");
        for n in [0usize, 1, 7, 32, 256, 4096] {
            let out = RandomDecoy.generate(&key, n).unwrap();
            assert_eq!(out.len(), n, "wrong length for n = {n}");
        }
    }

    #[test]
    fn two_calls_produce_different_bytes() {
        let key = raw(b"k");
        let a = RandomDecoy.generate(&key, 64).unwrap();
        let b = RandomDecoy.generate(&key, 64).unwrap();
        // Pure CSPRNG output collision at 64 bytes is astronomically
        // improbable. A match indicates broken randomness.
        assert_ne!(a, b);
    }

    #[test]
    fn describe_returns_random() {
        assert_eq!(RandomDecoy.describe(), "random");
    }
}
