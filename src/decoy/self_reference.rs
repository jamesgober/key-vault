//! [`SelfReferenceDecoy`] — decoy bytes sampled from the key itself.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use super::DecoyStrategy;
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;

/// Decoy strategy that draws bytes from the real key at random positions.
///
/// **Threat profile.** `SelfReferenceDecoy` is the **strongest** of the three
/// built-in strategies and the recommended default. The decoy bytes are
/// literally drawn from the key's own byte distribution, so any statistical
/// analysis of memory regions (byte-value histogram, entropy estimate,
/// chi-squared distinguisher) will report identical profiles for real
/// fragments and decoy fragments. An attacker has no statistical signal to
/// separate them.
///
/// The only way for an attacker to recover the key, given this strategy, is
/// to (a) obtain the position map (separately mlock'd) and (b) reverse the
/// fragmentation. Statistical attacks alone do not work.
///
/// # Why not just shuffle key bytes?
///
/// Sampling with replacement (which is what we do) is important: shuffling
/// would still preserve the multiset of key bytes, and a long contiguous
/// match would reveal a chunk boundary. With independent sampling, the
/// decoy bytes match the key's byte *distribution* without containing any
/// contiguous run of key bytes long enough to be confirmed.
///
/// # Examples
///
/// ```
/// use key_vault::decoy::{DecoyStrategy, SelfReferenceDecoy};
/// use key_vault::RawKey;
///
/// let key = RawKey::new(vec![0xa1, 0xb2, 0xc3, 0xd4, 0xe5]);
/// let decoy = SelfReferenceDecoy.generate(&key, 32).unwrap();
/// assert_eq!(decoy.len(), 32);
/// // Every decoy byte is drawn from the key's byte set.
/// for b in &decoy {
///     assert!([0xa1, 0xb2, 0xc3, 0xd4, 0xe5].contains(b));
/// }
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct SelfReferenceDecoy;

impl DecoyStrategy for SelfReferenceDecoy {
    fn generate(&self, key: &RawKey, output_len: usize) -> Result<Vec<u8>> {
        if output_len == 0 {
            return Ok(Vec::new());
        }
        let key_bytes = key.as_bytes();
        if key_bytes.is_empty() {
            return Err(Error::Decoy(alloc::string::ToString::to_string(
                "self-reference decoy requires a non-empty key",
            )));
        }

        // Fetch the index randomness in one syscall instead of one per byte.
        // We use four bytes of CSPRNG output per decoy byte (more than enough
        // entropy to index into a key of any practical size).
        let rand_byte_count = output_len.saturating_mul(4);
        let mut rand_buf = vec![0u8; rand_byte_count];
        getrandom::getrandom(&mut rand_buf).map_err(|_| Error::Internal("OS RNG failed"))?;

        let key_len = key_bytes.len();
        let mut out = Vec::with_capacity(output_len);
        for i in 0..output_len {
            let raw: [u8; 4] = rand_buf[i * 4..i * 4 + 4]
                .try_into()
                .map_err(|_| Error::Internal("rand buffer slice did not size to u32"))?;
            // Modulo bias against `key_len` is at worst 2^-32 / key_len; for
            // any practical key length this is negligible.
            let idx = (u32::from_le_bytes(raw) as usize) % key_len;
            out.push(key_bytes[idx]);
        }

        // Scrub the temporary randomness buffer.
        for b in &mut rand_buf {
            // SAFETY-equivalent: we still own rand_buf and the slice is
            // valid; volatile-zero defeats dead-store elimination.
            //
            // Note: we are not inside an `unsafe` block — `write_volatile`
            // is unsafe but we are taking the safe `iter_mut` path here for
            // clarity. To actually defeat dead-store elimination we need
            // the volatile write; see below.
            let _ = b;
        }
        // Real volatile-zero pass for the randomness buffer.
        // SAFETY: rand_buf points to a valid `rand_byte_count`-element
        // allocation we just constructed; we write within bounds.
        unsafe {
            let ptr = rand_buf.as_mut_ptr();
            for i in 0..rand_buf.len() {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        drop(rand_buf);

        Ok(out)
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("self-reference")
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
    use alloc::collections::BTreeSet;

    fn raw(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn produces_requested_length() {
        let key = raw(&[1, 2, 3, 4, 5]);
        for n in [0usize, 1, 7, 32, 256, 4096] {
            let out = SelfReferenceDecoy.generate(&key, n).unwrap();
            assert_eq!(out.len(), n, "wrong length for n = {n}");
        }
    }

    #[test]
    fn every_byte_is_drawn_from_the_key() {
        let key_bytes: alloc::vec::Vec<u8> = (0u8..16).collect();
        let key = raw(&key_bytes);
        let allowed: BTreeSet<u8> = key_bytes.iter().copied().collect();

        let out = SelfReferenceDecoy.generate(&key, 1024).unwrap();
        for (i, b) in out.iter().enumerate() {
            assert!(
                allowed.contains(b),
                "decoy byte {b:#04x} at index {i} not in key"
            );
        }
    }

    #[test]
    fn empty_key_is_rejected() {
        let key = raw(&[]);
        let err = SelfReferenceDecoy.generate(&key, 16).unwrap_err();
        assert!(matches!(err, Error::Decoy(_)));
    }

    #[test]
    fn two_calls_with_same_key_produce_different_outputs() {
        let key = raw(b"a key with reasonable length");
        let a = SelfReferenceDecoy.generate(&key, 64).unwrap();
        let b = SelfReferenceDecoy.generate(&key, 64).unwrap();
        // With independent sampling from a 28-byte key the chance of two
        // 64-byte outputs matching is (1/28)^64 — effectively zero.
        assert_ne!(a, b);
    }

    #[test]
    fn describe_returns_self_reference() {
        assert_eq!(SelfReferenceDecoy.describe(), "self-reference");
    }
}
