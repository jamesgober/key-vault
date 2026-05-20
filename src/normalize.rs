//! BLAKE3-based key normalization.
//!
//! Raw key material can carry format cues — DER envelopes, PEM markers,
//! ASCII-armored data, the trailing zero of a C string — that an attacker
//! can use to confirm "yes, this region is a key" even when fragmented and
//! decoyed. Normalization runs the raw key through BLAKE3 to produce a
//! fixed-size 32-byte output that has no such cues.
//!
//! Whether normalization is applied is a per-vault choice
//! ([`KeyVaultBuilder::normalize_with_blake3`](crate::KeyVaultBuilder::normalize_with_blake3)).
//! When enabled, every key registered with the vault is normalized before
//! being handed to the fragmenter.

use alloc::vec::Vec;

use crate::fetcher::RawKey;

/// Run `key` through BLAKE3 and return a new `RawKey` containing the
/// 32-byte hash output.
///
/// The input key bytes are not modified; the caller owns the original.
/// Future phases will route the original through the same locked/zeroed
/// path so the plaintext does not linger on the call stack.
#[must_use]
pub(crate) fn blake3_normalize(key: &RawKey) -> RawKey {
    let hash = blake3::hash(key.as_bytes());
    let mut out: Vec<u8> = Vec::with_capacity(32);
    out.extend_from_slice(hash.as_bytes());
    RawKey::new(out)
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
    fn output_is_thirty_two_bytes() {
        let normalized = blake3_normalize(&raw(b"hello world"));
        assert_eq!(normalized.len(), 32);
    }

    #[test]
    fn output_is_deterministic() {
        let a = blake3_normalize(&raw(b"the quick brown fox"));
        let b = blake3_normalize(&raw(b"the quick brown fox"));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_inputs_produce_different_outputs() {
        let a = blake3_normalize(&raw(b"key one"));
        let b = blake3_normalize(&raw(b"key two"));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn empty_input_still_hashes_to_thirty_two_bytes() {
        // BLAKE3 of the empty string is a well-defined 32-byte value.
        let normalized = blake3_normalize(&raw(&[]));
        assert_eq!(normalized.len(), 32);
    }

    #[test]
    fn varied_lengths_all_produce_thirty_two_bytes() {
        for size in [1usize, 16, 32, 256, 4096] {
            let bytes: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            let normalized = blake3_normalize(&raw(&bytes));
            assert_eq!(normalized.len(), 32, "len mismatch for input size {size}");
        }
    }
}
