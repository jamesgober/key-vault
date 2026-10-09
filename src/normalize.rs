//! BLAKE3-based key normalization.
//!
//! Raw key material can carry format cues (DER envelopes, PEM markers,
//! ASCII-armored data, the trailing zero of a C string) that make a
//! region of memory easier to recognize as a key. Normalization runs the
//! raw key through BLAKE3 to produce a fixed-size 32-byte value without
//! such cues.
//!
//! The 32-byte output is the effective key: it is what the vault stores
//! and what [`KeyVault::with_key`](crate::KeyVault::with_key) hands back.
//! It is a plain, unkeyed and unsalted BLAKE3 hash, so it is **not** a
//! password hash. For a low-entropy input (a passphrase) anyone who
//! obtains the normalized value can test guesses offline at BLAKE3
//! speed. Feed the vault high-entropy key material, or run passphrases
//! through a slow KDF (Argon2, scrypt) before registering them.
//!
//! Whether normalization is applied is a per-vault choice
//! ([`KeyVaultBuilder::normalize_with_blake3`](crate::KeyVaultBuilder::normalize_with_blake3)).
//! When enabled, every key registered with the vault is normalized before
//! being handed to the fragmenter.
//!
//! # Keyed normalization (1.1)
//!
//! [`KeyVaultBuilder::with_keyed_normalization`](crate::KeyVaultBuilder::with_keyed_normalization)
//! and [`KeyVaultBuilder::with_normalization_key`](crate::KeyVaultBuilder::with_normalization_key)
//! switch to `BLAKE3-keyed(k, key)`, where `k` is a 32-byte key held in
//! locked, dump-excluded memory. A copy of the stored value (from a heap
//! dump, say) is then useless for guessing the input offline without `k`.
//! Plain BLAKE3 stays the default because the normalized value is the
//! effective key handed to callers: changing it would change every key
//! derived from existing material, which needs a major version.

use zeroize::Zeroize;

use crate::fetcher::RawKey;

/// Length of the normalized key, in bytes.
const NORMALIZED_LEN: usize = 32;

/// Run `key` through BLAKE3 and return a new `RawKey` containing the
/// 32-byte hash output.
///
/// The input key bytes are not modified; the caller owns the original.
///
/// The digest is written straight into the returned `RawKey` (the first
/// 32 bytes of BLAKE3's extendable output are the regular BLAKE3 hash), so
/// there is no intermediate `blake3::Hash` copy. The hasher and output
/// reader, which hold state derived from the key, are zeroized before they
/// go out of scope. Temporaries inside BLAKE3's compression function live
/// on the stack and cannot be wiped from here.
#[must_use]
pub(crate) fn blake3_normalize(key: &RawKey) -> RawKey {
    let mut out = RawKey::new(alloc::vec![0u8; NORMALIZED_LEN]);
    blake3_into(key.as_bytes(), out.as_bytes_mut());
    out
}

/// Run `key` through keyed BLAKE3 under the 32-byte `hash_key` and return
/// a new `RawKey` with the 32-byte output. Hasher state is zeroized.
// The key is taken by reference on purpose: passing it by value would
// leave a copy on the stack that nothing wipes.
#[allow(clippy::trivially_copy_pass_by_ref)]
#[must_use]
pub(crate) fn blake3_keyed_normalize(hash_key: &[u8; 32], key: &RawKey) -> RawKey {
    let mut out = RawKey::new(alloc::vec![0u8; NORMALIZED_LEN]);
    blake3_keyed_into(hash_key, key.as_bytes(), out.as_bytes_mut());
    out
}

/// Keyed BLAKE3 of `input` under `hash_key`, written into `out`, with the
/// hasher and output reader zeroized afterwards.
#[allow(clippy::trivially_copy_pass_by_ref)] // see `blake3_keyed_normalize`.
pub(crate) fn blake3_keyed_into(hash_key: &[u8; 32], input: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(hash_key);
    let _ = hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    hasher.zeroize();
}

/// BLAKE3 key derivation (`derive_key` mode) of `material` under the fixed
/// `context` string, written into `out`. Used to turn a caller-supplied
/// normalization key of any length into a 32-byte BLAKE3 key.
pub(crate) fn blake3_derive_into(context: &str, material: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    let _ = hasher.update(material);
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    hasher.zeroize();
}

/// Write the BLAKE3 hash of `input` into `out` (`out.len()` bytes of the
/// extendable output; 32 bytes gives the standard hash), then zeroize the
/// hasher and output reader.
pub(crate) fn blake3_into(input: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    let _ = hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    hasher.zeroize();
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use alloc::vec::Vec;

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
    fn output_matches_plain_blake3_hash() {
        // The 1.0.2 rewrite must not change the normalized value: it is
        // the effective key callers see through `with_key`.
        for input in [
            &b""[..],
            b"hello world",
            &[0xa5; 1000][..],
            &[7u8; 5000][..],
        ] {
            let normalized = blake3_normalize(&raw(input));
            assert_eq!(normalized.as_bytes(), blake3::hash(input).as_bytes());
        }
    }

    #[test]
    fn keyed_output_differs_from_plain_blake3() {
        let input = b"correct horse battery staple";
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        let a = blake3_keyed_normalize(&k1, &raw(input));
        let b = blake3_keyed_normalize(&k2, &raw(input));
        assert_eq!(a.len(), 32);
        assert_ne!(a.as_bytes(), blake3::hash(input).as_bytes());
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes(), blake3::keyed_hash(&k1, input).as_bytes());
        // Same key, same input: same output.
        let again = blake3_keyed_normalize(&k1, &raw(input));
        assert_eq!(a.as_bytes(), again.as_bytes());
    }

    #[test]
    fn derive_matches_blake3_derive_key() {
        let mut out = [0u8; 32];
        blake3_derive_into("ctx", b"material", &mut out);
        assert_eq!(out, blake3::derive_key("ctx", b"material"));
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

    #[test]
    fn hasher_state_is_wiped_by_zeroize() {
        // `blake3_into` relies on `Hasher::zeroize` (blake3's `zeroize`
        // feature) clearing the chaining values and buffered block that
        // were derived from the key. After it, the hasher no longer
        // reflects the absorbed input.
        let mut hasher = blake3::Hasher::new();
        let _ = hasher.update(b"secret key material");
        assert_ne!(hasher.finalize(), blake3::hash(b""));
        hasher.zeroize();
        assert_eq!(hasher.count(), 0);
        assert_ne!(hasher.finalize(), blake3::hash(b"secret key material"));
    }
}
