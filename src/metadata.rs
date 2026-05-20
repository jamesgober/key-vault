//! Public, non-secret metadata associated with a registered key.
//!
//! [`KeyMetadata`] is the information *about* a key that callers are allowed to
//! see: when it was registered, how long the underlying material is, an
//! optional hint about which algorithm family it belongs to. None of these
//! fields contain key bytes; all of them are safe to log.
//!
//! Anything that would identify the *value* of the key (raw bytes, fragments,
//! decoy bytes, codex tables) lives elsewhere and is unreachable through
//! `KeyMetadata`.

use core::time::Duration;

/// Hint about which cryptographic algorithm a stored key is intended for.
///
/// This is advisory only. The vault does not verify that the registered bytes
/// are actually a valid key for the named algorithm — that is the caller's
/// responsibility, and the [`KeyFetch`](crate::KeyFetch) implementation's
/// responsibility for hardware-backed sources. The variant exists so that
/// audit-trail records and security monitors can label events meaningfully.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmHint {
    /// 128-bit symmetric key (e.g. AES-128 KEK).
    Symmetric128,
    /// 256-bit symmetric key (e.g. AES-256, ChaCha20).
    Symmetric256,
    /// Ed25519 signing key (32-byte seed).
    Ed25519,
    /// X25519 ECDH private key (32 bytes).
    X25519,
    /// NIST P-256 ECDSA private key.
    P256,
    /// NIST P-384 ECDSA private key.
    P384,
    /// RSA-2048 private key (DER-encoded).
    Rsa2048,
    /// RSA-3072 private key.
    Rsa3072,
    /// RSA-4096 private key.
    Rsa4096,
    /// HMAC key (length given by [`KeyMetadata::length`]).
    Hmac,
    /// Other — caller supplies their own meaning out-of-band.
    Other,
}

/// Public, non-secret information about a registered key.
///
/// `KeyMetadata` is safe to log, send to monitors, and include in audit
/// records. It contains no information from which the key value could be
/// derived.
///
/// The `length` field reports the *raw* key length in bytes — the size of the
/// material that was registered with the vault before fragmentation. It is not
/// the size of the in-memory fragmented representation (which is larger and
/// implementation-defined).
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Time at which the key was registered with the vault, expressed as a
    /// `Duration` since the [`UNIX_EPOCH`](std::time::UNIX_EPOCH).
    ///
    /// We use `Duration` instead of `SystemTime` so the type is portable to
    /// `no_std` builds in the future. Callers that need a wall-clock
    /// representation can reconstruct one via
    /// `UNIX_EPOCH + metadata.registered_since_epoch()`.
    registered_since_epoch: Duration,
    /// Raw key length in bytes.
    length: usize,
    /// Optional hint for downstream audit and monitoring code.
    algorithm: Option<AlgorithmHint>,
}

impl KeyMetadata {
    /// Construct metadata from explicit fields.
    ///
    /// Crate-internal — produced by the vault at registration time.
    #[allow(dead_code)] // produced by the vault when keys are registered in Phase 0.3.
    #[must_use]
    pub(crate) fn new(
        registered_since_epoch: Duration,
        length: usize,
        algorithm: Option<AlgorithmHint>,
    ) -> Self {
        Self {
            registered_since_epoch,
            length,
            algorithm,
        }
    }

    /// Raw key length, in bytes.
    ///
    /// This is the length of the material that was originally registered, not
    /// the size of the in-memory fragmented representation.
    #[must_use]
    pub fn length(&self) -> usize {
        self.length
    }

    /// Algorithm hint, if one was provided at registration.
    #[must_use]
    pub fn algorithm(&self) -> Option<AlgorithmHint> {
        self.algorithm
    }

    /// Time of registration, expressed as a `Duration` since the Unix epoch.
    #[must_use]
    pub fn registered_since_epoch(&self) -> Duration {
        self.registered_since_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip() {
        let meta = KeyMetadata::new(
            Duration::from_secs(1_700_000_000),
            32,
            Some(AlgorithmHint::Symmetric256),
        );
        assert_eq!(meta.length(), 32);
        assert_eq!(meta.algorithm(), Some(AlgorithmHint::Symmetric256));
        assert_eq!(
            meta.registered_since_epoch(),
            Duration::from_secs(1_700_000_000)
        );
    }

    #[test]
    fn algorithm_hint_is_optional() {
        let meta = KeyMetadata::new(Duration::ZERO, 16, None);
        assert!(meta.algorithm().is_none());
    }
}
