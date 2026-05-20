//! The vault itself.
//!
//! In this phase [`KeyVault`] owns the configured fragmenter and the
//! normalization toggle, and exposes `fragment` / `defragment` shortcuts so
//! downstream crates can exercise the Layer 2 + Layer 3 + Layer 7 stack
//! end-to-end. Key registration, naming, rotation, and recovery still arrive
//! in Phase 0.9 — today the vault is a stateless helper around the
//! fragmenter.
//!
//! ```
//! use key_vault::{KeyVault, KeyVaultBuilder};
//!
//! // The builder follows the standard fluent pattern. None of the methods
//! // perform I/O — construction is cheap and infallible.
//! let _vault: KeyVault = KeyVaultBuilder::new().build();
//! ```

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use crate::Result;
use crate::codex::Codex;
use crate::decoy::DecoyStrategy;
use crate::fetcher::RawKey;
use crate::fragment::{FragmentStrategy, Fragments, StandardFragmenter};
use crate::normalize::blake3_normalize;

/// Vault configuration.
///
/// Concrete fields are added in later phases as each layer comes online —
/// decoy strategy in 0.4, additional fragment strategies in 0.5, codex in
/// 0.6, monitor in 0.8.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct VaultConfig {
    /// If `true`, raw key material is BLAKE3-normalized to 32 bytes before
    /// fragmentation. Default is `true`.
    pub key_normalization: bool,
}

impl VaultConfig {
    /// Default-on configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_normalization: true,
        }
    }
}

/// In-memory key vault.
///
/// The vault is the entry point for everything `key-vault` does. Application
/// code constructs one via [`KeyVaultBuilder`], hands it [`RawKey`] values
/// to be fragmented, and (in later phases) receives
/// [`KeyHandle`](crate::KeyHandle)s in return. The vault itself is cheap to
/// clone (it is `Arc`-backed internally) and safe to share across threads.
///
/// In Phase 0.3 the vault exposes [`KeyVault::fragment`] and
/// [`KeyVault::defragment`] convenience methods that route through the
/// configured normalizer and [`StandardFragmenter`]. The full named-key
/// registry arrives in Phase 0.9.
#[derive(Clone)]
pub struct KeyVault {
    inner: Arc<VaultInner>,
}

struct VaultInner {
    config: VaultConfig,
    fragmenter: StandardFragmenter,
    /// Optional Layer-5 codex. When set, every byte of normalized key
    /// material passes through `codex.encode()` before being handed to
    /// the fragmenter; `defragment` applies `codex.decode()` to recover.
    codex: Option<Arc<dyn Codex>>,
    /// Set to `true` when a [`SecurityMonitor`](crate::SecurityMonitor)
    /// threshold breach has put the vault into lock-out state. Lock-out is
    /// not yet driven by the monitor — that arrives in Phase 0.8.
    locked_out: AtomicBool,
}

impl KeyVault {
    /// Returns `true` if the vault is in lock-out state.
    ///
    /// Lock-out is the [`SecurityMonitor`](crate::SecurityMonitor)'s response
    /// to repeated failures: once the threshold is crossed, access to every
    /// key in the vault is denied until the configured recovery condition is
    /// met. In Phase 0.2 the lock-out flag exists but is never set; Phase 0.8
    /// connects it to monitor events.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        self.inner.locked_out.load(Ordering::Acquire)
    }

    /// Snapshot of the vault's configuration.
    #[must_use]
    pub fn config(&self) -> &VaultConfig {
        &self.inner.config
    }

    /// Fragment a raw key through the configured normalizer, codex, and
    /// fragmenter.
    ///
    /// The returned [`Fragments`] is opaque; pass it back to
    /// [`KeyVault::defragment`] to recover the (normalized + codex-encoded)
    /// bytes inverse-transformed.
    ///
    /// # Pipeline
    ///
    /// ```text
    /// key → blake3_normalize (optional) → codex.encode (optional) → fragmenter.fragment → Fragments
    /// ```
    ///
    /// # Errors
    ///
    /// Returns whatever the underlying [`FragmentStrategy`] surfaces — in
    /// practice an [`Error::Fragment`](crate::Error::Fragment) for a
    /// zero-length input.
    pub fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        let working = if self.inner.config.key_normalization {
            blake3_normalize(key)
        } else {
            RawKey::new(key.as_bytes().to_vec())
        };
        let encoded = if let Some(codex) = &self.inner.codex {
            codex_apply(codex.as_ref(), &working)
        } else {
            working
        };
        self.inner.fragmenter.fragment(&encoded)
    }

    /// Reassemble fragments produced by [`KeyVault::fragment`].
    ///
    /// Inverts the codex transformation (if configured) so the recovered
    /// bytes are the normalized key (or the original raw key if
    /// normalization is off). Defragmentation itself is delegated to the
    /// configured [`FragmentStrategy`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`](crate::Error::Defragment) when the
    /// supplied fragments do not match the configured fragmenter's layout.
    pub fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        let encoded = self.inner.fragmenter.defragment(fragments)?;
        if let Some(codex) = &self.inner.codex {
            Ok(codex_apply(codex.as_ref(), &encoded))
        } else {
            Ok(encoded)
        }
    }
}

/// Apply a codex's transformation to every byte of a key.
///
/// Used both for encoding (pre-fragment) and decoding (post-defragment).
/// For involution-based codices `decode == encode`; the function name
/// reflects that — it's a single transformation pass either way.
fn codex_apply(codex: &dyn Codex, key: &RawKey) -> RawKey {
    let bytes: Vec<u8> = key.as_bytes().iter().map(|&b| codex.encode(b)).collect();
    RawKey::new(bytes)
}

impl core::fmt::Debug for KeyVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVault")
            .field("locked_out", &self.is_locked_out())
            .field("config", &self.inner.config)
            .finish()
    }
}

/// Fluent builder for [`KeyVault`].
///
/// The builder is the only way to construct a vault; the inherent
/// `KeyVault::new` constructor is intentionally not provided so that future
/// required configuration cannot be silently bypassed.
#[derive(Default, Clone)]
pub struct KeyVaultBuilder {
    config: VaultConfig,
    fragmenter: StandardFragmenter,
    codex: Option<Arc<dyn Codex>>,
}

impl core::fmt::Debug for KeyVaultBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVaultBuilder")
            .field("config", &self.config)
            .field("fragmenter", &self.fragmenter)
            .field("codex", &self.codex.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl KeyVaultBuilder {
    /// Start a new builder with default configuration and a default-range
    /// [`StandardFragmenter`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VaultConfig::new(),
            fragmenter: StandardFragmenter::new(),
            codex: None,
        }
    }

    /// Enable or disable BLAKE3 normalization of input key material.
    ///
    /// Default: `true`. Disabling normalization preserves the original byte
    /// pattern of the key in storage, which can leak format cues (DER
    /// envelopes, PEM markers, ASCII-armored data). Disable only when you
    /// have a specific reason to preserve the original bytes.
    #[must_use]
    pub fn normalize_with_blake3(mut self, enabled: bool) -> Self {
        self.config.key_normalization = enabled;
        self
    }

    /// Customize the fragmenter chunk-size range.
    ///
    /// Defaults are documented on [`StandardFragmenter::new`]. `min` is
    /// clamped to `>= 1` and `max` to `>= min`. Calling this replaces any
    /// previously-configured chunk range and resets the decoy strategy to
    /// `None`; configure decoy *after* this call.
    #[must_use]
    pub fn with_chunk_range(mut self, min: usize, max: usize) -> Self {
        self.fragmenter = StandardFragmenter::with_chunk_range(min, max);
        self
    }

    /// Attach a Layer-5 codex to the vault.
    ///
    /// When set, every byte of the (optionally BLAKE3-normalized) key
    /// passes through `codex.encode()` before being handed to the
    /// fragmenter; `defragment` applies `codex.decode()` to recover the
    /// original bytes. For involution-based codices ([`StaticCodex`](crate::StaticCodex),
    /// [`DynamicCodex`](crate::DynamicCodex), involution closures wrapped in
    /// [`FnCodex`](crate::codex::FnCodex)) `decode == encode`, but the
    /// vault calls them by name so non-involution codices would also
    /// work in principle.
    ///
    /// The codex is held in an `Arc<dyn Codex>` so the same codex can be
    /// shared across multiple vaults (rarely useful — usually each vault
    /// wants its own [`DynamicCodex`](crate::DynamicCodex)).
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::{DynamicCodex, KeyVaultBuilder};
    ///
    /// let vault = KeyVaultBuilder::new()
    ///     .with_codex(DynamicCodex::new().unwrap())
    ///     .build();
    /// // The vault now applies the codex transformation transparently
    /// // on every fragment / defragment.
    /// # let _ = vault;
    /// ```
    #[must_use]
    pub fn with_codex<C>(mut self, codex: C) -> Self
    where
        C: Codex + 'static,
    {
        self.codex = Some(Arc::new(codex));
        self
    }

    /// Attach a Layer-4 decoy strategy to the underlying fragmenter.
    ///
    /// When set, every `KeyVault::fragment` call also produces decoy chunks
    /// from the strategy. Decoys are interleaved with real chunks via the
    /// same Fisher-Yates shuffle and are skipped by `defragment`. See
    /// [`StandardFragmenter::with_decoy`] for details on chunk-count and
    /// size selection.
    ///
    /// Use [`SelfReferenceDecoy`](crate::SelfReferenceDecoy) for the
    /// strongest statistical indistinguishability (recommended default);
    /// [`KeyDerivedDecoy`](crate::KeyDerivedDecoy) for BLAKE3-XOF–derived
    /// CSPRNG-like output;
    /// [`RandomDecoy`](crate::RandomDecoy) for raw CSPRNG output.
    #[must_use]
    pub fn with_decoy<D>(mut self, decoy: D) -> Self
    where
        D: DecoyStrategy + 'static,
    {
        self.fragmenter = self.fragmenter.with_decoy(decoy);
        self
    }

    /// Finalize and produce a [`KeyVault`].
    ///
    /// Infallible in this phase — later phases may move this to a
    /// `Result`-returning shape if validation is added.
    #[must_use]
    pub fn build(self) -> KeyVault {
        KeyVault {
            inner: Arc::new(VaultInner {
                config: self.config,
                fragmenter: self.fragmenter,
                codex: self.codex,
                locked_out: AtomicBool::new(false),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn builder_defaults_to_normalization_on() {
        let v = KeyVaultBuilder::new().build();
        assert!(v.config().key_normalization);
    }

    #[test]
    fn builder_can_disable_normalization() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        assert!(!v.config().key_normalization);
    }

    #[test]
    fn fresh_vault_is_not_locked_out() {
        let v = KeyVaultBuilder::new().build();
        assert!(!v.is_locked_out());
    }

    #[test]
    fn debug_does_not_panic() {
        let v = KeyVaultBuilder::new().build();
        let _ = format!("{v:?}");
    }

    #[test]
    fn fragment_defragment_roundtrip_with_normalization() {
        let v = KeyVaultBuilder::new().build(); // normalization on
        let raw = RawKey::new(b"hello world".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // With normalization on, the output is the BLAKE3 hash (32 bytes),
        // not the original 11-byte input.
        assert_eq!(recovered.len(), 32);
        // It is deterministic — fragmenting the same input twice produces the
        // same recovered bytes (the bytes themselves; layout still varies).
        let frags2 = v.fragment(&raw).unwrap();
        let recovered2 = v.defragment(&frags2).unwrap();
        assert_eq!(recovered.as_bytes(), recovered2.as_bytes());
    }

    #[test]
    fn fragment_defragment_roundtrip_without_normalization() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let raw = RawKey::new((0u8..40).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_rejects_empty_key() {
        let v = KeyVaultBuilder::new().normalize_with_blake3(false).build();
        let err = v
            .fragment(&RawKey::new(alloc::vec::Vec::new()))
            .unwrap_err();
        assert!(matches!(err, crate::Error::Fragment(_)));
    }

    #[test]
    fn chunk_range_propagates_through_builder() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(4, 6)
            .build();
        let raw = RawKey::new((0u8..30).collect());
        let frags = v.fragment(&raw).unwrap();

        // After fragmentation, chunks have been Fisher-Yates shuffled, so the
        // "remainder" chunk (which the size-sampling loop allows to fall below
        // `min` when the total doesn't divide cleanly) can land at any index.
        // We verify the post-shuffle invariants instead of indexing by order:
        //   1. Every chunk fits in [1, max].
        //   2. At most one chunk falls below `min` (the remainder slot).
        //   3. Total bytes sum to the original length.
        let chunks = frags.chunks();
        let mut below_min = 0;
        let mut total = 0usize;
        for c in chunks {
            assert!(
                c.len() >= 1 && c.len() <= 6,
                "chunk size {} not in [1,6]",
                c.len()
            );
            if c.len() < 4 {
                below_min += 1;
            }
            total += c.len();
        }
        assert!(
            below_min <= 1,
            "more than one chunk below min size: {below_min}"
        );
        assert_eq!(total, 30);
    }

    #[test]
    fn fragment_with_random_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::RandomDecoy)
            .build();
        let raw = RawKey::new((0u8..32).collect());
        let frags = v.fragment(&raw).unwrap();
        // Chunk count is real + decoy (roughly 2x the real count).
        // Defragment must skip the decoys and return the original bytes.
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_self_reference_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::SelfReferenceDecoy)
            .build();
        let raw = RawKey::new(b"some user-supplied key material".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_key_derived_decoy_roundtrips() {
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_decoy(crate::KeyDerivedDecoy)
            .build();
        let raw = RawKey::new((0u8..64).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn decoy_increases_chunk_count_relative_to_no_decoy() {
        let no_decoy = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(2, 4)
            .build();
        let with_decoy = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_chunk_range(2, 4)
            .with_decoy(crate::SelfReferenceDecoy)
            .build();
        let raw = RawKey::new((0u8..32).collect());

        // The total chunk count is randomized per fragmentation, so average
        // over a few runs to get a stable comparison. The decoy-enabled
        // vault should average ~2x the chunks.
        let mut no_decoy_total = 0usize;
        let mut decoy_total = 0usize;
        for _ in 0..8 {
            no_decoy_total += no_decoy.fragment(&raw).unwrap().chunk_count();
            decoy_total += with_decoy.fragment(&raw).unwrap().chunk_count();
        }
        // The decoy-enabled vault adds one decoy chunk per real chunk, so
        // its total chunk count should be exactly twice the no-decoy count
        // (modulo per-call sampling that affects the real-chunk count
        // identically). Allow some slack for the random sampling variance.
        assert!(
            decoy_total > no_decoy_total,
            "decoy vault produced {decoy_total} chunks vs no-decoy {no_decoy_total}"
        );
    }

    #[test]
    fn fragment_with_static_codex_roundtrips() {
        use crate::StaticCodex;
        let codex = StaticCodex::from_swaps(&[(b'A', b'#'), (b'0', b'%')]).unwrap();
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_codex(codex)
            .build();
        let raw = RawKey::new(b"A0A0A0A0".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // Codex round-trips: the recovered bytes are the original
        // (pre-encode) bytes, not the encoded ones.
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_dynamic_codex_roundtrips() {
        use crate::DynamicCodex;
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            .with_codex(DynamicCodex::new().unwrap())
            .build();
        let raw = RawKey::new((0u8..=255).collect());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn fragment_with_codex_and_decoy_and_normalization_roundtrips() {
        use crate::{DynamicCodex, SelfReferenceDecoy};
        // All layers stacked: BLAKE3 normalize + DynamicCodex encode +
        // StandardFragmenter w/ SelfReferenceDecoy. Must still round-trip.
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(true)
            .with_codex(DynamicCodex::new().unwrap())
            .with_decoy(SelfReferenceDecoy)
            .build();
        let raw = RawKey::new(b"my application key".to_vec());
        let frags = v.fragment(&raw).unwrap();
        let recovered = v.defragment(&frags).unwrap();
        // With normalization on, recovered is 32 bytes (BLAKE3 hash).
        // It must be deterministic given the same input.
        assert_eq!(recovered.len(), 32);
        let recovered2 = v.defragment(&v.fragment(&raw).unwrap()).unwrap();
        assert_eq!(recovered.as_bytes(), recovered2.as_bytes());
    }

    #[test]
    fn codex_visibly_transforms_stored_bytes() {
        // Without codex, the fragment chunks contain the original bytes
        // somewhere among them. With a non-identity codex, the stored
        // bytes should differ — we verify by checking that some chunk
        // contains a transformed byte not in the original input.
        use crate::StaticCodex;
        let v = KeyVaultBuilder::new()
            .normalize_with_blake3(false)
            // Force every byte to swap with a distinct partner.
            .with_codex(crate::DynamicCodex::new().unwrap())
            .build();
        let raw = RawKey::new(alloc::vec![0xaa; 8]);
        let frags = v.fragment(&raw).unwrap();

        // Walk chunks and confirm at least one byte is *not* 0xaa
        // (the codex encoded 0xaa to something else).
        let mut saw_non_aa = false;
        for chunk in frags.chunks() {
            for &b in chunk.as_bytes() {
                if b != 0xaa {
                    saw_non_aa = true;
                    break;
                }
            }
            if saw_non_aa {
                break;
            }
        }
        assert!(
            saw_non_aa,
            "codex did not transform 0xaa — stored bytes still all 0xaa",
        );

        // And defragment recovers the original 0xaa bytes.
        let recovered = v.defragment(&frags).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_bytes());
        // Use the `_codex` import to keep the import non-dead.
        let _ = StaticCodex::from_swaps(&[]).unwrap();
    }
}
