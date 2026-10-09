//! Layer 3: fragmentation.
//!
//! The [`FragmentStrategy`] trait splits a [`RawKey`] into a number of
//! [`Fragments`], each chunk in its own page-locked heap allocation.
//! Reassembly is the inverse operation, performed only when the caller
//! needs to use the key.
//!
//! Fragmentation is **obfuscation**: it stops a scan from finding the key
//! as one contiguous run of bytes. It is not protection against anyone who
//! can read process memory, because the layout buffer that records how to
//! reassemble the chunks lives in the same process memory. Separate heap
//! allocations are usually close together, often on the same page.
//!
//! [`KeyVault`](crate::KeyVault) uses [`StandardFragmenter`] unless another
//! strategy is chosen with
//! [`KeyVaultBuilder::with_fragmenter`](crate::KeyVaultBuilder::with_fragmenter)
//! (or through the `fragment-*` features and
//! [`KeyVaultBuilder::from_features`](crate::KeyVaultBuilder::from_features)).
//!
//! # Writing your own strategy
//!
//! Implement [`FragmentStrategy`]. Read the key with
//! [`RawKey::expose_secret`], build the result with
//! [`Fragments::from_chunks`], and in `defragment_into` read it back with
//! [`Fragments::chunk`], [`Fragments::layout_bytes`] and
//! [`Fragments::total_len`].

use alloc::borrow::Cow;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

mod interleaved;
mod layered;
mod random;
mod standard;
pub(crate) mod util;

pub use self::interleaved::InterleavedFragmenter;
pub use self::layered::LayeredFragmenter;
pub use self::random::RandomFragmenter;
pub use self::standard::StandardFragmenter;

/// Opaque container for the fragmented representation of a key.
///
/// Each chunk lives in its own internal locked buffer (pinned in RAM via
/// `mlock` / `VirtualLock`, excluded from crash dumps where the OS allows
/// it, and zeroed on drop), so chunks are separate heap allocations. They
/// are not necessarily far apart in memory. The layout buffer encodes how
/// the chunks reassemble into the key and is itself locked and zeroed on
/// drop.
///
/// Keys registered in a vault with page protection on are moved into a
/// private page-protected mapping instead; those `Fragments` never leave
/// the vault.
///
/// The chunk and layout accessors exist so you can write your own
/// [`FragmentStrategy`]. Anyone holding a `Fragments` can rebuild the key
/// with the strategy that produced it, so treat it like the key.
pub struct Fragments {
    store: Arc<Store>,
    /// Bytes of the shared layout buffer skipped by this view. Non-zero
    /// only for the views [`LayeredFragmenter`] hands to its
    /// sub-strategies.
    layout_start: usize,
    /// Original length of the unfragmented key, in bytes.
    total_len: usize,
}

/// The buffers behind a [`Fragments`]. Shared (read-only) between a
/// `Fragments` and the views a [`LayeredFragmenter`] creates while
/// defragmenting, so those views copy nothing.
struct Store {
    /// Per-chunk locked buffers.
    chunks: Vec<LockedBytes>,
    /// Strategy-defined layout map.
    layout: LockedBytes,
    /// Page-protected mapping that `chunks` and `layout` point into, if
    /// any. Declared last so the views above are dropped before it.
    #[cfg(any(unix, windows))]
    region: Option<crate::memory::GuardedRegion>,
}

impl Fragments {
    /// Build `Fragments` from chunk bytes and a layout map, for use by a
    /// custom [`FragmentStrategy`].
    ///
    /// Each chunk is copied into its own locked, zero-on-drop buffer and
    /// the layout into another. The layout format is up to the strategy;
    /// the vault never interprets it. `total_len` is the length of the key
    /// the chunks reassemble into, which the vault uses to size the
    /// buffer passed to [`FragmentStrategy::defragment_into`].
    ///
    /// Wipe your own temporary copies of the chunks after this call.
    ///
    /// # Examples
    ///
    /// ```
    /// use key_vault::Fragments;
    ///
    /// // Two chunks, stored in reverse order; the layout records each
    /// // chunk's offset in the key.
    /// let frags = Fragments::from_chunks([&b"world"[..], b"hello "], &[6, 0], 11);
    /// assert_eq!(frags.chunk_count(), 2);
    /// assert_eq!(frags.chunk(1), Some(&b"hello "[..]));
    /// assert_eq!(frags.layout_bytes(), &[6, 0]);
    /// assert_eq!(frags.total_len(), 11);
    /// ```
    #[must_use]
    pub fn from_chunks<I, C>(chunks: I, layout: &[u8], total_len: usize) -> Self
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        let chunks = chunks
            .into_iter()
            .map(|c| LockedBytes::from_slice(c.as_ref()))
            .collect();
        Self::from_parts(chunks, LockedBytes::from_slice(layout), total_len)
    }

    /// Crate-internal: construct from already-prepared chunks and layout.
    pub(crate) fn from_parts(
        chunks: Vec<LockedBytes>,
        layout: LockedBytes,
        total_len: usize,
    ) -> Self {
        Self {
            store: Arc::new(Store {
                chunks,
                layout,
                #[cfg(any(unix, windows))]
                region: None,
            }),
            layout_start: 0,
            total_len,
        }
    }

    /// Length in bytes of the key these fragments reassemble into.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// Number of chunks the original key was split into (decoy chunks
    /// included).
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.store.chunks.len()
    }

    /// The bytes of chunk `index`, or `None` if there is no such chunk.
    #[must_use]
    pub fn chunk(&self, index: usize) -> Option<&[u8]> {
        self.store.chunks.get(index).map(LockedBytes::as_bytes)
    }

    /// The layout map the strategy stored with the chunks.
    #[must_use]
    pub fn layout_bytes(&self) -> &[u8] {
        self.store
            .layout
            .as_bytes()
            .get(self.layout_start..)
            .unwrap_or_default()
    }

    /// Crate-internal: borrow the chunks for defragmentation.
    #[inline]
    pub(crate) fn chunks(&self) -> &[LockedBytes] {
        &self.store.chunks
    }

    /// Crate-internal: the whole layout buffer (tests inspect its pages).
    #[cfg(test)]
    pub(crate) fn layout_buffer(&self) -> &LockedBytes {
        &self.store.layout
    }

    /// Crate-internal: another handle to the same storage. Used by the
    /// vault registry (whose entries are cloned on every update) and by
    /// `with_key`, which keeps the key alive while it reads it.
    #[inline]
    pub(crate) fn share(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            layout_start: self.layout_start,
            total_len: self.total_len,
        }
    }

    /// Crate-internal: a view of the same chunks with the first `skip`
    /// layout bytes hidden. [`LayeredFragmenter`] uses it to hand a
    /// sub-strategy its own layout without copying anything.
    pub(crate) fn view_skipping(&self, skip: usize) -> Self {
        Self {
            store: Arc::clone(&self.store),
            layout_start: self.layout_start.saturating_add(skip),
            total_len: self.total_len,
        }
    }

    /// Crate-internal: take the chunks out, for [`LayeredFragmenter`] to
    /// wrap a sub-strategy's output in its own layout. The chunks are moved
    /// when this is the only handle (always the case for freshly
    /// fragmented output) and copied otherwise.
    pub(crate) fn into_chunks(self) -> Vec<LockedBytes> {
        match Arc::try_unwrap(self.store) {
            Ok(store) => {
                let Store { chunks, .. } = store;
                chunks
            }
            Err(shared) => shared
                .chunks
                .iter()
                .map(|c| LockedBytes::from_slice(c.as_bytes()))
                .collect(),
        }
    }

    /// Crate-internal: move the chunks and layout into a page-protected
    /// region, sealed (inaccessible) on return. The heap copies are wiped
    /// as `self` drops.
    ///
    /// # Errors
    ///
    /// [`Error::MemoryLock`] if the region cannot be mapped or protected.
    #[cfg(any(unix, windows))]
    pub(crate) fn into_protected(self) -> Result<Self> {
        use crate::memory::GuardedRegion;

        let layout = self.layout_bytes();
        let sizes: Vec<usize> = self.chunks().iter().map(LockedBytes::len).collect();
        let total: usize = sizes
            .iter()
            .try_fold(layout.len(), |acc, &n| acc.checked_add(n))
            .ok_or(Error::Internal("fragment storage size overflowed"))?;
        let mut region = GuardedRegion::new(total)?;
        {
            let dst = region.bytes_mut();
            let mut at = 0usize;
            for chunk in self.chunks() {
                let bytes = chunk.as_bytes();
                dst[at..at + bytes.len()].copy_from_slice(bytes);
                at += bytes.len();
            }
            dst[at..at + layout.len()].copy_from_slice(layout);
        }
        let base = region.base();
        let locked = region.is_locked();
        let mut chunks = Vec::with_capacity(sizes.len());
        let mut at = 0usize;
        for n in sizes {
            // SAFETY: `at..at + n` lies inside the region (sized above),
            // and the region is stored in the same `Store`, after the
            // views, so it outlives them. Views are only read while the
            // region is open (see `KeyVault::with_key`).
            chunks.push(unsafe { LockedBytes::region_view(base.add(at), n, locked) });
            at += n;
        }
        // SAFETY: as above, for the layout bytes after the chunks.
        let layout = unsafe { LockedBytes::region_view(base.add(at), layout.len(), locked) };
        region.seal()?;
        Ok(Self {
            store: Arc::new(Store {
                chunks,
                layout,
                region: Some(region),
            }),
            layout_start: 0,
            total_len: self.total_len,
        })
    }

    /// Crate-internal: make the storage readable for the lifetime of the
    /// returned guard. `None` for ordinary (heap) fragments, which are
    /// always readable.
    ///
    /// # Errors
    ///
    /// [`Error::MemoryLock`] if the OS refuses the protection change.
    #[cfg(any(unix, windows))]
    #[inline]
    pub(crate) fn open(&self) -> Result<Option<crate::memory::RegionAccess<'_>>> {
        match &self.store.region {
            None => Ok(None),
            Some(region) => region.open().map(Some),
        }
    }

    /// Crate-internal: the protected region, if any (tests).
    #[cfg(all(test, any(unix, windows)))]
    pub(crate) fn region(&self) -> Option<&crate::memory::GuardedRegion> {
        self.store.region.as_ref()
    }
}

impl fmt::Debug for Fragments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug describes the shape only. It never reads the chunks or the
        // layout (which may be page-protected).
        f.debug_struct("Fragments")
            .field("chunks", &self.store.chunks.len())
            .field("total_len", &self.total_len)
            .field("contents", &"<opaque>")
            .finish_non_exhaustive()
    }
}

// Strategy for splitting and reassembling a key.
///
/// # Implementor contract
///
/// - **Round-trip.** For every `key`,
///   `self.defragment(&self.fragment(&key)?)?` must produce a [`RawKey`] equal
///   to `key` byte-for-byte. This invariant is the basis of all property
///   tests in later phases.
/// - **Variable layout per call.** Two consecutive calls to `fragment` on the
///   same input must produce [`Fragments`] with distinct internal layouts. If
///   a strategy is deterministic it should document the threat trade-off
///   explicitly.
/// - **No allocation beyond the produced [`Fragments`].** Hot-path defragment
///   should write into a single contiguous output buffer rather than spread
///   work across many intermediate allocations.
/// - **`Send + Sync`.** A strategy may be invoked from any thread.
pub trait FragmentStrategy: Send + Sync {
    /// Split a key into the strategy-defined fragmented representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Fragment`] on configuration
    /// inconsistency (for example a strategy that requires a minimum key
    /// length and was handed a shorter input).
    fn fragment(&self, key: &RawKey) -> Result<Fragments>;

    /// Reassemble fragments into the original raw key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`] if the layout
    /// disagrees with what this strategy produced. The vault will not
    /// attempt to retry — a defragmentation failure indicates corruption or
    /// a mismatched strategy.
    fn defragment(&self, fragments: &Fragments) -> Result<RawKey>;

    /// Reassemble fragments directly into a caller-supplied buffer.
    ///
    /// This is the hot-path entry point used by
    /// [`KeyVault::with_key`](crate::KeyVault::with_key): callers
    /// supply a scratch buffer (typically a thread-local), the strategy
    /// writes the recovered bytes in place, and no [`RawKey`] /
    /// `Vec<u8>` allocation occurs.
    ///
    /// `out.len()` must equal `fragments.total_len()`. Implementations
    /// must return [`Error::Defragment`] if the
    /// supplied slice is the wrong size.
    ///
    /// The default implementation falls back to
    /// [`defragment`](Self::defragment) and copies — overriding this method
    /// is the cheap way to opt into the zero-allocation hot path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Defragment`] when
    /// `out.len() != fragments.total_len()` or the underlying defragment
    /// fails.
    fn defragment_into(&self, fragments: &Fragments, out: &mut [u8]) -> Result<()> {
        if out.len() != fragments.total_len() {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "scratch buffer size does not match fragments.total_len()",
            )));
        }
        let raw = self.defragment(fragments)?;
        out.copy_from_slice(raw.as_bytes());
        Ok(())
    }

    /// Short identifier for audit and error attribution.
    fn describe(&self) -> Cow<'_, str>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn from_chunks_round_trips_through_the_accessors() {
        let f = Fragments::from_chunks([&[1u8, 2][..], &[3]], &[9, 8, 7], 3);
        assert_eq!(f.chunk_count(), 2);
        assert_eq!(f.chunk(0), Some(&[1u8, 2][..]));
        assert_eq!(f.chunk(1), Some(&[3u8][..]));
        assert_eq!(f.chunk(2), None);
        assert_eq!(f.layout_bytes(), &[9, 8, 7]);
        assert_eq!(f.view_skipping(1).layout_bytes(), &[8, 7]);
        assert_eq!(f.view_skipping(5).layout_bytes(), [0u8; 0]);
        assert_eq!(f.total_len(), 3);
    }

    #[test]
    fn fragments_debug_is_opaque() {
        let chunks = alloc::vec![LockedBytes::from_slice(&[1, 2, 3])];
        let layout = LockedBytes::from_slice(&[0, 0, 0, 0]);
        let f = Fragments::from_parts(chunks, layout, 3);
        let rendered = format!("{f:?}");
        assert!(rendered.contains("<opaque>"));
        assert!(rendered.contains("chunks: 1"));
        assert!(rendered.contains("total_len: 3"));
    }
}
