//! [`InterleavedFragmenter`] — byte-level placement in a single large pool.
//!
//! `InterleavedFragmenter` allocates **one** [`LockedBytes`] buffer larger
//! than the key (by a configurable factor) and writes individual key bytes
//! at randomly-chosen positions within it. The positions in between are
//! filled with random padding bytes. The layout records, for each key
//! byte, where it lives in the pool.
//!
//! # When to use
//!
//! `InterleavedFragmenter` defeats statistical analysis at the byte
//! granularity: the pool's byte-value distribution is roughly uniform
//! (random padding), so an attacker scanning the buffer cannot easily
//! distinguish key bytes from padding. The trade-off is that the pool is
//! contiguous in memory (a single allocation), which is a weaker defense
//! against contiguous-read attacks than
//! [`StandardFragmenter`](super::StandardFragmenter)'s per-chunk
//! allocations.
//!
//! Best paired with [`LayeredFragmenter`](super::LayeredFragmenter) to
//! combine the byte-level distribution defense with chunk-level scatter.
//!
//! # Layout encoding
//!
//! ```text
//! layout = [pool_size: u32 LE,
//!           pos[0]: u32 LE, pos[1]: u32 LE, ..., pos[key_len-1]: u32 LE]
//! ```
//!
//! Where `pos[i]` is the position in the pool of key byte `i`. The first
//! four bytes carry the pool size so `defragment` can sanity-check.

use alloc::borrow::Cow;
use alloc::vec;
use alloc::vec::Vec;

use super::util::{fisher_yates, zero_buffer};
use super::{FragmentStrategy, Fragments};
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

/// Default pool-size multiplier: pool is `key_len * 4` bytes.
const DEFAULT_POOL_FACTOR: usize = 4;

/// Byte-interleaving Layer 3 fragmenter.
///
/// See the module-level docs for the threat-model trade-off vs.
/// [`StandardFragmenter`](super::StandardFragmenter).
#[derive(Debug, Clone, Copy)]
pub struct InterleavedFragmenter {
    pool_factor: usize,
}

impl Default for InterleavedFragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl InterleavedFragmenter {
    /// Construct with the default pool factor (4× the key length).
    #[must_use]
    pub fn new() -> Self {
        Self {
            pool_factor: DEFAULT_POOL_FACTOR,
        }
    }

    /// Construct with a custom pool-size multiplier. `factor` is clamped to
    /// `>= 2` — a factor of 1 would mean "no padding", defeating the point
    /// of the strategy.
    ///
    /// Larger factors raise memory overhead proportionally but make
    /// statistical recovery harder.
    #[must_use]
    pub fn with_pool_factor(factor: usize) -> Self {
        Self {
            pool_factor: factor.max(2),
        }
    }
}

impl FragmentStrategy for InterleavedFragmenter {
    // The `pool_size as u32` casts are bounded by the
    // `pool_size > u32::MAX` check above; the cast is sound.
    #[allow(clippy::cast_possible_truncation)]
    fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        let bytes = key.as_bytes();
        let key_len = bytes.len();
        if key_len == 0 {
            return Err(Error::Fragment(alloc::string::ToString::to_string(
                "empty key cannot be fragmented",
            )));
        }
        let pool_size = key_len.checked_mul(self.pool_factor).ok_or_else(|| {
            Error::Fragment(alloc::string::ToString::to_string("pool size overflowed"))
        })?;
        if pool_size > u32::MAX as usize {
            return Err(Error::Fragment(alloc::string::ToString::to_string(
                "pool size exceeds u32 layout encoding",
            )));
        }

        // Step 1: choose key_len distinct random positions in `[0, pool_size)`
        // by shuffling `[0, pool_size)` and taking the first key_len. For
        // small pools this is cheap; we cap pool_factor in the builder so
        // it can't blow up.
        let mut all_positions: Vec<u32> = (0..pool_size as u32).collect();
        fisher_yates(&mut all_positions)?;
        all_positions.truncate(key_len);
        let positions = all_positions;

        // Step 2: build the pool. Start with random padding, then overlay
        // key bytes at the chosen positions.
        let mut pool: Vec<u8> = vec![0u8; pool_size];
        getrandom::getrandom(&mut pool).map_err(|_| Error::Internal("OS RNG failed"))?;
        for (i, &pos) in positions.iter().enumerate() {
            pool[pos as usize] = bytes[i];
        }

        // Step 3: chunk lives as a single LockedBytes — the pool itself.
        // We split here only because the public Fragments API takes a
        // Vec<LockedBytes>; conceptually it's one chunk.
        let chunk = LockedBytes::from_slice(&pool);
        zero_buffer(&mut pool);
        drop(pool);

        // Step 4: encode the layout.
        let mut layout_bytes: Vec<u8> = Vec::with_capacity(4 + key_len * 4);
        layout_bytes.extend_from_slice(&(pool_size as u32).to_le_bytes());
        for pos in &positions {
            layout_bytes.extend_from_slice(&pos.to_le_bytes());
        }
        let layout = LockedBytes::from_slice(&layout_bytes);
        zero_buffer(&mut layout_bytes);
        drop(layout_bytes);
        drop(positions);

        Ok(Fragments::from_parts(alloc::vec![chunk], layout, key_len))
    }

    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        let chunks = fragments.chunks();
        if chunks.len() != 1 {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "interleaved fragments expects exactly one chunk",
            )));
        }
        let pool = &chunks[0];
        let layout = fragments.layout().as_bytes();
        let key_len = fragments.total_len();

        if layout.len() != 4 + key_len * 4 {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "interleaved layout size does not match key length",
            )));
        }
        let pool_size_raw: [u8; 4] = layout[0..4]
            .try_into()
            .map_err(|_| Error::Defragment(alloc::string::ToString::to_string("layout slice")))?;
        let pool_size = u32::from_le_bytes(pool_size_raw) as usize;
        if pool_size != pool.as_bytes().len() {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "interleaved layout pool size disagrees with chunk size",
            )));
        }

        let pool_bytes = pool.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(key_len);
        for i in 0..key_len {
            let raw: [u8; 4] = layout[4 + i * 4..4 + (i + 1) * 4].try_into().map_err(|_| {
                Error::Defragment(alloc::string::ToString::to_string("layout slice"))
            })?;
            let pos = u32::from_le_bytes(raw) as usize;
            if pos >= pool_size {
                return Err(Error::Defragment(alloc::string::ToString::to_string(
                    "interleaved layout position out of range",
                )));
            }
            out.push(pool_bytes[pos]);
        }

        Ok(RawKey::new(out))
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("interleaved")
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

    fn key(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn round_trip_short_key() {
        let frag = InterleavedFragmenter::new();
        let original = key(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.as_bytes(), original.as_bytes());
    }

    #[test]
    fn round_trip_many_sizes() {
        let frag = InterleavedFragmenter::new();
        for len in [1usize, 7, 16, 32, 64, 128, 256, 500, 1024] {
            let bytes: Vec<u8> = (0..len).map(|i| ((i * 17) & 0xff) as u8).collect();
            let original = key(&bytes);
            let fragments = frag.fragment(&original).unwrap();
            let recovered = frag.defragment(&fragments).unwrap();
            assert_eq!(recovered.as_bytes(), &bytes[..], "mismatch at len {len}");
        }
    }

    #[test]
    fn empty_key_rejected() {
        let frag = InterleavedFragmenter::new();
        let err = frag.fragment(&key(&[])).unwrap_err();
        assert!(matches!(err, Error::Fragment(_)));
    }

    #[test]
    fn custom_pool_factor_changes_pool_size() {
        let small = InterleavedFragmenter::with_pool_factor(2);
        let large = InterleavedFragmenter::with_pool_factor(8);
        let bytes: Vec<u8> = (0..16).collect();
        let original = key(&bytes);
        let s = small.fragment(&original).unwrap();
        let l = large.fragment(&original).unwrap();
        assert_eq!(s.chunks()[0].as_bytes().len(), 16 * 2);
        assert_eq!(l.chunks()[0].as_bytes().len(), 16 * 8);
    }

    #[test]
    fn pool_factor_one_is_clamped_to_two() {
        let frag = InterleavedFragmenter::with_pool_factor(1);
        let bytes: Vec<u8> = (0..16).collect();
        let original = key(&bytes);
        let fragments = frag.fragment(&original).unwrap();
        assert_eq!(fragments.chunks()[0].as_bytes().len(), 16 * 2);
    }

    #[test]
    fn describe_returns_interleaved() {
        assert_eq!(InterleavedFragmenter::new().describe(), "interleaved");
    }
}
