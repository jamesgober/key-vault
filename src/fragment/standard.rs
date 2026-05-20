//! [`StandardFragmenter`] — the baseline Layer 3 implementation.
//!
//! `StandardFragmenter` splits the raw key into variable-size chunks whose
//! lengths are sampled uniformly from `[frag_min, frag_max]`, applies a
//! random Fisher-Yates permutation, allocates each chunk in its own
//! [`LockedBytes`] buffer (so chunks are at independent heap addresses),
//! and stores the reconstruction order in a separately-locked layout
//! buffer.
//!
//! Two consecutive calls to `fragment` on the same key produce
//! [`Fragments`] with different chunk counts, different chunk sizes, and
//! different orderings. The randomness is sourced from
//! [`getrandom`](https://docs.rs/getrandom), the OS CSPRNG.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{FragmentStrategy, Fragments};
use crate::Result;
use crate::error::Error;
use crate::fetcher::RawKey;
use crate::memory::LockedBytes;

/// Default minimum chunk size — small enough to avoid leaking the
/// fragmentation boundary, large enough to keep the chunk count
/// reasonable.
const DEFAULT_MIN_CHUNK: usize = 1;

/// Default maximum chunk size. Eight bytes is large enough to amortize
/// per-chunk overhead and small enough that a 32-byte symmetric key still
/// produces several chunks.
const DEFAULT_MAX_CHUNK: usize = 8;

/// Variable-chunk + shuffle fragmenter. Default Layer 3 implementation.
///
/// Construct with [`StandardFragmenter::new`] for the default chunk-size
/// range, or [`StandardFragmenter::with_chunk_range`] to customize.
///
/// # Examples
///
/// Typical use is through [`KeyVaultBuilder`](crate::KeyVaultBuilder), which
/// owns a `StandardFragmenter` internally. `RawKey` deliberately does not
/// expose its bytes to outside callers, so we verify the round-trip by
/// length:
///
/// ```
/// use key_vault::{KeyVaultBuilder, RawKey};
///
/// let vault = KeyVaultBuilder::new()
///     .normalize_with_blake3(false)
///     .with_chunk_range(2, 4)
///     .build();
///
/// let original_len = b"some key material".len();
/// let raw = RawKey::new(b"some key material".to_vec());
/// let frags = vault.fragment(&raw).unwrap();
/// let recovered = vault.defragment(&frags).unwrap();
/// assert_eq!(recovered.len(), original_len);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StandardFragmenter {
    min_chunk: usize,
    max_chunk: usize,
}

impl Default for StandardFragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardFragmenter {
    /// Construct a fragmenter with the default chunk-size range
    /// (`min = 1`, `max = 8`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_chunk: DEFAULT_MIN_CHUNK,
            max_chunk: DEFAULT_MAX_CHUNK,
        }
    }

    /// Construct a fragmenter with a custom chunk-size range. `min` must be
    /// at least 1 and `max` must be at least `min`; both are clamped at
    /// construction.
    ///
    /// Larger maxima reduce the chunk count (lower memory overhead, less
    /// scatter). Smaller maxima increase the chunk count (more scatter,
    /// higher memory overhead). The default of 1-8 strikes a balance
    /// validated by the round-trip + multi-fragmentation tests.
    #[must_use]
    pub fn with_chunk_range(min: usize, max: usize) -> Self {
        let min = min.max(1);
        let max = max.max(min);
        Self {
            min_chunk: min,
            max_chunk: max,
        }
    }
}

impl FragmentStrategy for StandardFragmenter {
    fn fragment(&self, key: &RawKey) -> Result<Fragments> {
        let bytes = key.as_bytes();
        let total_len = bytes.len();
        if total_len == 0 {
            return Err(Error::Fragment(alloc::string::ToString::to_string(
                "empty key cannot be fragmented",
            )));
        }

        // Step 1: choose chunk sizes that sum to total_len. We sample each
        // size uniformly from [min_chunk, max_chunk]; the last chunk
        // absorbs any remainder (within range) so the sum is exact.
        let sizes = sample_chunk_sizes(total_len, self.min_chunk, self.max_chunk)?;
        let n_chunks = sizes.len();

        // Step 2: build (original_offset, byte_slice) pairs in original
        // order. We hold them in an intermediate Vec just long enough to
        // permute; the bytes never live in a separate owned buffer.
        let mut originals: Vec<(u32, &[u8])> = Vec::with_capacity(n_chunks);
        {
            let mut offset = 0usize;
            for &size in &sizes {
                // Offsets fit in u32 since key lengths are bounded by the
                // RawKey contract; we still cap defensively.
                let offset_u32 = u32::try_from(offset).map_err(|_| {
                    Error::Fragment(alloc::string::ToString::to_string(
                        "key too large for fragmentation",
                    ))
                })?;
                originals.push((offset_u32, &bytes[offset..offset + size]));
                offset += size;
            }
        }

        // Step 3: shuffle the originals vector via Fisher-Yates.
        fisher_yates(&mut originals)?;

        // Step 4: allocate each chunk into its own LockedBytes — each
        // landing at an independent heap address.
        let mut chunks: Vec<LockedBytes> = Vec::with_capacity(n_chunks);
        for &(_, slice) in &originals {
            chunks.push(LockedBytes::from_slice(slice));
        }

        // Step 5: encode the layout (original_offset for each shuffled
        // position) into a single locked buffer.
        let mut layout_bytes: Vec<u8> = Vec::with_capacity(n_chunks * 4);
        for &(offset, _) in &originals {
            layout_bytes.extend_from_slice(&offset.to_le_bytes());
        }
        let layout = LockedBytes::from_slice(&layout_bytes);
        // Scrub the temporary plaintext copy.
        zero_buffer(&mut layout_bytes);
        // Drop intermediate so it doesn't outlive scrubbing.
        drop(layout_bytes);
        // Also drop the originals vector so the borrowed slices into the
        // input key are released promptly.
        drop(originals);

        Ok(Fragments::from_parts(chunks, layout, total_len))
    }

    fn defragment(&self, fragments: &Fragments) -> Result<RawKey> {
        let n_chunks = fragments.chunk_count();
        let layout = fragments.layout().as_bytes();
        if layout.len() != n_chunks * 4 {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "layout buffer length does not match chunk count",
            )));
        }

        // Read each original-offset, pair with its chunk, sort by offset to
        // recover the original ordering.
        let mut paired: Vec<(u32, &LockedBytes)> = Vec::with_capacity(n_chunks);
        for (i, chunk) in fragments.chunks().iter().enumerate() {
            let raw: [u8; 4] = layout[i * 4..i * 4 + 4].try_into().map_err(|_| {
                Error::Defragment(alloc::string::ToString::to_string(
                    "layout buffer slice did not size to u32",
                ))
            })?;
            paired.push((u32::from_le_bytes(raw), chunk));
        }
        paired.sort_by_key(|&(offset, _)| offset);

        // Concatenate into an exact-capacity output buffer. The caller's
        // RawKey takes ownership; in Phase 0.3 the bytes still live in a
        // plain Vec on this temporary contiguous buffer. Future phases
        // route the output through a Zeroizing wrapper at the public-API
        // boundary.
        let mut out: Vec<u8> = Vec::with_capacity(fragments.total_len());
        for (_, chunk) in paired {
            out.extend_from_slice(chunk.as_bytes());
        }

        if out.len() != fragments.total_len() {
            return Err(Error::Defragment(alloc::string::ToString::to_string(
                "reassembled length does not match recorded total",
            )));
        }

        Ok(RawKey::new(out))
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("standard")
    }
}

/// Sample chunk sizes summing exactly to `total`, with each size in
/// `[min, max]` except possibly the last (which absorbs any short
/// remainder).
fn sample_chunk_sizes(total: usize, min: usize, max: usize) -> Result<Vec<usize>> {
    if min == 0 || max < min {
        return Err(Error::Fragment(alloc::string::ToString::to_string(
            "invalid chunk-size range",
        )));
    }
    let mut sizes: Vec<usize> = Vec::new();
    let mut remaining = total;
    while remaining > 0 {
        if remaining <= max {
            // The remaining bytes fit in a single chunk that respects max.
            // We can either take the whole remainder as one chunk, or split
            // it into two when remaining > max + 1 — but we are in the
            // `<= max` branch, so a single chunk is fine.
            sizes.push(remaining);
            remaining = 0;
        } else {
            let pick = sample_range(min, max)?;
            // Ensure we leave at least `min` bytes for at least one more
            // chunk; otherwise pick a size such that `remaining - pick >=
            // min`.
            let pick = pick.min(remaining.saturating_sub(min));
            // `pick` could now be < min; clamp.
            let pick = pick.max(min).min(max).min(remaining);
            sizes.push(pick);
            remaining -= pick;
        }
    }
    Ok(sizes)
}

/// Inclusive uniform sample from `[min, max]` using the OS CSPRNG.
fn sample_range(min: usize, max: usize) -> Result<usize> {
    debug_assert!(min <= max);
    let span = max - min + 1;
    let r = random_u64()?;
    // Modulo bias is negligible at the small spans we use here. A 64-bit
    // input mod a span <= 64 has bias on the order of 2^-58. We compute
    // `r % span` in u64 space; the result is always < span and therefore
    // fits in usize on every supported target.
    let span_u64 = span as u64;
    let reduced = r % span_u64;
    // The reduction fits in usize because `reduced < span` and `span` is a
    // usize by construction.
    #[allow(clippy::cast_possible_truncation)]
    let reduced_usize = reduced as usize;
    Ok(min + reduced_usize)
}

fn random_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Internal("OS RNG failed"))?;
    Ok(u64::from_le_bytes(buf))
}

fn fisher_yates<T>(slice: &mut [T]) -> Result<()> {
    let len = slice.len();
    if len < 2 {
        return Ok(());
    }
    // Standard Fisher-Yates: walk from the last index down to 1, swapping
    // each element with a uniformly-chosen earlier index (inclusive).
    let mut i = len - 1;
    while i > 0 {
        let j_span = (i + 1) as u64;
        let r = random_u64()?;
        let reduced = r % j_span;
        // `reduced < j_span` and `j_span = i + 1 <= len`, so it always fits
        // in usize.
        #[allow(clippy::cast_possible_truncation)]
        let j = reduced as usize;
        slice.swap(i, j);
        i -= 1;
    }
    Ok(())
}

/// Volatile-zero a Vec<u8> we no longer need. Used for the intermediate
/// `layout_bytes` Vec; the in-tree [`LockedBytes`] takes care of its own
/// buffer.
fn zero_buffer(buf: &mut [u8]) {
    // SAFETY: `buf.as_mut_ptr()` is the start of a valid `buf.len()`-byte
    // slice; we write within bounds and only once per element.
    unsafe {
        let ptr = buf.as_mut_ptr();
        for i in 0..buf.len() {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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

    /// Build a `RawKey` with arbitrary bytes.
    fn key(bytes: &[u8]) -> RawKey {
        RawKey::new(bytes.to_vec())
    }

    #[test]
    fn round_trip_short_key() {
        let frag = StandardFragmenter::new();
        let original = key(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.len(), 10);
        assert_eq!(recovered.as_bytes(), original.as_bytes());
    }

    #[test]
    fn round_trip_256_bit_key() {
        let frag = StandardFragmenter::new();
        let bytes: Vec<u8> = (0..32).map(|i| (i * 7) as u8).collect();
        let original = key(&bytes);
        let fragments = frag.fragment(&original).unwrap();
        let recovered = frag.defragment(&fragments).unwrap();
        assert_eq!(recovered.as_bytes(), &bytes[..]);
    }

    #[test]
    fn round_trip_for_many_sizes() {
        let frag = StandardFragmenter::new();
        for len in [1usize, 7, 16, 32, 64, 128, 255, 256, 500, 1024, 4096] {
            let bytes: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let original = key(&bytes);
            let fragments = frag.fragment(&original).expect("fragment");
            let recovered = frag.defragment(&fragments).expect("defragment");
            assert_eq!(
                recovered.as_bytes(),
                &bytes[..],
                "round-trip mismatch for len = {len}"
            );
        }
    }

    #[test]
    fn two_calls_produce_different_layouts() {
        let frag = StandardFragmenter::new();
        let bytes: Vec<u8> = (0..32).map(|i| (i ^ 0x5a) as u8).collect();
        let original = key(&bytes);

        let a = frag.fragment(&original).unwrap();
        let b = frag.fragment(&original).unwrap();

        // At 32 bytes with chunk sizes 1..=8, the probability of two
        // consecutive fragmentations producing identical layout AND
        // identical chunk counts is astronomically small. Treat a match
        // as a strong signal of broken randomness rather than coincidence.
        let same_count = a.chunk_count() == b.chunk_count();
        let same_layout = same_count && a.layout().as_bytes() == b.layout().as_bytes();
        assert!(
            !(same_count && same_layout),
            "two consecutive fragmentations produced the same layout"
        );

        // Both still round-trip cleanly.
        assert_eq!(frag.defragment(&a).unwrap().as_bytes(), &bytes[..]);
        assert_eq!(frag.defragment(&b).unwrap().as_bytes(), &bytes[..]);
    }

    #[test]
    fn chunk_sizes_respect_configured_range() {
        let frag = StandardFragmenter::with_chunk_range(2, 4);
        let bytes: Vec<u8> = (0..32).collect();
        let original = key(&bytes);
        let fragments = frag.fragment(&original).unwrap();

        // Chunks are Fisher-Yates shuffled, so the "remainder" chunk (which
        // may fall below `min` when the total length doesn't divide cleanly)
        // can land at any index. We verify the post-shuffle invariants:
        //   1. Every chunk size is in [1, max].
        //   2. At most one chunk falls below `min` (the remainder).
        //   3. Total bytes sum to the original length.
        let chunks = fragments.chunks();
        let mut below_min = 0;
        let mut total = 0usize;
        for c in chunks {
            assert!(
                c.len() >= 1 && c.len() <= 4,
                "chunk size {} not in [1,4]",
                c.len()
            );
            if c.len() < 2 {
                below_min += 1;
            }
            total += c.len();
        }
        assert!(
            below_min <= 1,
            "more than one chunk below min size: {below_min}"
        );
        assert_eq!(total, 32);

        assert_eq!(frag.defragment(&fragments).unwrap().as_bytes(), &bytes[..]);
    }

    #[test]
    fn empty_key_rejected() {
        let frag = StandardFragmenter::new();
        let empty = key(&[]);
        let err = frag.fragment(&empty).unwrap_err();
        assert!(matches!(err, Error::Fragment(_)));
    }

    #[test]
    fn describe_returns_standard() {
        let frag = StandardFragmenter::new();
        assert_eq!(frag.describe(), "standard");
    }

    #[test]
    fn stress_round_trip_thousand_iterations() {
        let frag = StandardFragmenter::new();
        let bytes: Vec<u8> = (0..32).map(|i| ((i * 13) ^ 0xa5) as u8).collect();
        let original = key(&bytes);
        for _ in 0..1000 {
            let fragments = frag.fragment(&original).expect("fragment");
            let recovered = frag.defragment(&fragments).expect("defragment");
            assert_eq!(recovered.as_bytes(), &bytes[..]);
        }
    }
}
