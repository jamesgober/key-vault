//! Helpers shared across [`FragmentStrategy`](super::FragmentStrategy)
//! implementations.
//!
//! These are all crate-private; they are not part of the public API.

use alloc::vec::Vec;

use crate::Result;
use crate::error::Error;

/// Inclusive uniform sample from `[min, max]` using the OS CSPRNG.
///
/// Used by all fragmenters to pick chunk sizes and shuffle indices.
///
/// # Errors
///
/// Returns [`Error::Internal`](crate::Error::Internal) if the OS CSPRNG
/// fails. `getrandom` failure is a hard system-level event that the vault
/// cannot meaningfully recover from on its own; the caller is informed and
/// the operation aborts.
pub(crate) fn sample_range(min: usize, max: usize) -> Result<usize> {
    debug_assert!(min <= max);
    let span = max - min + 1;
    let r = random_u64()?;
    let span_u64 = span as u64;
    let reduced = r % span_u64;
    // `reduced < span` and `span` is a usize by construction, so the cast
    // is always lossless.
    #[allow(clippy::cast_possible_truncation)]
    let reduced_usize = reduced as usize;
    Ok(min + reduced_usize)
}

/// Single 64-bit draw from the OS CSPRNG.
pub(crate) fn random_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Internal("OS RNG failed"))?;
    Ok(u64::from_le_bytes(buf))
}

/// In-place Fisher-Yates shuffle backed by [`random_u64`].
///
/// Slices of length < 2 are left unchanged.
pub(crate) fn fisher_yates<T>(slice: &mut [T]) -> Result<()> {
    let len = slice.len();
    if len < 2 {
        return Ok(());
    }
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

/// Volatile-zero a byte slice and emit a `SeqCst` compiler fence. Used to
/// scrub intermediate plaintext buffers (layout encodings, decoy temp
/// buffers) before their `Vec` storage is dropped.
pub(crate) fn zero_buffer(buf: &mut [u8]) {
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

/// Volatile-zero an owned `Vec<u8>` and drop it. Convenience wrapper used
/// when a decoy strategy hands back a fresh plaintext `Vec` that we
/// immediately copy into a [`LockedBytes`](crate::memory::LockedBytes).
pub(crate) fn zero_buffer_owned(mut buf: Vec<u8>) {
    zero_buffer(&mut buf);
    drop(buf);
}
