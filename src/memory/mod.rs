//! Layer 2 + Layer 7 — page-locked, zero-on-drop byte buffers.
//!
//! [`LockedBytes`] is the in-crate primitive for storing bytes that
//! **must not** be swapped to disk and **must** be overwritten when freed.
//! Every fragment, every position map, and (in later phases) every codex
//! table is held inside a `LockedBytes`. The wrapper combines two POSIX /
//! Win32 behaviors:
//!
//! - **Page locking** via `mlock(2)` on Unix and `VirtualLock` on Windows.
//!   This pins the pages backing the buffer to RAM so the OS will not
//!   write them to swap or hibernation files. If the call fails (most
//!   often because the process has hit its `RLIMIT_MEMLOCK`), the buffer
//!   is still usable — we report the failure on the type and continue.
//!   The caller can inspect [`LockedBytes::is_locked`] to surface the
//!   condition to operators.
//!
//! - **Zero-on-drop** — we overwrite every byte with `0` before the
//!   backing allocation is returned to the allocator. Implemented with
//!   `core::ptr::write_volatile` + a compiler fence so the writes cannot
//!   be optimized away. The `zeroize` crate is functionally equivalent;
//!   we keep an in-crate implementation here so this module has no
//!   dependency on the `zeroize` feature being enabled.
//!
//! # Drop order
//!
//! `Drop` overwrites the bytes *first* and then `munlock`s the pages.
//! The order matters: the kernel must still consider the pages locked
//! while we are writing to them, otherwise a concurrent swap-out could
//! observe the pre-zero data. After `munlock` the `Vec<u8>` destructor
//! returns the allocation to the system.

use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// A page-locked, zero-on-drop byte buffer.
///
/// Construction copies the input bytes into a freshly-allocated buffer with
/// exact capacity, attempts to `mlock` (Unix) or `VirtualLock` (Windows) the
/// allocation, and records whether the lock succeeded. The bytes are
/// accessible through [`LockedBytes::as_bytes`] until the value is dropped;
/// at drop, the buffer is zeroed and unlocked.
///
/// `LockedBytes` is intentionally not `Clone` — duplicating key material
/// silently is the kind of mistake we built this crate to prevent.
pub(crate) struct LockedBytes {
    data: Vec<u8>,
    /// `true` if the OS confirmed the page lock. `false` if the lock failed
    /// (e.g. `EPERM` / `ENOMEM` from `mlock`, hit `RLIMIT_MEMLOCK`).
    locked: bool,
}

impl LockedBytes {
    /// Construct a new locked buffer from a slice.
    ///
    /// Always succeeds — if the OS rejects the lock request the buffer is
    /// returned with [`LockedBytes::is_locked`] reporting `false`, never with
    /// an error. The caller decides whether reduced-security mode is
    /// acceptable.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        // Allocate exactly the right size and never resize: any growth would
        // realloc and the OS lock would refer to a stale address.
        let mut data: Vec<u8> = Vec::with_capacity(bytes.len());
        data.extend_from_slice(bytes);
        debug_assert_eq!(data.capacity(), data.len());

        let locked = if data.is_empty() {
            false
        } else {
            // SAFETY: `data.as_ptr()` points to a live `data.len()`-byte
            // allocation we just constructed; we do not free or move it
            // before the corresponding `munlock`/`VirtualUnlock` in `Drop`.
            unsafe { lock_pages(data.as_ptr(), data.len()) }
        };

        Self { data, locked }
    }

    /// Borrow the protected bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Length of the protected buffer.
    #[allow(dead_code)] // accessor reserved for monitor / audit reporting in Phase 0.8.
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// `true` iff the OS confirmed the page lock at construction time.
    ///
    /// A `false` value is not an error in itself — it means the kernel
    /// declined the lock (usually because the process is over its
    /// `RLIMIT_MEMLOCK`). The buffer still zeroes on drop and is otherwise
    /// equivalent; the only weakened guarantee is swap protection.
    #[allow(dead_code)] // surfaced through monitor / audit hooks in Phase 0.8.
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        if !self.data.is_empty() {
            // Step 1: overwrite the bytes while the lock (if held) is still
            // in place. `write_volatile` defeats dead-store elimination; the
            // fence prevents the compiler from reordering subsequent loads
            // ahead of the writes.
            //
            // We deliberately do not use `Vec::iter_mut` + `*b = 0` here:
            // the compiler is free to delete those writes since the Vec is
            // about to drop. Volatile is the documented escape hatch.
            //
            // SAFETY: `ptr` is the start of a valid `len`-byte allocation
            // owned by `self.data`; both are still alive at this point in
            // `Drop`. We write within `0..len` only.
            unsafe {
                let ptr = self.data.as_mut_ptr();
                for i in 0..self.data.len() {
                    core::ptr::write_volatile(ptr.add(i), 0u8);
                }
            }
            atomic::compiler_fence(atomic::Ordering::SeqCst);

            // Step 2: unlock pages now that they have been overwritten.
            if self.locked {
                // SAFETY: the pointer/length pair refers to the same
                // allocation we passed to `lock_pages` in `from_slice` —
                // we never mutate `data`'s buffer pointer/capacity between
                // those calls.
                unsafe {
                    unlock_pages(self.data.as_ptr(), self.data.len());
                }
            }
        }
        // Step 3: drop the Vec normally. Allocation returns to the system.
    }
}

impl fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedBytes")
            .field("len", &self.data.len())
            .field("locked", &self.locked)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(unix)]
use self::unix::{lock_pages, unlock_pages};
#[cfg(windows)]
use self::windows::{lock_pages, unlock_pages};

#[cfg(not(any(unix, windows)))]
unsafe fn lock_pages(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
unsafe fn unlock_pages(_ptr: *const u8, _len: usize) {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn round_trips_bytes() {
        let input = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5];
        let buf = LockedBytes::from_slice(&input);
        assert_eq!(buf.as_bytes(), &input);
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn empty_buffer_is_unlocked() {
        let buf = LockedBytes::from_slice(&[]);
        assert_eq!(buf.len(), 0);
        assert!(!buf.is_locked());
        assert!(buf.as_bytes().is_empty());
    }

    #[test]
    fn debug_is_redacted() {
        let buf = LockedBytes::from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{buf:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("de"));
        assert!(!rendered.contains("ad"));
        assert!(rendered.contains("len"));
        assert!(rendered.contains("locked"));
    }

    #[test]
    fn many_small_buffers_do_not_leak_within_run() {
        // Smoke test for the construct/drop cycle. We don't assert on memory
        // residency — that requires dhat — but we want this exercised in CI
        // to catch obvious unsoundness with sanitizers.
        for size in [1, 7, 32, 64, 256, 4096] {
            let bytes: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            let buf = LockedBytes::from_slice(&bytes);
            assert_eq!(buf.as_bytes(), &bytes[..]);
            drop(buf);
        }
    }
}
