//! Layer 2 + Layer 7: page-locked, zero-on-drop byte buffers.
//!
//! [`LockedBytes`] is the in-crate primitive for storing bytes that
//! should not be swapped to disk and must be overwritten when freed.
//! Every fragment, every layout map and every codex table is held inside
//! a `LockedBytes`. The wrapper combines two behaviors:
//!
//! - **Page locking** via `mlock(2)` on Unix and `VirtualLock` on Windows.
//!   This asks the OS to keep the pages backing the buffer in RAM so they
//!   are not written to swap. If the call fails (most often because the
//!   process has hit its `RLIMIT_MEMLOCK`, or on Windows its minimum
//!   working-set size), the buffer is still usable; the failure is
//!   recorded and [`LockedBytes::is_locked`] reports `false`.
//!
//! - **Zero-on-drop.** Every byte is overwritten with `0` (through the
//!   `zeroize` crate, which uses volatile writes) before the allocation is
//!   returned to the allocator.
//!
//! # Page-lock reference counting
//!
//! The OS locks whole pages, and locks do not nest: one `munlock` /
//! `VirtualUnlock` on a page releases it no matter how many earlier
//! `mlock` calls covered it. Fragments are small separate heap
//! allocations, so several of them (often from different keys) share a
//! page. Before 1.0.2 each buffer unlocked its whole page range on drop,
//! which also unlocked pages still used by other live buffers.
//!
//! This module keeps a process-wide table that counts, per page, how many
//! live locked buffers touch it. A page is locked by the OS when its count
//! goes from 0 to 1 and unlocked only when the count returns to 0.
//!
//! # Drop order
//!
//! `Drop` overwrites the bytes *first* and then releases the page
//! references. The kernel must still consider the pages locked while we
//! are writing to them, otherwise the pre-zero data could be paged out.
//! After that the `Vec<u8>` destructor returns the allocation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use zeroize::Zeroize;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// A page-locked, zero-on-drop byte buffer.
///
/// Construction copies the input bytes into a freshly-allocated buffer with
/// exact capacity, takes a reference on every page the buffer touches
/// (locking pages that were not locked yet), and records whether that
/// succeeded. The bytes are accessible through [`LockedBytes::as_bytes`]
/// until the value is dropped; at drop, the buffer is zeroed and its page
/// references are released.
///
/// `LockedBytes` is intentionally not `Clone`: duplicating key material
/// silently is the kind of mistake this crate exists to prevent.
pub(crate) struct LockedBytes {
    data: Vec<u8>,
    /// `true` if every page of the buffer is locked and this buffer holds
    /// a reference on each of them. `false` if the OS refused the lock
    /// (e.g. `EPERM` / `ENOMEM` from `mlock`, `RLIMIT_MEMLOCK` reached).
    locked: bool,
}

impl LockedBytes {
    /// Construct a new locked buffer from a slice.
    ///
    /// Always succeeds. If the OS rejects the lock request the buffer is
    /// returned with [`LockedBytes::is_locked`] reporting `false`, never
    /// with an error. The caller decides whether reduced-security mode is
    /// acceptable.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        // Allocate exactly the right size and never resize: any growth would
        // realloc and the page references would refer to a stale address.
        let mut data: Vec<u8> = Vec::with_capacity(bytes.len());
        data.extend_from_slice(bytes);
        debug_assert_eq!(data.capacity(), data.len());

        let locked = if data.is_empty() {
            false
        } else {
            // SAFETY: `data.as_ptr()` points to a live `data.len()`-byte
            // allocation we just constructed; we do not free or move it
            // before the matching `release_region` in `Drop`.
            unsafe { acquire_region(data.as_ptr(), data.len()) }
        };

        Self { data, locked }
    }

    /// Borrow the protected bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Length of the protected buffer.
    #[allow(dead_code)] // used by tests and kept for monitor / audit reporting.
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// `true` iff the OS confirmed the page lock at construction time.
    ///
    /// A `false` value is not an error in itself: it means the kernel
    /// declined the lock (usually because the process is over its
    /// `RLIMIT_MEMLOCK`). The buffer still zeroes on drop; the only
    /// weakened guarantee is swap protection.
    #[allow(dead_code)] // used by tests and kept for monitor / audit reporting.
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        if !self.data.is_empty() {
            // Step 1: overwrite the bytes while the lock (if held) is still
            // in place. `zeroize` uses volatile writes plus a compiler
            // fence, so the stores cannot be removed as dead. The capacity
            // equals the length (we never resize), so this covers the whole
            // allocation.
            self.data.as_mut_slice().zeroize();

            // Step 2: drop this buffer's page references now that the
            // bytes are gone. Pages still used by other live buffers stay
            // locked.
            if self.locked {
                // SAFETY: the pointer/length pair refers to the same
                // allocation we passed to `acquire_region` in `from_slice`;
                // `data`'s buffer pointer and length never change between
                // those calls.
                unsafe {
                    release_region(self.data.as_ptr(), self.data.len());
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
use self::unix::{lock_pages, system_page_size, unlock_pages};
#[cfg(windows)]
use self::windows::{lock_pages, system_page_size, unlock_pages};

#[cfg(not(any(unix, windows)))]
unsafe fn lock_pages(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
unsafe fn unlock_pages(_ptr: *const u8, _len: usize) {}

#[cfg(not(any(unix, windows)))]
fn system_page_size() -> Option<usize> {
    None
}

// ------------------------- Page-lock table -------------------------

/// Page size used when the OS query fails or reports something unusable.
const FALLBACK_PAGE_SIZE: usize = 4096;

/// Process-wide map from page start address to the number of live locked
/// regions that touch that page. A page is in the map exactly when this
/// module holds an OS lock on it.
static PAGE_LOCKS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

/// OS page size, queried once.
pub(crate) fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| match system_page_size() {
        Some(n) if n.is_power_of_two() => n,
        _ => FALLBACK_PAGE_SIZE,
    })
}

/// Lock the page table. The table only holds integers and nothing that
/// runs under the lock panics, so a poisoned lock still guards consistent
/// data and is used as is.
fn page_table() -> MutexGuard<'static, BTreeMap<usize, usize>> {
    PAGE_LOCKS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Start addresses of the first and last page touched by
/// `[addr, addr + len)`. `len` must be non-zero.
fn page_span(addr: usize, len: usize, page: usize) -> (usize, usize) {
    let first = addr & !(page - 1);
    let last = addr.saturating_add(len - 1) & !(page - 1);
    (first, last)
}

/// Take one reference on every page touched by `[ptr, ptr + len)`,
/// asking the OS to lock each page whose count goes from 0 to 1.
///
/// Returns `true` if every page is now locked. On failure no references
/// are taken and the pages this call locked are unlocked again, so the
/// caller must not call [`release_region`] for this range.
///
/// # Safety
///
/// `ptr` must point to a live allocation of at least `len` bytes that
/// stays valid (and is not moved) until the matching [`release_region`].
/// `len` must be non-zero.
pub(crate) unsafe fn acquire_region(ptr: *const u8, len: usize) -> bool {
    let page = page_size();
    let (first, last) = page_span(ptr as usize, len, page);
    let mut table = page_table();

    // Pass 1: lock the pages nobody holds yet. The table lock is held
    // across the syscalls so no other thread can unlock a page between
    // our check and our lock.
    let mut newly_locked: Vec<usize> = Vec::new();
    let mut addr = first;
    loop {
        if !table.contains_key(&addr) {
            // SAFETY: `addr` is the start of a page that overlaps the
            // caller's live allocation, so the page is mapped. The OS
            // locks whole pages for any sub-range anyway.
            if unsafe { lock_pages(addr as *const u8, page) } {
                newly_locked.push(addr);
            } else {
                for &p in &newly_locked {
                    // SAFETY: `p` was locked by this call a moment ago and
                    // is not in the table, so no other region relies on it.
                    unsafe { unlock_pages(p as *const u8, page) };
                }
                return false;
            }
        }
        if addr == last {
            break;
        }
        addr += page;
    }

    // Pass 2: every page is locked; record one reference on each.
    let mut addr = first;
    loop {
        *table.entry(addr).or_insert(0) += 1;
        if addr == last {
            break;
        }
        addr += page;
    }
    true
}

/// Drop one reference on every page touched by `[ptr, ptr + len)`. Pages
/// whose count reaches 0 are unlocked and removed from the table.
///
/// # Safety
///
/// Must be called exactly once per successful [`acquire_region`] call,
/// with the same `ptr` and `len`, while the allocation is still live.
pub(crate) unsafe fn release_region(ptr: *const u8, len: usize) {
    let page = page_size();
    let (first, last) = page_span(ptr as usize, len, page);
    let mut table = page_table();
    let mut addr = first;
    loop {
        if let Some(count) = table.get_mut(&addr) {
            *count -= 1;
            if *count == 0 {
                let _ = table.remove(&addr);
                // SAFETY: the page overlaps the caller's live allocation
                // and no other locked region references it any more.
                unsafe { unlock_pages(addr as *const u8, page) };
            }
        }
        if addr == last {
            break;
        }
        addr += page;
    }
}

/// Number of live locked regions that touch the page containing `addr`.
/// `0` means the page is not locked by this module.
#[cfg(test)]
pub(crate) fn page_lock_count(addr: usize) -> usize {
    let page = page_size();
    page_table()
        .get(&(addr & !(page - 1)))
        .copied()
        .unwrap_or(0)
}

/// Start addresses of every page touched by `bytes`.
#[cfg(test)]
pub(crate) fn pages_of(bytes: &[u8]) -> Vec<usize> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let page = page_size();
    let (first, last) = page_span(bytes.as_ptr() as usize, bytes.len(), page);
    (first..=last).step_by(page).collect()
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
        assert_eq!(buf.as_bytes(), []);
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
        // residency (that requires dhat), but we want this exercised in CI
        // to catch obvious unsoundness with sanitizers.
        for size in [1, 7, 32, 64, 256, 4096] {
            let bytes: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            let buf = LockedBytes::from_slice(&bytes);
            assert_eq!(buf.as_bytes(), &bytes[..]);
            drop(buf);
        }
    }

    #[test]
    fn page_size_is_a_power_of_two() {
        assert!(page_size().is_power_of_two());
        assert!(page_size() >= 4096);
    }

    #[test]
    fn page_span_covers_every_touched_page() {
        assert_eq!(page_span(0x1000, 1, 0x1000), (0x1000, 0x1000));
        assert_eq!(page_span(0x1fff, 1, 0x1000), (0x1000, 0x1000));
        assert_eq!(page_span(0x1fff, 2, 0x1000), (0x1000, 0x2000));
        assert_eq!(page_span(0x1000, 0x2000, 0x1000), (0x1000, 0x2000));
        assert_eq!(page_span(0x1001, 0x2000, 0x1000), (0x1000, 0x3000));
    }

    /// Two regions inside one page: releasing one must leave the page
    /// locked for the other. Uses sub-slices of a single allocation so the
    /// regions are guaranteed to share a page.
    #[test]
    fn page_stays_locked_until_last_region_is_released() {
        let page = page_size();
        // Big enough to contain one full page, so there is a page whose
        // every byte belongs to this buffer and that no other test can be
        // holding a reference on.
        let buf = alloc::vec![0x5au8; 3 * page];
        let base = buf.as_ptr() as usize;
        let own_page = (base + page - 1) & !(page - 1);
        let offset = own_page - base;
        let a = &buf[offset..offset + 16];
        let b = &buf[offset + 64..offset + 80];
        assert_eq!(pages_of(a), pages_of(b));
        assert_eq!(page_lock_count(own_page), 0);

        // SAFETY: `a` and `b` are live sub-slices of `buf`, which outlives
        // both acquire/release pairs below.
        let a_locked = unsafe { acquire_region(a.as_ptr(), a.len()) };
        if !a_locked {
            // The OS refused the lock (RLIMIT_MEMLOCK / working-set quota),
            // so there is nothing to count. Nothing was recorded.
            assert_eq!(page_lock_count(own_page), 0);
            return;
        }
        // SAFETY: as above.
        let b_locked = unsafe { acquire_region(b.as_ptr(), b.len()) };
        assert!(
            b_locked,
            "page already locked; taking a reference cannot fail"
        );
        assert_eq!(page_lock_count(own_page), 2);

        // SAFETY: matches the successful acquire of `a` above.
        unsafe { release_region(a.as_ptr(), a.len()) };
        assert_eq!(
            page_lock_count(own_page),
            1,
            "page unlocked while region `b` still uses it"
        );

        // SAFETY: matches the successful acquire of `b` above.
        unsafe { release_region(b.as_ptr(), b.len()) };
        assert_eq!(page_lock_count(own_page), 0);
    }

    #[test]
    fn buffers_hold_a_reference_on_every_page_they_touch() {
        let bufs: Vec<LockedBytes> = (0..64u8)
            .map(|i| LockedBytes::from_slice(&[i; 24]))
            .collect();
        for b in &bufs {
            if b.is_locked() {
                for p in pages_of(b.as_bytes()) {
                    assert!(page_lock_count(p) >= 1);
                }
            }
        }
        // Drop every other buffer; the survivors' pages must stay counted.
        let survivors: Vec<LockedBytes> = bufs
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| (i % 2 == 0).then_some(b))
            .collect();
        for b in &survivors {
            if b.is_locked() {
                for p in pages_of(b.as_bytes()) {
                    assert!(
                        page_lock_count(p) >= 1,
                        "page of a live buffer was unlocked by a sibling's drop"
                    );
                }
            }
        }
    }
}
