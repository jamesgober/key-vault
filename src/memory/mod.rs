//! Layer 2 + Layer 7: page-locked, dump-excluded, zero-on-drop buffers.
//!
//! [`LockedBytes`] is the in-crate primitive for storing bytes that
//! should not be swapped to disk, should not appear in crash dumps, and
//! must be overwritten when freed. Every fragment, every layout map and
//! every codex table is held inside a `LockedBytes`. On each page a buffer
//! touches, the crate asks the OS for:
//!
//! - **Page locking**: `mlock(2)` on Unix, `VirtualLock` on Windows, so
//!   the page is not written to swap. If the call fails (most often
//!   because the process hit `RLIMIT_MEMLOCK`, or on Windows its minimum
//!   working-set size), the buffer still works and
//!   [`LockedBytes::is_locked`] reports `false`.
//! - **Dump exclusion** (1.1): `madvise(MADV_DONTDUMP)` on Linux and
//!   Android, `madvise(MADV_NOCORE)` on FreeBSD and DragonFly, and
//!   `WerRegisterExcludedMemoryBlock` on Windows (Windows Error Reporting
//!   dumps only). macOS has no per-page core-dump exclusion.
//!
//! and on drop every byte is overwritten with `0` (through the `zeroize`
//! crate, which uses volatile writes) before the allocation is returned.
//!
//! # Page pool
//!
//! Buffers of up to 2048 bytes (fragments, layout maps, codex tables) come
//! from a pool of pages the crate maps for itself (1.1, `pool.rs`). Each
//! pool page is locked and excluded from dumps once, when it is mapped,
//! holds only key buffers, and is kept for the life of the process, so
//! registering and dropping keys makes no system calls once the pool has
//! grown to its working size. Before 1.1 every small buffer lived on the
//! general heap.
//!
//! # Page reference counting
//!
//! Larger buffers (and the `with_key` scratch buffer) live on the general
//! heap. The OS applies locking and dump exclusion to whole pages, and
//! they do not nest:
//! one `munlock` / `VirtualUnlock` on a page releases it no matter how many
//! earlier `mlock` calls covered it. Fragments are small separate heap
//! allocations, so several of them (often from different keys) share a
//! page. A process-wide table counts, per page, how many live buffers
//! touch it. A page is locked and excluded from dumps when its count goes
//! from 0 to 1, and released only when the count returns to 0.
//!
//! Because heap pages are shared with whatever else the allocator put on
//! them, excluding such a page from dumps also leaves out the unrelated
//! objects that share it. Pool pages hold nothing else.
//!
//! # Page-protected regions
//!
//! Heap pages cannot be made inaccessible: other objects live on them.
//! For page protection ([`KeyVaultBuilder::with_page_protection`](crate::KeyVaultBuilder::with_page_protection))
//! each key gets its own mapping, a [`GuardedRegion`], which is locked,
//! excluded from dumps and kept `PROT_NONE` / `PAGE_NOACCESS` except while
//! it is being read.
//!
//! # Drop order
//!
//! `Drop` overwrites the bytes *first* and then releases the page
//! references. The kernel must still consider the pages locked while we
//! are writing to them, otherwise the pre-zero data could be paged out.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
#[cfg(any(test, not(feature = "std")))]
use alloc::vec::Vec;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroize;

use crate::sync::Mutex;

#[cfg(any(unix, windows))]
mod guarded;
#[cfg(any(unix, windows))]
mod pool;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(any(unix, windows))]
pub(crate) use self::guarded::{GuardedRegion, RegionAccess};

/// Page protection levels used by guarded regions.
#[allow(dead_code)] // not every variant is used on every target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// `PROT_NONE` / `PAGE_NOACCESS`.
    None,
    /// `PROT_READ` / `PAGE_READONLY`.
    Read,
    /// `PROT_READ | PROT_WRITE` / `PAGE_READWRITE`.
    ReadWrite,
}

/// A page-locked, dump-excluded, zero-on-drop byte buffer.
///
/// Normally owns its own heap allocation of exactly `len` bytes. Inside a
/// page-protected key (see [`GuardedRegion`]) it is a view into the
/// region instead, and the region does the locking, wiping and freeing.
///
/// `LockedBytes` is intentionally not `Clone`: duplicating key material
/// silently is the kind of mistake this crate exists to prevent.
pub(crate) struct LockedBytes {
    ptr: NonNull<u8>,
    len: usize,
    /// Where the bytes live and who frees them.
    storage: Storage,
    /// `true` if every page of the buffer is locked.
    locked: bool,
}

/// Backing storage of a [`LockedBytes`].
#[derive(Debug, Clone, Copy)]
enum Storage {
    /// A `Box<[u8]>` of exactly `len` bytes, with page references taken
    /// through the page table.
    Heap,
    /// A block from the page pool (`len <= pool::MAX_POOLED`).
    #[cfg(any(unix, windows))]
    Pooled { class: u8 },
    /// A view into a [`GuardedRegion`] owned by the same `Fragments`; the
    /// region wipes and frees it.
    #[cfg(any(unix, windows))]
    RegionView,
}

// SAFETY: `LockedBytes` owns (or, for region views, borrows from an owner
// that outlives it and is moved together with it) a plain byte buffer. It
// has no interior mutability; `&LockedBytes` only gives `&[u8]`.
unsafe impl Send for LockedBytes {}
// SAFETY: see above; shared access is read-only.
unsafe impl Sync for LockedBytes {}

impl LockedBytes {
    /// Construct a new locked buffer from a slice.
    ///
    /// Always succeeds. If the OS rejects the lock request the buffer is
    /// returned with [`LockedBytes::is_locked`] reporting `false`, never
    /// with an error.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        #[cfg(any(unix, windows))]
        if let Some(block) = pool::alloc(bytes.len()) {
            // SAFETY: the block is at least `bytes.len()` bytes, writable,
            // and exclusively ours until it is freed in `Drop`.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), block.ptr.as_ptr(), bytes.len());
            }
            return Self {
                ptr: block.ptr,
                len: bytes.len(),
                storage: Storage::Pooled { class: block.class },
                locked: block.locked,
            };
        }
        // `Box<[u8]>::from` allocates exactly `bytes.len()` bytes, so the
        // page references below cover the whole allocation and it is never
        // resized.
        let boxed: Box<[u8]> = Box::from(bytes);
        let len = boxed.len();
        let raw = Box::into_raw(boxed).cast::<u8>();
        // SAFETY: `Box::into_raw` never returns null (a zero-length box
        // gives a dangling, non-null pointer).
        let ptr = unsafe { NonNull::new_unchecked(raw) };
        let locked = if len == 0 {
            false
        } else {
            // SAFETY: `ptr` points to a live `len`-byte allocation that is
            // only freed in `Drop`, after the matching `release_region`.
            unsafe { acquire_region(ptr.as_ptr(), len) }
        };
        Self {
            ptr,
            len,
            storage: Storage::Heap,
            locked,
        }
    }

    /// A view of `len` bytes at `ptr` inside a guarded region.
    ///
    /// # Safety
    ///
    /// `[ptr, ptr + len)` must lie inside a live [`GuardedRegion`] that
    /// outlives the returned value. The value must only be read while the
    /// region is open for reading.
    #[cfg(any(unix, windows))]
    pub(crate) unsafe fn region_view(ptr: NonNull<u8>, len: usize, locked: bool) -> Self {
        Self {
            ptr,
            len,
            storage: Storage::RegionView,
            locked,
        }
    }

    /// Borrow the protected bytes.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // SAFETY: `ptr` / `len` describe a live allocation (owned, or a
        // region view whose region outlives `self`).
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Length of the protected buffer.
    #[inline]
    #[allow(dead_code)] // unused on targets without page protection.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// `true` if the buffer lives on the general heap and is tracked by
    /// the page table (rather than the pool or a protected region).
    #[cfg(test)]
    pub(crate) fn uses_page_table(&self) -> bool {
        matches!(self.storage, Storage::Heap)
    }

    /// `true` iff every page of the buffer is locked.
    ///
    /// A `false` value is not an error in itself: it means the kernel
    /// declined the lock (usually because the process is over its
    /// `RLIMIT_MEMLOCK`). The buffer still zeroes on drop.
    #[allow(dead_code)] // used by tests.
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        match self.storage {
            #[cfg(any(unix, windows))]
            Storage::RegionView => {
                // The region wipes and frees.
            }
            #[cfg(any(unix, windows))]
            Storage::Pooled { class } => {
                let block = pool::Block {
                    ptr: self.ptr,
                    class,
                    locked: self.locked,
                };
                // SAFETY: the block is ours and `len` bytes of it are in
                // use; the rest was zero when we got it and never written.
                let used = unsafe { core::slice::from_raw_parts_mut(block.ptr.as_ptr(), self.len) };
                used.zeroize();
                // SAFETY: the block came from `pool::alloc`, is returned
                // exactly once (here), and is zeroed.
                unsafe { pool::free(block) };
            }
            Storage::Heap => {
                let slice = core::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr(), self.len);
                // SAFETY: `slice` is the `Box<[u8]>` leaked in `from_slice`;
                // we are its only owner.
                let mut boxed = unsafe { Box::from_raw(slice) };
                if self.len > 0 {
                    // Step 1: overwrite the bytes while the pages are still
                    // locked.
                    boxed.zeroize();
                    // Step 2: release this buffer's page references. Pages
                    // still used by other live buffers stay locked and
                    // excluded.
                    // SAFETY: same pointer and length as the
                    // `acquire_region` call in `from_slice`; the allocation
                    // is still live.
                    unsafe { release_region(self.ptr.as_ptr(), self.len) };
                }
                // Step 3: `boxed` drops here and returns the allocation.
            }
        }
    }
}

impl fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedBytes")
            .field("len", &self.len)
            .field("locked", &self.locked)
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
use self::unix::{
    exclude_from_dumps, include_in_dumps, lock_pages, system_page_size, unlock_pages,
};
#[cfg(windows)]
use self::windows::{
    exclude_from_dumps, include_in_dumps, lock_pages, system_page_size, unlock_pages,
};

#[cfg(not(any(unix, windows)))]
unsafe fn lock_pages(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
unsafe fn unlock_pages(_ptr: *const u8, _len: usize) {}

#[cfg(not(any(unix, windows)))]
unsafe fn exclude_from_dumps(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
unsafe fn include_in_dumps(_ptr: *const u8, _len: usize) {}

#[cfg(not(any(unix, windows)))]
fn system_page_size() -> Option<usize> {
    None
}

// ------------------------- Page table -------------------------

/// Page size used when the OS query fails or reports something unusable,
/// and on targets without an OS.
const FALLBACK_PAGE_SIZE: usize = 4096;

/// What this module holds on one page.
#[derive(Debug, Clone, Copy)]
struct PageState {
    /// Live buffers touching the page.
    refs: usize,
    /// The page is locked by this module.
    locked: bool,
    /// The page is excluded from dumps by this module.
    no_dump: bool,
}

/// Process-wide map from page start address to the buffers that use it.
/// A page is in the map exactly while at least one live buffer touches it.
static PAGES: Mutex<BTreeMap<usize, PageState>> = Mutex::new(BTreeMap::new());

/// OS page size, queried once.
pub(crate) fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);
    match PAGE_SIZE.load(Ordering::Relaxed) {
        0 => {
            let n = match system_page_size() {
                Some(n) if n.is_power_of_two() => n,
                _ => FALLBACK_PAGE_SIZE,
            };
            PAGE_SIZE.store(n, Ordering::Relaxed);
            n
        }
        n => n,
    }
}

/// Start addresses of the first and last page touched by
/// `[addr, addr + len)`. `len` must be non-zero.
fn page_span(addr: usize, len: usize, page: usize) -> (usize, usize) {
    let first = addr & !(page - 1);
    let last = addr.saturating_add(len - 1) & !(page - 1);
    (first, last)
}

/// Take one reference on every page touched by `[ptr, ptr + len)`.
///
/// A page whose count goes from 0 to 1 is locked and excluded from dumps.
/// A page that is already referenced but whose lock or exclusion failed
/// earlier is retried. Returns `true` if every page is now locked.
///
/// References are taken whether or not the OS calls succeed, so every
/// call must be matched by exactly one [`release_region`].
///
/// # Safety
///
/// `ptr` must point to a live allocation of at least `len` bytes that
/// stays valid (and is not moved) until the matching [`release_region`].
/// `len` must be non-zero.
pub(crate) unsafe fn acquire_region(ptr: *const u8, len: usize) -> bool {
    let page = page_size();
    let (first, last) = page_span(ptr as usize, len, page);
    // The table lock is held across the syscalls so no other thread can
    // release a page between our check and our lock.
    let mut table = PAGES.lock();
    let mut all_locked = true;
    let mut addr = first;
    loop {
        let state = table.entry(addr).or_insert(PageState {
            refs: 0,
            locked: false,
            no_dump: false,
        });
        if !state.locked {
            // SAFETY: `addr` is the start of a page that overlaps the
            // caller's live allocation, so the page is mapped.
            state.locked = unsafe { lock_pages(addr as *const u8, page) };
        }
        if !state.no_dump {
            // SAFETY: as above; `addr` is page aligned.
            state.no_dump = unsafe { exclude_from_dumps(addr as *const u8, page) };
        }
        state.refs += 1;
        all_locked &= state.locked;
        if addr == last {
            break;
        }
        addr += page;
    }
    all_locked
}

/// Drop one reference on every page touched by `[ptr, ptr + len)`. Pages
/// whose count reaches 0 are unlocked, included in dumps again and
/// removed from the table.
///
/// # Safety
///
/// Must be called exactly once per [`acquire_region`] call, with the same
/// `ptr` and `len`, while the allocation is still live.
pub(crate) unsafe fn release_region(ptr: *const u8, len: usize) {
    let page = page_size();
    let (first, last) = page_span(ptr as usize, len, page);
    let mut table = PAGES.lock();
    let mut addr = first;
    loop {
        if let Some(state) = table.get_mut(&addr) {
            state.refs -= 1;
            if state.refs == 0 {
                let state = *state;
                let _ = table.remove(&addr);
                if state.locked {
                    // SAFETY: the page overlaps the caller's live
                    // allocation and no other buffer references it.
                    unsafe { unlock_pages(addr as *const u8, page) };
                }
                if state.no_dump {
                    // SAFETY: as above.
                    unsafe { include_in_dumps(addr as *const u8, page) };
                }
            }
        }
        if addr == last {
            break;
        }
        addr += page;
    }
}

/// Number of live buffers that touch the page containing `addr`.
#[cfg(test)]
pub(crate) fn page_lock_count(addr: usize) -> usize {
    page_state(addr).map_or(0, |(refs, locked, _)| if locked { refs } else { 0 })
}

/// `(refs, locked, excluded_from_dumps)` for the page containing `addr`.
#[cfg(test)]
pub(crate) fn page_state(addr: usize) -> Option<(usize, bool, bool)> {
    let page = page_size();
    PAGES
        .lock()
        .get(&(addr & !(page - 1)))
        .map(|s| (s.refs, s.locked, s.no_dump))
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

/// Per-call scratch buffer used by `with_key` in builds without
/// thread-local storage: locked and dump-excluded while it lives, wiped
/// on drop.
#[cfg(not(feature = "std"))]
pub(crate) struct ScratchBuf {
    buf: Vec<u8>,
}

#[cfg(not(feature = "std"))]
impl ScratchBuf {
    pub(crate) fn new(len: usize) -> Self {
        let buf = alloc::vec![0u8; len];
        if len > 0 {
            // SAFETY: `buf` is a live `len`-byte allocation that is never
            // resized and is released in `Drop` before it is freed.
            let _ = unsafe { acquire_region(buf.as_ptr(), len) };
        }
        Self { buf }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

#[cfg(not(feature = "std"))]
impl Drop for ScratchBuf {
    fn drop(&mut self) {
        self.buf.as_mut_slice().zeroize();
        if !self.buf.is_empty() {
            // SAFETY: matches the `acquire_region` in `new`.
            unsafe { release_region(self.buf.as_ptr(), self.buf.len()) };
        }
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
        assert_eq!(buf.as_bytes(), [0u8; 0]);
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
        for size in [1, 7, 32, 64, 256, 4096] {
            let bytes: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            let buf = LockedBytes::from_slice(&bytes);
            assert_eq!(buf.as_bytes(), &bytes[..]);
            drop(buf);
        }
    }

    /// Small buffers come from the pool; dropping one zeroes its block
    /// (the pool never unmaps, so the block can be inspected afterwards).
    #[cfg(any(unix, windows))]
    #[test]
    fn pooled_buffers_are_zeroed_on_drop() {
        let buf = LockedBytes::from_slice(&[0xc3; 40]);
        assert!(matches!(buf.storage, Storage::Pooled { .. }));
        assert!(core::mem::size_of::<LockedBytes>() <= 24);
        let ptr = buf.as_bytes().as_ptr();
        drop(buf);
        // Look at the freed block while the pool is locked, so no other
        // test can take it and write to it in between. If one already
        // has, there is nothing to check.
        let zeroed = pool::while_free(ptr as usize, || {
            // SAFETY: pool blocks stay mapped for the life of the process
            // and this one is on the free list, unused by anyone.
            let after = unsafe { core::slice::from_raw_parts(ptr, 40) };
            after.iter().all(|&b| b == 0)
        });
        assert_ne!(zeroed, Some(false), "freed block still holds key bytes");

        let big = LockedBytes::from_slice(&[1u8; 4000]);
        assert!(matches!(big.storage, Storage::Heap));
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
    /// locked for the other.
    #[test]
    fn page_stays_locked_until_last_region_is_released() {
        let page = page_size();
        let buf = alloc::vec![0x5au8; 3 * page];
        let base = buf.as_ptr() as usize;
        let own_page = (base + page - 1) & !(page - 1);
        let offset = own_page - base;
        let a = &buf[offset..offset + 16];
        let b = &buf[offset + 64..offset + 80];
        assert_eq!(pages_of(a), pages_of(b));
        assert!(page_state(own_page).is_none());

        // SAFETY: `a` and `b` are live sub-slices of `buf`, which outlives
        // both acquire/release pairs below.
        let a_locked = unsafe { acquire_region(a.as_ptr(), a.len()) };
        // SAFETY: as above.
        let b_locked = unsafe { acquire_region(b.as_ptr(), b.len()) };
        assert_eq!(a_locked, b_locked);
        assert_eq!(page_state(own_page).map(|s| s.0), Some(2));
        if a_locked {
            assert_eq!(page_lock_count(own_page), 2);
        }

        // SAFETY: matches the acquire of `a` above.
        unsafe { release_region(a.as_ptr(), a.len()) };
        assert_eq!(
            page_state(own_page).map(|s| (s.0, s.1)),
            Some((1, a_locked)),
            "page released while region `b` still uses it"
        );

        // SAFETY: matches the acquire of `b` above.
        unsafe { release_region(b.as_ptr(), b.len()) };
        assert!(page_state(own_page).is_none());
    }

    /// Heap buffers (too big for the pool) take page references.
    #[test]
    fn buffers_hold_a_reference_on_every_page_they_touch() {
        let bufs: Vec<LockedBytes> = (0..64u8)
            .map(|i| LockedBytes::from_slice(&[i; 2100]))
            .collect();
        for b in &bufs {
            for p in pages_of(b.as_bytes()) {
                assert!(page_state(p).is_some_and(|s| s.0 >= 1));
            }
        }
        // Drop every other buffer; the survivors' pages must stay counted.
        let survivors: Vec<LockedBytes> = bufs
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| (i % 2 == 0).then_some(b))
            .collect();
        for b in &survivors {
            for p in pages_of(b.as_bytes()) {
                let state = page_state(p).expect("page of a live buffer was released");
                assert!(state.0 >= 1);
                if b.is_locked() {
                    assert!(
                        state.1,
                        "page of a live buffer was unlocked by a sibling's drop"
                    );
                }
            }
        }
    }

    /// On Linux the dump exclusion is visible in `/proc/self/smaps`: the
    /// mapping that holds a key page carries the `dd` flag in `VmFlags`,
    /// and loses it when the last buffer on the page is dropped.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pages_carry_the_dontdump_flag() {
        let page = page_size();
        // A whole page of our own, so no other test shares it.
        let buf = LockedBytes::from_slice(&alloc::vec![0x77u8; 3 * page]);
        let base = buf.as_bytes().as_ptr() as usize;
        let own_page = (base + page - 1) & !(page - 1);
        let state = page_state(own_page).expect("page referenced");
        assert!(state.2, "madvise(MADV_DONTDUMP) failed");
        assert!(
            crate::test_util::smaps_flags(own_page).contains(&"dd".to_owned()),
            "VmFlags lacks dd while a key buffer lives on the page"
        );
        drop(buf);
        // Hold the page table so no other test can put a buffer on this
        // page while we look at it.
        let table = PAGES.lock();
        if !table.contains_key(&own_page) {
            assert!(
                !crate::test_util::smaps_flags(own_page).contains(&"dd".to_owned()),
                "dd flag left behind after the buffer was dropped"
            );
        }
        drop(table);
    }
}
