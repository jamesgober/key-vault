//! Page-protected regions (Layer 10).
//!
//! A [`GuardedRegion`] is a private mapping (`mmap` / `VirtualAlloc`)
//! that holds the fragments and layout of one key. Because nothing else
//! lives on its pages, they can be made inaccessible: between accesses
//! the region is `PROT_NONE` (`PAGE_NOACCESS` on Windows), so a stray
//! read, an out-of-bounds bug elsewhere in the process, or a scan that
//! walks readable memory faults or skips it instead of finding the key.
//!
//! Readers call [`GuardedRegion::open`], which makes the region readable
//! for as long as any [`RegionAccess`] guard is alive. A per-region count
//! (under a mutex) makes concurrent readers safe: the first one in turns
//! read access on, the last one out turns it off.
//!
//! The region is also excluded from dumps and, on Unix, locked into RAM
//! (one call each for the whole region), and is zeroed and unmapped on
//! drop. Windows cannot keep `PAGE_NOACCESS` pages locked (`VirtualProtect`
//! to `PAGE_NOACCESS` drops the `VirtualLock`), so on Windows a protected
//! key's pages can be written to the page file while they are
//! inaccessible; use BitLocker on the system drive or an encrypted page
//! file there.
//!
//! Page protection does not stop an attacker who can change page
//! protections or read memory through the kernel (`ptrace`,
//! `/proc/<pid>/mem`, a debugger): those bypass the page tables' user
//! permissions.

use core::ptr::NonNull;

use zeroize::Zeroize;

#[cfg(unix)]
use super::unix as os;
#[cfg(windows)]
use super::windows as os;
use super::{Access, page_size};
use crate::Result;
use crate::error::Error;
use crate::sync::Mutex;

/// A private, page-protected mapping holding one key's storage.
pub(crate) struct GuardedRegion {
    ptr: NonNull<u8>,
    /// Mapping length: `len` rounded up to whole pages.
    map_len: usize,
    /// Bytes in use.
    len: usize,
    locked: bool,
    no_dump: bool,
    /// Live readers. Protection changes happen under this lock.
    readers: Mutex<usize>,
}

// SAFETY: the region is a private mapping owned by this value. Shared
// access goes through `open`, which serializes protection changes through
// `readers`; the bytes themselves are only written through `&mut self`.
unsafe impl Send for GuardedRegion {}
// SAFETY: see above.
unsafe impl Sync for GuardedRegion {}

impl GuardedRegion {
    /// Map a new read-write region of at least `len` bytes, lock it and
    /// exclude it from dumps. Call [`GuardedRegion::seal`] after filling it.
    ///
    /// # Errors
    ///
    /// [`Error::MemoryLock`] if the OS refuses the mapping.
    pub(crate) fn new(len: usize) -> Result<Self> {
        let page = page_size();
        let map_len = len
            .max(1)
            .checked_next_multiple_of(page)
            .ok_or_else(|| Error::MemoryLock("protected region size overflowed".into()))?;
        let raw = os::map_region(map_len).ok_or_else(|| {
            Error::MemoryLock("could not map a page-protected region for the key".into())
        })?;
        // SAFETY: `map_region` returned a non-null pointer.
        let ptr = unsafe { NonNull::new_unchecked(raw) };
        // Windows releases a `VirtualLock` as soon as the pages become
        // `PAGE_NOACCESS`, so locking there would only pretend.
        let locked = if os::LOCK_SURVIVES_NO_ACCESS {
            // SAFETY: `[ptr, ptr + map_len)` is our own fresh mapping.
            unsafe { os::lock_pages(ptr.as_ptr(), map_len) }
        } else {
            false
        };
        // SAFETY: as above; the mapping is page aligned.
        let no_dump = unsafe { os::exclude_from_dumps(ptr.as_ptr(), map_len) };
        Ok(Self {
            ptr,
            map_len,
            len,
            locked,
            no_dump,
            readers: Mutex::new(0),
        })
    }

    /// The bytes in use, writable. Only valid before [`seal`](Self::seal):
    /// the region is read-write until then.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the mapping is live, read-write until `seal`, and
        // `&mut self` guarantees no other borrow.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Start of the region.
    pub(crate) fn base(&self) -> NonNull<u8> {
        self.ptr
    }

    /// `true` if the whole region is locked into RAM. Always `false` on
    /// Windows (see the module docs).
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// `true` if the region is excluded from dumps.
    #[allow(dead_code)] // used by tests.
    pub(crate) fn is_excluded_from_dumps(&self) -> bool {
        self.no_dump
    }

    /// Make the region inaccessible. Call once, after filling it.
    ///
    /// # Errors
    ///
    /// [`Error::MemoryLock`] if the OS refuses the protection change.
    pub(crate) fn seal(&mut self) -> Result<()> {
        // SAFETY: our own live mapping; nothing reads it until `open`.
        if unsafe { os::protect(self.ptr.as_ptr(), self.map_len, Access::None) } {
            Ok(())
        } else {
            Err(Error::MemoryLock(
                "could not make the key's pages inaccessible".into(),
            ))
        }
    }

    /// Make the region readable until the returned guard (and every other
    /// live guard) is dropped.
    ///
    /// # Errors
    ///
    /// [`Error::MemoryLock`] if the OS refuses the protection change.
    pub(crate) fn open(&self) -> Result<RegionAccess<'_>> {
        let mut readers = self.readers.lock();
        if *readers == 0 {
            // SAFETY: our own live mapping.
            if !unsafe { os::protect(self.ptr.as_ptr(), self.map_len, Access::Read) } {
                return Err(Error::MemoryLock(
                    "could not make the key's pages readable".into(),
                ));
            }
        }
        *readers += 1;
        Ok(RegionAccess { region: self })
    }

    /// Mapping address and length, for tests that inspect the OS state.
    #[cfg(test)]
    pub(crate) fn mapping(&self) -> (usize, usize) {
        (self.ptr.as_ptr() as usize, self.map_len)
    }
}

impl Drop for GuardedRegion {
    fn drop(&mut self) {
        // SAFETY: our own live mapping; `&mut self` means no reader holds
        // a guard.
        let writable = unsafe { os::protect(self.ptr.as_ptr(), self.map_len, Access::ReadWrite) };
        if writable {
            // SAFETY: the whole mapping is ours and now read-write.
            let all = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.map_len) };
            all.zeroize();
        }
        if self.no_dump {
            // SAFETY: same range that `exclude_from_dumps` registered.
            unsafe { os::include_in_dumps(self.ptr.as_ptr(), self.map_len) };
        }
        if self.locked {
            // SAFETY: same range that `lock_pages` locked.
            unsafe { os::unlock_pages(self.ptr.as_ptr(), self.map_len) };
        }
        // Unmapping returns the pages to the kernel, which hands out
        // zero-filled pages for any later mapping, so the bytes are gone
        // even if the protection change above failed.
        // SAFETY: our own mapping; nothing uses it after this.
        unsafe { os::unmap_region(self.ptr.as_ptr(), self.map_len) };
    }
}

impl core::fmt::Debug for GuardedRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardedRegion")
            .field("len", &self.len)
            .field("locked", &self.locked)
            .field("bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Read access to a [`GuardedRegion`]. The region goes back to
/// `PROT_NONE` / `PAGE_NOACCESS` when the last guard is dropped.
pub(crate) struct RegionAccess<'a> {
    region: &'a GuardedRegion,
}

impl Drop for RegionAccess<'_> {
    fn drop(&mut self) {
        let mut readers = self.region.readers.lock();
        *readers -= 1;
        if *readers == 0 {
            // SAFETY: the mapping is live (the guard borrows the region)
            // and no reader remains.
            let _ =
                unsafe { os::protect(self.region.ptr.as_ptr(), self.region.map_len, Access::None) };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn region_round_trips_through_seal_and_open() {
        let mut region = GuardedRegion::new(100).unwrap();
        region.bytes_mut().fill(0xab);
        region.seal().unwrap();
        for _ in 0..3 {
            let _a = region.open().unwrap();
            // SAFETY: the region is open for reading and 100 bytes long.
            let bytes = unsafe { core::slice::from_raw_parts(region.base().as_ptr(), 100) };
            assert!(bytes.iter().all(|&b| b == 0xab));
        }
    }

    /// On Linux the region stays locked while it is `PROT_NONE`: the
    /// mapping's `Locked` size in `/proc/self/smaps` covers it.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_region_stays_locked_while_inaccessible() {
        let mut region = GuardedRegion::new(100).unwrap();
        region.seal().unwrap();
        if !region.is_locked() {
            return; // RLIMIT_MEMLOCK exhausted on this machine
        }
        let (addr, _) = region.mapping();
        let locked_kb = crate::test_util::smaps_value(addr, "Locked").unwrap();
        assert!(
            locked_kb >= 4,
            "sealed region is not locked ({locked_kb} kB)"
        );
    }

    /// Windows drops a `VirtualLock` when the pages become
    /// `PAGE_NOACCESS` (`VirtualUnlock` then fails with
    /// `ERROR_NOT_LOCKED`), so protected regions are reported unlocked.
    #[cfg(windows)]
    #[test]
    fn windows_protected_region_is_reported_unlocked() {
        let region = GuardedRegion::new(100).unwrap();
        assert!(!region.is_locked());
        assert!(region.is_excluded_from_dumps());
    }
}
