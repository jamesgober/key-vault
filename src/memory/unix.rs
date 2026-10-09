//! Unix backend: `mlock` / `munlock`, dump exclusion through `madvise`,
//! and `mmap` / `mprotect` for page-protected regions.

use super::Access;

/// Whether a page lock survives a change to no-access protection.
pub(super) const LOCK_SURVIVES_NO_ACCESS: bool = true;

/// Attempt to lock `len` bytes starting at `ptr` into RAM.
///
/// # Safety
///
/// `ptr` must point into mapped memory covering at least `len` bytes
/// that stays mapped until a matching [`unlock_pages`] call. `len` must be
/// non-zero.
pub(super) unsafe fn lock_pages(ptr: *const u8, len: usize) -> bool {
    // SAFETY: `libc::mlock` is a thin shim around the kernel syscall. The
    // pointer/length pair are passed straight through; the kernel will
    // reject invalid ranges with EINVAL rather than corrupting state.
    let rc = unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) };
    rc == 0
}

/// Release the lock on `len` bytes starting at `ptr`.
///
/// # Safety
///
/// Same invariants as [`lock_pages`]. The result is ignored: failure to
/// unlock is not actionable from `Drop`.
pub(super) unsafe fn unlock_pages(ptr: *const u8, len: usize) {
    // SAFETY: pointer/length describe pages that were successfully
    // `mlock`'d by this module.
    let _ = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
}

/// Ask the kernel to leave these pages out of core dumps.
///
/// Linux and Android: `MADV_DONTDUMP`. FreeBSD and DragonFly:
/// `MADV_NOCORE`. Other Unix systems (macOS among them) have no per-page
/// core-dump exclusion; this returns `false` there.
///
/// # Safety
///
/// `ptr` must be page aligned and `[ptr, ptr + len)` must be mapped.
pub(super) unsafe fn exclude_from_dumps(ptr: *const u8, len: usize) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: page-aligned, mapped range per the caller's contract.
        // `MADV_DONTDUMP` only changes a VMA flag; it never touches data.
        unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DONTDUMP) == 0 }
    }
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    {
        // SAFETY: as above; `MADV_NOCORE` only changes a mapping flag.
        unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_NOCORE) == 0 }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Undo [`exclude_from_dumps`] for pages that no longer hold key material.
///
/// # Safety
///
/// Same as [`exclude_from_dumps`].
pub(super) unsafe fn include_in_dumps(ptr: *const u8, len: usize) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: page-aligned, mapped range per the caller's contract.
        let _ = unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DODUMP) };
    }
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    {
        // SAFETY: as above.
        let _ = unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_CORE) };
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = (ptr, len);
    }
}

/// The OS page size from `sysconf(_SC_PAGESIZE)`, or `None` if the query
/// fails.
pub(super) fn system_page_size() -> Option<usize> {
    // SAFETY: `sysconf` has no preconditions; it only reads a system
    // configuration value.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(n).ok().filter(|&n| n > 0)
}

/// Map `len` bytes (a multiple of the page size) of private, anonymous,
/// read-write memory. Returns `None` if the kernel refuses.
pub(super) fn map_region(len: usize) -> Option<*mut u8> {
    // SAFETY: an anonymous private mapping with a null hint has no
    // preconditions; the kernel picks the address.
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED || p.is_null() {
        None
    } else {
        Some(p.cast::<u8>())
    }
}

/// Unmap a region from [`map_region`].
///
/// # Safety
///
/// `ptr` / `len` must be exactly a live mapping returned by
/// [`map_region`], and nothing may use it afterwards.
pub(super) unsafe fn unmap_region(ptr: *mut u8, len: usize) {
    // SAFETY: per the caller's contract this is our own whole mapping.
    let _ = unsafe { libc::munmap(ptr.cast(), len) };
}

/// Change the protection of a region from [`map_region`].
///
/// # Safety
///
/// `ptr` / `len` must be a live mapping from [`map_region`]. With
/// [`Access::None`], nothing may touch the memory until access is
/// restored.
pub(super) unsafe fn protect(ptr: *mut u8, len: usize, access: Access) -> bool {
    let prot = match access {
        Access::None => libc::PROT_NONE,
        Access::Read => libc::PROT_READ,
        Access::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
    };
    // SAFETY: per the caller's contract the range is our own mapping.
    unsafe { libc::mprotect(ptr.cast(), len, prot) == 0 }
}
