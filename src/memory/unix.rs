//! `mlock(2)` / `munlock(2)` backend for Linux and macOS.

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
    // `mlock`'d by the page table in `super`.
    let _ = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
}

/// The OS page size from `sysconf(_SC_PAGESIZE)`, or `None` if the query
/// fails.
pub(super) fn system_page_size() -> Option<usize> {
    // SAFETY: `sysconf` has no preconditions; it only reads a system
    // configuration value.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(n).ok().filter(|&n| n > 0)
}
