//! `mlock(2)` / `munlock(2)` backend for Linux and macOS.

/// Attempt to lock `len` bytes starting at `ptr` into RAM.
///
/// # Safety
///
/// `ptr` must point to a live allocation of at least `len` bytes that will
/// remain valid until a matching [`unlock_pages`] call. `len` must be
/// non-zero (the empty case is filtered upstream).
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
/// Same invariants as [`lock_pages`]. The result is ignored — failure to
/// unlock is not actionable from `Drop`.
pub(super) unsafe fn unlock_pages(ptr: *const u8, len: usize) {
    // SAFETY: pointer/length come from the same allocation that was
    // successfully `mlock`'d, by Drop-order invariant.
    let _ = unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) };
}
