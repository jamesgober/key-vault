//! `VirtualLock` / `VirtualUnlock` backend for Windows.

use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

/// Attempt to lock `len` bytes starting at `ptr` into RAM.
///
/// # Safety
///
/// `ptr` must point to a live allocation of at least `len` bytes that will
/// remain valid until a matching [`unlock_pages`] call. `len` must be
/// non-zero (the empty case is filtered upstream).
pub(super) unsafe fn lock_pages(ptr: *const u8, len: usize) -> bool {
    // SAFETY: `VirtualLock` is a Win32 API that pins the pages backing the
    // given range into the working set. The pointer/length pair are passed
    // straight through; the kernel rejects invalid ranges rather than
    // corrupting state.
    let ok = unsafe { VirtualLock(ptr as *mut core::ffi::c_void, len) };
    ok != 0
}

/// Release the lock on `len` bytes starting at `ptr`.
///
/// # Safety
///
/// Same invariants as [`lock_pages`]. The result is ignored — failure to
/// unlock is not actionable from `Drop`.
pub(super) unsafe fn unlock_pages(ptr: *const u8, len: usize) {
    // SAFETY: pointer/length come from the same allocation that was
    // successfully `VirtualLock`'d, by Drop-order invariant.
    let _ = unsafe { VirtualUnlock(ptr as *mut core::ffi::c_void, len) };
}
