//! `VirtualLock` / `VirtualUnlock` backend for Windows.

use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

/// Attempt to lock `len` bytes starting at `ptr` into RAM.
///
/// # Safety
///
/// `ptr` must point into committed memory covering at least `len` bytes
/// that stays committed until a matching [`unlock_pages`] call. `len` must
/// be non-zero.
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
/// Same invariants as [`lock_pages`]. The result is ignored: failure to
/// unlock is not actionable from `Drop`.
pub(super) unsafe fn unlock_pages(ptr: *const u8, len: usize) {
    // SAFETY: pointer/length describe pages that were successfully
    // `VirtualLock`'d by the page table in `super`.
    let _ = unsafe { VirtualUnlock(ptr as *mut core::ffi::c_void, len) };
}

/// The OS page size from `GetSystemInfo`, or `None` if it reports zero.
pub(super) fn system_page_size() -> Option<usize> {
    // SAFETY: `SYSTEM_INFO` is a plain C struct; all-zero is a valid bit
    // pattern for it.
    let mut info: SYSTEM_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: `GetSystemInfo` writes into the struct we pass and has no
    // other preconditions.
    unsafe { GetSystemInfo(&raw mut info) };
    usize::try_from(info.dwPageSize).ok().filter(|&n| n > 0)
}
