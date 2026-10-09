//! Windows backend: `VirtualLock` / `VirtualUnlock`, exclusion from
//! Windows Error Reporting dumps, and `VirtualAlloc` / `VirtualProtect`
//! for page-protected regions.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use super::Access;

/// Whether a page lock survives a change to no-access protection.
pub(super) const LOCK_SURVIVES_NO_ACCESS: bool = false;

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
    let ok = unsafe { VirtualLock(ptr as *mut c_void, len) };
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
    // `VirtualLock`'d by this module.
    let _ = unsafe { VirtualUnlock(ptr as *mut c_void, len) };
}

/// `WerRegisterExcludedMemoryBlock` (Windows 10 1709 and later).
type WerRegister = unsafe extern "system" fn(*const c_void, u32) -> i32;
/// `WerUnregisterExcludedMemoryBlock`.
type WerUnregister = unsafe extern "system" fn(*const c_void) -> i32;

/// Cached `GetProcAddress` result: 0 = not looked up yet, 1 = not
/// available, anything else = the function address.
static WER_REGISTER: AtomicUsize = AtomicUsize::new(0);
static WER_UNREGISTER: AtomicUsize = AtomicUsize::new(0);

/// Look up an export of kernel32.dll once and cache it in `slot`.
fn kernel32_export(slot: &AtomicUsize, name: &[u8]) -> Option<usize> {
    match slot.load(Ordering::Acquire) {
        0 => {}
        1 => return None,
        addr => return Some(addr),
    }
    // "kernel32.dll" as a NUL-terminated UTF-16 string.
    let mut module_name = [0u16; 13];
    for (dst, &src) in module_name.iter_mut().zip(b"kernel32.dll") {
        *dst = u16::from(src);
    }
    // SAFETY: `module_name` is a NUL-terminated UTF-16 string. kernel32 is
    // loaded into every Win32 process, so the handle is valid for the life
    // of the process and needs no reference counting.
    let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
    let addr = if module.is_null() {
        None
    } else {
        // SAFETY: `name` is a NUL-terminated ASCII export name and
        // `module` is a valid module handle.
        unsafe { GetProcAddress(module, name.as_ptr()) }.map(|f| f as usize)
    };
    slot.store(addr.unwrap_or(1), Ordering::Release);
    addr
}

/// Exclude the pages from Windows Error Reporting crash dumps with
/// `WerRegisterExcludedMemoryBlock`. Returns `false` if the API is
/// missing (Windows before 10 1709) or refuses (WER keeps a small
/// per-process table of excluded blocks).
///
/// Dumps written by other tools (`MiniDumpWriteDump` with full memory,
/// debuggers, Task Manager, procdump) do not consult this list.
///
/// # Safety
///
/// `[ptr, ptr + len)` must be committed memory of this process.
pub(super) unsafe fn exclude_from_dumps(ptr: *const u8, len: usize) -> bool {
    let Ok(size) = u32::try_from(len) else {
        return false;
    };
    let Some(addr) = kernel32_export(&WER_REGISTER, b"WerRegisterExcludedMemoryBlock\0") else {
        return false;
    };
    // SAFETY: `addr` came from `GetProcAddress` for this exact export, whose
    // documented signature is `HRESULT (const void*, DWORD)`.
    let register: WerRegister = unsafe { core::mem::transmute::<usize, WerRegister>(addr) };
    // SAFETY: the range is committed memory of this process.
    let hr = unsafe { register(ptr.cast(), size) };
    hr >= 0
}

/// Undo [`exclude_from_dumps`].
///
/// # Safety
///
/// `ptr` must be the address of a block registered by
/// [`exclude_from_dumps`].
pub(super) unsafe fn include_in_dumps(ptr: *const u8, _len: usize) {
    let Some(addr) = kernel32_export(&WER_UNREGISTER, b"WerUnregisterExcludedMemoryBlock\0") else {
        return;
    };
    // SAFETY: as in `exclude_from_dumps`; documented signature
    // `HRESULT (const void*)`.
    let unregister: WerUnregister = unsafe { core::mem::transmute::<usize, WerUnregister>(addr) };
    // SAFETY: `ptr` was registered by `exclude_from_dumps`.
    let _ = unsafe { unregister(ptr.cast()) };
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

/// Reserve and commit `len` bytes of read-write memory. Returns `None`
/// if the allocation fails.
pub(super) fn map_region(len: usize) -> Option<*mut u8> {
    // SAFETY: a null address asks the system to choose the location; no
    // other preconditions.
    let p = unsafe {
        VirtualAlloc(
            core::ptr::null(),
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(p.cast::<u8>())
    }
}

/// Release a region from [`map_region`].
///
/// # Safety
///
/// `ptr` must be the base address returned by [`map_region`], and nothing
/// may use the region afterwards.
pub(super) unsafe fn unmap_region(ptr: *mut u8, _len: usize) {
    // SAFETY: per the caller's contract this is the base of our own
    // allocation; `MEM_RELEASE` requires a size of 0.
    let _ = unsafe { VirtualFree(ptr.cast(), 0, MEM_RELEASE) };
}

/// Change the protection of a region from [`map_region`].
///
/// # Safety
///
/// `ptr` / `len` must lie within a live region from [`map_region`]. With
/// [`Access::None`], nothing may touch the memory until access is
/// restored.
pub(super) unsafe fn protect(ptr: *mut u8, len: usize, access: Access) -> bool {
    let prot: PAGE_PROTECTION_FLAGS = match access {
        Access::None => PAGE_NOACCESS,
        Access::Read => PAGE_READONLY,
        Access::ReadWrite => PAGE_READWRITE,
    };
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    // SAFETY: per the caller's contract the range is our own committed
    // region; `old` is a valid out-pointer.
    unsafe { VirtualProtect(ptr.cast(), len, prot, &raw mut old) != 0 }
}
