//! Helpers shared by unit tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_os = "linux")]
use alloc::string::{String, ToString};
#[cfg(target_os = "linux")]
use alloc::vec::Vec;

/// The `/proc/self/smaps` block for the mapping containing `addr`:
/// its `VmFlags` entries (for example `"dd"` for `MADV_DONTDUMP`).
#[cfg(target_os = "linux")]
pub(crate) fn smaps_flags(addr: usize) -> Vec<String> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("read /proc/self/smaps");
    let mut inside = false;
    for line in smaps.lines() {
        if let Some((start, end)) = mapping_range(line) {
            inside = (start..end).contains(&addr);
            continue;
        }
        if inside {
            if let Some(flags) = line.strip_prefix("VmFlags:") {
                return flags.split_whitespace().map(ToString::to_string).collect();
            }
        }
    }
    Vec::new()
}

/// A `kB` field (for example `"Locked"`) of the `/proc/self/smaps` block
/// for the mapping containing `addr`.
#[cfg(target_os = "linux")]
pub(crate) fn smaps_value(addr: usize, field: &str) -> Option<u64> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("read /proc/self/smaps");
    let mut inside = false;
    let prefix = alloc::format!("{field}:");
    for line in smaps.lines() {
        if let Some((start, end)) = mapping_range(line) {
            inside = (start..end).contains(&addr);
            continue;
        }
        if inside {
            if let Some(rest) = line.strip_prefix(&prefix) {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
    }
    None
}

/// The permission string (`"r--p"`, `"---p"`, ...) of the mapping
/// containing `addr`, from `/proc/self/maps`.
#[cfg(target_os = "linux")]
pub(crate) fn maps_perms(addr: usize) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
    maps.lines().find_map(|line| {
        let (start, end) = mapping_range(line)?;
        if (start..end).contains(&addr) {
            line.split_whitespace().nth(1).map(ToString::to_string)
        } else {
            None
        }
    })
}

/// Parse the `start-end` address range at the start of a maps / smaps
/// mapping header line.
#[cfg(target_os = "linux")]
fn mapping_range(line: &str) -> Option<(usize, usize)> {
    let range = line.split_whitespace().next()?;
    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    Some((start, end))
}

/// `Protect` value of the region containing `addr`, from `VirtualQuery`.
#[cfg(windows)]
pub(crate) fn virtual_query_protect(addr: usize) -> u32 {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    // SAFETY: all-zero is a valid MEMORY_BASIC_INFORMATION.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: `info` is a valid out-buffer of the size we pass.
    let n = unsafe {
        VirtualQuery(
            addr as *const core::ffi::c_void,
            &raw mut info,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(n, 0, "VirtualQuery failed");
    info.Protect
}
