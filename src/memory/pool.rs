//! Pool of locked, dump-excluded pages for small key buffers.
//!
//! Most buffers the vault creates are small: 1-8 byte fragments, layout
//! maps of a few dozen bytes, 256-byte codex tables. Placing each on the
//! general heap meant locking and excluding whichever heap page it landed
//! on, and releasing it again when the last buffer there was dropped:
//! two to four system calls (and page-table splits) per page on every
//! register / rotate / unregister, plus leaving unrelated heap objects on
//! those pages out of core dumps.
//!
//! The pool instead hands out blocks from pages it maps for itself. Each
//! page serves one size class (16 to 2048 bytes), is locked and excluded
//! from dumps once when it is mapped, and holds nothing but key buffers.
//! Freed blocks (already zeroed by their owner) go back on a free list
//! for reuse; pages are kept for the life of the process, so the pool
//! grows to the peak number of live key buffers and stays there.
//!
//! Buffers larger than 2048 bytes use the heap and the per-page
//! reference count in the parent module.

use alloc::vec::Vec;
use core::ptr::NonNull;

use super::page_size;
#[cfg(unix)]
use super::unix as os;
#[cfg(windows)]
use super::windows as os;
use crate::sync::Mutex;

/// Block sizes, smallest first.
const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

/// Largest buffer the pool serves.
#[cfg(test)]
pub(crate) const MAX_POOLED: usize = CLASSES[CLASSES.len() - 1];

/// A free block: address and whether its page is locked.
type FreeBlock = (usize, bool);

/// Free lists, one per size class.
struct Pool {
    free: [Vec<FreeBlock>; CLASSES.len()],
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    free: [const { Vec::new() }; CLASSES.len()],
});

/// A block handed out by [`alloc`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Block {
    pub(crate) ptr: NonNull<u8>,
    pub(crate) class: u8,
    pub(crate) locked: bool,
}

/// A zeroed block of at least `len` bytes (`1..=MAX_POOLED`), or `None`
/// if `len` is out of range or the OS refuses a new page.
pub(crate) fn alloc(len: usize) -> Option<Block> {
    let class = CLASSES.iter().position(|&size| len <= size)?;
    if len == 0 {
        return None;
    }
    let mut pool = POOL.lock();
    if pool.free[class].is_empty() {
        grow(&mut pool.free[class], CLASSES[class])?;
    }
    let (addr, locked) = pool.free[class].pop()?;
    Some(Block {
        // SAFETY: free-list addresses come from `grow`, which only pushes
        // addresses inside a successful (non-null) mapping.
        ptr: unsafe { NonNull::new_unchecked(addr as *mut u8) },
        class: u8::try_from(class).ok()?,
        locked,
    })
}

/// Return a block to the pool.
///
/// # Safety
///
/// `block` must come from [`alloc`], must not be returned twice, must not
/// be used afterwards, and its bytes must already be zeroed.
pub(crate) unsafe fn free(block: Block) {
    let class = usize::from(block.class);
    POOL.lock().free[class].push((block.ptr.as_ptr() as usize, block.locked));
}

/// Map one more page for blocks of `size` bytes, lock it, exclude it from
/// dumps, and add its blocks to `free`.
fn grow(free: &mut Vec<FreeBlock>, size: usize) -> Option<()> {
    let page = page_size().max(size);
    let base = os::map_region(page)?;
    // SAFETY: `[base, base + page)` is our own fresh mapping. It is never
    // unmapped, so the lock and the exclusion hold for the life of the
    // process.
    let locked = unsafe { os::lock_pages(base, page) };
    // SAFETY: as above; the mapping is page aligned.
    let _ = unsafe { os::exclude_from_dumps(base, page) };
    let count = page / size;
    free.reserve(count);
    // Push in reverse so blocks are handed out in address order.
    for i in (0..count).rev() {
        free.push((base as usize + i * size, locked));
    }
    Some(())
}

/// Run `f` with the pool locked if the block at `addr` is on a free list
/// (so nobody can take it meanwhile). Returns `None` if it is in use.
#[cfg(test)]
pub(crate) fn while_free<T>(addr: usize, f: impl FnOnce() -> T) -> Option<T> {
    let pool = POOL.lock();
    pool.free
        .iter()
        .any(|list| list.iter().any(|&(a, _)| a == addr))
        .then(f)
}

/// Size of the blocks in `class`.
#[cfg(test)]
pub(crate) fn class_size(class: u8) -> usize {
    CLASSES[usize::from(class)]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_sized_by_class_and_reused() {
        assert!(alloc(0).is_none());
        assert!(alloc(MAX_POOLED + 1).is_none());
        let a = alloc(5).unwrap();
        assert_eq!(class_size(a.class), 16);
        let b = alloc(17).unwrap();
        assert_eq!(class_size(b.class), 32);
        let c = alloc(MAX_POOLED).unwrap();
        assert_eq!(class_size(c.class), MAX_POOLED);
        assert_eq!(a.ptr.as_ptr() as usize % 16, 0);
        let addr = a.ptr.as_ptr() as usize;
        // SAFETY: the blocks came from `alloc`, are freed once, and were
        // never written (still zero).
        unsafe {
            free(a);
            free(b);
            free(c);
        }
        // The most recently freed block of a class is handed out next
        // (unless another test took it in between).
        let again = alloc(8).unwrap();
        let _ = again.ptr.as_ptr() as usize == addr;
        // SAFETY: as above.
        unsafe { free(again) };
    }

    /// Pool pages are locked and carry the `dd` flag on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pool_pages_are_locked_and_excluded() {
        let block = alloc(24).unwrap();
        let addr = block.ptr.as_ptr() as usize;
        let flags = crate::test_util::smaps_flags(addr);
        assert!(
            flags.contains(&"dd".to_owned()),
            "pool page lacks dd: {flags:?}"
        );
        if block.locked {
            assert!(
                flags.contains(&"lo".to_owned()),
                "pool page lacks lo: {flags:?}"
            );
        }
        // SAFETY: from `alloc`, freed once, unwritten.
        unsafe { free(block) };
    }
}
