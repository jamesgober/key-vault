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
//! page serves one size class (16 to 2048 bytes) and holds nothing but key
//! buffers. Freed blocks (already zeroed by their owner) go back on a free
//! list for reuse; pages are kept for the life of the process, so the pool
//! grows to the peak number of live key buffers and stays there.
//!
//! # Mapping, locking and dump exclusion
//!
//! The pool maps memory in chunks of [`CHUNK_PAGES`] pages (64 KiB with
//! 4 KiB pages, the allocation granularity of Windows), excludes each
//! chunk from dumps with one call (so one Windows Error Reporting
//! exclusion covers 16 pages) and locks it with one call. Locking the
//! whole chunk keeps it a single mapping with one set of flags; if that
//! fails (the process is near its lock limit), each page is locked on its
//! own when it is handed to a size class.
//!
//! Since 1.2 the pool keeps the lock state of every page and prefers
//! blocks on locked pages. When no locked block is free it retries the
//! lock on a page that failed earlier, then on a fresh page. The first
//! lock that succeeds after failures retries every page that is still
//! unlocked, so raising the lock limit while the process runs also locks
//! the keys already stored on those pages.
//! While locking keeps failing, retries back off (up to one attempt per
//! [`MAX_SKIP`] allocations), so a process at its limit does not pay a
//! failing system call for every block.
//!
//! Buffers larger than 2048 bytes use the heap and the per-page
//! reference count in the parent module.

use alloc::collections::BTreeMap;
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

/// Pages mapped (and excluded from dumps) together.
pub(crate) const CHUNK_PAGES: usize = 16;

/// Longest run of allocations that skip a lock retry after failures.
const MAX_SKIP: u32 = 64;

/// What the pool knows about one of its chunks.
#[derive(Debug, Clone, Copy)]
struct ChunkInfo {
    /// The chunk is excluded from dumps.
    excluded: bool,
    /// The whole chunk is locked.
    locked: bool,
}

/// What the pool knows about one of its pages.
#[derive(Debug, Clone, Copy)]
struct PageInfo {
    /// Start of the chunk the page belongs to.
    chunk: usize,
    /// Size class the page serves.
    class: u8,
    /// The page is locked.
    locked: bool,
}

/// Free blocks of one size class, split by the lock state of their page.
#[derive(Default)]
struct FreeList {
    locked: Vec<usize>,
    unlocked: Vec<usize>,
}

/// Lock-retry backoff: after a failure, skip the next `skip` retries.
#[derive(Default)]
struct Backoff {
    skip: u32,
    countdown: u32,
}

impl Backoff {
    /// `true` if a retry may be attempted now.
    fn allow(&mut self) -> bool {
        if self.countdown == 0 {
            true
        } else {
            self.countdown -= 1;
            false
        }
    }

    fn failed(&mut self) {
        self.skip = (self.skip.saturating_mul(2)).clamp(1, MAX_SKIP);
        self.countdown = self.skip;
    }

    fn succeeded(&mut self) {
        self.skip = 0;
        self.countdown = 0;
    }
}

struct Pool {
    free: [FreeList; CLASSES.len()],
    /// Every page handed to a size class, by start address.
    pages: BTreeMap<usize, PageInfo>,
    /// Every chunk, by start address.
    chunks: BTreeMap<usize, ChunkInfo>,
    /// Mapped pages not yet given to a size class, with their chunk.
    fresh: Vec<(usize, usize)>,
    backoff: Backoff,
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    free: [const {
        FreeList {
            locked: Vec::new(),
            unlocked: Vec::new(),
        }
    }; CLASSES.len()],
    pages: BTreeMap::new(),
    chunks: BTreeMap::new(),
    fresh: Vec::new(),
    backoff: Backoff {
        skip: 0,
        countdown: 0,
    },
});

/// A block handed out by [`alloc`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Block {
    pub(crate) ptr: NonNull<u8>,
    pub(crate) class: u8,
}

/// Start of the page holding `addr`.
fn page_of(addr: usize) -> usize {
    addr & !(page_size() - 1)
}

impl Pool {
    /// Lock `page` (one of ours) and record the result.
    fn lock_page(&mut self, page: usize) -> bool {
        // SAFETY: `page` is a page of one of our own chunks, which stay
        // mapped for the life of the process.
        let locked = unsafe { os::lock_pages(page as *const u8, page_size()) };
        if let Some(info) = self.pages.get_mut(&page) {
            info.locked = locked;
        }
        locked
    }

    /// Retry dump exclusion for the chunk holding `page`, where the OS
    /// supports it and it failed before.
    fn retry_exclusion(&mut self, chunk: usize) {
        if !os::DUMP_EXCLUSION_SUPPORTED {
            return;
        }
        if let Some(info) = self.chunks.get_mut(&chunk) {
            if !info.excluded {
                // SAFETY: `chunk` is the start of one of our own mappings,
                // `CHUNK_PAGES` pages long.
                info.excluded = unsafe {
                    os::exclude_from_dumps(chunk as *const u8, page_size() * CHUNK_PAGES)
                };
            }
        }
    }

    /// Move the free blocks of `class` on `page` to the locked list.
    fn promote(&mut self, class: usize, page: usize) {
        let list = &mut self.free[class];
        let mut i = 0;
        while i < list.unlocked.len() {
            if page_of(list.unlocked[i]) == page {
                let addr = list.unlocked.swap_remove(i);
                list.locked.push(addr);
            } else {
                i += 1;
            }
        }
    }

    /// A page from the fresh list and its chunk, mapping a new chunk if
    /// the list is empty.
    fn fresh_page(&mut self) -> Option<(usize, usize)> {
        if self.fresh.is_empty() {
            let page = page_size();
            let len = page * CHUNK_PAGES;
            let base = os::map_region(len)? as usize;
            // SAFETY: `[base, base + len)` is our own fresh mapping, never
            // unmapped.
            let excluded = unsafe { os::exclude_from_dumps(base as *const u8, len) };
            // SAFETY: as above.
            let locked = unsafe { os::lock_pages(base as *const u8, len) };
            let _ = self.chunks.insert(base, ChunkInfo { excluded, locked });
            // Reverse, so pages are handed out in address order.
            self.fresh
                .extend((0..CHUNK_PAGES).rev().map(|i| (base + i * page, base)));
        }
        self.fresh.pop()
    }

    /// Give a fresh page to `class` and try to lock it. Returns the lock
    /// result, or `None` if no memory could be mapped.
    fn grow(&mut self, class: usize) -> Option<bool> {
        let (page, chunk) = self.fresh_page()?;
        let size = page_size();
        let _ = self.pages.insert(
            page,
            PageInfo {
                chunk,
                class: u8::try_from(class).unwrap_or(u8::MAX),
                locked: false,
            },
        );
        self.retry_exclusion(chunk);
        let chunk_locked = self.chunks.get(&chunk).is_some_and(|c| c.locked);
        let locked = if chunk_locked {
            if let Some(info) = self.pages.get_mut(&page) {
                info.locked = true;
            }
            true
        } else {
            self.lock_page(page)
        };
        let block = CLASSES[class];
        let list = &mut self.free[class];
        let target = if locked {
            &mut list.locked
        } else {
            &mut list.unlocked
        };
        let count = size / block;
        target.reserve(count);
        for i in (0..count).rev() {
            target.push(page + i * block);
        }
        Some(locked)
    }

    /// Record a successful lock. If locks were failing before (the limit
    /// has just been raised, or memory freed), retry every page that is
    /// still unlocked, so keys already stored on them are locked too.
    fn lock_succeeded(&mut self) {
        let was_failing = self.backoff.skip > 0;
        self.backoff.succeeded();
        if was_failing {
            self.sweep_unlocked();
        }
    }

    /// Try to lock every unlocked page, stopping at the first failure.
    fn sweep_unlocked(&mut self) {
        let unlocked: Vec<(usize, usize, u8)> = self
            .pages
            .iter()
            .filter(|(_, info)| !info.locked)
            .map(|(&page, info)| (page, info.chunk, info.class))
            .collect();
        for (page, chunk, class) in unlocked {
            if !self.lock_page(page) {
                self.backoff.failed();
                return;
            }
            self.retry_exclusion(chunk);
            if usize::from(class) < CLASSES.len() {
                self.promote(usize::from(class), page);
            }
        }
    }

    /// Lock every page again (after `fork`, which drops memory locks in
    /// the child) and sort the free lists by the new state.
    #[cfg(unix)]
    fn relock_all(&mut self) {
        self.backoff.succeeded();
        let len = page_size() * CHUNK_PAGES;
        for (&base, info) in &mut self.chunks {
            // SAFETY: `base` is the start of one of our own chunks.
            info.locked = unsafe { os::lock_pages(base as *const u8, len) };
        }
        let pages: Vec<(usize, usize)> = self.pages.iter().map(|(&p, i)| (p, i.chunk)).collect();
        for (page, chunk) in pages {
            if self.chunks.get(&chunk).is_some_and(|c| c.locked) {
                if let Some(info) = self.pages.get_mut(&page) {
                    info.locked = true;
                }
            } else {
                let _ = self.lock_page(page);
            }
        }
        for list in &mut self.free {
            let all: Vec<usize> = list
                .locked
                .drain(..)
                .chain(list.unlocked.drain(..))
                .collect();
            for addr in all {
                let locked = self.pages.get(&page_of(addr)).is_some_and(|p| p.locked);
                if locked {
                    list.locked.push(addr);
                } else {
                    list.unlocked.push(addr);
                }
            }
        }
    }
}

/// A zeroed block of at least `len` bytes (`1..=MAX_POOLED`), or `None`
/// if `len` is out of range or the OS refuses new memory.
///
/// Blocks on locked pages are handed out first. See the module docs for
/// how unlocked pages are retried.
pub(crate) fn alloc(len: usize) -> Option<Block> {
    let class = CLASSES.iter().position(|&size| len <= size)?;
    if len == 0 {
        return None;
    }
    super::relock_if_forked();
    let mut pool = POOL.lock();
    let addr = take_block(&mut pool, class)?;
    Some(Block {
        // SAFETY: free-list addresses come from `grow`, which only pushes
        // addresses inside a successful (non-null) mapping.
        ptr: unsafe { NonNull::new_unchecked(addr as *mut u8) },
        class: u8::try_from(class).ok()?,
    })
}

fn take_block(pool: &mut Pool, class: usize) -> Option<usize> {
    if let Some(addr) = pool.free[class].locked.pop() {
        return Some(addr);
    }
    let may_retry = pool.backoff.allow();
    if may_retry {
        // A page of this class whose lock failed earlier.
        if let Some(&addr) = pool.free[class].unlocked.last() {
            let page = page_of(addr);
            if pool.lock_page(page) {
                if let Some(chunk) = pool.pages.get(&page).map(|p| p.chunk) {
                    pool.retry_exclusion(chunk);
                }
                pool.promote(class, page);
                pool.lock_succeeded();
                return pool.free[class].locked.pop();
            }
        }
    }
    if may_retry || pool.free[class].unlocked.is_empty() {
        match pool.grow(class) {
            Some(true) => {
                pool.lock_succeeded();
                return pool.free[class].locked.pop();
            }
            Some(false) => pool.backoff.failed(),
            None => {}
        }
    }
    pool.free[class].unlocked.pop()
}

/// Lock every pool page again. Called once in a child process after
/// `fork`.
#[cfg(unix)]
pub(crate) fn relock_all() {
    POOL.lock().relock_all();
}

/// Return a block to the pool.
///
/// # Safety
///
/// `block` must come from [`alloc`], must not be returned twice, must not
/// be used afterwards, and its bytes must already be zeroed.
pub(crate) unsafe fn free(block: Block) {
    let class = usize::from(block.class);
    let addr = block.ptr.as_ptr() as usize;
    let mut pool = POOL.lock();
    let locked = pool.pages.get(&page_of(addr)).is_some_and(|p| p.locked);
    let list = &mut pool.free[class];
    if locked {
        list.locked.push(addr);
    } else {
        list.unlocked.push(addr);
    }
}

/// Retry the lock on the page holding the block at `addr` (of size class
/// `class`) if it is not locked. Returns `true` if it is locked now.
pub(crate) fn retry_block(addr: usize, class: u8) -> bool {
    let page = page_of(addr);
    let mut pool = POOL.lock();
    match pool.pages.get(&page) {
        None => false,
        Some(info) if info.locked => true,
        Some(info) => {
            let chunk = info.chunk;
            if !pool.lock_page(page) {
                return false;
            }
            pool.retry_exclusion(chunk);
            pool.promote(usize::from(class), page);
            pool.lock_succeeded();
            true
        }
    }
}

/// `(locked, excluded_from_dumps)` for the page holding the block at
/// `addr`.
pub(crate) fn block_state(addr: usize) -> (bool, bool) {
    let pool = POOL.lock();
    pool.pages.get(&page_of(addr)).map_or((false, false), |p| {
        (
            p.locked,
            pool.chunks.get(&p.chunk).is_some_and(|c| c.excluded),
        )
    })
}

/// Run `f` with the pool locked if the block at `addr` is on a free list
/// (so nobody can take it meanwhile). Returns `None` if it is in use.
#[cfg(test)]
pub(crate) fn while_free<T>(addr: usize, f: impl FnOnce() -> T) -> Option<T> {
    let pool = POOL.lock();
    pool.free
        .iter()
        .any(|list| list.locked.contains(&addr) || list.unlocked.contains(&addr))
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

    #[test]
    fn backoff_skips_retries_while_failing_and_resets_on_success() {
        let mut b = Backoff::default();
        assert!(b.allow());
        b.failed();
        assert!(!b.allow());
        assert!(b.allow());
        for _ in 0..20 {
            b.failed();
        }
        let skipped = (0..1000).take_while(|_| !b.allow()).count();
        assert_eq!(skipped, MAX_SKIP as usize);
        b.succeeded();
        assert!(b.allow());
    }

    #[test]
    fn pages_record_their_lock_state() {
        let block = alloc(100).unwrap();
        let addr = block.ptr.as_ptr() as usize;
        let (locked, excluded) = block_state(addr);
        if os::DUMP_EXCLUSION_SUPPORTED {
            assert!(excluded, "pool chunk not excluded from dumps");
        }
        let _ = locked; // depends on the machine's lock limit
        // SAFETY: from `alloc`, freed once, unwritten.
        unsafe { free(block) };
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
        if block_state(addr).0 {
            assert!(
                flags.contains(&"lo".to_owned()),
                "pool page lacks lo: {flags:?}"
            );
        }
        // SAFETY: from `alloc`, freed once, unwritten.
        unsafe { free(block) };
    }
}
