//! Locking primitives that work with and without `std`.
//!
//! With `std`, [`Mutex`] wraps `std::sync::Mutex` and ignores poisoning
//! (every lock in this crate guards plain data whose invariants hold even
//! if a holder panicked). Without `std` it is a small spin lock: bare-metal
//! targets have no threads to park, and the critical sections here are a
//! few instructions long.
//!
//! [`ArcCell`] is the registry container for `no_std` builds, where
//! `arc-swap` is not available. `std` builds use `arc_swap::ArcSwap`.

#[cfg(not(feature = "std"))]
use core::cell::UnsafeCell;
#[cfg(not(feature = "std"))]
use core::ops::{Deref, DerefMut};
#[cfg(not(feature = "std"))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Mutual exclusion lock. See the module docs.
#[cfg(feature = "std")]
pub(crate) struct Mutex<T>(std::sync::Mutex<T>);

#[cfg(feature = "std")]
impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    /// Lock, recovering the data from a poisoned lock.
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Try to lock without blocking. Test helper.
    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        matches!(self.0.try_lock(), Err(std::sync::TryLockError::WouldBlock))
    }
}

/// Mutual exclusion lock. See the module docs.
#[cfg(not(feature = "std"))]
pub(crate) struct Mutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: access to `value` is serialized by `locked` (acquire on lock,
// release on unlock), so sharing the lock between threads only ever hands
// out one `&mut T` at a time. `T: Send` is required because the value can
// be reached from whichever thread takes the lock.
#[cfg(not(feature = "std"))]
unsafe impl<T: Send> Sync for Mutex<T> {}
// SAFETY: moving the lock moves the value; that is fine when `T: Send`.
#[cfg(not(feature = "std"))]
unsafe impl<T: Send> Send for Mutex<T> {}

#[cfg(not(feature = "std"))]
impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Spin until the lock is free, then take it.
    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinGuard { lock: self }
    }
}

/// Guard returned by the `no_std` [`Mutex::lock`].
#[cfg(not(feature = "std"))]
pub(crate) struct SpinGuard<'a, T> {
    lock: &'a Mutex<T>,
}

#[cfg(not(feature = "std"))]
impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while `locked` is held by us.
        unsafe { &*self.lock.value.get() }
    }
}

#[cfg(not(feature = "std"))]
impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard exists only while `locked` is held by us, and
        // `&mut self` makes this the only borrow through the guard.
        unsafe { &mut *self.lock.value.get() }
    }
}

#[cfg(not(feature = "std"))]
impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// Atomically replaceable `Arc<T>` for `no_std` builds. Readers take the
/// lock only long enough to clone the `Arc`.
#[cfg(not(feature = "std"))]
pub(crate) struct ArcCell<T> {
    inner: Mutex<alloc::sync::Arc<T>>,
}

#[cfg(not(feature = "std"))]
impl<T> ArcCell<T> {
    pub(crate) fn from_pointee(value: T) -> Self {
        Self {
            inner: Mutex::new(alloc::sync::Arc::new(value)),
        }
    }

    /// Current value. Named like `ArcSwap::load` so the vault code is the
    /// same in both builds.
    pub(crate) fn load(&self) -> alloc::sync::Arc<T> {
        alloc::sync::Arc::clone(&self.inner.lock())
    }

    pub(crate) fn load_full(&self) -> alloc::sync::Arc<T> {
        self.load()
    }

    /// Install `new` and return the previous value.
    pub(crate) fn swap(&self, new: alloc::sync::Arc<T>) -> alloc::sync::Arc<T> {
        core::mem::replace(&mut *self.inner.lock(), new)
    }
}
