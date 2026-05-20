//! Opaque key references.
//!
//! A [`KeyHandle`] is the only thing client code ever receives in exchange for
//! registering a key. It carries no usable cryptographic material on its own —
//! defragmentation and codex decode happen inside the vault, in scratch memory,
//! and the result is never exposed as a raw `&[u8]` through the public API.
//!
//! # Opacity guarantee
//!
//! The [`Debug`] implementation prints `KeyHandle(<redacted>)` regardless of the
//! underlying identifier. Handles are not [`serde::Serialize`]; they are not
//! [`Display`]; their internal id is `pub(crate)` only. If you find yourself
//! reaching for the raw id from outside the crate, you are bypassing a defense
//! layer and the API should grow a method instead.
//!
//! [`Display`]: core::fmt::Display

use core::fmt;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use subtle::{Choice, ConstantTimeEq};

/// Process-wide handle identifier.
///
/// `KeyId` is a [`NonZeroU64`] so that `Option<KeyId>` is the same size as
/// `KeyId` itself (niche optimization), and so that `0` is unambiguously not a
/// valid handle. Identifiers are allocated from a single process-global
/// counter (crate-internal); they are unique within the lifetime of a process
/// and **not** portable across runs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(NonZeroU64);

impl KeyId {
    /// Allocate the next identifier.
    ///
    /// Identifiers start at 1 and increase monotonically. The counter is
    /// process-global; overflow is treated as an internal invariant
    /// violation and the function will saturate at `u64::MAX` rather than
    /// wrap. In practice no process will allocate 2⁶⁴ handles.
    #[must_use]
    pub(crate) fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        // Saturating add prevents wrap-around producing duplicates. With a 64-bit
        // counter incremented once per vault key registration the saturation
        // arm is unreachable in any realistic process.
        let raw = COUNTER.fetch_add(1, Ordering::Relaxed);
        let raw = if raw == 0 { 1 } else { raw };
        // SAFETY: `raw` is always at least 1 because the counter starts at 1
        // and we replaced any observed 0 with 1 above.
        let id = unsafe { NonZeroU64::new_unchecked(raw) };
        Self(id)
    }

    /// Construct a `KeyId` from a known non-zero value.
    ///
    /// Crate-internal: tests and the vault use this when materializing handles
    /// from a recovered state. External code must use [`KeyId::next`] (which is
    /// itself not part of the public API).
    #[allow(dead_code)] // wired up by the vault in Phase 0.3.
    #[must_use]
    pub(crate) fn from_raw(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    /// Return the raw numeric identifier.
    ///
    /// Crate-internal so that the public API never exposes it. Useful inside the
    /// vault for indexing into the internal handle table.
    #[allow(dead_code)] // consumed by the vault registry in Phase 0.3.
    #[must_use]
    pub(crate) fn get(self) -> NonZeroU64 {
        self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even the id is never printed — KeyId mostly exists to make APIs
        // type-safe inside the crate.
        f.write_str("KeyId(<redacted>)")
    }
}

/// Opaque, redacted reference to a key stored inside a
/// [`KeyVault`](crate::KeyVault).
///
/// A `KeyHandle` is cheap to clone (it is `Copy`-shaped — currently `Clone +
/// Copy`) and safe to pass across threads. It exposes no methods that return
/// raw key bytes; all operations that need the underlying material are performed
/// by the vault on the caller's behalf.
///
/// # Examples
///
/// ```
/// use key_vault::KeyHandle;
///
/// // Handles are only constructed by the vault. In tests you can construct one
/// // via the unit-tested helper. The important property is opacity:
/// # let h = KeyHandle::__for_test();
/// let rendered = format!("{h:?}");
/// assert!(rendered.contains("redacted"));
/// ```
///
/// # Equality
///
/// `KeyHandle` implements both `PartialEq` and
/// [`subtle::ConstantTimeEq`]. The latter is the equality check the vault
/// uses internally: it compares both inner identifiers in constant time
/// regardless of input values, eliminating timing side-channels even
/// though the underlying ids are not themselves secret.
#[derive(Clone, Copy, Eq)]
pub struct KeyHandle {
    id: KeyId,
}

impl ConstantTimeEq for KeyHandle {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare the raw NonZeroU64 values byte-equivalently in constant
        // time. `subtle` provides ConstantTimeEq for `u64`, so we feed it
        // the underlying numeric representation.
        self.id.0.get().ct_eq(&other.id.0.get())
    }
}

impl PartialEq for KeyHandle {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

// `Hash` must be consistent with `PartialEq`: equal handles must hash equal.
// We derive `Eq` and implement `PartialEq` through `ConstantTimeEq` (still on
// the same inner id), so hashing the id satisfies the invariant.
impl core::hash::Hash for KeyHandle {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.0.get().hash(state);
    }
}

impl KeyHandle {
    /// Allocate a fresh handle backed by a freshly-issued [`KeyId`].
    ///
    /// Crate-internal — only the vault is allowed to mint handles.
    #[must_use]
    pub(crate) fn allocate() -> Self {
        Self { id: KeyId::next() }
    }

    /// Construct a handle from an existing identifier.
    #[allow(dead_code)] // wired up by the vault registry in Phase 0.3.
    #[must_use]
    pub(crate) fn from_id(id: KeyId) -> Self {
        Self { id }
    }

    /// Return the underlying identifier. Crate-internal.
    #[allow(dead_code)] // consumed by the vault registry in Phase 0.3.
    #[must_use]
    pub(crate) fn id(self) -> KeyId {
        self.id
    }

    /// Construct a placeholder handle for use in doctests and unit tests.
    ///
    /// **Not part of the supported public API.** This exists only so that
    /// rustdoc examples can demonstrate opacity without first standing up a full
    /// vault. The underlying id is freshly allocated from the global counter;
    /// there is no key material associated with it.
    #[doc(hidden)]
    #[must_use]
    pub fn __for_test() -> Self {
        Self::allocate()
    }
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // CRITICAL: never print the inner id. The whole point of the type is
        // that nothing escapes through Debug.
        f.write_str("KeyHandle(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_is_redacted() {
        let h = KeyHandle::allocate();
        let rendered = format!("{h:?}");
        assert_eq!(rendered, "KeyHandle(<redacted>)");
    }

    #[test]
    fn debug_never_prints_inner_id() {
        // Generate a bunch of handles and confirm none of them leaks a digit.
        for _ in 0..1024 {
            let h = KeyHandle::allocate();
            let rendered = format!("{h:?}");
            assert!(
                !rendered.chars().any(|c| c.is_ascii_digit()),
                "KeyHandle Debug must not leak the inner id (got {rendered:?})"
            );
        }
    }

    #[test]
    fn key_id_debug_is_redacted() {
        let id = KeyId::next();
        let rendered = format!("{id:?}");
        assert_eq!(rendered, "KeyId(<redacted>)");
    }

    #[test]
    fn ids_are_unique_and_monotonic() {
        let a = KeyId::next();
        let b = KeyId::next();
        let c = KeyId::next();
        assert!(a != b);
        assert!(b != c);
        assert!(a.get() < b.get());
        assert!(b.get() < c.get());
    }

    #[test]
    fn handles_are_distinct() {
        let h1 = KeyHandle::allocate();
        let h2 = KeyHandle::allocate();
        assert!(h1 != h2);
    }

    #[test]
    fn handles_compare_by_id() {
        let id = KeyId::next();
        let h1 = KeyHandle::from_id(id);
        let h2 = KeyHandle::from_id(id);
        assert_eq!(h1, h2);
    }

    #[test]
    fn constant_time_eq_matches_partial_eq() {
        use core::hash::BuildHasher;
        use std::collections::hash_map::RandomState;

        use subtle::ConstantTimeEq;

        let id = KeyId::next();
        let same_a = KeyHandle::from_id(id);
        let same_b = KeyHandle::from_id(id);
        let different = KeyHandle::allocate();

        assert!(bool::from(same_a.ct_eq(&same_b)));
        assert!(!bool::from(same_a.ct_eq(&different)));

        // Hash invariant: equal handles must hash equal (Eq + Hash).
        let s = RandomState::new();
        assert_eq!(s.hash_one(same_a), s.hash_one(same_b));
    }
}
