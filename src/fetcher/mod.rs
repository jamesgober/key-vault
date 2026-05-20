//! Layer 1 — Secure Acquisition.
//!
//! The [`KeyFetch`] trait abstracts the source of raw key material. It is the
//! seam through which keys enter the vault: a TPM, an OS keychain, an encrypted
//! file, an environment variable, or a custom user-provided source.
//!
//! Implementations of [`KeyFetch`] are responsible for:
//!
//! - returning a redaction-clean [`Error`](crate::Error) on failure (no key bytes
//!   in error messages);
//! - performing acquisition synchronously — the vault treats fetch as a slow
//!   path and does not retry on its own;
//! - emitting audit events via the configured logging facility when applicable.
//!
//! The trait does **not** specify caching: fetchers are called exactly once per
//! key registration; the vault keeps the post-fragmentation representation in
//! memory after that. Re-acquiring a key is the caller's decision.
//!
//! Concrete implementations land in later phases. This module currently defines
//! only the trait surface, the [`FetchContext`] passed to it, and the
//! [`RawKey`] container that wraps the returned bytes.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::Result;

#[cfg(feature = "fetcher-env")]
mod env;
#[cfg(feature = "fetcher-file")]
mod file;
#[cfg(feature = "fetcher-keychain")]
mod keychain;
#[cfg(feature = "fetcher-tpm")]
mod tpm;

#[cfg(feature = "fetcher-env")]
pub use self::env::EnvFetch;
#[cfg(feature = "fetcher-file")]
pub use self::file::FileFetch;
#[cfg(feature = "fetcher-keychain")]
pub use self::keychain::KeychainFetch;
#[cfg(feature = "fetcher-tpm")]
pub use self::tpm::TpmFetch;

/// Information given to a [`KeyFetch`] implementation when it is asked to
/// produce a key.
///
/// The struct is `#[non_exhaustive]` — additional fields (a tracing span, a
/// caller identifier, telemetry hooks) will be added in later phases without
/// requiring a major version bump.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FetchContext {
    /// Logical name of the key being requested.
    ///
    /// Fetchers that talk to a named store (keychain entries, environment
    /// variables, file paths) use this to disambiguate which key to load.
    /// It does **not** carry any policy meaning to the vault itself.
    pub key_name: String,
}

impl FetchContext {
    /// Construct a context for the given logical key name.
    #[must_use]
    pub fn new(key_name: impl Into<String>) -> Self {
        Self {
            key_name: key_name.into(),
        }
    }
}

/// Container for raw key material returned by a [`KeyFetch`] implementation.
///
/// `RawKey` deliberately exposes no method that returns a borrowed `&[u8]` to
/// outside the crate. The only consumers of the inner bytes are the
/// fragmentation pipeline and (eventually) the zero-on-drop wrapper introduced
/// in Phase 0.3. From outside `key-vault` you can construct a `RawKey`, hand it
/// to the vault, and never see it again.
///
/// # Layout
///
/// In this phase `RawKey` stores the bytes in a plain [`Vec<u8>`]. Phase 0.3
/// will swap this for `Zeroizing<Vec<u8>>` from the `zeroize` crate without a
/// public API change.
pub struct RawKey {
    bytes: Vec<u8>,
}

impl RawKey {
    /// Wrap a freshly-acquired byte buffer.
    ///
    /// Callers are expected to overwrite the original buffer immediately after
    /// constructing the `RawKey` if they kept a copy (for example a stack
    /// buffer from `read_exact`). The vault itself never holds a separate
    /// borrow.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Number of raw key bytes.
    ///
    /// Not redacted — the *length* of a key does not by itself compromise the
    /// secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the key contains zero bytes. A zero-length key is
    /// almost always a configuration error; the vault rejects such keys at
    /// registration.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Crate-internal access to the raw bytes for the fragmentation pipeline.
    ///
    /// This is `pub(crate)` and not part of the public API. The only legitimate
    /// consumers live inside this crate.
    #[allow(dead_code)] // wired up by FragmentStrategy implementations in Phase 0.3.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for RawKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the raw bytes through Debug. Print only the length.
        f.debug_struct("RawKey")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Drop for RawKey {
    fn drop(&mut self) {
        // Volatile-zero every byte before the underlying Vec frees its
        // allocation. Without the volatile + fence pair the compiler is
        // free to elide the writes since the buffer is about to drop.
        if !self.bytes.is_empty() {
            // SAFETY: `self.bytes.as_mut_ptr()` is the start of a valid
            // `self.bytes.len()`-byte allocation we own. Writes are
            // within the buffer's bounds and only touch initialized
            // bytes.
            unsafe {
                let ptr = self.bytes.as_mut_ptr();
                for i in 0..self.bytes.len() {
                    core::ptr::write_volatile(ptr.add(i), 0u8);
                }
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Pluggable source of key material.
///
/// Implementors describe themselves through [`KeyFetch::describe`]; that name
/// appears in audit events and in [`Error::Acquisition`](crate::Error::Acquisition)
/// when the fetcher fails.
///
/// # Implementor contract
///
/// - **No retries.** A failure to find a key is a configuration error from the
///   vault's perspective; the fetcher should report it once and return.
/// - **No caching.** The fetcher is called once per key registration. Caching
///   inside the fetcher defeats the vault's storage discipline.
/// - **Sanitized errors.** Returned errors must not include key material or
///   any secret-equivalent value (passwords, tokens, file contents).
/// - **`Send + Sync`.** The vault may invoke the fetcher from any thread.
pub trait KeyFetch: Send + Sync {
    /// Acquire raw key material from the underlying source.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Acquisition`](crate::Error::Acquisition) when the source
    /// is reachable but the key cannot be obtained (missing entry, permission
    /// denied, decryption failure). The `source` field of the error must match
    /// the value returned by [`KeyFetch::describe`].
    fn fetch(&self, ctx: &FetchContext) -> Result<RawKey>;

    /// Short, machine-friendly identifier for this fetcher (e.g. `"keychain"`,
    /// `"file"`, `"env"`). Used for audit records and error attribution.
    ///
    /// The returned value should be stable across calls and free of secret
    /// information.
    fn describe(&self) -> Cow<'_, str>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn raw_key_debug_is_redacted() {
        let key = RawKey::new(alloc::vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("aa"));
        assert!(!rendered.contains("bb"));
        assert!(rendered.contains("len"));
    }

    #[test]
    fn raw_key_len_and_empty() {
        let empty = RawKey::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let one = RawKey::new(alloc::vec![1, 2, 3]);
        assert!(!one.is_empty());
        assert_eq!(one.len(), 3);
    }

    #[test]
    fn fetch_context_holds_name() {
        let ctx = FetchContext::new("db-primary");
        assert_eq!(ctx.key_name, "db-primary");
    }
}
