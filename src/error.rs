//! Error type for the vault.
//!
//! Every fallible operation on a [`KeyVault`](crate::KeyVault) and on the pluggable
//! trait implementations returns [`Result<T>`], which is shorthand for
//! [`core::result::Result<T, Error>`].
//!
//! The variants intentionally carry only sanitized information. **Raw key bytes,
//! cryptographic material, decoy contents, and fragment layouts MUST NEVER appear
//! inside an [`Error`].** The error path is one of the data egress routes that an
//! attacker can observe (logs, panics, traces, alert webhooks), so it is held to
//! the same redaction discipline as [`KeyHandle`](crate::KeyHandle)'s `Debug`
//! impl.
//!
//! [`Error`] is `#[non_exhaustive]` — new variants may be added in minor releases
//! and consumers must include a wildcard arm when matching.

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;

/// Convenient shorthand for results returned by the vault and its trait
/// implementations.
pub type Result<T> = core::result::Result<T, Error>;

/// A redaction-safe error type covering every failure mode the vault can
/// surface.
///
/// Variants are coarse on purpose: callers branch on category (acquisition vs.
/// storage vs. policy) and use the embedded message for diagnostics. Variants
/// must remain free of key material — see the module-level documentation.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// A [`KeyFetch`](crate::KeyFetch) implementation failed to obtain key
    /// material from its source.
    ///
    /// The `source` is a short identifier for the fetcher (for example
    /// `"keychain"`, `"file"`, `"env"`). The `reason` is a redacted, human-readable
    /// explanation that **must not** include the key bytes, the credential, or any
    /// secret-equivalent value.
    Acquisition {
        /// Short identifier for the fetcher that produced the failure.
        source: Cow<'static, str>,
        /// Sanitized explanation. Never key material.
        reason: String,
    },

    /// A lookup failed because no key matching the requested identifier is
    /// registered in the vault.
    KeyNotFound,

    /// Fragmenting the raw key into the configured storage layout failed.
    ///
    /// Reasons include: invalid configuration (for example `frag_max < frag_min`),
    /// or an internal invariant being violated by a custom
    /// [`FragmentStrategy`](crate::FragmentStrategy).
    Fragment(String),

    /// Reassembling fragments back into a usable key failed.
    ///
    /// This is almost always an internal error: the fragmenter and defragmenter
    /// disagreed on the layout, or storage was corrupted.
    Defragment(String),

    /// A decoy strategy could not produce filler bytes for the configured
    /// output length.
    Decoy(String),

    /// A [`Codex`](crate::Codex) failed to encode or decode a byte. Custom codex
    /// implementations may return this if they want to refuse specific inputs;
    /// the built-in codices never do.
    Codex(String),

    /// The vault is locked out: a [`SecurityMonitor`](crate::SecurityMonitor)
    /// threshold has been crossed and access is denied until the configured
    /// recovery condition is met.
    LockedOut,

    /// Acquiring or releasing OS-level memory page locks (mlock / VirtualLock)
    /// failed. This typically means the process has hit its memlock rlimit and
    /// the operator must raise it.
    MemoryLock(String),

    /// The configuration passed to the [`KeyVaultBuilder`](crate::KeyVaultBuilder)
    /// is internally inconsistent.
    InvalidConfig(String),

    /// An internal invariant was violated. Indicates a bug in `key-vault` itself;
    /// please file an issue.
    Internal(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquisition { source, reason } => {
                write!(f, "key acquisition from {source} failed: {reason}")
            }
            Self::KeyNotFound => f.write_str("no key registered under the requested identifier"),
            Self::Fragment(reason) => write!(f, "fragmentation failed: {reason}"),
            Self::Defragment(reason) => write!(f, "defragmentation failed: {reason}"),
            Self::Decoy(reason) => write!(f, "decoy generation failed: {reason}"),
            Self::Codex(reason) => write!(f, "codex transformation failed: {reason}"),
            Self::LockedOut => f.write_str("vault is locked out by security monitor threshold"),
            Self::MemoryLock(reason) => write!(f, "memory lock operation failed: {reason}"),
            Self::InvalidConfig(reason) => write!(f, "invalid vault configuration: {reason}"),
            Self::Internal(reason) => write!(f, "internal vault invariant violated: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    #[test]
    fn display_uses_sanitized_template() {
        let e = Error::Acquisition {
            source: Cow::Borrowed("keychain"),
            reason: "user denied access".to_string(),
        };
        let rendered = format!("{e}");
        assert!(rendered.contains("keychain"));
        assert!(rendered.contains("user denied access"));
    }

    #[test]
    fn key_not_found_has_stable_message() {
        let rendered = format!("{}", Error::KeyNotFound);
        assert!(rendered.contains("no key"));
    }

    #[test]
    fn debug_does_not_panic_for_any_variant() {
        for e in [
            Error::KeyNotFound,
            Error::Fragment("x".to_string()),
            Error::Defragment("x".to_string()),
            Error::Decoy("x".to_string()),
            Error::Codex("x".to_string()),
            Error::LockedOut,
            Error::MemoryLock("x".to_string()),
            Error::InvalidConfig("x".to_string()),
            Error::Internal("x"),
        ] {
            let _ = format!("{e:?}");
        }
    }
}
