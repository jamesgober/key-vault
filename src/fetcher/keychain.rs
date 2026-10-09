//! [`KeychainFetch`] — OS keychain [`KeyFetch`] backend.
//!
//! Wraps the [`keyring`](https://crates.io/crates/keyring) crate to read
//! secrets from the host's native credential store:
//!
//! - **macOS** — Keychain Services
//! - **Windows** — Credential Manager
//! - **Linux** — Secret Service (gnome-keyring, KWallet)
//!
//! Gated behind the `fetcher-keychain` Cargo feature.
//!
//! # Threat profile
//!
//! The native credential stores enforce OS-level access control: secrets
//! are scoped to the user account and (on macOS) to the requesting
//! application's signing identity. This is the strongest built-in
//! fetcher. Use it whenever you have the option.
//!
//! # Text and binary secrets
//!
//! By default the entry is read with `keyring`'s `get_password`, so only
//! UTF-8 values are accepted. A stored binary key fails with "stored value
//! is not UTF-8"; the bytes carried by that error are zeroized before the
//! error is dropped. [`KeychainFetch::binary`] reads the entry with
//! `get_secret` instead and returns the stored bytes as they are. On
//! Windows a value stored as a *password* (with `set_password`) is kept
//! as UTF-16, so reading it in binary mode returns the UTF-16LE bytes;
//! store binary keys with `set_secret`.
//!
//! # Platform stores
//!
//! Since 1.1 the `fetcher-keychain` feature turns on `keyring`'s native
//! stores: Keychain Services on macOS, Credential Manager on Windows, and
//! the Secret Service over D-Bus (pure Rust, no `libdbus` needed) on Linux
//! and the BSDs. Earlier releases depended on `keyring` without any store
//! feature, which made `keyring` fall back to its in-memory mock store, so
//! `KeychainFetch` never reached the OS keychain.
//!
//! # Limits
//!
//! - Buffers inside `keyring` and the platform credential APIs are
//!   outside this crate's control and are not wiped.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};

use zeroize::Zeroize;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// `KeyFetch` implementation that reads from the OS native credential
/// store. Cross-platform via the `keyring` crate.
///
/// Construct with [`KeychainFetch::new`] and the `(service, account)`
/// pair that identifies your entry. Both values are stored verbatim; they
/// appear in failure messages for diagnostics.
///
/// # Examples
///
/// ```no_run
/// use key_vault::{FetchContext, KeyFetch, KeychainFetch};
///
/// # fn main() -> Result<(), key_vault::Error> {
/// let fetcher = KeychainFetch::new("my-app", "primary-key");
/// let raw = fetcher.fetch(&FetchContext::new("primary"))?;
/// # let _ = raw;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeychainFetch {
    service: String,
    account: String,
    binary: bool,
}

impl KeychainFetch {
    /// Construct a fetcher for the given keychain entry.
    ///
    /// `service` is the application or namespace name (e.g. `"my-app"`).
    /// `account` is the entry identifier within that service (e.g.
    /// `"primary-key"`).
    #[must_use]
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
            binary: false,
        }
    }

    /// Read the entry as raw bytes (`keyring`'s `get_secret`) instead of a
    /// UTF-8 password.
    ///
    /// Use this for binary keys stored with `set_secret`. See the module
    /// documentation for how Windows stores passwords.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use key_vault::{FetchContext, KeyFetch, KeychainFetch};
    ///
    /// # fn main() -> Result<(), key_vault::Error> {
    /// let raw = KeychainFetch::new("my-app", "aes-key")
    ///     .binary()
    ///     .fetch(&FetchContext::new("aes-key"))?;
    /// assert_eq!(raw.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn binary(mut self) -> Self {
        self.binary = true;
        self
    }
}

impl KeyFetch for KeychainFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        let entry =
            keyring::Entry::new(&self.service, &self.account).map_err(|e| Error::Acquisition {
                source: Cow::Borrowed("keychain"),
                reason: format!(
                    "could not open keychain entry {}/{}: {}",
                    self.service,
                    self.account,
                    redact_keyring_error(&e),
                ),
            })?;
        let read_error = |e: &keyring::Error| Error::Acquisition {
            source: Cow::Borrowed("keychain"),
            reason: format!(
                "could not read keychain entry {}/{}: {}",
                self.service,
                self.account,
                redact_keyring_error(e),
            ),
        };
        if self.binary {
            let value = entry.get_secret().map_err(|e| read_error(&e))?;
            return Ok(RawKey::new(value));
        }
        let value = entry.get_password().map_err(|mut e| {
            // `BadEncoding` carries the raw secret bytes that failed UTF-8
            // decoding. Wipe them before the error is dropped.
            if let keyring::Error::BadEncoding(bytes) = &mut e {
                bytes.zeroize();
            }
            read_error(&e)
        })?;
        Ok(RawKey::new(value.into_bytes()))
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("keychain")
    }
}

/// Redact the `keyring` crate's error message.
///
/// `keyring` error types carry platform-specific detail (OS error
/// numbers, internal API failures). We expose only the discriminant
/// name — never any embedded credential-adjacent strings.
fn redact_keyring_error(e: &keyring::Error) -> String {
    use keyring::Error;
    match e {
        Error::NoEntry => "no such entry".to_string(),
        Error::BadEncoding(_) => "stored value is not UTF-8".to_string(),
        Error::TooLong(field, _) => format!("{field} too long for platform"),
        Error::Invalid(field, _) => format!("invalid {field}"),
        Error::PlatformFailure(_) => "platform-specific keyring failure".to_string(),
        Error::NoStorageAccess(_) => "keyring service inaccessible".to_string(),
        Error::Ambiguous(_) => "multiple matching entries (ambiguous)".to_string(),
        // Future variants of keyring::Error get a generic label.
        _ => "keyring error".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn describe_returns_keychain() {
        let f = KeychainFetch::new("svc", "acct");
        assert_eq!(f.describe(), "keychain");
    }

    #[test]
    fn construction_holds_service_and_account() {
        let f = KeychainFetch::new("test-service", "test-account");
        assert_eq!(f.service, "test-service");
        assert_eq!(f.account, "test-account");
        assert!(!f.binary);
        assert!(f.binary().binary);
    }

    /// Before 1.1 the `keyring` dependency had no store feature, so every
    /// entry was backed by `keyring`'s in-memory mock and `KeychainFetch`
    /// never reached the OS. Creating an entry reads and writes nothing,
    /// so this is safe to run anywhere.
    #[test]
    fn entries_use_the_native_store_not_the_mock() {
        let entry = keyring::Entry::new("key-vault-test", "store-check").unwrap();
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::mock::MockCredential>()
                .is_none(),
            "keyring is using its mock store"
        );
    }

    // Live integration test against the real OS keychain is gated by an
    // env var so it does not run in default CI (which has no keychain).
    // Set `KEY_VAULT_KEYCHAIN_TEST=1` and seed an entry manually to run it.
    #[test]
    fn live_keychain_test_skipped_when_not_opted_in() {
        if std::env::var("KEY_VAULT_KEYCHAIN_TEST").ok().as_deref() != Some("1") {
            return; // skipped — the common case in CI
        }
        let fetcher = KeychainFetch::new("key-vault-test", "ci-key");
        // The opt-in environment is expected to have seeded this entry;
        // we just verify the fetch contract.
        let raw = fetcher.fetch(&FetchContext::new("k")).unwrap();
        assert!(!raw.is_empty());
    }
}
