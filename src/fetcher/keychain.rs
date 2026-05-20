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
//! application's signing identity. They are the highest-security
//! general-purpose backend short of dedicated hardware. Use this whenever
//! you have the option.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};

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
        }
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
        let value = entry.get_password().map_err(|e| Error::Acquisition {
            source: Cow::Borrowed("keychain"),
            reason: format!(
                "could not read keychain entry {}/{}: {}",
                self.service,
                self.account,
                redact_keyring_error(&e),
            ),
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
