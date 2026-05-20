//! [`EnvFetch`] — environment-variable [`KeyFetch`] backend.
//!
//! Reads key bytes from a named process environment variable. The variable
//! **name** is not secret and appears in error messages for diagnostics; the
//! variable **value** is treated as secret and never appears in error output
//! or logging produced by this module.
//!
//! # Threat profile
//!
//! `EnvFetch` is the **lowest-security** built-in fetcher. Anything in the
//! process environment is readable by other processes with appropriate
//! privileges (e.g. `/proc/<pid>/environ` on Linux), by debuggers, and by
//! crash-dump tooling. Use it for development and container deployments where
//! the orchestration layer already controls the environment securely
//! (Kubernetes Secrets mounted as env, AWS Secrets Manager → env via Lambda,
//! systemd `EnvironmentFile=` with restricted permissions, etc.).
//!
//! For higher-security deployments prefer
//! [`KeychainFetch`](super::keychain::KeychainFetch) (when available) or a
//! TEE-backed fetcher.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use std::env;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// `KeyFetch` implementation that reads bytes from a process environment
/// variable.
///
/// The variable name is configured at construction. The variable's bytes
/// are returned verbatim — no decoding, no trimming, no parsing.
///
/// # Examples
///
/// ```no_run
/// use key_vault::{EnvFetch, FetchContext, KeyFetch};
///
/// # fn main() -> Result<(), key_vault::Error> {
/// // SAFETY for the example: setting an env var in a single-threaded
/// // doctest is fine. Real applications should set keys via the
/// // orchestration layer (Kubernetes Secrets, AWS Lambda env, etc.).
/// unsafe { std::env::set_var("MY_APP_KEY", "very-secret-value"); }
///
/// let fetcher = EnvFetch::new("MY_APP_KEY");
/// let ctx = FetchContext::new("my-key");
/// let raw = fetcher.fetch(&ctx)?;
/// assert_eq!(raw.len(), "very-secret-value".len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EnvFetch {
    var_name: String,
}

impl EnvFetch {
    /// Construct a fetcher that reads from the named environment variable.
    ///
    /// The name is stored verbatim. It is logged in failure messages for
    /// diagnosability — keep that in mind if your variable names themselves
    /// encode sensitive deployment metadata.
    #[must_use]
    pub fn new(var_name: impl Into<String>) -> Self {
        Self {
            var_name: var_name.into(),
        }
    }
}

impl KeyFetch for EnvFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        match env::var(&self.var_name) {
            Ok(value) => Ok(RawKey::new(value.into_bytes())),
            Err(env::VarError::NotPresent) => Err(Error::Acquisition {
                source: Cow::Borrowed("env"),
                reason: format!("environment variable {} is not set", self.var_name),
            }),
            Err(env::VarError::NotUnicode(_)) => Err(Error::Acquisition {
                source: Cow::Borrowed("env"),
                // We deliberately do NOT include the OsString in the message —
                // it could expose key bytes that happen to be near-UTF-8.
                reason: format!(
                    "environment variable {} contained non-UTF-8 bytes",
                    self.var_name
                ),
            }),
        }
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("env")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // env::set_var / env::remove_var are `unsafe` on Rust 1.85+ because
    // mutating the process environment races with concurrent readers in
    // other threads. Each test below uses a unique variable name, so the
    // only writer is the test itself; cargo test's default multi-thread
    // mode still concurrently reads `getenv`, but the variables we touch
    // are exclusive to this test invocation. Wrapping every call site in
    // its own `unsafe { ... }` block lets us put one SAFETY note per call
    // satisfying `clippy::undocumented_unsafe_blocks`.

    /// SAFETY: see module-level test comment — the var name is unique to
    /// this test and no other thread reads it.
    fn set_var_for_test(name: &str, value: &str) {
        // SAFETY: see fn doc.
        unsafe {
            env::set_var(name, value);
        }
    }

    /// SAFETY: see module-level test comment.
    fn remove_var_for_test(name: &str) {
        // SAFETY: see fn doc.
        unsafe {
            env::remove_var(name);
        }
    }

    #[test]
    fn fetches_existing_env_var() {
        set_var_for_test("KEY_VAULT_TEST_ENV_FETCH_OK", "hello");
        let f = EnvFetch::new("KEY_VAULT_TEST_ENV_FETCH_OK");
        let raw = f.fetch(&FetchContext::new("k")).unwrap();
        assert_eq!(raw.len(), 5);
        remove_var_for_test("KEY_VAULT_TEST_ENV_FETCH_OK");
    }

    #[test]
    fn missing_env_var_returns_acquisition_error() {
        let f = EnvFetch::new("KEY_VAULT_TEST_ENV_FETCH_MISSING_VAR_42x");
        let err = f.fetch(&FetchContext::new("k")).unwrap_err();
        match err {
            Error::Acquisition { source, reason } => {
                assert_eq!(source, "env");
                assert!(reason.contains("not set"));
                assert!(reason.contains("KEY_VAULT_TEST_ENV_FETCH_MISSING_VAR_42x"));
            }
            other => panic!("expected Acquisition error, got {other:?}"),
        }
    }

    #[test]
    fn error_message_does_not_contain_value() {
        set_var_for_test("KEY_VAULT_TEST_ENV_FETCH_SECRET", "do-not-log-me");
        remove_var_for_test("KEY_VAULT_TEST_ENV_FETCH_SECRET");
        let f = EnvFetch::new("KEY_VAULT_TEST_ENV_FETCH_SECRET");
        let err = f.fetch(&FetchContext::new("k")).unwrap_err();
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("do-not-log-me"),
            "error message must not include env value (got: {rendered})"
        );
    }

    #[test]
    fn describe_returns_env() {
        assert_eq!(EnvFetch::new("VAR").describe(), "env");
    }
}
