//! [`TpmFetch`]: TPM 2.0 [`KeyFetch`] placeholder (**not implemented**).
//!
//! **`TpmFetch` does not talk to a TPM.** It provides no hardware-backed
//! protection of any kind. TPM acquisition (talking to the TPM, unsealing
//! keys, attestation) is not implemented; it would need
//! integration with `tss-esapi` or an equivalent.
//!
//! [`detect_tee_capabilities`](crate::tee::detect_tee_capabilities) does
//! not detect TPMs either: it reports CPU/platform TEE features (SGX,
//! TDX, SEV, TrustZone, Secure Enclave, Nitro).
//!
//! Calling [`TpmFetch::fetch`] always returns
//! [`Error::Acquisition`](crate::Error::Acquisition) with a documented
//! message so consumers can fall through to another fetcher in a
//! composite arrangement without a panic.
//!
//! # Deprecated
//!
//! `TpmFetch` is deprecated since 1.1.1 so that a build which names it
//! gets a warning instead of a key source that can never produce a key.
//! It stays in 1.x because the 1.x API is frozen; it will be removed in
//! 2.0 unless TPM support lands first. Code that wants a "prefer TPM,
//! then keychain, then file" chain can still compile with
//! `#[allow(deprecated)]`; the TPM entry always fails and the chain falls
//! through to the next fetcher.
//!
//! Naming `TpmFetch` with the `deprecated` lint denied does not compile:
//!
//! ```compile_fail
//! #![deny(deprecated)]
//! use key_vault::TpmFetch;
//!
//! let _fetcher = TpmFetch;
//! ```

use alloc::borrow::Cow;
use alloc::string::ToString;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// TPM 2.0 fetcher placeholder. **Not implemented**, and deprecated since
/// 1.1.1.
///
/// Always returns [`Error::Acquisition`](crate::Error::Acquisition). It
/// never reads a key and offers no hardware protection. Use
/// `KeychainFetch`, `FileFetch`, `EnvFetch`, or your own [`KeyFetch`]
/// implementation instead.
///
/// # Examples
///
/// ```
/// # #![allow(deprecated)]
/// use key_vault::{FetchContext, KeyFetch, TpmFetch};
///
/// let fetcher = TpmFetch;
/// let err = fetcher.fetch(&FetchContext::new("k")).unwrap_err();
/// // Not implemented: fetch always fails.
/// assert!(format!("{err}").contains("TPM"));
/// ```
#[deprecated(
    since = "1.1.1",
    note = "TpmFetch is not implemented: fetch() always returns an error. Use another KeyFetch; TpmFetch is removed in 2.0 unless TPM support lands first."
)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TpmFetch;

#[allow(deprecated)]
impl KeyFetch for TpmFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        Err(Error::Acquisition {
            source: Cow::Borrowed("tpm"),
            reason: "TPM 2.0 acquisition is not implemented in key-vault (TpmFetch is a \
                 placeholder); use another fetcher."
                .to_string(),
        })
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("tpm")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, deprecated)]
mod tests {
    use super::*;

    #[test]
    fn fetch_returns_not_implemented_error() {
        let err = TpmFetch.fetch(&FetchContext::new("k")).unwrap_err();
        match err {
            Error::Acquisition { source, reason } => {
                assert_eq!(source, "tpm");
                assert!(reason.contains("not implemented"));
            }
            other => panic!("expected Acquisition, got {other:?}"),
        }
    }

    #[test]
    fn describe_returns_tpm() {
        assert_eq!(TpmFetch.describe(), "tpm");
    }
}
