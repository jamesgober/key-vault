//! [`TpmFetch`]: TPM 2.0 [`KeyFetch`] placeholder (**not implemented**).
//!
//! **`TpmFetch` does not talk to a TPM.** It provides no hardware-backed
//! protection of any kind. TPM acquisition (talking to the TPM, unsealing
//! keys, attestation) is not implemented in 1.0.x; it would need
//! integration with `tss-esapi` or an equivalent.
//!
//! [`detect_tee_capabilities`](crate::tee::detect_tee_capabilities) does
//! not detect TPMs either: it reports CPU/platform TEE features (SGX,
//! TDX, SEV, TrustZone, Secure Enclave, Nitro).
//!
//! Calling [`TpmFetch::fetch`] in 1.0.x always returns
//! [`Error::Acquisition`](crate::Error::Acquisition) with a documented
//! message so consumers can fall through to another fetcher in a
//! composite arrangement without a panic.
//!
//! # When this exists despite returning errors
//!
//! Code that wants to declare its intended fetcher hierarchy at
//! configuration time (for example "prefer TPM, then keychain, then
//! file") can put `TpmFetch` first in its chain; today that entry always
//! fails and the chain falls through to the next fetcher.

use alloc::borrow::Cow;
use alloc::string::ToString;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// TPM 2.0 fetcher placeholder. **Not implemented.**
///
/// Always returns [`Error::Acquisition`](crate::Error::Acquisition) in
/// 1.0.x. It never reads a key and offers no hardware protection.
///
/// # Examples
///
/// ```
/// use key_vault::{FetchContext, KeyFetch, TpmFetch};
///
/// let fetcher = TpmFetch;
/// let err = fetcher.fetch(&FetchContext::new("k")).unwrap_err();
/// // Not implemented in 1.0.x: fetch always fails.
/// assert!(format!("{err}").contains("TPM"));
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct TpmFetch;

impl KeyFetch for TpmFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        Err(Error::Acquisition {
            source: Cow::Borrowed("tpm"),
            reason: "TPM 2.0 acquisition is not implemented in key-vault 1.0.x (detection-only \
                 placeholder); use another fetcher."
                .to_string(),
        })
    }

    fn describe(&self) -> Cow<'_, str> {
        Cow::Borrowed("tpm")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fetch_returns_detection_only_error() {
        let err = TpmFetch.fetch(&FetchContext::new("k")).unwrap_err();
        match err {
            Error::Acquisition { source, reason } => {
                assert_eq!(source, "tpm");
                assert!(reason.contains("detection-only"));
            }
            other => panic!("expected Acquisition, got {other:?}"),
        }
    }

    #[test]
    fn describe_returns_tpm() {
        assert_eq!(TpmFetch.describe(), "tpm");
    }
}
