//! [`TpmFetch`] — TPM 2.0 [`KeyFetch`] backend (**detection-only in 1.0**).
//!
//! 1.0 ships TPM **detection** via
//! [`detect_tee_capabilities`](crate::tee::detect_tee_capabilities) — the
//! CPUID-based probe will tell you whether a TPM-equipped TEE is present
//! on the host. Full TPM **acquisition** (talking to the TPM, unsealing
//! keys, attestation) is on the 1.x roadmap and requires deep integration
//! with `tss-esapi` or equivalent.
//!
//! Calling [`TpmFetch::fetch`] in 1.0 always returns
//! [`Error::Acquisition`](crate::Error::Acquisition) with a documented
//! message so consumers can fall through to another fetcher in a
//! composite arrangement without a panic.
//!
//! # When this exists despite returning errors
//!
//! Code that wants to declare its intended fetcher hierarchy at
//! configuration time — e.g. "prefer TPM, then keychain, then file" —
//! can wire `TpmFetch` into its chain and inherit the 1.x upgrade
//! automatically when full integration ships.

use alloc::borrow::Cow;
use alloc::string::ToString;

use super::{FetchContext, KeyFetch, RawKey};
use crate::Result;
use crate::error::Error;

/// Detection-only TPM 2.0 fetcher.
///
/// Always returns
/// [`Error::Acquisition`](crate::Error::Acquisition) in 1.0. Use the TEE
/// detection probe ([`detect_tee_capabilities`](crate::tee::detect_tee_capabilities))
/// to check whether a TPM is present at all.
///
/// # Examples
///
/// ```
/// use key_vault::{FetchContext, KeyFetch, TpmFetch};
///
/// let fetcher = TpmFetch;
/// let err = fetcher.fetch(&FetchContext::new("k")).unwrap_err();
/// // 1.0 ships detection only — full TPM integration is in the 1.x roadmap.
/// assert!(format!("{err}").contains("TPM"));
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct TpmFetch;

impl KeyFetch for TpmFetch {
    fn fetch(&self, _ctx: &FetchContext) -> Result<RawKey> {
        Err(Error::Acquisition {
            source: Cow::Borrowed("tpm"),
            reason:
                "TPM 2.0 acquisition is detection-only in 1.0; full integration arrives in the \
                 1.x release line. Use detect_tee_capabilities() to probe for TPM presence."
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
