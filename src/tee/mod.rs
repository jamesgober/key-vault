//! Trusted Execution Environment detection.
//!
//! [`detect_tee_capabilities`] inspects the host platform and returns a
//! [`TeeCapabilities`] snapshot describing which trusted execution
//! environments are *available* — not whether the current process is *running
//! inside* one. The vault uses this at startup to choose between
//! `KeyFetch` implementations and to surface availability through audit
//! records.
//!
//! # What 1.0 promises
//!
//! Detection only. Integration with the underlying enclave APIs (signing
//! attestation reports, sealing data, running code inside SGX/TDX/SEV/SE/Nitro)
//! is explicitly deferred to the 1.x line — see `.dev/ROADMAP.md`.
//!
//! # Verification semantics
//!
//! Each capability is reported as one of three values:
//!
//! - [`Detection::Detected`] — the capability is present on this host and the
//!   detection path completed successfully.
//! - [`Detection::NotDetected`] — the detection path completed successfully
//!   and found no support.
//! - [`Detection::Unknown`] — the detection path is not implemented on this
//!   platform, or the necessary detection signal is not accessible from
//!   userspace.
//!
//! Treating `Unknown` as "not available" is the safe default for selecting
//! fetchers.

use core::fmt;

#[cfg(target_arch = "x86_64")]
mod x86_64;

/// Result of a single TEE capability probe.
///
/// `Unknown` is distinct from `NotDetected` on purpose. On platforms where we
/// cannot run the probe (for example asking about Intel SGX from an aarch64
/// host) we report `Unknown` rather than claim absence — callers that care
/// about the distinction can degrade gracefully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Detection {
    /// The capability is present and a fetcher backed by it would succeed.
    Detected,
    /// The probe ran and found no support.
    NotDetected,
    /// The probe is not implemented on this platform, or its signal is
    /// inaccessible from userspace.
    Unknown,
}

impl Detection {
    /// `true` only if this probe positively confirmed the capability.
    #[must_use]
    pub fn is_detected(self) -> bool {
        matches!(self, Self::Detected)
    }
}

impl fmt::Display for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Detected => "detected",
            Self::NotDetected => "not detected",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Snapshot of every TEE probe the vault knows how to run on this host.
///
/// Adding a new probe is a minor-version change — the struct is
/// `#[non_exhaustive]`. Existing fields will not change meaning across the 1.x
/// line.
///
/// # Examples
///
/// ```
/// use key_vault::tee::{detect_tee_capabilities, Detection};
///
/// let caps = detect_tee_capabilities();
/// // We cannot assert specific values — the result depends on hardware. But
/// // every field is queryable:
/// let _ = caps.sgx;
/// let _ = caps.tdx;
/// let _ = caps.sev;
/// let _ = caps.sev_snp;
/// let _ = caps.trustzone;
/// let _ = caps.secure_enclave;
/// let _ = caps.nitro;
///
/// // Display is implemented for human-readable summaries:
/// let _ = format!("{caps}");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TeeCapabilities {
    /// Intel Software Guard Extensions (SGX). Detected by CPUID leaf 7,
    /// EBX bit 2 on x86_64. Always `Unknown` on non-x86_64.
    pub sgx: Detection,

    /// Intel Trust Domain Extensions (TDX). Detected by CPUID leaf 0x21
    /// returning the "IntelTDX    " signature in EBX/ECX/EDX on x86_64.
    /// Always `Unknown` on non-x86_64.
    pub tdx: Detection,

    /// AMD Secure Encrypted Virtualization (SEV). Detected by CPUID extended
    /// leaf 0x8000001F EAX bit 1 on x86_64. Always `Unknown` on non-x86_64
    /// or on Intel hosts.
    pub sev: Detection,

    /// AMD Secure Encrypted Virtualization — Secure Nested Paging (SEV-SNP).
    /// Detected by CPUID extended leaf 0x8000001F EAX bit 4 on x86_64.
    /// Always `Unknown` on non-x86_64 or on Intel hosts.
    pub sev_snp: Detection,

    /// ARM TrustZone. Userspace cannot reliably probe TrustZone availability
    /// without privileged registers, so this is always `Unknown` in 1.0.
    /// Operators that know their hardware supports TrustZone should configure
    /// the vault explicitly.
    pub trustzone: Detection,

    /// Apple Secure Enclave. Reported as `Detected` on Apple Silicon
    /// (`aarch64-apple-darwin`), `NotDetected` on Intel macOS, and `Unknown`
    /// on non-Apple platforms.
    pub secure_enclave: Detection,

    /// AWS Nitro Enclaves availability. On Linux this is inferred from the
    /// DMI system vendor (`/sys/devices/virtual/dmi/id/sys_vendor`); other
    /// hosts report `Unknown`.
    pub nitro: Detection,
}

impl TeeCapabilities {
    /// Returns `true` if at least one probe positively confirmed a TEE.
    ///
    /// This is the convenience predicate for "should I prefer a hardware-backed
    /// fetcher?". `Unknown` does not count.
    #[must_use]
    pub fn any_detected(self) -> bool {
        self.sgx.is_detected()
            || self.tdx.is_detected()
            || self.sev.is_detected()
            || self.sev_snp.is_detected()
            || self.trustzone.is_detected()
            || self.secure_enclave.is_detected()
            || self.nitro.is_detected()
    }
}

impl fmt::Display for TeeCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TeeCapabilities {{ sgx: {}, tdx: {}, sev: {}, sev_snp: {}, trustzone: {}, secure_enclave: {}, nitro: {} }}",
            self.sgx,
            self.tdx,
            self.sev,
            self.sev_snp,
            self.trustzone,
            self.secure_enclave,
            self.nitro,
        )
    }
}

/// Run every supported TEE probe on this host and return a snapshot.
///
/// This is a synchronous, side-effect-free function suitable for calling at
/// process startup. It performs a handful of CPUID instructions on x86_64 and,
/// on Linux, reads `/sys/devices/virtual/dmi/id/sys_vendor` to detect AWS
/// Nitro. It does **not** open privileged files, talk to the network, or
/// load any drivers.
///
/// Callers can cache the result; capabilities do not change at runtime.
#[must_use]
pub fn detect_tee_capabilities() -> TeeCapabilities {
    let (sgx, tdx, sev, sev_snp) = detect_x86_64();
    TeeCapabilities {
        sgx,
        tdx,
        sev,
        sev_snp,
        trustzone: detect_trustzone(),
        secure_enclave: detect_secure_enclave(),
        nitro: detect_nitro(),
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_x86_64() -> (Detection, Detection, Detection, Detection) {
    self::x86_64::detect()
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_x86_64() -> (Detection, Detection, Detection, Detection) {
    (
        Detection::Unknown,
        Detection::Unknown,
        Detection::Unknown,
        Detection::Unknown,
    )
}

#[cfg(target_arch = "aarch64")]
fn detect_trustzone() -> Detection {
    // Userspace cannot positively probe TrustZone without reading EL3-protected
    // registers. Returning Unknown lets operators configure the vault
    // explicitly without us silently misreporting.
    Detection::Unknown
}

#[cfg(not(target_arch = "aarch64"))]
fn detect_trustzone() -> Detection {
    Detection::Unknown
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn detect_secure_enclave() -> Detection {
    // Apple Silicon Macs (M1 and later) ship with the Secure Enclave
    // coprocessor. Apple does not document a userspace probe; presence is
    // implied by the CPU family.
    Detection::Detected
}

#[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
fn detect_secure_enclave() -> Detection {
    // Intel Macs with a T2 chip also have a Secure Enclave, but we have no
    // portable userspace probe for the T2. Report NotDetected on Intel macOS
    // — callers that know they are on a T2 host should configure manually.
    Detection::NotDetected
}

#[cfg(not(target_os = "macos"))]
fn detect_secure_enclave() -> Detection {
    Detection::Unknown
}

#[cfg(target_os = "linux")]
fn detect_nitro() -> Detection {
    // AWS sets `sys_vendor` to "Amazon EC2" on Nitro-backed instances. This
    // is a heuristic — it distinguishes Nitro instances from non-Nitro EC2 —
    // and it does not by itself prove that nitro-enclaves is configured.
    // For 1.0 detection-only semantics this is the right granularity.
    match std::fs::read_to_string("/sys/devices/virtual/dmi/id/sys_vendor") {
        Ok(vendor) => {
            if vendor.trim().eq_ignore_ascii_case("Amazon EC2") {
                Detection::Detected
            } else {
                Detection::NotDetected
            }
        }
        Err(_) => Detection::Unknown,
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_nitro() -> Detection {
    Detection::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn detection_renders_human_readable() {
        assert_eq!(format!("{}", Detection::Detected), "detected");
        assert_eq!(format!("{}", Detection::NotDetected), "not detected");
        assert_eq!(format!("{}", Detection::Unknown), "unknown");
    }

    #[test]
    fn detection_is_detected_predicate() {
        assert!(Detection::Detected.is_detected());
        assert!(!Detection::NotDetected.is_detected());
        assert!(!Detection::Unknown.is_detected());
    }

    #[test]
    fn detect_tee_capabilities_does_not_panic() {
        // We can't assert specific values — this runs on heterogeneous CI
        // hosts. But the function must complete cleanly on every supported
        // target.
        let caps = detect_tee_capabilities();
        let _ = format!("{caps}");
        let _ = caps.any_detected();
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn non_x86_64_reports_unknown_for_intel_amd() {
        let caps = detect_tee_capabilities();
        assert_eq!(caps.sgx, Detection::Unknown);
        assert_eq!(caps.tdx, Detection::Unknown);
        assert_eq!(caps.sev, Detection::Unknown);
        assert_eq!(caps.sev_snp, Detection::Unknown);
    }
}
