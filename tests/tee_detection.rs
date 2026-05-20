//! Integration tests for the TEE detection probe.
//!
//! These exercise the public surface of `key_vault::tee` from outside the
//! crate, which is the perspective downstream consumers (e.g. `crypt-io`)
//! will see.

use key_vault::tee::{Detection, detect_tee_capabilities};

#[test]
fn detect_completes_and_returns_consistent_snapshot() {
    // Calling the probe must not panic, must not block, and must return the
    // same snapshot across consecutive calls (capabilities don't change at
    // runtime).
    let first = detect_tee_capabilities();
    let second = detect_tee_capabilities();
    assert_eq!(first, second);
}

#[test]
fn detection_variants_are_self_consistent() {
    let caps = detect_tee_capabilities();
    for d in [
        caps.sgx,
        caps.tdx,
        caps.sev,
        caps.sev_snp,
        caps.trustzone,
        caps.secure_enclave,
        caps.nitro,
    ] {
        if d.is_detected() {
            assert!(matches!(d, Detection::Detected));
        } else {
            assert!(matches!(d, Detection::NotDetected | Detection::Unknown));
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_returns_known_detection_for_intel_amd_probes() {
    let caps = detect_tee_capabilities();
    // On x86_64, SGX/TDX/SEV/SEV-SNP probes must complete — they should never
    // be Unknown on a supported architecture.
    for d in [caps.sgx, caps.tdx, caps.sev, caps.sev_snp] {
        assert_ne!(d, Detection::Unknown);
    }
}
