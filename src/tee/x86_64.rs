//! x86_64-specific TEE probes via CPUID.
//!
//! This file is compiled only when `target_arch = "x86_64"`. All inline-asm
//! uses go through [`safe_cpuid_count`], which locally discharges the `unsafe`
//! obligation for `__cpuid_count`.

use core::arch::x86_64::{__cpuid_count, CpuidResult};

use super::Detection;

/// Run all x86_64 TEE probes.
///
/// Returns `(sgx, tdx, sev, sev_snp)`.
pub(super) fn detect() -> (Detection, Detection, Detection, Detection) {
    let vendor = vendor_string();
    let standard_max = safe_cpuid_count(0, 0).eax;

    let sgx = detect_sgx(standard_max);
    let tdx = detect_tdx(vendor, standard_max);
    let (sev, sev_snp) = detect_sev(vendor);
    (sgx, tdx, sev, sev_snp)
}

fn detect_sgx(standard_max: u32) -> Detection {
    if standard_max < 7 {
        return Detection::NotDetected;
    }
    // CPUID.07H.0: EBX bit 2 = SGX support.
    let leaf7 = safe_cpuid_count(7, 0);
    if (leaf7.ebx & (1 << 2)) != 0 {
        Detection::Detected
    } else {
        Detection::NotDetected
    }
}

fn detect_tdx(vendor: [u8; 12], standard_max: u32) -> Detection {
    // TDX-host detection: CPUID.21H.0 returns the signature "IntelTDX    "
    // packed into EBX, EDX, ECX in that order. Only meaningful on Intel CPUs.
    if !is_intel(vendor) {
        return Detection::NotDetected;
    }
    if standard_max < 0x21 {
        return Detection::NotDetected;
    }
    let leaf = safe_cpuid_count(0x21, 0);
    let ebx = leaf.ebx.to_le_bytes();
    let edx = leaf.edx.to_le_bytes();
    let ecx = leaf.ecx.to_le_bytes();
    let signature = [
        ebx[0], ebx[1], ebx[2], ebx[3], edx[0], edx[1], edx[2], edx[3], ecx[0], ecx[1], ecx[2],
        ecx[3],
    ];
    if &signature == b"IntelTDX    " {
        Detection::Detected
    } else {
        Detection::NotDetected
    }
}

fn detect_sev(vendor: [u8; 12]) -> (Detection, Detection) {
    if !is_amd(vendor) {
        return (Detection::NotDetected, Detection::NotDetected);
    }
    // CPUID.80000000H returns the max extended leaf in EAX.
    let extended_max = safe_cpuid_count(0x8000_0000, 0).eax;
    if extended_max < 0x8000_001F {
        return (Detection::NotDetected, Detection::NotDetected);
    }
    let leaf = safe_cpuid_count(0x8000_001F, 0);
    let sev = if (leaf.eax & (1 << 1)) != 0 {
        Detection::Detected
    } else {
        Detection::NotDetected
    };
    let snp = if (leaf.eax & (1 << 4)) != 0 {
        Detection::Detected
    } else {
        Detection::NotDetected
    };
    (sev, snp)
}

fn vendor_string() -> [u8; 12] {
    let leaf0 = safe_cpuid_count(0, 0);
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    out[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    out[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());
    out
}

fn is_intel(vendor: [u8; 12]) -> bool {
    &vendor == b"GenuineIntel"
}

fn is_amd(vendor: [u8; 12]) -> bool {
    &vendor == b"AuthenticAMD"
}

/// Thin wrapper around [`__cpuid_count`].
///
/// In modern Rust the intrinsic is a safe function (CPUID is part of the
/// baseline x86_64 ISA, has no preconditions on its operands, and invalid
/// leaves return zeros in unused registers). The whole module is gated on
/// `target_arch = "x86_64"` so this never compiles on a target that lacks the
/// instruction.
fn safe_cpuid_count(leaf: u32, sub_leaf: u32) -> CpuidResult {
    __cpuid_count(leaf, sub_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_string_is_twelve_bytes() {
        let v = vendor_string();
        assert_eq!(v.len(), 12);
    }

    #[test]
    fn detect_runs_without_panicking() {
        let _ = detect();
    }
}
