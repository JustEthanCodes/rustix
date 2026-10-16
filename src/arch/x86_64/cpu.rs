//! Minimal CPUID identification for boot diagnostics on x86_64.

use core::arch::x86_64::{__cpuid, __cpuid_count};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInfo {
    pub vendor: [u8; 12],
    pub max_basic_leaf: u32,
    pub max_extended_leaf: u32,
    pub has_sse2: bool,
    pub has_nx: bool,
    pub has_1g_pages: bool,
    pub has_long_mode: bool,
    pub has_la57: bool,
}

/// Read CPUID identity and a small set of baseline kernel-relevant features.
pub fn identify() -> CpuInfo {
    // CPUID is part of the x86_64 architectural baseline.
    let basic = __cpuid(0);
    let mut vendor = [0; 12];
    vendor[0..4].copy_from_slice(&basic.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&basic.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&basic.ecx.to_le_bytes());

    let basic_features = if basic.eax >= 1 {
        Some(__cpuid(1))
    } else {
        None
    };
    let extended = __cpuid(0x8000_0000);
    let extended_features = if extended.eax >= 0x8000_0001 {
        Some(__cpuid(0x8000_0001))
    } else {
        None
    };
    let structured_features = if basic.eax >= 7 {
        Some(__cpuid_count(7, 0))
    } else {
        None
    };

    CpuInfo {
        vendor,
        max_basic_leaf: basic.eax,
        max_extended_leaf: extended.eax,
        has_sse2: basic_features.is_some_and(|features| features.edx & (1 << 26) != 0),
        has_nx: extended_features.is_some_and(|features| features.edx & (1 << 20) != 0),
        has_1g_pages: extended_features.is_some_and(|features| features.edx & (1 << 26) != 0),
        has_long_mode: extended_features.is_some_and(|features| features.edx & (1 << 29) != 0),
        has_la57: structured_features.is_some_and(|features| features.ecx & (1 << 16) != 0),
    }
}
