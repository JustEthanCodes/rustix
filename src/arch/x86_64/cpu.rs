//! CPU feature and gated, read-only MSR reporting for x86_64 boot diagnostics.

use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count};
use rustix_kernel::paging::{capture_mtrr_registers, MtrrState};

const IA32_EFER: u32 = 0xc000_0080;
const IA32_PAT: u32 = 0x0000_0277;
const EFER_NXE: u64 = 1 << 11;
const CR4_PGE: u64 = 1 << 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInfo {
    pub vendor: [u8; 12],
    pub max_basic_leaf: u32,
    pub max_extended_leaf: u32,
    pub has_sse2: bool,
    pub has_nx: bool,
    pub nx_enabled: bool,
    pub normal_caching: bool,
    pub has_pat: bool,
    pub pat_msr_value: Option<u64>,
    pub mtrr: MtrrState,
    pub has_1g_pages: bool,
    pub has_long_mode: bool,
    pub has_la57: bool,
    pub physical_address_bits: Option<u8>,
    pub max_linear_address_bits: Option<u8>,
    pub active_linear_address_bits: u8,
    pub pcid_enabled: bool,
}

/// Read CPUID identity, selected feature bits, and supported read-only MSR state.
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
    let address_widths = if extended.eax >= 0x8000_0008 {
        Some(__cpuid(0x8000_0008).eax)
    } else {
        None
    };
    let cr0 = read_cr0_raw();
    let cr4 = read_cr4_raw();
    let has_nx = extended_features.is_some_and(|features| features.edx & (1 << 20) != 0);
    let nx_enabled = if has_nx {
        // SAFETY: EFER is available in x86_64 long mode; CPUID confirms NX support,
        // and this boot-time code executes at CPL 0. The read does not change state.
        unsafe { read_msr(IA32_EFER) & EFER_NXE != 0 }
    } else {
        false
    };
    let has_pat = basic_features.is_some_and(|features| features.edx & (1 << 16) != 0);
    let pat_msr_value = if has_pat {
        // SAFETY: CPUID reports PAT support and boot-time kernel code runs at CPL 0.
        Some(unsafe { read_msr(IA32_PAT) })
    } else {
        None
    };
    let has_mtrr = basic_features.is_some_and(|features| features.edx & (1 << 12) != 0);
    let mtrr = capture_mtrr_registers(has_mtrr, |index| {
        // SAFETY: CPUID reports MTRR support; the capture helper only requests
        // architectural MTRR MSRs after that feature check.
        unsafe { read_msr(index) }
    });

    CpuInfo {
        vendor,
        max_basic_leaf: basic.eax,
        max_extended_leaf: extended.eax,
        has_sse2: basic_features.is_some_and(|features| features.edx & (1 << 26) != 0),
        has_nx,
        nx_enabled,
        normal_caching: cr0 & ((1 << 30) | (1 << 29)) == 0,
        has_pat,
        pat_msr_value,
        mtrr,
        has_1g_pages: extended_features.is_some_and(|features| features.edx & (1 << 26) != 0),
        has_long_mode: extended_features.is_some_and(|features| features.edx & (1 << 29) != 0),
        has_la57: structured_features.is_some_and(|features| features.ecx & (1 << 16) != 0),
        physical_address_bits: address_widths.map(|eax| (eax & 0xff) as u8),
        max_linear_address_bits: address_widths.map(|eax| ((eax >> 8) & 0xff) as u8),
        active_linear_address_bits: if cr4 & (1 << 12) != 0 { 57 } else { 48 },
        pcid_enabled: cr4 & (1 << 17) != 0,
    }
}

/// Return the bootstrap processor's legacy xAPIC ID from CPUID leaf 1.
///
/// Callers must separately verify that the CPU and platform support xAPIC.
pub fn bootstrap_apic_id() -> u8 {
    (__cpuid(1).ebx >> 24) as u8
}

/// Read the current raw CR3 value without changing page-table state.
pub fn read_cr3_raw() -> u64 {
    let cr3: u64;
    // SAFETY: Rustix runs at CPL 0; reading CR3 is privileged but non-mutating.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
    cr3
}

/// Install a pre-validated CR3 value.
///
/// # Safety
/// The root must name a complete, valid page-table hierarchy that preserves the
/// current instruction, stack, data, exception, and HHDM mappings. Paging mode
/// and address-width controls must already match the hierarchy, and interrupts
/// must remain disabled during the transition.
pub unsafe fn write_cr3_raw(value: u64) {
    // SAFETY: The caller establishes the page-table and transition invariants.
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags)) };
}

/// Replace CR3 while invalidating global translations when CR4.PGE is enabled.
///
/// Returns whether PGE was toggled. With PGE clear, the CR3 write still
/// invalidates the active PCID (or all non-global translations when PCID is
/// disabled); global translations cannot be retained while PGE is clear.
///
/// # Safety
/// `value` must satisfy [`write_cr3_raw`]'s safety requirements, and interrupts
/// must remain disabled until the target root and translations are verified.
pub unsafe fn write_cr3_with_global_flush(value: u64) -> bool {
    let cr4 = read_cr4_raw();
    if cr4 & CR4_PGE == 0 {
        // SAFETY: The caller supplies the same validated root required by
        // `write_cr3_raw`; with PGE already clear there are no global entries.
        unsafe { write_cr3_raw(value) };
        return false;
    }

    // A 1-to-0 PGE transition invalidates cached global translations. Keep PGE
    // clear across the CR3 write so the target context starts without stale
    // global translations, then restore the original control-register state.
    // SAFETY: Only CR4.PGE is modified, and the original value is restored.
    unsafe { write_cr4_raw(cr4 & !CR4_PGE) };
    // SAFETY: The caller supplies a validated root and keeps interrupts disabled.
    unsafe { write_cr3_raw(value) };
    // SAFETY: Restore the previously observed CR4 value without changing mode.
    unsafe { write_cr4_raw(cr4) };
    true
}

/// Read a model-specific register at CPL 0.
///
/// # Safety
/// The caller must ensure the MSR exists on this CPU and that the current
/// privilege level permits the read.
unsafe fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: The caller guarantees that this MSR is supported and accessible.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") index,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Read CR0 without changing processor state.
fn read_cr0_raw() -> u64 {
    let cr0: u64;
    // SAFETY: Rustix runs at CPL 0; reading CR0 is privileged but non-mutating.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    cr0
}

/// Read CR4 without changing paging state.
fn read_cr4_raw() -> u64 {
    let cr4: u64;
    // SAFETY: Rustix runs at CPL 0; reading CR4 is privileged but non-mutating.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4
}

/// Write CR4 while preserving the caller's complete control-register value.
///
/// # Safety
/// `value` must be a valid CR4 value for the current CPU and execution mode.
unsafe fn write_cr4_raw(value: u64) {
    // SAFETY: The caller validates the value by preserving the current CR4
    // state and changing only the architectural PGE bit.
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags)) };
}
