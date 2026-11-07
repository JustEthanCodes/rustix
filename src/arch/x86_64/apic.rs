//! Single-vCPU xAPIC, I/O APIC, and PIT setup for early boot.
//!
//! The caller must keep the supplied supervisor RW/NX/UC MMIO pages mapped.
//! Initialization, PIT configuration, and PIT unmasking require IF=0 and must
//! run on the bootstrap processor. This module does not install handlers or
//! enable maskable interrupts.

use core::arch::x86_64::__cpuid;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use rustix_kernel::acpi::{InterruptPolarity, InterruptTrigger, Madt};

use super::io;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_ADDRESS_MASK: u64 = 0x0000_000f_ffff_f000;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;
const CPUID_APIC_FEATURE: u32 = 1 << 9;

const APIC_ID: u64 = 0x020;
const APIC_TPR: u64 = 0x080;
const APIC_EOI: u64 = 0x0b0;
const APIC_SVR: u64 = 0x0f0;
const APIC_LVT_TIMER: u64 = 0x320;
const APIC_LVT_THERMAL: u64 = 0x330;
const APIC_LVT_PERFORMANCE: u64 = 0x340;
const APIC_LVT_LINT0: u64 = 0x350;
const APIC_LVT_LINT1: u64 = 0x360;
const APIC_LVT_ERROR: u64 = 0x370;
const APIC_LVT_MASKED: u32 = 1 << 16;
const APIC_SVR_SOFTWARE_ENABLE: u32 = 1 << 8;
const APIC_SPURIOUS_VECTOR: u8 = 0xff;

const IO_APIC_ID: u8 = 0x00;
const IO_APIC_VERSION: u8 = 0x01;
const IO_APIC_REDIR_BASE: u8 = 0x10;
const IO_APIC_REDIR_MAX: u8 = 0xfe;
const IO_APIC_REDIR_MASKED: u32 = 1 << 16;
const IO_APIC_MAX_REDIRECTIONS: u8 = 120;

const PIC1_DATA: u16 = 0x21;
const PIC2_DATA: u16 = 0xa1;
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_RATE_GENERATOR_LOHI: u8 = 0x34;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static TIMER_CONFIGURED: AtomicBool = AtomicBool::new(false);
static LOCAL_APIC_VIRTUAL: AtomicU64 = AtomicU64::new(0);
static IO_APIC_VIRTUAL: AtomicU64 = AtomicU64::new(0);
static TIMER_LOW_REGISTER: AtomicU8 = AtomicU8::new(0);
static TIMER_ROUTE_ATTRIBUTES: AtomicU8 = AtomicU8::new(0);
static BOOTSTRAP_APIC_ID: AtomicU8 = AtomicU8::new(0);
static IO_APIC_GSI_BASE: AtomicU32 = AtomicU32::new(0);
static IO_APIC_MAX_REDIRECTION: AtomicU8 = AtomicU8::new(0);
static ISA_ROUTE_LOW_REGISTERS: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];

/// Errors reported while validating or configuring the bootstrap APIC route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicError {
    InterruptsEnabled,
    AlreadyInitialized,
    ApicFeatureUnavailable,
    X2ApicMode,
    LocalApicAddressMismatch,
    InvalidMappedAddress,
    MissingBootstrapApic,
    BootstrapApicIdMismatch,
    MissingOrMultipleIoApics,
    IoApicAddressMismatch,
    IoApicIdMismatch,
    InvalidIoApicVersion,
    GsiRangeOverflow,
    TimerGsiOutOfRange,
    InvalidVector,
    NotInitialized,
    TimerNotConfigured,
    InvalidIsaIrq,
    IsaRouteOutOfRange,
    IsaRouteNotConfigured,
}

/// Initialize the local xAPIC and the single MADT-described I/O APIC.
///
/// This masks both legacy PICs and all I/O APIC redirection entries, masks the
/// local APIC LVT entries, then enables the local APIC's software interface.
/// The ISA IRQ0 route is resolved and range-checked here, but remains masked.
///
/// # Safety
/// Must execute at CPL 0 on the bootstrap processor with maskable interrupts
/// disabled. `local_apic_virtual` and `io_apic_virtual` must be page-aligned
/// virtual addresses of valid, writable, supervisor, NX, UC mappings of the
/// complete physical pages identified by `madt`. Those mappings must remain
/// valid for all subsequent calls. No other CPU or code may access or reprogram
/// these controllers concurrently. `madt` must be a validated ACPI MADT.
pub unsafe fn initialize(
    madt: &Madt,
    local_apic_virtual: u64,
    io_apic_virtual: u64,
    bootstrap_apic_id: u8,
) -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::AlreadyInitialized);
    }

    TIMER_CONFIGURED.store(false, Ordering::Relaxed);
    IO_APIC_GSI_BASE.store(0, Ordering::Relaxed);
    IO_APIC_MAX_REDIRECTION.store(0, Ordering::Relaxed);
    for route in &ISA_ROUTE_LOW_REGISTERS {
        route.store(0, Ordering::Relaxed);
    }
    LOCAL_APIC_VIRTUAL.store(0, Ordering::Relaxed);
    IO_APIC_VIRTUAL.store(0, Ordering::Relaxed);
    TIMER_LOW_REGISTER.store(0, Ordering::Relaxed);

    // Fail closed for legacy interrupt delivery before inspecting the APICs.
    // SAFETY: The caller executes at CPL 0 and the standard PIC data ports are
    // valid; writing 0xff masks every 8259 input.
    unsafe {
        io::write_u8(PIC1_DATA, 0xff);
        io::write_u8(PIC2_DATA, 0xff);
    }

    if __cpuid(1).edx & CPUID_APIC_FEATURE == 0 {
        return Err(ApicError::ApicFeatureUnavailable);
    }
    validate_mapped_page(local_apic_virtual)?;
    validate_mapped_page(io_apic_virtual)?;

    let mut io_apics = madt.io_apics();
    let io_apic = io_apics.next().ok_or(ApicError::MissingOrMultipleIoApics)?;
    if io_apics.next().is_some() {
        return Err(ApicError::MissingOrMultipleIoApics);
    }
    if io_apic.physical_address == 0 || io_apic.physical_address & 0xfff != 0 {
        return Err(ApicError::IoApicAddressMismatch);
    }
    if madt.local_apic_address & 0xfff != 0
        || madt.local_apic_address & !APIC_BASE_ADDRESS_MASK != 0
    {
        return Err(ApicError::LocalApicAddressMismatch);
    }
    if !madt
        .local_apics()
        .any(|cpu| cpu.apic_id == bootstrap_apic_id && cpu.flags & 1 != 0)
    {
        return Err(ApicError::MissingBootstrapApic);
    }

    // SAFETY: IA32_APIC_BASE is an architectural x86_64 MSR, and the CPUID APIC
    // feature check above confirms the APIC facility. CPL 0 is required.
    let apic_base = unsafe { read_msr(IA32_APIC_BASE) };
    if apic_base & APIC_BASE_X2APIC != 0 {
        return Err(ApicError::X2ApicMode);
    }
    if apic_base & APIC_BASE_ADDRESS_MASK != madt.local_apic_address {
        return Err(ApicError::LocalApicAddressMismatch);
    }

    // Enable the xAPIC global interface without changing its physical base.
    // SAFETY: Same architectural MSR/CPL invariants as the preceding read.
    unsafe { write_msr(IA32_APIC_BASE, apic_base | APIC_BASE_GLOBAL_ENABLE) };

    // SAFETY: The caller guarantees a live mapped APIC page, and the selected
    // offsets are aligned registers within the 4 KiB mapping.
    unsafe {
        write_local(local_apic_virtual, APIC_SVR, 0);
        mask_local_apic_lvt_entries(local_apic_virtual);
        write_local(local_apic_virtual, APIC_TPR, 0);
    }

    let io_version = unsafe { io_apic_read(io_apic_virtual, IO_APIC_VERSION) };
    let max_redirection_index = ((io_version >> 16) & 0xff) as u8;
    if max_redirection_index >= IO_APIC_MAX_REDIRECTIONS
        || redirection_registers(max_redirection_index, max_redirection_index).is_none()
    {
        return Err(ApicError::InvalidIoApicVersion);
    }
    unsafe { mask_all_io_apic_entries(io_apic_virtual, max_redirection_index)? };

    let io_id = unsafe { io_apic_read(io_apic_virtual, IO_APIC_ID) };
    if ((io_id >> 24) & 0x0f) as u8 != io_apic.apic_id {
        return Err(ApicError::IoApicIdMismatch);
    }

    // Check the hardware-reported bootstrap identity before enabling the APIC.
    let local_id = unsafe { read_local(local_apic_virtual, APIC_ID) };
    if (local_id >> 24) as u8 != bootstrap_apic_id {
        return Err(ApicError::BootstrapApicIdMismatch);
    }

    let last_gsi = io_apic
        .global_system_interrupt_base
        .checked_add(u32::from(max_redirection_index))
        .ok_or(ApicError::GsiRangeOverflow)?;
    let timer_route = madt.resolve_isa_interrupt(0);
    if timer_route.global_system_interrupt < io_apic.global_system_interrupt_base
        || timer_route.global_system_interrupt > last_gsi
    {
        return Err(ApicError::TimerGsiOutOfRange);
    }
    let timer_pin =
        (timer_route.global_system_interrupt - io_apic.global_system_interrupt_base) as u8;
    let (timer_low_register, _) = redirection_registers(timer_pin, max_redirection_index)
        .ok_or(ApicError::TimerGsiOutOfRange)?;

    // SAFETY: The caller guarantees the APIC mapping and disabled-interrupt
    // single-CPU setup context. Vector 0xff is reserved for the spurious vector.
    unsafe {
        write_local(
            local_apic_virtual,
            APIC_SVR,
            APIC_SVR_SOFTWARE_ENABLE as u64 | u64::from(APIC_SPURIOUS_VECTOR),
        );
    }

    LOCAL_APIC_VIRTUAL.store(local_apic_virtual, Ordering::Relaxed);
    IO_APIC_VIRTUAL.store(io_apic_virtual, Ordering::Relaxed);
    TIMER_LOW_REGISTER.store(timer_low_register, Ordering::Relaxed);
    TIMER_ROUTE_ATTRIBUTES.store(
        u8::from(timer_route.polarity == InterruptPolarity::ActiveLow)
            | (u8::from(timer_route.trigger == InterruptTrigger::Level) << 1),
        Ordering::Relaxed,
    );
    IO_APIC_GSI_BASE.store(io_apic.global_system_interrupt_base, Ordering::Relaxed);
    IO_APIC_MAX_REDIRECTION.store(max_redirection_index, Ordering::Relaxed);
    BOOTSTRAP_APIC_ID.store(bootstrap_apic_id, Ordering::Relaxed);
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

/// Configure one MADT-resolved ISA route, keeping it masked until explicitly enabled.
///
/// # Safety
/// Must run on the bootstrap CPU with IF=0 after APIC initialization. The MADT
/// must be the validated table used by `initialize`, the source must remain
/// disabled until its handler is ready, and no other code may reprogram the APIC.
pub unsafe fn configure_isa_irq(madt: &Madt, isa_irq: u8, vector: u8) -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::NotInitialized);
    }
    if isa_irq >= 16 {
        return Err(ApicError::InvalidIsaIrq);
    }
    if vector < 32 || vector == APIC_SPURIOUS_VECTOR {
        return Err(ApicError::InvalidVector);
    }

    let route = madt.resolve_isa_interrupt(isa_irq);
    let gsi_base = IO_APIC_GSI_BASE.load(Ordering::Relaxed);
    let max_index = IO_APIC_MAX_REDIRECTION.load(Ordering::Relaxed);
    let last_gsi = gsi_base
        .checked_add(u32::from(max_index))
        .ok_or(ApicError::GsiRangeOverflow)?;
    if route.global_system_interrupt < gsi_base || route.global_system_interrupt > last_gsi {
        return Err(ApicError::IsaRouteOutOfRange);
    }
    let pin = (route.global_system_interrupt - gsi_base) as u8;
    let (low_register, high_register) =
        redirection_registers(pin, max_index).ok_or(ApicError::IsaRouteOutOfRange)?;
    let polarity = route.polarity;
    let trigger = route.trigger;
    let low = encode_redirection(vector, polarity, trigger, true);
    let destination = BOOTSTRAP_APIC_ID.load(Ordering::Relaxed);
    let io_apic_virtual = IO_APIC_VIRTUAL.load(Ordering::Relaxed);
    // SAFETY: Initialization validated the single I/O APIC mapping and masked
    // every entry. The caller keeps this source disabled until its handler is ready.
    unsafe {
        io_apic_write(io_apic_virtual, high_register, u32::from(destination) << 24);
        io_apic_write(io_apic_virtual, low_register, low);
    }
    ISA_ROUTE_LOW_REGISTERS[usize::from(isa_irq)].store(low_register, Ordering::Release);
    Ok(())
}

/// Unmask a previously configured MADT-resolved ISA IRQ route.
///
/// # Safety
/// Must run on the bootstrap CPU with IF=0 after the matching handler and device
/// state are ready. The APIC mapping and route must remain exclusively owned.
pub unsafe fn unmask_isa_irq(isa_irq: u8, vector: u8) -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::NotInitialized);
    }
    if isa_irq >= 16 {
        return Err(ApicError::InvalidIsaIrq);
    }
    if vector < 32 || vector == APIC_SPURIOUS_VECTOR {
        return Err(ApicError::InvalidVector);
    }
    let low_register = ISA_ROUTE_LOW_REGISTERS[usize::from(isa_irq)].load(Ordering::Acquire);
    if low_register == 0 {
        return Err(ApicError::IsaRouteNotConfigured);
    }
    let io_apic_virtual = IO_APIC_VIRTUAL.load(Ordering::Relaxed);
    let entry = unsafe { io_apic_read(io_apic_virtual, low_register) };
    if entry as u8 != vector || entry & IO_APIC_REDIR_MASKED == 0 {
        return Err(ApicError::IsaRouteNotConfigured);
    }
    unsafe { io_apic_write(io_apic_virtual, low_register, entry & !IO_APIC_REDIR_MASKED) };
    Ok(())
}

/// Program PIT channel 0 and configure the resolved ISA IRQ0 I/O APIC entry.
///
/// The route is installed masked. A divisor of zero uses the 8254's encoding
/// for 65,536 input clocks; values 1 through 65,535 are used literally.
///
/// # Safety
/// Must execute at CPL 0 on the bootstrap processor with maskable interrupts
/// disabled, after successful [`initialize`]. No other code may concurrently
/// access the PIT or I/O APIC. The mappings supplied to `initialize` must remain
/// valid and retain their documented permissions and cache type.
pub unsafe fn configure_pit_timer(vector: u8, divisor: u16) -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::NotInitialized);
    }
    if vector < 32 || vector == APIC_SPURIOUS_VECTOR {
        return Err(ApicError::InvalidVector);
    }

    let io_apic_virtual = IO_APIC_VIRTUAL.load(Ordering::Relaxed);
    let low_register = TIMER_LOW_REGISTER.load(Ordering::Relaxed);
    let high_register = low_register
        .checked_add(1)
        .ok_or(ApicError::TimerGsiOutOfRange)?;
    let destination = BOOTSTRAP_APIC_ID.load(Ordering::Relaxed);
    let attributes = TIMER_ROUTE_ATTRIBUTES.load(Ordering::Relaxed);
    let polarity = if attributes & 1 != 0 {
        InterruptPolarity::ActiveLow
    } else {
        InterruptPolarity::ActiveHigh
    };
    let trigger = if attributes & 2 != 0 {
        InterruptTrigger::Level
    } else {
        InterruptTrigger::Edge
    };
    let route_low = encode_redirection(vector, polarity, trigger, true);

    // Install the destination first, then the masked low dword so no transient
    // unmasked route can be observed.
    unsafe {
        io_apic_write(io_apic_virtual, high_register, u32::from(destination) << 24);
        io_apic_write(io_apic_virtual, low_register, route_low);
        io::write_u8(PIT_COMMAND, PIT_RATE_GENERATOR_LOHI);
        io::write_u8(PIT_CHANNEL_0, divisor as u8);
        io::write_u8(PIT_CHANNEL_0, (divisor >> 8) as u8);
    }

    TIMER_CONFIGURED.store(true, Ordering::Release);
    Ok(())
}

/// Unmask only the IRQ0 redirection entry validated by [`initialize`].
///
/// # Safety
/// Must execute at CPL 0 on the bootstrap processor with maskable interrupts
/// disabled, after successful [`configure_pit_timer`]. The I/O APIC mapping
/// must remain valid and no other code may modify its redirection table.
pub unsafe fn unmask_pit_timer() -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::NotInitialized);
    }
    if !TIMER_CONFIGURED.load(Ordering::Acquire) {
        return Err(ApicError::TimerNotConfigured);
    }

    let io_apic_virtual = IO_APIC_VIRTUAL.load(Ordering::Relaxed);
    let low_register = TIMER_LOW_REGISTER.load(Ordering::Relaxed);
    let entry = unsafe { io_apic_read(io_apic_virtual, low_register) };
    unsafe { io_apic_write(io_apic_virtual, low_register, entry & !IO_APIC_REDIR_MASKED) };
    Ok(())
}

/// Mask the configured ISA IRQ0 route after a timer startup failure.
///
/// # Safety
/// Must execute at CPL 0 on the bootstrap processor with maskable interrupts
/// disabled after successful [`initialize`]. The I/O APIC mapping must remain
/// valid and no other code may modify its redirection table.
pub unsafe fn mask_pit_timer() -> Result<(), ApicError> {
    if !interrupts_are_disabled() {
        return Err(ApicError::InterruptsEnabled);
    }
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(ApicError::NotInitialized);
    }

    let io_apic_virtual = IO_APIC_VIRTUAL.load(Ordering::Relaxed);
    let low_register = TIMER_LOW_REGISTER.load(Ordering::Relaxed);
    let entry = unsafe { io_apic_read(io_apic_virtual, low_register) };
    unsafe { io_apic_write(io_apic_virtual, low_register, entry | IO_APIC_REDIR_MASKED) };
    TIMER_CONFIGURED.store(false, Ordering::Release);
    Ok(())
}

/// Send a local-APIC end-of-interrupt notification when initialized.
///
/// This is safe to call from the bootstrap CPU's eventual interrupt handler.
/// It is a no-op before successful initialization; it does not acknowledge any
/// legacy PIC or I/O APIC directly.
pub fn end_of_interrupt() {
    if INITIALIZED.load(Ordering::Acquire) {
        let local_apic_virtual = LOCAL_APIC_VIRTUAL.load(Ordering::Relaxed);
        // SAFETY: Initialization publishes this still-mapped page address, and
        // the EOI register is a valid aligned register in the local APIC page.
        unsafe { write_local(local_apic_virtual, APIC_EOI, 0) };
    }
}

fn interrupts_are_disabled() -> bool {
    let flags: u64;
    // SAFETY: Reading RFLAGS is non-mutating and supported in x86_64 mode.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) flags) };
    flags & (1 << 9) == 0
}

fn validate_mapped_page(address: u64) -> Result<(), ApicError> {
    if address == 0 || address & 0xfff != 0 || address.checked_add(0xfff).is_none() {
        return Err(ApicError::InvalidMappedAddress);
    }
    Ok(())
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: The caller validates the MSR, CPU feature, and CPL requirements.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: The caller validates the MSR, CPU feature, and CPL requirements.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

unsafe fn read_local(base: u64, offset: u64) -> u32 {
    let address = base + offset;
    // SAFETY: The caller supplies the mapped APIC page and a checked in-page
    // register offset; the resulting pointer is four-byte aligned.
    unsafe { read_volatile(address as *const u32) }
}

unsafe fn write_local(base: u64, offset: u64, value: u64) {
    let address = base + offset;
    // SAFETY: The caller supplies the mapped APIC page and a checked in-page
    // register offset; the resulting pointer is four-byte aligned.
    unsafe { write_volatile(address as *mut u32, value as u32) };
}

unsafe fn io_apic_read(base: u64, register: u8) -> u32 {
    // SAFETY: The caller supplies the mapped I/O APIC page. Both indirect
    // registers are within the first 0x14 bytes of that page.
    unsafe {
        write_volatile(base as *mut u32, u32::from(register));
        read_volatile((base + 0x10) as *const u32)
    }
}

unsafe fn io_apic_write(base: u64, register: u8, value: u32) {
    // SAFETY: The caller supplies the mapped I/O APIC page. Both indirect
    // registers are within the first 0x14 bytes of that page.
    unsafe {
        write_volatile(base as *mut u32, u32::from(register));
        write_volatile((base + 0x10) as *mut u32, value);
    }
}

unsafe fn mask_all_io_apic_entries(base: u64, max_redirection_index: u8) -> Result<(), ApicError> {
    let mut pin = 0;
    while pin <= max_redirection_index {
        let (low, _) = redirection_registers(pin, max_redirection_index)
            .ok_or(ApicError::InvalidIoApicVersion)?;
        let current = unsafe { io_apic_read(base, low) };
        unsafe { io_apic_write(base, low, current | IO_APIC_REDIR_MASKED) };
        pin += 1;
    }
    Ok(())
}

unsafe fn mask_local_apic_lvt_entries(base: u64) {
    for offset in [
        APIC_LVT_TIMER,
        APIC_LVT_THERMAL,
        APIC_LVT_PERFORMANCE,
        APIC_LVT_LINT0,
        APIC_LVT_LINT1,
        APIC_LVT_ERROR,
    ] {
        let value = unsafe { read_local(base, offset) };
        unsafe { write_local(base, offset, u64::from(value | APIC_LVT_MASKED)) };
    }
}

fn redirection_registers(pin: u8, max_redirection_index: u8) -> Option<(u8, u8)> {
    if pin > max_redirection_index || pin >= IO_APIC_MAX_REDIRECTIONS {
        return None;
    }
    let low = IO_APIC_REDIR_BASE.checked_add(pin.checked_mul(2)?)?;
    let high = low.checked_add(1)?;
    if high > IO_APIC_REDIR_MAX {
        None
    } else {
        Some((low, high))
    }
}

fn encode_redirection(
    vector: u8,
    polarity: InterruptPolarity,
    trigger: InterruptTrigger,
    masked: bool,
) -> u32 {
    let mut value = u32::from(vector);
    if polarity == InterruptPolarity::ActiveLow {
        value |= 1 << 13;
    }
    if trigger == InterruptTrigger::Level {
        value |= 1 << 15;
    }
    if masked {
        value |= IO_APIC_REDIR_MASKED;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{encode_redirection, redirection_registers, IO_APIC_REDIR_MASKED};
    use core::assert_eq;
    use rustix_kernel::acpi::{InterruptPolarity, InterruptTrigger};

    #[test]
    fn redirection_register_bounds_cover_only_supported_pins() {
        assert_eq!(redirection_registers(0, 23), Some((0x10, 0x11)));
        assert_eq!(redirection_registers(23, 23), Some((0x3e, 0x3f)));
        assert_eq!(redirection_registers(24, 23), None);
        assert_eq!(redirection_registers(120, 120), None);
    }

    #[test]
    fn redirection_encoding_keeps_madt_polarity_trigger_and_mask() {
        let value = encode_redirection(
            0x40,
            InterruptPolarity::ActiveLow,
            InterruptTrigger::Level,
            true,
        );
        assert_eq!(value, 0x40 | (1 << 13) | (1 << 15) | IO_APIC_REDIR_MASKED);
    }
}
