//! Interrupt-driven raw-byte input from a legacy PS/2-compatible keyboard port.
//!
//! The API returns raw controller bytes; it does not translate scancode sets,
//! handle keyboard commands, or provide USB HID support. A bounded IRQ queue is
//! available after controller and I/O APIC setup; polling remains available for
//! early boot and recovery.

use super::io::{read_u8, write_u8};

const CONFIGURE_MAX_POLLS: usize = 100_000;
const IRQ_DRAIN_LIMIT: usize = 16;

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const OUTPUT_BUFFER_FULL: u8 = 1 << 0;
const AUXILIARY_OUTPUT: u8 = 1 << 5;
const TIMEOUT_ERROR: u8 = 1 << 6;
const PARITY_ERROR: u8 = 1 << 7;

/// Enable the controller's keyboard IRQ after bounded status checks.
///
/// Returns false when the legacy controller does not respond within the bounded
/// waits. The caller must keep the I/O APIC route masked until the handler is
/// registered and this setup has succeeded.
pub fn initialize_interrupts() -> bool {
    // SAFETY: This privileged driver owns the legacy controller ports during
    // single-CPU bootstrap; all waits are bounded and no other reader is active.
    unsafe {
        for _ in 0..IRQ_DRAIN_LIMIT {
            if read_u8(STATUS_PORT) & OUTPUT_BUFFER_FULL == 0 {
                break;
            }
            let _ = read_u8(DATA_PORT);
        }
        if !wait_input_empty() {
            return false;
        }
        write_u8(STATUS_PORT, 0x20);
        if !wait_output_full() {
            return false;
        }
        let mut config = read_u8(DATA_PORT);
        config |= 1 << 1;
        config &= !(1 << 4);
        if !wait_input_empty() {
            return false;
        }
        write_u8(STATUS_PORT, 0x60);
        if !wait_input_empty() {
            return false;
        }
        write_u8(DATA_PORT, config);
        if !wait_input_empty() {
            return false;
        }
        write_u8(STATUS_PORT, 0xae);
        wait_input_empty()
    }
}

fn wait_input_empty() -> bool {
    for _ in 0..CONFIGURE_MAX_POLLS {
        // SAFETY: Caller runs at CPL 0 and this is the controller status port.
        if unsafe { read_u8(STATUS_PORT) } & (1 << 1) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn wait_output_full() -> bool {
    for _ in 0..CONFIGURE_MAX_POLLS {
        // SAFETY: Caller runs at CPL 0 and this is the controller status port.
        if unsafe { read_u8(STATUS_PORT) } & OUTPUT_BUFFER_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// IRQ1 handler: drain a bounded number of bytes into the raw input queue.
pub extern "C" fn irq_handler() {
    let mut received = false;
    for _ in 0..IRQ_DRAIN_LIMIT {
        // SAFETY: IRQ1 is registered only after controller setup. The handler is
        // the sole controller-data consumer while maskable interrupts are off.
        let status = unsafe { read_u8(STATUS_PORT) };
        if status & OUTPUT_BUFFER_FULL == 0 {
            break;
        }
        // SAFETY: Status reported an available controller output byte.
        let byte = unsafe { read_u8(DATA_PORT) };
        if status & (AUXILIARY_OUTPUT | TIMEOUT_ERROR | PARITY_ERROR) == 0 {
            received |= rustix_kernel::input::KEYBOARD_INPUT.try_push(byte);
        }
    }
    if received {
        rustix_kernel::input::INPUT_EVENT_PENDING
            .store(true, core::sync::atomic::Ordering::Release);
    }
    super::apic::end_of_interrupt();
}

/// Pop one raw scancode delivered by IRQ1 without waiting.
pub fn try_read_irq_scancode() -> Option<u8> {
    rustix_kernel::input::KEYBOARD_INPUT.try_pop()
}

/// Return one pending keyboard byte without waiting.
///
/// Auxiliary-device bytes (normally a PS/2 mouse) and controller-error bytes
/// are consumed and discarded so they cannot leave the output buffer blocked.
/// Returns `None` when no keyboard byte is ready.
pub fn try_read_scancode() -> Option<u8> {
    // SAFETY: The x86_64 platform driver is privileged and owns these legacy
    // controller ports. Reads are non-blocking and only performed when ready.
    unsafe {
        let status = read_u8(STATUS_PORT);
        if status & OUTPUT_BUFFER_FULL == 0 {
            return None;
        }

        let byte = read_u8(DATA_PORT);
        if status & (AUXILIARY_OUTPUT | TIMEOUT_ERROR | PARITY_ERROR) != 0 {
            return None;
        }
        Some(byte)
    }
}
