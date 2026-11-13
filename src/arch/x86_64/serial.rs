//! Minimal polling 16550-compatible serial output for early x86_64 diagnostics.

use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicBool, Ordering};

const COM1: u16 = 0x3f8;
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RX_INTERRUPT_MODE: AtomicBool = AtomicBool::new(false);
const IRQ_DRAIN_LIMIT: usize = 32;

/// Configure COM1 for 38,400 baud, 8 data bits, no parity, one stop bit.
pub fn initialize() {
    // SAFETY: These are the conventional legacy COM1 I/O ports on x86 PCs.
    unsafe {
        super::io::write_u8(COM1 + 1, 0x00);
        super::io::write_u8(COM1 + 3, 0x80);
        super::io::write_u8(COM1, 0x03);
        super::io::write_u8(COM1 + 1, 0x00);
        super::io::write_u8(COM1 + 3, 0x03);
        super::io::write_u8(COM1 + 2, 0xc7);
        super::io::write_u8(COM1 + 4, 0x0b);
    }
    INITIALIZED.store(true, Ordering::Release);
}

/// Write formatted text to COM1. Output is silently skipped until initialized.
pub fn print(arguments: fmt::Arguments<'_>) {
    if INITIALIZED.load(Ordering::Acquire) {
        let _ = SerialPort.write_fmt(arguments);
    }
}

/// Return a received COM1 byte if one is ready, without waiting for input.
pub fn try_read_byte() -> Option<u8> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return None;
    }
    if RX_INTERRUPT_MODE.load(Ordering::Acquire) {
        return rustix_kernel::input::UART_INPUT.try_pop();
    }

    // SAFETY: COM1 is configured by `initialize`; the line-status register and
    // receive register are accessed only by the single-core polling shell.
    unsafe {
        if super::io::read_u8(COM1 + 5) & 0x01 != 0 {
            Some(super::io::read_u8(COM1))
        } else {
            None
        }
    }
}

/// Enable receive-data interrupts after the matching IRQ route and handler exist.
pub fn enable_receive_interrupts() -> bool {
    if !INITIALIZED.load(Ordering::Acquire) {
        return false;
    }
    RX_INTERRUPT_MODE.store(true, Ordering::Release);
    // SAFETY: COM1 was initialized and the caller keeps its I/O APIC route masked
    // until this bounded, allocation-free device setup is complete.
    unsafe { super::io::write_u8(COM1 + 1, 0x01) };
    true
}

pub fn disable_receive_interrupts() {
    RX_INTERRUPT_MODE.store(false, Ordering::Release);
    if INITIALIZED.load(Ordering::Acquire) {
        // SAFETY: COM1 was initialized by this module.
        unsafe { super::io::write_u8(COM1 + 1, 0x00) };
    }
}

/// IRQ4 handler: drain a bounded number of UART receive/status causes.
pub extern "C" fn irq_handler() {
    for _ in 0..IRQ_DRAIN_LIMIT {
        // SAFETY: COM1 is initialized and this handler is the sole receive
        // consumer while the interrupt gate keeps maskable IRQs disabled.
        let interrupt_id = unsafe { super::io::read_u8(COM1 + 2) };
        if interrupt_id & 1 != 0 {
            break;
        }
        match interrupt_id & 0x0e {
            0x04 | 0x0c | 0x06 => {
                // SAFETY: COM1 line status identifies the current receive state.
                let status = unsafe { super::io::read_u8(COM1 + 5) };
                if status & 0x01 != 0 {
                    // SAFETY: Line status reports a byte in the receive register.
                    let byte = unsafe { super::io::read_u8(COM1) };
                    if rustix_kernel::input::UART_INPUT.try_push(byte) {
                        rustix_kernel::input::INPUT_EVENT_PENDING.store(true, Ordering::Release);
                    }
                } else if interrupt_id & 0x0e == 0x06 {
                    break;
                }
            }
            0x00 => {
                // SAFETY: Reading the modem status register clears its interrupt.
                let _ = unsafe { super::io::read_u8(COM1 + 6) };
            }
            _ => {
                // Drain a pending receive byte if a UART variant reports an
                // implementation-specific cause identifier.
                // SAFETY: The line-status register is valid on 16550-compatible UARTs.
                let status = unsafe { super::io::read_u8(COM1 + 5) };
                if status & 0x01 != 0 {
                    // SAFETY: Line status reports a byte in the receive register.
                    let byte = unsafe { super::io::read_u8(COM1) };
                    if rustix_kernel::input::UART_INPUT.try_push(byte) {
                        rustix_kernel::input::INPUT_EVENT_PENDING.store(true, Ordering::Release);
                    }
                }
            }
        }
    }
    super::apic::end_of_interrupt();
}

struct SerialPort;

impl fmt::Write for SerialPort {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            // SAFETY: COM1 is initialized by `initialize`; accesses are serialized
            // by the single-core bootstrap path before the kernel starts scheduling.
            unsafe { write_byte(byte) };
        }
        Ok(())
    }
}

unsafe fn write_byte(byte: u8) {
    // Bound the wait so a missing or misconfigured UART cannot deadlock boot.
    for _ in 0..100_000 {
        // SAFETY: The caller ensures this is a legacy x86 port-I/O operation.
        if unsafe { super::io::read_u8(COM1 + 5) } & 0x20 != 0 {
            // SAFETY: The UART transmit register is COM1's base port.
            unsafe { super::io::write_u8(COM1, byte) };
            return;
        }
        core::hint::spin_loop();
    }
}
