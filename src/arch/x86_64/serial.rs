//! Minimal polling 16550-compatible serial output for early x86_64 diagnostics.

use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicBool, Ordering};

const COM1: u16 = 0x3f8;
static INITIALIZED: AtomicBool = AtomicBool::new(false);

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
