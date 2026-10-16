//! Non-blocking polling access to a legacy PS/2-compatible keyboard port.
//!
//! The API returns raw controller bytes; it does not translate scancode sets,
//! handle keyboard commands, or provide USB HID support. The kernel currently
//! has no input subsystem or interrupt handler, so callers must poll explicitly.

use super::io::read_u8;

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const OUTPUT_BUFFER_FULL: u8 = 1 << 0;
const AUXILIARY_OUTPUT: u8 = 1 << 5;
const TIMEOUT_ERROR: u8 = 1 << 6;
const PARITY_ERROR: u8 = 1 << 7;

/// Return one pending keyboard byte without waiting for input.
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
