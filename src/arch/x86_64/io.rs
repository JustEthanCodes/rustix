//! Narrow wrappers around x86 port I/O used by legacy platform drivers.

use core::arch::asm;

/// Read one byte from an x86 I/O port.
///
/// # Safety
/// The caller must execute at the intended privilege level and use a valid
/// device register with the access width required by that device.
pub(super) unsafe fn read_u8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: The caller upholds the port and privilege-level requirements.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Write one byte to an x86 I/O port.
///
/// # Safety
/// The caller must execute at the intended privilege level and use a valid
/// device register with the access width required by that device.
pub(super) unsafe fn write_u8(port: u16, value: u8) {
    // SAFETY: The caller upholds the port and privilege-level requirements.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}
