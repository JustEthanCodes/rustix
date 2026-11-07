#[allow(dead_code)]
pub mod apic;
#[allow(dead_code)]
pub mod context;
pub mod cpu;
pub mod interrupts;
pub mod io;
// Keep polling available as the early-boot and recovery path.
#[allow(dead_code)]
pub mod keyboard;
pub mod serial;
