#![no_std]
#![no_main]

mod arch;
mod boot;
mod shell;

use core::panic::PanicInfo;
use rustix_kernel::vfs::RamFs;

static mut RAM_FILESYSTEM: RamFs = RamFs::new();

macro_rules! kprintln {
    () => {{
        crate::arch::x86_64::serial::print(format_args!("\r\n"));
    }};
    ($($argument:tt)*) => {{
        crate::arch::x86_64::serial::print(format_args!($($argument)*));
        crate::arch::x86_64::serial::print(format_args!("\r\n"));
    }};
}

pub(crate) use kprintln;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    arch::x86_64::serial::initialize();
    kprintln!("Rustix kernel: x86_64 Rust bootstrap");
    arch::x86_64::interrupts::initialize();
    kprintln!("x86_64 exception diagnostics: enabled (IRQs remain disabled)");
    let boot_info = match boot::capture_boot_information() {
        Ok(boot_info) => boot_info,
        Err(error) => {
            kprintln!("boot information rejected: {:?}", error);
            halt_forever();
        }
    };
    boot::report_boot_information(&boot_info);

    // SAFETY: Crabshell is the only owner of this filesystem. The bootstrap is
    // single-core and has no scheduler or filesystem-touching interrupt handlers.
    let filesystem = unsafe { &mut *core::ptr::addr_of_mut!(RAM_FILESYSTEM) };
    match filesystem.seed_defaults() {
        Ok(home) => shell::run(filesystem, home, &boot_info),
        Err(error) => {
            kprintln!("RAM filesystem initialization failed: {:?}", error);
            halt_forever()
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    arch::x86_64::serial::initialize();
    kprintln!("KERNEL PANIC: {}", info);
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: The bootstrap has no interrupt handlers or scheduler to resume.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
