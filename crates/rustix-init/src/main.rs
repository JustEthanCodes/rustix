#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const ABI_VERSION: u64 = 0x0001_0000;
const SYS_ABI_VERSION: u64 = 0;
const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 2;
const STDOUT: u64 = 1;
const MESSAGE: &[u8] = b"rustix-init: hello from ring 3\n";
const FAULT_MESSAGE: &[u8] = b"rustix-init: invalid user buffer returned EFAULT\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    #[cfg(rustix_fault_probe)]
    trigger_user_fault();

    #[cfg(not(rustix_fault_probe))]
    {
        let version = unsafe { syscall(SYS_ABI_VERSION, 0, 0, 0, 0, 0, 0) };
        if version != ABI_VERSION as i64 {
            exit(120);
        }

        let written = unsafe {
            syscall(
                SYS_WRITE,
                STDOUT,
                MESSAGE.as_ptr() as u64,
                MESSAGE.len() as u64,
                0,
                0,
                0,
            )
        };
        if written != MESSAGE.len() as i64 {
            exit(121);
        }

        let invalid_write = unsafe { syscall(SYS_WRITE, STDOUT, 0x5000_0000, 1, 0, 0, 0) };
        if invalid_write != -3 {
            exit(122);
        }
        let fault_message_written = unsafe {
            syscall(
                SYS_WRITE,
                STDOUT,
                FAULT_MESSAGE.as_ptr() as u64,
                FAULT_MESSAGE.len() as u64,
                0,
                0,
                0,
            )
        };
        if fault_message_written != FAULT_MESSAGE.len() as i64 {
            exit(123);
        }
        exit(42)
    }
}

#[cfg(rustix_fault_probe)]
fn trigger_user_fault() -> ! {
    #[cfg(rustix_user_fault_ud)]
    // SAFETY: This payload variant deliberately raises user-mode #UD in QEMU.
    unsafe {
        asm!("ud2", options(noreturn));
    }

    #[cfg(rustix_user_fault_page)]
    // SAFETY: The test intentionally reads an unmapped lower-half address from
    // Ring 3, producing a user page fault handled by the process-exit path.
    unsafe {
        asm!(
            "mov rax, 0x50000000",
            "mov rax, qword ptr [rax]",
            out("rax") _,
            options(nostack, readonly)
        );
    }

    #[cfg(rustix_user_fault_gp)]
    // SAFETY: DPL 0 vector 0x20 is intentionally invoked from Ring 3 to trigger
    // #GP before the interrupt handler can run.
    unsafe {
        asm!("int 0x20", options(nomem, nostack));
    }

    #[cfg(rustix_user_fault_de)]
    // SAFETY: The zero divisor deliberately produces user-mode #DE in QEMU.
    unsafe {
        asm!(
            "xor edx, edx",
            "xor eax, eax",
            "xor ecx, ecx",
            "div ecx",
            out("eax") _,
            out("edx") _,
            out("ecx") _,
            options(nostack)
        );
    }

    loop {
        core::hint::spin_loop();
    }
}

fn exit(status: i32) -> ! {
    // The kernel's exit syscall must not return; spinning is a fail-closed fallback.
    let _ = unsafe { syscall(SYS_EXIT, status as u32 as u64, 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn syscall(
    number: u64,
    first: u64,
    second: u64,
    third: u64,
    fourth: u64,
    fifth: u64,
    sixth: u64,
) -> i64 {
    let result: u64;
    // SAFETY: The kernel installs the documented DPL-3 int 0x80 gate and saves
    // all listed registers. The Rustix syscall ABI uses RAX and six argument regs.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            in("r8") fifth,
            in("r9") sixth,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    result as i64
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(127)
}
