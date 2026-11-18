#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const FAULT_MESSAGE: &[u8] = b"rustix-init: invalid user buffer returned EFAULT\n";
const WAIT_MESSAGE: &[u8] = b"rustix-init: wait copied child status 7 after EFAULT retry\n";
const RUNNING_WAIT_MESSAGE: &[u8] = b"rustix-init: wait returned ENOTSUP for a running child\n";
const USER_STACK_BASE: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_GUARD_ADDRESS: u64 = USER_STACK_BASE - 0x1000;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    #[cfg(rustix_fault_probe)]
    trigger_user_fault();

    #[cfg(not(rustix_fault_probe))]
    {
        // SAFETY: The kernel maps this byte in the newly allocated initial stack
        // page and clears the page before entering this diagnostic process.
        if unsafe { (USER_STACK_BASE as *const u8).read_volatile() } != 0 {
            exit(130);
        }

        let version = rustix_user::abi_version().unwrap_or(0);
        if version != rustix_user::ABI_VERSION {
            exit(120);
        }

        if rustix_user::write_fmt(
            rustix_user::STDOUT,
            format_args!("rustix-init: hello from ring {}\n", 3),
        )
        .is_err()
        {
            exit(121);
        }

        let invalid_write = rustix_user::syscall(
            rustix_user::SYS_WRITE,
            [rustix_user::STDOUT, 0x5000_0000, 1, 0, 0, 0],
        );
        if invalid_write != -3 {
            exit(122);
        }
        if rustix_user::write_all(rustix_user::STDOUT, FAULT_MESSAGE).is_err() {
            exit(123);
        }

        let invalid_wait =
            rustix_user::syscall(rustix_user::SYS_WAIT, [0, 0x5000_0000, 0, 0, 0, 0]);
        if invalid_wait != -3 {
            exit(124);
        }
        let mut wait_status = i32::MIN;
        let waited_pid = match rustix_user::wait(0, Some(&mut wait_status)) {
            Ok(pid) => pid,
            Err(_) => exit(125),
        };
        let waited_status = wait_status;
        if waited_pid == 0 || waited_status != 7 {
            exit(125);
        }
        if rustix_user::write_all(rustix_user::STDOUT, WAIT_MESSAGE).is_err() {
            exit(126);
        }
        if !matches!(
            rustix_user::wait(0, None),
            Err(rustix_user::SyscallError::NotSupported)
        ) {
            exit(128);
        }
        if rustix_user::write_all(rustix_user::STDOUT, RUNNING_WAIT_MESSAGE).is_err() {
            exit(129);
        }
        rustix_user::exit(42)
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
    // SAFETY: The diagnostic process maps one stack page at USER_STACK_BASE;
    // this reads the immediately preceding unmapped guard page from Ring 3.
    unsafe {
        asm!(
            "mov rax, {guard}",
            "mov rax, qword ptr [rax]",
            guard = const USER_STACK_GUARD_ADDRESS,
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

#[inline]
fn exit(status: i32) -> ! {
    rustix_user::exit(status)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    rustix_user::panic_exit(info)
}
