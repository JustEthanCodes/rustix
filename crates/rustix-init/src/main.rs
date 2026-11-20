#![no_std]
#![no_main]

extern crate alloc;

#[cfg(not(rustix_child_probe))]
use alloc::boxed::Box;
#[cfg(not(rustix_child_probe))]
use alloc::vec::Vec;
use core::arch::asm;
use core::panic::PanicInfo;

#[global_allocator]
static ALLOCATOR: rustix_user::UserAllocator = rustix_user::UserAllocator::new();

const FAULT_MESSAGE: &[u8] = b"rustix-init: invalid user buffer returned EFAULT\n";
const WAIT_MESSAGE: &[u8] =
    b"rustix-init: blocking wait copied child status 7 after EFAULT retry\n";
const USER_STACK_BASE: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_GUARD_ADDRESS: u64 = USER_STACK_BASE - 0x1000;
const HEAP_MESSAGE: &[u8] = b"rustix-init: heap Vec and Box round-trip ok\n";
const MULTI_PAGE_MESSAGE: &[u8] = b"rustix-init: multi-page mmap zero/write/unmap ok\n";

#[cfg(rustix_child_probe)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-child: real child entered ring 3 and is exiting\n",
    )
    .is_err()
    {
        exit(70);
    }
    rustix_user::exit(7)
}

#[cfg(not(rustix_child_probe))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    #[cfg(rustix_fault_probe)]
    trigger_user_fault();

    #[cfg(not(rustix_fault_probe))]
    rustix_user::run_main(init_main)
}

#[cfg(all(not(rustix_fault_probe), not(rustix_child_probe)))]
fn init_main() -> i32 {
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

        if !matches!(
            rustix_user::mmap(0),
            Err(rustix_user::SyscallError::InvalidArgument)
        ) {
            exit(136);
        }
        if !matches!(
            rustix_user::mmap(rustix_user::USER_PAGE_SIZE + 1),
            Err(rustix_user::SyscallError::ArgumentListTooLong)
        ) {
            exit(137);
        }
        let protected_stack_unmap = rustix_user::syscall(
            rustix_user::SYS_MUNMAP,
            [
                USER_STACK_BASE,
                rustix_user::USER_PAGE_SIZE as u64,
                0,
                0,
                0,
                0,
            ],
        );
        if protected_stack_unmap != -1 {
            exit(138);
        }

        let anonymous_page = match rustix_user::mmap(1) {
            Ok(region) => region,
            Err(_) => exit(131),
        };
        let anonymous_pointer = anonymous_page.as_mut_ptr();
        // SAFETY: The kernel returns one mapped, zeroed, writable user page, and
        // this process has exclusive access to its new anonymous region.
        unsafe {
            if anonymous_pointer.read_volatile() != 0 {
                exit(132);
            }
            anonymous_pointer.write_volatile(0x5a);
            if anonymous_pointer.read_volatile() != 0x5a {
                exit(133);
            }
        }
        let anonymous_address = anonymous_page.address();
        if rustix_user::munmap(anonymous_page).is_err() {
            exit(134);
        }
        let unmapped_write = rustix_user::syscall(
            rustix_user::SYS_WRITE,
            [rustix_user::STDOUT, anonymous_address, 1, 0, 0, 0],
        );
        if unmapped_write != -3 {
            exit(135);
        }
        let repeated_unmap = rustix_user::syscall(
            rustix_user::SYS_MUNMAP,
            [
                anonymous_address,
                rustix_user::USER_PAGE_SIZE as u64,
                0,
                0,
                0,
                0,
            ],
        );
        if repeated_unmap != -1 {
            exit(139);
        }

        let multi_page = match rustix_user::mmap_region(rustix_user::USER_PAGE_SIZE + 1) {
            Ok(region) if region.length() == rustix_user::USER_PAGE_SIZE * 2 => region,
            _ => exit(148),
        };
        let multi_page_address = multi_page.address();
        // SAFETY: mmap_region returns two zeroed, writable pages, and these
        // accesses straddle their boundary while remaining within the mapping.
        unsafe {
            let first = multi_page.as_mut_ptr().add(rustix_user::USER_PAGE_SIZE - 1);
            let second = multi_page.as_mut_ptr().add(rustix_user::USER_PAGE_SIZE);
            if first.read_volatile() != 0 || second.read_volatile() != 0 {
                exit(149);
            }
            first.write_volatile(0xa5);
            second.write_volatile(0x5a);
            if first.read_volatile() != 0xa5 || second.read_volatile() != 0x5a {
                exit(150);
            }
        }
        let partial_multi_page_unmap = rustix_user::syscall(
            rustix_user::SYS_MUNMAP_REGION,
            [
                multi_page_address,
                rustix_user::USER_PAGE_SIZE as u64,
                0,
                0,
                0,
                0,
            ],
        );
        if partial_multi_page_unmap != -1 {
            exit(154);
        }
        // SAFETY: Rejected partial unmaps must leave the complete region mapped.
        unsafe {
            if (multi_page_address as *const u8)
                .add(rustix_user::USER_PAGE_SIZE - 1)
                .read_volatile()
                != 0xa5
            {
                exit(155);
            }
        }
        if rustix_user::munmap_region(multi_page).is_err() {
            exit(151);
        }
        let stale_multi_page_write = rustix_user::syscall(
            rustix_user::SYS_WRITE,
            [rustix_user::STDOUT, multi_page_address, 1, 0, 0, 0],
        );
        if stale_multi_page_write != -3 {
            exit(152);
        }
        if rustix_user::write_all(rustix_user::STDOUT, MULTI_PAGE_MESSAGE).is_err() {
            exit(153);
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

        let duplicate_stdout = match rustix_user::dup(rustix_user::STDOUT) {
            Ok(fd) if fd >= 3 => fd,
            _ => exit(140),
        };
        if rustix_user::write_all(duplicate_stdout, b"rustix-init: duplicated stdout works\n")
            .is_err()
        {
            exit(141);
        }
        if rustix_user::close(duplicate_stdout).is_err() {
            exit(142);
        }
        if !matches!(
            rustix_user::write(duplicate_stdout, b"closed"),
            Err(rustix_user::SyscallError::BadFileDescriptor)
        ) {
            exit(143);
        }
        if !matches!(
            rustix_user::dup(duplicate_stdout),
            Err(rustix_user::SyscallError::BadFileDescriptor)
        ) {
            exit(144);
        }
        if !matches!(
            rustix_user::close(duplicate_stdout),
            Err(rustix_user::SyscallError::BadFileDescriptor)
        ) {
            exit(145);
        }

        let values: Vec<u32> = (0..64).collect();
        let boxed = Box::new(values.iter().map(|value| u64::from(*value)).sum::<u64>());
        if *boxed != 2016 || values.len() != 64 {
            exit(146);
        }
        drop(values);
        drop(boxed);
        if rustix_user::write_all(rustix_user::STDOUT, HEAP_MESSAGE).is_err() {
            exit(147);
        }

        42
    }
}

#[cfg(all(rustix_fault_probe, not(rustix_child_probe)))]
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
