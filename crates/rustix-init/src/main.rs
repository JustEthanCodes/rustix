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
const SPAWN_MESSAGE: &[u8] = b"rustix-init: spawn copied user ELF and enforced task capacity\n";
#[cfg(any(
    rustix_spawner_probe,
    all(
        not(rustix_child_probe),
        not(rustix_fault_probe),
        not(rustix_exec_probe),
        not(rustix_exec_target_probe)
    )
))]
const CHILD_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rustix-child.elf"));
#[cfg(all(
    not(rustix_child_probe),
    not(rustix_fault_probe),
    not(rustix_spawner_probe),
    not(rustix_exec_probe),
    not(rustix_exec_target_probe)
))]
const SPAWNER_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rustix-spawner.elf"));
#[cfg(all(
    not(rustix_child_probe),
    not(rustix_fault_probe),
    not(rustix_spawner_probe),
    not(rustix_exec_probe),
    not(rustix_exec_target_probe)
))]
const EXEC_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rustix-exec.elf"));
#[cfg(rustix_exec_probe)]
const EXEC_TARGET_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/rustix-exec-target.elf"));

#[cfg(rustix_child_probe)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let stack_pointer: u64;
    // SAFETY: Reading the current stack register does not access memory.
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags))
    };
    let Some(first_stack_byte) = stack_pointer.checked_sub(1) else {
        rustix_user::exit(71)
    };
    let Some(second_stack_page_byte) =
        stack_pointer.checked_sub(rustix_user::USER_PAGE_SIZE as u64 + 1)
    else {
        rustix_user::exit(72)
    };
    // SAFETY: Each child is spawned with a two-page zero-filled stack, and both
    // addresses lie in its two mapped pages below the initial stack pointer.
    if unsafe {
        (first_stack_byte as *const u8).read_volatile() != 0
            || (second_stack_page_byte as *const u8).read_volatile() != 0
    } {
        rustix_user::exit(73);
    }
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-child: real child entered ring 3 with zeroed two-page stack and is exiting\n",
    )
    .is_err()
    {
        exit(70);
    }
    rustix_user::exit(7)
}

#[cfg(all(
    not(rustix_child_probe),
    not(rustix_spawner_probe),
    not(rustix_exec_probe),
    not(rustix_exec_target_probe)
))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    #[cfg(all(rustix_fault_probe, not(rustix_invalid_syscall_return_probe)))]
    trigger_user_fault();

    #[cfg(rustix_invalid_syscall_return_probe)]
    trigger_invalid_syscall_return();

    #[cfg(not(rustix_fault_probe))]
    rustix_user::run_main(init_main)
}

#[cfg(rustix_spawner_probe)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    rustix_user::run_main(spawner_main)
}

#[cfg(rustix_exec_probe)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    rustix_user::run_main(exec_main)
}

#[cfg(rustix_exec_target_probe)]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    rustix_user::run_main(exec_target_main)
}

/// A child that itself spawns: verifies nested spawn, repeated slot reuse
/// beyond the concurrent capacity, and parent-exit orphan reparenting.
#[cfg(rustix_spawner_probe)]
fn spawner_main() -> i32 {
    let child_image = match rustix_user::mmap_region(CHILD_IMAGE.len()) {
        Ok(region) => region,
        Err(_) => exit(180),
    };
    // SAFETY: The kernel returned a writable region large enough for the
    // embedded ELF; both source and destination are valid user mappings.
    unsafe {
        core::ptr::copy_nonoverlapping(
            CHILD_IMAGE.as_ptr(),
            child_image.as_mut_ptr(),
            CHILD_IMAGE.len(),
        );
    }
    let child_user_bytes =
        unsafe { core::slice::from_raw_parts(child_image.as_mut_ptr(), CHILD_IMAGE.len()) };
    // Five sequential spawn/wait/reap rounds reuse the same bounded task,
    // root, and stack slots; only three processes may exist concurrently.
    for _ in 0..5 {
        let pid = match rustix_user::spawn(child_user_bytes, 2) {
            Ok(pid) => pid,
            Err(_) => exit(181),
        };
        let mut status = i32::MIN;
        match rustix_user::wait(pid, Some(&mut status)) {
            Ok(waited) if waited == pid && status == 7 => {}
            _ => exit(182),
        }
    }
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-spawner: nested spawn/wait reuse passed five rounds\n",
    )
    .is_err()
    {
        exit(183);
    }
    // Leave one child unwaited: this parent exits first, so the kernel
    // supervisor must adopt and reap the orphan after the runtime drains.
    if rustix_user::spawn(child_user_bytes, 2).is_err() {
        exit(184);
    }
    if rustix_user::munmap_region(child_image).is_err() {
        exit(185);
    }
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-spawner: leaving one orphan for kernel reap\n",
    )
    .is_err()
    {
        exit(186);
    }
    9
}

/// Exec tester: exercises failed exec (process must remain usable) and then
/// replaces itself with the target image, which exits with status 23.
#[cfg(rustix_exec_probe)]
fn exec_main() -> i32 {
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-exec: pre-exec image running\n",
    )
    .is_err()
    {
        exit(190);
    }
    let target_image = match rustix_user::mmap_region(EXEC_TARGET_IMAGE.len()) {
        Ok(region) => region,
        Err(_) => exit(191),
    };
    // SAFETY: The region is writable and large enough for the embedded ELF.
    unsafe {
        core::ptr::copy_nonoverlapping(
            EXEC_TARGET_IMAGE.as_ptr(),
            target_image.as_mut_ptr(),
            EXEC_TARGET_IMAGE.len(),
        );
    }
    // Failed exec with an invalid source pointer must return EFAULT and leave
    // this image running.
    let invalid_exec = rustix_user::syscall(rustix_user::SYS_EXEC, [0x5000_0000, 1, 1, 0, 0, 0]);
    if invalid_exec != -3 {
        exit(192);
    }
    // SAFETY: The mapping is writable; corrupting the ELF magic exercises a
    // clean load failure without touching the running image.
    unsafe { target_image.as_mut_ptr().write_volatile(0) };
    let malformed = {
        let bytes = unsafe {
            core::slice::from_raw_parts(target_image.as_mut_ptr(), EXEC_TARGET_IMAGE.len())
        };
        rustix_user::exec(bytes, 2)
    };
    if !matches!(malformed, Err(rustix_user::SyscallError::InvalidArgument)) {
        exit(193);
    }
    // SAFETY: Restore the valid image bytes in the same writable mapping.
    unsafe {
        core::ptr::copy_nonoverlapping(
            EXEC_TARGET_IMAGE.as_ptr(),
            target_image.as_mut_ptr(),
            EXEC_TARGET_IMAGE.len(),
        );
    }
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-exec: failed exec left original image usable\n",
    )
    .is_err()
    {
        exit(197);
    }
    let target_bytes =
        unsafe { core::slice::from_raw_parts(target_image.as_mut_ptr(), EXEC_TARGET_IMAGE.len()) };
    if let Err(error) = rustix_user::exec(target_bytes, 2) {
        let _ = rustix_user::write_fmt(
            rustix_user::STDOUT,
            format_args!("rustix-exec: replacement failed: {:?}\n", error),
        );
        exit(194);
    }
    // A successful exec never returns; reaching here is a contract violation.
    exit(195)
}

/// Replacement image entered through exec: verifies its fresh zeroed stack.
#[cfg(rustix_exec_target_probe)]
fn exec_target_main() -> i32 {
    let stack_pointer: u64;
    // SAFETY: Reading the current stack register does not access memory.
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags))
    };
    let Some(first_stack_byte) = stack_pointer.checked_sub(1) else {
        exit(198);
    };
    let Some(second_stack_page_byte) =
        stack_pointer.checked_sub(rustix_user::USER_PAGE_SIZE as u64 + 1)
    else {
        exit(199);
    };
    // SAFETY: Exec prepared a two-page zero-filled stack; both addresses lie
    // in its mapped pages below the initial stack pointer.
    if unsafe {
        (first_stack_byte as *const u8).read_volatile() != 0
            || (second_stack_page_byte as *const u8).read_volatile() != 0
    } {
        exit(200);
    }
    if rustix_user::write_all(
        rustix_user::STDOUT,
        b"rustix-exec: replacement image entered ring 3 with zeroed stack\n",
    )
    .is_err()
    {
        exit(196);
    }
    23
}

#[cfg(all(
    not(rustix_fault_probe),
    not(rustix_child_probe),
    not(rustix_spawner_probe),
    not(rustix_exec_probe),
    not(rustix_exec_target_probe)
))]
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

        let child_image = match rustix_user::mmap_region(CHILD_IMAGE.len()) {
            Ok(region) => region,
            Err(_) => exit(156),
        };
        // SAFETY: The kernel returned a writable region large enough for the
        // embedded ELF, and both source and destination are valid user mappings.
        unsafe {
            core::ptr::copy_nonoverlapping(
                CHILD_IMAGE.as_ptr(),
                child_image.as_mut_ptr(),
                CHILD_IMAGE.len(),
            );
        }
        let invalid_spawn =
            rustix_user::syscall(rustix_user::SYS_SPAWN, [0x5000_0000, 1, 1, 0, 0, 0]);
        if invalid_spawn != -3 {
            exit(163);
        }
        // SAFETY: The mapping is writable and the kernel must copy the image
        // before parsing; corrupting its ELF magic exercises clean load failure.
        unsafe { child_image.as_mut_ptr().write_volatile(0) };
        let malformed_spawn = {
            let malformed_image =
                unsafe { core::slice::from_raw_parts(child_image.as_mut_ptr(), CHILD_IMAGE.len()) };
            rustix_user::spawn(malformed_image, 2)
        };
        if !matches!(
            malformed_spawn,
            Err(rustix_user::SyscallError::InvalidArgument)
        ) {
            exit(164);
        }
        // SAFETY: The destination remains the same writable user mapping.
        unsafe {
            core::ptr::copy_nonoverlapping(
                CHILD_IMAGE.as_ptr(),
                child_image.as_mut_ptr(),
                CHILD_IMAGE.len(),
            );
        }
        let child_user_bytes =
            unsafe { core::slice::from_raw_parts(child_image.as_mut_ptr(), CHILD_IMAGE.len()) };
        let spawned_pid = match rustix_user::spawn(child_user_bytes, 2) {
            Ok(pid) => pid,
            Err(_) => exit(157),
        };
        let second_spawned_pid = match rustix_user::spawn(child_user_bytes, 2) {
            Ok(pid) if pid != spawned_pid => pid,
            Ok(_) => exit(160),
            Err(error) => {
                let _ = rustix_user::write_fmt(
                    rustix_user::STDOUT,
                    format_args!("rustix-init: second spawn failed: {:?}\n", error),
                );
                exit(162);
            }
        };
        let third_spawned_pid = match rustix_user::spawn(child_user_bytes, 2) {
            Ok(pid) if pid != spawned_pid && pid != second_spawned_pid => pid,
            Ok(_) => exit(165),
            Err(_) => exit(166),
        };
        if !matches!(
            rustix_user::spawn(child_user_bytes, 2),
            Err(rustix_user::SyscallError::OutOfMemory)
        ) {
            exit(167);
        }
        if rustix_user::munmap_region(child_image).is_err() {
            exit(158);
        }
        if rustix_user::write_all(rustix_user::STDOUT, SPAWN_MESSAGE).is_err() {
            exit(159);
        }

        let invalid_wait = rustix_user::syscall(
            rustix_user::SYS_WAIT,
            [spawned_pid, 0x5000_0000, 0, 0, 0, 0],
        );
        if invalid_wait != -3 {
            exit(124);
        }
        let mut wait_status = i32::MIN;
        let waited_pid = match rustix_user::wait(spawned_pid, Some(&mut wait_status)) {
            Ok(pid) => pid,
            Err(_) => exit(125),
        };
        let waited_status = wait_status;
        if waited_pid != spawned_pid || waited_status != 7 {
            exit(125);
        }
        if rustix_user::write_all(rustix_user::STDOUT, WAIT_MESSAGE).is_err() {
            exit(126);
        }
        let mut second_wait_status = i32::MIN;
        match rustix_user::wait(second_spawned_pid, Some(&mut second_wait_status)) {
            Ok(pid) if pid == second_spawned_pid && second_wait_status == 7 => {}
            _ => exit(161),
        }
        let mut third_wait_status = i32::MIN;
        match rustix_user::wait(third_spawned_pid, Some(&mut third_wait_status)) {
            Ok(pid) if pid == third_spawned_pid && third_wait_status == 7 => {}
            _ => exit(168),
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

        // Nested spawn: the spawner is itself a child and spawns grandchildren,
        // reusing bounded slots across five rounds and leaving one orphan.
        let spawner_region = match rustix_user::mmap_region(SPAWNER_IMAGE.len()) {
            Ok(region) => region,
            Err(_) => exit(170),
        };
        // SAFETY: The region is writable and large enough for the embedded ELF.
        unsafe {
            core::ptr::copy_nonoverlapping(
                SPAWNER_IMAGE.as_ptr(),
                spawner_region.as_mut_ptr(),
                SPAWNER_IMAGE.len(),
            );
        }
        let spawner_pid = {
            let bytes = unsafe {
                core::slice::from_raw_parts(spawner_region.as_mut_ptr(), SPAWNER_IMAGE.len())
            };
            match rustix_user::spawn(bytes, 2) {
                Ok(pid) => pid,
                Err(_) => exit(171),
            }
        };
        if rustix_user::munmap_region(spawner_region).is_err() {
            exit(172);
        }
        let mut spawner_status = i32::MIN;
        match rustix_user::wait(spawner_pid, Some(&mut spawner_status)) {
            Ok(pid) if pid == spawner_pid && spawner_status == 9 => {}
            _ => exit(173),
        }
        if rustix_user::write_all(
            rustix_user::STDOUT,
            b"rustix-init: nested spawn and slot reuse verified\n",
        )
        .is_err()
        {
            exit(174);
        }

        // Exec: the tester replaces its own image and exits with status 23.
        let exec_region = match rustix_user::mmap_region(EXEC_IMAGE.len()) {
            Ok(region) => region,
            Err(_) => exit(175),
        };
        // SAFETY: The region is writable and large enough for the embedded ELF.
        unsafe {
            core::ptr::copy_nonoverlapping(
                EXEC_IMAGE.as_ptr(),
                exec_region.as_mut_ptr(),
                EXEC_IMAGE.len(),
            );
        }
        let exec_pid = {
            let bytes =
                unsafe { core::slice::from_raw_parts(exec_region.as_mut_ptr(), EXEC_IMAGE.len()) };
            match rustix_user::spawn(bytes, 2) {
                Ok(pid) => pid,
                Err(_) => exit(176),
            }
        };
        if rustix_user::munmap_region(exec_region).is_err() {
            exit(177);
        }
        let mut exec_status = i32::MIN;
        match rustix_user::wait(exec_pid, Some(&mut exec_status)) {
            Ok(pid) if pid == exec_pid && exec_status == 23 => {}
            _ => exit(178),
        }
        if rustix_user::write_all(
            rustix_user::STDOUT,
            b"rustix-init: exec replacement and old-image reclamation verified\n",
        )
        .is_err()
        {
            exit(179);
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

#[cfg(rustix_invalid_syscall_return_probe)]
fn trigger_invalid_syscall_return() -> ! {
    // SAFETY: This probe leaves Ring 3 with a canonical but invalid zero RSP,
    // then enters through the privilege-switching syscall gate. The kernel must
    // terminate this process instead of halting the whole machine.
    unsafe {
        asm!(
            "xor rsp, rsp",
            "xor eax, eax",
            "int 0x80",
            options(noreturn)
        );
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
