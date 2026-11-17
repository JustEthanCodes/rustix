//! Bootstrap GDT, TSS, and interrupt entry for x86_64.
//!
//! Bootstrap installs exception and device-IRQ gates with maskable interrupts
//! disabled. APIC setup, route masking, handler registration, and explicit `sti`
//! are owned by the boot path. Kernel exceptions and selected critical user
//! exceptions remain fatal; the diagnostic user-process path can reap other CPL3 faults.

use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use rustix_kernel::sync::InterruptContextGuard;

const EXCEPTION_COUNT: usize = 32;
const IRQ_FIRST_VECTOR: usize = 0x20;
const IRQ_LAST_VECTOR: usize = 0xef;
const IRQ_VECTOR_COUNT: usize = IRQ_LAST_VECTOR - IRQ_FIRST_VECTOR + 1;
const APIC_SPURIOUS_VECTOR: usize = 0xff;
/// Vectors 0xf0-0xfe have no registered source or IDT-worthy meaning today.
/// They are wired to a controlled fatal stop instead of left non-present.
const IRQ_UNWIRED_FIRST_VECTOR: usize = 0xf0;
const IRQ_UNWIRED_LAST_VECTOR: usize = 0xfe;
const IRQ_UNWIRED_COUNT: usize = IRQ_UNWIRED_LAST_VECTOR - IRQ_UNWIRED_FIRST_VECTOR + 1;
const IRQ_STUB_COUNT: usize = IRQ_VECTOR_COUNT + IRQ_UNWIRED_COUNT + 1;
const USER_SYSCALL_VECTOR: usize = rustix_kernel::syscall::USER_SYSCALL_VECTOR as usize;
const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const USER_DATA_SELECTOR: u16 = rustix_kernel::syscall::USER_DATA_SELECTOR;
pub const USER_CODE_SELECTOR: u16 = rustix_kernel::syscall::USER_CODE_SELECTOR;
const USER_DATA_DESCRIPTOR: u64 = 0x00cf_f200_0000_ffff;
const USER_CODE_DESCRIPTOR: u64 = 0x00af_fa00_0000_ffff;
const _: [(); 0x2b] = [(); USER_DATA_SELECTOR as usize];
const _: [(); 0x33] = [(); USER_CODE_SELECTOR as usize];
const _: [(); 208] = [(); IRQ_VECTOR_COUNT];
const STACK_SIZE: usize = 16 * 1024;
const TSS_DESCRIPTOR_TYPE: u64 = 0x89;

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(C, align(16))]
struct IdtTable([IdtEntry; 256]);

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x07,
            attributes: 0x8e,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    fn user_interrupt_gate(handler: u64) -> Self {
        let mut entry = Self::interrupt_gate(handler, 0);
        entry.attributes = 0xee;
        entry
    }
}

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl TaskStateSegment {
    const EMPTY: Self = Self {
        reserved0: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        reserved1: 0,
        ist1: 0,
        ist2: 0,
        ist3: 0,
        ist4: 0,
        ist5: 0,
        ist6: 0,
        ist7: 0,
        reserved2: 0,
        reserved3: 0,
        iomap_base: size_of::<Self>() as u16,
    };
}

#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

static mut GDT: [u64; 7] = [0; 7];
static mut IDT: IdtTable = IdtTable([IdtEntry::MISSING; 256]);
static mut TSS: TaskStateSegment = TaskStateSegment::EMPTY;
static mut RING0_STACK: Stack = Stack([0; STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; STACK_SIZE]);
static mut IRQ_HANDLERS: [Option<IrqHandler>; 256] = [None; 256];
/// Whether a fatal exception diagnostic is in progress. A fault from inside
/// the fatal path stops silently instead of recursively printing.
static IN_FATAL_EXCEPTION: AtomicBool = AtomicBool::new(false);
static USER_VIRTUAL_ADDRESS_BITS: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "probe-user-process")]
pub(crate) type UserSyscallHandler =
    extern "C" fn(*mut rustix_kernel::syscall::SyscallContext, *mut ()) -> i64;
#[cfg(feature = "probe-user-process")]
pub(crate) type UserExceptionHandler = extern "C" fn(u64, *mut ()) -> bool;

#[cfg(feature = "probe-user-process")]
#[derive(Clone, Copy)]
struct UserSyscallRuntime {
    handler: UserSyscallHandler,
    exception_handler: UserExceptionHandler,
    context: *mut (),
}

#[cfg(feature = "probe-user-process")]
static mut USER_SYSCALL_RUNTIME: Option<UserSyscallRuntime> = None;
#[no_mangle]
static mut RUSTIX_USER_RESUME_RSP: u64 = 0;
#[no_mangle]
static mut RUSTIX_USER_EXIT_PENDING: u8 = 0;
#[no_mangle]
static mut RUSTIX_USER_EXIT_STATUS: i32 = 0;
#[repr(C, align(16))]
struct UserKernelFxState([u8; 512]);
#[no_mangle]
static mut RUSTIX_USER_KERNEL_FX_STATE: UserKernelFxState = UserKernelFxState([0; 512]);

/// A device interrupt callback. The callback is responsible for issuing EOI.
pub type IrqHandler = extern "C" fn();

/// Reasons an IRQ callback could not be registered.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqRegistrationError {
    InvalidVector,
    InterruptsEnabled,
    AlreadyRegistered,
}

// In 64-bit mode, exception entry saves SS:RSP even for a CPL 0 fault.
#[repr(C)]
// Register dumps are only compiled with the `fatal-register-dump` feature;
// the vector/error/RIP fields are always needed for the fatal diagnostic.
#[cfg_attr(not(feature = "fatal-register-dump"), allow(dead_code))]
pub(crate) struct ExceptionContext {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

const _: [(); 16] = [(); size_of::<IdtEntry>()];
const _: [(); 4096] = [(); size_of::<IdtTable>()];
const _: [(); 104] = [(); size_of::<TaskStateSegment>()];
const _: [(); 176] = [(); size_of::<ExceptionContext>()];
const _: [(); 120] = [(); core::mem::offset_of!(ExceptionContext, vector)];
const _: [(); 128] = [(); core::mem::offset_of!(ExceptionContext, error_code)];
const _: [(); 136] = [(); core::mem::offset_of!(ExceptionContext, rip)];
const _: [(); 144] = [(); core::mem::offset_of!(ExceptionContext, cs)];
const _: [(); 152] = [(); core::mem::offset_of!(ExceptionContext, rflags)];
const _: [(); 160] = [(); core::mem::offset_of!(ExceptionContext, rsp)];
const _: [(); 168] = [(); core::mem::offset_of!(ExceptionContext, ss)];

extern "C" {
    static exception_stub_table: [usize; EXCEPTION_COUNT];
    static irq_stub_table: [usize; IRQ_STUB_COUNT];
    fn rustix_load_gdt(descriptor_table_pointer: *const DescriptorTablePointer);
    fn rustix_syscall_stub();
    #[cfg(feature = "probe-user-process")]
    fn rustix_enter_user(frame: *const rustix_kernel::syscall::UserIretFrame) -> i32;
    #[cfg(feature = "probe-user-process")]
    fn rustix_user_exception_exit() -> !;
}

/// Install a private kernel GDT/TSS, exception gates, and device IRQ gates.
///
/// The bootstrap runs with maskable interrupts disabled. This routine leaves
/// them disabled and does not modify CR3 or the inherited page-table hierarchy.
pub fn initialize() {
    // SAFETY: Single-core bootstrap ownership; the descriptor tables are private
    // static storage and are initialized before any gate is loaded.
    unsafe {
        asm!("cli", options(nomem, nostack));
        initialize_tss();
        initialize_gdt();
        initialize_idt();
    }
}

unsafe fn initialize_tss() {
    let ring0_stack = core::ptr::addr_of_mut!(RING0_STACK).cast::<u8>();
    let double_fault_stack = core::ptr::addr_of_mut!(DOUBLE_FAULT_STACK).cast::<u8>();
    // SAFETY: These pointers refer to the ends of distinct, aligned static stacks.
    let ring0_top = unsafe { ring0_stack.add(STACK_SIZE) } as u64;
    // SAFETY: These pointers refer to the ends of distinct, aligned static stacks.
    let double_fault_top = unsafe { double_fault_stack.add(STACK_SIZE) } as u64;
    let tss = core::ptr::addr_of_mut!(TSS);

    // The architectural TSS fields are packed; use unaligned raw writes rather
    // than creating references to their potentially unaligned storage.
    unsafe {
        core::ptr::addr_of_mut!((*tss).rsp0).write_unaligned(ring0_top);
        core::ptr::addr_of_mut!((*tss).ist1).write_unaligned(double_fault_top);
    }
}

unsafe fn initialize_gdt() {
    let tss_base = core::ptr::addr_of!(TSS) as u64;
    let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let low = (tss_limit & 0xffff)
        | ((tss_base & 0x00ff_ffff) << 16)
        | (TSS_DESCRIPTOR_TYPE << 40)
        | ((tss_limit & 0x000f_0000) << 32)
        | ((tss_base & 0xff00_0000) << 32);
    let high = tss_base >> 32;

    unsafe {
        core::ptr::addr_of_mut!(GDT[0]).write(0);
        core::ptr::addr_of_mut!(GDT[1]).write(0x00af_9a00_0000_ffff);
        core::ptr::addr_of_mut!(GDT[2]).write(0x00cf_9200_0000_ffff);
        core::ptr::addr_of_mut!(GDT[3]).write(low);
        core::ptr::addr_of_mut!(GDT[4]).write(high);
        core::ptr::addr_of_mut!(GDT[5]).write(USER_DATA_DESCRIPTOR);
        core::ptr::addr_of_mut!(GDT[6]).write(USER_CODE_DESCRIPTOR);
    }

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: core::ptr::addr_of!(GDT) as u64,
    };
    // SAFETY: `GDT` and its TSS descriptor are initialized and remain live.
    unsafe { rustix_load_gdt(&gdtr) };
}

unsafe fn initialize_idt() {
    let idt_entries = core::ptr::addr_of_mut!(IDT.0).cast::<IdtEntry>();
    let stubs = core::ptr::addr_of!(exception_stub_table).cast::<usize>();

    for vector in 0..EXCEPTION_COUNT {
        // SAFETY: The assembly table contains exactly 32 stub addresses.
        let handler = unsafe { stubs.add(vector).read() } as u64;
        let ist = if vector == 8 { 1 } else { 0 };
        // SAFETY: `vector` is bounded by the statically allocated 256-entry IDT.
        unsafe {
            idt_entries
                .add(vector)
                .write(IdtEntry::interrupt_gate(handler, ist));
        }
    }

    let irq_stubs = core::ptr::addr_of!(irq_stub_table).cast::<usize>();
    for vector in IRQ_FIRST_VECTOR..=IRQ_LAST_VECTOR {
        // SAFETY: The assembly table contains one stub for each allocated vector.
        let handler = unsafe { irq_stubs.add(vector - IRQ_FIRST_VECTOR).read() } as u64;
        // SAFETY: `vector` is bounded by the statically allocated 256-entry IDT.
        unsafe {
            idt_entries
                .add(vector)
                .write(IdtEntry::interrupt_gate(handler, 0));
        }
    }
    // Vector 0x80 is reserved from device allocation and uses its own DPL-3
    // interrupt gate rather than the generic device-IRQ dispatch path.
    // SAFETY: The assembly defines this dedicated entry stub in the kernel image.
    unsafe {
        idt_entries
            .add(USER_SYSCALL_VECTOR)
            .write(IdtEntry::user_interrupt_gate(
                rustix_syscall_stub as *const () as usize as u64,
            ));
    }

    // SAFETY: The final table entry is the dedicated 0xff spurious-IRQ stub.
    let spurious_handler =
        unsafe { irq_stubs.add(IRQ_VECTOR_COUNT + IRQ_UNWIRED_COUNT).read() } as u64;
    // SAFETY: The APIC spurious vector is a valid IDT index.
    unsafe {
        idt_entries
            .add(APIC_SPURIOUS_VECTOR)
            .write(IdtEntry::interrupt_gate(spurious_handler, 0));
    }
    // Vectors 0xf0-0xfe have no registered source; wire them to a controlled
    // fatal stop (through the shared dispatch, which halts) instead of leaving
    // non-present gates that would cascade into #GP with no diagnostics.
    for vector in IRQ_UNWIRED_FIRST_VECTOR..=IRQ_UNWIRED_LAST_VECTOR {
        // SAFETY: The assembly table provides one stub for each vector.
        let handler =
            unsafe { irq_stubs.add(IRQ_VECTOR_COUNT + (vector - IRQ_UNWIRED_FIRST_VECTOR)) }.read()
                as u64;
        // SAFETY: `vector` is bounded by the statically allocated 256-entry IDT.
        unsafe {
            idt_entries
                .add(vector)
                .write(IdtEntry::interrupt_gate(handler, 0));
        }
    }

    let idtr = DescriptorTablePointer {
        limit: (size_of::<IdtTable>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: Every architectural exception gate is initialized in static storage.
    unsafe { asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags)) };
}

/// Configure the active user virtual-address width used to sanitize syscall returns.
///
/// Call after boot CPU discovery and before any CPL3 code can execute.
pub fn configure_user_address_width(virtual_address_bits: u8) -> Result<(), KernelEntryStackError> {
    if !matches!(virtual_address_bits, 48 | 57) {
        return Err(KernelEntryStackError::InvalidVirtualAddressWidth);
    }
    USER_VIRTUAL_ADDRESS_BITS.store(virtual_address_bits, Ordering::Release);
    Ok(())
}

/// Errors returned while selecting the ring-0 entry stack for a user context.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelEntryStackError {
    InvalidVirtualAddressWidth,
    NonCanonical,
    NotKernelAddress,
    Misaligned,
}

#[cfg(feature = "probe-user-process")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserRuntimeError {
    InterruptsEnabled,
    AlreadyInstalled,
    NotInstalled,
}

/// Select the stack used by the next privilege transition from CPL3 to CPL0.
///
/// # Safety
/// The TSS must already be initialized, local interrupts must be disabled, and
/// `stack_top` must be the aligned top of a live, writable supervisor stack that
/// is mapped in the active address space and every address space that may run
/// before this value is changed again. Callers must update it before entering a
/// different process. The function validates the address shape, not the mapping
/// or ownership of the stack memory.
#[allow(dead_code)]
pub unsafe fn set_kernel_entry_stack(
    stack_top: u64,
    virtual_address_bits: u8,
) -> Result<(), KernelEntryStackError> {
    if !matches!(virtual_address_bits, 48 | 57) {
        return Err(KernelEntryStackError::InvalidVirtualAddressWidth);
    }
    if stack_top & 0xf != 0 {
        return Err(KernelEntryStackError::Misaligned);
    }
    if !rustix_kernel::memory::is_canonical_virtual_address(stack_top, virtual_address_bits) {
        return Err(KernelEntryStackError::NonCanonical);
    }
    if stack_top & (1u64 << (virtual_address_bits - 1)) == 0 {
        return Err(KernelEntryStackError::NotKernelAddress);
    }

    let tss = core::ptr::addr_of_mut!(TSS);
    // SAFETY: The function contract requires initialized TSS storage; the field
    // is packed, so write without creating an aligned reference to it.
    unsafe { core::ptr::addr_of_mut!((*tss).rsp0).write_unaligned(stack_top) };
    Ok(())
}

/// Install the syscall callback for one synchronously entered user process.
///
/// # Safety
/// Local interrupts must be disabled, no other CPU may access this state, and
/// `context` must remain live until the callback is cleared after user return.
#[cfg(feature = "probe-user-process")]
pub(crate) unsafe fn install_user_syscall_handler(
    handler: UserSyscallHandler,
    exception_handler: UserExceptionHandler,
    context: *mut (),
) -> Result<(), UserRuntimeError> {
    let flags: u64;
    // SAFETY: The temporary stack operation is balanced at CPL 0.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
    if flags & (1 << 9) != 0 {
        return Err(UserRuntimeError::InterruptsEnabled);
    }
    let runtime = core::ptr::addr_of_mut!(USER_SYSCALL_RUNTIME);
    // SAFETY: IF is clear and the first implementation is single-vCPU.
    if unsafe { runtime.read() }.is_some() {
        return Err(UserRuntimeError::AlreadyInstalled);
    }
    // SAFETY: The caller keeps the function context live until clearing it.
    unsafe {
        runtime.write(Some(UserSyscallRuntime {
            handler,
            exception_handler,
            context,
        }))
    };
    // SAFETY: IF is clear and assembly reads these values only on this CPU.
    unsafe {
        core::ptr::addr_of_mut!(RUSTIX_USER_EXIT_PENDING).write(0);
        core::ptr::addr_of_mut!(RUSTIX_USER_EXIT_STATUS).write(0);
    }
    Ok(())
}

/// Remove the user-process syscall callback after returning to the kernel root.
///
/// # Safety
/// Local interrupts must be disabled, and no syscall callback may be in flight.
#[cfg(feature = "probe-user-process")]
pub(crate) unsafe fn clear_user_syscall_handler() {
    let runtime = core::ptr::addr_of_mut!(USER_SYSCALL_RUNTIME);
    // SAFETY: The API contract guarantees single-vCPU exclusion with IF clear.
    unsafe { runtime.write(None) };
}

/// Request the syscall/exception assembly exit path after restoring the kernel root.
///
/// # Safety
/// The kernel root must be active, the process root must no longer be active,
/// and execution must be on this single CPU with maskable interrupts disabled.
#[cfg(feature = "probe-user-process")]
pub(crate) unsafe fn request_user_process_exit(status: i32) {
    // SAFETY: The caller satisfies the documented ordering and single-vCPU contract.
    unsafe {
        core::ptr::addr_of_mut!(RUSTIX_USER_EXIT_STATUS).write(status);
        core::sync::atomic::compiler_fence(Ordering::Release);
        core::ptr::addr_of_mut!(RUSTIX_USER_EXIT_PENDING).write(1);
    }
}

/// Enter a validated user frame and return only through the process-exit path.
///
/// # Safety
/// The process root must already be active in CR3, TSS.RSP0 must point to a live
/// supervisor stack mapped in both roots, syscall and user-fault callbacks must
/// be installed, and maskable interrupts must be disabled.
#[cfg(feature = "probe-user-process")]
pub(crate) unsafe fn enter_user(
    frame: rustix_kernel::syscall::ValidatedUserIretFrame,
) -> Result<i32, UserRuntimeError> {
    let flags: u64;
    // SAFETY: The temporary stack operation is balanced at CPL 0.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
    if flags & (1 << 9) != 0 {
        return Err(UserRuntimeError::InterruptsEnabled);
    }
    let runtime = core::ptr::addr_of!(USER_SYSCALL_RUNTIME);
    // SAFETY: IF is clear and only this CPU can update the runtime slot.
    if unsafe { runtime.read() }.is_none() {
        return Err(UserRuntimeError::NotInstalled);
    }
    let frame = frame.into_raw();
    // SAFETY: The caller establishes the root, stack, TSS, callback, and fault
    // policy invariants. The assembly returns only after a process exit request.
    Ok(unsafe { rustix_enter_user(&frame) })
}

/// Register one callback for an allocated device IRQ vector.
///
/// # Safety
///
/// The caller must keep the IRQ source masked while registering and ensure it
/// is masked whenever this callback is dispatched. The caller must serialize
/// registration against IRQ dispatch on every CPU. `handler` must not allocate,
/// format output, block, or unwind; it runs with IF disabled and owns the EOI.
/// The source must remain masked until all handler state is ready.
#[allow(dead_code)]
pub unsafe fn register_irq_handler(
    vector: u8,
    handler: IrqHandler,
) -> Result<(), IrqRegistrationError> {
    let vector = vector as usize;
    if !(IRQ_FIRST_VECTOR..=IRQ_LAST_VECTOR).contains(&vector) {
        return Err(IrqRegistrationError::InvalidVector);
    }

    let flags: u64;
    // SAFETY: This reads RFLAGS at CPL 0; the temporary push/pop is balanced.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    if flags & (1 << 9) != 0 {
        return Err(IrqRegistrationError::InterruptsEnabled);
    }

    // SAFETY: The API contract requires registration to be serialized with IRQ
    // dispatch, and the vector has been checked against the table bounds.
    let slot = unsafe {
        core::ptr::addr_of_mut!(IRQ_HANDLERS)
            .cast::<Option<IrqHandler>>()
            .add(vector)
    };
    // SAFETY: `slot` points into the initialized static callback table.
    if unsafe { slot.read() }.is_some() {
        return Err(IrqRegistrationError::AlreadyRegistered);
    }
    // SAFETY: Registration is serialized by the caller's masking/IF contract.
    unsafe { slot.write(Some(handler)) };
    Ok(())
}

/// Device IRQ target called by the normalized assembly stubs.
#[no_mangle]
pub extern "C" fn rustix_irq_dispatch(vector: u64) {
    // SAFETY: guard records this entry frame for the heap's debug checks; it
    // decrements automatically on every return path.
    let _depth = InterruptContextGuard::enter();
    if vector == APIC_SPURIOUS_VECTOR as u64 {
        return;
    }

    if !(IRQ_FIRST_VECTOR as u64..=IRQ_LAST_VECTOR as u64).contains(&vector) {
        fatal_irq_halt();
    }

    // SAFETY: Interrupt gates clear IF, and registration's safety contract
    // serializes writes against this read. No mutable reference is created.
    let handler = unsafe {
        core::ptr::addr_of!(IRQ_HANDLERS)
            .cast::<Option<IrqHandler>>()
            .add(vector as usize)
            .read()
    };
    match handler {
        Some(handler) => handler(),
        None => fatal_irq_halt(),
    }
}

#[no_mangle]
pub extern "C" fn rustix_syscall_dispatch(context: *mut rustix_kernel::syscall::SyscallContext) {
    use rustix_kernel::syscall::{
        sanitize_user_syscall_return_frame, SyscallArguments, UserIretFrame,
    };

    // SAFETY: The assembly entry is reached only through the DPL-3 syscall gate;
    // the stack pointer refers to its normalized GPR and hardware return frame.
    let _depth = InterruptContextGuard::enter();
    let Some(context) = (unsafe { context.as_mut() }) else {
        fatal_irq_halt();
    };
    let address_bits = USER_VIRTUAL_ADDRESS_BITS.load(Ordering::Acquire);
    if address_bits == 0 {
        fatal_irq_halt();
    }
    let frame = UserIretFrame {
        instruction_pointer: context.instruction_pointer,
        code_selector: context.code_selector,
        flags: context.flags,
        stack_pointer: context.stack_pointer,
        stack_selector: context.stack_selector,
    };
    let frame = match sanitize_user_syscall_return_frame(frame, address_bits) {
        Ok(frame) => frame.into_raw(),
        Err(_) => fatal_irq_halt(),
    };
    context.instruction_pointer = frame.instruction_pointer;
    context.code_selector = frame.code_selector;
    context.flags = frame.flags;
    context.stack_pointer = frame.stack_pointer;
    context.stack_selector = frame.stack_selector;

    let arguments = SyscallArguments {
        rdi: context.rdi,
        rsi: context.rsi,
        rdx: context.rdx,
        r10: context.r10,
        r8: context.r8,
        r9: context.r9,
    };
    #[cfg(feature = "probe-user-process")]
    let result = {
        let runtime = core::ptr::addr_of!(USER_SYSCALL_RUNTIME);
        // SAFETY: IF is clear and only this CPU can update the runtime slot.
        let runtime = unsafe { runtime.read() };
        if let Some(runtime) = runtime {
            (runtime.handler)(context, runtime.context)
        } else {
            fallback_syscall_result(context.rax, arguments)
        }
    };
    #[cfg(not(feature = "probe-user-process"))]
    let result = fallback_syscall_result(context.rax, arguments);
    context.rax = result as u64;
}

fn fallback_syscall_result(
    number: u64,
    arguments: rustix_kernel::syscall::SyscallArguments,
) -> i64 {
    use rustix_kernel::syscall::{decode_syscall, SyscallError, SyscallRequest, ABI_VERSION};

    match decode_syscall(number, arguments) {
        Ok(SyscallRequest::AbiVersion) => ABI_VERSION as i64,
        Ok(
            SyscallRequest::Exit { .. }
            | SyscallRequest::Write { .. }
            | SyscallRequest::Wait { .. },
        ) => SyscallError::NotSupported.return_value(),
        Err(error) => error.return_value(),
    }
}

fn fatal_irq_halt() -> ! {
    loop {
        // SAFETY: Unknown device interrupts are fatal and must not be retried.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// Fatal exception target called by the assembly stubs.
#[no_mangle]
pub extern "C" fn rustix_exception_dispatch(context: *const ExceptionContext) -> ! {
    // SAFETY: The common assembly stub passes a pointer to its normalized stack
    // frame, which remains live for the duration of this non-returning handler.
    let context = unsafe { &*context };
    #[cfg(feature = "probe-user-process")]
    if context.cs & 3 == 3 && !matches!(context.vector, 2 | 8 | 18) {
        let runtime = core::ptr::addr_of!(USER_SYSCALL_RUNTIME);
        // SAFETY: Exceptions arrive with IF clear; the diagnostic process runtime
        // is installed only for the synchronous single-vCPU user entry.
        if let Some(runtime) = unsafe { runtime.read() } {
            let depth = InterruptContextGuard::enter();
            crate::kprintln!(
                "USER EXCEPTION: vector {} ({}) error={:#018x}; terminating process",
                context.vector,
                exception_name(context.vector),
                context.error_code
            );
            if context.vector == 14 {
                let fault_address: u64;
                // SAFETY: Reading CR2 is privileged and this handler runs at CPL0.
                unsafe {
                    asm!(
                        "mov {}, cr2",
                        out(reg) fault_address,
                        options(nomem, nostack, preserves_flags)
                    )
                };
                crate::kprintln!("user page fault address (CR2): {:#018x}", fault_address);
            }
            if (runtime.exception_handler)(context.vector, runtime.context) {
                core::sync::atomic::compiler_fence(Ordering::Acquire);
                // SAFETY: The callback's contract guarantees it has restored the
                // kernel root and marked the process root inactive before setting
                // this single-vCPU exit flag.
                if unsafe { core::ptr::addr_of!(RUSTIX_USER_EXIT_PENDING).read() } != 0 {
                    drop(depth);
                    // SAFETY: The exit callback restored CR3, completed teardown
                    // ownership transitions, and IF remains disabled. The asm
                    // trampoline restores the kernel FPU/stack continuation.
                    unsafe { rustix_user_exception_exit() };
                }
            }
        }
    }

    // SAFETY: guard records this fatal entry frame; fatal paths never return.
    let _depth = InterruptContextGuard::enter();
    // A fault raised while this handler is running (including a #DF on the
    // IST stack) must not re-enter the printing path; stop silently instead.
    if IN_FATAL_EXCEPTION.swap(true, Ordering::Acquire) {
        loop {
            // SAFETY: Re-entrant fatal diagnostics are deliberately silent.
            unsafe { asm!("cli; hlt", options(nomem, nostack)) };
        }
    }
    crate::kprintln!(
        "FATAL EXCEPTION: vector {} ({}) error={:#018x} RIP={:#018x}",
        context.vector,
        exception_name(context.vector),
        context.error_code,
        context.rip
    );
    #[cfg(feature = "fatal-register-dump")]
    crate::kprintln!(
        "CS={:#06x} SS={:#06x} RFLAGS={:#018x} RSP={:#018x}",
        context.cs,
        context.ss,
        context.rflags,
        context.rsp
    );
    #[cfg(feature = "fatal-register-dump")]
    crate::kprintln!(
        "RAX={:#018x} RBX={:#018x} RCX={:#018x}",
        context.rax,
        context.rbx,
        context.rcx
    );
    #[cfg(feature = "fatal-register-dump")]
    crate::kprintln!(
        "RDX={:#018x} RSI={:#018x} RDI={:#018x} RBP={:#018x}",
        context.rdx,
        context.rsi,
        context.rdi,
        context.rbp
    );
    #[cfg(feature = "fatal-register-dump")]
    crate::kprintln!(
        "R8={:#018x} R9={:#018x} R10={:#018x} R11={:#018x}",
        context.r8,
        context.r9,
        context.r10,
        context.r11
    );
    #[cfg(feature = "fatal-register-dump")]
    crate::kprintln!(
        "R12={:#018x} R13={:#018x} R14={:#018x} R15={:#018x}",
        context.r12,
        context.r13,
        context.r14,
        context.r15
    );

    if context.vector == 14 {
        crate::kprintln!(
            "page fault: present={} write={} user={} reserved={} instruction-fetch={}",
            context.error_code & 1 != 0,
            context.error_code & 2 != 0,
            context.error_code & 4 != 0,
            context.error_code & 8 != 0,
            context.error_code & 16 != 0
        );
        let fault_address: u64;
        // SAFETY: Reading CR2 is a privileged x86_64 operation in this handler.
        unsafe {
            asm!("mov {}, cr2", out(reg) fault_address, options(nomem, nostack, preserves_flags))
        };
        crate::kprintln!("page fault address (CR2): {:#018x}", fault_address);
    }

    loop {
        // SAFETY: Fatal exceptions are not recoverable in the current kernel.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

fn exception_name(vector: u64) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "non-maskable interrupt",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        9 => "coprocessor segment overrun",
        10 => "invalid TSS",
        11 => "segment not present",
        12 => "stack-segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating-point",
        17 => "alignment check",
        18 => "machine check",
        19 => "SIMD floating-point",
        20 => "virtualization",
        21 => "control protection",
        28 => "hypervisor injection",
        29 => "VMM communication",
        30 => "security exception",
        _ => "reserved or architecture-specific exception",
    }
}

global_asm!(
    r#"
    .section .text
    .code64

    .macro RUSTIX_ISR_NO_ERROR name, number
    .global \name
    .type \name, @function
\name:
    push 0
    push \number
    jmp rustix_exception_common
    .endm

    .macro RUSTIX_ISR_ERROR name, number
    .global \name
    .type \name, @function
\name:
    push \number
    jmp rustix_exception_common
    .endm

    RUSTIX_ISR_NO_ERROR rustix_exception_0, 0
    RUSTIX_ISR_NO_ERROR rustix_exception_1, 1
    RUSTIX_ISR_NO_ERROR rustix_exception_2, 2
    RUSTIX_ISR_NO_ERROR rustix_exception_3, 3
    RUSTIX_ISR_NO_ERROR rustix_exception_4, 4
    RUSTIX_ISR_NO_ERROR rustix_exception_5, 5
    RUSTIX_ISR_NO_ERROR rustix_exception_6, 6
    RUSTIX_ISR_NO_ERROR rustix_exception_7, 7
    RUSTIX_ISR_ERROR rustix_exception_8, 8
    RUSTIX_ISR_NO_ERROR rustix_exception_9, 9
    RUSTIX_ISR_ERROR rustix_exception_10, 10
    RUSTIX_ISR_ERROR rustix_exception_11, 11
    RUSTIX_ISR_ERROR rustix_exception_12, 12
    RUSTIX_ISR_ERROR rustix_exception_13, 13
    RUSTIX_ISR_ERROR rustix_exception_14, 14
    RUSTIX_ISR_NO_ERROR rustix_exception_15, 15
    RUSTIX_ISR_NO_ERROR rustix_exception_16, 16
    RUSTIX_ISR_ERROR rustix_exception_17, 17
    RUSTIX_ISR_NO_ERROR rustix_exception_18, 18
    RUSTIX_ISR_NO_ERROR rustix_exception_19, 19
    RUSTIX_ISR_NO_ERROR rustix_exception_20, 20
    RUSTIX_ISR_ERROR rustix_exception_21, 21
    RUSTIX_ISR_NO_ERROR rustix_exception_22, 22
    RUSTIX_ISR_NO_ERROR rustix_exception_23, 23
    RUSTIX_ISR_NO_ERROR rustix_exception_24, 24
    RUSTIX_ISR_NO_ERROR rustix_exception_25, 25
    RUSTIX_ISR_NO_ERROR rustix_exception_26, 26
    RUSTIX_ISR_NO_ERROR rustix_exception_27, 27
    RUSTIX_ISR_NO_ERROR rustix_exception_28, 28
    RUSTIX_ISR_ERROR rustix_exception_29, 29
    RUSTIX_ISR_ERROR rustix_exception_30, 30
    RUSTIX_ISR_NO_ERROR rustix_exception_31, 31

    rustix_exception_common:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    call rustix_exception_dispatch
    ud2

    .global rustix_load_gdt
    .type rustix_load_gdt, @function
rustix_load_gdt:
    lgdt [rdi]
    push 0x08
    lea rax, [rip + 2f]
    push rax
    retfq
2:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov ax, 0x18
    ltr ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    ret

    .section .rodata
    .align 8
    .global exception_stub_table
exception_stub_table:
    .quad rustix_exception_0, rustix_exception_1, rustix_exception_2, rustix_exception_3
    .quad rustix_exception_4, rustix_exception_5, rustix_exception_6, rustix_exception_7
    .quad rustix_exception_8, rustix_exception_9, rustix_exception_10, rustix_exception_11
    .quad rustix_exception_12, rustix_exception_13, rustix_exception_14, rustix_exception_15
    .quad rustix_exception_16, rustix_exception_17, rustix_exception_18, rustix_exception_19
    .quad rustix_exception_20, rustix_exception_21, rustix_exception_22, rustix_exception_23
    .quad rustix_exception_24, rustix_exception_25, rustix_exception_26, rustix_exception_27
    .quad rustix_exception_28, rustix_exception_29, rustix_exception_30, rustix_exception_31

    .section .text
    # Each IRQ entry is exactly 12 bytes: push synthetic error code, push its
    # vector as imm32, then a rel32 jump to the shared GPR-saving entry.
    .macro RUSTIX_IRQ_STUB vector
    .byte 0x6a, 0
    .byte 0x68
    .long \vector
    .byte 0xe9
    .long rustix_irq_common - . - 4
    .endm

    .global rustix_irq_stub_start
rustix_irq_stub_start:
    .set irq_vector, 0x20
    .rept 208
    RUSTIX_IRQ_STUB irq_vector
    .set irq_vector, irq_vector + 1
    .endr
    .set unwired_vector, 0xf0
    .rept 15
    RUSTIX_IRQ_STUB unwired_vector
    .set unwired_vector, unwired_vector + 1
    .endr
    .global rustix_irq_spurious_stub
rustix_irq_spurious_stub:
    RUSTIX_IRQ_STUB 0xff

    rustix_irq_common:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    # Preserve asynchronous x87/SSE state before Rust IRQ dispatch can use it.
    mov rax, qword ptr [rip + rustix_active_fpu_state_pointer]
    # A null pointer here means IRQ/FPU initialization order was broken; stop.
    test rax, rax
    jz rustix_irq_fatal_no_fx_state
    fxsave64 [rax]
    mov edi, dword ptr [rsp + 120]
    mov rbx, rsp
    and rsp, -16
    call rustix_irq_dispatch
    # A timer switch updates the active state pointer before selecting a context.
    mov rax, qword ptr [rip + rustix_active_fpu_state_pointer]
    test rax, rax
    jz rustix_irq_fatal_no_fx_state
    fxrstor64 [rax]
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

    .global rustix_syscall_stub
    .type rustix_syscall_stub, @function
rustix_syscall_stub:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    # A CPL0 software interrupt has no saved user RSP/SS; fail closed before
    # passing such a frame to Rust as the complete syscall context.
    mov rax, qword ptr [rbx + 128]
    and eax, 3
    cmp eax, 3
    jne rustix_syscall_fatal_entry
    # 15 pushed registers leave RSP 16-byte aligned from a TSS.RSP0 aligned top.
    # Keep user x87/SSE state isolated from any Rust dispatch instructions.
    sub rsp, 512
    fxsave64 [rsp]
    mov rdi, rbx
    call rustix_syscall_dispatch
    fxrstor64 [rsp]
    cmp byte ptr [rip + RUSTIX_USER_EXIT_PENDING], 0
    jne rustix_user_exit_return
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq

    .global rustix_enter_user
    .type rustix_enter_user, @function
rustix_enter_user:
    # Preserve the SysV callee-saved kernel registers and remember the exact
    # continuation stack before building the five-word privilege frame.
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov qword ptr [rip + RUSTIX_USER_RESUME_RSP], rsp
    fxsave64 [rip + RUSTIX_USER_KERNEL_FX_STATE]
    mov rbx, rdi
    push qword ptr [rbx + 32]
    push qword ptr [rbx + 24]
    push qword ptr [rbx + 16]
    push qword ptr [rbx + 8]
    push qword ptr [rbx]
    xor eax, eax
    xor ebx, ebx
    xor ebp, ebp
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq
    .size rustix_enter_user, . - rustix_enter_user

.global rustix_user_exception_exit
    .type rustix_user_exception_exit, @function
rustix_user_exception_exit:
    jmp rustix_user_exit_return

rustix_user_exit_return:
    # The handler already restored the kernel CR3 and marked the process root
    # inactive. Restore the kernel's pre-user x87/SSE state and continuation.
    fxrstor64 [rip + RUSTIX_USER_KERNEL_FX_STATE]
    mov rsp, qword ptr [rip + RUSTIX_USER_RESUME_RSP]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    mov eax, dword ptr [rip + RUSTIX_USER_EXIT_STATUS]
    mov byte ptr [rip + RUSTIX_USER_EXIT_PENDING], 0
    ret

rustix_syscall_fatal_entry:
    cli
    hlt
    jmp rustix_syscall_fatal_entry

    .global rustix_irq_fatal_no_fx_state
    .type rustix_irq_fatal_no_fx_state, @function
rustix_irq_fatal_no_fx_state:
    cli
    hlt
    jmp rustix_irq_fatal_no_fx_state

    .section .rodata
    .align 8
    .global irq_stub_table
irq_stub_table:
    .set irq_vector, 0x20
    .rept 208
    .quad rustix_irq_stub_start + ((irq_vector - 0x20) * 12)
    .set irq_vector, irq_vector + 1
    .endr
    .set unwired_vector, 0xf0
    .rept 15
    .quad rustix_irq_stub_start + ((208 + unwired_vector - 0xf0) * 12)
    .set unwired_vector, unwired_vector + 1
    .endr
    .quad rustix_irq_spurious_stub

    "#
);
