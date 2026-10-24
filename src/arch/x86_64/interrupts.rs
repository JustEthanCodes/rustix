//! Bootstrap GDT, TSS, and fatal exception diagnostics for x86_64.
//!
//! Hardware interrupts remain disabled. This installs exception gates only; it
//! does not initialize a PIC/APIC, enable IRQs, or provide recoverable faults.

use core::arch::{asm, global_asm};
use core::mem::size_of;

const EXCEPTION_COUNT: usize = 32;
const KERNEL_CODE_SELECTOR: u16 = 0x08;
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

static mut GDT: [u64; 5] = [0; 5];
static mut IDT: IdtTable = IdtTable([IdtEntry::MISSING; 256]);
static mut TSS: TaskStateSegment = TaskStateSegment::EMPTY;
static mut RING0_STACK: Stack = Stack([0; STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; STACK_SIZE]);

#[repr(C)]
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
}

const _: [(); 16] = [(); size_of::<IdtEntry>()];
const _: [(); 4096] = [(); size_of::<IdtTable>()];
const _: [(); 104] = [(); size_of::<TaskStateSegment>()];
const _: [(); 160] = [(); size_of::<ExceptionContext>()];

extern "C" {
    static exception_stub_table: [usize; EXCEPTION_COUNT];
    fn rustix_load_gdt(descriptor_table_pointer: *const DescriptorTablePointer);
}

/// Install a private kernel GDT/TSS and exception gates for vectors 0–31.
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
    }

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<[u64; 5]>() - 1) as u16,
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

    let idtr = DescriptorTablePointer {
        limit: (size_of::<IdtTable>() - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: Every architectural exception gate is initialized in static storage.
    unsafe { asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags)) };
}

/// Fatal exception target called by the assembly stubs.
#[no_mangle]
pub extern "C" fn rustix_exception_dispatch(context: *const ExceptionContext) -> ! {
    // SAFETY: The common assembly stub passes a pointer to its normalized stack
    // frame, which remains live for the duration of this non-returning handler.
    let context = unsafe { &*context };
    crate::kprintln!(
        "KERNEL EXCEPTION: vector {} ({}) error={:#018x} RIP={:#018x}",
        context.vector,
        exception_name(context.vector),
        context.error_code,
        context.rip
    );
    crate::kprintln!(
        "CS={:#06x} RFLAGS={:#018x} RAX={:#018x} RBX={:#018x} RCX={:#018x}",
        context.cs,
        context.rflags,
        context.rax,
        context.rbx,
        context.rcx
    );
    crate::kprintln!(
        "RDX={:#018x} RSI={:#018x} RDI={:#018x} RBP={:#018x}",
        context.rdx,
        context.rsi,
        context.rdi,
        context.rbp
    );
    crate::kprintln!(
        "R8={:#018x} R9={:#018x} R10={:#018x} R11={:#018x}",
        context.r8,
        context.r9,
        context.r10,
        context.r11
    );
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
    "#
);
