//! x86_64 execution-context switching for cooperative and preempted threads.
//!
//! The switch preserves the SysV callee-saved general-purpose registers, stack
//! pointer, and x87/SSE state. It does not save flags, caller-saved general-
//! purpose registers, control registers, or address-space state. Timer
//! preemption uses a separate entry because the IRQ stub has already saved the
//! interrupted task's x87/SSE state before calling Rust.

core::arch::global_asm!(
    ".section .text.rustix_context_switch,\"ax\"",
    ".global rustix_context_switch",
    "rustix_context_switch:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    fxsave64 [rdx]",
    "    mov [rdi], rsp",
    "    mov rsp, rsi",
    "    fxrstor64 [rcx]",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    ret",
    ".global rustix_context_switch_from_irq",
    "rustix_context_switch_from_irq:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp",
    "    mov rsp, rsi",
    "    fxrstor64 [rdx]",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    ret",
);

extern "C" {
    /// Saves the current cooperative context and resumes another one.
    ///
    /// This is a normal SysV ABI function. `old_rsp` must point to a writable,
    /// pointer-aligned slot that remains valid for as long as the saved context
    /// may be resumed. `new_rsp` must point to a valid saved frame containing
    /// six register slots followed by a return address; a fresh frame can be
    /// prepared with `scheduler::initialize_thread_context_stack`. Both stacks must remain
    /// mapped, writable, and alive while their contexts can run. Fresh frames
    /// can be built with `scheduler::initialize_thread_context_stack`.
    ///
    /// # Safety
    ///
    /// Call only from ordinary thread context with local interrupts disabled.
    /// Both contexts must run on the same CPU, at the same privilege level, with
    /// compatible mappings and valid 16-byte-aligned FXSAVE areas. The trampoline
    /// used for a fresh context must not return. No stack or FXSAVE area may be
    /// freed while its context is saved or active.
    #[link_name = "rustix_context_switch"]
    pub fn context_switch(
        old_rsp: *mut usize,
        new_rsp: *mut usize,
        old_fx_state: *mut u8,
        new_fx_state: *const u8,
    );

    /// Switch from the configured timer IRQ path after its assembly stub saved
    /// the interrupted context's FXSAVE image. Does not save the handler's FP
    /// scratch state into the interrupted context.
    ///
    /// # Safety
    /// The same context and mapping requirements as [`context_switch`] apply.
    /// Call only from the timer IRQ with IF clear and pass an aligned initialized
    /// FXSAVE area for `new_fx_state`.
    #[link_name = "rustix_context_switch_from_irq"]
    pub fn context_switch_from_irq(
        old_rsp: *mut usize,
        new_rsp: *mut usize,
        new_fx_state: *const u8,
    );
}
