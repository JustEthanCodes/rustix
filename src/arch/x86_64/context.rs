//! Cooperative x86_64 execution-context switching.
//!
//! The switch preserves the SysV callee-saved general-purpose registers and
//! stack pointer only. It does not save flags, caller-saved registers, SIMD/FPU
//! state, control registers, or address-space state.

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
    "    mov [rdi], rsp",
    "    mov rsp, rsi",
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
    /// Call only from ordinary cooperative thread context, never from an
    /// interrupt or exception handler. Both contexts must run on the same CPU,
    /// at the same privilege level, with compatible mappings and machine state.
    /// Callers must separately preserve any FPU/SIMD or other state required by
    /// their context policy. The trampoline used for a fresh context must not
    /// return. No stack may be freed while it is saved or active.
    #[link_name = "rustix_context_switch"]
    pub fn context_switch(old_rsp: *mut usize, new_rsp: *mut usize);
}
