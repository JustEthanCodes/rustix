# Security and unsafe-code policy

Rustix is an early kernel prototype, not a security-reviewed operating system. It has no user/kernel separation implementation, process isolation, security boundary, or supported deployment profile today.

## Current unsafe boundaries

- `src/arch/x86_64/io.rs` issues privileged x86 port-I/O instructions behind narrow driver wrappers.
- `src/arch/x86_64/serial.rs` configures and writes to the legacy COM1 UART. It is intended for early kernel context only.
- `src/arch/x86_64/keyboard.rs` reads raw bytes from a legacy PS/2-compatible controller; callers must poll without blocking.
- `src/arch/x86_64/cpu.rs` executes CPUID for boot-time feature reporting, reads CR0/CR4/CR3 without modifying them, and performs gated, read-only `RDMSR` reads of EFER.NXE, `IA32_PAT`, and supported MTRR registers. EFER and PAT reads are gated by their CPUID features; MTRR reads are skipped unless CPUID reports MTRR support and are bounded to the reported variable-register count, up to 32 pairs. These paths assume CPL 0 and architectural feature/MSR availability, and they do not write control registers or MSRs.
- `src/arch/x86_64/interrupts.rs` loads the GDT/TSS/IDT and exception-entry assembly, reads CR2 on page faults, and halts after printing the saved context. The exception gates are kernel-only and maskable interrupts remain disabled.
- `src/boot.rs` reads Limine response pointers and entries, then validates and copies range metadata into an owned boot snapshot. Nullness, alignment, count bounds, arithmetic, and range overlap are checked; the kernel still trusts Limine to make non-null response objects readable for the handoff lifetime.
- `src/main.rs` uses `cli` and `hlt` to stop the bootstrap CPU after a fatal startup error.
- `src/vfs.rs` and `src/shell.rs` provide a kernel-mode RAM filesystem and shell. They have no user/kernel isolation, permissions, persistence, or protection from kernel bugs; shell commands are trusted kernel code, not sandboxed applications.

Unsafe blocks should remain as small as practical and state the assumptions that make each operation valid. Avoid widening `unsafe impl` or introducing raw-pointer-based public APIs without a documented safety argument. The PS/2 routine consumes bytes from the controller, including discarding auxiliary/error bytes, so it must only be used by a single owner of that controller until input serialization is designed. External boot inputs, user pointers, MMIO, and DMA must not be treated as trusted merely because current boot data is trusted.

## Security requirements for future subsystems

- Validate every physical range and checked address calculation before mapping or allocating it.
- Enforce least privilege in page mappings; avoid writable-executable pages by default.
- Keep user memory untrusted and use explicit copy-in/copy-out routines at syscall boundaries.
- Define ownership and lifetime rules for descriptors, processes, shared memory, and device buffers.
- Test malformed input and error paths as well as successful operation.
- Do not claim isolation or security guarantees until those properties have end-to-end tests and review.
