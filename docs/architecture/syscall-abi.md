# Unix-like process and syscall direction

**Status: design direction only. No process, syscall, or userland support is implemented.**

Rustix aims to expose a small, versioned syscall surface that can support Unix-like processes and tools. The kernel must own this interface rather than inherit an ABI accidentally from a bootloader or emulator.

## Proposed compatibility principles

- Processes have independent virtual address spaces and explicit lifecycle states.
- File descriptors are per-process integer handles to kernel-managed objects; descriptor inheritance, close-on-exec, duplication, and sharing semantics must be specified together.
- Syscalls use one documented error convention and stable numeric identifiers. New operations must not silently repurpose old numbers.
- Arguments crossing privilege boundaries are copied or validated using narrowly scoped helpers. User memory is never dereferenced as a trusted Rust reference.
- Blocking, interruption, cancellation, and restart behavior are explicit for each syscall class.
- A compatibility layer (for example, POSIX-shaped libc behavior) remains separate from internal kernel APIs.

## ABI questions to settle before implementation

1. Register convention and syscall-entry mechanism for the selected x86_64 execution mode.
2. ABI version discovery and compatibility guarantees.
3. Error encoding and a complete initial syscall-number allocation.
4. Pointer/length validation, partial reads/writes, and copy-fault behavior.
5. Process creation and execution semantics, including file actions and inherited descriptors.
6. Signal-like asynchronous delivery, interruption, and restart semantics.
7. Time, clocks, and structure layout rules.

## Suggested first user-visible slice

After address spaces, scheduler, and storage primitives exist, implement a controlled `init` process with a small syscall subset: process exit, read/write through descriptors, open/close, and wait. Add end-to-end tests for invalid pointers, partial transfers, descriptor lifetime, process exit status, and ABI version negotiation before describing it as Unix-compatible.
