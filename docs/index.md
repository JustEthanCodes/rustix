# Rustix documentation

Rustix is a 64-bit, Rust-first, Unix-like operating-system project. This index separates current implementation facts from planned interfaces: roadmap items are proposals until the corresponding code and tests exist.

## Start here

- [Project and implementation overview](architecture/overview.md)
- [Boot protocol and current entry path](architecture/boot.md)
- [Memory-management direction](architecture/memory.md)
- [x86_64 drivers and hardware boundary](architecture/drivers.md)
- [Crabshell and the volatile RAM filesystem](architecture/crabshell.md)
- [Unix-like process and syscall direction](architecture/syscall-abi.md)
- [Build and toolchain guide](development/building.md)
- [Testing and verification](development/testing.md)
- [Security and unsafe-code policy](security.md)
- [Milestones and acceptance criteria](roadmap/README.md)

## Current status

The repository contains a bare-metal `no_std` Rust kernel for `x86_64-unknown-none`. After Limine handoff it validates and copies memory-map metadata into an owned snapshot, reports baseline CPUID features, seeds a volatile RAM filesystem, and runs Crabshell over the COM1 serial console. Crabshell's allocation-free parser is a separate crate; the kernel handles command execution. On 2026-10-16, `just verify` passed in WSL2 Ubuntu 24.04 for the current working tree, including image creation and a bounded QEMU boot to the shell prompt; the serial log showed memory-map and CPU reporting. A separate interactive QEMU session exercised `help`, `ls`, `meminfo`, directory navigation, and file create/write/append/read/copy/move/remove commands. A clean-checkout run with uncached build/tool state and a CI run remain pending. This is a kernel-mode shell, not a user process. A bounded physical-frame allocator core is initialized from the validated map and reported by `meminfo`, but no kernel service allocates or maps frames yet; there is not yet page-table management, a heap, a general IRQ subsystem, a scheduler, process isolation, a persistent filesystem, or a Unix compatibility layer. Fatal CPU exceptions have basic GDT/TSS/IDT diagnostics but no recovery or fault-injection tests yet.

## Documentation conventions

- **Implemented** means present in the repository and checked by current code or tests.
- **Planned** means an architectural direction, not a stable ABI or delivered capability.
- Any future ABI proposal must state versioning, error behavior, memory ownership, and compatibility expectations before it is treated as stable.
