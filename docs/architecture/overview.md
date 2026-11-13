# Architecture overview

## Goals

Rustix is a from-scratch operating system project with its own kernel, written in Rust. The intended initial platform is 64-bit x86 (`x86_64`), with a Unix-like process and file-descriptor model. The kernel should eventually own machine initialization, physical and virtual memory management, interrupt handling, scheduling, system calls, and device policy. A bootloader is a transport into the kernel, not a replacement for those facilities.

Unix-like is a compatibility direction. It does **not** mean the current kernel is POSIX-compliant, nor does it commit the project to a particular existing kernel's internals. Compatibility profiles and a userland should be defined only after the underlying process, descriptor, and syscall semantics are implemented and tested.

## Current implementation

1. Cargo builds a `no_std`, `no_main` ELF for `x86_64-unknown-none` and uses Limine for the boot handoff.
2. `_start` initializes COM1 and exception diagnostics, captures a validated boot snapshot and frame-allocator state, activates a clone of Limine's page tables, configures the validated single-vCPU APIC/PIT path, installs bounded heap growth, and starts the shell runtime when timer and UART IRQ setup succeed.
3. Crabshell reads an ASCII command line from COM1's bounded IRQ queue and blocks cooperatively while idle; polling remains fallback. It supports basic navigation, directory creation/listing, and text-file operations.
4. The separately packaged `crabshell` `no_std` crate parses commands without allocation or dependence on kernel I/O, making that layer reusable by a future graphical frontend.
5. The kernel library contains checked memory accounting, bounded ACPI/IRQ/time/input/scheduler policies, heap tests, and the bounded VFS implementation, covered by host-side tests.

The shell and filesystem run in kernel mode. Files exist only in RAM and disappear at reboot. Bootstrap exceptions remain fatal-only; selected timer/UART/PS/2 IRQ routes are enabled after APIC, IDT, and handler setup. The single-vCPU scheduler supports cooperative waits/yields and PIT-driven preemption; IRQ-safe locking protects the global heap, while IRQ/exception allocation remains prohibited. Timer context switches preserve x87/SSE state with per-context FXSAVE areas. The active page tables are an owned clone of Limine's reachable hierarchy, with bounded active mapping and a global heap consisting of a 256 KiB BSS arena plus up to 1 MiB of frame-backed growth. There is no clean-room address-space policy, general-purpose MMIO/mapping policy, frame reclamation, SMP, user/kernel isolation, syscall ABI, on-disk filesystem, network stack, or userspace process.

## Intended layers (planned)

```text
User programs and system utilities
        | versioned syscall ABI
Kernel services: processes, descriptors, VFS, IPC, signals
        | explicit ownership and authorization checks
Core kernel: scheduler, virtual memory, physical frames, interrupts
        | narrow architecture abstractions
x86_64 platform: paging, exceptions, timers, AP startup, drivers
        | Limine boot handoff only
Firmware and hardware
```

The diagram is a target decomposition, not a claim that those layers are implemented. Architecture-independent policy should live in safe Rust where possible; privileged instructions and raw device access should stay in small, reviewed architecture modules.

## Design constraints

- **Freestanding:** kernel code does not link `std`; global allocation is bounded, frame-backed growth is explicit, and allocation is forbidden in IRQ/exception context.
- **Explicit unsafe boundaries:** raw pointers from boot protocol responses and x86 port I/O are unsafe. Each use must document its preconditions and remain short-lived.
- **Fail visibly:** early boot failures should produce serial diagnostics where possible and then halt, rather than continue with invalid machine state.
- **Checked arithmetic:** physical ranges, sizes, and address translations must reject overflow.
- **No premature ABI:** userspace interfaces stay unstable until process lifetime, error conventions, copy-in/copy-out, and versioning are designed together.
- **Hardware-independent tests:** parsing, range arithmetic, and policy should be testable as ordinary host-side Rust wherever possible.

## Boot and CPU assumptions

The current target is x86_64, with a 4 KiB page-oriented linker layout and no red zone. Limine performs the initial platform setup required by its protocol. Rustix must not assume that receiving a memory-map response means it owns the loader's page tables or can overwrite reserved regions. The bootstrap enables only validated single-vCPU APIC routes after their handlers and EOI paths are ready; it does not start application processors. Timer preemption is enabled only after the scheduler runtime is live.

See [Boot protocol](boot.md), [Memory management](memory.md), [x86_64 drivers](drivers.md), [Crabshell](crabshell.md), and [the roadmap](../roadmap/README.md) for subsystem boundaries and planned acceptance criteria.
