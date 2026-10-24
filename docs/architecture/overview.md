# Architecture overview

## Goals

Rustix is a from-scratch operating system project with its own kernel, written in Rust. The intended initial platform is 64-bit x86 (`x86_64`), with a Unix-like process and file-descriptor model. The kernel should eventually own machine initialization, physical and virtual memory management, interrupt handling, scheduling, system calls, and device policy. A bootloader is a transport into the kernel, not a replacement for those facilities.

Unix-like is a compatibility direction. It does **not** mean the current kernel is POSIX-compliant, nor does it commit the project to a particular existing kernel's internals. Compatibility profiles and a userland should be defined only after the underlying process, descriptor, and syscall semantics are implemented and tested.

## Current implementation

1. Cargo builds a `no_std`, `no_main` ELF for `x86_64-unknown-none` and uses Limine for the boot handoff.
2. `_start` initializes COM1 and exception diagnostics, captures a validated boot snapshot and frame-allocator state, reports memory/CPU information, initializes a fixed-capacity RAM filesystem, and enters Crabshell.
3. Crabshell reads an ASCII command line from the serial UART and supports basic navigation, directory creation/listing, and text-file operations.
4. The separately packaged `crabshell` `no_std` crate parses commands without allocation or dependence on kernel I/O, making that layer reusable by a future graphical frontend.
5. The kernel library contains checked memory accounting and the bounded VFS implementation, both covered by host-side unit tests.

The current shell and filesystem run in kernel mode. Files exist only in RAM and disappear at reboot. Bootstrap GDT/TSS/IDT setup and fatal exception handlers for vectors 0–31 exist, but maskable IRQs remain disabled and exception recovery is not implemented. The active page tables are an owned clone of Limine's reachable hierarchy, and a bounded 256 KiB BSS heap is installed. There is no clean-room address-space policy, general active mapping service, frame reclamation, IRQ-safe allocation, general IRQ subsystem, scheduler, user/kernel isolation, syscall ABI, on-disk filesystem, network stack, or userspace process.

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

- **Freestanding:** kernel code does not link `std`; allocation must be introduced deliberately after a physical-frame and heap strategy exists.
- **Explicit unsafe boundaries:** raw pointers from boot protocol responses and x86 port I/O are unsafe. Each use must document its preconditions and remain short-lived.
- **Fail visibly:** early boot failures should produce serial diagnostics where possible and then halt, rather than continue with invalid machine state.
- **Checked arithmetic:** physical ranges, sizes, and address translations must reject overflow.
- **No premature ABI:** userspace interfaces stay unstable until process lifetime, error conventions, copy-in/copy-out, and versioning are designed together.
- **Hardware-independent tests:** parsing, range arithmetic, and policy should be testable as ordinary host-side Rust wherever possible.

## Boot and CPU assumptions

The current target is x86_64, with a 4 KiB page-oriented linker layout and no red zone. Limine performs the initial platform setup required by its protocol. Rustix must not assume that receiving a memory-map response means it owns the loader's page tables or can overwrite reserved regions. The current bootstrap does not enable interrupts or start application processors.

See [Boot protocol](boot.md), [Memory management](memory.md), [x86_64 drivers](drivers.md), [Crabshell](crabshell.md), and [the roadmap](../roadmap/README.md) for subsystem boundaries and planned acceptance criteria.
