# Rustix

> **Experimental operating system.** Rustix is a 64-bit, Unix-like OS project with its own Rust kernel. Limine is the external bootloader/protocol; it is not the Rustix kernel.

> **AI-assisted project:** most of this repository has been written with AI assistance. Contributions and review are welcome; please follow the project guidance in [`AGENTS.md`](AGENTS.md).

## What works today

Rustix targets `x86_64-unknown-none` and runs as a freestanding `no_std` kernel. The current implementation includes:

- Limine boot handoff validation, serial diagnostics, and an owned snapshot of selected boot metadata.
- A bounded frame allocator, cloned active page-table hierarchy, and a small frame-backed heap extension.
- Single-vCPU APIC/PIT interrupt routing, cooperative kernel tasks, timer preemption, and bounded UART/PS/2 input queues.
- A controlled Ring 3 `rustix-init` using a versioned syscall ABI. The runtime supports a limited static ELF format, up to four cooperative processes, selected descriptor operations, anonymous mappings, spawn/exec/wait/exit, and bounded user-memory copying.
- Crabshell, a kernel-mode serial development shell, with a separate allocation-free parser and a fixed-capacity volatile RAM filesystem.

These are experimental, bounded capabilities—not general-purpose userspace, POSIX compatibility, or production security guarantees. Process address spaces share supervisor-only kernel mappings derived from Limine. Persistent storage, SMP, networking, and physical-hardware validation remain outstanding. See [current status and roadmap](docs/index.md) for details and evidence.

## Quick start

The easiest setup is the repository's Dev Container, based on Ubuntu 24.04. Otherwise install the pinned Rust toolchain and `x86_64-unknown-none` target, `just`, Python 3, `xorriso`, and QEMU (`qemu-system-x86_64`). `just verify` also needs OVMF; on Linux/WSL, a C compiler is needed to build Limine's host utility. The first image build downloads the pinned Limine archive and verifies its SHA-256.

From the repository root:

```sh
just help       # list available tasks
just test       # host-side unit tests
just check      # check the freestanding target
just build      # build the kernel and bundled user payloads
just smoke      # build image and check BIOS boot
just run        # run interactively in QEMU; Ctrl+C stops the emulator
just verify     # full prescribed test/build/boot validation
```

`just image` creates the hybrid BIOS/UEFI image at `target/rustix.iso`. `just process-smoke` and `just user-fault-smoke` run additional bounded userspace lifecycle/fault probes. Refer to [Building Rustix](docs/development/building.md) for prerequisites, debug setup, and all targets, and [Testing and verification](docs/development/testing.md) for what each check does—and does not—prove.

## Exploring the system

The normal image launches the bundled init in Ring 3. Crabshell is a kernel-mode development/recovery shell, not the default userspace command interpreter. Its fixed-capacity RAM filesystem is volatile and disappears on reset. The shell supports `help`, `pwd`, `meminfo`, `ls`, `cd`, `mkdir`, `touch`, `write`, `append`, `cp`, `mv`, `cat`, `rm`, and `rmdir`.

For a userspace walkthrough and constraints, see the [userspace development guide](docs/development/userspace.md). For shell behavior and filesystem limits, see [Crabshell](docs/architecture/crabshell.md). The [syscall ABI document](docs/architecture/syscall-abi.md) is the source of truth for supported calls and their exact limits.

## Project principles

- Keep the kernel and OS implementation Rust-first and `no_std`; isolate privileged architecture code under `src/arch/`.
- Treat the kernel as the product. The bootloader transfers control; Rustix owns its policies and services.
- Keep unsafe code narrow, documented, and adjacent to its hardware or protocol boundary.
- Implement incrementally, with tests and documentation that match verified behavior.
- Treat Unix-like behavior as a compatibility goal, not a present claim of POSIX compliance.

## Where to go next

- [Documentation index](docs/index.md) — architecture, development, security, and roadmap.
- [Architecture overview](docs/architecture/overview.md) — subsystem boundaries and current design.
- [Boot protocol](docs/architecture/boot.md) and [memory management](docs/architecture/memory.md).
- [Userspace guide](docs/development/userspace.md) and [syscall ABI](docs/architecture/syscall-abi.md).
- [Security policy](docs/security.md) — trust boundaries and unsafe-code guidance.
- [Contributing](CONTRIBUTING.md) — contribution workflow.

## Repository map

- `src/main.rs`, `src/boot.rs` — kernel entry and validated boot snapshot.
- `src/paging.rs`, `src/frame.rs`, `src/heap.rs` — page tables, physical frames, and bounded heap.
- `src/process.rs`, `src/syscall.rs`, `src/elf.rs` — process preparation, ABI dispatch, and static ELF loading.
- `src/arch/x86_64/` — CPU, interrupt, APIC, serial, keyboard, context-switch, and port-I/O code.
- `src/shell.rs`, `src/vfs.rs`, `crates/crabshell/` — kernel shell, volatile RAM filesystem, and parser crate.
- `crates/rustix-user/`, `crates/rustix-init/` — userspace syscall wrappers and bundled init payload.
- `justfile`, `scripts/boot.py`, `limine.conf`, `linker.ld` — development tasks, image workflow, boot configuration, and ELF layout.
