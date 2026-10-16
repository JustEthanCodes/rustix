# Rustix agent instructions

These instructions apply to every coding agent working in this repository. Read this file before changing code. For the architecture and detailed subsystem contracts, use the linked documents under `docs/`; this file summarizes the rules agents must preserve.

## Project mission

Rustix is an experimental 64-bit, Unix-like operating system with its own Rust kernel. Limine is the external boot protocol/loader only. Do not describe Limine, a host shell, or a userspace project as the Rustix kernel.

The kernel is `no_std` and targets `x86_64-unknown-none`. Rust is the implementation language for kernel and OS components. The repository currently uses a Python standard-library script only to assemble and smoke-test the boot image; it does not replace kernel or OS functionality.

Unix-like behavior is a long-term design goal, not a claim of POSIX compatibility. Make unsupported behavior explicit rather than approximating it silently.

## Current project status — read before planning

The source contains:

- A Limine-based x86_64 kernel entry, linker layout, serial diagnostics, and boot-memory reporting.
- A separate allocation-free `no_std` `crabshell` parser crate and a kernel-mode COM1 shell frontend.
- A volatile, fixed-capacity RAM filesystem used by the shell.
- A validated, fixed-capacity boot memory-map snapshot and baseline CPUID reporting.
- A fixed-capacity physical frame allocator retained in `BootInfo`; Crabshell's `meminfo` command reports counts. No kernel service currently allocates frames for mappings or other services.
- Bootstrap GDT/TSS/IDT setup and fatal exception handlers for vectors 0–31. Double faults use an IST stack and page faults report CR2. Maskable IRQs remain disabled; exception recovery and fault-injection tests are not implemented.

Important incomplete work:

- `just verify` passed for the current working tree in WSL2 Ubuntu 24.04 on 2026-10-16: formatting, 19 host tests, target check, optimized build, image creation, and the 20-second QEMU prompt smoke test. A separate interactive `just run` session exercised directory navigation and create/write/append/read/copy/move/list/remove operations; `cp` replaced an existing destination, `rmdir` rejected a nonempty directory and succeeded after its child was removed, and unsupported `memtest` was rejected as expected. A clean-checkout run with an uncached build/tool state and a CI run remain outstanding.
- The boot snapshot tests and QEMU boot-metadata reporting path have now been exercised. Structural pointer checks still cannot prove that a Limine-provided non-null pointer is mapped or readable; that remains a loader trust boundary.
- Milestone 2 is **in progress**, not complete. Rustix still inherits Limine's page tables; it has no kernel-owned page-table manager, no heap, and no live frame-allocation callers. The descriptor setup reaches the shell in QEMU, but exception handlers have not had fault-injection testing.
- There is no scheduler, userspace, syscall ABI, persistent filesystem, user/kernel isolation, or general IRQ subsystem.

Never advance status or check off a roadmap item merely because source code or an interface exists. Update `docs/roadmap/README.md` only to reflect implementation and validation actually achieved.

## Source-of-truth documents

Consult the relevant documentation before modifying a subsystem:

- [`docs/index.md`](docs/index.md) — documentation entry point and current status.
- [`docs/roadmap/README.md`](docs/roadmap/README.md) — milestone sequencing and exit criteria.
- [`docs/architecture/overview.md`](docs/architecture/overview.md) — current architecture and intended layers.
- [`docs/architecture/boot.md`](docs/architecture/boot.md) — Limine requests, boot snapshot, and trust boundary.
- [`docs/architecture/memory.md`](docs/architecture/memory.md) — memory ownership, frame allocator, and paging direction.
- [`docs/architecture/crabshell.md`](docs/architecture/crabshell.md) — parser/kernel boundary and shell/VFS contract.
- [`docs/architecture/drivers.md`](docs/architecture/drivers.md) — current driver scope and limitations.
- [`docs/security.md`](docs/security.md) — unsafe boundaries and security policy.
- [`docs/development/building.md`](docs/development/building.md) and [`docs/development/testing.md`](docs/development/testing.md) — supported commands and validation expectations.

When code and documentation disagree, inspect the implementation, resolve the discrepancy deliberately, and update the relevant documentation in the same change.

## Repository map

- `src/main.rs` — freestanding entry, boot snapshot acquisition, panic path, and shell handoff.
- `src/boot.rs` — mutable Limine requests, structural response/range validation, owned `BootInfo`, and boot diagnostics.
- `src/memory.rs` — allocation-free memory-map validation and known/unknown region classification.
- `src/frame.rs` — bounded physical-frame allocator core; it only uses validated `Usable` ranges, reserves the first MiB, and has fixed range metadata.
- `src/shell.rs` — serial line editor and kernel-side Crabshell executor.
- `src/vfs.rs` — fixed-capacity volatile RAM filesystem and host-side tests.
- `crates/crabshell/` — separate `no_std` parser crate. It has no terminal, filesystem, or kernel dependencies.
- `src/arch/x86_64/serial.rs` — polling COM1 driver for shell input/output.
- `src/arch/x86_64/interrupts.rs` — bootstrap GDT/TSS/IDT, assembly stubs, and fatal exception diagnostics.
- `src/arch/x86_64/cpu.rs` — CPUID identification and selected feature reporting.
- `src/arch/x86_64/keyboard.rs` — raw, non-blocking PS/2-compatible scancode polling; not an input subsystem.
- `src/arch/x86_64/io.rs` — narrow port-I/O wrappers.
- `linker.ld`, `.cargo/config.toml`, `rust-toolchain.toml` — target, linker, and toolchain configuration.
- `limine.conf`, `scripts/boot.py` — boot configuration and pinned image/emulator workflow.
- `justfile` — supported development commands.
- `.github/workflows/ci.yml` — CI validation workflow.

## Engineering rules

### Keep changes incremental and coherent

1. Inspect the relevant source, tests, docs, and call sites before editing.
2. State assumptions, invariants, and failure behavior for new kernel interfaces.
3. Prefer small vertical slices that compile and can be tested over broad scaffolding or placeholder APIs.
4. Update tests and documentation alongside behavior changes.
5. Do not change unrelated code, rename files gratuitously, add speculative features, or rewrite project history.
6. Do not commit or create branches unless the user explicitly asks.

### Rust and dependency policy

- Preserve the kernel's `no_std`/freestanding constraints. Do not introduce `std` into kernel code.
- Prefer `core` and existing in-tree abstractions. Do not add third-party Rust dependencies without a concrete need and compatibility/security review.
- Keep the Crabshell parser independent of kernel I/O and VFS implementation. Kernel execution belongs in `src/shell.rs` or an appropriate kernel service.
- Do not add allocation-dependent APIs before a real heap exists. Fixed-capacity structures must document their limits and exhaustion behavior.
- Respect the workspace structure and the host-testable `rustix-kernel` library versus freestanding `rustix` binary boundary.

### Unsafe and hardware code

Unsafe code is expected only at explicit hardware, boot-protocol, assembly, or raw-memory boundaries. Keep each unsafe block narrow and document the invariant that makes it sound. Do not add broad `unsafe impl`, mutable global references, unchecked pointer arithmetic, or unreviewed inline/global assembly.

Before changing boot or memory code, account for these facts:

- Limine fills response pointers before `_start`; the request records must remain writable in the ELF image.
- Rustix validates nullness, alignment, counts, arithmetic, and physical ranges, but cannot prove that a non-null bootloader pointer is readable.
- Physical ranges are half-open `[start, end)` and must use checked arithmetic.
- Only regions classified `Usable` may enter the frame allocator. ACPI, bootloader-reclaimable, framebuffer, reserved, unknown, and other types are not free frames.
- A `Frame` is a physical address, not a dereferenceable pointer. Do not access it through the HHDM or change CR3 until an explicit, reviewed mapping policy and ownership proof exist.
- The kernel currently inherits Limine's page tables. Do not casually replace or mutate them: preserve the executing kernel, boot stack, `BootInfo`, request/response data, exception stacks, and mappings needed to continue execution.
- The exception setup is fatal-only. It does not enable maskable interrupts, configure a PIC/APIC, or provide recovery. Do not call `sti` or claim interrupt support without an IRQ design and tests.
- The shell and VFS run in ring 0 and are not isolated or secure.

For hardware changes, document assumptions about CPU mode, selectors, stacks, page permissions, interrupt state, and failure handling. Avoid new architecture mechanisms that cannot be statically reviewed or validated.

### Shell and filesystem contract

- Crabshell is presently a kernel-mode serial shell, not a userspace program or a POSIX shell.
- Its parser is a separate `no_std`, allocation-free crate; retain that boundary.
- The RAM filesystem is volatile and bounded. Preserve explicit errors and test capacity, path, and mutation edge cases.
- Do not imply persistence, permissions, links, process launching, or shell features that do not exist.
- Update the parser tests and `docs/architecture/crabshell.md` when adding or changing commands.

## Validation workflow

Run the narrowest relevant checks first, then broaden them. From the repository root, the supported commands are:

```sh
just fmt
just test
just check
just build
just image
just smoke
just verify
```

`just test` runs host-side library tests (memory-map validation, frame allocator, VFS, and Crabshell parser). `just check` checks `x86_64-unknown-none`; `just build` links the optimized ELF. `just verify` includes formatting, host tests, target check, pinned Limine image creation, and QEMU prompt smoke test. Image/boot checks need Python, `xorriso`, QEMU, the Rust target, and network access for the first pinned Limine download; Linux/WSL also needs `cc` to build Limine's host utility.

For changes to `src/main.rs`, `src/boot.rs`, linker/request configuration, `src/arch/x86_64/`, `src/frame.rs`, or paging/heap code, the intended full validation is `just verify`. If the environment does not permit a check, report the exact blocker and leave the corresponding roadmap criterion pending.

Do not claim a check passed unless it was run and its successful result was observed. Editor diagnostics are useful but are not a substitute for `cargo test`, a target build, or QEMU. A target check is not a final link; a linked ELF is not proof of boot; a prompt smoke test is not proof of interactive shell behavior or physical-hardware correctness.

## Completion criteria for agent changes

Before reporting work complete:

- Ensure source, tests, docs, and call sites agree.
- Review unsafe and hardware assumptions, including error paths and capacity limits.
- Run appropriate formatting/tests/build/boot checks, or clearly state why they could not run.
- Report files changed, behavior delivered, validation actually observed, and remaining risks.
- Keep milestone status accurate. A subsystem is not complete just because it has code.
