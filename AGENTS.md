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
- A validated, fixed-capacity boot memory-map snapshot, CPUID/address-width reporting, read-only CR0 caching-mode reporting, and gated read-only EFER.NXE/IA32_PAT/MTRR reporting.
- A fixed-capacity physical frame allocator retained in `BootInfo`; Crabshell's `meminfo` command reports counts. The opt-in `probe-hhdm-frame` QEMU feature allocates, validates, writes, reads, clears, and returns one `Usable` frame through Limine's HHDM contract. `src/paging.rs` has a bounded candidate-root builder that owns allocator-issued table/leaf tokens and maps/unmaps 4 KiB leaves transactionally. The default boot path clones and activates the full reachable inherited hierarchy, hardens kernel-image HHDM aliases to R/NX or RW/NX while preserving PAT bits, and retains the active table tokens. A 256 KiB BSS-backed global heap is installed; it has fixed capacity and does not grow from frames.
- Pure 4 KiB mapping-range validation, leaf-PTE bit encoding, PAT layout parsing, and host-tested MTRR/PAT policy in `src/paging.rs`; these helpers check alignment, address widths, canonical virtual ranges, W^X, NXE input, PAT indices, captured-register validity, MTRR overlap rules, and Intel SDM Table 11-7 effective types under normal caching. Discontinuous variable-MTRR masks are explicitly unsupported. A pure selector chooses a PAT index only when its effective type remains uniform across all MTRR boundaries in an aligned physical range, and range-bound selected attributes can encode 4 KiB leaves. The bounded candidate builder stores its unique mutable table-memory backend borrow, uses allocator-issued `Frame` tokens for table pages and leaf mappings, restricts walks to owned tables, and rolls back failures. Active candidates reject mutation and release. Boot captures CR0 caching mode, EFER.NXE, `IA32_PAT`, and a bounded MTRR snapshot read-only when supported, validates the captured state, and reports a diagnostic PA 0 resolution. QEMU checks the requested 256 KiB stack, active CR3 clone, kernel-image HHDM alias permissions/cache preservation, and heap allocation behavior; the old root and its leaf frames are not reclaimed.
- Bootstrap GDT/TSS/IDT setup and fatal exception handlers for vectors 0–31. Double faults use an IST stack and page faults report CR2. Opt-in QEMU tests inject a page fault and invalid opcode and verify diagnostics plus fatal halt; maskable IRQs remain disabled and exceptions are not recoverable.

Important incomplete work:

- Milestone 0's local exit criteria were met on 2026-10-16: `just verify` passed from both the working tree and a clean detached worktree in WSL2 Ubuntu 24.04. The detached worktree had an empty `target` directory, so the run exercised fresh Limine download/host-tool compilation, formatting, 19 host tests, target check, optimized build, image creation, and the 20-second QEMU prompt smoke test. Hosted CI has not been observed.
- A separate interactive `just run` session exercised directory navigation and create/write/append/read/copy/move/list/remove operations; `cp` replaced an existing destination, `rmdir` rejected a nonempty directory and succeeded after its child was removed, and unsupported `memtest` was rejected as expected. Boot snapshot tests and QEMU boot-metadata reporting were exercised. Structural checks still cannot prove that a Limine-provided non-null pointer is mapped or readable; that remains a loader trust boundary.
- Milestone 2's local exit criteria were met on 2026-10-24 after final review and successful `just verify`, `just frame-smoke`, and `just fault-smoke` runs. The frame allocator specifies token ownership and preserves the token on failed deallocation; unique allocator-instance use is still caller-enforced. The active root is an allocator-owned clone of Limine's reachable hierarchy, with critical translations checked, kernel-image HHDM aliases set R/NX or RW/NX while PAT bits are preserved, and CR3 transitions flushing the current translations and global entries when PGE is enabled. QEMU exercised the PGE-clear CR3 reload path; the PGE-toggle path is statically reviewed but not exercised by this configuration. QEMU also exercised the 256 KiB requested stack, fixed BSS heap alignment/reuse/exhaustion, frame probes, and fatal page-fault/invalid-opcode paths. Host tests cover clone/table ownership, huge-page splitting, active-state guards, frame rollback, and heap behavior. Hosted CI and physical-hardware validation remain unobserved. The old root and inherited leaf frames are retained; there is no clean-room address-space policy, active general mapping service, frame reclamation, or IRQ-safe heap path.
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
- `src/memory.rs` — allocation-free memory-map, address-width, canonical-address, Limine HHDM-range, and linker-defined kernel segment validation.
- `src/frame.rs` — bounded physical-frame allocator core; it only uses validated `Usable` ranges, reserves the first MiB, and has fixed range metadata.
- `src/paging.rs` — checked mapping/cache policy, inherited page-table walking, and a bounded candidate-root builder. The default boot path activates a cloned hierarchy and retains its owned table tokens; the HHDM backend accesses only complete allocator-owned `Usable` frames after checked address derivation.
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
- A `Frame` is a physical address, not a dereferenceable pointer. HHDM access is allowed only through checked full-frame token-based paths that rely on the documented Limine contract; never access arbitrary physical addresses. Do not change CR3 until a complete, reviewed transition mapping policy and ownership proof exist.
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

<!-- entire-agent:begin -->
Read .entire/agent-guide.md for this repository's workflow, source inspection, and verification guidance.
@.entire/agent-guide.md
<!-- entire-agent:end -->
