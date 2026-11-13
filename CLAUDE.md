# Claude Code instructions for Rustix

These are project-specific instructions for Claude Code and Claude-based agents working in this repository. `AGENTS.md` is the canonical shared engineering contract; read and follow it together with this file. If advice conflicts, preserve the stricter Rustix safety and validation rule, and do not infer that an unfinished subsystem is complete.

## What this repository is

Rustix is an experimental 64-bit Unix-like operating system with its own Rust kernel. The kernel is `no_std` and targets `x86_64-unknown-none`. Limine is only the external boot protocol/loader. Do not conflate the loader with Rustix or describe a host tool as the kernel.

The project is deliberately staged. Rustix currently boots to a kernel-mode Crabshell over COM1, with bounded IRQ input and a volatile RAM filesystem. A single-vCPU runtime supports cooperative waits/yields and timer preemption; this is not a userspace terminal, persistent filesystem, secure shell, or POSIX implementation. The `crabshell` workspace crate parses commands only; kernel I/O and filesystem operations remain in the kernel.

## Status must stay honest

Before planning a task, read `docs/roadmap/README.md` and the relevant architecture document. Milestones 0–3 have met their documented local exit criteria; the source includes:

- A Limine handoff and fixed-capacity owned boot snapshot with structural validation, CPUID/address-width reporting, and a classified memory map.
- A bounded physical-frame allocator, cloned active page-table hierarchy, kernel-image HHDM permission hardening, and a fixed BSS heap with bounded frame-backed growth.
- Bootstrap GDT/TSS/IDT and fatal exception stubs for vectors 0–31; double faults use an IST stack, and page faults report CR2/error bits.
- A validated single-vCPU xAPIC/I/O APIC path with masked-first IRQ routes, PIT ticks, EOI handling, and bounded UART/PS/2 IRQ input.
- A single-vCPU thread runtime with cooperative waits/yields and timer preemption, plus a separate allocation-free Crabshell parser and bounded volatile RAM filesystem.

Important limitations:

- Milestone 0–3 validation evidence is documented in `AGENTS.md` and `docs/roadmap/README.md`; it does not validate uncommitted changes in the current working tree.
- Structural boot checks cannot prove that a non-null Limine pointer is readable; the loader trust boundary remains.
- Scheduling is single-vCPU with cooperative waits/yields and timer preemption. There is no SMP, userspace, syscall ABI, persistent storage, user/kernel isolation, or general-purpose device model.
- Exceptions remain fatal-only. The shell and VFS run in ring 0 and are not isolated or secure.

Do not check off roadmap criteria merely because code or an interface exists. Only report builds, tests, and emulator checks that you actually ran and observed passing.

## Required workflow

1. Read `AGENTS.md`, the relevant `docs/architecture/*.md` document, and the actual implementation/call sites before changing code.
2. Identify the subsystem boundary and failure behavior. For hardware work, state assumptions about privilege level, selectors, page mappings, stack state, and IF/interrupt state before coding.
3. Make the smallest coherent vertical change. Prefer tested architecture-independent helpers in `src/lib.rs` modules over untestable freestanding-only logic when that preserves the design.
4. Add or update tests for normal, boundary, malformed, and exhaustion cases. Keep parser tests in `crates/crabshell`; do not make that crate depend on kernel facilities.
5. Update the relevant architecture, testing, security, and roadmap docs in the same change.
6. Run the narrow validation first, then the broader check appropriate to the touched paths.
7. In the final summary, distinguish implementation from verification and list any environmental blocker or remaining risk.

Do not commit, create branches, run broad formatting rewrites, or modify unrelated files unless explicitly requested.

## Rustix implementation rules

### `no_std` and fixed capacity

- Kernel code must remain freestanding and `no_std`; use `core`, not `std`.
- Avoid new Rust dependencies unless there is a concrete need and compatibility/security review.
- The global heap is bounded: a 256 KiB BSS arena plus up to 1 MiB of frame-backed growth. Allocation remains forbidden in IRQ/exception context; prefer fixed-capacity interfaces for core paths.
- Fixed-capacity tables must document capacity, exhaustion behavior, and whether an error leaves state unchanged.
- The kernel binary is not the host test target. Keep pure logic in the `rustix-kernel` library where practical.

### Boot, memory, and physical frames

- Limine writes response pointers before `_start`; response-bearing request records and their linker section must remain writable to the loader.
- Validate pointer nullness/alignment/counts and checked arithmetic, but preserve the documented trust boundary: Rustix cannot prove a loader pointer is mapped and readable.
- All physical ranges are half-open `[start, end)`. Use checked arithmetic and reject overlaps rather than silently normalizing malformed maps.
- Only `RegionKind::Usable` ranges feed the frame allocator. Reserved, ACPI, loader-reclaimable, framebuffer, bad, executable/module, and unknown ranges are never ordinary free frames.
- A frame handle represents a physical address; it is not a pointer. Do not dereference it, add the HHDM offset and assume success, or change CR3 until a reviewed mapping policy proves the access and ownership.
- The active root is an allocator-owned clone of Limine's reachable hierarchy. Any future replacement must preserve the executing kernel, boot stack, `BootInfo`, request/response objects, GDT/TSS/IDT data, exception stacks, and all mappings needed for continued execution.
- The current allocator is bounded and single-owner/single-core. It is not a page-table manager, heap, or concurrent allocator.

### x86_64 and exceptions

- Keep privileged instructions, port I/O, assembly, and raw pointer operations in narrow architecture modules with nearby safety comments.
- Exception handling remains fatal-only. The validated single-vCPU APIC path enables only configured, registered routes after IRQ dispatch and EOI setup. Timer preemption saves/restores x87/SSE state with FXSAVE/FXRSTOR; AVX/XSAVE remains disabled.
- Do not broaden IRQ use, add exception recovery, or add SMP without an explicit design, ownership/locking rules, fault injection, and emulator validation.
- When editing `src/arch/x86_64/interrupts.rs`, review normalized CPU-error-code stack layout, register-save ordering, stack alignment before calling Rust, the double-fault IST, descriptor selectors, and fatal behavior. Assembly diagnostics are not a substitute for assembling/linking the target.
- `CPUID` support bits do not prove a feature is enabled in control registers or active page tables. Label reports as supported/capable unless activation is verified.

### Crabshell and VFS

- The parser crate may contain syntax/model types, but no terminal, VFS, kernel, or hardware I/O.
- Kernel command execution belongs in `src/shell.rs`; the fixed-capacity VFS contract belongs in `src/vfs.rs`.
- RAM filesystem contents disappear on reset. Preserve explicit errors, root protection, directory rules, path limits, node limits, and file-size limits.
- When adding/changing a command, update parser behavior/tests, shell execution/help, `docs/architecture/crabshell.md`, and user-facing examples as appropriate.

## Supported validation

Run these from the repository root using `just`:

```sh
just fmt
just test
just check
just build
just image
just smoke
just verify
```

`just test` runs host tests for ACPI parsing, paging and mapping policy, frame allocation, heap, IRQ/time/input/scheduler policy, VFS, and Crabshell parsing. `just check` type-checks `x86_64-unknown-none`; `just build` links the release ELF. `just verify` covers formatting, host tests, target check, pinned Limine image creation, BIOS/OVMF boot, active-map, cooperative-thread, and UART/PS/2 input QEMU smokes. Image/boot steps need Python 3, `xorriso`, QEMU, OVMF, the target, and network access for the first pinned download.

Changes to boot requests/entry, `linker.ld`, `src/arch/x86_64/`, memory allocation, paging, or heap code should receive `just verify` when the environment permits. If it does not, report the exact command failure and leave the corresponding roadmap criterion unchecked.

Editor diagnostics are useful but are not proof that Rust compiled, assembly assembled, the target linked, the image booted, or the hardware path works. Never say “tests pass” when they were not run.

## Relevant documentation

- `docs/index.md` — documentation entry point and current status.
- `docs/roadmap/README.md` — sequencing and milestone exit criteria.
- `docs/architecture/overview.md` — architecture and subsystem layering.
- `docs/architecture/boot.md` — Limine request/response contract and trust boundary.
- `docs/architecture/memory.md` — ranges, frame allocator, inherited mappings, and future paging.
- `docs/architecture/crabshell.md` — parser, commands, and RAM filesystem contract.
- `docs/architecture/drivers.md` — driver status and scope.
- `docs/security.md` — unsafe boundaries and security requirements.
- `docs/development/building.md`, `docs/development/testing.md` — commands and evidence expectations.

<!-- entire-agent:begin -->
Read .entire/agent-guide.md for this repository's workflow, source inspection, and verification guidance.
@.entire/agent-guide.md
<!-- entire-agent:end -->
