# Gemini CLI instructions for Rustix

This file provides project-specific context for Gemini CLI and Gemini-based coding agents. Read `AGENTS.md` before editing; it is the canonical shared contract for all agents. Also follow any more specific instructions attached to the user request. Do not weaken the safety, status, or validation requirements described here and in `AGENTS.md`.

## Project identity and goal

Rustix (Rust-unix) is an experimental 64-bit Unix-like operating system with its own Rust kernel. The kernel itself is built as a `no_std` binary for `x86_64-unknown-none`. Limine is an external boot protocol/loader, not the Rustix kernel. A Python standard-library script only builds and smoke-tests the boot image; it does not implement OS behavior.

The project aims toward Unix-like services incrementally. It does not currently claim POSIX conformance, security isolation, or production readiness. Unsupported operations should produce clear failures or be documented as future work, not silently approximated.

## Current state and validation boundaries

Milestones 0–3 have met their documented local exit criteria. The repository has a Limine boot path, validated boot snapshot and memory map, CPUID reporting, a bounded physical-frame allocator, cloned active page tables, a bounded global heap, bootstrap GDT/TSS/IDT exception handling, a validated single-vCPU xAPIC/I/O APIC and PIT path, cooperative waits/yields with timer preemption, Crabshell, and a volatile fixed-capacity RAM filesystem.

Crabshell's parser is a standalone allocation-free `no_std` workspace crate. Kernel-side I/O and command execution are in `src/shell.rs`. Shell input uses bounded COM1 IRQ input with polling fallback; PS/2 IRQ input remains raw scancode reporting. The shell runs in ring 0 and is not a userspace application or a POSIX shell. `meminfo` reports validated RAM and frame counts. The bounded heap and frame-backed mappings are kernel services, but allocation is not allowed in IRQ/exception context.

Do not assume uncommitted source is validated just because a previous tree passed:

- Milestone 0–3 evidence is recorded in `AGENTS.md` and `docs/roadmap/README.md`; rerun relevant checks for current changes.
- Structural boot validation cannot prove that a non-null Limine pointer is readable; this remains a loader trust boundary.
- Scheduling is single-vCPU, with cooperative waits/yields and timer preemption. Exceptions remain fatal-only. There is no SMP, userspace, syscall ABI, persistent storage, user/kernel isolation, or general-purpose device model.

Never mark a roadmap item complete merely because an API, design, or source file exists. The relevant implementation and validation evidence must both meet that item's exit criteria.

## How to work in this repository

1. Start at the repository root. Read `AGENTS.md`, the relevant architecture document, and the actual implementation and call sites before making changes.
2. Keep the task scoped. Prefer a small, coherent, testable vertical slice; avoid speculative scaffolding or broad rewrites.
3. Identify invariants, capacity limits, failure semantics, and any unsafe boundary before coding.
4. Put architecture-independent logic in the `rustix-kernel` library when appropriate so host tests can exercise it. Keep the freestanding binary and parser crate boundaries intact.
5. Add or update tests and documentation together. If code and docs disagree, inspect the implementation and resolve the mismatch in the same change.
6. Run the narrowest relevant validation, then broaden it. Record exact commands and actual results.
7. Report files changed, behavior delivered, validation observed, and remaining risks. Do not conceal failures or say a check passed if it did not run.

Do not commit, create branches, alter project history, or modify unrelated files unless the user explicitly requests it.

## Rust, dependencies, and API constraints

- Keep kernel and OS implementation code `no_std`; use `core` rather than `std` in the kernel.
- Do not add a third-party Rust dependency without a concrete need and compatibility/security review. The existing project uses in-tree abstractions.
- The global heap is bounded: a 256 KiB BSS arena plus up to 1 MiB of frame-backed growth. Allocation is forbidden in IRQ/exception context; prefer fixed-capacity interfaces for core paths.
- Fixed-capacity data structures must document their limit, exhaustion/error behavior, and mutation guarantees on failure.
- Keep `crates/crabshell` limited to parsing and command representation. It must not depend on the VFS, kernel modules, serial I/O, or hardware.
- Treat `src/lib.rs` as the host-testable architecture-independent kernel library boundary; the freestanding binary is not a host test target.

## Memory, boot, and safety constraints

- Limine writes the response pointers into request records before entering `_start`; those records must remain in writable loaded storage.
- The boot snapshot checks pointer nullness/alignment, count limits, checked arithmetic, physical range validity, and overlap. It cannot establish that loader-provided memory is mapped/readable; the Limine handoff remains a trust boundary.
- Physical regions use half-open `[start, end)` ranges. Use checked arithmetic for every endpoint and address calculation.
- Feed only `Usable` regions to the frame allocator. Never turn ACPI, loader-reclaimable, reserved, framebuffer, bad-memory, executable/module, or unknown classifications into free frames without an explicit ownership transition.
- A frame is a physical address, not a dereferenceable pointer. HHDM access is restricted to checked full-frame, allocator-token paths that rely on the documented Limine contract. Do not access arbitrary physical addresses or change page-table ownership without a reviewed mapping and lifetime proof.
- The active page-table root is an allocator-owned clone of Limine's reachable hierarchy. Any future replacement must preserve the executing kernel image, bootstrap stack, `BootInfo`, request/response memory, GDT/TSS/IDT, exception stacks, and required direct-map/console mappings.
- The current frame allocator has fixed range metadata and is not a heap, page mapper, concurrent allocator, or scheduling primitive.

## x86_64 hardware and exception rules

- Keep port I/O, privileged instructions, raw pointer operations, and assembly isolated under `src/arch/x86_64/` and document their invariants near each unsafe block.
- Exception vectors 0–31 remain fatal-only; double faults use an IST stack, and page faults report CR2 and error bits. The validated single-vCPU APIC path enables only configured, registered IRQ routes after dispatch and EOI setup.
- The PIT timer handler increments ticks, acknowledges the local APIC, and may preempt a thread after scheduler state is safely updated. Timer switches preserve x87/SSE with FXSAVE/FXRSTOR; AVX/XSAVE is disabled. Do not broaden IRQ use or add SMP without explicit ownership and synchronization rules, tests, and emulator validation.
- When modifying exception stubs, verify CPU error-code normalization, stack layout, saved-register order, SysV stack alignment before calling Rust, GDT selectors, TSS descriptor/IST setup, and non-returning failure behavior.
- CPUID capability bits indicate support, not necessarily that a feature is enabled in CR registers or active paging.
- Hardware/boot code changes require more than host unit tests: include target check/build and emulator validation when possible. If unavailable, describe the exact blocker and keep status unverified.

## Crabshell and filesystem contract

- Crabshell is a kernel-mode serial shell with a separate parser crate; it is not a process or a security boundary.
- The RAM filesystem is volatile, bounded, and reset on reboot. It has no persistent block device, permissions, links, journaling, or general POSIX semantics.
- Preserve explicit path, capacity, and mutation errors. Do not add hidden truncation or destructive overwrite behavior.
- When adding a command, update parser syntax/tests, kernel execution/help, and `docs/architecture/crabshell.md`; update README examples if users will encounter it.

## Supported repository checks

Run commands from the repository root:

```sh
just fmt
just test
just check
just build
just image
just smoke
just verify
```

- `just fmt` checks workspace Rust formatting.
- `just test` runs host-side ACPI, paging, frame allocator, heap, IRQ/time/input/scheduler policy, VFS, and Crabshell parser tests.
- `just check` checks the freestanding `x86_64-unknown-none` target; it is not a final link.
- `just build` links the optimized kernel ELF.
- `just image` builds the hybrid ISO and may download the pinned Limine archive on first use.
- `just smoke` uses QEMU and checks that the shell prompt is reached.
- `just verify` combines formatting, host tests, target check, image creation, BIOS/OVMF boot, active-map, cooperative-thread, and UART/PS/2 input smokes.

Image and boot checks need Python 3, `xorriso`, QEMU, the Rust target, and network access for the initial pinned download. For changes to boot entry/requests, linker configuration, architecture code, frame allocation, paging, or heap code, the intended full validation is `just verify`. Report failed or unavailable commands exactly. Editor diagnostics are not a substitute for Cargo or QEMU evidence.

## Documentation to consult

- `docs/index.md` — project status and documentation map.
- `docs/roadmap/README.md` — milestone plan and exit criteria.
- `docs/architecture/overview.md` — architecture and layering.
- `docs/architecture/boot.md` — Limine handoff and boot snapshot.
- `docs/architecture/memory.md` — physical ranges, frame allocation, and paging direction.
- `docs/architecture/crabshell.md` — parser, shell commands, and RAM filesystem.
- `docs/architecture/drivers.md` — implemented drivers and limitations.
- `docs/security.md` — unsafe boundaries and security requirements.
- `docs/development/building.md` and `docs/development/testing.md` — build/test workflows and evidence policy.


<!-- entire-agent:begin -->
Read .entire/agent-guide.md for this repository's workflow, source inspection, and verification guidance.
@.entire/agent-guide.md
<!-- entire-agent:end -->
