# Rustix documentation

Rustix is a 64-bit, Rust-first, Unix-like operating-system project. This index separates current implementation facts from planned interfaces: roadmap items are proposals until the corresponding code and tests exist.

## Start here

- [Project and implementation overview](architecture/overview.md)
- [Process runtime and syscall ABI](architecture/syscall-abi.md)
- [Boot protocol and current entry path](architecture/boot.md)
- [Memory-management direction](architecture/memory.md)
- [ACPI table parsing foundation](architecture/acpi.md)
- [Interrupts and IRQ vector allocation](architecture/interrupts.md)
- [x86_64 drivers and hardware boundary](architecture/drivers.md)
- [Build and toolchain guide](development/building.md)
- [Userspace development guide](development/userspace.md)
- [Testing and verification](development/testing.md)
- [Security and unsafe-code policy](security.md)
- [Milestones and acceptance criteria](roadmap/README.md)

## Current status

Rustix is a bare-metal `no_std` Rust kernel targeting `x86_64-unknown-none`. Limine supplies the boot handoff only. The kernel validates and snapshots boot metadata, clones and activates an owned page-table hierarchy, manages bounded physical frames and heap growth, configures a single-vCPU APIC/PIT and selected input IRQs, and supports both a controlled Ring 3 init runtime and a kernel-mode serial shell. Crabshell's parser is a separate allocation-free crate; its RAM filesystem is volatile.

Milestones 0–3 have locally met their documented exit criteria. Milestone 4's bounded single-vCPU scope is implemented: default boot launches a controlled Ring 3 `rustix-init` through the versioned syscall ABI, with generation-safe process slots, nested spawn, `exec`, reusable TSS entry stacks, and a four-process concurrency bound. The runtime is cooperative and IF-disabled, with shared Limine-derived kernel mappings; do not interpret this as general-purpose process isolation or a curated kernel mapping policy. SMP, physical-hardware validation, persistent storage, and broad Unix compatibility remain future work. On 2026-11-24, `just verify` passed on the current worktree with 195 kernel host tests, target check/build, boot and scheduler/input smokes, process lifecycle coverage, and CPL3/CPL0 fault coverage, including the malformed syscall-return regression.

Historical validation records are retained in the [roadmap](roadmap/README.md) and [testing guide](development/testing.md). The 2026-11-06 hosted CI result covers only its published commit, not current uncommitted changes.

## Documentation conventions

- **Implemented** means present in the repository; the cited validation describes what was actually exercised, not a proof of all properties.
- **Planned** means an architectural direction, not a stable ABI or delivered capability.
- **Bounded** calls out fixed capacities, supported inputs, or execution modes; it must not be generalized beyond those limits.
- **Locally validated** records a local command/result and does not imply CI coverage or physical-hardware validation.
- Any future ABI proposal must state versioning, error behavior, memory ownership, and compatibility expectations before it is treated as stable.
