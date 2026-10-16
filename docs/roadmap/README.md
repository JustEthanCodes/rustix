# Rustix roadmap

This roadmap describes an incremental path from the current bare-metal kernel to a useful Unix-like operating system. It is a dependency plan, not a schedule or a claim of compatibility. Features become current only after the implementation, tests, and exit criteria below agree.

## How to read status

- A checked box means the source/design work exists; it does **not** imply the code compiled, linked, booted, or passed an integration test.
- A milestone is not complete until its stated exit criteria are met and the evidence is recorded.
- Hardware work needs target build and emulator evidence. Host tests cannot validate privileged instructions, bootloader pointers, page tables, device I/O, or exception-entry assembly.
- Future work is intentionally not represented by placeholder APIs or dummy implementations.

## Current status

- **Milestone 0: current working tree passes `just verify`; clean-checkout reproducibility remains pending.** The WSL2 Ubuntu 24.04 run on 2026-10-16 built the image and reached the Crabshell prompt in QEMU. A fresh checkout with uncached build/tool state and a CI run have not yet been tested.
- **Milestone 1: host validation and QEMU boot-metadata reporting have been exercised.** The bounded boot snapshot, memory-range classification, and CPUID reporting were covered by `just verify`; the Limine pointer-readability trust boundary remains explicit.
- **Milestone 2: in progress, not complete.** A bounded frame allocator is retained in `BootInfo`, and bootstrap GDT/TSS/IDT fatal exception handlers exist. The kernel still inherits Limine's page tables; there is no owned page-table manager, global heap, live frame-allocation caller, or fault-injection/emulator validation.
- **Milestones 3 and later: planned.** There is no general IRQ system, scheduler, userspace, syscall ABI, persistent filesystem, GUI, or networking stack.

## Dependency path

```text
Reliable boot
    -> validated boot state
    -> owned mappings + frame allocation + heap + fault diagnostics
    -> timer/IRQ model + scheduler
    -> isolated processes + syscall ABI
    -> VFS/storage + userland utilities
    -> graphical terminal and other optional services
```

Some device-driver work can proceed in parallel after the core ownership, locking, and testing rules exist. It must not bypass them with direct, unreviewed hardware access.

---

## Milestone 0 — repeatable Rust kernel boot (current baseline)

### Implementation present

- [x] `no_std` Rust kernel binary for `x86_64-unknown-none` with its own ELF linker layout and `_start`.
- [x] Limine boot requests and documented external-loader boundary.
- [x] COM1 serial output/input, startup reporting, and panic/fatal halt path.
- [x] Narrow x86 port-I/O helpers and raw non-blocking PS/2-compatible scancode polling.
- [x] `just` tasks for formatting, host tests, target checks, ELF/image builds, and QEMU smoke/run workflows.
- [x] Pinned Limine v12.9.3 binary archive with SHA-256 verification, BIOS/UEFI hybrid image recipe, and CI workflow.
- [x] Separate allocation-free Crabshell parser, kernel serial frontend, and bounded volatile RAM filesystem.

### Validation evidence and remaining proof

- [x] Current source passed formatting, host tests, target check, and optimized build through `just verify`.
- [x] The pinned image built and the bounded QEMU smoke test reached the Crabshell prompt in WSL2 Ubuntu 24.04 on 2026-10-16.
- [x] A separate interactive QEMU session exercised `help`, `ls`, `meminfo`, directory navigation, and file create/write/append/read/copy/move/remove operations; `cp` replaced an existing destination, `rmdir` refused a nonempty directory, and unsupported `memtest` was rejected as expected.
- [ ] Repeat verification from a clean checkout with uncached build/tool state; CI has not yet been observed.

The QEMU serial log showed the startup banner, HHDM offset, validated memory-map summary, frame counts, CPUID report, and initial prompt. The interactive command check is a focused manual test, not exhaustive shell coverage or a persistence test. `cat` returned `hello Rustix from QEMU`, `cp` replaced an existing destination with source data, `rmdir` refused a nonempty directory, and `pwd` returned to `/home/rustix` after cleanup. If a future smoke test fails, preserve `target/rustix-qemu-serial.log` as failure evidence.

**Exit criteria:** a clean checkout builds the image, reaches `_start`, reports the expected startup state, and reaches the Crabshell prompt in the automated QEMU test. The current working tree meets the boot path checks; clean-checkout reproducibility is still pending.

---

## Milestone 1 — validated boot state and machine diagnostics (validation exercised)

### Source work present

- [x] Copy Limine HHDM and memory-map information into an owned `BootInfo` before shell startup.
- [x] Bound map entries; check pointer nullness/alignment, count conversion, arithmetic, nonzero ranges, and overlap.
- [x] Convert ranges to half-open `[start, end)` physical intervals.
- [x] Preserve usable, reserved, ACPI, bad-memory, bootloader-reclaimable, executable/module, framebuffer, and unknown region classifications.
- [x] Reject the complete snapshot rather than continue with partial or invalid map metadata.
- [x] Report baseline CPUID vendor/features and document the current COM1-only console.
- [x] Document that classifying a range does not transfer ownership or authorize access/reclamation.

### Remaining proof and polish

- [x] Host tests cover malformed and boundary memory-map values, including empty input, capacity, zero length, overflow, overlap, adjacency, and unknown types.
- [ ] Add serial/report formatting tests if output formatting is separated into a host-testable pure helper.
- [x] Build and boot the image with the current request-section/linker layout; the QEMU serial log showed the boot metadata and CPUID report.
- [ ] Revisit loader pointer validation before introducing another boot source: numeric checks cannot prove non-null response data is mapped and readable.

**Exit criteria:** the host tests and QEMU metadata/reporting path were observed in the 2026-10-16 WSL2 `just verify` run. The loader readability trust boundary remains documented; clean-checkout reproducibility is tracked under Milestone 0.

---

## Milestone 2 — memory ownership, paging, heap, and exceptions (in progress)

This milestone must establish a safe basis for future allocation and kernel services. Do not allocate a frame for a mapping or dereference it through the HHDM until the mapping/ownership proof is explicit.

### Source work present

- [x] Fixed-capacity frame allocator over validated `Usable` ranges, with page alignment, first-MiB reservation, deallocation, coalescing, bounded metadata, and host tests (`src/frame.rs`).
- [x] Initialize allocator metadata from the boot snapshot and expose counts through Crabshell `meminfo`.
- [x] Bootstrap GDT/TSS/IDT and fatal handlers for exception vectors 0–31.
- [x] Give double faults a dedicated IST stack; report saved register/error context and CR2/error bits for page faults.
- [x] Keep maskable IRQ delivery disabled; current exception handling is fatal-only.

### Required memory-management work

- [ ] Specify how one allocator instance owns its ranges, how allocated frames are returned, and how exhaustion/metadata exhaustion is surfaced to callers.
- [ ] Document the active virtual-address width, HHDM coverage, physical-address width, page size, and the policy for MMIO, guard regions, kernel image, stacks, boot data, and page-table frames.
- [ ] Design a kernel-owned page-table transition that preserves every mapping needed to execute during and after the switch: kernel text/data/BSS, current stack, `BootInfo`, Limine requests/responses still needed, GDT/TSS/IDT, exception stacks, serial state, and any direct-map access used by the transition.
- [ ] Implement checked page-table entry construction and mapping operations: canonical/aligned addresses, permissions, cache attributes, ownership, huge-page behavior, and explicit writable-executable rejection by default.
- [ ] Ensure mapping failure (including no free frame or range-table exhaustion) rolls back partial page-table allocations or leaves the old map active.
- [ ] Add host tests for mapping/address policy and allocator failure invariants. Add a reviewable emulator test for mapping, unmapping, permission behavior, and frame reclamation before replacing the inherited CR3.
- [ ] Only after a mapping policy works, add a kernel heap with documented alignment, allocation/free semantics, deterministic exhaustion behavior, and an explicit rule for interrupt contexts.

### Required exception/descriptor validation

- [x] Source contains GDT/TSS/IDT setup and normalized stubs for architectural exception vectors 0–31; double fault uses IST1.
- [ ] Target-assemble and link the stubs; inspect descriptor layout/selectors and verify call-stack alignment and error-code normalization.
- [ ] Add fault-injection tests for at least a controlled page fault and a controlled exception. Confirm diagnostics are captured and the kernel halts rather than returning.
- [ ] Confirm the descriptor setup and exception paths boot in QEMU before relying on them as a memory-management safety net.

**Exit criteria:** the kernel owns and validates its page-table state, frame allocation/mapping invariants are tested, OOM/failure leaves memory state consistent, page faults are diagnosable, and the kernel remains bootable under emulator tests. Not met: page tables, heap, fault-injection, and boot verification remain outstanding.

---

## Milestone 3 — IRQs, time, and kernel scheduling

Do not enable interrupts as a side effect of installing exception gates. IRQ delivery needs its own controller, acknowledgement, masking, ownership, and synchronization design.

### Planned work

- [ ] Select and document the initial interrupt controller policy for QEMU and target hardware (for example, legacy PIC compatibility versus local I/O APIC; do not enable both accidentally).
- [ ] Add IRQ vector allocation, controller masking/unmasking, end-of-interrupt acknowledgement, spurious-interrupt handling, and a policy for unexpected IRQs.
- [ ] Add a calibrated/verified timer source and monotonic timekeeping; test interval arithmetic and drift assumptions.
- [ ] Establish interrupt-safe lock primitives and rules for code callable from normal, exception, and IRQ contexts. No allocator or blocking console operation may run in an unsafe interrupt context.
- [ ] Add a minimal kernel-thread context and lifecycle model, stack ownership/guard policy, context-switch tests, and emulator scheduling tests.
- [ ] Add preemption only after lock, stack, timer, and interrupt-return invariants have deterministic tests.
- [ ] Keep application-processor startup/SMP as a separate sub-milestone after per-CPU state, TLB invalidation, and lock semantics exist.

**Exit criteria:** tested IRQ acknowledgement and timer behavior, deterministic thread lifecycle/context-switch tests, and bounded QEMU tests under repeated timer interrupts. No `sti` before the design and tests are ready.

---

## Milestone 4 — isolated processes and syscall ABI

Userspace begins only after page tables, exception handling, scheduling, and controlled memory allocation are trustworthy. The syscall ABI is a product interface and must not emerge accidentally from internal functions.

### Planned work

- [ ] Decide and document the x86_64 user-entry/syscall mechanism, register convention, selector/MSR setup, per-CPU state requirements, and safe return path.
- [ ] Add user/kernel page permissions and process-owned address spaces, including teardown and TLB invalidation rules.
- [ ] Implement copy-in/copy-out helpers that validate lengths, arithmetic, canonical ranges, permissions, and faults; never form a kernel reference directly from a user pointer.
- [ ] Specify version discovery, stable syscall numbers, argument layouts, error encoding, partial-I/O behavior, interruption/restart, and compatibility policy before exposing calls.
- [ ] Add initial process lifecycle and descriptor-table semantics: create/load, exit, wait, close, duplication/inheritance, and process cleanup.
- [ ] Load a deliberately small documented executable format with bounds/segment/permission checks; reject malformed binaries safely.
- [ ] Build adversarial tests for bad pointers, overflow, invalid mappings, process teardown, descriptor misuse, and failed exec.

### First user-visible target

A small controlled `init` process should start from a reproducible image, write through a descriptor, exit with a status, and be waited on by a kernel test harness. Do not claim userspace or process isolation from ring-0 tasks that merely use process-shaped structs.

**Exit criteria:** an isolated init process runs in user mode and uses a versioned, documented syscall subset; invalid user pointers and process teardown are tested without corrupting the kernel.

---

## Milestone 5 — VFS, storage, and device ownership

Keep the current RAM filesystem as a bootstrap/test implementation. Persistence and device drivers require explicit block ownership, error handling, and recovery behavior.

### Planned work

- [ ] Define VFS node, mount, path, metadata, and file-descriptor contracts independently of a particular disk format.
- [ ] Preserve volatile RAMFS as a test backend and add tests for mount/path errors, capacity, partial I/O, and object lifetime.
- [ ] Add a narrowly scoped block-device interface with request validation, timeout/error reporting, and a QEMU-supported initial device driver (such as virtio-blk after PCI discovery is ready).
- [ ] Choose and document the first on-disk filesystem format. Specify partition discovery, byte order, block size, metadata limits, corruption handling, and read-only/recovery behavior before writable support.
- [ ] Add persistent write/read/remount/reboot integration tests; never claim persistence from an in-memory cache alone.
- [ ] Add a driver ownership and DMA policy before any device can write into arbitrary kernel memory.
- [ ] Define file descriptors and basic process I/O semantics before exposing them to applications.

**Exit criteria:** a reproducible image mounts a documented on-disk filesystem, user-visible tools can create/read files across reboot, and corruption/I/O errors fail safely.

---

## Milestone 6 — initial userspace and command-line utilities

Crabshell is currently an in-kernel parser/frontend. The long-term terminal application should reuse its parser model without linking kernel internals or bypassing syscalls.

### Planned work

- [ ] Start a user-mode `init` process and establish executable search, environment, current directory, descriptor inheritance, and process startup rules.
- [ ] Port or adapt Crabshell into a userspace terminal application that uses only the documented syscall/VFS interfaces.
- [ ] Add a small utility set with explicit scope: file listing, text output, create/remove/copy/move, and system information.
- [ ] Add command-line quoting, escaping, history, redirection, and pipelines only with parser tests and process/descriptor/pipe semantics to support them.
- [ ] Add integration tests that launch tools from the filesystem image and exercise them through syscalls; keep unsupported features explicit.

**Exit criteria:** shell and basic tools run as isolated user processes from a reproducible image; no shell command directly calls kernel-private VFS internals.

---

## Milestone 7 — graphical console and GUI (long-term)

A GUI is intentionally downstream of stable memory management, interrupts/input, process isolation, drivers, and userspace. Keep Crabshell's parser independent so a graphical terminal frontend can reuse it.

### Planned work

- [ ] Add validated framebuffer discovery and memory ownership; implement a minimal text/graphics console without compromising serial panic diagnostics.
- [ ] Establish an input subsystem that separates raw device events from key mapping and terminal policy. Plan PS/2 and USB HID support separately; do not treat the current raw scancode poller as a keyboard driver stack.
- [ ] Define a graphics buffer ownership/presentation API, clipping rules, pixel format, and bounds/overflow checks.
- [ ] Implement a minimal compositor/windowing policy only after process isolation and input routing are ready.
- [ ] Run Crabshell as a terminal application in a GUI window using the same parser and userspace services as the serial/TTY path.
- [ ] Preserve serial as a headless recovery/debug console and add repeatable QEMU display/input tests.

**Exit criteria:** a documented GUI session starts from userspace, renders a terminal, accepts tested input, and does not require direct kernel-private VFS access.

---

## Milestone 8 — networking (long-term, after drivers and process isolation)

Networking is not implied by the current device drivers. The initial target should be a tightly scoped virtual-device path with clear ownership and bounded buffers.

### Planned work

- [ ] Complete PCI/device discovery and define DMA buffer ownership, address translation, cache synchronization, and reset/error behavior.
- [ ] Implement one virtual NIC driver with bounded queues and timeouts; test against QEMU user networking.
- [ ] Choose and document a minimal link/network protocol scope before implementation. Keep packet parsing length-checked and fuzzable on the host.
- [ ] Add interface configuration, routing, socket/descriptor ownership, and per-process access policy.
- [ ] Add adversarial packet tests and integration tests for link loss, malformed packets, queue exhaustion, and device reset.
- [ ] Add higher-level transports/services only when the required protocol semantics, entropy source, and security model are designed.

**Exit criteria:** documented user processes can communicate through a tested virtual NIC/network stack, with malformed input and resource exhaustion handled safely. Do not claim internet, TLS, or POSIX sockets merely from a packet driver.

---

## Cross-cutting acceptance gates

Every milestone should include the relevant subset of these gates:

1. **Design:** documented ownership, invariants, resource limits, error semantics, and unsupported cases.
2. **Tests:** host tests for pure policy and malformed/boundary input; integration tests for hardware-facing behavior.
3. **Safety:** review unsafe blocks, pointer provenance/access, integer overflow, privilege boundaries, concurrency, and cleanup/rollback paths.
4. **Build:** format, host tests, target check, and final ELF link as appropriate.
5. **Boot/integration:** QEMU tests for changes to boot, paging, descriptors, interrupts, drivers, processes, or persistence.
6. **Documentation/status:** update architecture and roadmap docs; never check off a criterion without evidence.
7. **Compatibility:** claim Unix/POSIX behavior only for the exact documented subset with conformance-style tests.

## Working rule

Prefer a small end-to-end vertical slice over broad, unbootable scaffolding. A source file, interface, or architecture document is not proof that the corresponding subsystem is operational. When a check cannot run, record the exact environment blocker and leave that acceptance gate pending.
