# Rustix roadmap

This roadmap describes an incremental path from the current bare-metal kernel to a useful Unix-like operating system. It is a dependency plan, not a schedule or a claim of compatibility. Features become current only after the implementation, tests, and exit criteria below agree.

## How to read status

- A checked box means the source/design work exists; it does **not** imply the code compiled, linked, booted, or passed an integration test.
- A milestone is not complete until its stated exit criteria are met and the evidence is recorded.
- Hardware work needs target build and emulator evidence. Host tests cannot validate privileged instructions, bootloader pointers, page tables, device I/O, or exception-entry assembly.
- Future work is intentionally not represented by placeholder APIs or dummy implementations.

## Current status

- **Milestone 0: local exit criteria met from a clean detached worktree; hosted CI pending.** On 2026-10-16, `just verify` passed in WSL2 Ubuntu 24.04 from both the working tree and a clean detached worktree with an empty `target` directory. The clean run downloaded and compiled the pinned Limine host utility, formatted and tested the workspace, checked and built the target, created the image, and passed the 20-second QEMU prompt smoke test. Hosted CI has not been observed.
- **Milestone 1: validation criteria met for the current Limine path.** The bounded boot snapshot, memory-range classification, and CPUID reporting were covered by host tests and QEMU reporting; the Limine pointer-readability trust boundary remains explicit.
- **Milestone 2: local exit criteria met on 2026-10-24; hosted CI and physical-hardware validation remain pending.** The boot path owns and activates a clone of Limine's reachable page-table hierarchy, preserves inherited mappings, hardens kernel HHDM aliases to R/NX or RW/NX while retaining PAT attributes, invalidates stale translations on CR3 transitions, and retains table-frame tokens. `just verify`, `just frame-smoke`, and `just fault-smoke` passed after final review; QEMU exercised the active-PCID/CR3 invalidation path with CR4.PGE clear. The PGE-toggle path is statically reviewed but was not exercised by this QEMU configuration. The bounded heap does not grow from frames; broad mapping policy, reclamation, IRQ-safe allocation, and physical-hardware validation remain outside this milestone's completed scope.
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

## Milestone 0 — repeatable Rust kernel boot (local exit criteria met)

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
- [x] Repeat verification from a clean detached worktree with an empty `target` directory and uncached build/tool state; fresh Limine download/host-tool compilation, image creation, and QEMU prompt smoke test all passed on 2026-10-16.
- [ ] Observe the hosted CI workflow; it has not yet been run or verified.

The QEMU serial log showed the startup banner, HHDM offset, validated memory-map summary, frame counts, CPUID report, and initial prompt. The interactive command check is a focused manual test, not exhaustive shell coverage or a persistence test. `cat` returned `hello Rustix from QEMU`, `cp` replaced an existing destination with source data, `rmdir` refused a nonempty directory, and `pwd` returned to `/home/rustix` after cleanup. If a future smoke test fails, preserve `target/rustix-qemu-serial.log` as failure evidence.

**Exit criteria:** met locally. A clean detached worktree with uncached build/tool state built the image, reached `_start`, reported the expected startup state, and reached the Crabshell prompt in the automated QEMU test. Hosted CI remains unobserved, but is tracked separately from the local exit criteria.

---

## Milestone 1 — validated boot state and machine diagnostics (current Limine path validated)

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

**Exit criteria:** met for the current Limine path. Host tests and QEMU metadata/reporting were observed in the 2026-10-16 WSL2 `just verify` run, including the clean detached-worktree verification. The loader readability trust boundary remains documented and must be reconsidered before adding another boot source.

---

## Milestone 2 — memory ownership, paging, heap, and exceptions (local exit criteria met)

This milestone establishes a safe basis for future allocation and kernel services. HHDM access is limited to checked full-frame token paths that rely on Limine's documented contract. The boot path clones the complete reachable inherited hierarchy and activates it only after validating the requested stack span, kernel segments, candidate-root HHDM alias, and kernel-image HHDM permissions.

### Source work present

- [x] Fixed-capacity frame allocator over validated `Usable` ranges, with page alignment, first-MiB reservation, deallocation, coalescing, bounded metadata, and host tests (`src/frame.rs`).
- [x] Initialize allocator metadata from the boot snapshot and expose counts through Crabshell `meminfo`.
- [x] Specify frame-token ownership and failure semantics: `Frame` is non-copyable, failed deallocation returns the token without changing allocator state, and the current API documents (but does not enforce) one allocator instance per physical map.
- [x] Bootstrap GDT/TSS/IDT and fatal handlers for exception vectors 0–31.
- [x] Give double faults a dedicated IST stack; report saved register/error context and CR2/error bits for page faults.
- [x] Keep maskable IRQ delivery disabled; current exception handling is fatal-only.

### Required memory-management work

- [x] Read `CR4.LA57` and `CPUID.80000008H` when available to report active/max address widths; validate Limine pointers against active canonical width and host-test 48-/57-bit boundaries.
- [x] Document base revision 3 HHDM region coverage, page-boundary behavior, and x86 permissions/cache attributes. HHDM access is limited to opt-in, checked frame and candidate-table probes relying on the protocol contract; there is no general physical-memory service.
- [x] Reject physical map ranges outside the reported CPUID width when available; validate page-rounded HHDM address arithmetic/canonicality for base revision 3 mapped types. This is protocol-derived validation, not a page-table walk or proof of pointer readability.
- [x] Record current transition-critical objects, their mapping sources/permissions, and unresolved bounds in `docs/architecture/memory.md`.
- [x] Capture Limine's executable physical/virtual bases and resolve the complete linker-defined half-open kernel-image span in `BootInfo`; validate the linker/loader base agreement, canonical virtual span, arithmetic, and reported physical width.
- [x] Capture and validate the linker-defined page-aligned text, rodata, and data segment bounds in `BootInfo`; host-test their ordering, contiguity, rounded image coverage, and derived physical ranges. `just verify` reported all three in QEMU on 2026-10-21. This metadata does not prove inherited page-table coverage or live permissions.
- [x] Request a 256 KiB Limine x86_64 stack, require its response, and capture/validate the requested span from entry `RSP`; verify its HHDM translation and `BootloaderReclaimable` backing. `just frame-smoke` walked all 64 pages in QEMU. This request fixed stack-frame overflow in the diagnostic path.
- [x] Record that Limine guarantees at least the requested stack size but does not report the larger allocation's exact bounds or guard status; preserve the requested 256 KiB span and do not infer a guard page.
- [x] Decode the inherited CR3 root address and interpret its low bits using the reported physical-address width and active `CR4.PCIDE` state; host-test reserved-bit and width rejection. `just frame-smoke` reads the root, walks kernel segments and the requested stack span, compares effective PAT/MTRR types for kernel-image/HHDM aliases, and exercises the active-root transition.
- [x] Document the active clone's kernel alias W^X policy, inherited cache behavior, MMIO limits, huge-page splitting, stack bounds, and inherited-root preservation in `docs/architecture/memory.md`.
- [x] Clone every reachable present inherited page-table hierarchy entry into allocator-owned table frames, preserving inherited leaves and non-present entries. Validate kernel segments, the full requested stack span, candidate-root HHDM access, and critical paths; keep the inherited root and backing frames untouched.
- [x] Add pure host-tested 4 KiB mapping-range validation and leaf-PTE bit encoding. Validation requires alignment, checked bounds, known physical width, canonical virtual ranges, and W^X; encoding bounds the physical width and PAT index and requires NXE for non-executable entries. These helpers alone do not prove frame ownership, mapping coverage, or PAT cache semantics, and do not touch tables.
- [x] Implement a bounded candidate-root builder for 4 KiB mappings backed by allocator-issued table and leaf tokens. It requires NXE, uses range-bound PAT attributes, restricts walks to owned tables, and holds a unique mutable backend borrow. Mapping preflights the path and prepares all missing tables before linking them; host tests cover 4-/5-level paths, W^X, ownership rejection, and rollback. An active-state guard prevents candidate mutation/release while CR3 names its root.
- [x] Ensure candidate mapping failure (including frame exhaustion and prepare failure) rolls back partial page-table allocations without changing the active root. Host tests cover rollback and retryable release failure; `just frame-smoke` maps, walks, unmaps, and releases a separate candidate mapping in QEMU.
- [x] Validate and activate the cloned root in QEMU, preserving CR3 low-bit mode, invalidating the active PCID, and flushing global translations when CR4.PGE is enabled; verify the active CR3 plus critical translations after the switch. On failure, restore and verify the inherited root with the same TLB invalidation before releasing the inactive candidate.
- [x] Add host tests for raw PTE-bit encoding and parsing a supplied PAT layout to find WB/UC/WC indexes.
- [x] Read EFER.NXE only when NX is supported and read `IA32_PAT` only when PAT is supported; report these read-only values and recognized PAT indexes at boot.
- [x] Host-test that rejected deallocations preserve free-range state and return the frame token for unaligned, unmanaged, already-free, and range-table-full cases.
- [x] Add a pure host-tested MTRR decoder/resolver for supplied fixed and variable register values, including disabled-MTRR behavior and overlap rules. Host tests and `just verify` passed on 2026-10-21.
- [x] Capture supported MTRR capability, default-type, fixed-range, and variable-range registers read-only at boot. Retain at most 32 variable pairs; report capacity overflow explicitly without a partial snapshot. Host tests cover feature gating, supported fixed/variable register reads, unsupported fixed ranges, and capacity overflow. `just verify` passed on 2026-10-22; the QEMU serial log reported the live MTRR summary.
- [x] Validate captured MTRR capability/default-type bits, register counts and fixed-range availability, WC support, and variable-range mask/alignment; resolve the Intel SDM Table 11-7 PAT/MTRR combinations for one physical address only when `CR0.CD=0` and `CR0.NW=0`. Host tests cover all 30 documented type pairs and malformed inputs. Boot validates the captured PAT/MTRR state and prints a diagnostic resolution at PA 0; `just verify` passed on 2026-10-22. This policy helper does not establish the cache type of an inherited mapping.
- [x] Add a pure range-level PAT selector that returns an index only when it yields the requested effective type across every fixed/variable MTRR transition in the aligned physical range. Host tests cover variable boundaries, fixed-range transitions, no-uniform-index failure, and malformed range inputs. This remains policy-only and does not inspect live PTEs or aliases.
- [x] Compose range-level PAT selection with validated mapping metadata; bind the selected attributes to the physical extent and use them to encode individual 4 KiB leaves. Host tests cover a range crossing variable-MTRR types, width mismatch, and rejecting attributes for a different extent. This does not inspect inherited PTEs, establish frame ownership, or detect cache aliases.
- [x] Calculate HHDM addresses only for allocator-issued frame tokens whose complete page remains in a validated `Usable` region, with known physical width and checked protocol bounds. `just frame-smoke` passed in QEMU: one frame was written, read, cleared, and returned to the allocator. This relies on Limine's base revision 3 HHDM guarantee and does not inspect live PTEs or validate arbitrary physical addresses.
- [x] Validate the inherited CR3 root's numeric HHDM location only when its page lies wholly in a validated `BootloaderReclaimable` region and address-width arithmetic passes. Host tests reject unknown widths and other region types; `just frame-smoke` reads the 512 root entries in QEMU and confirms the HHDM access.
- [x] Add a bounded read-only 4-/5-level page-table walker with synthetic host tests for translations, permissions, PAT selection bits, 2 MiB pages, and absent entries. The opt-in QEMU probe follows every page in linker-defined text/rodata/data spans and the requested stack span, checking translations and effective cache types for kernel-image/HHDM aliases.
- [x] Add host-tested candidate page-table mapping/unmapping and transactional ownership handling; `just frame-smoke` verifies a separate candidate root can map, walk, unmap, and release one frame without changing CR3. The default boot path separately activates an inherited-root clone after critical translation and kernel-alias permission/cache checks.
- [x] Harden kernel-image HHDM aliases before activation: text/rodata become R/NX and data/BSS become RW/NX. Split inherited 1 GiB/2 MiB mappings as needed while preserving translation and PAT bits. Host tests cover both large-page splits; QEMU verifies every kernel-image alias retains its physical translation, desired permissions, and PAT index.
- [x] Add a 256 KiB BSS-backed global heap with 128 allocation records, first-fit aligned placement, exact-layout free/reuse, deterministic arena/metadata exhaustion, and an explicit prohibition on interrupt-context allocation. Host tests cover alignment, reuse, exhaustion, and invalid frees; the QEMU boot probe exercises the global allocator before entering the shell. The arena is fixed and does not grow from physical frames.

### Required exception/descriptor validation

- [x] Source contains GDT/TSS/IDT setup and normalized stubs for architectural exception vectors 0–31; double fault uses IST1.
- [x] Target-assemble/link and inspect the stubs and descriptor setup; ELF disassembly confirms call-stack alignment and the error-code normalization paths, while compile-time size assertions pin the IDT, TSS, and exception-context layouts.
- [x] Add QEMU fault-injection tests for a controlled page fault and invalid opcode. `just fault-smoke` verifies vector diagnostics, the exact CR2 address, no shell prompt or return marker, and that QEMU remains halted until its timeout; it then restores the default release kernel and ISO.
- [x] Boot the descriptor setup and both tested exception paths in QEMU. These checks cover only the injected page fault and invalid opcode, not all vectors or physical hardware.

**Exit criteria:** met locally on 2026-10-24. `just verify`, `just frame-smoke`, and `just fault-smoke` passed after final review, covering host tests, the target build, active cloned-root boot, frame and candidate-map probes, heap behavior, and fatal page-fault/invalid-opcode diagnostics. The QEMU configuration reported CR4.PGE clear and exercised the CR3 reload path; the PGE-toggle global-TLB path is statically reviewed but was not exercised in QEMU. The active hierarchy preserves Limine's complete reachable mapping graph and hardens the kernel-image HHDM aliases; it is not a clean-room address-space policy, does not reclaim the old root or leaf frames, and has no general active mapping service. Hosted CI and physical-hardware validation remain pending and are not claimed by this local exit status.

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
- [ ] Load a deliberately small documented executable format with bounds/segment/permission checks and reject malformed binaries safely. Use `.bin` for command-line executables and `.app` for GUI applications; these suffixes identify the intended application role, not different executable formats. `.app` is a Rustix file suffix, not an Apple/macOS app bundle.
- [ ] Begin moving the existing `cp`, `mv`, and `mkdir` shell commands into separate command crates that build `.bin` executables. Since persistent storage is not available yet, preinstall these binaries in the reproducible system image.
- [ ] Establish a trusted command-search policy: normal command lookup checks `~/.bin/` before `/usr/bin/`; commands run through `sudo` use a restricted trusted system path and do not inherit the caller's command path.
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
- [ ] Define the planned top-level filesystem layout: `/home`, `/root`, `/etc`, `/usr`, `/dev`, `/proc`, `/sys`, `/tmp`, `/var`, `/run`, `/mnt`, `/media`, and `/boot`, plus `/usr/sbin`. Document that `/proc` and `/sys` are future virtual interfaces, `/dev` exposes device interfaces, `/tmp` and `/run` are volatile, and mount-point and boot-file usage depends on later storage/boot design.
- [ ] Specify that `/etc` and `/usr` are root-owned and writable only by root, while normal users may read configuration and execute permitted programs. Keep readable account metadata separate from a root-only credential file containing password hashes. Reserve `/usr/Apps` for globally installed `.app` GUI applications and `/usr/bin` for globally installed `.bin` command-line tools; `/usr/sbin` is reserved for system-administration tools if needed.

**Exit criteria:** a reproducible image mounts a documented on-disk filesystem, user-visible tools can create/read files across reboot, and corruption/I/O errors fail safely.

---

## Milestone 6 — initial userspace and command-line utilities

Crabshell is currently an in-kernel parser/frontend. The long-term terminal application should reuse its parser model without linking kernel internals or bypassing syscalls.

The planned filesystem layout is illustrated below. This is a directory-layout proposal, not a claim that these paths or services are implemented; `/dev`, `/proc`, and `/sys` are intended system interfaces, while `/tmp` and `/run` are volatile.

```text
/
├── boot/
├── dev/
├── etc/
├── home/
│   ├── Public/  (created when a second account is added)
│   └── test/
│       ├── Apps/
│       ├── Desktop/
│       ├── Documents/
│       ├── Downloads/
│       ├── Pictures/
│       ├── Videos/
│       ├── .bin/
│       ├── .config/
│       └── .local/
├── media/
├── mnt/
├── proc/
├── root/
├── run/
├── sys/
├── tmp/
├── usr/
│   ├── Apps/
│   ├── bin/
│   └── sbin/
└── var/
    └── log/
```

### Planned work

- [ ] Start a user-mode `init` process and establish executable search, environment, current directory, descriptor inheritance, and process startup rules.
- [ ] Design a local-account and privilege model. Reserve UID/GID 0 for root, IDs 1–999 for future system/service accounts, and assign regular users IDs starting at 1000; initially give each user a primary group with the same ID. Use local username/password authentication, with a reviewed password-hashing implementation, a unique salt, and a trustworthy random source; Argon2id is a candidate, but exact implementation and parameters require a later security review. Never store plaintext passwords.
- [ ] Create the first regular account through installation or first-boot setup and grant it administrator privileges. Later accounts are standard users by default; root can explicitly grant or revoke administrator status. Run a text login prompt on the serial/terminal console and start the shell under the authenticated user's identity. Do not permit direct root login during normal operation; GUI login is deferred to the GUI milestone.
- [ ] Create `/home/{username}/` for each regular user and `/root/` for the root account. Give regular-user homes `Apps/`, `Desktop/`, `Documents/`, `Downloads/`, `Pictures/`, `Videos/`, `.local/`, `.config/`, and `.bin/`. Homes and newly created files are private by default. Use owner/group/other read, write, and execute permissions initially; defer ACLs.
- [ ] Create `/home/Public/` when a second account is added. All users may read it and add files; only a file's owner or root may change or remove that file. Test the shared-directory permission behavior explicitly.
- [ ] Keep `/etc` and `/usr` root-owned and writable only by root. Normal users may read configuration and execute permitted programs. Store readable account metadata separately from password hashes, which must be in a root-only credential file. Global `.app` files go in `/usr/Apps/`; global `.bin` tools go in `/usr/bin/`.
- [ ] Restrict `sudo` to administrators; require the invoking administrator's password for every invocation, with no credential caching. Run the requested command as root using a restricted trusted command path, not the caller's environment. Add increasing delays after repeated failed password attempts rather than permanent account lockout. Record successful and failed privileged actions in `/var/log/` without logging passwords; durable logging depends on persistent storage.
- [ ] Provide a root-only `userctl` command-line tool for creating, disabling, removing, and administering accounts, changing passwords, and granting or revoking administrator privileges. Account removal disables login but preserves the home directory unless file deletion is explicitly requested.
- [ ] Provide designated, administrator-controlled recovery media that can reset any local account, including an administrator account, without a separate recovery secret in the initial design. Document that this alone does not protect against physical attackers; secure boot and disk encryption are separate future security work.
- [ ] Port or adapt Crabshell into a userspace terminal application that uses only the documented syscall/VFS interfaces.
- [ ] Add a small utility set with explicit scope: file listing, text output, create/remove/copy/move, and system information. Keep every command in its own crate and build it as a separate `.bin` executable; this applies to future command-line tools as well as `cp`, `mv`, and `mkdir`. Install per-user CLI tools in `~/.bin/` and single-file GUI `.app` applications in `~/Apps/`; GUI drag-and-drop installation is a later goal. Initial installation is copying a file and removal is deleting it; global installation requires root. Never silently overwrite a same-named app or tool. Defer package management, dependency tracking, and automatic updates.
- [ ] Add command-line quoting, escaping, history, redirection, and pipelines only with parser tests and process/descriptor/pipe semantics to support them.
- [ ] Add integration tests for login identity, account-ID allocation, password verification and failure delays, private homes, `/home/Public/` ownership rules, `/etc` and `/usr` write restrictions, `sudo` authorization and trusted command lookup, `userctl` authorization, account recovery, and launching tools as user processes. Verify password hashes are not exposed and credentials never appear in logs.

**Exit criteria:** the shell and basic tools run as isolated user processes from a reproducible image; local login and account administration enforce the documented identity and permission model; account, `sudo`, and recovery tests pass; no shell command directly calls kernel-private VFS internals.

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
