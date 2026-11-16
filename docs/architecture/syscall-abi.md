# Unix-like process and syscall direction

**Status: design direction only. No process, syscall, or userland support is implemented.**

Rustix aims to expose a small, versioned syscall surface that can support Unix-like processes and tools. The kernel must own this interface rather than inherit an ABI accidentally from a bootloader or emulator.

## Proposed compatibility principles

- Processes have independent virtual address spaces and explicit lifecycle states.
- File descriptors are per-process integer handles to kernel-managed objects; descriptor inheritance, close-on-exec, duplication, and sharing semantics must be specified together.
- Syscalls use one documented error convention and stable numeric identifiers. New operations must not silently repurpose old numbers.
- Arguments crossing privilege boundaries are copied or validated using narrowly scoped helpers. User memory is never dereferenced as a trusted Rust reference.
- Blocking, interruption, cancellation, and restart behavior are explicit for each syscall class.
- A compatibility layer (for example, POSIX-shaped libc behavior) remains separate from internal kernel APIs.

## Initial x86_64 entry design (Milestone 4; not implemented)

The first single-vCPU user-mode slice will enter the kernel with `int $0x80` through a dedicated IDT interrupt gate at DPL 3 and return with `IRETQ`. This intentionally avoids `SYSCALL`/`SYSRET`, `STAR`/`LSTAR`/`FMASK`, and `SWAPGS` state transitions in the first userspace path. It is a provisional architecture decision, not a published or implemented syscall ABI.

- **Vector ownership:** `0x80` is currently inside Rustix's device-vector allocation range (`0x20..=0xef`). Before installing the user-callable gate, reserve it from `InterruptVectorAllocator` and install a dedicated syscall stub rather than the generic device-IRQ stub. The gate must be an interrupt gate, so maskable interrupts are disabled on entry before Rust dispatch.
- **Selectors:** the current GDT uses `0x08` for kernel code, `0x10` for kernel data, and `0x18` for the two-slot TSS descriptor. Append ring-3 data and code descriptors after the TSS without moving existing selectors: user data selector `0x2b` and user code selector `0x33` (GDT indexes 5 and 6 with RPL 3). The user code descriptor must be 64-bit code; the data selector is loaded into user `SS` on return. These values are a design target and must be asserted by the GDT implementation/tests before use.
- **Privilege stack:** a CPL3-to-CPL0 interrupt uses `TSS.RSP0`; it must point to the top of the current process's mapped, writable kernel-entry stack before user execution is resumed. The existing TSS points to one static bootstrap ring-0 stack, so it is not sufficient for processes. On this single-vCPU design the scheduler must update `RSP0` whenever it selects a process to run in user mode. A future SMP design needs per-CPU TSS and entry-stack state.
- **Entry frame and state:** the assembly stub must preserve the complete user register state and construct a separately specified syscall frame; it must not assume the existing fatal-exception frame is interchangeable. Kernel code must run with the direction flag clear. Preserve user x87/SSE state across kernel handling; AVX remains disabled under the current CPU-state policy. Do not form Rust references from user pointers.
- **Initial register convention:** `RAX` carries the syscall number; arguments use `RDI`, `RSI`, `RDX`, `R10`, `R8`, and `R9`; `RAX` carries the result. This is only a proposed register convention. It becomes stable only together with ABI version discovery, syscall numbers, errors, and transfer semantics below.
- **Return validation:** use `IRETQ`, not `SYSRET`. Before returning, validate that the saved `CS` and `SS` are exactly the ring-3 selectors, `RIP` and `RSP` are canonical and within the process's executable/code and stack regions respectively, and `RFLAGS` contains no privileged or unsupported bits. Construct a safe flags value rather than echoing user-controlled flags. A malformed frame terminates the process with a reported status; never attempt the return and rely on a ring-0 `#GP` to catch it.
- **NMI and interrupt policy:** no GS-base swap is needed on this entry path. An NMI can still arrive during entry; the current NMI/exception path is fatal-only, and this design does not claim to recover from it. Keep that behavior explicit until user-origin exception/NMI policy is implemented and tested. Ordinary maskable IRQs may resume only after the entry state and scheduler ownership are consistent.

This design depends on a process-owned address space that maps the syscall entry/return code, IDT, GDT, TSS, and the active kernel stack safely. No Ring 3 execution should be enabled until the address-space implementation is reviewed and validated.

### Process address spaces (design; not implemented)

Use a separate four- or five-level root per process. The initial source is the retained active clone of Limine's hierarchy, not a curated clean-room root. Each process root owns its root page, all lower-half intermediate tables, and every user leaf frame. Keep the kernel-root owner alive for the lifetime of every process root. Copy only upper-half top-level entries from that owner into each process root; these entries are non-owning references to shared kernel subtrees, not deep copies, and must never be released by a process teardown. Do not copy lower-half entries from the kernel root.

Before publishing a shared kernel subtree, validate its page-table structure and physical bounds and reject any present entry with the user/supervisor bit set at any level. `paging::validate_supervisor_kernel_half` implements this bounded preflight, but it does not install roots or prove physical backing is readable; the supplied reader must provide that access guarantee. Sharing the active clone means every accepted upper-half supervisor mapping and alias is present in every process CR3. This is not a curated kernel map or kernel-page-table isolation, and it provides no transient-execution protection. User mappings remain private to one process, are confined to the lower canonical half, preserve W^X, and are non-global in the first implementation.

The kernel address-space owner is the only authority allowed to modify shared upper-half tables. Mutations must be serialized with local interrupts disabled on the current single-vCPU system and invalidate the affected local translation before the mapping change is relied on. A process root may not edit or reclaim shared tables. Before releasing a process root or any of its user frames, switch CR3 to a different live root and invalidate the local non-global translations; keep the shared kernel owner alive. Do not add PCID or SMP teardown/shootdown behavior implicitly: those require a separate design.

The current `CandidatePageTables` deep-clones the inherited hierarchy, tracks all cloned table frames as owned, holds an exclusive mutable borrow of one memory backend, and does not provide shared-subtree ownership. It is not itself the process-address-space abstraction. Implement the shared-root policy in a distinct owner/handle API that can safely support multiple process roots without aliasing mutable backend references. Until that implementation and its negative tests exist, these paragraphs are a design contract only.

## ABI decisions still required before exposing calls

1. ABI version discovery and compatibility guarantees.
2. Error encoding and a complete initial syscall-number allocation.
3. Pointer/length validation, partial reads/writes, and copy-fault behavior.
4. Process creation and execution semantics, including file actions and inherited descriptors.
5. Signal-like asynchronous delivery, interruption, and restart semantics.
6. Time, clocks, and structure layout rules.

## Suggested first user-visible slice

After address spaces, scheduler, and storage primitives exist, implement a controlled `init` process with a small syscall subset: process exit, read/write through descriptors, open/close, and wait. Add end-to-end tests for invalid pointers, partial transfers, descriptor lifetime, process exit status, and ABI version negotiation before describing it as Unix-compatible.
