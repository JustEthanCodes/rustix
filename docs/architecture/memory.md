# Memory-management direction

## What exists now

`src/memory.rs` contains an allocation-free `MemoryMapBuilder` that copies Limine ranges into validated half-open physical regions. It rejects empty ranges, `base + length` overflow, overlapping ranges, empty maps, and maps exceeding the fixed 256-region capacity. Known Limine types remain distinct, and unknown type values are preserved. Host-side tests cover range validation and classification. `src/boot.rs` stores the resulting map in an owned boot snapshot and reports usable bytes.

`src/frame.rs` provides a fixed-capacity allocator core with host-side tests. It only manages complete 4 KiB frames inside validated `Usable` regions, reserves the first MiB, and rejects invalid/double frees while merging adjacent ranges. Its bounded range metadata can report fragmentation exhaustion. The kernel initializes it from the validated map, retains it in `BootInfo`, and exposes counts through Crabshell's `meminfo` command. It does not yet allocate frames for kernel services or map/dereference any allocated frame. Rustix does not reclaim bootloader memory, own or replace the inherited Limine page tables, or provide a heap. The HHDM offset is checked and logged, not used for memory access. Bootstrap GDT/TSS/IDT setup and fatal exception diagnostics live in `src/arch/x86_64/interrupts.rs`; they do not enable maskable IRQs.

## Planned memory layers

1. **Validated physical regions:** implemented as a fixed-capacity owned snapshot; allocator ownership and reclaim policy remain future work.
2. **Frame allocator integration:** the bounded core is initialized from `BootInfo`; add real allocation callers only after the page-mapping policy and ownership rules are implemented.
3. **Kernel virtual memory:** Rustix still runs on inherited Limine page tables. Before replacing them, preserve the executing kernel, bootstrap/Ring-0 stacks, request/response data, and exception stacks; define the HHDM extent and explicit mapping permissions/cache attributes. Keep writable-executable mappings disallowed by default and reserve MMIO and guard regions.
4. **Heap:** add a global allocator only after frame allocation and page mapping are initialized. Define allocation failure behavior for kernel and interrupt contexts.
5. **Process address spaces:** isolate userspace; define copy-in/copy-out helpers and never treat user pointers as kernel references.

## Invariants to preserve

- Physical ranges use checked arithmetic and the half-open convention `[start, end)`.
- Reserved regions are never returned as free frames.
- A failed allocation leaves allocator state unchanged.
- Mapping changes validate alignment, canonical addresses, ownership, and permissions before touching tables.
- User-controlled addresses are validated on every syscall boundary; prior validation is not a substitute for access checks during later copies.
- Tests cover unaligned edges, exact-boundary allocations, arithmetic overflow, overlaps, and exhaustion.

These are design requirements for future milestones, not functionality delivered by the current boot summary.
