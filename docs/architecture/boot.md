# Boot protocol and kernel entry

## Current boot contract

Rustix currently expects a Limine-compatible x86_64 handoff. Limine is an external loader; it does not implement Rustix's kernel services. The kernel requests protocol base revision 3, the higher-half direct-map (HHDM) offset, and the memory map.

Requests are kept in `.limine_requests_start`, `.limine_requests`, and `.limine_requests_end` by `linker.ld`. The response-bearing request records are mutable and the output `.limine_requests` section is placed in a writable load segment because Limine fills their response pointers before entering Rustix. The ELF entry symbol is `_start`.

### Entry sequence

1. Limine loads the ELF and transfers control to `_start` under the x86_64 Limine protocol.
2. `_start` configures the legacy COM1 UART for polling output and input.
3. The kernel disables maskable interrupts and installs its bootstrap GDT, TSS, and fatal-exception IDT. This does not initialize IRQ delivery.
4. The kernel copies the HHDM and memory-map responses into an owned `BootInfo` snapshot, including a frame allocator built only from validated usable ranges. It rejects malformed metadata before starting the shell.
5. The kernel reports validated ranges, frame counts, and baseline CPUID features, then seeds a volatile RAM filesystem and enters Crabshell on the serial console.
6. The shell busy-polls COM1 because no scheduler or UART interrupt handler exists yet. The kernel does not return to the loader.

The memory-map snapshot stores physical regions as checked half-open ranges `[start, end)` and retains Limine's known classifications plus unknown type values. It is diagnostic metadata only: it does not authorize Rustix to access every region, reclaim loader memory, or mutate the current page tables. The HHDM offset is validated and reported but is not yet used to translate or dereference physical addresses.

## Link and target configuration

- Rust target: `x86_64-unknown-none`
- Linker script: `linker.ld`
- Kernel virtual base: `0xffffffff80000000`
- Required code-generation constraints: kernel code model, static relocation, and disabled red zone
- Rust panic strategy: abort; the panic handler logs and halts

See [`../development/building.md`](../development/building.md) for commands and toolchain setup.

## Failure behavior and limitations

Missing responses, bad pointers/alignment, invalid HHDM values, excessive counts, null entries, address arithmetic overflow, and invalid or overlapping physical ranges reject the complete boot snapshot. `_start` halts before starting Crabshell rather than continuing with partial memory metadata. Structural checks cannot establish that a non-null loader pointer is mapped and readable; that remains an explicit trust assumption of the Limine handoff. The installed exception handlers print fatal context and halt; no fault recovery or maskable IRQ delivery is provided. COM1 writes use a bounded polling loop so a non-responsive UART does not block forever.

The repository includes a Limine v12.9.3 binary archive pin with SHA-256 verification, a hybrid ISO recipe, and a bounded QEMU serial smoke test that checks Crabshell's prompt. On 2026-10-16, `just verify` passed in WSL2 Ubuntu 24.04 on the current working tree, and the QEMU log showed boot metadata before reaching the prompt. A clean-checkout run with uncached build/tool state and a CI run remain outstanding, so the baseline boot milestone is not yet complete. There is still no framebuffer console, reboot/shutdown interface, or broader boot-protocol compatibility test. The available serial and keyboard drivers do not imply a general device model.

## Future boot work

The kernel now snapshots and validates the Limine map and preserves firmware and loader-reclaimable classifications without reclaiming them. No region is considered Rustix-owned or free for allocation yet. Loader-reclaimable memory must remain unavailable until Rustix has copied any needed boot data and explicitly reaches a documented reclaim point; ACPI reclaimable memory needs the ACPI tables to be copied or parsed first. Frame allocation, page-table replacement, and ownership transfer remain future work.
