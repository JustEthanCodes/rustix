# Testing and verification

## Current checks

`just verify` runs the standard development verification sequence:

1. `just fmt` — fail on formatting differences across the workspace.
2. `just test` — run host-side memory-map, frame-allocator, RAM-filesystem, and Crabshell parser tests.
3. `just check` — check the `x86_64-unknown-none` kernel target.
4. `just smoke` — build the pinned hybrid ISO, boot it in QEMU, and check that Crabshell reaches its prompt within a deadline.

Keep the Crabshell parser, VFS, memory-map validator, and frame allocator independent of hardware so syntax, path handling, storage semantics, and frame ownership can be tested without booting. The GDT/TSS/IDT entry path is privileged kernel code and currently has no host fault-injection harness; it still requires target build and QEMU validation. Add tests for boundaries and failure behavior when introducing new pure kernel helpers. The kernel binary is not a host test target.

## What current checks do not prove

- `cargo check` does not perform a final target link.
- A successful ELF link does not prove the boot protocol is recognized or `_start` is reached.
- Host unit tests do not validate privileged instructions, UART behavior, memory-map pointer validity, page tables, interrupts, or actual hardware.
- The automated QEMU smoke test checks only that the kernel reaches the shell prompt. A separate manual QEMU session exercised directory navigation and file create/write/append/read/copy/move/remove operations, including `cp` replacing an existing destination and rejection of `rmdir` on a nonempty directory. This is not exhaustive shell coverage and does not prove persistence across reboot.
- There is no on-disk filesystem integration test, syscall/userspace test, fuzz target, or physical-hardware test.

## Validation policy

For changes to the kernel entry, linker script, boot requests, architecture code, shell, or VFS, run `just verify`. For memory-management and ABI code, add negative tests for overflow, malformed ranges, permission failures, and invalid user pointers before exposing those paths to userspace.

Record commands actually run and any environment limitation in change summaries; never call an unexecuted build “passing.”
