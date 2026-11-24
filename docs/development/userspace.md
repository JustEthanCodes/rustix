# Userspace development guide

This guide describes the current, deliberately small userspace path. Rustix can launch its bundled static ELF init and exercise syscall-driven child processes, but it does not yet provide an installed application format, a filesystem-backed executable loader, or a general-purpose process environment.

## Components and ownership

- `crates/rustix-user` is an `x86_64`-only `no_std` library. It provides typed syscall wrappers, the ABI version constant, process entry support, bounded console output and formatting helpers, panic reporting, and an optional allocator backed by Rustix anonymous mappings.
- `crates/rustix-init/src/main.rs` contains the bundled init and the diagnostic child/fault variants built from the same source.
- `build.rs` builds the runtime and static user ELF payloads for `x86_64-unknown-none`, then embeds the normal init image into the kernel build. These payloads are build artifacts under Cargo's output directory; they are not separate installable programs.
- `src/elf.rs` validates and loads the supported static ELF64 format, and `src/process.rs` prepares a private process root, image, guard page, and initial stack. The syscall dispatcher and ABI contract are documented in [Process runtime and syscall ABI](../architecture/syscall-abi.md).

The kernel owns process records, page tables, physical frames, and user-memory access. A user process may pass a virtual pointer to a syscall, but must not assume that the kernel trusts or directly dereferences it. Syscall wrappers reduce register-level calling mistakes; they do not replace kernel validation or turn arbitrary pointers into safe Rust references.

## What a userspace program can rely on today

The implemented ABI reports version `0x0001_0001` with syscall 0. Its current bounded syscall set includes:

- `write` to the initial console output streams, with short writes possible;
- `exit` and child `wait` with optional status copy-out;
- process-local console descriptor `close` and `dup`;
- zeroed read/write, non-executable anonymous mappings (`mmap` and bounded multi-page `mmap_region`) and exact unmapping;
- `spawn` from a user-provided static ELF image and non-returning `exec` replacement.

The ABI guide is the source of truth for register arguments, stable negative error values, limits, pointer rules, and edge-case behavior. Do not infer support from a wrapper or constant alone: consult the call's implementation and tests. In particular, there is no `read`, `open`, filesystem access, command execution service, signal model, or general file-object interface yet.

The runtime's supported execution model is constrained:

- x86_64 Ring 3, one CPU, cooperative process switching, and IF disabled while user code runs;
- at most four active process slots, including init;
- static, non-interpreted ELF64 images, bounded by the parser's segment/program-header/page limits;
- an initial stack of 1–16 zeroed pages with an unmapped guard;
- user mappings confined to the lower canonical half and constrained by permission metadata and W^X policy;
- process roots with private user mappings but shared supervisor-only upper-half mappings derived from Limine's hierarchy.

These constraints are not general-purpose userspace guarantees, a POSIX environment, or a complete security boundary. See [Security policy](../security.md) for the trust and isolation limits.

## Runtime conventions

Prefer the typed API in `rustix-user` over raw inline assembly. The ABI returns nonnegative success values and negative error numbers in `RAX`; wrappers expose the result through their Rust return types. A successful write may consume fewer bytes than requested, so output code that needs complete delivery must retry the unwritten suffix and handle a no-progress/error result. Do not assume console output is input, or that descriptor 0 is currently readable.

The optional `UserAllocator` obtains pages from the anonymous mapping syscalls and subdivides them into bounded size classes. It is opt-in: programs that use `alloc`-based collections must provide this allocator (or another supported allocator) and must respect its size/alignment limits. Mapped allocator pages are retained until process teardown; there is no per-allocation page return. Allocation failure must be handled within the program's available policy; the kernel process boundary does not make infallible allocation safe.

`run_main` is the runtime's process-entry helper. Panic reporting is best effort because the process may be unable to write, and a panic is not a recoverable process-control mechanism. Applications should check ABI discovery and syscall results explicitly and use `exit` with a deliberate status.

## Build and validation workflow

From the repository root:

```sh
just fmt
just test
just check
just build
just smoke
just process-smoke
just user-fault-smoke
just verify
```

`just build` compiles the kernel and the build script's bundled payloads. `just smoke` exercises ordinary boot. `just process-smoke` uses a diagnostic process image to test syscall behavior, spawn/wait/exec, bounded capacity, and teardown. `just user-fault-smoke` validates selected user-fault termination paths. `just verify` runs the repository's full prescribed suite; consult the [testing guide](testing.md) for the exact checks and their limitations.

There is not yet a supported standalone application packaging/install command. To add a user-program experiment, first extend the existing payload build path deliberately, document its ELF and embedding contract, and add host tests for parsing/rollback plus a QEMU lifecycle check. Avoid changing `build.rs` payload variants as if they were a stable third-party application interface. Keep diagnostic fault payloads isolated to opt-in features and ensure the normal build still embeds the intended init.

## Extending the ABI safely

Before adding a syscall, update the contract in `docs/architecture/syscall-abi.md` and specify:

1. A new, never-reused syscall number and ABI versioning policy.
2. Argument widths, register mapping, result/error values, and partial-progress behavior.
3. User-pointer range, alignment, permission, and copy-in/copy-out rules.
4. Ownership and cleanup behavior on success, failure, process exit, and retry.
5. Fixed limits and how exhaustion is reported.
6. Host-side negative tests and an integration smoke for the live privilege boundary.

Do not change existing v1 meanings to make a new operation convenient. Keep syscall handlers bounded and allocation behavior explicit; user pointers and ELF bytes remain untrusted even when they originate from another Rustix process.

## Related documentation

- [Process runtime and syscall ABI](../architecture/syscall-abi.md)
- [Architecture overview](../architecture/overview.md)
- [Security and unsafe-code policy](../security.md)
- [Build and toolchain guide](building.md)
- [Testing and verification](testing.md)
- [Roadmap and acceptance criteria](../roadmap/README.md)
