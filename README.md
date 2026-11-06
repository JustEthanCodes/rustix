# Rustix

Rustix (Rust-unix) is an experimental, 64-bit, Unix-like operating system whose kernel is written in Rust. This repository builds the kernel itself; Limine is used only as the external boot protocol/loader, not as a substitute for a Rustix kernel.

Rustix now boots into **Crabshell**, a small kernel-mode shell on the COM1 serial terminal. It includes basic navigation and file commands backed by a fixed-capacity RAM filesystem. The filesystem is volatile and reset at every boot; this is an early kernel shell, not a userspace process or POSIX shell. The command parser lives in a separate, allocation-free `crabshell` crate so a future GUI terminal can reuse it. Scheduling, process isolation, persistent storage, a syscall ABI, networking, and userspace are still future work. See [`docs/roadmap/README.md`](docs/roadmap/README.md) for the staged plan.

## Quick start

Prerequisites: a Rust stable toolchain, `just`, Python 3, `xorriso`, QEMU (`qemu-system-x86_64`), and the target installed by `rust-toolchain.toml` (or `rustup target add x86_64-unknown-none`). The first image build downloads a pinned Limine binary release and verifies its SHA-256.

For a ready-to-use environment with these tools installed, open the repository in a Dev Container using `.devcontainer/`. The container uses Ubuntu 24.04 and includes the Rust target and `rustfmt` component from `rust-toolchain.toml`.

```sh
just help
just fmt
just test
just check
just build
just image
just smoke
just run       # interactive serial shell in QEMU; exit with Ctrl+C
just verify
```

`just build` produces `target/x86_64-unknown-none/release/rustix`. `just image` creates `target/rustix.iso`, a hybrid BIOS/UEFI image; `just smoke` checks that Crabshell reaches its prompt; and `just run` starts an interactive QEMU session attached to the current terminal.

Try `pwd`, `ls /`, `mkdir notes`, `write notes/hello.txt "hello from Rustix"`, `cat notes/hello.txt`, and `cd ..` in Crabshell. Commands include `help`, `clear`, `pwd`, `meminfo`, `ls`, `cd`, `mkdir`, `touch`, `write`, `append`, `cp`, `mv`, `cat`, `rm`, and `rmdir`. The RAM filesystem holds at most 31 entries plus its root, with files capped at 1024 bytes. See [`docs/architecture/crabshell.md`](docs/architecture/crabshell.md) for the shell and filesystem contract, [`docs/development/building.md`](docs/development/building.md) for build/emulator details, and [`docs/index.md`](docs/index.md) for the documentation map.

## Project principles

- The kernel and operating-system implementation are Rust-first and `no_std`; architecture-specific privileged operations are isolated under `src/arch/`.
- The kernel is the product. A bootloader may initialize the machine and transfer control, but policy, memory management, scheduling, and Unix-like services belong to Rustix.
- Keep unsafe code small, documented, and adjacent to its hardware/protocol boundary.
- Build incrementally: every roadmap milestone should have build checks, tests where practical, and updated design documentation.
- Unix-like behavior is an explicit compatibility goal, not a claim of POSIX compliance today.

## Repository map

- `src/main.rs` — freestanding kernel entry point and Crabshell handoff.
- `src/shell.rs` — serial line editor and kernel command executor.
- `src/vfs.rs` — fixed-capacity volatile RAM filesystem, with host-side tests.
- `crates/crabshell/` — separate `no_std` command parser crate; no I/O or filesystem coupling.
- `src/boot.rs` — mutable Limine response requests, validated owned boot snapshot, and diagnostics.
- `src/arch/x86_64/serial.rs` — COM1 polling driver used for shell output and input.
- `src/arch/x86_64/cpu.rs` — baseline CPUID vendor and feature reporting.
- `src/arch/x86_64/interrupts.rs` — bootstrap GDT/TSS/IDT and fatal exception diagnostics.
- `src/arch/x86_64/keyboard.rs` — raw, non-blocking PS/2-compatible scancode polling.
- `src/arch/x86_64/io.rs` — narrow x86 port-I/O wrappers.
- `src/memory.rs` — fixed-capacity validated physical-memory-map snapshot and host tests.
- `src/frame.rs` — bounded physical frame allocator initialized from `BootInfo`; no kernel service allocates frames yet.
- `.cargo/config.toml`, `linker.ld` — x86_64-none code generation and ELF layout.
- `justfile` — formatting, tests, target checks, image creation, emulator smoke test, and aggregate verification.
- `limine.conf` — pinned boot configuration for the Rustix kernel.
- `scripts/boot.py` — checksum-verified Limine download, hybrid ISO assembly, and bounded QEMU validation.
- `.github/workflows/ci.yml` — runs `just verify` on pushes and pull requests.
- `docs/` — architecture, drivers, development, security, and roadmap documentation.
