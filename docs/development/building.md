# Building Rustix

## Prerequisites

- Rust stable with `rustfmt`; the repository pins these in `rust-toolchain.toml`.
- The `x86_64-unknown-none` target. The toolchain file requests it automatically; if needed, install it with `rustup target add x86_64-unknown-none`.
- [`just`](https://just.systems/) to run the repository's named tasks.
- Python 3.8 or newer (standard library only), with `python` on `PATH`; `xorriso`; and QEMU with `qemu-system-x86_64` for image creation and boot smoke tests.
- A C compiler providing `cc` on Linux/WSL to build Limine's host utility from the pinned archive; Windows uses the bundled `limine.exe`.

An ELF inspection tool such as `llvm-readelf` or `readelf` is useful when diagnosing linker output. The first image build downloads the pinned Limine v12.9.3 binary archive into `target/tools/` and verifies its published SHA-256 before extraction.

## Common commands

Run from the repository root:

```sh
just help
just fmt       # check Rust formatting
just test      # parser, RAM-filesystem, memory-map, paging policy, and frame-allocator tests
just check     # type-check the freestanding kernel target
just build       # optimized kernel ELF
just image       # hybrid BIOS/UEFI ISO at target/rustix.iso
just debug-build # optimized kernel ELF with full debug symbols
just debug-image # ISO built from the debug-symbol-enabled ELF
just debug-run   # paused QEMU with a loopback GDB stub for Zed/CodeLLDB
just smoke       # bounded QEMU boot to the Crabshell prompt
just frame-smoke # probe one owned frame through the HHDM, then restore the default image
just fault-smoke # inject page fault and invalid opcode, then restore the default image
just run         # interactive serial shell in QEMU (Ctrl+C to stop)
just verify      # fmt, workspace tests, target check, image, and QEMU smoke test
```

Equivalent Rust checks are `cargo fmt --all -- --check`, `cargo test --workspace --lib`, `cargo check --target x86_64-unknown-none`, and `cargo build --release --target x86_64-unknown-none`. Image creation and QEMU validation are provided by `scripts/boot.py` and are intentionally part of `just verify`.

The optimized ELF is written to `target/x86_64-unknown-none/release/rustix`. `cargo check` checks the target without producing a boot image. The library tests run on the host and exercise code that does not require privileged instructions.

## Target-specific linker setup

`.cargo/config.toml` applies the Rustix linker script and x86_64 kernel constraints only to `x86_64-unknown-none`. `linker.ld` emits an ELF64 x86_64 image at the higher-half base, retains Limine request sections in a writable load segment for bootloader response pointers, defines `_start` as an assembly entry shim, and exports the load-image boundary symbols consumed by `BootInfo`. The shim captures the initial stack pointer before entering Rust. The build uses no third-party Rust crates; the boot protocol is represented by small in-tree Rust structures and constants.

Changing the target, virtual base, relocation model, or request ABI requires updating the linker script, protocol documentation, and validation plan together. Do not use host builds of the kernel binary as evidence that the freestanding target links correctly.

## Building and smoke-testing a boot image

`limine.conf` boots the kernel immediately and enables 38,400-baud serial output. `just image` builds the ELF, fetches Limine v12.9.3's binary ZIP from its immutable GitHub release, checks the pinned SHA-256, prepares a BIOS/UEFI hybrid ISO, and installs the BIOS boot code. The Limine archive and extracted tools remain under ignored `target/`; no third-party binaries are checked into the source tree.

`just smoke` launches `target/rustix.iso` in `qemu-system-x86_64` with a 256 MiB q35 machine, headless display, captured COM1 output, and a 20-second deadline. QEMU is expected to remain running at the interactive shell; the runner terminates it at the deadline and requires the startup banner, Crabshell-ready message, and initial prompt. On a failure it prints the serial log. The log remains at `target/rustix-qemu-serial.log` for inspection.

`just run` launches the same image with the serial port attached to the host terminal, allowing interactive shell use. Stop the emulator with `Ctrl+C`.

## Debugging the kernel from Zed

On the Windows Zed workspace with the repository built through WSL2, run the `Rustix: QEMU Debug Server` task from the task picker. It builds the release ELF with full DWARF debug information, creates the ISO, and starts QEMU paused with its GDB stub bound only to `127.0.0.1:1234`. Then open Zed's debugger (`F4`) and start `Rustix: QEMU (CodeLLDB)`. The configuration loads the ELF from the Windows worktree, maps WSL compiler paths back to the workspace, and sets a breakpoint at `rustix_start`; continue once from the initial reset stop to reach the Rust entry function. Stop QEMU with `Ctrl+C` in its task terminal.

The debug build uses a per-command Cargo profile override and does not change the normal release profile. It writes to the usual release ELF and ISO paths, so a later `just build`, `just image`, or `just run` rebuilds the normal image. CodeLLDB remote debugging must be available in Zed. The GDB stub listens on loopback only; do not change this to a public interface.

`just verify` includes the emulator smoke test and therefore needs Python 3, xorriso, QEMU, network access for the first Limine download, and the Rust target. `.github/workflows/ci.yml` installs the system tools on Ubuntu 24.04 and runs the same command. This verifies the boot path in CI; it is still not a substitute for testing physical hardware.

## Troubleshooting

- **Target not installed:** install `x86_64-unknown-none` as shown above.
- **`just` not found:** install `just`; Rust-only checks can still be run with the Cargo commands above.
- **`xorriso` or QEMU not found:** install the host image/emulator tools listed in prerequisites, then retry `just image` or `just smoke`.
- **`cc` not found on Linux/WSL:** install a C compiler (for example, `build-essential` on Ubuntu), then retry `just image`.
- **Limine SHA-256 mismatch:** the pinned archive may have changed or been corrupted; the script removes the mismatched download and refuses to use it. Check the official v12.9.3 release digest before changing the pin.
- **Linker-script error:** build only for `x86_64-unknown-none`; confirm the invocation runs from the repository root so `linker.ld` resolves.
- **No serial output:** inspect `target/rustix-qemu-serial.log` and QEMU's stderr. The image config and Rustix COM1 driver both use 38,400 baud.
