kernel_target := "x86_64-unknown-none"

# List the common development tasks.
help:
    @just --list

# Format all Rust sources and fail if formatting changes are needed.
fmt:
    cargo fmt --all -- --check

# Check the freestanding kernel for the target architecture.
check:
    cargo check --target {{kernel_target}}

# Build the optimized kernel ELF for the target architecture.
build:
    cargo build --release --target {{kernel_target}}

# Build the optimized kernel ELF with full debug symbols for CodeLLDB.
debug-build:
    cargo build --release --target {{kernel_target}} --config profile.release.debug=true

# Create a debug-symbol-enabled Limine ISO.
debug-image: debug-build
    python3 scripts/boot.py image

# Run QEMU paused with a loopback-only GDB stub for Zed/CodeLLDB.
debug-run: debug-image
    python3 scripts/boot.py debug

# Build a pinned Limine BIOS/UEFI hybrid ISO. Requires Python 3 and xorriso.
image: build
    python3 scripts/boot.py image

# Boot the ISO in QEMU's default BIOS mode and verify Crabshell's prompt.
smoke: image
    python3 scripts/boot.py smoke

# Boot the ISO with OVMF and verify ACPI MADT, CR3 transition, and prompt.
uefi-smoke: image
    python3 scripts/boot.py uefi-smoke

# Probe active owned-page mappings and TLB invalidation in QEMU, then restore the default image.
active-map-smoke:
    python3 scripts/boot.py active-map-smoke

# Probe checked HHDM access, inherited mappings, and an inactive candidate root in QEMU.
frame-smoke:
    python3 scripts/boot.py frame-smoke

# Run bundled init in Ring 3 and verify syscalls, nested spawn, reuse, exec, and teardown in QEMU.
process-smoke:
    python3 scripts/boot.py process-smoke

# Inject a normal-boot userspace launch failure and verify report + shell fallback in QEMU.
userspace-failure-smoke:
    python3 scripts/boot.py userspace-failure-smoke

# Terminate Ring 3 processes on #PF/#GP/#UD/#DE and verify wait/reap plus teardown in QEMU.
user-fault-smoke:
    python3 scripts/boot.py user-fault-smoke

# Exercise IRQ-safe locking, cooperative waits, timer preemption, and FPU state in OVMF.
thread-smoke:
    python3 scripts/boot.py thread-smoke

# Exercise UART and PS/2 IRQ input waking the cooperative shell in OVMF.
input-smoke: image
    python3 scripts/boot.py input-smoke

# Inject controlled exceptions in QEMU, then restore the default release image.
fault-smoke:
    python3 scripts/boot.py fault-smoke

# Run Crabshell interactively over the host terminal's serial connection.
run: image
    python3 scripts/boot.py run

# Run host-side unit tests for architecture-independent kernel and shell code.
test:
    cargo test --workspace --lib

# Run formatting, host tests, target checks, and the boot, scheduler, input, and process QEMU smokes.
verify: fmt test check smoke uefi-smoke active-map-smoke thread-smoke input-smoke fault-smoke process-smoke userspace-failure-smoke user-fault-smoke
