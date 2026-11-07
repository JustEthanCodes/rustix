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
    python scripts/boot.py image

# Run QEMU paused with a loopback-only GDB stub for Zed/CodeLLDB.
debug-run: debug-image
    python scripts/boot.py debug

# Build a pinned Limine BIOS/UEFI hybrid ISO. Requires Python 3 and xorriso.
image: build
    python scripts/boot.py image

# Boot the ISO in QEMU's default BIOS mode and verify Crabshell's prompt.
smoke: image
    python scripts/boot.py smoke

# Boot the ISO with OVMF and verify ACPI MADT, CR3 transition, and prompt.
uefi-smoke: image
    python scripts/boot.py uefi-smoke

# Probe active owned-page mappings and TLB invalidation in QEMU, then restore the default image.
active-map-smoke:
    python scripts/boot.py active-map-smoke

# Probe checked HHDM access, inherited mappings, and an inactive candidate root in QEMU.
frame-smoke:
    python scripts/boot.py frame-smoke

# Exercise cooperative thread switching and wait queues in OVMF, then restore the default image.
thread-smoke:
    python scripts/boot.py thread-smoke

# Exercise UART and PS/2 IRQ input waking the cooperative shell in OVMF.
input-smoke: image
    python scripts/boot.py input-smoke

# Inject controlled exceptions in QEMU, then restore the default release image.
fault-smoke:
    python scripts/boot.py fault-smoke

# Run Crabshell interactively over the host terminal's serial connection.
run: image
    python scripts/boot.py run

# Run host-side unit tests for architecture-independent kernel and shell code.
test:
    cargo test --workspace --lib

# Run formatting, host tests, target checks, and the Milestone 3 QEMU smoke suite.
verify: fmt test check smoke uefi-smoke active-map-smoke thread-smoke input-smoke
