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

# Boot the ISO in QEMU and verify Crabshell's prompt within 20 seconds.
smoke: image
    python scripts/boot.py smoke

# Probe checked HHDM access, inherited mappings, and an inactive candidate root in QEMU.
frame-smoke:
    python scripts/boot.py frame-smoke

# Inject controlled exceptions in QEMU, then restore the default release image.
fault-smoke:
    python scripts/boot.py fault-smoke

# Run Crabshell interactively over the host terminal's serial connection.
run: image
    python scripts/boot.py run

# Run host-side unit tests for architecture-independent kernel and shell code.
test:
    cargo test --workspace --lib

# Run formatting, host tests, target checks, image creation, and QEMU smoke test.
verify: fmt test check smoke
