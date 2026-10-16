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

# Build a pinned Limine BIOS/UEFI hybrid ISO. Requires Python 3 and xorriso.
image: build
    python scripts/boot.py image

# Boot the ISO in QEMU and verify Crabshell's prompt within 20 seconds.
smoke: image
    python scripts/boot.py smoke

# Run Crabshell interactively over the host terminal's serial connection.
run: image
    python scripts/boot.py run

# Run host-side unit tests for architecture-independent kernel and shell code.
test:
    cargo test --workspace --lib

# Run formatting, host tests, target checks, image creation, and QEMU smoke test.
verify: fmt test check smoke
