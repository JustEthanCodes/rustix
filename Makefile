.DEFAULT_GOAL := help

CARGO ?= cargo
PYTHON ?= python3
KERNEL_TARGET ?= x86_64-unknown-none

.PHONY: help fmt test check build debug-build debug-image debug-run image smoke uefi-smoke \
	active-map-smoke frame-smoke process-smoke user-fault-smoke thread-smoke \
	input-smoke fault-smoke run verify

help:
	@printf '%s\n' \
		'Rustix development targets:' \
		'  fmt                 Check Rust formatting' \
		'  test                Run host-side library tests' \
		'  check               Check the freestanding kernel target' \
		'  build               Build the optimized kernel ELF' \
		'  image               Build the BIOS/UEFI hybrid ISO' \
		'  smoke               Run the BIOS boot smoke test' \
		'  uefi-smoke          Run the OVMF boot smoke test' \
		'  verify              Run the full verification sequence'

fmt:
	$(CARGO) fmt --all -- --check

test:
	$(CARGO) test --workspace --lib

check:
	$(CARGO) check --target $(KERNEL_TARGET)

build:
	$(CARGO) build --release --target $(KERNEL_TARGET)

debug-build:
	$(CARGO) build --release --target $(KERNEL_TARGET) --config profile.release.debug=true

debug-image: debug-build
	$(PYTHON) scripts/boot.py image

debug-run: debug-image
	$(PYTHON) scripts/boot.py debug

image: build
	$(PYTHON) scripts/boot.py image

smoke: image
	$(PYTHON) scripts/boot.py smoke

uefi-smoke: image
	$(PYTHON) scripts/boot.py uefi-smoke

active-map-smoke:
	$(PYTHON) scripts/boot.py active-map-smoke

frame-smoke:
	$(PYTHON) scripts/boot.py frame-smoke

process-smoke:
	$(PYTHON) scripts/boot.py process-smoke

user-fault-smoke:
	$(PYTHON) scripts/boot.py user-fault-smoke

thread-smoke:
	$(PYTHON) scripts/boot.py thread-smoke

input-smoke: image
	$(PYTHON) scripts/boot.py input-smoke

fault-smoke:
	$(PYTHON) scripts/boot.py fault-smoke

run: image
	$(PYTHON) scripts/boot.py run

# Run sequentially: QEMU probes rebuild shared kernel/image artifacts.
verify:
	$(MAKE) fmt
	$(MAKE) test
	$(MAKE) check
	$(MAKE) smoke
	$(MAKE) uefi-smoke
	$(MAKE) active-map-smoke
	$(MAKE) thread-smoke
	$(MAKE) input-smoke
	$(MAKE) fault-smoke
	$(MAKE) process-smoke
	$(MAKE) user-fault-smoke
