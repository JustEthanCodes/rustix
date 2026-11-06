# Interrupts and IRQ vector allocation

## Current implementation

`src/arch/x86_64/interrupts.rs` installs the bootstrap GDT, TSS, and IDT gates for architectural exception vectors 0–31. Exceptions are fatal-only. Bootstrap leaves maskable interrupts disabled; there is no PIC/APIC initialization, IRQ entry/dispatch, acknowledgement, or return path.

`src/irq.rs` provides a host-tested, allocation-free token allocator for device vectors `0x20..=0xef`. Exception vectors `0x00..=0x1f` and the upper range `0xf0..=0xff` are reserved. Allocation is bounded and deterministic; releasing an invalid token returns it without changing allocator state. The caller must maintain one allocator per CPU vector namespace and return tokens to their originating allocator.

The allocator only reserves numbers. It does not install IDT entries or establish that a controller is configured to deliver a vector. Future IRQ registration must couple vector-token ownership with a valid interrupt gate and controller route; sources must remain masked until dispatch and end-of-interrupt handling are ready. Do not enable interrupts as a side effect of installing gates.

## Required IRQ path

The initial hardware target remains one-vCPU QEMU `q35`: validated ACPI/MADT topology, local APIC and I/O APIC setup, legacy PIC masking, IRQ-specific interrupt entry/return, vector ownership, masking/unmasking, EOI, spurious and unexpected IRQ policy, and the PIT tick. A controller route may be unmasked only after its gate, handler, and acknowledgement path are installed and validated. Host tests can check vector and routing policy; QEMU is required for privileged entry, MMIO/port-I/O, delivery, acknowledgement, and timing behavior.

The fixed kernel heap remains forbidden in IRQ and exception context. Until IRQ-safe synchronization and bounded work are established, handlers must not allocate, block, log via unbounded paths, or take locks that interrupted code can hold.
