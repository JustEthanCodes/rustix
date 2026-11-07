# Interrupts and IRQ vector allocation

## Current implementation

`src/arch/x86_64/interrupts.rs` installs the bootstrap GDT, TSS, exception gates for vectors 0–31, device IRQ stubs, and the APIC spurious-vector gate. Exceptions remain fatal-only. Maskable interrupts start disabled and are enabled only after the validated APIC route, registered handler, and acknowledgement path are ready.

`src/irq.rs` provides a host-tested, allocation-free token allocator for device vectors `0x20..=0xef`; exception vectors and the reserved upper range are excluded. `rustix_irq_dispatch` invokes the registered handler, returns for the APIC spurious vector without EOI, and halts on unregistered/unexpected vectors. Device handlers own their EOI. Vector registration is performed with IF clear before the corresponding I/O APIC source is unmasked.

The initial hardware target is single-vCPU QEMU `q35`: validated ACPI/MADT topology, local APIC and I/O APIC, masked legacy PIC routing, MADT-resolved ISA routes, and a periodic 8254 PIT tick near 100 Hz. OVMF smokes validate PIT delivery/EOI and UART/keyboard IRQ delivery. Host tests cover vector ownership and PIT/time arithmetic; they do not replace privileged QEMU coverage.

The scheduler is cooperative and single-vCPU; timer IRQs only update the atomic tick counter and acknowledge the APIC. IRQ and exception handlers are bounded, allocation-free, and do not block or schedule. The global heap is explicitly not IRQ-safe. Timer preemption, SMP, and the IRQ-safe locking rules needed before either remain future work.
