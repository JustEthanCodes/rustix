# Interrupts and IRQ vector allocation

## Current implementation

`src/arch/x86_64/interrupts.rs` installs the bootstrap GDT, TSS, exception gates for vectors 0–31, device IRQ stubs, and the APIC spurious-vector gate. Exceptions remain fatal-only. Maskable interrupts start disabled and are enabled only after the validated APIC route, registered handler, and acknowledgement path are ready.

`src/irq.rs` provides a host-tested, allocation-free token allocator for device vectors `0x20..=0xef`; exception vectors and the reserved upper range are excluded. `rustix_irq_dispatch` invokes the registered handler, returns for the APIC spurious vector without EOI, and halts on unregistered/unexpected vectors. Device handlers own their EOI. Vector registration is performed with IF clear before the corresponding I/O APIC source is unmasked.

The initial hardware target is single-vCPU QEMU `q35`: validated ACPI/MADT topology, local APIC and I/O APIC, masked legacy PIC routing, MADT-resolved ISA routes, and a periodic 8254 PIT tick near 100 Hz. OVMF smokes validate PIT delivery/EOI, non-yielding timer preemption, x87/SSE state preservation, and UART/keyboard IRQ delivery. Host tests cover vector ownership and PIT/time arithmetic; they do not replace privileged QEMU coverage.

The scheduler is single-vCPU and supports cooperative waits/yields plus PIT-driven timer preemption. The timer handler advances ticks and sends APIC EOI before any scheduling switch. The common IRQ stub saves the interrupted x87/SSE state before Rust dispatch and restores the selected context before `IRETQ`; the context switch keeps aligned per-context FXSAVE areas. IRQ-safe spin locks save and restore the prior IF state, and the global heap uses one; scheduler mutations are separately serialized by masking local interrupts. IRQ/exception handlers remain bounded and allocation-free, and no current IRQ handler acquires the heap lock. SMP, per-CPU state, and physical-hardware validation remain future work.
