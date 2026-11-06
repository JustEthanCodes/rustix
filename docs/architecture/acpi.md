# ACPI parsing foundation

## Current implementation

`src/acpi.rs` provides allocation-free helpers over caller-supplied byte slices:

- RSDP signature, legacy checksum, revision, bounded extended length, and extended checksum validation.
- System Description Table header, advertised-length, 64 KiB maximum-size, and checksum validation.
- Bounded, allocation-free RSDT/XSDT pointer-array views with entry-width, payload-length, null-entry, and count checks.
- Fixed-capacity copying of MADT local-APIC, I/O-APIC, interrupt-source-override, and local-APIC-address-override records.
- Structural rejection of malformed/truncated MADT records, unsupported x2APIC processor records, excessive entry counts, and fixed-array exhaustion.

The byte-slice parsers validate structures already present in memory. `read_madt` adds bounded allocation-free RSDP → RSDT/XSDT → MADT traversal over the unsafe `AcpiPhysicalReader` contract; it uses fixed scratch/root-pointer storage and validates advertised lengths and checksums before parsing. Host tests exercise the traversal algorithm. Boot now requests Limine's RSDP response and records its base-revision-3 physical address only after confirming that its initial 20-byte span and complete page-rounded mapping extent are covered by ACPI-reclaimable or ACPI NVS memory-map regions and fit the reported physical width. Before the permanent CR3 transition, boot implements the reader by mapping one validated ACPI page at a time read-only/NX into an unused virtual slot in the cloned candidate, switching CR3 with global-TLB flushing, copying bytes, restoring the prior root, and removing the borrowed mapping. It copies the parsed MADT into `BootInfo`; read/cache-policy failures leave the MADT unavailable and do not enable interrupts. This hardware path still requires QEMU validation. The parser itself never maps or dereferences physical addresses. Boot does not initialize APIC hardware, configure interrupt routing, or enable interrupts.

## Required safe reader before hardware setup

`MemoryMap::validate_acpi_span` bounds an ACPI byte span to 64 KiB, rounds it to 4 KiB mapping pages with checked arithmetic, and returns a validated physical mapping extent only if every byte of those pages is ACPI-reclaimable or ACPI NVS and within the known physical width. The generic `read_madt` traversal enumerates bounded RSDT/XSDT entries without allocation; the boot reader validates each read span against the memory map and obtains a temporary read-only/NX mapping before reading it. The reader does not use the HHDM or frame allocator as authorization to access ACPI physical addresses. Boot copies only the parsed MADT into owned state; FADT data and a general ACPI mapping service remain future work. ACPI memory remains reserved until required table data has been copied and a separate reclamation policy is implemented.

MADT parsing currently supports the xAPIC processor records needed for the initial one-vCPU QEMU target. x2APIC processor records fail explicitly rather than being silently treated as xAPIC. The parser rejects invalid local-APIC flags, zero/unaligned controller addresses, duplicate local-APIC identities and I/O-APIC IDs, duplicate source overrides, and reserved/invalid override-flag encodings. It does not establish that controller MMIO spans are mapped or safe, detect overlapping I/O-APIC GSI windows (which require controller version reads), or initialize hardware; those checks and policies remain prerequisites for IRQ routing.
