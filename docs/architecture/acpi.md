# ACPI parsing foundation

## Current implementation

`src/acpi.rs` provides allocation-free helpers over caller-supplied byte slices:

- RSDP signature, legacy checksum, revision, bounded extended length, and extended checksum validation.
- System Description Table header, advertised-length, 64 KiB maximum-size, and checksum validation.
- Bounded, allocation-free RSDT/XSDT pointer-array views with entry-width, payload-length, null-entry, and count checks.
- Fixed-capacity copying of MADT local-APIC, I/O-APIC, interrupt-source-override, and local-APIC-address-override records.
- Structural rejection of malformed/truncated MADT records, unsupported x2APIC processor records, excessive entry counts, and fixed-array exhaustion.

The byte-slice parsers validate structures already present in memory. `read_madt` adds bounded allocation-free RSDP → RSDT/XSDT → MADT traversal over the unsafe `AcpiPhysicalReader` contract; it uses fixed scratch/root-pointer storage and validates advertised lengths and checksums before parsing. Host tests exercise the traversal algorithm. Boot now requests Limine's RSDP response and records its base-revision-3 physical address only after confirming that its initial 20-byte span and complete page-rounded mapping extent are covered by ACPI-reclaimable or ACPI NVS memory-map regions and fit the reported physical width. Before the permanent CR3 transition, boot maps one validated ACPI page at a time read-only/NX into an unused slot in the cloned candidate, switches CR3 with global-TLB flushing, copies bytes, restores the prior root, and removes the borrowed mapping. It copies the parsed MADT into `BootInfo`; read/cache-policy failures leave the MADT unavailable and do not enable interrupts. OVMF QEMU validation reports the copied MADT and exercises the resulting APIC routing. The parser itself never maps or dereferences physical addresses. ACPI handling does not read FADT data or provide a general ACPI mapping service.

## Reader bounds and remaining limits

`MemoryMap::validate_acpi_span` bounds an ACPI byte span to 64 KiB, rounds it to 4 KiB mapping pages with checked arithmetic, and returns a validated physical mapping extent only if every byte of those pages is ACPI-reclaimable or ACPI NVS and within the known physical width. The generic `read_madt` traversal enumerates bounded RSDT/XSDT entries without allocation; the boot reader validates each read span against the memory map and obtains a temporary read-only/NX mapping before reading it. The reader does not use the HHDM or frame allocator as authorization to access ACPI physical addresses. Boot copies only the parsed MADT into owned state; FADT data and a general ACPI mapping service remain future work. ACPI memory remains reserved until required table data has been copied and a separate reclamation policy is implemented.

MADT parsing supports the xAPIC records and interrupt-source overrides needed for the initial one-vCPU QEMU target. x2APIC processor records fail explicitly rather than being silently treated as xAPIC. The parser rejects invalid local-APIC flags, zero/unaligned controller addresses, duplicate local-APIC identities and I/O-APIC IDs, duplicate source overrides, and reserved/invalid override-flag encodings. Boot validates and maps the specific controller MMIO pages as supervisor RW/NX with an effective UC cache type, then initializes the APIC path. Multi-I/O-APIC GSI-window discovery, x2APIC, FADT power control, and a general ACPI mapping service remain out of scope.
