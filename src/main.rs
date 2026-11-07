#![no_std]
#![no_main]

#[cfg(any(
    all(feature = "inject-page-fault", feature = "inject-invalid-opcode"),
    all(feature = "inject-page-fault", feature = "probe-hhdm-frame"),
    all(feature = "inject-invalid-opcode", feature = "probe-hhdm-frame"),
    all(feature = "probe-kernel-threads", feature = "inject-page-fault"),
    all(feature = "probe-kernel-threads", feature = "inject-invalid-opcode"),
    all(feature = "probe-kernel-threads", feature = "probe-hhdm-frame"),
    all(feature = "probe-kernel-threads", feature = "probe-active-mapping")
))]
compile_error!("opt-in QEMU diagnostic features are mutually exclusive");

mod arch;
mod boot;
mod kernel_threads;
mod shell;

use core::hint::spin_loop;
use core::panic::PanicInfo;
use rustix_kernel::time::{AtomicTickCounter, PitRate};
use rustix_kernel::vfs::RamFs;

const LOCAL_APIC_VIRTUAL_ADDRESS: u64 = 0xffff_c100_0000_0000;
const IO_APIC_VIRTUAL_ADDRESS: u64 = LOCAL_APIC_VIRTUAL_ADDRESS + rustix_kernel::paging::PAGE_SIZE;
const KERNEL_HEAP_GROWTH_VIRTUAL_BASE: u64 = 0xffff_c200_0000_0000;
const KERNEL_HEAP_GROWTH_MAX_PAGES: usize = 256;

static BOOTSTRAP_TIMER_TICKS: AtomicTickCounter = AtomicTickCounter::new();
static mut RAM_FILESYSTEM: RamFs = RamFs::new();

#[global_allocator]
static KERNEL_HEAP: rustix_kernel::heap::KernelHeap = rustix_kernel::heap::KernelHeap::new();

macro_rules! kprintln {
    () => {{
        crate::arch::x86_64::serial::print(format_args!("\r\n"));
    }};
    ($($argument:tt)*) => {{
        crate::arch::x86_64::serial::print(format_args!($($argument)*));
        crate::arch::x86_64::serial::print(format_args!("\r\n"));
    }};
}

pub(crate) use kprintln;

struct LimineHhdmPageTableReader<'a> {
    memory_map: &'a rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: u8,
    virtual_address_bits: u8,
}

impl rustix_kernel::paging::PageTableReader for LimineHhdmPageTableReader<'_> {
    type Error = rustix_kernel::memory::HhdmAddressError;

    fn read_entry(&self, table_physical: u64, index: u16) -> Result<u64, Self::Error> {
        if index >= 512 {
            return Err(rustix_kernel::memory::HhdmAddressError::InvalidHhdmRange);
        }
        let table_end = table_physical
            .checked_add(rustix_kernel::paging::PAGE_SIZE)
            .ok_or(rustix_kernel::memory::HhdmAddressError::AddressOverflow)?;
        if !self.memory_map.range_is_within_region_kind(
            table_physical,
            table_end,
            rustix_kernel::memory::RegionKind::BootloaderReclaimable,
        ) {
            return Err(rustix_kernel::memory::HhdmAddressError::NotLimineMapped);
        }
        let table_address = self.memory_map.limine_hhdm_address(
            self.hhdm_offset,
            table_physical,
            rustix_kernel::paging::PAGE_SIZE,
            Some(self.physical_address_bits),
            self.virtual_address_bits,
        )?;
        let entry_address = table_address
            .checked_add(u64::from(index) * core::mem::size_of::<u64>() as u64)
            .ok_or(rustix_kernel::memory::HhdmAddressError::AddressOverflow)?;
        // SAFETY: The complete table page was restricted to bootloader-reclaimable
        // memory and its HHDM address arithmetic was checked. The reader relies
        // on the Limine base-revision-3 mapping contract and never returns a ref.
        Ok(unsafe { (entry_address as *const u64).read_volatile() })
    }
}

struct LimineHhdmCandidateMemory<'a> {
    memory_map: &'a rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: u8,
    virtual_address_bits: u8,
}

// SAFETY: `prepare_table` accepts only an allocator-issued frame and validates
// its complete usable span and HHDM address. Handles are only used while the
// candidate retains the frame token and this unique backend borrow.
unsafe impl rustix_kernel::paging::CandidatePageTableMemory for LimineHhdmCandidateMemory<'_> {
    type PreparedTable = u64;
    type Error = rustix_kernel::memory::HhdmAddressError;

    fn prepare_table(
        &mut self,
        frame: &rustix_kernel::frame::Frame,
    ) -> Result<Self::PreparedTable, Self::Error> {
        frame.hhdm_address(
            self.memory_map,
            self.hhdm_offset,
            Some(self.physical_address_bits),
            self.virtual_address_bits,
        )
    }

    unsafe fn read_entry(
        &self,
        table: Self::PreparedTable,
        index: u16,
    ) -> Result<u64, Self::Error> {
        if index >= 512 {
            return Err(rustix_kernel::memory::HhdmAddressError::InvalidHhdmRange);
        }
        let entry_address = table
            .checked_add(u64::from(index) * core::mem::size_of::<u64>() as u64)
            .ok_or(rustix_kernel::memory::HhdmAddressError::AddressOverflow)?;
        // SAFETY: The unsafe trait contract requires `table` to be the prepared
        // HHDM address of a complete writable frame; the index is in [0, 512).
        Ok(unsafe { (entry_address as *const u64).read_volatile() })
    }

    unsafe fn clear_table(&mut self, table: Self::PreparedTable) {
        let entries = table as *mut u64;
        // SAFETY: The caller provides a handle prepared by this backend for a
        // complete writable frame retained by its candidate.
        unsafe {
            for index in 0..512 {
                entries.add(index).write_volatile(0);
            }
        }
    }

    unsafe fn write_entry(&mut self, table: Self::PreparedTable, index: u16, value: u64) {
        if index >= 512 {
            return;
        }
        let entry = (table as *mut u64).wrapping_add(usize::from(index));
        // SAFETY: The caller provides a prepared complete frame and an index in
        // range; this writes one entry without creating a Rust reference.
        unsafe { entry.write_volatile(value) };
    }

    unsafe fn invalidate_page(&mut self, virtual_address: u64) {
        // SAFETY: Active mapping callers provide the current virtual page and run
        // at CPL 0 with exclusive local page-table ownership.
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) virtual_address,
                options(nostack, preserves_flags)
            );
        }
    }
}

struct KernelHeapMappingContext {
    candidate: *mut (),
    allocator: *mut rustix_kernel::frame::FrameAllocator,
    cpu_info: *const arch::x86_64::cpu::CpuInfo,
}

unsafe fn map_kernel_heap_pages(
    opaque_context: *mut (),
    first_page: usize,
    page_count: usize,
) -> bool {
    use rustix_kernel::paging::{
        validate_mapping_range, CachePolicy, CandidatePageTables, EffectiveMemoryType, MtrrState,
        PagePermissions, PatLayout, PAGE_SIZE,
    };

    if page_count == 0
        || first_page
            .checked_add(page_count)
            .is_none_or(|end| end > KERNEL_HEAP_GROWTH_MAX_PAGES)
    {
        return false;
    }

    // SAFETY: The caller configures this callback only after the active root,
    // allocator, CPU snapshot, and local context are all live. The boot path is
    // single-vCPU and never returns from the stack containing that context.
    let state = unsafe { &mut *opaque_context.cast::<KernelHeapMappingContext>() };
    // SAFETY: These pointers refer to the retained local candidate and BootInfo
    // members. The callback is synchronous and never stores a derived reference.
    let candidate = unsafe {
        &mut *state
            .candidate
            .cast::<CandidatePageTables<'static, LimineHhdmCandidateMemory<'static>>>()
    };
    // SAFETY: The frame allocator and CPU snapshot remain owned by retained
    // BootInfo; this callback runs on the sole CPU with the heap lock held.
    let allocator = unsafe { &mut *state.allocator };
    // SAFETY: The CPU snapshot is immutable and remains live with BootInfo.
    let cpu_info = unsafe { &*state.cpu_info };

    let flags: u64;
    // SAFETY: The callback runs at CPL 0; save IF before disabling local IRQs
    // while the active page tables and allocator are mutated.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    let result = (|| {
        let physical_width = cpu_info.physical_address_bits?;
        let pat = PatLayout::from_msr_value(cpu_info.pat_msr_value?).ok()?;
        let mtrrs = match &cpu_info.mtrr {
            MtrrState::Captured(registers) => registers.validated_layout(physical_width).ok()?,
            _ => return None,
        };
        let permissions = PagePermissions {
            writable: true,
            executable: false,
            user_accessible: false,
        };
        let mut mapped = 0usize;
        for page in first_page..first_page + page_count {
            let virtual_address = KERNEL_HEAP_GROWTH_VIRTUAL_BASE
                .checked_add((page as u64).checked_mul(PAGE_SIZE)?)?;
            let frame = match allocator.allocate() {
                Some(frame) => frame,
                None => {
                    rollback_kernel_heap_pages(candidate, allocator, first_page, mapped);
                    return None;
                }
            };
            let mapping = match validate_mapping_range(
                virtual_address,
                frame.address(),
                PAGE_SIZE,
                permissions,
                Some(physical_width),
                cpu_info.active_linear_address_bits,
            ) {
                Ok(mapping) => mapping,
                Err(_) => {
                    deallocate_kernel_heap_frame(allocator, frame);
                    rollback_kernel_heap_pages(candidate, allocator, first_page, mapped);
                    return None;
                }
            };
            let attributes = match mapping.select_cache_attributes(
                CachePolicy::WriteBack,
                pat,
                &mtrrs,
                cpu_info.normal_caching,
            ) {
                Ok(attributes) if attributes.effective_type() == EffectiveMemoryType::WriteBack => {
                    attributes
                }
                _ => {
                    deallocate_kernel_heap_frame(allocator, frame);
                    rollback_kernel_heap_pages(candidate, allocator, first_page, mapped);
                    return None;
                }
            };
            // SAFETY: IF is clear, the current candidate owns the active root,
            // and the allocator-issued frame is mapped RW/NX with local TLB
            // invalidation before its token becomes page-table-owned.
            if let Err(failure) =
                unsafe { candidate.map_owned_page_active(allocator, frame, mapping, attributes) }
            {
                deallocate_kernel_heap_frame(allocator, failure.frame);
                rollback_kernel_heap_pages(candidate, allocator, first_page, mapped);
                return None;
            }
            mapped += 1;
        }
        Some(())
    })()
    .is_some();
    if flags & (1 << 9) != 0 {
        // SAFETY: The mapping transaction is complete or fully rolled back.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
    result
}

fn rollback_kernel_heap_pages(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<
        'static,
        LimineHhdmCandidateMemory<'static>,
    >,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    first_page: usize,
    mapped_pages: usize,
) {
    use rustix_kernel::paging::PAGE_SIZE;

    for page in (first_page..first_page + mapped_pages).rev() {
        let virtual_address = KERNEL_HEAP_GROWTH_VIRTUAL_BASE + page as u64 * PAGE_SIZE;
        // SAFETY: The pages belong to this transaction in the current active
        // root; unmapping invalidates their TLB entries before token return.
        let frame = unsafe { candidate.unmap_owned_page_active(virtual_address) }
            .unwrap_or_else(|_| halt_forever());
        deallocate_kernel_heap_frame(allocator, frame);
    }
}

fn deallocate_kernel_heap_frame(
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    frame: rustix_kernel::frame::Frame,
) {
    if allocator.deallocate(frame).is_err() {
        halt_forever();
    }
}

// Error payloads provide boot diagnostics through the derived `Debug` output.
#[allow(dead_code)]
#[derive(Debug)]
enum AcpiMappingError {
    InvalidAcpiSpan {
        physical_start: u64,
        length: usize,
        error: rustix_kernel::memory::AcpiSpanError,
    },
    InvalidMapping(rustix_kernel::paging::MappingError),
    CandidateMap(
        rustix_kernel::paging::CandidateMapErrorKind<rustix_kernel::memory::HhdmAddressError>,
    ),
    CandidateWalk,
    UnexpectedCurrentCr3,
}

struct CandidateAcpiReader<'candidate, 'memory, 'map> {
    candidate: &'candidate mut rustix_kernel::paging::CandidatePageTables<
        'memory,
        LimineHhdmCandidateMemory<'map>,
    >,
    allocator: &'candidate mut rustix_kernel::frame::FrameAllocator,
    memory_map: &'map rustix_kernel::memory::MemoryMap,
    physical_address_bits: u8,
    virtual_address_bits: u8,
    cache_layout: rustix_kernel::paging::ValidatedMtrrLayout,
    pat: rustix_kernel::paging::PatLayout,
    normal_caching: bool,
    candidate_cr3: u64,
    previous_cr3: u64,
    virtual_address: u64,
}

impl CandidateAcpiReader<'_, '_, '_> {
    fn remove_temporary_mapping(&mut self) {
        if let Err(error) = self.candidate.unmap_acpi_page(self.virtual_address) {
            crate::kprintln!("temporary ACPI mapping could not be removed: {:?}", error);
            halt_forever();
        }
    }
}

// The legacy-reserved authorization is accepted only for RSDP reads; all
// root and child tables require ACPI-reclaimable/NVS memory-map coverage.
impl CandidateAcpiReader<'_, '_, '_> {
    fn read_mapped(
        &mut self,
        physical_start: u64,
        output: &mut [u8],
        allow_legacy_rsdp: bool,
    ) -> Result<(), AcpiMappingError> {
        use rustix_kernel::paging::{
            validate_mapping_range, CachePolicy, PagePermissions, PageWalkOutcome, PAGE_SIZE,
        };

        if arch::x86_64::cpu::read_cr3_raw() != self.previous_cr3 {
            return Err(AcpiMappingError::UnexpectedCurrentCr3);
        }
        if output.is_empty() {
            return Ok(());
        }
        let length =
            u64::try_from(output.len()).map_err(|_| AcpiMappingError::InvalidAcpiSpan {
                physical_start,
                length: output.len(),
                error: rustix_kernel::memory::AcpiSpanError::AddressOverflow,
            })?;
        let span = if allow_legacy_rsdp {
            self.memory_map.validate_rsdp_span(
                physical_start,
                length,
                Some(self.physical_address_bits),
            )
        } else {
            self.memory_map.validate_acpi_span(
                physical_start,
                length,
                Some(self.physical_address_bits),
            )
        }
        .map_err(|error| AcpiMappingError::InvalidAcpiSpan {
            physical_start,
            length: output.len(),
            error,
        })?;
        let permissions = PagePermissions {
            writable: false,
            executable: false,
            user_accessible: false,
        };
        let mut copied = 0usize;
        while copied < output.len() {
            let current_physical = physical_start.checked_add(copied as u64).ok_or(
                AcpiMappingError::InvalidAcpiSpan {
                    physical_start,
                    length: output.len(),
                    error: rustix_kernel::memory::AcpiSpanError::AddressOverflow,
                },
            )?;
            let physical_page = current_physical & !(PAGE_SIZE - 1);
            let page_offset = current_physical - physical_page;
            let page_length = (PAGE_SIZE - page_offset).min((output.len() - copied) as u64);
            let mapping = validate_mapping_range(
                self.virtual_address,
                physical_page,
                PAGE_SIZE,
                permissions,
                Some(self.physical_address_bits),
                self.virtual_address_bits,
            )
            .map_err(AcpiMappingError::InvalidMapping)?;
            let cache_attributes = mapping
                .select_cache_attributes(
                    CachePolicy::Uncacheable,
                    self.pat,
                    &self.cache_layout,
                    self.normal_caching,
                )
                .map_err(AcpiMappingError::InvalidMapping)?;
            self.candidate
                .map_acpi_page(self.allocator, span, mapping, cache_attributes)
                .map_err(|failure| AcpiMappingError::CandidateMap(failure.cause))?;

            let candidate_mapping_is_valid = matches!(
                self.candidate.walk(self.virtual_address),
                Ok(PageWalkOutcome::Mapped(translation))
                    if translation.physical_address == physical_page
                        && translation.permissions == permissions
            );
            if !candidate_mapping_is_valid {
                self.remove_temporary_mapping();
                return Err(AcpiMappingError::CandidateWalk);
            }
            if arch::x86_64::cpu::read_cr3_raw() != self.previous_cr3 {
                halt_forever();
            }

            // SAFETY: The candidate is a complete clone of the current inherited
            // hierarchy with all critical paths verified; this temporary page is
            // supervisor R/NX and the candidate remains owned by this stack.
            unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(self.candidate_cr3) };
            // SAFETY: The CR3 write above installed the candidate root and maskable
            // interrupts remain disabled during this single-core bootstrap read.
            unsafe { self.candidate.mark_active() };
            if arch::x86_64::cpu::read_cr3_raw() != self.candidate_cr3 {
                // SAFETY: Restoring the previous validated root preserves all code,
                // stack, data, and exception mappings needed by this path.
                unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(self.previous_cr3) };
                if arch::x86_64::cpu::read_cr3_raw() != self.previous_cr3 {
                    halt_forever();
                }
                // SAFETY: The verified CR3 is no longer the candidate root.
                unsafe { self.candidate.mark_inactive() };
                self.remove_temporary_mapping();
                return Err(AcpiMappingError::UnexpectedCurrentCr3);
            }

            let source = (self.virtual_address + page_offset) as *const u8;
            for offset in 0..page_length as usize {
                // SAFETY: The exact physical page is temporarily mapped R/NX in
                // the active candidate and this byte lies within its 4 KiB leaf.
                output[copied + offset] = unsafe { source.add(offset).read_volatile() };
            }

            // SAFETY: The prior root remains allocated and its critical mappings
            // were verified before this temporary switch.
            unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(self.previous_cr3) };
            if arch::x86_64::cpu::read_cr3_raw() != self.previous_cr3 {
                halt_forever();
            }
            // SAFETY: The previous root was restored and verified above.
            unsafe { self.candidate.mark_inactive() };
            self.remove_temporary_mapping();
            copied += page_length as usize;
        }
        Ok(())
    }
}

// SAFETY: `read_mapped` authorizes ordinary table reads only through validated
// ACPI map regions; its separate RSDP entry point permits only the bounded legacy
// reserved window recognized by `MemoryMap::validate_rsdp_span`.
unsafe impl rustix_kernel::acpi::AcpiPhysicalReader for CandidateAcpiReader<'_, '_, '_> {
    type Error = AcpiMappingError;

    fn read(&mut self, physical_start: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.read_mapped(physical_start, output, false)
    }

    fn read_rsdp(&mut self, physical_start: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.read_mapped(physical_start, output, true)
    }
}

// Capture Limine's entry RSP before a Rust prologue changes it. The synthetic
// return slot is part of the SysV entry stack; realign before calling Rust.
core::arch::global_asm!(
    ".section .text",
    ".code64",
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mov rdi, rsp",
    "and rsp, -16",
    "call rustix_start",
    "ud2",
    ".size _start, . - _start",
);

#[no_mangle]
pub extern "C" fn rustix_start(entry_rsp: u64) -> ! {
    arch::x86_64::serial::initialize();
    kprintln!("Rustix kernel: x86_64 Rust bootstrap");
    arch::x86_64::interrupts::initialize();
    kprintln!("x86_64 exception diagnostics: enabled (IRQs remain disabled)");
    let mut boot_info = match boot::capture_boot_information(entry_rsp) {
        Ok(boot_info) => boot_info,
        Err(error) => {
            kprintln!("boot information rejected: {:?}", error);
            halt_forever();
        }
    };
    boot::report_boot_information(&boot_info);

    #[cfg(feature = "probe-hhdm-frame")]
    probe_hhdm_frame(&mut boot_info);

    #[cfg(any(feature = "inject-page-fault", feature = "inject-invalid-opcode"))]
    run_fault_injection();

    activate_cloned_page_tables_and_run(&mut boot_info)
}

fn activate_cloned_page_tables_and_run(boot_info: &mut boot::BootInfo) -> ! {
    use rustix_kernel::paging::{
        encode_cr3_value, CandidatePageTables, PageWalkConfig, PageWalkOutcome, PAGE_SIZE,
    };

    let physical_address_bits = match boot_info.cpu_info.physical_address_bits {
        Some(bits) => bits,
        None => {
            kprintln!("page-table transition rejected: physical width unknown");
            halt_forever();
        }
    };
    let inherited_root = match boot_info.inherited_cr3_root {
        Ok(root) => root,
        Err(error) => {
            kprintln!("page-table transition rejected: inherited CR3: {:?}", error);
            halt_forever();
        }
    };
    if !boot_info.cpu_info.nx_enabled {
        kprintln!("page-table transition rejected: NXE is not enabled");
        halt_forever();
    }
    let config = PageWalkConfig {
        levels: if boot_info.cpu_info.active_linear_address_bits == 57 {
            5
        } else {
            4
        },
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
        nx_enabled: boot_info.cpu_info.nx_enabled,
        page_2m_supported: true,
        page_1g_supported: boot_info.cpu_info.has_1g_pages,
    };
    let reader = LimineHhdmPageTableReader {
        memory_map: &boot_info.memory_map,
        hhdm_offset: boot_info.hhdm_offset,
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
    };
    let mut memory = LimineHhdmCandidateMemory {
        memory_map: &boot_info.memory_map,
        hhdm_offset: boot_info.hhdm_offset,
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
    };
    let mut candidate =
        match CandidatePageTables::new(&mut boot_info.frame_allocator, &mut memory, config) {
            Ok(candidate) => candidate,
            Err(error) => {
                kprintln!(
                    "page-table transition failed to create root: {:?}",
                    error.cause
                );
                if let Some(frame) = error.frame {
                    release_probe_frame(&mut boot_info.frame_allocator, frame);
                }
                halt_forever();
            }
        };
    if let Err(error) =
        candidate.clone_inherited_hierarchy(&mut boot_info.frame_allocator, &reader, inherited_root)
    {
        kprintln!(
            "page-table transition failed to clone inherited root: {:?}",
            error
        );
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }

    let segments = boot_info.kernel_image_segments;
    let spans = [
        (
            "kernel text",
            segments.text.virtual_start,
            segments.text.physical_start,
            segments.text.virtual_end - segments.text.virtual_start,
        ),
        (
            "kernel rodata",
            segments.rodata.virtual_start,
            segments.rodata.physical_start,
            segments.rodata.virtual_end - segments.rodata.virtual_start,
        ),
        (
            "kernel data",
            segments.data.virtual_start,
            segments.data.physical_start,
            segments.data.virtual_end - segments.data.virtual_start,
        ),
        (
            "active boot stack",
            boot_info.boot_stack_virtual_start,
            boot_info.boot_stack_physical_start,
            boot_info.boot_stack_virtual_end - boot_info.boot_stack_virtual_start,
        ),
    ];
    for (label, virtual_start, physical_start, length) in spans {
        if !candidate_span_matches_source(
            &candidate,
            &reader,
            inherited_root,
            config,
            virtual_start,
            physical_start,
            length,
        ) {
            kprintln!(
                "page-table transition rejected: {} was not preserved",
                label
            );
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    }
    if !harden_kernel_hhdm_aliases(
        &mut candidate,
        &mut boot_info.frame_allocator,
        &boot_info.memory_map,
        boot_info.hhdm_offset,
        boot_info.cpu_info.physical_address_bits,
        boot_info.cpu_info.active_linear_address_bits,
        boot_info.kernel_image_segments,
        &reader,
        inherited_root,
        config,
    ) {
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }
    kprintln!("kernel HHDM aliases validated: text/rodata R/NX, data RW/NX, PAT preserved");
    let candidate_root = candidate
        .root_physical_address()
        .expect("a live candidate retains its root frame");
    let root_hhdm_address = match boot_info.memory_map.limine_hhdm_address(
        boot_info.hhdm_offset,
        candidate_root,
        rustix_kernel::paging::PAGE_SIZE,
        Some(physical_address_bits),
        boot_info.cpu_info.active_linear_address_bits,
    ) {
        Ok(address) => address,
        Err(error) => {
            kprintln!(
                "page-table transition rejected: candidate root HHDM: {:?}",
                error
            );
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    };
    let root_alias = match candidate.walk(root_hhdm_address) {
        Ok(PageWalkOutcome::Mapped(translation))
            if translation.physical_address == candidate_root =>
        {
            translation
        }
        result => {
            kprintln!(
                "page-table transition rejected: candidate root HHDM alias: {:?}",
                result
            );
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    };
    if !root_alias.permissions.writable || root_alias.permissions.user_accessible {
        kprintln!("page-table transition rejected: candidate root alias permissions are unsafe");
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }

    let new_cr3 = match encode_cr3_value(
        candidate_root,
        inherited_root.low_bits(),
        physical_address_bits,
    ) {
        Ok(value) => value,
        Err(error) => {
            kprintln!("page-table transition rejected: new CR3: {:?}", error);
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    };
    let inherited_cr3 = boot_info.inherited_cr3_raw;
    if arch::x86_64::cpu::read_cr3_raw() != inherited_cr3 {
        kprintln!("page-table transition aborted: active CR3 changed before switch");
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }
    if let Some(rsdp_physical_address) = boot_info.rsdp_physical_address {
        match load_acpi_madt(
            &mut candidate,
            &mut boot_info.frame_allocator,
            &boot_info.memory_map,
            &boot_info.cpu_info,
            rsdp_physical_address,
            new_cr3,
            inherited_cr3,
        ) {
            Ok(madt) => {
                kprintln!(
                    "ACPI MADT copied: LAPIC={:#x}, {} local APICs, {} I/O APICs, {} overrides",
                    madt.local_apic_address,
                    madt.local_apics().count(),
                    madt.io_apics().count(),
                    madt.interrupt_overrides().count()
                );
                boot_info.acpi_madt = Some(madt);
            }
            Err(error) => kprintln!("ACPI MADT unavailable: {:?}", error),
        }
    }
    let apic_virtual_addresses = match boot_info.acpi_madt.as_ref() {
        Some(madt) => match map_bootstrap_apic_pages(
            &mut candidate,
            &mut boot_info.frame_allocator,
            &boot_info.cpu_info,
            madt,
        ) {
            Ok(addresses) => Some(addresses),
            Err(error) => {
                kprintln!("APIC MMIO mappings unavailable: {}", error);
                None
            }
        },
        None => None,
    };
    // SAFETY: The candidate is a complete clone of every present inherited
    // hierarchy entry, with all referenced intermediate tables owned and the
    // critical code/data/stack paths compared before this point. The inherited
    // root's paging mode, address widths, PAT/MTRR state, and low CR3 mode are
    // preserved; interrupts remain disabled through this transition and are enabled
    // later only after the selected APIC routes and handlers are ready.
    let global_tlb_flushed = unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(new_cr3) };
    if global_tlb_flushed {
        kprintln!("page-table transition: global TLB flushed via CR4.PGE toggle");
    } else {
        kprintln!("page-table transition: CR4.PGE clear; CR3 reload flushed active translations");
    }
    if arch::x86_64::cpu::read_cr3_raw() != new_cr3
        || !spans
            .iter()
            .all(|(_, virtual_start, physical_start, length)| {
                candidate_span_matches_source(
                    &candidate,
                    &reader,
                    inherited_root,
                    config,
                    *virtual_start,
                    *physical_start,
                    *length,
                )
            })
    {
        // SAFETY: The inherited root and its backing memory remain untouched and
        // mapped by the candidate, so restoring its validated CR3 value is safe.
        unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(inherited_cr3) };
        if arch::x86_64::cpu::read_cr3_raw() != inherited_cr3 {
            kprintln!("page-table transition failed to restore inherited CR3; candidate retained");
            halt_forever();
        }
        kprintln!("page-table transition failed post-switch verification; restored inherited CR3");
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }
    // SAFETY: CR3 matches `new_cr3` and post-switch translation checks passed;
    // interrupts are disabled and the candidate root must remain allocated.
    unsafe { candidate.mark_active() };
    kprintln!(
        "page-table transition passed: active CR3={:#x}, cloned root={:#x}, {} owned tables",
        new_cr3,
        candidate_root,
        candidate.table_count()
    );

    #[cfg(feature = "probe-active-mapping")]
    {
        if let Err(error) = probe_active_mapping(
            &mut candidate,
            &mut boot_info.frame_allocator,
            &boot_info.cpu_info,
        ) {
            kprintln!("active mapping probe failed: {}", error);
            halt_forever();
        }
        kprintln!("active mapping probe passed: mapped, accessed, unmapped, reclaimed frame");
    }

    let mut vector_allocator = rustix_kernel::irq::InterruptVectorAllocator::new();
    let mut timer_vector = None;
    let mut timer_verified = false;
    if let (Some(madt), Some((local_apic_virtual, io_apic_virtual))) =
        (boot_info.acpi_madt.as_ref(), apic_virtual_addresses)
    {
        if let Some(vector) = vector_allocator.allocate() {
            let vector_number = vector.number();
            timer_vector = Some(vector);
            // SAFETY: Boot is single-core with IF=0. The cloned root is active,
            // and these virtual addresses were validated supervisor RW/NX/UC
            // mappings of the exact MADT-described APIC pages.
            match unsafe {
                arch::x86_64::apic::initialize(
                    madt,
                    local_apic_virtual,
                    io_apic_virtual,
                    arch::x86_64::cpu::bootstrap_apic_id(),
                )
            } {
                Err(error) => kprintln!(
                    "APIC initialization failed; IRQs remain disabled: {:?}",
                    error
                ),
                Ok(()) => {
                    // SAFETY: APIC initialization masked every route, including
                    // PIT IRQ0; the handler is ready before the route is armed.
                    match unsafe {
                        arch::x86_64::interrupts::register_irq_handler(
                            vector_number,
                            bootstrap_timer_irq,
                        )
                    } {
                        Err(error) => {
                            kprintln!("timer IRQ handler registration failed: {:?}", error)
                        }
                        Ok(()) => match PitRate::for_frequency(100) {
                            Err(error) => kprintln!("PIT rate selection failed: {:?}", error),
                            Ok(rate) => {
                                // SAFETY: The source remains masked through
                                // configuration and the ISR is already registered.
                                let configured = unsafe {
                                    arch::x86_64::apic::configure_pit_timer(
                                        vector_number,
                                        rate.divisor(),
                                    )
                                };
                                match configured {
                                    Err(error) => {
                                        kprintln!("PIT configuration failed: {:?}", error)
                                    }
                                    Ok(()) => {
                                        // SAFETY: Only the validated IRQ0 route is
                                        // unmasked after its handler is installed.
                                        match unsafe { arch::x86_64::apic::unmask_pit_timer() } {
                                            Err(error) => {
                                                kprintln!("PIT route unmask failed: {:?}", error)
                                            }
                                            Ok(()) => {
                                                // SAFETY: IDT/APIC/EOI/handler are
                                                // ready, every other route is masked,
                                                // and this ISR neither allocates nor
                                                // touches non-atomic shared state.
                                                unsafe {
                                                    core::arch::asm!(
                                                        "sti",
                                                        options(nomem, nostack)
                                                    );
                                                }
                                                let target =
                                                    BOOTSTRAP_TIMER_TICKS.ticks().saturating_add(3);
                                                let mut observed = false;
                                                for _ in 0..100_000_000 {
                                                    if BOOTSTRAP_TIMER_TICKS.ticks() >= target {
                                                        observed = true;
                                                        break;
                                                    }
                                                    spin_loop();
                                                }
                                                if observed {
                                                    timer_verified = true;
                                                    kprintln!("timer IRQ path passed: 3 ticks, EOI acknowledged");
                                                } else {
                                                    // SAFETY: Stop the sole unmasked
                                                    // source before continuing without
                                                    // a verified runtime clock.
                                                    unsafe {
                                                        core::arch::asm!(
                                                            "cli",
                                                            options(nomem, nostack)
                                                        );
                                                        let _ =
                                                            arch::x86_64::apic::mask_pit_timer();
                                                    }
                                                    kprintln!("timer IRQ validation timed out; interrupts disabled");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
        } else {
            kprintln!("no device IRQ vector available; interrupts remain disabled");
        }
    } else {
        kprintln!("validated MADT/APIC mappings unavailable; polling mode retained");
    }
    let input_irq_flags: u64;
    // SAFETY: Route setup and callback registration require IF=0.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) input_irq_flags) };
    let input_setup = if timer_verified {
        boot_info
            .acpi_madt
            .as_ref()
            .map(|madt| configure_input_irqs(madt, &mut vector_allocator))
            .unwrap_or_default()
    } else {
        InputIrqSetup::default()
    };
    if input_irq_flags & (1 << 9) != 0 {
        // SAFETY: Device handlers and masked-first routes are initialized.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }
    let _keep_vector_allocator_and_token_live = (
        vector_allocator,
        timer_vector,
        input_setup.uart_vector,
        input_setup.keyboard_vector,
    );
    let mut heap_mapping_context = KernelHeapMappingContext {
        candidate: core::ptr::addr_of_mut!(candidate).cast(),
        allocator: core::ptr::addr_of_mut!(boot_info.frame_allocator),
        cpu_info: core::ptr::addr_of!(boot_info.cpu_info),
    };
    for page in 0..KERNEL_HEAP_GROWTH_MAX_PAGES {
        let address = KERNEL_HEAP_GROWTH_VIRTUAL_BASE + page as u64 * PAGE_SIZE;
        if !matches!(
            candidate.walk(address),
            Ok(PageWalkOutcome::NotPresent { .. })
        ) {
            kprintln!(
                "frame-backed heap virtual range is already mapped at {:#x}",
                address
            );
            halt_forever();
        }
    }
    // SAFETY: The full virtual range is confirmed unmapped and exclusively
    // reserved. Candidate, allocator, CPU snapshot, and context remain live on
    // this non-returning boot path; the callback is transactional and nonallocating.
    if let Err(error) = unsafe {
        KERNEL_HEAP.initialize_frame_backed_region(
            KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize,
            KERNEL_HEAP_GROWTH_MAX_PAGES,
            core::ptr::addr_of_mut!(heap_mapping_context).cast(),
            map_kernel_heap_pages,
        )
    } {
        kprintln!("frame-backed heap setup failed: {:?}", error);
        halt_forever();
    }
    kprintln!(
        "frame-backed heap configured: {} KiB maximum, demand-mapped",
        KERNEL_HEAP_GROWTH_MAX_PAGES * PAGE_SIZE as usize / 1024
    );
    #[cfg(feature = "probe-kernel-threads")]
    if timer_verified {
        if let Err(error) = kernel_threads::smoke(
            &mut candidate,
            &mut boot_info.frame_allocator,
            &boot_info.cpu_info,
            &BOOTSTRAP_TIMER_TICKS,
        ) {
            kprintln!("cooperative thread probe failed: {}", error);
            halt_forever();
        }
    }
    probe_kernel_heap();

    // Keep the candidate and its frame tokens alive for as long as this root is
    // active. The shell runs forever and does not return to this stack frame.
    // SAFETY: The bootstrap remains single-core. If enabled, the timer handler
    // touches only its atomic counter and APIC EOI; the shell owns the filesystem.
    let filesystem = unsafe { &mut *core::ptr::addr_of_mut!(RAM_FILESYSTEM) };
    match filesystem.seed_defaults() {
        Ok(home) if input_setup.uart_ready && timer_verified => {
            let mut shell_context = ShellThreadContext {
                filesystem: core::ptr::addr_of_mut!(*filesystem),
                cwd: home,
                memory_map: core::ptr::addr_of!(boot_info.memory_map),
                frame_allocator: core::ptr::addr_of!(boot_info.frame_allocator),
            };
            // SAFETY: The active root, candidate tokens, allocator, BootInfo,
            // filesystem, and callback context remain live on this non-returning
            // single-vCPU path. The allocator pointer stays raw between calls.
            kernel_threads::run_shell(
                &mut candidate,
                core::ptr::addr_of_mut!(boot_info.frame_allocator),
                &boot_info.cpu_info,
                &BOOTSTRAP_TIMER_TICKS,
                shell_thread_entry,
                core::ptr::addr_of_mut!(shell_context) as usize,
            )
        }
        Ok(home) => shell::run(
            filesystem,
            home,
            &boot_info.memory_map,
            core::ptr::addr_of!(boot_info.frame_allocator),
            core::ptr::null_mut(),
        ),
        Err(error) => {
            kprintln!("RAM filesystem initialization failed: {:?}", error);
            halt_forever()
        }
    }
}

extern "C" fn bootstrap_timer_irq() {
    BOOTSTRAP_TIMER_TICKS.tick();
    arch::x86_64::apic::end_of_interrupt();
}

#[derive(Default)]
struct InputIrqSetup {
    uart_vector: Option<rustix_kernel::irq::InterruptVector>,
    keyboard_vector: Option<rustix_kernel::irq::InterruptVector>,
    uart_ready: bool,
    keyboard_ready: bool,
}

fn configure_input_irqs(
    madt: &rustix_kernel::acpi::Madt,
    vectors: &mut rustix_kernel::irq::InterruptVectorAllocator,
) -> InputIrqSetup {
    let mut setup = InputIrqSetup::default();
    if let Some((vector, route_ready)) =
        configure_one_input_irq(madt, vectors, 4, arch::x86_64::serial::irq_handler)
    {
        let vector_number = vector.number();
        setup.uart_vector = Some(vector);
        if route_ready && arch::x86_64::serial::enable_receive_interrupts() {
            // SAFETY: The UART handler is installed, COM1 is initialized, and
            // only its previously masked MADT route is being unmasked.
            setup.uart_ready =
                unsafe { arch::x86_64::apic::unmask_isa_irq(4, vector_number).is_ok() };
            if !setup.uart_ready {
                arch::x86_64::serial::disable_receive_interrupts();
            }
        }
    }

    if let Some((vector, route_ready)) =
        configure_one_input_irq(madt, vectors, 1, arch::x86_64::keyboard::irq_handler)
    {
        let vector_number = vector.number();
        setup.keyboard_vector = Some(vector);
        if route_ready && arch::x86_64::keyboard::initialize_interrupts() {
            // SAFETY: The bounded PS/2 controller setup succeeded and its
            // registered IRQ handler is ready before unmasking the route.
            setup.keyboard_ready =
                unsafe { arch::x86_64::apic::unmask_isa_irq(1, vector_number).is_ok() };
        }
    }
    kprintln!(
        "interrupt-driven input: UART RX {}, PS/2 raw scancodes {}",
        if setup.uart_ready {
            "ready"
        } else {
            "unavailable"
        },
        if setup.keyboard_ready {
            "ready"
        } else {
            "unavailable"
        }
    );
    setup
}

fn configure_one_input_irq(
    madt: &rustix_kernel::acpi::Madt,
    vectors: &mut rustix_kernel::irq::InterruptVectorAllocator,
    isa_irq: u8,
    handler: arch::x86_64::interrupts::IrqHandler,
) -> Option<(rustix_kernel::irq::InterruptVector, bool)> {
    let vector = vectors.allocate()?;
    let vector_number = vector.number();
    // SAFETY: This function is called with IF=0. The device route is masked
    // until both the APIC redirection and its callback are installed.
    if unsafe { arch::x86_64::interrupts::register_irq_handler(vector_number, handler) }.is_err() {
        let _ = vectors.release(vector);
        return None;
    }
    // SAFETY: `madt` is the validated owned table used for APIC initialization;
    // its route is kept masked until the device and handler are ready.
    if unsafe { arch::x86_64::apic::configure_isa_irq(madt, isa_irq, vector_number) }.is_err() {
        kprintln!(
            "ISA IRQ{} route configuration failed; source remains masked",
            isa_irq
        );
        return Some((vector, false));
    }
    Some((vector, true))
}

struct ShellThreadContext {
    filesystem: *mut RamFs,
    cwd: usize,
    memory_map: *const rustix_kernel::memory::MemoryMap,
    frame_allocator: *const rustix_kernel::frame::FrameAllocator,
}

extern "C" fn shell_thread_entry(runtime: *mut (), context_address: usize) {
    // SAFETY: `activate_cloned_page_tables_and_run` keeps this local context,
    // the static filesystem, and boot metadata live for the non-returning runtime.
    let context = unsafe { &mut *(context_address as *mut ShellThreadContext) };
    // SAFETY: This is the sole shell thread and owns the mutable filesystem.
    let filesystem = unsafe { &mut *context.filesystem };
    // SAFETY: The memory map is immutable and retained with BootInfo. The frame
    // allocator is passed as a raw pointer so no shared reference to BootInfo's
    // allocator field remains live while heap growth mutates it.
    let memory_map = unsafe { &*context.memory_map };
    shell::run(
        filesystem,
        context.cwd,
        memory_map,
        context.frame_allocator,
        runtime,
    )
}

#[cfg(feature = "probe-active-mapping")]
fn probe_active_mapping<'memory, 'map>(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<
        'memory,
        LimineHhdmCandidateMemory<'map>,
    >,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    cpu_info: &arch::x86_64::cpu::CpuInfo,
) -> Result<(), &'static str> {
    use rustix_kernel::paging::{
        validate_mapping_range, CachePolicy, MtrrState, PagePermissions, PageWalkOutcome,
        PatLayout, PAGE_SIZE,
    };

    const PROBE_VIRTUAL_ADDRESS: u64 = 0xffff_c300_0000_0000;
    let physical_address_bits = cpu_info
        .physical_address_bits
        .ok_or("unknown physical width")?;
    let frame = allocator.allocate().ok_or("no frame available")?;
    let physical_address = frame.address();
    let permissions = PagePermissions {
        writable: true,
        executable: false,
        user_accessible: false,
    };
    let mapping_result = validate_mapping_range(
        PROBE_VIRTUAL_ADDRESS,
        physical_address,
        PAGE_SIZE,
        permissions,
        Some(physical_address_bits),
        cpu_info.active_linear_address_bits,
    );
    let mapping = match mapping_result {
        Ok(mapping) => mapping,
        Err(_) => {
            let _ = allocator.deallocate(frame);
            return Err("mapping range rejected");
        }
    };
    let pat_value = match cpu_info.pat_msr_value {
        Some(value) => value,
        None => {
            let _ = allocator.deallocate(frame);
            return Err("PAT unavailable");
        }
    };
    let pat = match PatLayout::from_msr_value(pat_value) {
        Ok(pat) => pat,
        Err(_) => {
            let _ = allocator.deallocate(frame);
            return Err("PAT state invalid");
        }
    };
    let cache_layout = match &cpu_info.mtrr {
        MtrrState::Captured(registers) => match registers.validated_layout(physical_address_bits) {
            Ok(layout) => layout,
            Err(_) => {
                let _ = allocator.deallocate(frame);
                return Err("MTRR state invalid");
            }
        },
        _ => {
            let _ = allocator.deallocate(frame);
            return Err("MTRR state unavailable");
        }
    };
    let attributes = match mapping.select_cache_attributes(
        CachePolicy::WriteBack,
        pat,
        &cache_layout,
        cpu_info.normal_caching,
    ) {
        Ok(attributes) => attributes,
        Err(_) => {
            let _ = allocator.deallocate(frame);
            return Err("frame has no uniform write-back policy");
        }
    };
    if !matches!(
        candidate.walk(PROBE_VIRTUAL_ADDRESS),
        Ok(PageWalkOutcome::NotPresent { .. })
    ) {
        let _ = allocator.deallocate(frame);
        return Err("probe virtual address is not unmapped");
    }

    // SAFETY: The active cloned root is current, bootstrap runs on one CPU,
    // interrupts are still disabled, and the backend performs `invlpg` before
    // returning. The mapping is backed by this allocator-issued frame token.
    if let Err(failure) =
        unsafe { candidate.map_owned_page_active(allocator, frame, mapping, attributes) }
    {
        let _ = allocator.deallocate(failure.frame);
        return Err("active frame mapping rejected");
    }

    let translation_matches = matches!(
        candidate.walk(PROBE_VIRTUAL_ADDRESS),
        Ok(PageWalkOutcome::Mapped(translation))
            if translation.physical_address == physical_address
                && translation.permissions == permissions
                && translation.pat_index == attributes.pat_index()
    );
    let mut access_matches = false;
    if translation_matches {
        let pointer = PROBE_VIRTUAL_ADDRESS as *mut u64;
        // SAFETY: The active mapping was verified as supervisor RW/NX for this
        // allocator-owned page, and the accesses stay within its first word.
        unsafe {
            pointer.write_volatile(0x5255_5354_4958_4d41);
            access_matches = pointer.read_volatile() == 0x5255_5354_4958_4d41;
            pointer.write_volatile(0);
        }
    }
    // SAFETY: Same active-root/IF=0 invariants as the map above. This invalidates
    // the translation before returning the frame token to the allocator.
    let frame = unsafe { candidate.unmap_owned_page_active(PROBE_VIRTUAL_ADDRESS) }
        .map_err(|_| "active frame unmap failed")?;
    if !matches!(
        candidate.walk(PROBE_VIRTUAL_ADDRESS),
        Ok(PageWalkOutcome::NotPresent { .. })
    ) {
        let _ = allocator.deallocate(frame);
        return Err("active mapping remained present after unmap");
    }
    allocator
        .deallocate(frame)
        .map_err(|_| "active mapping frame could not be reclaimed")?;
    if !translation_matches || !access_matches {
        return Err("active frame translation or access did not verify");
    }
    Ok(())
}

fn map_bootstrap_apic_pages<'memory, 'map>(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<
        'memory,
        LimineHhdmCandidateMemory<'map>,
    >,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    cpu_info: &arch::x86_64::cpu::CpuInfo,
    madt: &rustix_kernel::acpi::Madt,
) -> Result<(u64, u64), &'static str> {
    use rustix_kernel::paging::{
        validate_mapping_range, CachePolicy, EffectiveMemoryType, MtrrState, PagePermissions,
        PageWalkOutcome, PatLayout, PAGE_SIZE,
    };

    let physical_address_bits = cpu_info
        .physical_address_bits
        .ok_or("unknown physical width")?;
    let pat_value = cpu_info.pat_msr_value.ok_or("PAT unavailable")?;
    let pat = PatLayout::from_msr_value(pat_value).map_err(|_| "invalid PAT state")?;
    let cache_layout = match &cpu_info.mtrr {
        MtrrState::Captured(registers) => registers
            .validated_layout(physical_address_bits)
            .map_err(|_| "invalid MTRR state")?,
        _ => return Err("MTRR state unavailable"),
    };
    let mut io_apics = madt.io_apics();
    let io_apic = io_apics.next().ok_or("MADT has no I/O APIC")?;
    if io_apics.next().is_some() {
        return Err("multiple I/O APICs are unsupported by bootstrap routing");
    }

    let pages = [
        (LOCAL_APIC_VIRTUAL_ADDRESS, madt.local_apic_address),
        (IO_APIC_VIRTUAL_ADDRESS, u64::from(io_apic.physical_address)),
    ];
    let permissions = PagePermissions {
        writable: true,
        executable: false,
        user_accessible: false,
    };
    for (virtual_address, physical_address) in pages {
        if !matches!(
            candidate.walk(virtual_address),
            Ok(PageWalkOutcome::NotPresent { .. })
        ) {
            return Err("reserved APIC virtual address is not unmapped");
        }
        let mapping = validate_mapping_range(
            virtual_address,
            physical_address,
            PAGE_SIZE,
            permissions,
            Some(physical_address_bits),
            cpu_info.active_linear_address_bits,
        )
        .map_err(|_| "APIC mapping range rejected")?;
        let attributes = mapping
            .select_cache_attributes(
                CachePolicy::Uncacheable,
                pat,
                &cache_layout,
                cpu_info.normal_caching,
            )
            .map_err(|_| "APIC page has no uniform UC cache policy")?;
        if attributes.effective_type() != EffectiveMemoryType::Uncacheable {
            return Err("APIC page is not effectively uncacheable");
        }
        // SAFETY: Both physical addresses come from the copied MADT, are used
        // only as device registers, and will be mapped with the validated UC
        // policy. The API enforces supervisor RW/NX mappings and non-ownership.
        unsafe {
            candidate
                .map_mmio_page(allocator, mapping, attributes)
                .map_err(|_| "APIC candidate mapping failed")?;
        }
        match candidate.walk(virtual_address) {
            Ok(PageWalkOutcome::Mapped(translation))
                if translation.physical_address == physical_address
                    && translation.page_size == PAGE_SIZE
                    && translation.permissions == permissions
                    && translation.pat_index == attributes.pat_index() => {}
            _ => return Err("APIC candidate mapping did not verify"),
        }
    }
    Ok((LOCAL_APIC_VIRTUAL_ADDRESS, IO_APIC_VIRTUAL_ADDRESS))
}

// Error payloads provide boot diagnostics through the derived `Debug` output.
#[allow(dead_code)]
#[derive(Debug)]
enum AcpiBootReadError {
    PhysicalWidthUnknown,
    PatUnavailable,
    InvalidPat(rustix_kernel::paging::PatLayoutError),
    InvalidMtrr(rustix_kernel::paging::MtrrError),
    MtrrUnavailable,
    NoVirtualWindow,
    PageTableWalk,
    Read(rustix_kernel::acpi::AcpiReadError<AcpiMappingError>),
}

fn load_acpi_madt<'candidate, 'memory, 'map>(
    candidate: &'candidate mut rustix_kernel::paging::CandidatePageTables<
        'memory,
        LimineHhdmCandidateMemory<'map>,
    >,
    allocator: &'candidate mut rustix_kernel::frame::FrameAllocator,
    memory_map: &'map rustix_kernel::memory::MemoryMap,
    cpu_info: &arch::x86_64::cpu::CpuInfo,
    rsdp_physical_address: u64,
    candidate_cr3: u64,
    previous_cr3: u64,
) -> Result<rustix_kernel::acpi::Madt, AcpiBootReadError> {
    use rustix_kernel::paging::{MtrrState, PageWalkOutcome, PatLayout};

    let physical_address_bits = cpu_info
        .physical_address_bits
        .ok_or(AcpiBootReadError::PhysicalWidthUnknown)?;
    let pat_value = cpu_info
        .pat_msr_value
        .ok_or(AcpiBootReadError::PatUnavailable)?;
    let pat = PatLayout::from_msr_value(pat_value).map_err(AcpiBootReadError::InvalidPat)?;
    let cache_layout = match &cpu_info.mtrr {
        MtrrState::Captured(registers) => registers
            .validated_layout(physical_address_bits)
            .map_err(AcpiBootReadError::InvalidMtrr)?,
        _ => return Err(AcpiBootReadError::MtrrUnavailable),
    };

    const WINDOW_BASE: u64 = 0xffff_c000_0000_0000;
    const WINDOW_PAGES: u64 = 4096;
    let mut virtual_address = WINDOW_BASE;
    let mut window_found = false;
    for _ in 0..WINDOW_PAGES {
        match candidate.walk(virtual_address) {
            Ok(PageWalkOutcome::NotPresent { .. }) => {
                window_found = true;
                break;
            }
            Ok(PageWalkOutcome::Mapped(_)) => {}
            Err(_) => return Err(AcpiBootReadError::PageTableWalk),
        }
        virtual_address = virtual_address
            .checked_add(rustix_kernel::paging::PAGE_SIZE)
            .ok_or(AcpiBootReadError::NoVirtualWindow)?;
    }
    if !window_found {
        return Err(AcpiBootReadError::NoVirtualWindow);
    }

    let mut reader = CandidateAcpiReader {
        candidate,
        allocator,
        memory_map,
        physical_address_bits,
        virtual_address_bits: cpu_info.active_linear_address_bits,
        cache_layout,
        pat,
        normal_caching: cpu_info.normal_caching,
        candidate_cr3,
        previous_cr3,
        virtual_address,
    };
    let mut scratch = [0u8; rustix_kernel::acpi::MAX_ACPI_STRUCTURE_SIZE];
    rustix_kernel::acpi::read_madt(&mut reader, rsdp_physical_address, &mut scratch)
        .map_err(AcpiBootReadError::Read)
}

fn harden_kernel_hhdm_aliases(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    memory_map: &rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: Option<u8>,
    virtual_address_bits: u8,
    segments: rustix_kernel::memory::KernelImageSegments,
    reader: &impl rustix_kernel::paging::PageTableReader<
        Error = rustix_kernel::memory::HhdmAddressError,
    >,
    inherited_root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
) -> bool {
    use rustix_kernel::paging::{
        walk_virtual_address, PagePermissions, PageWalkOutcome, PAGE_SIZE,
    };

    let image_segments = [
        ("kernel text", segments.text, false),
        ("kernel rodata", segments.rodata, false),
        ("kernel data", segments.data, true),
    ];
    for (label, segment, writable) in image_segments {
        let length = segment.physical_end - segment.physical_start;
        let mut offset = 0;
        while offset < length {
            let Some(physical_address) = segment.physical_start.checked_add(offset) else {
                kprintln!(
                    "kernel HHDM alias check failed: {} physical overflow",
                    label
                );
                return false;
            };
            let alias = match memory_map.limine_hhdm_address(
                hhdm_offset,
                physical_address,
                PAGE_SIZE,
                physical_address_bits,
                virtual_address_bits,
            ) {
                Ok(alias) => alias,
                Err(error) => {
                    kprintln!(
                        "kernel HHDM alias check failed: {} address: {:?}",
                        label,
                        error
                    );
                    return false;
                }
            };
            let source = match walk_virtual_address(reader, inherited_root, alias, config) {
                Ok(PageWalkOutcome::Mapped(translation)) => translation,
                result => {
                    kprintln!(
                        "kernel HHDM alias check failed: {} inherited walk: {:?}",
                        label,
                        result
                    );
                    return false;
                }
            };
            let permissions = PagePermissions {
                writable,
                executable: false,
                user_accessible: false,
            };
            if let Err(error) = candidate.set_inherited_page_permissions(
                allocator,
                alias,
                physical_address,
                permissions,
            ) {
                kprintln!(
                    "kernel HHDM alias check failed: {} protection: {:?}",
                    label,
                    error
                );
                return false;
            }
            match candidate.walk(alias) {
                Ok(PageWalkOutcome::Mapped(translation))
                    if translation.physical_address == physical_address
                        && translation.permissions == permissions
                        && translation.pat_index == source.pat_index => {}
                result => {
                    kprintln!(
                        "kernel HHDM alias check failed: {} candidate walk: {:?}",
                        label,
                        result
                    );
                    return false;
                }
            }
            offset += PAGE_SIZE;
        }
    }
    true
}

fn probe_kernel_heap() {
    use core::alloc::{GlobalAlloc, Layout};
    use rustix_kernel::paging::PAGE_SIZE;

    let full_layout = match Layout::from_size_align(rustix_kernel::heap::KERNEL_HEAP_CAPACITY, 1) {
        Ok(layout) => layout,
        Err(error) => {
            kprintln!(
                "kernel heap probe failed to construct full-arena layout: {:?}",
                error
            );
            halt_forever();
        }
    };
    // SAFETY: The heap static is initialized before use and maskable interrupts
    // remain disabled; this probe requests a valid nonzero layout.
    let full_arena = unsafe { KERNEL_HEAP.alloc(full_layout) };
    if full_arena.is_null() {
        kprintln!("kernel heap probe failed: full-arena allocation was rejected");
        halt_forever();
    }
    let oversized_layout =
        match Layout::from_size_align(KERNEL_HEAP_GROWTH_MAX_PAGES * PAGE_SIZE as usize + 1, 1) {
            Ok(layout) => layout,
            Err(_) => halt_forever(),
        };
    // SAFETY: The request is larger than either bounded arena and must fail.
    let exhausted = unsafe { KERNEL_HEAP.alloc(oversized_layout) };
    if !exhausted.is_null() {
        // SAFETY: Both pointers are live allocations with their original layouts.
        unsafe {
            KERNEL_HEAP.dealloc(exhausted, oversized_layout);
            KERNEL_HEAP.dealloc(full_arena, full_layout);
        }
        kprintln!("kernel heap probe failed: bounded growth exhaustion was not deterministic");
        halt_forever();
    }
    // SAFETY: `full_arena` is the complete live allocation created above.
    unsafe { KERNEL_HEAP.dealloc(full_arena, full_layout) };

    let layout = match Layout::from_size_align(257, 64) {
        Ok(layout) => layout,
        Err(error) => {
            kprintln!(
                "kernel heap probe failed to construct aligned layout: {:?}",
                error
            );
            halt_forever();
        }
    };
    // SAFETY: The heap is available after releasing the full-arena allocation.
    let allocation = unsafe { KERNEL_HEAP.alloc(layout) };
    if allocation.is_null() || allocation as usize % layout.align() != 0 {
        if !allocation.is_null() {
            // SAFETY: This is the live allocation returned for `layout`.
            unsafe { KERNEL_HEAP.dealloc(allocation, layout) };
        }
        kprintln!("kernel heap probe failed: aligned allocation was rejected or misaligned");
        halt_forever();
    }
    // SAFETY: The allocator returned `layout.size()` writable bytes.
    unsafe { core::ptr::write_bytes(allocation, 0xa5, layout.size()) };
    for index in 0..layout.size() {
        // SAFETY: `index` remains inside the live allocation.
        if unsafe { allocation.add(index).read_volatile() } != 0xa5 {
            // SAFETY: The allocation is still live with its original layout.
            unsafe { KERNEL_HEAP.dealloc(allocation, layout) };
            kprintln!("kernel heap probe failed: allocation data did not round-trip");
            halt_forever();
        }
    }
    // SAFETY: The allocation is live and the original layout is supplied.
    unsafe { KERNEL_HEAP.dealloc(allocation, layout) };
    // SAFETY: The previous allocation was returned; first-fit should reuse it.
    let reused = unsafe { KERNEL_HEAP.alloc(layout) };
    if reused != allocation {
        if !reused.is_null() {
            // SAFETY: `reused` is a live allocation with `layout`.
            unsafe { KERNEL_HEAP.dealloc(reused, layout) };
        }
        kprintln!("kernel heap probe failed: freed space was not reused");
        halt_forever();
    }
    // SAFETY: The reused allocation is live and has the same layout.
    unsafe { KERNEL_HEAP.dealloc(reused, layout) };

    let growth_layout = match Layout::from_size_align(
        rustix_kernel::heap::KERNEL_HEAP_CAPACITY + PAGE_SIZE as usize,
        64,
    ) {
        Ok(layout) => layout,
        Err(_) => halt_forever(),
    };
    // SAFETY: This request is larger than the bootstrap arena, so it must use
    // the configured frame-backed range and remain within its fixed limit.
    let growth = unsafe { KERNEL_HEAP.alloc(growth_layout) };
    let growth_end = KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize
        + KERNEL_HEAP_GROWTH_MAX_PAGES * PAGE_SIZE as usize;
    if growth.is_null()
        || (growth as usize) < KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize
        || (growth as usize)
            .checked_add(growth_layout.size())
            .is_none_or(|end| end > growth_end)
        || growth as usize % growth_layout.align() != 0
    {
        if !growth.is_null() {
            // SAFETY: `growth` was returned for `growth_layout`.
            unsafe { KERNEL_HEAP.dealloc(growth, growth_layout) };
        }
        kprintln!("kernel heap probe failed: frame-backed allocation was rejected or invalid");
        halt_forever();
    }
    // SAFETY: The committed pages cover the complete live allocation.
    unsafe {
        growth.write(0x5a);
        growth.add(growth_layout.size() - 1).write(0xa5);
    }
    // SAFETY: Both offsets are within the live allocation.
    if unsafe { growth.read_volatile() } != 0x5a
        || unsafe { growth.add(growth_layout.size() - 1).read_volatile() } != 0xa5
    {
        // SAFETY: The allocation is still live with its original layout.
        unsafe { KERNEL_HEAP.dealloc(growth, growth_layout) };
        kprintln!("kernel heap probe failed: frame-backed data did not round-trip");
        halt_forever();
    }
    // SAFETY: Return the exact growth allocation and then require first-fit reuse.
    unsafe { KERNEL_HEAP.dealloc(growth, growth_layout) };
    let growth_reused = unsafe { KERNEL_HEAP.alloc(growth_layout) };
    if growth_reused != growth {
        if !growth_reused.is_null() {
            // SAFETY: The pointer is live with `growth_layout`.
            unsafe { KERNEL_HEAP.dealloc(growth_reused, growth_layout) };
        }
        kprintln!("kernel heap probe failed: frame-backed space was not reused");
        halt_forever();
    }
    // SAFETY: Release the reused allocation with its original layout.
    unsafe { KERNEL_HEAP.dealloc(growth_reused, growth_layout) };
    kprintln!("kernel heap probe passed: bootstrap exhaustion, frame-backed growth, reuse");
}

#[cfg(feature = "probe-hhdm-frame")]
fn probe_hhdm_frame(boot_info: &mut boot::BootInfo) {
    use rustix_kernel::frame::FRAME_SIZE;

    let frame = match boot_info.frame_allocator.allocate() {
        Some(frame) => frame,
        None => {
            kprintln!("HHDM frame probe failed: no free frame");
            halt_forever();
        }
    };
    let hhdm_address = match frame.hhdm_address(
        &boot_info.memory_map,
        boot_info.hhdm_offset,
        boot_info.cpu_info.physical_address_bits,
        boot_info.cpu_info.active_linear_address_bits,
    ) {
        Ok(address) => address,
        Err(error) => {
            kprintln!("HHDM frame probe rejected frame translation: {:?}", error);
            release_probe_frame(&mut boot_info.frame_allocator, frame);
            halt_forever();
        }
    };

    let words = (FRAME_SIZE / core::mem::size_of::<u64>() as u64) as usize;
    let page = hhdm_address as *mut u64;
    let mut verified = true;
    // SAFETY: The non-copyable `Frame` token is held exclusively; its full page
    // is within validated `Usable` memory and its HHDM arithmetic was checked.
    // Limine base revision 3 guarantees usable memory in the HHDM, and no other
    // Rustix mapping aliases this newly allocated frame. This is an opt-in QEMU
    // probe; a broken loader mapping would fault and be caught by the fatal path.
    unsafe {
        for index in 0..words {
            page.add(index)
                .write_volatile(0xa5a5_0000_0000_0000 ^ index as u64);
        }
        for index in 0..words {
            if page.add(index).read_volatile() != (0xa5a5_0000_0000_0000 ^ index as u64) {
                verified = false;
                break;
            }
        }
        for index in 0..words {
            page.add(index).write_volatile(0);
        }
    }

    release_probe_frame(&mut boot_info.frame_allocator, frame);
    if !verified {
        kprintln!("HHDM frame probe failed: readback mismatch");
        halt_forever();
    }
    kprintln!("HHDM frame probe passed: wrote, read, cleared, and reclaimed one frame");
    probe_inherited_root(boot_info);
}

#[cfg(feature = "probe-hhdm-frame")]
fn probe_inherited_root(boot_info: &mut boot::BootInfo) {
    use rustix_kernel::paging::inherited_cr3_root_hhdm_address;

    let root = match boot_info.inherited_cr3_root {
        Ok(root) => root,
        Err(error) => {
            kprintln!(
                "inherited root probe failed: CR3 decode rejected: {:?}",
                error
            );
            halt_forever();
        }
    };
    let address = match inherited_cr3_root_hhdm_address(
        root,
        &boot_info.memory_map,
        boot_info.hhdm_offset,
        boot_info.cpu_info.physical_address_bits,
        boot_info.cpu_info.active_linear_address_bits,
    ) {
        Ok(address) => address,
        Err(error) => {
            kprintln!(
                "inherited root probe failed: HHDM validation rejected: {:?}",
                error
            );
            halt_forever();
        }
    };
    let entries = address as *const u64;
    let mut present_entries = 0;
    // SAFETY: The complete root page was validated as bootloader-reclaimable
    // and its HHDM range arithmetic was checked. The Limine base-revision-3
    // contract maps that region; this read-only opt-in probe trusts that handoff.
    unsafe {
        for index in 0..512 {
            if entries.add(index).read_volatile() & 1 != 0 {
                present_entries += 1;
            }
        }
    }
    kprintln!(
        "inherited root HHDM probe passed: read 512 entries, {} present",
        present_entries
    );
    let physical_address_bits = match boot_info.cpu_info.physical_address_bits {
        Some(bits) => bits,
        None => {
            kprintln!("inherited page-table walk failed: physical width unknown");
            halt_forever();
        }
    };
    let reader = LimineHhdmPageTableReader {
        memory_map: &boot_info.memory_map,
        hhdm_offset: boot_info.hhdm_offset,
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
    };
    let config = rustix_kernel::paging::PageWalkConfig {
        levels: if boot_info.cpu_info.active_linear_address_bits == 57 {
            5
        } else {
            4
        },
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
        nx_enabled: boot_info.cpu_info.nx_enabled,
        page_2m_supported: true,
        page_1g_supported: boot_info.cpu_info.has_1g_pages,
    };
    let segments = boot_info.kernel_image_segments;
    verify_inherited_mapping(
        &reader,
        root,
        config,
        "kernel text",
        segments.text.virtual_start,
        segments.text.physical_start,
        segments.text.virtual_end - segments.text.virtual_start,
    );
    verify_inherited_mapping(
        &reader,
        root,
        config,
        "kernel rodata",
        segments.rodata.virtual_start,
        segments.rodata.physical_start,
        segments.rodata.virtual_end - segments.rodata.virtual_start,
    );
    verify_inherited_mapping(
        &reader,
        root,
        config,
        "kernel data",
        segments.data.virtual_start,
        segments.data.physical_start,
        segments.data.virtual_end - segments.data.virtual_start,
    );
    verify_inherited_mapping(
        &reader,
        root,
        config,
        "active boot stack",
        boot_info.boot_stack_virtual_start,
        boot_info.boot_stack_physical_start,
        boot_info.boot_stack_virtual_end - boot_info.boot_stack_virtual_start,
    );

    let pat_value = match boot_info.cpu_info.pat_msr_value {
        Some(value) => value,
        None => {
            kprintln!("cache-alias probe failed: active PAT value unavailable");
            halt_forever();
        }
    };
    let pat = match rustix_kernel::paging::PatLayout::from_msr_value(pat_value) {
        Ok(pat) => pat,
        Err(error) => {
            kprintln!("cache-alias probe failed: invalid PAT layout: {:?}", error);
            halt_forever();
        }
    };
    let registers = match &boot_info.cpu_info.mtrr {
        rustix_kernel::paging::MtrrState::Captured(registers) => registers,
        _ => {
            kprintln!("cache-alias probe failed: captured MTRR state unavailable");
            halt_forever();
        }
    };
    let mtrrs = match registers.validated_layout(physical_address_bits) {
        Ok(mtrrs) => mtrrs,
        Err(error) => {
            kprintln!("cache-alias probe failed: invalid MTRR state: {:?}", error);
            halt_forever();
        }
    };
    if !boot_info.cpu_info.normal_caching {
        kprintln!("cache-alias probe failed: non-normal CR0 caching mode");
        halt_forever();
    }
    verify_kernel_cache_aliases(
        boot_info,
        &reader,
        root,
        config,
        pat,
        &mtrrs,
        "kernel text",
        segments.text.virtual_start,
        segments.text.physical_start,
        segments.text.virtual_end - segments.text.virtual_start,
    );
    verify_kernel_cache_aliases(
        boot_info,
        &reader,
        root,
        config,
        pat,
        &mtrrs,
        "kernel rodata",
        segments.rodata.virtual_start,
        segments.rodata.physical_start,
        segments.rodata.virtual_end - segments.rodata.virtual_start,
    );
    verify_kernel_cache_aliases(
        boot_info,
        &reader,
        root,
        config,
        pat,
        &mtrrs,
        "kernel data",
        segments.data.virtual_start,
        segments.data.physical_start,
        segments.data.virtual_end - segments.data.virtual_start,
    );
    probe_cloned_page_tables(
        &mut boot_info.frame_allocator,
        &boot_info.memory_map,
        boot_info.hhdm_offset,
        physical_address_bits,
        boot_info.cpu_info.active_linear_address_bits,
        &reader,
        root,
        config,
        [
            (
                "kernel text",
                segments.text.virtual_start,
                segments.text.physical_start,
                segments.text.virtual_end - segments.text.virtual_start,
            ),
            (
                "kernel rodata",
                segments.rodata.virtual_start,
                segments.rodata.physical_start,
                segments.rodata.virtual_end - segments.rodata.virtual_start,
            ),
            (
                "kernel data",
                segments.data.virtual_start,
                segments.data.physical_start,
                segments.data.virtual_end - segments.data.virtual_start,
            ),
            (
                "active boot stack",
                boot_info.boot_stack_virtual_start,
                boot_info.boot_stack_physical_start,
                boot_info.boot_stack_virtual_end - boot_info.boot_stack_virtual_start,
            ),
        ],
    );
    probe_candidate_page_tables(boot_info);
}

#[cfg(feature = "probe-hhdm-frame")]
fn probe_cloned_page_tables(
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    memory_map: &rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: u8,
    virtual_address_bits: u8,
    source_reader: &impl rustix_kernel::paging::PageTableReader<
        Error = rustix_kernel::memory::HhdmAddressError,
    >,
    source_root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
    spans: [(&str, u64, u64, u64); 4],
) {
    use rustix_kernel::paging::CandidatePageTables;

    let mut memory = LimineHhdmCandidateMemory {
        memory_map,
        hhdm_offset,
        physical_address_bits,
        virtual_address_bits,
    };
    let mut candidate = match CandidatePageTables::new(allocator, &mut memory, config) {
        Ok(candidate) => candidate,
        Err(error) => {
            kprintln!(
                "candidate clone probe failed to create root: {:?}",
                error.cause
            );
            if let Some(frame) = error.frame {
                release_probe_frame(allocator, frame);
            }
            halt_forever();
        }
    };
    if let Err(error) = candidate.clone_inherited_hierarchy(allocator, source_reader, source_root) {
        kprintln!("candidate clone probe failed: {:?}", error);
        release_candidate_after_probe_failure(candidate, allocator);
    }
    for (label, virtual_start, physical_start, length) in spans {
        if !candidate_span_matches_source(
            &candidate,
            source_reader,
            source_root,
            config,
            virtual_start,
            physical_start,
            length,
        ) {
            kprintln!(
                "candidate clone probe failed: {} translation mismatch",
                label
            );
            release_candidate_after_probe_failure(candidate, allocator);
        }
    }
    let table_count = candidate.table_count();
    if let Err(failure) = candidate.release(allocator) {
        kprintln!(
            "candidate clone probe failed to release frames: {:?}",
            failure
        );
        halt_forever();
    }
    kprintln!(
        "candidate inherited-root clone probe passed: {} owned table pages preserve critical paths; CR3 unchanged",
        table_count
    );
}

fn candidate_span_matches_source(
    candidate: &rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>,
    source_reader: &impl rustix_kernel::paging::PageTableReader<
        Error = rustix_kernel::memory::HhdmAddressError,
    >,
    source_root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
    virtual_start: u64,
    physical_start: u64,
    length: u64,
) -> bool {
    use rustix_kernel::paging::{walk_virtual_address, PageWalkOutcome};

    let mut offset = 0;
    while offset < length {
        let Some(virtual_address) = virtual_start.checked_add(offset) else {
            return false;
        };
        let Some(expected_physical) = physical_start.checked_add(offset) else {
            return false;
        };
        let source_result =
            walk_virtual_address(source_reader, source_root, virtual_address, config);
        let candidate_result = candidate.walk(virtual_address);
        let (source_translation, candidate_translation) = match (source_result, candidate_result) {
            (Ok(PageWalkOutcome::Mapped(source)), Ok(PageWalkOutcome::Mapped(candidate))) => {
                (source, candidate)
            }
            (source, candidate) => {
                kprintln!(
                    "candidate clone walk mismatch at {:#018x}: inherited={:?}, candidate={:?}",
                    virtual_address,
                    source,
                    candidate
                );
                return false;
            }
        };
        if !source_translation.same_effective_mapping(candidate_translation)
            || candidate_translation.physical_address != expected_physical
        {
            kprintln!(
                "candidate clone translation mismatch at {:#018x}: inherited={:?}, candidate={:?}, expected PA={:#x}",
                virtual_address,
                source_translation,
                candidate_translation,
                expected_physical
            );
            return false;
        }
        let Some(next_offset) = offset.checked_add(rustix_kernel::paging::PAGE_SIZE) else {
            return false;
        };
        offset = next_offset;
    }
    true
}

#[cfg(feature = "probe-hhdm-frame")]
fn probe_candidate_page_tables(boot_info: &mut boot::BootInfo) {
    use rustix_kernel::paging::{
        validate_mapping_range, CachePolicy, CandidatePageTables, PagePermissions, PageWalkOutcome,
    };

    let Some(physical_address_bits) = boot_info.cpu_info.physical_address_bits else {
        kprintln!("candidate page-table probe failed: physical width unknown");
        halt_forever();
    };
    if !boot_info.cpu_info.nx_enabled || !boot_info.cpu_info.normal_caching {
        kprintln!("candidate page-table probe failed: NXE or normal caching unavailable");
        halt_forever();
    }
    let pat_value = boot_info
        .cpu_info
        .pat_msr_value
        .expect("inherited cache-alias probe validated active PAT");
    let pat = rustix_kernel::paging::PatLayout::from_msr_value(pat_value).unwrap_or_else(|error| {
        kprintln!(
            "candidate page-table probe failed: invalid PAT: {:?}",
            error
        );
        halt_forever();
    });
    let registers = match &boot_info.cpu_info.mtrr {
        rustix_kernel::paging::MtrrState::Captured(registers) => registers,
        _ => {
            kprintln!("candidate page-table probe failed: captured MTRR state unavailable");
            halt_forever();
        }
    };
    let mtrrs = match registers.validated_layout(physical_address_bits) {
        Ok(mtrrs) => mtrrs,
        Err(error) => {
            kprintln!(
                "candidate page-table probe failed: invalid MTRR: {:?}",
                error
            );
            halt_forever();
        }
    };
    let config = rustix_kernel::paging::PageWalkConfig {
        levels: if boot_info.cpu_info.active_linear_address_bits == 57 {
            5
        } else {
            4
        },
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
        nx_enabled: true,
        page_2m_supported: true,
        page_1g_supported: boot_info.cpu_info.has_1g_pages,
    };
    let virtual_address = 0xffff_9000_ffff_f000;
    let permissions = PagePermissions {
        writable: true,
        executable: false,
        user_accessible: false,
    };
    let frame = match boot_info.frame_allocator.allocate() {
        Some(frame) => frame,
        None => {
            kprintln!("candidate page-table probe failed: no leaf frame available");
            halt_forever();
        }
    };
    let mapping = match validate_mapping_range(
        virtual_address,
        frame.address(),
        rustix_kernel::paging::PAGE_SIZE,
        permissions,
        Some(physical_address_bits),
        config.virtual_address_bits,
    ) {
        Ok(mapping) => mapping,
        Err(error) => {
            kprintln!(
                "candidate page-table probe failed: invalid mapping: {:?}",
                error
            );
            release_probe_frame(&mut boot_info.frame_allocator, frame);
            halt_forever();
        }
    };
    let cache_attributes = match mapping.select_cache_attributes(
        CachePolicy::WriteBack,
        pat,
        &mtrrs,
        boot_info.cpu_info.normal_caching,
    ) {
        Ok(attributes) => attributes,
        Err(error) => {
            kprintln!(
                "candidate page-table probe failed: cache policy: {:?}",
                error
            );
            release_probe_frame(&mut boot_info.frame_allocator, frame);
            halt_forever();
        }
    };

    let mut memory = LimineHhdmCandidateMemory {
        memory_map: &boot_info.memory_map,
        hhdm_offset: boot_info.hhdm_offset,
        physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
    };
    let mut candidate =
        match CandidatePageTables::new(&mut boot_info.frame_allocator, &mut memory, config) {
            Ok(candidate) => candidate,
            Err(error) => {
                kprintln!(
                    "candidate page-table probe failed to create root: {:?}",
                    error.cause
                );
                release_probe_frame(&mut boot_info.frame_allocator, frame);
                if let Some(root_frame) = error.frame {
                    release_probe_frame(&mut boot_info.frame_allocator, root_frame);
                }
                halt_forever();
            }
        };
    let root = candidate.root_physical_address();
    let frame_address = frame.address();
    if let Err(failure) = candidate.map_owned_page(
        &mut boot_info.frame_allocator,
        frame,
        mapping,
        cache_attributes,
    ) {
        kprintln!(
            "candidate page-table probe failed to map leaf: {:?}",
            failure.cause
        );
        release_probe_frame(&mut boot_info.frame_allocator, failure.frame);
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }

    let walk = candidate.walk(virtual_address);
    let returned_frame = match candidate.unmap_owned_page(virtual_address) {
        Ok(frame) => frame,
        Err(error) => {
            kprintln!(
                "candidate page-table probe failed to unmap leaf: {:?}",
                error
            );
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    };
    let translation_valid = match &walk {
        Ok(PageWalkOutcome::Mapped(translation)) => {
            translation.physical_address == frame_address
                && translation.page_size == rustix_kernel::paging::PAGE_SIZE
                && translation.permissions == permissions
                && translation.pat_index == cache_attributes.pat_index()
        }
        _ => false,
    };
    if returned_frame.address() != frame_address {
        kprintln!("candidate page-table probe failed: unmap returned the wrong frame");
        release_probe_frame(&mut boot_info.frame_allocator, returned_frame);
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }
    release_probe_frame(&mut boot_info.frame_allocator, returned_frame);
    if !translation_valid {
        kprintln!(
            "candidate page-table probe failed: candidate walk: {:?}",
            walk
        );
        release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
    }
    if let Err(failure) = candidate.release(&mut boot_info.frame_allocator) {
        kprintln!(
            "candidate page-table probe failed to release frames: {:?}",
            failure
        );
        halt_forever();
    }
    kprintln!(
        "candidate page-table probe passed: mapped, walked, unmapped, and released root {:#x}; CR3 unchanged",
        root.expect("candidate retains root until release")
    );
}

fn release_candidate_after_probe_failure(
    candidate: rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
) -> ! {
    if let Err(failure) = candidate.release(allocator) {
        kprintln!("candidate page-table cleanup also failed: {:?}", failure);
    }
    halt_forever()
}

#[cfg(feature = "probe-hhdm-frame")]
fn verify_inherited_mapping(
    reader: &impl rustix_kernel::paging::PageTableReader<
        Error = rustix_kernel::memory::HhdmAddressError,
    >,
    root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
    label: &str,
    virtual_start: u64,
    physical_start: u64,
    length: u64,
) {
    use rustix_kernel::paging::{walk_virtual_address, PageWalkOutcome};

    let mut offset = 0;
    let mut pages = 0;
    let mut first_translation: Option<rustix_kernel::paging::PageTranslation> = None;
    let mut permissions_uniform = true;
    let mut pat_index_uniform = true;
    while offset < length {
        let virtual_address = match virtual_start.checked_add(offset) {
            Some(address) => address,
            None => {
                kprintln!("inherited mapping probe failed: {} virtual overflow", label);
                halt_forever();
            }
        };
        let expected_physical = match physical_start.checked_add(offset) {
            Some(address) => address,
            None => {
                kprintln!(
                    "inherited mapping probe failed: {} physical overflow",
                    label
                );
                halt_forever();
            }
        };
        let translation = match walk_virtual_address(reader, root, virtual_address, config) {
            Ok(PageWalkOutcome::Mapped(translation)) => translation,
            Ok(PageWalkOutcome::NotPresent { level }) => {
                if level == rustix_kernel::paging::PageLevel::Pml4 {
                    let pml4_index = ((virtual_address >> 39) & 0x1ff) as u16;
                    let root_entry = reader.read_entry(root.physical_address(), pml4_index);
                    kprintln!(
                        "inherited mapping PML4 detail: VA={:#018x}, index={}, root={:#x}, entry={:?}",
                        virtual_address,
                        pml4_index,
                        root.physical_address(),
                        root_entry
                    );
                }
                kprintln!(
                    "inherited mapping probe failed: {} absent at {:?}",
                    label,
                    level
                );
                halt_forever();
            }
            Err(error) => {
                kprintln!("inherited mapping probe failed: {}: {:?}", label, error);
                halt_forever();
            }
        };
        if translation.physical_address != expected_physical {
            kprintln!(
                "inherited mapping probe failed: {} {:#018x} mapped to {:#018x}, expected {:#018x}",
                label,
                virtual_address,
                translation.physical_address,
                expected_physical
            );
            halt_forever();
        }
        if let Some(first) = first_translation {
            permissions_uniform &= translation.permissions == first.permissions;
            pat_index_uniform &= translation.pat_index == first.pat_index;
        } else {
            first_translation = Some(translation);
        }
        pages += 1;
        offset += rustix_kernel::paging::PAGE_SIZE;
    }
    if let Some(first) = first_translation {
        kprintln!(
            "inherited mapping probe passed: {} ({} pages), first permissions={:?}, PAT index={}, leaf size={}, uniform permissions={}, uniform PAT index={}",
            label,
            pages,
            first.permissions,
            first.pat_index,
            first.page_size,
            permissions_uniform,
            pat_index_uniform
        );
    }
}

#[cfg(feature = "probe-hhdm-frame")]
fn verify_kernel_cache_aliases(
    boot_info: &boot::BootInfo,
    reader: &impl rustix_kernel::paging::PageTableReader<
        Error = rustix_kernel::memory::HhdmAddressError,
    >,
    root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
    pat: rustix_kernel::paging::PatLayout,
    mtrrs: &rustix_kernel::paging::ValidatedMtrrLayout,
    label: &str,
    kernel_virtual_start: u64,
    physical_start: u64,
    length: u64,
) {
    use rustix_kernel::paging::{walk_virtual_address, PageWalkOutcome};

    let mut offset = 0;
    let mut pages = 0;
    while offset < length {
        let physical = match physical_start.checked_add(offset) {
            Some(address) => address,
            None => {
                kprintln!("cache-alias probe failed: {} physical overflow", label);
                halt_forever();
            }
        };
        let kernel_virtual = match kernel_virtual_start.checked_add(offset) {
            Some(address) => address,
            None => {
                kprintln!("cache-alias probe failed: {} virtual overflow", label);
                halt_forever();
            }
        };
        let hhdm_virtual = match boot_info.memory_map.limine_hhdm_address(
            boot_info.hhdm_offset,
            physical,
            rustix_kernel::paging::PAGE_SIZE,
            boot_info.cpu_info.physical_address_bits,
            boot_info.cpu_info.active_linear_address_bits,
        ) {
            Ok(address) => address,
            Err(error) => {
                kprintln!(
                    "cache-alias probe failed: {} HHDM range: {:?}",
                    label,
                    error
                );
                halt_forever();
            }
        };
        let kernel_translation = match walk_virtual_address(reader, root, kernel_virtual, config) {
            Ok(PageWalkOutcome::Mapped(translation)) => translation,
            result => {
                kprintln!(
                    "cache-alias probe failed: {} kernel walk: {:?}",
                    label,
                    result
                );
                halt_forever();
            }
        };
        let hhdm_translation = match walk_virtual_address(reader, root, hhdm_virtual, config) {
            Ok(PageWalkOutcome::Mapped(translation)) => translation,
            result => {
                kprintln!(
                    "cache-alias probe failed: {} HHDM walk: {:?}",
                    label,
                    result
                );
                halt_forever();
            }
        };
        if kernel_translation.physical_address != physical
            || hhdm_translation.physical_address != physical
        {
            kprintln!(
                "cache-alias probe failed: {} physical {:#018x} has inconsistent translations",
                label,
                physical
            );
            halt_forever();
        }
        let kernel_type = match mtrrs.effective_memory_type_for(
            physical,
            pat,
            kernel_translation.pat_index,
            boot_info.cpu_info.normal_caching,
        ) {
            Ok(memory_type) => memory_type,
            Err(error) => {
                kprintln!(
                    "cache-alias probe failed: {} kernel PAT/MTRR: {:?}",
                    label,
                    error
                );
                halt_forever();
            }
        };
        let hhdm_type = match mtrrs.effective_memory_type_for(
            physical,
            pat,
            hhdm_translation.pat_index,
            boot_info.cpu_info.normal_caching,
        ) {
            Ok(memory_type) => memory_type,
            Err(error) => {
                kprintln!(
                    "cache-alias probe failed: {} HHDM PAT/MTRR: {:?}",
                    label,
                    error
                );
                halt_forever();
            }
        };
        if kernel_type != hhdm_type {
            kprintln!(
                "cache-alias conflict: {} PA {:#018x}, kernel {:?} vs HHDM {:?}",
                label,
                physical,
                kernel_type,
                hhdm_type
            );
            halt_forever();
        }
        pages += 1;
        offset += rustix_kernel::paging::PAGE_SIZE;
    }
    kprintln!(
        "cache-alias probe passed: {} ({} pages; effective types match)",
        label,
        pages
    );
}

fn release_probe_frame(
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    frame: rustix_kernel::frame::Frame,
) {
    if let Err(error) = allocator.deallocate(frame) {
        kprintln!(
            "HHDM frame probe failed to return its frame: {:?}",
            error.error
        );
        halt_forever();
    }
}

#[cfg(feature = "inject-page-fault")]
fn run_fault_injection() {
    kprintln!("fault injection: triggering page fault at 0x00000000deadbeef");
    // SAFETY: This is an opt-in QEMU test that deliberately reads an unmapped
    // low virtual address; the installed page-fault handler is expected to halt.
    unsafe {
        core::arch::asm!(
            "mov rax, 0xdeadbeef",
            "mov rax, qword ptr [rax]",
            out("rax") _,
            options(nostack)
        );
    }
    kprintln!("fault injection unexpectedly returned");
    halt_forever();
}

#[cfg(feature = "inject-invalid-opcode")]
fn run_fault_injection() {
    kprintln!("fault injection: triggering invalid opcode with ud2");
    // SAFETY: This is an opt-in QEMU test that deliberately raises #UD; the
    // installed invalid-opcode handler is expected to halt.
    unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
    kprintln!("fault injection unexpectedly returned");
    halt_forever();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    arch::x86_64::serial::initialize();
    kprintln!("KERNEL PANIC: {}", info);
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: The bootstrap has no interrupt handlers or scheduler to resume.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
