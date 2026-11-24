#![no_std]
#![no_main]

#[cfg(any(
    all(feature = "inject-page-fault", feature = "inject-invalid-opcode"),
    all(feature = "inject-page-fault", feature = "probe-hhdm-frame"),
    all(feature = "inject-invalid-opcode", feature = "probe-hhdm-frame"),
    all(feature = "probe-kernel-threads", feature = "inject-page-fault"),
    all(feature = "probe-kernel-threads", feature = "inject-invalid-opcode"),
    all(feature = "probe-kernel-threads", feature = "probe-hhdm-frame"),
    all(feature = "probe-kernel-threads", feature = "probe-active-mapping"),
    all(feature = "boot-userspace", feature = "inject-page-fault"),
    all(feature = "boot-userspace", feature = "inject-invalid-opcode"),
    all(feature = "boot-userspace", feature = "probe-kernel-threads"),
    all(feature = "boot-userspace", feature = "probe-hhdm-frame"),
    all(feature = "boot-userspace", feature = "probe-active-mapping"),
    all(feature = "inject-page-fault", feature = "inject-general-protection"),
    all(feature = "inject-page-fault", feature = "inject-divide-error"),
    all(
        feature = "inject-invalid-opcode",
        feature = "inject-general-protection"
    ),
    all(feature = "inject-invalid-opcode", feature = "inject-divide-error"),
    all(feature = "inject-general-protection", feature = "inject-divide-error"),
    all(feature = "inject-general-protection", feature = "probe-hhdm-frame"),
    all(
        feature = "inject-general-protection",
        feature = "probe-kernel-threads"
    ),
    all(
        feature = "inject-general-protection",
        feature = "probe-active-mapping"
    ),
    all(feature = "inject-general-protection", feature = "boot-userspace"),
    all(feature = "inject-divide-error", feature = "probe-hhdm-frame"),
    all(feature = "inject-divide-error", feature = "probe-kernel-threads"),
    all(feature = "inject-divide-error", feature = "probe-active-mapping"),
    all(feature = "inject-divide-error", feature = "boot-userspace"),
    all(feature = "probe-user-fault", feature = "probe-user-page-fault"),
    all(
        feature = "probe-user-fault",
        feature = "probe-user-general-protection"
    ),
    all(feature = "probe-user-fault", feature = "probe-user-divide-error"),
    all(
        feature = "probe-user-page-fault",
        feature = "probe-user-general-protection"
    ),
    all(feature = "probe-user-page-fault", feature = "probe-user-divide-error"),
    all(
        feature = "probe-user-fault",
        feature = "probe-user-invalid-syscall-return"
    ),
    all(
        feature = "probe-user-page-fault",
        feature = "probe-user-invalid-syscall-return"
    ),
    all(
        feature = "probe-user-general-protection",
        feature = "probe-user-invalid-syscall-return"
    ),
    all(
        feature = "probe-user-divide-error",
        feature = "probe-user-invalid-syscall-return"
    ),
    all(
        feature = "probe-user-general-protection",
        feature = "probe-user-divide-error"
    ),
    all(
        feature = "probe-userspace-launch-failure",
        feature = "probe-user-process"
    )
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
#[cfg(target_os = "none")]
const INIT_ELF_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rustix-init.elf"));

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
static mut SPAWN_IMAGE_STAGING: [u8; rustix_kernel::syscall::MAX_SPAWN_IMAGE_BYTES as usize] =
    [0; rustix_kernel::syscall::MAX_SPAWN_IMAGE_BYTES as usize];
#[cfg(any(
    feature = "probe-user-fault",
    feature = "probe-user-page-fault",
    feature = "probe-user-general-protection",
    feature = "probe-user-divide-error",
    feature = "probe-user-invalid-syscall-return"
))]
const PROBE_USER_FAULT_VECTOR: u64 = if cfg!(feature = "probe-user-invalid-syscall-return") {
    13
} else if cfg!(feature = "probe-user-fault") {
    6
} else if cfg!(feature = "probe-user-page-fault") {
    14
} else if cfg!(feature = "probe-user-general-protection") {
    13
} else {
    0
};

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

#[cfg(any(
    feature = "probe-hhdm-frame",
    all(target_os = "none", feature = "boot-userspace")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimineUserFrameMemoryError {
    OutOfBounds,
    Address(rustix_kernel::memory::HhdmAddressError),
}

#[cfg(any(
    feature = "probe-hhdm-frame",
    all(target_os = "none", feature = "boot-userspace")
))]
struct LimineHhdmUserFrameMemory<'a> {
    memory_map: &'a rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: Option<u8>,
    virtual_address_bits: u8,
}

#[cfg(any(
    feature = "probe-hhdm-frame",
    all(target_os = "none", feature = "boot-userspace")
))]
impl LimineHhdmUserFrameMemory<'_> {
    fn frame_slice_address(
        &self,
        frame: &rustix_kernel::frame::Frame,
        offset: usize,
        length: usize,
    ) -> Result<*mut u8, LimineUserFrameMemoryError> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > rustix_kernel::frame::FRAME_SIZE as usize)
        {
            return Err(LimineUserFrameMemoryError::OutOfBounds);
        }
        if length == 0 {
            return Ok(core::ptr::null_mut());
        }

        let base = frame
            .hhdm_address(
                self.memory_map,
                self.hhdm_offset,
                self.physical_address_bits,
                self.virtual_address_bits,
            )
            .map_err(LimineUserFrameMemoryError::Address)?;
        let address =
            base.checked_add(offset as u64)
                .ok_or(LimineUserFrameMemoryError::Address(
                    rustix_kernel::memory::HhdmAddressError::AddressOverflow,
                ))?;
        Ok(address as *mut u8)
    }
}

#[cfg(any(
    feature = "probe-hhdm-frame",
    all(target_os = "none", feature = "boot-userspace")
))]
// SAFETY: The non-copyable Frame token and checked HHDM conversion authorize a
// complete Usable page. Each operation checks its subrange, accesses only that
// page, and uses raw copies rather than forming user virtual references. The
// implementation relies on Limine's mapped-usable-memory contract; hardware
// faults from a broken mapping remain fatal and are not recoverable here.
unsafe impl rustix_kernel::paging::UserFrameMemory for LimineHhdmUserFrameMemory<'_> {
    type Error = LimineUserFrameMemoryError;

    fn copy_from_frame(
        &mut self,
        frame: &rustix_kernel::frame::Frame,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let source = self.frame_slice_address(frame, offset, destination.len())?;
        if !destination.is_empty() {
            // SAFETY: The frame subrange was checked and the HHDM address was
            // validated for the full allocator-owned frame. `copy` permits overlap.
            unsafe { core::ptr::copy(source, destination.as_mut_ptr(), destination.len()) };
        }
        Ok(())
    }

    fn copy_to_frame(
        &mut self,
        frame: &rustix_kernel::frame::Frame,
        offset: usize,
        source: &[u8],
    ) -> Result<(), Self::Error> {
        let destination = self.frame_slice_address(frame, offset, source.len())?;
        if !source.is_empty() {
            // SAFETY: The frame subrange was checked and the HHDM address was
            // validated for the full allocator-owned frame. `copy` permits overlap.
            unsafe { core::ptr::copy(source.as_ptr(), destination, source.len()) };
        }
        Ok(())
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
        for (mapped, page) in (first_page..first_page + page_count).enumerate() {
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
        }
        Some(())
    })()
    .is_some();
    if flags & (1 << 9) != 0 {
        // SAFETY: The mapping transaction is complete or fully rolled back.
        unsafe { core::arch::asm!("sti") };
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
        let Some(virtual_address) = (page as u64)
            .checked_mul(PAGE_SIZE)
            .and_then(|offset| KERNEL_HEAP_GROWTH_VIRTUAL_BASE.checked_add(offset))
        else {
            halt_forever();
        };
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
    // Keep interrupts masked until FPU state and the IRQ save destination are ready.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    arch::x86_64::serial::initialize();
    if let Err(error) = arch::x86_64::cpu::initialize_fpu_state() {
        kprintln!("required x87/SSE state unavailable: {:?}", error);
        halt_forever();
    }
    kernel_threads::initialize_fpu_context();
    kprintln!("Rustix kernel: x86_64 Rust bootstrap");
    kprintln!("x87/SSE context state enabled with FXSAVE/FXRSTOR; AVX disabled");
    arch::x86_64::interrupts::initialize();
    kprintln!("x86_64 exception diagnostics: enabled (IRQs remain disabled)");
    let mut boot_info = match boot::capture_boot_information(entry_rsp) {
        Ok(boot_info) => boot_info,
        Err(error) => {
            kprintln!("boot information rejected: {:?}", error);
            halt_forever();
        }
    };
    if let Err(error) = arch::x86_64::interrupts::configure_user_address_width(
        boot_info.cpu_info.active_linear_address_bits,
    ) {
        kprintln!("user syscall address-width setup failed: {:?}", error);
        halt_forever();
    }
    #[cfg(target_os = "none")]
    let init_image = match rustix_kernel::elf::Elf64Image::parse(
        INIT_ELF_IMAGE,
        boot_info.cpu_info.active_linear_address_bits,
    ) {
        Ok(image) => image,
        Err(error) => {
            kprintln!("bundled init ELF rejected: {:?}", error);
            halt_forever();
        }
    };
    #[cfg(target_os = "none")]
    kprintln!(
        "bundled init ELF validated: entry={:#x}, load pages={}",
        init_image.entry_point(),
        init_image.load_page_count()
    );
    boot::report_boot_information(&boot_info);

    #[cfg(feature = "probe-hhdm-frame")]
    probe_hhdm_frame(&mut boot_info);

    #[cfg(any(
        feature = "inject-page-fault",
        feature = "inject-invalid-opcode",
        feature = "inject-general-protection",
        feature = "inject-divide-error"
    ))]
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
        KernelAliasHardeningContext {
            memory_map: &boot_info.memory_map,
            hhdm_offset: boot_info.hhdm_offset,
            physical_address_bits: boot_info.cpu_info.physical_address_bits,
            virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
            segments: boot_info.kernel_image_segments,
            reader: &reader,
            inherited_root,
            config,
        },
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
            &boot_info.memory_map,
            (
                boot_info.kernel_physical_base,
                boot_info.kernel_physical_end,
            ),
        ) {
            Ok(addresses) => Some(addresses),
            Err(error) => {
                kprintln!("APIC MMIO mappings unavailable: {}", error);
                None
            }
        },
        None => None,
    };
    match candidate.validate_supervisor_kernel_half() {
        Ok(table_count) => kprintln!(
            "kernel upper-half preflight passed: {} shared supervisor tables",
            table_count
        ),
        Err(error) => {
            kprintln!(
                "page-table transition rejected: unsafe kernel upper half: {:?}",
                error
            );
            release_candidate_after_probe_failure(candidate, &mut boot_info.frame_allocator);
        }
    }
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
        unsafe { core::arch::asm!("sti") };
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

    #[cfg(all(target_os = "none", feature = "boot-userspace"))]
    {
        let probe_flags: u64;
        // SAFETY: This is the single-vCPU bootstrap path; retain IF for restoration.
        unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) probe_flags) };
        KERNEL_HEAP.seal_frame_backed_growth();

        let probe_result = probe_user_process_root(
            &mut candidate,
            &boot_info.memory_map,
            &mut boot_info.frame_allocator,
            &boot_info.cpu_info,
            boot_info.hhdm_offset,
            config,
        );
        // SAFETY: The process root set and its shared borrow are dropped before
        // returning from the probe. The candidate and callback context remain live.
        if let Err(error) = unsafe {
            KERNEL_HEAP.initialize_frame_backed_region(
                KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize,
                KERNEL_HEAP_GROWTH_MAX_PAGES,
                core::ptr::addr_of_mut!(heap_mapping_context).cast(),
                map_kernel_heap_pages,
            )
        } {
            kprintln!(
                "process-root probe could not restore heap growth: {:?}",
                error
            );
            halt_forever();
        }
        if probe_flags & (1 << 9) != 0 {
            // SAFETY: The process root is destroyed and heap growth is restored.
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
        }
        if let Err(error) = probe_result {
            #[cfg(feature = "probe-user-process")]
            {
                kprintln!("process-root probe failed: {}", error);
                halt_forever();
            }
            // Normal-boot failure policy: report the launch failure over the
            // serial console and fall back to the kernel shell so diagnostics
            // remain reachable. The runtime reclaims every root and stack it
            // created before returning an error.
            #[cfg(not(feature = "probe-user-process"))]
            kprintln!(
                "normal-boot userspace launch failed: {}; continuing to Crabshell",
                error
            );
        }
        #[cfg(not(any(
            feature = "probe-user-fault",
            feature = "probe-user-page-fault",
            feature = "probe-user-general-protection",
            feature = "probe-user-divide-error",
            feature = "probe-user-invalid-syscall-return"
        )))]
        {
            if probe_result.is_ok() {
                kprintln!("Ring 3 init passed: write/EFAULT/blocking child wait/exit syscalls, kernel wait, and process-root teardown");
                #[cfg(not(feature = "probe-user-process"))]
                kprintln!("normal-boot userspace passed: init ran, exited, and was reaped before the shell");
            }
        }
        #[cfg(any(
            feature = "probe-user-fault",
            feature = "probe-user-page-fault",
            feature = "probe-user-general-protection",
            feature = "probe-user-divide-error",
            feature = "probe-user-invalid-syscall-return"
        ))]
        kprintln!(
            "Ring 3 user fault passed: process exited, was waited on, and its root was torn down"
        );
    }

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
    // Acknowledge before a scheduling switch so the APIC does not retain an
    // in-service timer vector while another context runs.
    arch::x86_64::apic::end_of_interrupt();
    kernel_threads::timer_interrupt();
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
    memory_map: &rustix_kernel::memory::MemoryMap,
    kernel_physical_span: (u64, u64),
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
        if physical_address & (PAGE_SIZE - 1) != 0 {
            return Err("APIC MMIO page is not 4 KiB aligned");
        }
        // Platform data does not authorize writing to ordinary memory: the APIC
        // MMIO pages must lie outside known non-MMIO memory-map regions and the
        // kernel image. A hostile or buggy MADT can name an arbitrary page.
        let mmio_span = memory_map
            .validate_mmio_page(physical_address, Some(physical_address_bits))
            .map_err(|_| "APIC MMIO page failed physical-memory authorization")?;
        let page_end = physical_address
            .checked_add(PAGE_SIZE)
            .ok_or("APIC MMIO page address overflows")?;
        if physical_address < kernel_physical_span.1 && kernel_physical_span.0 < page_end {
            return Err("APIC MMIO page overlaps the kernel image");
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
        // SAFETY: Both physical addresses come from the copied MADT, were
        // validated against the physical memory map and the kernel image span,
        // and are used only as device registers; they will be mapped with the
        // validated UC policy. The API enforces supervisor RW/NX mappings and
        // non-ownership.
        unsafe {
            candidate
                .map_mmio_page(allocator, mmio_span, mapping, attributes)
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

struct KernelAliasHardeningContext<'a, R> {
    memory_map: &'a rustix_kernel::memory::MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: Option<u8>,
    virtual_address_bits: u8,
    segments: rustix_kernel::memory::KernelImageSegments,
    reader: &'a R,
    inherited_root: rustix_kernel::paging::Cr3Root,
    config: rustix_kernel::paging::PageWalkConfig,
}

fn harden_kernel_hhdm_aliases<R>(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    context: KernelAliasHardeningContext<'_, R>,
) -> bool
where
    R: rustix_kernel::paging::PageTableReader<Error = rustix_kernel::memory::HhdmAddressError>,
{
    use rustix_kernel::paging::{
        walk_virtual_address, PagePermissions, PageWalkOutcome, PAGE_SIZE,
    };

    let KernelAliasHardeningContext {
        memory_map,
        hhdm_offset,
        physical_address_bits,
        virtual_address_bits,
        segments,
        reader,
        inherited_root,
        config,
    } = context;

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
    if allocation.is_null() || !(allocation as usize).is_multiple_of(layout.align()) {
        if !allocation.is_null() {
            // SAFETY: This is the live allocation returned for `layout`.
            unsafe { KERNEL_HEAP.dealloc(allocation, layout) };
        }
        kprintln!("kernel heap probe failed: aligned allocation was rejected or misaligned");
        halt_forever();
    }
    let Some(allocation) = core::ptr::NonNull::new(allocation) else {
        kprintln!("kernel heap probe failed: aligned allocation was unexpectedly null");
        halt_forever();
    };
    // SAFETY: The allocator returned `layout.size()` writable bytes.
    unsafe { core::ptr::write_bytes(allocation.as_ptr(), 0xa5, layout.size()) };
    for index in 0..layout.size() {
        // SAFETY: `index` remains inside the live allocation.
        if unsafe { allocation.as_ptr().add(index).read_volatile() } != 0xa5 {
            // SAFETY: The allocation is still live with its original layout.
            unsafe { KERNEL_HEAP.dealloc(allocation.as_ptr(), layout) };
            kprintln!("kernel heap probe failed: allocation data did not round-trip");
            halt_forever();
        }
    }
    // SAFETY: The allocation is live and the original layout is supplied.
    unsafe { KERNEL_HEAP.dealloc(allocation.as_ptr(), layout) };
    // SAFETY: The previous allocation was returned; first-fit should reuse it.
    let reused = unsafe { KERNEL_HEAP.alloc(layout) };
    if reused != allocation.as_ptr() {
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
    let Some(growth) = core::ptr::NonNull::new(growth) else {
        kprintln!("kernel heap probe failed: frame-backed allocation was rejected");
        halt_forever();
    };
    let growth_address = growth.as_ptr() as usize;
    let growth_end = KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize
        + KERNEL_HEAP_GROWTH_MAX_PAGES * PAGE_SIZE as usize;
    if growth_address < KERNEL_HEAP_GROWTH_VIRTUAL_BASE as usize
        || growth_address
            .checked_add(growth_layout.size())
            .is_none_or(|end| end > growth_end)
        || !growth_address.is_multiple_of(growth_layout.align())
    {
        // SAFETY: `growth` is the live allocation returned for `growth_layout`.
        unsafe { KERNEL_HEAP.dealloc(growth.as_ptr(), growth_layout) };
        kprintln!("kernel heap probe failed: frame-backed allocation was invalid");
        halt_forever();
    }
    // SAFETY: GlobalAlloc returned a live allocation, and the checks above keep
    // its complete extent inside the reserved range. The heap mapper commits all
    // pages covering the allocation before returning it. MaybeUninit permits the
    // backing frames to be uninitialized when the mutable view is created.
    let growth_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            growth.as_ptr().cast::<core::mem::MaybeUninit<u8>>(),
            growth_layout.size(),
        )
    };
    let last_byte = growth_layout.size() - 1;
    growth_bytes[0].write(0x5a);
    growth_bytes[last_byte].write(0xa5);
    // SAFETY: Both slots were initialized immediately above and are within the
    // validated live allocation. Reading through the references retains the
    // allocation's validity proof for the volatile access.
    let first_byte = unsafe { growth_bytes[0].assume_init_ref() };
    let last_byte = unsafe { growth_bytes[last_byte].assume_init_ref() };
    if unsafe { core::ptr::read_volatile(first_byte) } != 0x5a
        || unsafe { core::ptr::read_volatile(last_byte) } != 0xa5
    {
        // SAFETY: The allocation is still live with its original layout.
        unsafe { KERNEL_HEAP.dealloc(growth.as_ptr(), growth_layout) };
        kprintln!("kernel heap probe failed: frame-backed data did not round-trip");
        halt_forever();
    }
    // SAFETY: Return the exact growth allocation and then require first-fit reuse.
    unsafe { KERNEL_HEAP.dealloc(growth.as_ptr(), growth_layout) };
    let growth_reused = unsafe { KERNEL_HEAP.alloc(growth_layout) };
    if growth_reused != growth.as_ptr() {
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

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
struct SerialProcessProbeOutput;

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
impl rustix_kernel::syscall::ConsoleOutput for SerialProcessProbeOutput {
    type Error = ();

    fn write(
        &mut self,
        _stream: rustix_kernel::syscall::ConsoleStream,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        let text = core::str::from_utf8(bytes).map_err(|_| ())?;
        arch::x86_64::serial::print(format_args!("{}", text));
        Ok(bytes.len())
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
struct ActiveUserProcessSyscallContext {
    roots: *mut (),
    kernel_candidate: *mut (),
    cpu_info: *const arch::x86_64::cpu::CpuInfo,
    cr3_low_bits: rustix_kernel::paging::Cr3LowBits,
    user_memory: *mut (),
    allocator: *mut rustix_kernel::frame::FrameAllocator,
    user_regions: *mut rustix_kernel::process::UserRegionTable,
    process_table: *mut rustix_kernel::process::ProcessTable,
    mtrr_layout: *const rustix_kernel::paging::ValidatedMtrrLayout,
    process: rustix_kernel::paging::ProcessAddressSpaceHandle,
    process_id: rustix_kernel::process::ProcessId,
    kernel_cr3: u64,
    process_cr3: u64,
    kernel_entry_stack_top: u64,
    runtime_pointer: *mut (),
    user_frame: rustix_kernel::syscall::ValidatedUserIretFrame,
    slots: *mut ProcessTaskSlot,
    task_slot: usize,
    pat: rustix_kernel::paging::PatLayout,
    normal_caching: bool,
    physical_address_bits: u8,
    virtual_address_bits: u8,
}

/// One reusable scheduler-slot record for a process task.
///
/// `occupied` means the context is published and the task owns its stacks until
/// it is reaped; `root_owned` tracks whether the process root still needs
/// teardown. Slot indices are scheduler slots, never PID arithmetic.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
struct ProcessTaskSlot {
    occupied: bool,
    root_owned: bool,
    regions: core::mem::MaybeUninit<rustix_kernel::process::UserRegionTable>,
    context: core::mem::MaybeUninit<ActiveUserProcessSyscallContext>,
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
impl ProcessTaskSlot {
    const EMPTY: Self = Self {
        occupied: false,
        root_owned: false,
        regions: core::mem::MaybeUninit::uninit(),
        context: core::mem::MaybeUninit::uninit(),
    };
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn finish_active_user_process<M: rustix_kernel::paging::CandidatePageTableMemory>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    status: i32,
) -> i64 {
    use rustix_kernel::syscall::SyscallError;

    // SAFETY: The process table remains live through this synchronous entry.
    if unsafe { &mut *state.process_table }
        .exit(state.process_id, status)
        .is_err()
    {
        return SyscallError::InvalidArgument.return_value();
    }
    // SAFETY: The kernel CR3 was captured before entering this root, and
    // interrupts remain disabled for the complete user-process run.
    unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(state.kernel_cr3) };
    if arch::x86_64::cpu::read_cr3_raw() != state.kernel_cr3 {
        halt_forever();
    }
    // SAFETY: The kernel root is installed and verified; no CPU can use the
    // process root after this point in the single-vCPU test harness.
    if unsafe { roots.mark_inactive(state.process) }.is_err() {
        halt_forever();
    }
    // SAFETY: This exit callback runs with IF clear inside a live pinned process task.
    if !unsafe { crate::kernel_threads::wake_process_exit_waiters(state.runtime_pointer) } {
        halt_forever();
    }
    // SAFETY: The kernel root is active, process root is inactive, and IF=0.
    unsafe { arch::x86_64::interrupts::request_user_process_exit(status) };
    0
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
extern "C" fn dispatch_active_user_process_syscall(
    raw_context: *mut rustix_kernel::syscall::SyscallContext,
    opaque: *mut (),
) -> i64 {
    use rustix_kernel::syscall::{
        decode_syscall, SyscallArguments, SyscallError, SyscallRequest, ABI_VERSION,
    };

    // SAFETY: The DPL-3 entry supplies a live kernel-stack context. The runtime
    // pointer is installed only for the synchronous user entry below and remains
    // valid until the exit path returns to this stack.
    let Some(context) = (unsafe { raw_context.as_mut() }) else {
        halt_forever();
    };
    // SAFETY: `opaque` points to the live stack-owned runtime record registered
    // before switching to the process root; callbacks cannot retain its fields.
    let state_ptr = opaque.cast::<ActiveUserProcessSyscallContext>();
    if state_ptr.is_null() {
        halt_forever();
    }
    // SAFETY: The process root is active and the sanitized syscall return frame
    // must resolve to executable code and a writable NX stack before any service.
    let process = unsafe { core::ptr::addr_of!((*state_ptr).process).read() };
    let roots_ptr = unsafe {
        core::ptr::addr_of!((*state_ptr).roots).read().cast::<
            rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_ ,
                '_ ,
                '_ ,
                LimineHhdmCandidateMemory<'_>,
            >,
        >()
    };
    let return_state_valid = unsafe { &*roots_ptr }
        .validate_user_return_state(process, context.instruction_pointer, context.stack_pointer)
        .is_ok();
    if !return_state_valid {
        // The process root remains active until its fatal bad-return path switches
        // back to the kernel root and requests the nested entry exit.
        let state = unsafe { &mut *state_ptr };
        let roots = unsafe { &mut *roots_ptr };
        return finish_active_user_process(state, roots, 141);
    }
    let arguments = SyscallArguments {
        rdi: context.rdi,
        rsi: context.rsi,
        rdx: context.rdx,
        r10: context.r10,
        r8: context.r8,
        r9: context.r9,
    };
    let request = match decode_syscall(context.rax, arguments) {
        Ok(request) => request,
        Err(error) => return error.return_value(),
    };
    if let SyscallRequest::Wait {
        child_pid,
        status_address,
    } = request
    {
        return dispatch_user_wait(state_ptr, child_pid, status_address);
    }
    if let SyscallRequest::Spawn {
        image_address,
        image_length,
        stack_pages,
    } = request
    {
        return dispatch_user_spawn(state_ptr, image_address, image_length, stack_pages);
    }
    if let SyscallRequest::Exec {
        image_address,
        image_length,
        stack_pages,
    } = request
    {
        return dispatch_user_exec(
            state_ptr,
            raw_context,
            image_address,
            image_length,
            stack_pages,
        );
    }

    // These mutable references are created only after the blocking-wait branch
    // returns; the child runner may re-enter the callback with this same state.
    let state = unsafe { &mut *state_ptr };
    let roots = unsafe { &mut *roots_ptr };
    let user_memory = unsafe { &mut *state.user_memory.cast::<LimineHhdmUserFrameMemory<'_>>() };
    match request {
        SyscallRequest::AbiVersion => ABI_VERSION as i64,
        SyscallRequest::Write {
            fd,
            user_buffer,
            length,
        } => {
            let stream =
                // SAFETY: The process table remains live and IF is clear for this
                // synchronous single-vCPU dispatch.
                unsafe { &*state.process_table }.descriptor_stream(state.process_id, fd);
            let Some(stream) = stream else {
                return SyscallError::BadFileDescriptor.return_value();
            };
            let mut output = SerialProcessProbeOutput;
            // SAFETY: The kernel stack is not allocator-usable user memory; the
            // service copies via owned frame tokens and never dereferences user VA.
            match unsafe {
                rustix_kernel::syscall::write_user_buffer_to_stream(
                    roots,
                    state.process,
                    stream,
                    user_buffer,
                    length,
                    user_memory,
                    &mut output,
                )
            } {
                Ok(written) => written as i64,
                Err(error) => error.return_value(),
            }
        }
        SyscallRequest::Close { fd } => {
            // SAFETY: Process-table mutation is serialized by IF=0 on the single CPU.
            match unsafe { &mut *state.process_table }.close_descriptor(state.process_id, fd) {
                Ok(()) => 0,
                Err(error) => descriptor_error_to_syscall(error).return_value(),
            }
        }
        SyscallRequest::Duplicate { fd } => {
            // SAFETY: Process-table mutation is serialized by IF=0 on the single CPU.
            match unsafe { &mut *state.process_table }.duplicate_descriptor(state.process_id, fd) {
                Ok(duplicate) => duplicate as i64,
                Err(error) => descriptor_error_to_syscall(error).return_value(),
            }
        }
        SyscallRequest::Exit { status } => finish_active_user_process(state, roots, status),
        SyscallRequest::Mmap { length } => {
            match map_anonymous_user_page(state, roots, user_memory, length) {
                Ok(address) => address as i64,
                Err(error) => error.return_value(),
            }
        }
        SyscallRequest::Munmap { address } => {
            match unmap_anonymous_user_page(state, roots, user_memory, address) {
                Ok(()) => 0,
                Err(error) => error.return_value(),
            }
        }
        SyscallRequest::MmapRegion { length } => {
            match map_anonymous_user_region(state, roots, user_memory, length) {
                Ok(address) => address as i64,
                Err(error) => error.return_value(),
            }
        }
        SyscallRequest::MunmapRegion { address, length } => {
            match unmap_anonymous_user_region(state, roots, user_memory, address, length) {
                Ok(()) => 0,
                Err(error) => error.return_value(),
            }
        }
        SyscallRequest::Spawn { .. } => unreachable!("spawn is dispatched before mutable borrows"),
        SyscallRequest::Exec { .. } => unreachable!("exec is dispatched before mutable borrows"),
        SyscallRequest::Wait { .. } => unreachable!("wait is dispatched before mutable borrows"),
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn dispatch_user_spawn(
    state_ptr: *mut ActiveUserProcessSyscallContext,
    image_address: u64,
    image_length: usize,
    stack_pages: usize,
) -> i64 {
    use rustix_kernel::syscall::SyscallError;

    if image_length == 0
        || image_length > rustix_kernel::syscall::MAX_SPAWN_IMAGE_BYTES as usize
        || stack_pages == 0
        || stack_pages > rustix_kernel::syscall::MAX_SPAWN_STACK_PAGES as usize
        || image_address.checked_add(image_length as u64).is_none()
    {
        return SyscallError::InvalidArgument.return_value();
    }
    let Some(state) = (unsafe { state_ptr.as_ref() }) else {
        return SyscallError::Io.return_value();
    };
    if state.slots.is_null() {
        return SyscallError::NotSupported.return_value();
    }
    if let Err(error) = copy_user_image_to_staging(state, image_address, image_length) {
        return error.return_value();
    }

    let roots_ptr =
        state
            .roots
            .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>();
    let state = unsafe { &mut *state_ptr };
    let roots = unsafe { &mut *roots_ptr };
    switch_process_to_kernel_root(state, roots);
    let staging = core::ptr::addr_of_mut!(SPAWN_IMAGE_STAGING).cast::<u8>();
    let image = unsafe { core::slice::from_raw_parts(staging.cast_const(), image_length) };
    let result = spawn_child_process(state, roots, image, stack_pages);
    switch_kernel_to_process_root(state, roots);
    match result {
        Ok(pid) => pid as i64,
        Err(error) => error.return_value(),
    }
}

/// Copy a bounded user ELF image into kernel-owned staging storage.
///
/// Runs while the caller's process root is active; user bytes are accessed only
/// through checked frame-token copies, never by dereferencing user addresses.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn copy_user_image_to_staging(
    state: &ActiveUserProcessSyscallContext,
    image_address: u64,
    image_length: usize,
) -> Result<(), rustix_kernel::syscall::SyscallError> {
    use rustix_kernel::syscall::SyscallError;

    let staging = core::ptr::addr_of_mut!(SPAWN_IMAGE_STAGING).cast::<u8>();
    let roots = unsafe {
        &*state
            .roots
            .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>()
    };
    let Some(user_memory) = (unsafe {
        state
            .user_memory
            .cast::<LimineHhdmUserFrameMemory<'_>>()
            .as_mut()
    }) else {
        return Err(SyscallError::Io);
    };
    let mut copied = 0usize;
    while copied < image_length {
        let length = (rustix_kernel::paging::PAGE_SIZE as usize).min(image_length - copied);
        let destination = unsafe { core::slice::from_raw_parts_mut(staging.add(copied), length) };
        let source = image_address + copied as u64;
        // SAFETY: The destination is kernel-owned staging storage and cannot
        // alias a frame mapped by the calling process. User bytes are copied
        // only through checked frame-token access while the caller root is active.
        match unsafe { roots.copy_from_user(state.process, source, destination, user_memory) } {
            Ok(length) if length == destination.len() => copied += length,
            Ok(_) => return Err(SyscallError::Fault),
            Err(failure) => {
                return Err(match failure.cause {
                    rustix_kernel::paging::ProcessUserCopyError::Memory(_) => SyscallError::Io,
                    _ => SyscallError::Fault,
                });
            }
        }
    }
    Ok(())
}

/// Compute the initial user stack base just below the lower-half canonical end.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn initial_user_stack_base(
    virtual_address_bits: u8,
    stack_pages: usize,
) -> Result<u64, rustix_kernel::syscall::SyscallError> {
    use rustix_kernel::syscall::SyscallError;

    let stack_bytes = (stack_pages as u64)
        .checked_mul(rustix_kernel::paging::PAGE_SIZE)
        .ok_or(SyscallError::Overflow)?;
    let lower_half_shift = u32::from(
        virtual_address_bits
            .checked_sub(1)
            .ok_or(SyscallError::InvalidArgument)?,
    );
    let stack_top = 1u64
        .checked_shl(lower_half_shift)
        .ok_or(SyscallError::InvalidArgument)?;
    stack_top
        .checked_sub(stack_bytes)
        .ok_or(SyscallError::InvalidArgument)
}

/// Replace the calling process's image, root, and stack (syscall 11).
///
/// On success the saved syscall return frame is rewritten to the replacement
/// image's validated entry, so the normal IRETQ path resumes Ring 3 there; the
/// old root is destroyed and the process keeps its PID, descriptors, parent,
/// children, and task/entry stacks. On any failure the old root is restored
/// active and the caller continues in the original image.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn dispatch_user_exec(
    state_ptr: *mut ActiveUserProcessSyscallContext,
    raw_context: *mut rustix_kernel::syscall::SyscallContext,
    image_address: u64,
    image_length: usize,
    stack_pages: usize,
) -> i64 {
    use rustix_kernel::syscall::SyscallError;

    if image_length == 0
        || image_length > rustix_kernel::syscall::MAX_SPAWN_IMAGE_BYTES as usize
        || stack_pages == 0
        || stack_pages > rustix_kernel::syscall::MAX_SPAWN_STACK_PAGES as usize
        || image_address.checked_add(image_length as u64).is_none()
    {
        return SyscallError::InvalidArgument.return_value();
    }
    let Some(state) = (unsafe { state_ptr.as_ref() }) else {
        return SyscallError::Io.return_value();
    };
    if let Err(error) = copy_user_image_to_staging(state, image_address, image_length) {
        return error.return_value();
    }

    let roots_ptr =
        state
            .roots
            .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>();
    let state = unsafe { &mut *state_ptr };
    let roots = unsafe { &mut *roots_ptr };
    switch_process_to_kernel_root(state, roots);
    let staging = core::ptr::addr_of_mut!(SPAWN_IMAGE_STAGING).cast::<u8>();
    let image = unsafe { core::slice::from_raw_parts(staging.cast_const(), image_length) };
    match exec_replace_process(state, roots, image, stack_pages, raw_context) {
        Ok(()) => 0,
        Err(error) => {
            // The replacement failed; the original root is still owned and the
            // process must resume in its original image.
            switch_kernel_to_process_root(state, roots);
            error.return_value()
        }
    }
}

/// Prepare and commit one exec replacement with the kernel root active.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn exec_replace_process<M: rustix_kernel::paging::CandidatePageTableMemory>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    image: &[u8],
    stack_pages: usize,
    raw_context: *mut rustix_kernel::syscall::SyscallContext,
) -> Result<(), rustix_kernel::syscall::SyscallError> {
    use rustix_kernel::paging::CachePolicy;
    use rustix_kernel::process::UserProgramPrepareErrorKind;
    use rustix_kernel::syscall::SyscallError;

    let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
        return Err(SyscallError::Io);
    };
    let Some(user_memory) = (unsafe {
        state
            .user_memory
            .cast::<LimineHhdmUserFrameMemory<'_>>()
            .as_mut()
    }) else {
        return Err(SyscallError::Io);
    };
    let Some(mtrr_layout) = (unsafe { state.mtrr_layout.as_ref() }) else {
        return Err(SyscallError::Io);
    };
    let mut select_cache = |mapping: rustix_kernel::paging::ValidatedMappingRange| {
        mapping
            .select_cache_attributes(
                CachePolicy::WriteBack,
                state.pat,
                mtrr_layout,
                state.normal_caching,
            )
            .map_err(|_| "no uniform write-back cache policy for exec process page")
    };
    let stack_base = initial_user_stack_base(state.virtual_address_bits, stack_pages)?;
    let program = match rustix_kernel::process::prepare_user_program(
        roots,
        allocator,
        user_memory,
        image,
        stack_base,
        stack_pages as u64,
        1,
        state.physical_address_bits,
        state.virtual_address_bits,
        arch::x86_64::interrupts::USER_CODE_SELECTOR,
        arch::x86_64::interrupts::USER_DATA_SELECTOR,
        &mut select_cache,
    ) {
        Ok(program) => program,
        Err(failure) => {
            let error = match failure.kind {
                UserProgramPrepareErrorKind::InvalidElf
                | UserProgramPrepareErrorKind::RegionReservation
                | UserProgramPrepareErrorKind::StackGuard
                | UserProgramPrepareErrorKind::InvalidInitialState
                | UserProgramPrepareErrorKind::InvalidIretFrame => SyscallError::InvalidArgument,
                UserProgramPrepareErrorKind::RootCreation
                | UserProgramPrepareErrorKind::StackAllocation => SyscallError::OutOfMemory,
                _ => SyscallError::Io,
            };
            if failure.cleanup(roots, allocator).is_err() {
                halt_forever();
            }
            return Err(error);
        }
    };
    let new_root_address = match roots.root_physical_address(program.process) {
        Ok(address) => address,
        Err(_) => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            return Err(SyscallError::Io);
        }
    };
    let new_cr3 = match rustix_kernel::paging::encode_cr3_value(
        new_root_address,
        state.cr3_low_bits,
        state.physical_address_bits,
    ) {
        Ok(value) => value,
        Err(_) => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            return Err(SyscallError::Io);
        }
    };

    // The old root is inactive (kernel root active). Reclaim it before the
    // switch; if reclamation fails it remains owned and the exec is rejected.
    let old_process = state.process;
    if roots.destroy(allocator, old_process).is_err() {
        roots
            .destroy(allocator, program.process)
            .unwrap_or_else(|_| halt_forever());
        return Err(SyscallError::Io);
    }

    // SAFETY: The replacement root is complete and owned; IF is clear on this
    // single vCPU and the shared kernel stacks remain mapped in both roots.
    unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(new_cr3) };
    if arch::x86_64::cpu::read_cr3_raw() != new_cr3 {
        halt_forever();
    }
    // SAFETY: CR3 now names the replacement root; the old root was destroyed.
    if unsafe { roots.mark_active(program.process) }.is_err() {
        halt_forever();
    }
    state.process = program.process;
    state.process_cr3 = new_cr3;
    state.user_frame = program.user_frame;
    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    *regions = program.regions;

    // Rewrite the saved return frame so the entry stub's IRETQ resumes Ring 3
    // at the replacement image. The stub restores the saved user x87/SSE image;
    // exec deliberately preserves it, and the new entry observes RAX=0.
    let Some(context) = (unsafe { raw_context.as_mut() }) else {
        halt_forever();
    };
    let frame = program.user_frame.into_raw();
    context.instruction_pointer = frame.instruction_pointer;
    context.code_selector = frame.code_selector;
    context.flags = frame.flags;
    context.stack_pointer = frame.stack_pointer;
    context.stack_selector = frame.stack_selector;
    Ok(())
}

/// Create one child of the calling process: record, private root, and task.
///
/// Runs with the kernel root active and IF clear. Every failure after the
/// process record is reserved rolls the record back; every failure after root
/// creation destroys the root; task creation failure leaves no scheduler state.
#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn spawn_child_process<M: rustix_kernel::paging::CandidatePageTableMemory>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    image: &[u8],
    stack_pages: usize,
) -> Result<u64, rustix_kernel::syscall::SyscallError> {
    use rustix_kernel::paging::CachePolicy;
    use rustix_kernel::process::UserProgramPrepareErrorKind;
    use rustix_kernel::syscall::SyscallError;

    let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
        return Err(SyscallError::Io);
    };
    let Some(user_memory) = (unsafe {
        state
            .user_memory
            .cast::<LimineHhdmUserFrameMemory<'_>>()
            .as_mut()
    }) else {
        return Err(SyscallError::Io);
    };
    let Some(mtrr_layout) = (unsafe { state.mtrr_layout.as_ref() }) else {
        return Err(SyscallError::Io);
    };
    let Some(process_table) = (unsafe { state.process_table.as_mut() }) else {
        return Err(SyscallError::Io);
    };
    let child_id = match process_table.spawn(state.process_id) {
        Ok(pid) => pid,
        Err(rustix_kernel::process::ProcessTableError::Capacity)
        | Err(rustix_kernel::process::ProcessTableError::ProcessIdExhausted) => {
            return Err(SyscallError::OutOfMemory);
        }
        Err(_) => return Err(SyscallError::InvalidArgument),
    };
    let mut select_cache = |mapping: rustix_kernel::paging::ValidatedMappingRange| {
        mapping
            .select_cache_attributes(
                CachePolicy::WriteBack,
                state.pat,
                mtrr_layout,
                state.normal_caching,
            )
            .map_err(|_| "no uniform write-back cache policy for spawned process page")
    };
    let stack_base = initial_user_stack_base(state.virtual_address_bits, stack_pages)?;
    let program = match rustix_kernel::process::prepare_user_program(
        roots,
        allocator,
        user_memory,
        image,
        stack_base,
        stack_pages as u64,
        1,
        state.physical_address_bits,
        state.virtual_address_bits,
        arch::x86_64::interrupts::USER_CODE_SELECTOR,
        arch::x86_64::interrupts::USER_DATA_SELECTOR,
        &mut select_cache,
    ) {
        Ok(program) => program,
        Err(failure) => {
            let error = match failure.kind {
                UserProgramPrepareErrorKind::InvalidElf
                | UserProgramPrepareErrorKind::RegionReservation
                | UserProgramPrepareErrorKind::StackGuard
                | UserProgramPrepareErrorKind::InvalidInitialState
                | UserProgramPrepareErrorKind::InvalidIretFrame => SyscallError::InvalidArgument,
                UserProgramPrepareErrorKind::RootCreation
                | UserProgramPrepareErrorKind::StackAllocation => SyscallError::OutOfMemory,
                _ => SyscallError::Io,
            };
            if failure.cleanup(roots, allocator).is_err() {
                halt_forever();
            }
            rollback_unstarted_child(process_table, state.process_id, child_id);
            return Err(error);
        }
    };

    let slot_index = match (0..rustix_kernel::process::MAX_PROCESSES)
        .find(|index| !unsafe { core::ptr::addr_of!((*state.slots.add(*index)).occupied).read() })
    {
        Some(index) => index,
        None => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            rollback_unstarted_child(process_table, state.process_id, child_id);
            return Err(SyscallError::OutOfMemory);
        }
    };
    let child_root_address = match roots.root_physical_address(program.process) {
        Ok(address) => address,
        Err(_) => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            rollback_unstarted_child(process_table, state.process_id, child_id);
            return Err(SyscallError::Io);
        }
    };
    let process_cr3 = match rustix_kernel::paging::encode_cr3_value(
        child_root_address,
        state.cr3_low_bits,
        state.physical_address_bits,
    ) {
        Ok(value) => value,
        Err(_) => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            rollback_unstarted_child(process_table, state.process_id, child_id);
            return Err(SyscallError::Io);
        }
    };

    let Some(candidate) = (unsafe {
        state
            .kernel_candidate
            .cast::<rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>>()
            .as_mut()
    }) else {
        roots
            .destroy(allocator, program.process)
            .unwrap_or_else(|_| halt_forever());
        rollback_unstarted_child(process_table, state.process_id, child_id);
        return Err(SyscallError::Io);
    };
    let Some(cpu_info) = (unsafe { state.cpu_info.as_ref() }) else {
        roots
            .destroy(allocator, program.process)
            .unwrap_or_else(|_| halt_forever());
        rollback_unstarted_child(process_table, state.process_id, child_id);
        return Err(SyscallError::Io);
    };
    // SAFETY: The slot array lives on the outer runtime stack until every task
    // exits; this slot is unoccupied and unpublished.
    let slot = unsafe { &mut *state.slots.add(slot_index) };
    let context_pointer =
        core::ptr::addr_of_mut!(slot.context).cast::<ActiveUserProcessSyscallContext>();
    // SAFETY: IF is clear and the pinned runtime stays live. The task becomes
    // Ready here, but the current task does not block, yield, or exit before
    // the context is published below, so it cannot dispatch prematurely.
    let spawned = unsafe {
        crate::kernel_threads::spawn_process_task(
            state.runtime_pointer,
            candidate,
            allocator,
            cpu_info,
            run_user_process_task,
            context_pointer as usize,
        )
    };
    let (_child_thread, entry_stack_top) = match spawned {
        Ok(spawned) => spawned,
        Err(_) => {
            roots
                .destroy(allocator, program.process)
                .unwrap_or_else(|_| halt_forever());
            rollback_unstarted_child(process_table, state.process_id, child_id);
            return Err(SyscallError::OutOfMemory);
        }
    };

    // SAFETY: The slot remains stable on the outer runtime stack until the task
    // runtime returns, and it has not previously been initialized or published.
    unsafe {
        core::ptr::addr_of_mut!(slot.regions).write(core::mem::MaybeUninit::new(program.regions));
        core::ptr::addr_of_mut!(slot.context).write(core::mem::MaybeUninit::new(
            ActiveUserProcessSyscallContext {
                roots: state.roots,
                kernel_candidate: state.kernel_candidate,
                cpu_info: state.cpu_info,
                cr3_low_bits: state.cr3_low_bits,
                user_memory: state.user_memory,
                allocator: state.allocator,
                user_regions: core::ptr::addr_of_mut!(slot.regions)
                    .cast::<rustix_kernel::process::UserRegionTable>(),
                process_table: state.process_table,
                mtrr_layout: state.mtrr_layout,
                process: program.process,
                process_id: child_id,
                kernel_cr3: state.kernel_cr3,
                process_cr3,
                kernel_entry_stack_top: entry_stack_top,
                runtime_pointer: core::ptr::null_mut(),
                user_frame: program.user_frame,
                slots: state.slots,
                task_slot: slot_index,
                pat: state.pat,
                normal_caching: state.normal_caching,
                physical_address_bits: state.physical_address_bits,
                virtual_address_bits: state.virtual_address_bits,
            },
        ));
        core::ptr::addr_of_mut!(slot.root_owned).write(true);
        core::ptr::addr_of_mut!(slot.occupied).write(true);
    }
    Ok(child_id.get())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn rollback_unstarted_child(
    process_table: &mut rustix_kernel::process::ProcessTable,
    parent: rustix_kernel::process::ProcessId,
    child_id: rustix_kernel::process::ProcessId,
) {
    // The record was never published to a task; reap it through its real parent
    // so the slot returns to the pool without leaving a zombie behind.
    if process_table.exit(child_id, 127).is_err()
        || !matches!(
            process_table.try_wait(parent, child_id.get()),
            Ok(rustix_kernel::process::WaitResult::Exited { pid, .. }) if pid == child_id
        )
    {
        halt_forever();
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn destroy_spawned_child_root<M: rustix_kernel::paging::CandidatePageTableMemory>(
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    slot: &mut ProcessTaskSlot,
) -> Result<(), &'static str> {
    if !slot.occupied || !slot.root_owned {
        return Ok(());
    }
    // SAFETY: A ready slot is initialized before the scheduler can dispatch it.
    let process = unsafe { slot.context.assume_init_ref() }.process;
    roots
        .destroy(allocator, process)
        .map_err(|_| "inactive spawned process root teardown failed")?;
    slot.root_owned = false;
    Ok(())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn destroy_spawned_child_roots<M: rustix_kernel::paging::CandidatePageTableMemory>(
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    slots: &mut [ProcessTaskSlot],
) -> Result<(), &'static str> {
    for slot in slots {
        destroy_spawned_child_root(roots, allocator, slot)?;
    }
    Ok(())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn dispatch_user_wait(
    state_ptr: *mut ActiveUserProcessSyscallContext,
    child_pid: u64,
    status_address: Option<u64>,
) -> i64 {
    use rustix_kernel::syscall::SyscallError;

    // SAFETY: The installed callback context remains live while this scheduler
    // task blocks and resumes; IF=0 serializes process-table access on one CPU.
    let (
        process_id,
        process_table_ptr,
        roots_ptr,
        runtime_pointer,
        entry_stack_top,
        virtual_address_bits,
        slots_ptr,
    ) = unsafe {
        (
            core::ptr::addr_of!((*state_ptr).process_id).read(),
            core::ptr::addr_of!((*state_ptr).process_table).read(),
            core::ptr::addr_of!((*state_ptr).roots)
                .read()
                .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>(),
            core::ptr::addr_of!((*state_ptr).runtime_pointer).read(),
            core::ptr::addr_of!((*state_ptr).kernel_entry_stack_top).read(),
            core::ptr::addr_of!((*state_ptr).virtual_address_bits).read(),
            core::ptr::addr_of!((*state_ptr).slots).read(),
        )
    };
    let result = loop {
        let result = match unsafe { &*process_table_ptr }.peek_wait(process_id, child_pid) {
            Ok(result) => result,
            Err(rustix_kernel::process::ProcessTableError::NoChild) => {
                return SyscallError::NoChild.return_value();
            }
            Err(_) => return SyscallError::InvalidArgument.return_value(),
        };
        let rustix_kernel::process::WaitResult::Running { pid } = result else {
            break result;
        };
        if slots_ptr.is_null() {
            return SyscallError::NotSupported.return_value();
        }
        let child_matches = (0..rustix_kernel::process::MAX_PROCESSES).any(|index| {
            let slot = unsafe { slots_ptr.add(index) };
            if !unsafe { core::ptr::addr_of!((*slot).occupied).read() } {
                return false;
            }
            let child_process = unsafe {
                core::ptr::addr_of!((*slot).context).cast::<ActiveUserProcessSyscallContext>()
            };
            unsafe { core::ptr::addr_of!((*child_process).process_id).read() == pid }
        });
        if !child_matches {
            return SyscallError::NotSupported.return_value();
        }

        // Do not retain process-root borrows while the scheduler runs another
        // task. The parent's syscall stack remains suspended on its entry stack.
        let roots = unsafe { &mut *roots_ptr };
        let state = unsafe { &*state_ptr };
        switch_process_to_kernel_root(state, roots);
        // SAFETY: The runtime belongs to this pinned scheduler task set; this
        // syscall is IF-disabled and may suspend only the current task.
        let woke = unsafe { crate::kernel_threads::wait_for_process_exit(runtime_pointer) };
        if unsafe {
            arch::x86_64::interrupts::set_kernel_entry_stack(entry_stack_top, virtual_address_bits)
        }
        .is_err()
        {
            halt_forever();
        }
        let roots = unsafe { &mut *roots_ptr };
        let state = unsafe { &*state_ptr };
        switch_kernel_to_process_root(state, roots);
        if !woke {
            return SyscallError::Io.return_value();
        }
    };

    let rustix_kernel::process::WaitResult::Exited { pid, status } = result else {
        return SyscallError::Io.return_value();
    };
    let (process, roots_ptr, user_memory_ptr, allocator_ptr) = unsafe {
        (
            core::ptr::addr_of!((*state_ptr).process).read(),
            core::ptr::addr_of!((*state_ptr).roots)
                .read()
                .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>(),
            core::ptr::addr_of!((*state_ptr).user_memory)
                .read()
                .cast::<LimineHhdmUserFrameMemory<'_>>(),
            core::ptr::addr_of!((*state_ptr).allocator)
                .read()
                .cast::<rustix_kernel::frame::FrameAllocator>(),
        )
    };
    if let Some(user_address) = status_address {
        let status_bytes = status.to_le_bytes();
        // SAFETY: Kernel-local status bytes are disjoint from allocator-owned
        // user frames; the helper validates and copies through frame tokens.
        match unsafe {
            (&*roots_ptr).copy_to_user(process, user_address, &status_bytes, &mut *user_memory_ptr)
        } {
            Ok(4) => {}
            Ok(_) => return SyscallError::Fault.return_value(),
            Err(failure) => {
                return match failure.cause {
                    rustix_kernel::paging::ProcessUserCopyError::Memory(_) => {
                        SyscallError::Io.return_value()
                    }
                    _ => SyscallError::Fault.return_value(),
                };
            }
        }
    }

    let child_slot = if slots_ptr.is_null() {
        return SyscallError::NotSupported.return_value();
    } else {
        (0..rustix_kernel::process::MAX_PROCESSES).find_map(|index| {
            let slot = unsafe { slots_ptr.add(index) };
            if !unsafe { core::ptr::addr_of!((*slot).occupied).read() } {
                return None;
            }
            let child_context = unsafe {
                core::ptr::addr_of!((*slot).context).cast::<ActiveUserProcessSyscallContext>()
            };
            (unsafe { core::ptr::addr_of!((*child_context).process_id).read() } == pid)
                .then_some(slot)
        })
    };
    let Some(child_slot) = child_slot else {
        return SyscallError::NotSupported.return_value();
    };
    // Status copyout must succeed before releasing the child's address space.
    // If teardown itself fails, the zombie and root ownership remain retryable.
    let roots = unsafe { &mut *roots_ptr };
    let allocator = unsafe { &mut *allocator_ptr };
    let child_slot = unsafe { &mut *child_slot };
    // SAFETY: An occupied slot was initialized before its task became runnable.
    let child_task_slot = unsafe { child_slot.context.assume_init_ref() }.task_slot;
    let state = unsafe { &*state_ptr };
    // Stack reclamation maps/unmaps in the active kernel root; the child root
    // is already inactive because its exit path switched away before waking us.
    switch_process_to_kernel_root(state, roots);
    let root_was_owned = child_slot.root_owned;
    if destroy_spawned_child_root(roots, allocator, child_slot).is_err() {
        switch_kernel_to_process_root(state, roots);
        return SyscallError::Io.return_value();
    }
    if root_was_owned {
        kprintln!(
            "spawned process root reclaimed after wait: pid={}",
            pid.get()
        );
    }
    let reaped = matches!(
        unsafe { &mut *process_table_ptr }.reap_exited(process_id, pid),
        Ok(rustix_kernel::process::WaitResult::Exited { pid: reaped, .. }) if reaped == pid
    );
    if !reaped {
        switch_kernel_to_process_root(state, roots);
        return SyscallError::InvalidArgument.return_value();
    }
    // The child recorded its exit before waking waiters, but its exit trampoline
    // may still be returning to its scheduler stack. Yield until the thread has
    // exited so no continuation can remain on either of its stacks, then return
    // both stacks and the scheduler slot to their pools for reuse.
    let Some(child_thread) = (unsafe {
        crate::kernel_threads::process_task_thread(state.runtime_pointer, child_task_slot)
    }) else {
        halt_forever();
    };
    if !unsafe { crate::kernel_threads::wait_for_task_exit(state.runtime_pointer, child_thread) } {
        halt_forever();
    }
    let Some(candidate) = (unsafe {
        state
            .kernel_candidate
            .cast::<rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>>()
            .as_mut()
    }) else {
        halt_forever();
    };
    // SAFETY: IF is clear, the kernel root is active, the runtime stays pinned,
    // and the child thread has exited, so both of its stacks are dead.
    if unsafe {
        crate::kernel_threads::reap_exited_process_task(
            state.runtime_pointer,
            candidate,
            allocator,
            child_thread,
        )
    }
    .is_err()
    {
        halt_forever();
    }
    child_slot.occupied = false;
    switch_kernel_to_process_root(state, roots);
    pid.get() as i64
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
extern "C" fn run_user_process_task(runtime_pointer: *mut (), context: usize) {
    let state_ptr = context as *mut ActiveUserProcessSyscallContext;
    if state_ptr.is_null() || runtime_pointer.is_null() {
        halt_forever();
    }
    // SAFETY: The process context belongs to this scheduler task and remains live
    // until all tasks have exited. Each task installs its runtime pointer once.
    unsafe { core::ptr::addr_of_mut!((*state_ptr).runtime_pointer).write(runtime_pointer) };
    let (kernel_cr3, process_cr3, entry_stack_top, user_frame, virtual_address_bits, roots_ptr) = unsafe {
        let state = &*state_ptr;
        (
            state.kernel_cr3,
            state.process_cr3,
            state.kernel_entry_stack_top,
            state.user_frame,
            state.virtual_address_bits,
            state
                .roots
                .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                    '_,
                    '_,
                    '_,
                    LimineHhdmCandidateMemory<'_>,
                >>(),
        )
    };
    if arch::x86_64::cpu::read_cr3_raw() != kernel_cr3 {
        halt_forever();
    }
    // SAFETY: Each PID has a distinct validated supervisor entry stack shared
    // by the kernel and process roots. IF remains clear throughout user mode.
    if unsafe {
        arch::x86_64::interrupts::set_kernel_entry_stack(entry_stack_top, virtual_address_bits)
    }
    .is_err()
    {
        halt_forever();
    }
    let roots = unsafe { &mut *roots_ptr };
    let state = unsafe { &*state_ptr };
    switch_kernel_to_process_root(state, roots);
    if arch::x86_64::cpu::read_cr3_raw() != process_cr3 {
        halt_forever();
    }
    let mut entry_state = arch::x86_64::interrupts::UserEntryState::new();
    // SAFETY: This task owns its unique entry state and callback context until
    // enter_user returns through the process's exit trampoline.
    if unsafe {
        arch::x86_64::interrupts::enter_user(
            user_frame,
            core::ptr::addr_of_mut!(entry_state),
            state_ptr.cast(),
        )
    }
    .is_err()
    {
        halt_forever();
    }
    if arch::x86_64::cpu::read_cr3_raw() != kernel_cr3 {
        halt_forever();
    }
    // The task is now back on its scheduler-owned kernel stack; its process entry
    // stack is no longer active. Restore the bootstrap TSS stack before exit.
    if unsafe {
        arch::x86_64::interrupts::restore_bootstrap_kernel_entry_stack(virtual_address_bits)
    }
    .is_err()
    {
        halt_forever();
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn descriptor_error_to_syscall(
    error: rustix_kernel::process::ProcessTableError,
) -> rustix_kernel::syscall::SyscallError {
    use rustix_kernel::process::ProcessTableError;
    use rustix_kernel::syscall::SyscallError;

    match error {
        ProcessTableError::BadFileDescriptor => SyscallError::BadFileDescriptor,
        ProcessTableError::DescriptorTableFull => SyscallError::TooManyOpenFiles,
        _ => SyscallError::InvalidArgument,
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn map_anonymous_user_page<M, U>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    user_memory: &mut U,
    requested_length: u64,
) -> Result<u64, rustix_kernel::syscall::SyscallError>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
{
    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    let region = regions
        .allocate_anonymous(requested_length, state.virtual_address_bits)
        .map_err(user_region_error_to_syscall)?;

    switch_process_to_kernel_root(state, roots);
    let map_result = allocate_and_map_user_page(state, roots, user_memory, region.start());
    switch_kernel_to_process_root(state, roots);

    if map_result.is_err() {
        let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
            halt_forever();
        };
        if regions
            .release_anonymous(region.start(), region.length())
            .is_err()
        {
            halt_forever();
        }
    }
    map_result.map(|()| region.start())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn map_anonymous_user_region<M, U>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    user_memory: &mut U,
    requested_length: u64,
) -> Result<u64, rustix_kernel::syscall::SyscallError>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
{
    use rustix_kernel::paging::PAGE_SIZE;

    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    let region = regions
        .allocate_anonymous(requested_length, state.virtual_address_bits)
        .map_err(user_region_error_to_syscall)?;
    switch_process_to_kernel_root(state, roots);
    let mut mapped_pages = 0u64;
    let mut result = Ok(());
    while mapped_pages < region.length() / PAGE_SIZE {
        let address = region.start() + mapped_pages * PAGE_SIZE;
        if let Err(error) = allocate_and_map_user_page(state, roots, user_memory, address) {
            result = Err(error);
            break;
        }
        mapped_pages += 1;
    }
    if result.is_err() {
        let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
            halt_forever();
        };
        for page in (0..mapped_pages).rev() {
            let address = region.start() + page * PAGE_SIZE;
            let frame = roots
                .unmap_user_page(state.process, address)
                .unwrap_or_else(|_| halt_forever());
            if allocator.deallocate(frame).is_err() {
                halt_forever();
            }
        }
    }
    switch_kernel_to_process_root(state, roots);
    if result.is_err() {
        let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
            halt_forever();
        };
        if regions
            .release_anonymous(region.start(), region.length())
            .is_err()
        {
            halt_forever();
        }
    }
    result.map(|()| region.start())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn unmap_anonymous_user_region<M, U>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    user_memory: &mut U,
    virtual_address: u64,
    length: u64,
) -> Result<(), rustix_kernel::syscall::SyscallError>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
{
    use rustix_kernel::paging::PAGE_SIZE;
    use rustix_kernel::process::UserRegionKind;
    use rustix_kernel::syscall::SyscallError;

    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    let exact_region = regions.regions().any(|region| {
        region.start() == virtual_address
            && region.length() == length
            && region.kind() == UserRegionKind::Anonymous
    });
    if !exact_region {
        return Err(SyscallError::InvalidArgument);
    }

    let mut probe = [0u8; 1];
    for offset in (0..length).step_by(PAGE_SIZE as usize) {
        // SAFETY: The local byte is kernel stack storage; the helper accesses
        // user frames only through allocator-issued frame tokens.
        if let Err(failure) = unsafe {
            roots.copy_from_user(
                state.process,
                virtual_address + offset,
                &mut probe,
                user_memory,
            )
        } {
            return Err(match failure.cause {
                rustix_kernel::paging::ProcessUserCopyError::Memory(_) => SyscallError::Io,
                _ => SyscallError::Fault,
            });
        }
    }

    switch_process_to_kernel_root(state, roots);
    let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
        halt_forever();
    };
    for page_index in (0..length / PAGE_SIZE).rev() {
        let offset = page_index * PAGE_SIZE;
        let frame = roots
            .unmap_user_page(state.process, virtual_address + offset)
            .unwrap_or_else(|_| halt_forever());
        if allocator.deallocate(frame).is_err() {
            halt_forever();
        }
    }
    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    if regions.release_anonymous(virtual_address, length).is_err() {
        halt_forever();
    }
    switch_kernel_to_process_root(state, roots);
    Ok(())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn allocate_and_map_user_page<M, U>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    user_memory: &mut U,
    virtual_address: u64,
) -> Result<(), rustix_kernel::syscall::SyscallError>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
{
    use rustix_kernel::paging::zero_user_frame;
    use rustix_kernel::syscall::SyscallError;

    let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
        halt_forever();
    };
    let frame = allocator.allocate().ok_or(SyscallError::OutOfMemory)?;
    if zero_user_frame(&frame, user_memory).is_err() {
        if allocator.deallocate(frame).is_err() {
            halt_forever();
        }
        return Err(SyscallError::Io);
    }
    let (mapping, cache_attributes) = match user_mapping_attributes(state, virtual_address, &frame)
    {
        Ok(attributes) => attributes,
        Err(error) => {
            if allocator.deallocate(frame).is_err() {
                halt_forever();
            }
            return Err(error);
        }
    };
    match roots.map_user_page(allocator, state.process, frame, mapping, cache_attributes) {
        Ok(()) => Ok(()),
        Err(failure) => {
            let error = page_map_error_to_syscall(failure.cause);
            if allocator.deallocate(failure.frame).is_err() {
                halt_forever();
            }
            Err(error)
        }
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn unmap_anonymous_user_page<M, U>(
    state: &mut ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    user_memory: &mut U,
    virtual_address: u64,
) -> Result<(), rustix_kernel::syscall::SyscallError>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
{
    use rustix_kernel::paging::PAGE_SIZE;
    use rustix_kernel::process::UserRegionKind;
    use rustix_kernel::syscall::SyscallError;

    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    let is_anonymous = regions.regions().any(|region| {
        region.start() == virtual_address
            && region.length() == PAGE_SIZE
            && region.kind() == UserRegionKind::Anonymous
    });
    if !is_anonymous {
        return Err(SyscallError::InvalidArgument);
    }

    let mut probe = [0u8; 1];
    // SAFETY: This kernel-stack byte is disjoint from all allocator-owned user
    // frames; copy_from_user validates and accesses the user frame by token.
    if let Err(failure) =
        unsafe { roots.copy_from_user(state.process, virtual_address, &mut probe, user_memory) }
    {
        return Err(match failure.cause {
            rustix_kernel::paging::ProcessUserCopyError::Memory(_) => SyscallError::Io,
            _ => SyscallError::Fault,
        });
    }

    switch_process_to_kernel_root(state, roots);
    let Some(allocator) = (unsafe { state.allocator.as_mut() }) else {
        halt_forever();
    };
    let frame = match roots.unmap_user_page(state.process, virtual_address) {
        Ok(frame) => frame,
        Err(_) => {
            switch_kernel_to_process_root(state, roots);
            return Err(SyscallError::Io);
        }
    };
    if let Err(failure) = allocator.deallocate(frame) {
        let frame = failure.frame;
        let (mapping, cache_attributes) =
            match user_mapping_attributes(state, virtual_address, &frame) {
                Ok(attributes) => attributes,
                Err(_) => halt_forever(),
            };
        if let Err(failure) =
            roots.map_user_page(allocator, state.process, frame, mapping, cache_attributes)
        {
            let _owned_frame = failure.frame;
            halt_forever();
        }
        switch_kernel_to_process_root(state, roots);
        return Err(SyscallError::Io);
    }
    let Some(regions) = (unsafe { state.user_regions.as_mut() }) else {
        halt_forever();
    };
    if regions
        .release_anonymous(virtual_address, PAGE_SIZE)
        .is_err()
    {
        halt_forever();
    }
    switch_kernel_to_process_root(state, roots);
    Ok(())
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn user_mapping_attributes(
    state: &ActiveUserProcessSyscallContext,
    virtual_address: u64,
    frame: &rustix_kernel::frame::Frame,
) -> Result<
    (
        rustix_kernel::paging::ValidatedMappingRange,
        rustix_kernel::paging::SelectedCacheAttributes,
    ),
    rustix_kernel::syscall::SyscallError,
> {
    use rustix_kernel::paging::{CachePolicy, PagePermissions, PAGE_SIZE};
    use rustix_kernel::syscall::SyscallError;

    let mapping = rustix_kernel::paging::validate_mapping_range(
        virtual_address,
        frame.address(),
        PAGE_SIZE,
        PagePermissions {
            writable: true,
            executable: false,
            user_accessible: true,
        },
        Some(state.physical_address_bits),
        state.virtual_address_bits,
    )
    .map_err(|_| SyscallError::InvalidArgument)?;
    // SAFETY: The validated register snapshot lives in the synchronous process
    // probe stack until the callback is cleared and the process returns.
    let Some(mtrr_layout) = (unsafe { state.mtrr_layout.as_ref() }) else {
        halt_forever();
    };
    let cache_attributes = mapping
        .select_cache_attributes(
            CachePolicy::WriteBack,
            state.pat,
            mtrr_layout,
            state.normal_caching,
        )
        .map_err(|_| SyscallError::Io)?;
    Ok((mapping, cache_attributes))
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn switch_process_to_kernel_root<M: rustix_kernel::paging::CandidatePageTableMemory>(
    state: &ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
) {
    // SAFETY: Syscall entry has IF clear and runs on a stack mapped in both roots.
    unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(state.kernel_cr3) };
    if arch::x86_64::cpu::read_cr3_raw() != state.kernel_cr3 {
        halt_forever();
    }
    // SAFETY: The kernel root is active and no other CPU can use this process root.
    if unsafe { roots.mark_inactive(state.process) }.is_err() {
        halt_forever();
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn switch_kernel_to_process_root<M: rustix_kernel::paging::CandidatePageTableMemory>(
    state: &ActiveUserProcessSyscallContext,
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
) {
    // SAFETY: The process root is owned and mapped for this synchronous run;
    // the kernel/TSS stacks are shared and IF remains clear across the switch.
    unsafe { arch::x86_64::cpu::write_cr3_with_global_flush(state.process_cr3) };
    if arch::x86_64::cpu::read_cr3_raw() != state.process_cr3 {
        halt_forever();
    }
    // SAFETY: CR3 now names this process root, and the shared kernel owner and
    // root set remain live until this synchronous process exits.
    if unsafe { roots.mark_active(state.process) }.is_err() {
        halt_forever();
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn user_region_error_to_syscall(
    error: rustix_kernel::process::UserRegionError,
) -> rustix_kernel::syscall::SyscallError {
    use rustix_kernel::process::UserRegionError;
    use rustix_kernel::syscall::SyscallError;

    match error {
        UserRegionError::Capacity | UserRegionError::AnonymousAddressSpaceExhausted => {
            SyscallError::OutOfMemory
        }
        UserRegionError::AddressOverflow => SyscallError::Overflow,
        _ => SyscallError::InvalidArgument,
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn page_map_error_to_syscall<E>(
    error: rustix_kernel::paging::ProcessPageMapError<E>,
) -> rustix_kernel::syscall::SyscallError {
    use rustix_kernel::paging::{CandidateMapErrorKind, ProcessPageMapError};
    use rustix_kernel::syscall::SyscallError;

    match error {
        ProcessPageMapError::Candidate(
            CandidateMapErrorKind::OutOfFrames
            | CandidateMapErrorKind::MappingCapacity
            | CandidateMapErrorKind::TableCapacity,
        ) => SyscallError::OutOfMemory,
        ProcessPageMapError::Candidate(CandidateMapErrorKind::TableMemory(_)) => SyscallError::Io,
        ProcessPageMapError::Candidate(CandidateMapErrorKind::Mapping(_)) => {
            SyscallError::InvalidArgument
        }
        _ => SyscallError::InvalidArgument,
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
extern "C" fn dispatch_active_user_process_exception(vector: u64, opaque: *mut ()) -> bool {
    if vector >= 128 {
        return false;
    }
    // SAFETY: `opaque` points to the same live, stack-owned process runtime used
    // by syscall dispatch and remains valid until the exception exit trampoline.
    let state = unsafe { &mut *opaque.cast::<ActiveUserProcessSyscallContext>() };
    // SAFETY: The root manager is retained by the runtime for the synchronous
    // user entry; this exception arrived on its mapped supervisor entry stack.
    let roots = unsafe {
        &mut *state
            .roots
            .cast::<rustix_kernel::paging::ProcessAddressSpaceRoots<
                '_,
                '_,
                '_,
                LimineHhdmCandidateMemory<'_>,
            >>()
    };
    finish_active_user_process(state, roots, 128 + vector as i32) == 0
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
type PreparedUserProgram = rustix_kernel::process::PreparedUserProgram;

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn prepare_user_program<M, U, F>(
    roots: &mut rustix_kernel::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    user_memory: &mut U,
    image_bytes: &[u8],
    stack_base: u64,
    physical_address_bits: u8,
    virtual_address_bits: u8,
    select_cache: &mut F,
) -> Result<PreparedUserProgram, &'static str>
where
    M: rustix_kernel::paging::CandidatePageTableMemory,
    U: rustix_kernel::paging::UserFrameMemory,
    F: FnMut(
        rustix_kernel::paging::ValidatedMappingRange,
    ) -> Result<rustix_kernel::paging::SelectedCacheAttributes, &'static str>,
{
    match rustix_kernel::process::prepare_user_program(
        roots,
        allocator,
        user_memory,
        image_bytes,
        stack_base,
        1,
        1,
        physical_address_bits,
        virtual_address_bits,
        arch::x86_64::interrupts::USER_CODE_SELECTOR,
        arch::x86_64::interrupts::USER_DATA_SELECTOR,
        select_cache,
    ) {
        Ok(program) => Ok(program),
        Err(failure) => {
            let message = failure.kind.message();
            if let Err(_retained_resources) = failure.cleanup(roots, allocator) {
                halt_forever();
            }
            Err(message)
        }
    }
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
fn probe_user_process_root<M: rustix_kernel::paging::CandidatePageTableMemory>(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<'_, M>,
    memory_map: &rustix_kernel::memory::MemoryMap,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    cpu_info: &arch::x86_64::cpu::CpuInfo,
    hhdm_offset: u64,
    config: rustix_kernel::paging::PageWalkConfig,
) -> Result<(), &'static str> {
    let mut process_tasks = core::pin::pin!(crate::kernel_threads::new_process_tasks(
        &BOOTSTRAP_TIMER_TICKS
    )?);
    // Pre-create every stack-slot table path before any process root snapshots
    // the kernel half; later spawn/reap cycles only touch leaves inside them.
    crate::kernel_threads::prepare_process_stack_tables(candidate, allocator, cpu_info)?;
    // Table paths created above are retained by the candidate; the baseline
    // excludes them. Init's task stacks are created inside the probe and are
    // reclaimed below, so full frame restoration is checked after that.
    let process_setup_free_frames = allocator.free_frames();
    let result = probe_user_process_root_with_tasks(
        candidate,
        memory_map,
        allocator,
        cpu_info,
        hhdm_offset,
        config,
        process_tasks.as_mut(),
    );
    crate::kernel_threads::reclaim_process_task_stacks(
        process_tasks.as_mut(),
        candidate,
        allocator,
    )?;
    if allocator.free_frames() != process_setup_free_frames {
        return Err("process-root teardown did not restore its frame count");
    }
    result
}

#[cfg(all(target_os = "none", feature = "boot-userspace"))]
#[cfg_attr(
    feature = "probe-userspace-launch-failure",
    allow(unused_variables, unused_imports, unused_mut, unreachable_code)
)]
fn probe_user_process_root_with_tasks<M: rustix_kernel::paging::CandidatePageTableMemory>(
    candidate: &mut rustix_kernel::paging::CandidatePageTables<'_, M>,
    memory_map: &rustix_kernel::memory::MemoryMap,
    allocator: &mut rustix_kernel::frame::FrameAllocator,
    cpu_info: &arch::x86_64::cpu::CpuInfo,
    hhdm_offset: u64,
    config: rustix_kernel::paging::PageWalkConfig,
    mut process_tasks: core::pin::Pin<&mut crate::kernel_threads::PreparedProcessTasks>,
) -> Result<(), &'static str> {
    use rustix_kernel::paging::{CachePolicy, MtrrState, PatLayout, ProcessAddressSpaceRoots};

    // Capture the candidate's raw address before the kernel-half snapshot borrows
    // it; task creation later re-derives a temporary mutable reference from this
    // pointer while no live reference to the candidate exists (single vCPU, IF=0).
    let kernel_candidate_pointer = core::ptr::addr_of_mut!(*candidate).cast::<()>();
    let kernel_half = candidate
        .share_supervisor_kernel_half()
        .map_err(|_| "active kernel half could not be shared safely")?;
    let physical_address_bits = cpu_info
        .physical_address_bits
        .ok_or("physical address width unavailable")?;
    let pat = match cpu_info.pat_msr_value {
        Some(value) => PatLayout::from_msr_value(value)
            .map_err(|_| "PAT state is invalid for process mappings")?,
        None => return Err("PAT state unavailable for process mappings"),
    };
    let mtrr_layout = match &cpu_info.mtrr {
        MtrrState::Captured(registers) => registers
            .validated_layout(physical_address_bits)
            .map_err(|_| "MTRR state is invalid for process mappings")?,
        _ => return Err("MTRR state unavailable for process mappings"),
    };
    let mut select_cache = |mapping: rustix_kernel::paging::ValidatedMappingRange| {
        mapping
            .select_cache_attributes(
                CachePolicy::WriteBack,
                pat,
                &mtrr_layout,
                cpu_info.normal_caching,
            )
            .map_err(|_| "no uniform write-back cache policy for process page")
    };
    let mut process_memory = LimineHhdmCandidateMemory {
        memory_map,
        hhdm_offset,
        physical_address_bits,
        virtual_address_bits: cpu_info.active_linear_address_bits,
    };
    let mut roots = match ProcessAddressSpaceRoots::new(&kernel_half, &mut process_memory, config) {
        Ok(roots) => roots,
        Err(failure) => {
            if let Some(frame) = failure.frame {
                allocator
                    .deallocate(frame)
                    .map_err(|_| "process-root manager frame could not be reclaimed")?;
            }
            return Err("process-root manager creation failed");
        }
    };

    let mut user_memory = LimineHhdmUserFrameMemory {
        memory_map,
        hhdm_offset,
        physical_address_bits: Some(physical_address_bits),
        virtual_address_bits: cpu_info.active_linear_address_bits,
    };
    const USER_STACK_BASE: u64 = 0x0000_7fff_ffff_f000;
    let init_program = match prepare_user_program(
        &mut roots,
        allocator,
        &mut user_memory,
        INIT_ELF_IMAGE,
        USER_STACK_BASE,
        physical_address_bits,
        cpu_info.active_linear_address_bits,
        &mut select_cache,
    ) {
        Ok(program) => program,
        Err(error) => return Err(error),
    };
    let process = init_program.process;
    let user_frame = init_program.user_frame;

    // Opt-in normal-boot failure injection: fail after the init root exists so
    // the error path must reclaim it, restore the frame count, and let the boot
    // path report the failure and fall back to the shell.
    #[cfg(feature = "probe-userspace-launch-failure")]
    {
        roots
            .destroy(allocator, process)
            .map_err(|_| "injected launch failure could not reclaim the init root")?;
        return Err("injected userspace launch failure after root creation");
    }

    let mut process_table = rustix_kernel::process::ProcessTable::new();
    let process_id = process_table
        .create_initial()
        .map_err(|_| "initial process record could not be created")?;

    let root_address = match roots.root_physical_address(process) {
        Ok(address) => address,
        Err(_) => {
            roots
                .destroy(allocator, process)
                .map_err(|_| "process root could not be destroyed after root lookup failed")?;
            return Err("process root address is unavailable");
        }
    };
    let kernel_cr3 = arch::x86_64::cpu::read_cr3_raw();
    let kernel_cr3_root = match rustix_kernel::paging::parse_cr3_root(
        kernel_cr3,
        Some(physical_address_bits),
        cpu_info.pcid_enabled,
    ) {
        Ok(root) => root,
        Err(_) => {
            roots.destroy(allocator, process).map_err(|_| {
                "process root could not be destroyed after kernel CR3 validation failed"
            })?;
            return Err("active kernel CR3 could not be validated");
        }
    };
    let process_cr3 = match rustix_kernel::paging::encode_cr3_value(
        root_address,
        kernel_cr3_root.low_bits(),
        physical_address_bits,
    ) {
        Ok(value) => value,
        Err(_) => {
            roots
                .destroy(allocator, process)
                .map_err(|_| "process root could not be destroyed after CR3 encoding failed")?;
            return Err("process CR3 encoding failed");
        }
    };

    let mut process_slots: [ProcessTaskSlot; rustix_kernel::process::MAX_PROCESSES] =
        core::array::from_fn(|_| ProcessTaskSlot::EMPTY);
    // SAFETY: IF was disabled by the caller; all pointer targets remain live
    // until the synchronous user entry returns through its exit syscall.
    if unsafe {
        arch::x86_64::interrupts::install_user_syscall_handler(
            dispatch_active_user_process_syscall,
            dispatch_active_user_process_exception,
        )
    }
    .is_err()
    {
        roots.destroy(allocator, process).map_err(|_| {
            "process root could not be destroyed after syscall handler setup failed"
        })?;
        return Err("user syscall handler setup failed");
    }

    // Publish the init context, then create its task. The entry-stack top is
    // patched after stack mapping and before any dispatch can occur.
    let slots_pointer = process_slots.as_mut_ptr();
    // SAFETY: Slot zero is inside the live slot array and is unoccupied.
    let init_slot = unsafe { &mut *slots_pointer };
    // SAFETY: The slot array lives on this stack until every task exits; slot
    // zero is unoccupied and unpublished.
    unsafe {
        core::ptr::addr_of_mut!(init_slot.regions)
            .write(core::mem::MaybeUninit::new(init_program.regions));
        core::ptr::addr_of_mut!(init_slot.context).write(core::mem::MaybeUninit::new(
            ActiveUserProcessSyscallContext {
                roots: core::ptr::addr_of_mut!(roots).cast(),
                kernel_candidate: kernel_candidate_pointer,
                cpu_info: core::ptr::from_ref(cpu_info),
                cr3_low_bits: kernel_cr3_root.low_bits(),
                user_memory: core::ptr::addr_of_mut!(user_memory).cast(),
                allocator: core::ptr::addr_of_mut!(*allocator),
                user_regions: core::ptr::addr_of_mut!(init_slot.regions)
                    .cast::<rustix_kernel::process::UserRegionTable>(),
                process_table: core::ptr::addr_of_mut!(process_table),
                mtrr_layout: core::ptr::addr_of!(mtrr_layout),
                process,
                process_id,
                kernel_cr3,
                process_cr3,
                kernel_entry_stack_top: 0,
                runtime_pointer: core::ptr::null_mut(),
                user_frame,
                slots: slots_pointer,
                task_slot: 0,
                pat,
                normal_caching: cpu_info.normal_caching,
                physical_address_bits,
                virtual_address_bits: cpu_info.active_linear_address_bits,
            },
        ));
        core::ptr::addr_of_mut!(init_slot.root_owned).write(true);
        core::ptr::addr_of_mut!(init_slot.occupied).write(true);
    }
    // SAFETY: Slot zero is inside the live, exclusively owned slot array.
    let init_context_pointer = unsafe {
        core::ptr::addr_of_mut!((*slots_pointer).context).cast::<ActiveUserProcessSyscallContext>()
    };
    // SAFETY: The pinned runtime stays at a stable address until all tasks exit.
    let runtime_pointer =
        unsafe { crate::kernel_threads::process_runtime_pointer(process_tasks.as_mut()) };
    // SAFETY: IF is clear, the runtime is pinned, and the init context is
    // published before the task can dispatch. The candidate reference is
    // re-derived from its raw address; no live reference aliases it here.
    let (init_thread, init_entry_stack_top) = match unsafe {
        crate::kernel_threads::spawn_process_task(
            runtime_pointer,
            &mut *kernel_candidate_pointer
                .cast::<rustix_kernel::paging::CandidatePageTables<'_, LimineHhdmCandidateMemory<'_>>>(),
            allocator,
            cpu_info,
            run_user_process_task,
            init_context_pointer as usize,
        )
    } {
        Ok(spawned) => spawned,
        Err(error) => {
            unsafe { arch::x86_64::interrupts::clear_user_syscall_handler() };
            destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
            return Err(error);
        }
    };
    // SAFETY: The init task has not dispatched; IF remains clear on this CPU.
    unsafe {
        core::ptr::addr_of_mut!((*init_context_pointer).kernel_entry_stack_top)
            .write(init_entry_stack_top);
        core::ptr::addr_of_mut!((*init_context_pointer).task_slot).write(init_thread.slot_index());
    }
    kprintln!(
        "Ring 3 entry stack validated: pid={}, entry={:#x}",
        process_id.get(),
        init_entry_stack_top
    );

    if let Err(error) = crate::kernel_threads::run_process_runtime(process_tasks.as_mut()) {
        // No process entry began if task preparation failed; the process roots
        // remain inactive and can be reclaimed before returning the setup error.
        unsafe { arch::x86_64::interrupts::clear_user_syscall_handler() };
        destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
        return Err(error);
    }
    if arch::x86_64::cpu::read_cr3_raw() != kernel_cr3 {
        halt_forever();
    }
    // All process tasks returned through their user-exit trampolines, and the
    // scheduler has reclaimed its own guarded stacks before the callback clears.
    unsafe { arch::x86_64::interrupts::clear_user_syscall_handler() };
    let exit_status = match process_table.state(process_id) {
        Some(rustix_kernel::process::ProcessState::Exited(status)) => status,
        _ => {
            destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
            return Err("init process task returned without recording its exit");
        }
    };
    let wait_result =
        match process_table.try_wait(rustix_kernel::process::KERNEL_PROCESS_ID, process_id.get()) {
            Ok(result) => result,
            Err(_) => {
                destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
                return Err("kernel wait could not inspect the init process");
            }
        };
    #[cfg(any(
        feature = "probe-user-fault",
        feature = "probe-user-page-fault",
        feature = "probe-user-general-protection",
        feature = "probe-user-divide-error",
        feature = "probe-user-invalid-syscall-return"
    ))]
    let expected_status = 128 + PROBE_USER_FAULT_VECTOR as i32;
    #[cfg(not(any(
        feature = "probe-user-fault",
        feature = "probe-user-page-fault",
        feature = "probe-user-general-protection",
        feature = "probe-user-divide-error",
        feature = "probe-user-invalid-syscall-return"
    )))]
    let expected_status = 42;
    if !matches!(
        wait_result,
        rustix_kernel::process::WaitResult::Exited { pid, status }
            if pid == process_id && status == exit_status && status == expected_status
    ) {
        kprintln!(
            "process wait validation mismatch: result={:?}, init pid={}, trampoline status={}, expected status={}",
            wait_result,
            process_id.get(),
            exit_status,
            expected_status
        );
        destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
        return Err("init exit status was not retained and reaped as expected");
    }
    for slot in &mut process_slots {
        if !slot.occupied {
            continue;
        }
        // SAFETY: The scheduler has returned, and this slot was initialized
        // before its task became runnable. Its process root is now inactive.
        let child_id = unsafe { slot.context.assume_init_ref() }.process_id;
        if matches!(
            process_table.state(child_id),
            Some(rustix_kernel::process::ProcessState::Running)
        ) && process_table.exit(child_id, 127).is_err()
        {
            destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
            return Err("unstarted child process could not be exited during cleanup");
        }
        if process_table.state(child_id).is_some()
            && !matches!(
                process_table.try_wait(
                    rustix_kernel::process::KERNEL_PROCESS_ID,
                    child_id.get()
                ),
                Ok(rustix_kernel::process::WaitResult::Exited { pid, .. })
                    if pid == child_id
            )
        {
            destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
            return Err("remaining child process record could not be reaped");
        }
        if process_table.state(child_id).is_none() && child_id != process_id {
            kprintln!(
                "orphaned process reaped by kernel supervisor: pid={}",
                child_id.get()
            );
        }
    }
    // Destroys every still-owned root, including init's, after its record was
    // reaped above; mid-run waits already reclaimed the children they consumed.
    destroy_spawned_child_roots(&mut roots, allocator, &mut process_slots)?;
    if process_table.live_records() != 0 {
        return Err("process records remained after process teardown");
    }

    #[cfg(not(any(
        feature = "probe-user-fault",
        feature = "probe-user-page-fault",
        feature = "probe-user-general-protection",
        feature = "probe-user-divide-error",
        feature = "probe-user-invalid-syscall-return"
    )))]
    kprintln!(
        "init process exited with status {} and was reaped by kernel wait",
        exit_status
    );
    #[cfg(any(
        feature = "probe-user-fault",
        feature = "probe-user-page-fault",
        feature = "probe-user-general-protection",
        feature = "probe-user-divide-error",
        feature = "probe-user-invalid-syscall-return"
    ))]
    kprintln!(
        "user fault vector {} exited with status {} and was reaped by kernel wait",
        PROBE_USER_FAULT_VECTOR,
        exit_status
    );
    Ok(())
}

#[cfg(feature = "probe-hhdm-frame")]
fn probe_hhdm_frame(boot_info: &mut boot::BootInfo) {
    use rustix_kernel::frame::FRAME_SIZE;
    use rustix_kernel::paging::UserFrameMemory;

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

    let mut user_memory = LimineHhdmUserFrameMemory {
        memory_map: &boot_info.memory_map,
        hhdm_offset: boot_info.hhdm_offset,
        physical_address_bits: boot_info.cpu_info.physical_address_bits,
        virtual_address_bits: boot_info.cpu_info.active_linear_address_bits,
    };
    let mut expected = [0; 64];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = index as u8 ^ 0x5a;
    }
    let mut observed = [0; 64];
    let copy_round_trip = user_memory
        .copy_to_frame(&frame, 128, &expected)
        .and_then(|()| user_memory.copy_from_frame(&frame, 128, &mut observed));
    let mut out_of_bounds = [0; 2];
    let bounds_rejected = user_memory
        .copy_from_frame(&frame, FRAME_SIZE as usize - 1, &mut out_of_bounds)
        .is_err();
    let empty_copy = user_memory
        .copy_to_frame(&frame, FRAME_SIZE as usize, &[])
        .is_ok();
    let mut verified =
        copy_round_trip.is_ok() && observed == expected && bounds_rejected && empty_copy;
    let words = (FRAME_SIZE / core::mem::size_of::<u64>() as u64) as usize;
    let page = hhdm_address as *mut u64;
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

#[cfg(feature = "inject-general-protection")]
fn run_fault_injection() {
    kprintln!("fault injection: triggering general protection with invalid DS selector");
    // SAFETY: The selector index is outside the installed GDT limit, so loading
    // it into DS deliberately raises a kernel-origin #GP in QEMU.
    unsafe {
        core::arch::asm!(
            "mov ax, 0xffff",
            "mov ds, ax",
            out("ax") _,
            options(nostack)
        )
    };
    kprintln!("fault injection unexpectedly returned");
    halt_forever();
}

#[cfg(feature = "inject-divide-error")]
fn run_fault_injection() {
    kprintln!("fault injection: triggering divide error with a zero divisor");
    // SAFETY: Integer division by zero deliberately raises kernel-origin #DE.
    unsafe {
        core::arch::asm!(
            "xor edx, edx",
            "xor eax, eax",
            "xor ecx, ecx",
            "div ecx",
            out("eax") _,
            out("edx") _,
            out("ecx") _,
            options(nostack)
        )
    };
    kprintln!("fault injection unexpectedly returned");
    halt_forever();
}

/// Set once the fatal panic path has started. A panic from inside the fatal
/// path stops silently instead of recursively printing or looping diagnostics.
static FATAL_PANIC_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Mask maskable interrupts before any diagnostics run: another kernel
    // thread must not resume after a panic is declared, and the fatal report
    // must not be preempted mid-print.
    //
    // SAFETY: Kernel panic path runs at CPL 0; masking IF is always sound.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    if FATAL_PANIC_ACTIVE.swap(true, core::sync::atomic::Ordering::Acquire) {
        loop {
            // SAFETY: Re-entrant panics are deliberately silent.
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }
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
