#![no_std]
#![no_main]

#[cfg(any(
    all(feature = "inject-page-fault", feature = "inject-invalid-opcode"),
    all(feature = "inject-page-fault", feature = "probe-hhdm-frame"),
    all(feature = "inject-invalid-opcode", feature = "probe-hhdm-frame")
))]
compile_error!("opt-in QEMU diagnostic features are mutually exclusive");

mod arch;
mod boot;
mod shell;

use core::panic::PanicInfo;
use rustix_kernel::vfs::RamFs;

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
        encode_cr3_value, CandidatePageTables, PageWalkConfig, PageWalkOutcome,
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
    // SAFETY: The candidate is a complete clone of every present inherited
    // hierarchy entry, with all referenced intermediate tables owned and the
    // critical code/data/stack paths compared before this point. The inherited
    // root's paging mode, address widths, PAT/MTRR state, and low CR3 mode are
    // preserved; interrupts are disabled from bootstrap initialization onward.
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
    probe_kernel_heap();

    // Keep the candidate and its frame tokens alive for as long as this root is
    // active. The shell runs forever and does not return to this stack frame.
    // SAFETY: The bootstrap is single-core, interrupts remain disabled, and the
    // shell is the only filesystem owner.
    let filesystem = unsafe { &mut *core::ptr::addr_of_mut!(RAM_FILESYSTEM) };
    match filesystem.seed_defaults() {
        Ok(home) => shell::run(filesystem, home, boot_info),
        Err(error) => {
            kprintln!("RAM filesystem initialization failed: {:?}", error);
            halt_forever()
        }
    }
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
    let small_layout = Layout::new::<u8>();
    // SAFETY: The heap lock serializes this valid nonzero allocation request.
    let exhausted = unsafe { KERNEL_HEAP.alloc(small_layout) };
    if !exhausted.is_null() {
        // SAFETY: Both pointers are live allocations with their original layouts.
        unsafe {
            KERNEL_HEAP.dealloc(exhausted, small_layout);
            KERNEL_HEAP.dealloc(full_arena, full_layout);
        }
        kprintln!("kernel heap probe failed: exhaustion was not deterministic");
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
    kprintln!("kernel heap probe passed: alignment, reuse, deterministic exhaustion");
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
        // The CPU may update Accessed/Dirty in the active hierarchy after the
        // clone; they are hardware tracking state, not translation policy.
        let hardware_tracking_bits = (1 << 5) | (1 << 6);
        if source_translation.physical_address != candidate_translation.physical_address
            || source_translation.leaf_physical_base != candidate_translation.leaf_physical_base
            || source_translation.page_size != candidate_translation.page_size
            || source_translation.permissions != candidate_translation.permissions
            || source_translation.pat_index != candidate_translation.pat_index
            || source_translation.raw_leaf_entry & !hardware_tracking_bits
                != candidate_translation.raw_leaf_entry & !hardware_tracking_bits
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
