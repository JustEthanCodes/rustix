//! Limine boot-protocol requests and validated, copied boot information.

use core::mem::{align_of, size_of};
use rustix_kernel::frame::{FrameAllocator, FrameError};
use rustix_kernel::memory::{
    is_canonical_virtual_address, kernel_image_physical_end, kernel_image_segments,
    limine_v3_hhdm_range_is_valid, limine_x86_64_stack_bounds, physical_range_fits_address_width,
    KernelImageSegments, KernelImageVirtualSegments, MemoryMap, MemoryMapBuilder, MemoryMapError,
    RegionKind, MAX_MEMORY_REGIONS,
};
use rustix_kernel::paging::{
    parse_cr3_root, CachePolicy, Cr3Error, Cr3Root, MtrrState, PatLayout,
    MAX_CAPTURED_VARIABLE_MTRRS,
};

const REQUESTS_START: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];
const REQUESTS_END: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];
const BASE_REVISION: [u64; 3] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc, 3];
const REQUESTED_BOOT_STACK_SIZE: u64 = 256 * 1024;

#[used]
#[link_section = ".limine_requests_start"]
static REQUESTS_START_MARKER: [u64; 4] = REQUESTS_START;

#[used]
#[link_section = ".limine_requests"]
static BASE_REVISION_REQUEST: [u64; 3] = BASE_REVISION;

#[used]
#[link_section = ".limine_requests_end"]
static REQUESTS_END_MARKER: [u64; 2] = REQUESTS_END;

#[repr(C)]
struct Request<T> {
    id: [u64; 4],
    revision: u64,
    response: *mut T,
}

// Limine writes each mutable response pointer before transferring control to Rustix.
#[repr(C)]
#[derive(Clone, Copy)]
struct HhdmResponse {
    revision: u64,
    offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StackSizeResponse {
    revision: u64,
}

#[repr(C)]
struct StackSizeRequest {
    id: [u64; 4],
    revision: u64,
    response: *mut StackSizeResponse,
    stack_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecutableAddressResponse {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemoryMapResponse {
    revision: u64,
    entry_count: u64,
    entries: *const *const MemoryMapEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemoryMapEntry {
    base: u64,
    length: u64,
    kind: u64,
}

#[used]
#[link_section = ".limine_requests"]
static mut STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest {
    id: [
        0xc7b1_dd30_df4c_8b88,
        0x0a82_e883_a194_f07b,
        0x224e_f046_0a8e_8926,
        0xe1cb_0fc2_5f46_ea3d,
    ],
    revision: 0,
    response: core::ptr::null_mut(),
    stack_size: REQUESTED_BOOT_STACK_SIZE,
};

#[used]
#[link_section = ".limine_requests"]
static mut HHDM_REQUEST: Request<HhdmResponse> = Request {
    id: [
        0xc7b1_dd30_df4c_8b88,
        0x0a82_e883_a194_f07b,
        0x48dc_f1cb_8ad2_b852,
        0x6398_4e95_9a98_244b,
    ],
    revision: 0,
    response: core::ptr::null_mut(),
};

#[used]
#[link_section = ".limine_requests"]
static mut EXECUTABLE_ADDRESS_REQUEST: Request<ExecutableAddressResponse> = Request {
    id: [
        0xc7b1_dd30_df4c_8b88,
        0x0a82_e883_a194_f07b,
        0x71ba_7686_3cc5_5f63,
        0xb264_4a48_c516_a487,
    ],
    revision: 0,
    response: core::ptr::null_mut(),
};

#[used]
#[link_section = ".limine_requests"]
static mut MEMORY_MAP_REQUEST: Request<MemoryMapResponse> = Request {
    id: [
        0xc7b1_dd30_df4c_8b88,
        0x0a82_e883_a194_f07b,
        0x67cf_3d9d_378a_806f,
        0xe304_acdf_c50c_3c62,
    ],
    revision: 0,
    response: core::ptr::null_mut(),
};

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
    static __kernel_text_mapping_start: u8;
    static __kernel_text_mapping_end: u8;
    static __kernel_rodata_mapping_start: u8;
    static __kernel_rodata_mapping_end: u8;
    static __kernel_data_mapping_start: u8;
    static __kernel_data_mapping_end: u8;
}

/// Owned snapshot of bootloader data and CPU state consumed by the kernel.
pub struct BootInfo {
    pub hhdm_revision: u64,
    pub hhdm_offset: u64,
    pub inherited_cr3_raw: u64,
    pub inherited_cr3_root: Result<Cr3Root, Cr3Error>,
    pub executable_address_revision: u64,
    pub kernel_physical_base: u64,
    pub kernel_physical_end: u64,
    pub kernel_virtual_base: u64,
    pub kernel_virtual_end: u64,
    pub kernel_image_segments: KernelImageSegments,
    pub boot_stack_physical_start: u64,
    pub boot_stack_physical_end: u64,
    pub boot_stack_virtual_start: u64,
    pub boot_stack_virtual_end: u64,
    pub memory_map_revision: u64,
    pub memory_map: MemoryMap,
    pub frame_allocator: FrameAllocator,
    pub cpu_info: crate::arch::x86_64::cpu::CpuInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoError {
    MissingHhdmResponse,
    InvalidHhdmResponsePointer,
    InvalidHhdmOffset,
    MissingExecutableAddressResponse,
    InvalidExecutableAddressResponsePointer,
    InvalidKernelImageRange,
    InvalidKernelImageSegments,
    MissingStackSizeResponse,
    InvalidStackSizeResponsePointer,
    InvalidInitialStackBounds,
    InvalidInitialStackHhdmRange,
    InitialStackNotBootloaderReclaimable,
    MissingMemoryMapResponse,
    InvalidMemoryMapResponsePointer,
    MemoryMapCountDoesNotFit,
    TooManyMemoryRegions,
    EmptyMemoryMap,
    InvalidEntriesPointer,
    EntriesAddressOverflow,
    InvalidEntryPointer { index: usize },
    InvalidPhysicalRange { index: usize },
    InvalidHhdmMappingRange { index: usize },
    InvalidMemoryMap(MemoryMapError),
    FrameAllocator(FrameError),
}

/// Copy and validate the boot data needed by the current kernel.
///
/// Structural checks can reject malformed pointers and ranges, but cannot prove
/// that a loader-provided pointer is mapped and readable. That remains part of
/// the documented Limine handoff trust boundary until the kernel owns its maps.
pub fn capture_boot_information(entry_rsp: u64) -> Result<BootInfo, BootInfoError> {
    let cpu_info = crate::arch::x86_64::cpu::identify();
    let inherited_cr3_raw = crate::arch::x86_64::cpu::read_cr3_raw();
    let inherited_cr3_root = parse_cr3_root(
        inherited_cr3_raw,
        cpu_info.physical_address_bits,
        cpu_info.pcid_enabled,
    );
    let virtual_address_bits = cpu_info.active_linear_address_bits;
    let stack_size_request = core::ptr::addr_of_mut!(STACK_SIZE_REQUEST);
    // SAFETY: Limine completes supported request responses before `_start`.
    let stack_size_response_pointer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*stack_size_request).response)) };
    if stack_size_response_pointer.is_null() {
        return Err(BootInfoError::MissingStackSizeResponse);
    }
    if !is_valid_pointer(stack_size_response_pointer, virtual_address_bits) {
        return Err(BootInfoError::InvalidStackSizeResponsePointer);
    }
    // SAFETY: The response pointer is non-null, aligned, and canonical. As with
    // the other Limine responses, readability relies on the handoff contract.
    let _stack_size_response = unsafe { stack_size_response_pointer.read_volatile() };
    let (boot_stack_virtual_start, boot_stack_virtual_end) =
        limine_x86_64_stack_bounds(entry_rsp, virtual_address_bits, REQUESTED_BOOT_STACK_SIZE)
            .ok_or(BootInfoError::InvalidInitialStackBounds)?;
    let hhdm_request = core::ptr::addr_of_mut!(HHDM_REQUEST);
    // SAFETY: Limine has completed writing the request response before `_start`.
    let hhdm_pointer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*hhdm_request).response)) };
    if hhdm_pointer.is_null() {
        return Err(BootInfoError::MissingHhdmResponse);
    }
    if !is_valid_pointer(hhdm_pointer, virtual_address_bits) {
        return Err(BootInfoError::InvalidHhdmResponsePointer);
    }
    // SAFETY: The Limine response pointer is trusted to refer to a readable
    // response object; its nullness and alignment are checked above.
    let hhdm = unsafe { hhdm_pointer.read_volatile() };
    if hhdm.offset & 0xfff != 0 || !is_canonical_virtual_address(hhdm.offset, virtual_address_bits)
    {
        return Err(BootInfoError::InvalidHhdmOffset);
    }

    let executable_address_request = core::ptr::addr_of_mut!(EXECUTABLE_ADDRESS_REQUEST);
    // SAFETY: Limine has completed writing the request response before `_start`.
    let executable_address_pointer = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!((*executable_address_request).response))
    };
    if executable_address_pointer.is_null() {
        return Err(BootInfoError::MissingExecutableAddressResponse);
    }
    if !is_valid_pointer(executable_address_pointer, virtual_address_bits) {
        return Err(BootInfoError::InvalidExecutableAddressResponsePointer);
    }
    // SAFETY: Limine's response pointer is trusted to refer to a readable object;
    // nullness, alignment, and active-width canonicality were checked above.
    let executable_address = unsafe { executable_address_pointer.read_volatile() };
    // `linker.ld` defines these symbols as the boundaries of the loaded image.
    let (linked_virtual_start, linked_virtual_end) = (
        core::ptr::addr_of!(__kernel_start) as u64,
        core::ptr::addr_of!(__kernel_end) as u64,
    );
    let kernel_physical_end = kernel_image_physical_end(
        executable_address.physical_base,
        executable_address.virtual_base,
        linked_virtual_start,
        linked_virtual_end,
        cpu_info.physical_address_bits,
        virtual_address_bits,
    )
    .ok_or(BootInfoError::InvalidKernelImageRange)?;
    let linked_segments = KernelImageVirtualSegments {
        text: (
            core::ptr::addr_of!(__kernel_text_mapping_start) as u64,
            core::ptr::addr_of!(__kernel_text_mapping_end) as u64,
        ),
        rodata: (
            core::ptr::addr_of!(__kernel_rodata_mapping_start) as u64,
            core::ptr::addr_of!(__kernel_rodata_mapping_end) as u64,
        ),
        data: (
            core::ptr::addr_of!(__kernel_data_mapping_start) as u64,
            core::ptr::addr_of!(__kernel_data_mapping_end) as u64,
        ),
    };
    let kernel_image_segments = kernel_image_segments(
        executable_address.physical_base,
        executable_address.virtual_base,
        linked_virtual_start,
        linked_virtual_end,
        linked_segments,
        cpu_info.physical_address_bits,
        virtual_address_bits,
    )
    .ok_or(BootInfoError::InvalidKernelImageSegments)?;

    let memory_map_request = core::ptr::addr_of_mut!(MEMORY_MAP_REQUEST);
    // SAFETY: Limine has completed writing the request response before `_start`.
    let memory_map_pointer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*memory_map_request).response)) };
    if memory_map_pointer.is_null() {
        return Err(BootInfoError::MissingMemoryMapResponse);
    }
    if !is_valid_pointer(memory_map_pointer, virtual_address_bits) {
        return Err(BootInfoError::InvalidMemoryMapResponsePointer);
    }
    // SAFETY: The Limine response pointer is trusted to refer to a readable
    // response object; its nullness and alignment are checked above.
    let response = unsafe { memory_map_pointer.read_volatile() };
    let entry_count = usize::try_from(response.entry_count)
        .map_err(|_| BootInfoError::MemoryMapCountDoesNotFit)?;
    if entry_count > MAX_MEMORY_REGIONS {
        return Err(BootInfoError::TooManyMemoryRegions);
    }
    if entry_count == 0 {
        return Err(BootInfoError::EmptyMemoryMap);
    }
    if response.entries.is_null() {
        return Err(BootInfoError::InvalidEntriesPointer);
    }
    if !is_valid_pointer(response.entries, virtual_address_bits) {
        return Err(BootInfoError::InvalidEntriesPointer);
    }
    let entry_bytes = entry_count
        .checked_mul(size_of::<*const MemoryMapEntry>())
        .ok_or(BootInfoError::EntriesAddressOverflow)?;
    let entries_start = response.entries as usize;
    let entries_end = entries_start
        .checked_add(entry_bytes)
        .ok_or(BootInfoError::EntriesAddressOverflow)?;
    if !is_canonical_virtual_address(entries_start as u64, virtual_address_bits)
        || !is_canonical_virtual_address((entries_end - 1) as u64, virtual_address_bits)
    {
        return Err(BootInfoError::InvalidEntriesPointer);
    }

    let mut builder = MemoryMapBuilder::new();
    for index in 0..entry_count {
        // SAFETY: Limine promises an array of `entry_count` pointers. The count
        // is capped and pointer alignment/address arithmetic are checked above.
        let entry_pointer = unsafe { response.entries.add(index).read_volatile() };
        if !is_valid_pointer(entry_pointer, virtual_address_bits) {
            return Err(BootInfoError::InvalidEntryPointer { index });
        }
        // SAFETY: Limine promises each non-null entry pointer is readable.
        let entry = unsafe { entry_pointer.read_volatile() };
        builder
            .push(entry.base, entry.length, entry.kind)
            .map_err(BootInfoError::InvalidMemoryMap)?;
    }

    let memory_map = builder.finish().map_err(|error| match error {
        MemoryMapError::EmptyMap => BootInfoError::EmptyMemoryMap,
        other => BootInfoError::InvalidMemoryMap(other),
    })?;
    for (index, region) in memory_map.regions().iter().enumerate() {
        if let Some(physical_bits) = cpu_info.physical_address_bits {
            if !physical_range_fits_address_width(region.start(), region.end(), physical_bits) {
                return Err(BootInfoError::InvalidPhysicalRange { index });
            }
        }
        if region.kind().is_mapped_by_limine_v3_hhdm()
            && !limine_v3_hhdm_range_is_valid(
                hhdm.offset,
                region.start(),
                region.end(),
                cpu_info.physical_address_bits,
                virtual_address_bits,
            )
        {
            return Err(BootInfoError::InvalidHhdmMappingRange { index });
        }
    }
    let boot_stack_physical_start = boot_stack_virtual_start
        .checked_sub(hhdm.offset)
        .ok_or(BootInfoError::InvalidInitialStackHhdmRange)?;
    let boot_stack_physical_end = boot_stack_virtual_end
        .checked_sub(hhdm.offset)
        .ok_or(BootInfoError::InvalidInitialStackHhdmRange)?;
    if !limine_v3_hhdm_range_is_valid(
        hhdm.offset,
        boot_stack_physical_start,
        boot_stack_physical_end,
        cpu_info.physical_address_bits,
        virtual_address_bits,
    ) {
        return Err(BootInfoError::InvalidInitialStackHhdmRange);
    }
    if !memory_map.range_is_within_region_kind(
        boot_stack_physical_start,
        boot_stack_physical_end,
        RegionKind::BootloaderReclaimable,
    ) {
        return Err(BootInfoError::InitialStackNotBootloaderReclaimable);
    }
    let frame_allocator =
        FrameAllocator::from_memory_map(&memory_map).map_err(BootInfoError::FrameAllocator)?;

    Ok(BootInfo {
        hhdm_revision: hhdm.revision,
        hhdm_offset: hhdm.offset,
        inherited_cr3_raw,
        inherited_cr3_root,
        executable_address_revision: executable_address.revision,
        kernel_physical_base: executable_address.physical_base,
        kernel_physical_end,
        kernel_virtual_base: executable_address.virtual_base,
        kernel_virtual_end: linked_virtual_end,
        kernel_image_segments,
        boot_stack_physical_start,
        boot_stack_physical_end,
        boot_stack_virtual_start,
        boot_stack_virtual_end,
        memory_map_revision: response.revision,
        memory_map,
        frame_allocator,
        cpu_info,
    })
}

/// Print a report from the copied snapshot; no loader pointers are used here.
pub fn report_boot_information(boot_info: &BootInfo) {
    crate::kprintln!(
        "HHDM: offset {:#018x}, response revision {}",
        boot_info.hhdm_offset,
        boot_info.hhdm_revision
    );
    crate::kprintln!(
        "inherited CR3: raw {:#018x} (not walked during boot snapshot)",
        boot_info.inherited_cr3_raw
    );
    match boot_info.inherited_cr3_root {
        Ok(root) => crate::kprintln!(
            "inherited CR3 root: physical {:#018x}, low bits {:?}",
            root.physical_address(),
            root.low_bits()
        ),
        Err(error) => crate::kprintln!("inherited CR3 root could not be decoded: {:?}", error),
    }
    crate::kprintln!(
        "kernel image: physical [{:#018x}, {:#018x}), virtual [{:#018x}, {:#018x}), response revision {}",
        boot_info.kernel_physical_base,
        boot_info.kernel_physical_end,
        boot_info.kernel_virtual_base,
        boot_info.kernel_virtual_end,
        boot_info.executable_address_revision
    );
    let segments = &boot_info.kernel_image_segments;
    crate::kprintln!(
        "kernel mapping text RX: physical [{:#018x}, {:#018x}), virtual [{:#018x}, {:#018x})",
        segments.text.physical_start,
        segments.text.physical_end,
        segments.text.virtual_start,
        segments.text.virtual_end
    );
    crate::kprintln!(
        "kernel mapping rodata R/NX: physical [{:#018x}, {:#018x}), virtual [{:#018x}, {:#018x})",
        segments.rodata.physical_start,
        segments.rodata.physical_end,
        segments.rodata.virtual_start,
        segments.rodata.virtual_end
    );
    crate::kprintln!(
        "kernel mapping data RW/NX: physical [{:#018x}, {:#018x}), virtual [{:#018x}, {:#018x})",
        segments.data.physical_start,
        segments.data.physical_end,
        segments.data.virtual_start,
        segments.data.virtual_end
    );
    crate::kprintln!(
        "boot stack (requested span: {} KiB): physical [{:#018x}, {:#018x}), virtual [{:#018x}, {:#018x})",
        (boot_info.boot_stack_virtual_end - boot_info.boot_stack_virtual_start) / 1024,
        boot_info.boot_stack_physical_start,
        boot_info.boot_stack_physical_end,
        boot_info.boot_stack_virtual_start,
        boot_info.boot_stack_virtual_end
    );
    crate::kprintln!(
        "memory map: {} validated regions, {} MiB usable RAM, response revision {}",
        boot_info.memory_map.regions().len(),
        boot_info.memory_map.usable_bytes() / (1024 * 1024),
        boot_info.memory_map_revision
    );
    crate::kprintln!(
        "physical frames: {} managed, {} free (4 KiB each)",
        boot_info.frame_allocator.managed_frames(),
        boot_info.frame_allocator.free_frames()
    );
    for region in boot_info.memory_map.regions() {
        crate::kprintln!(
            "  [{:#018x}, {:#018x}) {:?}",
            region.start(),
            region.end(),
            region.kind()
        );
    }
    crate::kprintln!("console: COM1 serial (polling)");

    let cpu = &boot_info.cpu_info;
    let vendor = core::str::from_utf8(&cpu.vendor).unwrap_or("unknown");
    let mtrr_supported = !matches!(&cpu.mtrr, MtrrState::Unsupported);
    crate::kprintln!(
        "CPU: {} (basic leaf {}, extended leaf {:#x})",
        vendor,
        cpu.max_basic_leaf,
        cpu.max_extended_leaf
    );
    crate::kprintln!(
        "CPU feature support: SSE2={}, NX={}, NXE-enabled={}, normal-caching={}, PAT={}, MTRR={}, 1GiB-pages={}, long-mode={}, LA57-supported={}, PCID-enabled={}",
        cpu.has_sse2,
        cpu.has_nx,
        cpu.nx_enabled,
        cpu.normal_caching,
        cpu.has_pat,
        mtrr_supported,
        cpu.has_1g_pages,
        cpu.has_long_mode,
        cpu.has_la57,
        cpu.pcid_enabled
    );
    match cpu.pat_msr_value {
        Some(value) => match PatLayout::from_msr_value(value) {
            Ok(layout) => crate::kprintln!(
                "PAT: IA32_PAT={:#018x}, WB index={:?}, UC index={:?}, WC index={:?}",
                value,
                layout.index_for(CachePolicy::WriteBack),
                layout.index_for(CachePolicy::Uncacheable),
                layout.index_for(CachePolicy::WriteCombining)
            ),
            Err(error) => crate::kprintln!(
                "PAT: IA32_PAT={:#018x} has unsupported layout: {:?}",
                value,
                error
            ),
        },
        None => crate::kprintln!("PAT: unsupported"),
    }
    match &cpu.mtrr {
        MtrrState::Unsupported => {
            crate::kprintln!("MTRR: unsupported")
        }
        MtrrState::VariableRangeCapacityExceeded { reported_count } => {
            crate::kprintln!(
                "MTRR: {} variable pairs exceed the snapshot capacity {}; no partial state retained",
                reported_count,
                MAX_CAPTURED_VARIABLE_MTRRS
            )
        }
        MtrrState::Captured(registers) => {
            crate::kprintln!(
                "MTRR snapshot: MTRRCAP={:#018x}, DEF_TYPE={:#018x}, enabled={}, fixed-enabled={}, fixed-supported={}, WC-supported={}, variable-pairs={}",
                registers.capability,
                registers.default_type,
                registers.default_type & (1 << 11) != 0,
                registers.default_type & (1 << 10) != 0,
                registers.capability & (1 << 8) != 0,
                registers.capability & (1 << 10) != 0,
                registers.variable_register_count
            )
        }
    }
    match (&cpu.mtrr, cpu.pat_msr_value, cpu.physical_address_bits) {
        (MtrrState::Captured(registers), Some(pat_value), Some(address_bits)) => {
            match (
                registers.validated_layout(address_bits),
                PatLayout::from_msr_value(pat_value),
            ) {
                (Ok(mtrr), Ok(pat)) => crate::kprintln!(
                    "MTRR/PAT: validated; effective type at PA 0x0 using PAT[0]={:?}",
                    mtrr.effective_memory_type_for(0, pat, 0, cpu.normal_caching)
                ),
                (Err(error), _) => {
                    crate::kprintln!("MTRR/PAT: rejected captured MTRR state: {:?}", error)
                }
                (_, Err(error)) => {
                    crate::kprintln!("MTRR/PAT: rejected captured PAT state: {:?}", error)
                }
            }
        }
        _ => crate::kprintln!(
            "MTRR/PAT: effective type unavailable (missing state or address width)"
        ),
    }
    crate::kprintln!(
        "CPU address widths (bits): physical={:?}, max-linear={:?}, active-linear={} (LA57 active={})",
        cpu.physical_address_bits,
        cpu.max_linear_address_bits,
        cpu.active_linear_address_bits,
        cpu.active_linear_address_bits == 57
    );
}

fn is_valid_pointer<T>(pointer: *const T, virtual_address_bits: u8) -> bool {
    let start = pointer as usize;
    let Some(end) = start.checked_add(size_of::<T>()) else {
        return false;
    };
    !pointer.is_null()
        && start & (align_of::<T>() - 1) == 0
        && is_canonical_virtual_address(start as u64, virtual_address_bits)
        && is_canonical_virtual_address((end - 1) as u64, virtual_address_bits)
}
