//! Limine boot-protocol requests and validated, copied boot information.

use core::mem::{align_of, size_of};
use rustix_kernel::frame::{FrameAllocator, FrameError};
use rustix_kernel::memory::{MemoryMap, MemoryMapBuilder, MemoryMapError, MAX_MEMORY_REGIONS};

const REQUESTS_START: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];
const REQUESTS_END: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];
const BASE_REVISION: [u64; 3] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc, 3];

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

/// Owned kernel snapshot of the handoff values Rustix currently consumes.
pub struct BootInfo {
    pub hhdm_revision: u64,
    pub hhdm_offset: u64,
    pub memory_map_revision: u64,
    pub memory_map: MemoryMap,
    pub frame_allocator: FrameAllocator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootInfoError {
    MissingHhdmResponse,
    InvalidHhdmResponsePointer,
    InvalidHhdmOffset,
    MissingMemoryMapResponse,
    InvalidMemoryMapResponsePointer,
    MemoryMapCountDoesNotFit,
    TooManyMemoryRegions,
    EmptyMemoryMap,
    InvalidEntriesPointer,
    EntriesAddressOverflow,
    InvalidEntryPointer { index: usize },
    InvalidMemoryMap(MemoryMapError),
    FrameAllocator(FrameError),
}

/// Copy and validate the boot data needed by the current kernel.
///
/// Structural checks can reject malformed pointers and ranges, but cannot prove
/// that a loader-provided pointer is mapped and readable. That remains part of
/// the documented Limine handoff trust boundary until the kernel owns its maps.
pub fn capture_boot_information() -> Result<BootInfo, BootInfoError> {
    let hhdm_request = core::ptr::addr_of_mut!(HHDM_REQUEST);
    // SAFETY: Limine has completed writing the request response before `_start`.
    let hhdm_pointer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*hhdm_request).response)) };
    if hhdm_pointer.is_null() {
        return Err(BootInfoError::MissingHhdmResponse);
    }
    if !is_valid_pointer(hhdm_pointer) {
        return Err(BootInfoError::InvalidHhdmResponsePointer);
    }
    // SAFETY: The Limine response pointer is trusted to refer to a readable
    // response object; its nullness and alignment are checked above.
    let hhdm = unsafe { hhdm_pointer.read_volatile() };
    if hhdm.offset & 0xfff != 0 || !is_canonical_virtual_address(hhdm.offset) {
        return Err(BootInfoError::InvalidHhdmOffset);
    }

    let memory_map_request = core::ptr::addr_of_mut!(MEMORY_MAP_REQUEST);
    // SAFETY: Limine has completed writing the request response before `_start`.
    let memory_map_pointer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*memory_map_request).response)) };
    if memory_map_pointer.is_null() {
        return Err(BootInfoError::MissingMemoryMapResponse);
    }
    if !is_valid_pointer(memory_map_pointer) {
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
    if !is_valid_pointer(response.entries) {
        return Err(BootInfoError::InvalidEntriesPointer);
    }
    let entry_bytes = entry_count
        .checked_mul(size_of::<*const MemoryMapEntry>())
        .ok_or(BootInfoError::EntriesAddressOverflow)?;
    let entries_start = response.entries as usize;
    let entries_end = entries_start
        .checked_add(entry_bytes)
        .ok_or(BootInfoError::EntriesAddressOverflow)?;
    if !is_canonical_virtual_address(entries_start as u64)
        || !is_canonical_virtual_address((entries_end - 1) as u64)
    {
        return Err(BootInfoError::InvalidEntriesPointer);
    }

    let mut builder = MemoryMapBuilder::new();
    for index in 0..entry_count {
        // SAFETY: Limine promises an array of `entry_count` pointers. The count
        // is capped and pointer alignment/address arithmetic are checked above.
        let entry_pointer = unsafe { response.entries.add(index).read_volatile() };
        if !is_valid_pointer(entry_pointer) {
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
    let frame_allocator =
        FrameAllocator::from_memory_map(&memory_map).map_err(BootInfoError::FrameAllocator)?;

    Ok(BootInfo {
        hhdm_revision: hhdm.revision,
        hhdm_offset: hhdm.offset,
        memory_map_revision: response.revision,
        memory_map,
        frame_allocator,
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

    let cpu = crate::arch::x86_64::cpu::identify();
    let vendor = core::str::from_utf8(&cpu.vendor).unwrap_or("unknown");
    crate::kprintln!(
        "CPU: {} (basic leaf {}, extended leaf {:#x})",
        vendor,
        cpu.max_basic_leaf,
        cpu.max_extended_leaf
    );
    crate::kprintln!(
        "CPU feature support: SSE2={}, NX={}, 1GiB-pages={}, long-mode={}, LA57-supported={}",
        cpu.has_sse2,
        cpu.has_nx,
        cpu.has_1g_pages,
        cpu.has_long_mode,
        cpu.has_la57
    );
}

fn is_valid_pointer<T>(pointer: *const T) -> bool {
    let start = pointer as usize;
    let Some(end) = start.checked_add(size_of::<T>()) else {
        return false;
    };
    !pointer.is_null()
        && start & (align_of::<T>() - 1) == 0
        && is_canonical_virtual_address(start as u64)
        && is_canonical_virtual_address((end - 1) as u64)
}

fn is_canonical_virtual_address(address: u64) -> bool {
    let upper_48 = address >> 48;
    let upper_57 = address >> 57;
    upper_48 == 0 || upper_48 == 0xffff || upper_57 == 0 || upper_57 == 0x7f
}
