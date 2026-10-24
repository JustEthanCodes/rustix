//! Checked x86_64 mapping policy and a bounded owned page-table builder.
//!
//! Pure helpers validate addresses, permissions, and cache policy. Candidate
//! table access is delegated to an unsafe backend contract. This module never
//! writes CR3; callers may activate a validated hierarchy through the explicit
//! unsafe ownership marker after performing their architecture-specific switch.

use crate::frame::{Frame, FrameAllocator, FrameError};
use crate::memory::{
    is_canonical_virtual_address, physical_range_fits_address_width, HhdmAddressError, MemoryMap,
    RegionKind,
};

/// Base page size supported by the initial Rustix mapping policy.
pub const PAGE_SIZE: u64 = 4096;

/// The physical root address and interpretation of CR3's low bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cr3Root {
    physical_address: u64,
    low_bits: Cr3LowBits,
}

impl Cr3Root {
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    pub const fn low_bits(self) -> Cr3LowBits {
        self.low_bits
    }
}

/// CR3's low bits are either a PCID or the paging-structure cache controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cr3LowBits {
    Pcid(u16),
    CacheControls {
        page_level_write_through: bool,
        page_level_cache_disable: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cr3Error {
    UnknownPhysicalAddressWidth,
    InvalidPhysicalAddressWidth,
    InvalidRootAddress,
    ReservedBits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cr3RootAccessError {
    NotBootloaderReclaimable,
    Hhdm(HhdmAddressError),
}

/// Decode the currently active CR3 value without dereferencing its root table.
///
/// The caller supplies the reported physical-address width and whether CR4.PCIDE
/// is active, since those determine the valid address and low-bit encodings.
/// Encode a replacement CR3 value while preserving the active low-bit mode.
///
/// PCID is retained but the no-flush bit is always cleared so the selected PCID
/// is invalidated on load. Legacy PWT/PCD controls are preserved unchanged.
pub fn encode_cr3_value(
    root_physical_address: u64,
    low_bits: Cr3LowBits,
    physical_address_bits: u8,
) -> Result<u64, Cr3Error> {
    if !(12..=MAX_PTE_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
        return Err(Cr3Error::InvalidPhysicalAddressWidth);
    }
    let root_end = root_physical_address
        .checked_add(PAGE_SIZE)
        .ok_or(Cr3Error::InvalidRootAddress)?;
    if root_physical_address & (PAGE_SIZE - 1) != 0
        || !physical_range_fits_address_width(
            root_physical_address,
            root_end,
            physical_address_bits,
        )
    {
        return Err(Cr3Error::InvalidRootAddress);
    }
    let low = match low_bits {
        Cr3LowBits::Pcid(pcid) if pcid <= 0x0fff => u64::from(pcid),
        Cr3LowBits::Pcid(_) => return Err(Cr3Error::ReservedBits),
        Cr3LowBits::CacheControls {
            page_level_write_through,
            page_level_cache_disable,
        } => {
            (u64::from(page_level_write_through) << 3) | (u64::from(page_level_cache_disable) << 4)
        }
    };
    Ok(root_physical_address | low)
}

pub fn parse_cr3_root(
    raw: u64,
    physical_address_bits: Option<u8>,
    pcid_enabled: bool,
) -> Result<Cr3Root, Cr3Error> {
    let physical_address_bits =
        physical_address_bits.ok_or(Cr3Error::UnknownPhysicalAddressWidth)?;
    if !(12..=MAX_PTE_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
        return Err(Cr3Error::InvalidPhysicalAddressWidth);
    }

    let physical_mask = ((1u64 << physical_address_bits) - 1) & !(PAGE_SIZE - 1);
    let low_mask = if pcid_enabled {
        PAGE_SIZE - 1
    } else {
        (1 << 3) | (1 << 4)
    };
    if raw & !(physical_mask | low_mask) != 0 {
        return Err(Cr3Error::ReservedBits);
    }

    let low_bits = if pcid_enabled {
        Cr3LowBits::Pcid((raw & (PAGE_SIZE - 1)) as u16)
    } else {
        Cr3LowBits::CacheControls {
            page_level_write_through: raw & (1 << 3) != 0,
            page_level_cache_disable: raw & (1 << 4) != 0,
        }
    };

    Ok(Cr3Root {
        physical_address: raw & physical_mask,
        low_bits,
    })
}

/// Calculate the protocol-backed HHDM address of Limine's inherited root page.
///
/// This requires the root page to be wholly contained in bootloader-reclaimable
/// memory, as specified for Limine page tables. It does not dereference the page
/// or prove that the active hierarchy contains the HHDM mapping.
pub fn inherited_cr3_root_hhdm_address(
    root: Cr3Root,
    memory_map: &MemoryMap,
    hhdm_offset: u64,
    physical_address_bits: Option<u8>,
    virtual_address_bits: u8,
) -> Result<u64, Cr3RootAccessError> {
    let physical_start = root.physical_address();
    let physical_end = physical_start
        .checked_add(PAGE_SIZE)
        .ok_or(Cr3RootAccessError::Hhdm(HhdmAddressError::AddressOverflow))?;
    if !memory_map.range_is_within_region_kind(
        physical_start,
        physical_end,
        RegionKind::BootloaderReclaimable,
    ) {
        return Err(Cr3RootAccessError::NotBootloaderReclaimable);
    }
    memory_map
        .limine_hhdm_address(
            hhdm_offset,
            physical_start,
            PAGE_SIZE,
            physical_address_bits,
            virtual_address_bits,
        )
        .map_err(Cr3RootAccessError::Hhdm)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLevel {
    Pml5,
    Pml4,
    Pdpt,
    Pd,
    Pt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageWalkConfig {
    pub levels: u8,
    pub physical_address_bits: u8,
    pub virtual_address_bits: u8,
    pub nx_enabled: bool,
    pub page_2m_supported: bool,
    pub page_1g_supported: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTranslation {
    pub physical_address: u64,
    pub leaf_physical_base: u64,
    pub page_size: u64,
    pub permissions: PagePermissions,
    pub pat_index: u8,
    pub raw_leaf_entry: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageWalkOutcome {
    NotPresent { level: PageLevel },
    Mapped(PageTranslation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageTableEntryError {
    PhysicalAddressOutOfRange,
    NxDisabled,
    LargePageUnsupported,
    LargePageAtInvalidLevel,
    LargePageMisaligned,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PageWalkError<E> {
    InvalidConfiguration,
    NonCanonicalAddress,
    InvalidRoot,
    InvalidEntry {
        level: PageLevel,
        error: PageTableEntryError,
    },
    Reader(E),
}

/// Read one raw entry from a table at a validated physical page address.
pub trait PageTableReader {
    type Error;

    fn read_entry(&self, table_physical: u64, index: u16) -> Result<u64, Self::Error>;
}

/// Translate one virtual address by following at most five page-table entries.
///
/// The reader owns all physical-memory access policy. This walker does not turn
/// physical addresses into pointers, modify tables, or infer effective cache
/// types from the leaf PAT selector.
pub fn walk_virtual_address<R: PageTableReader>(
    reader: &R,
    root: Cr3Root,
    virtual_address: u64,
    config: PageWalkConfig,
) -> Result<PageWalkOutcome, PageWalkError<R::Error>> {
    if !(12..=MAX_PTE_PHYSICAL_ADDRESS_BITS).contains(&config.physical_address_bits)
        || (config.levels != 4 && config.levels != 5)
        || config.virtual_address_bits != if config.levels == 4 { 48 } else { 57 }
    {
        return Err(PageWalkError::InvalidConfiguration);
    }
    if !is_canonical_virtual_address(virtual_address, config.virtual_address_bits) {
        return Err(PageWalkError::NonCanonicalAddress);
    }
    let root_physical = root.physical_address();
    let root_end = root_physical
        .checked_add(PAGE_SIZE)
        .ok_or(PageWalkError::InvalidRoot)?;
    if root_physical & (PAGE_SIZE - 1) != 0
        || !physical_range_fits_address_width(root_physical, root_end, config.physical_address_bits)
    {
        return Err(PageWalkError::InvalidRoot);
    }

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER: u64 = 1 << 2;
    const WRITE_THROUGH: u64 = 1 << 3;
    const CACHE_DISABLE: u64 = 1 << 4;
    const PAGE_SIZE_OR_PAT: u64 = 1 << 7;
    const LARGE_PAGE_PAT: u64 = 1 << 12;
    const NO_EXECUTE: u64 = 1 << 63;
    const ADDRESS_FIELD_MASK: u64 = 0x000f_ffff_ffff_f000;

    let physical_mask = ((1u64 << config.physical_address_bits) - 1) & !(PAGE_SIZE - 1);
    let mut table_physical = root_physical;
    let mut writable = true;
    let mut user_accessible = true;
    let mut executable = true;
    let mut level_number = config.levels;

    loop {
        let shift = 12 + 9 * (level_number - 1);
        let index = ((virtual_address >> shift) & 0x1ff) as u16;
        let entry = reader
            .read_entry(table_physical, index)
            .map_err(PageWalkError::Reader)?;
        let level = match level_number {
            5 => PageLevel::Pml5,
            4 => PageLevel::Pml4,
            3 => PageLevel::Pdpt,
            2 => PageLevel::Pd,
            1 => PageLevel::Pt,
            _ => return Err(PageWalkError::InvalidConfiguration),
        };
        if entry & PRESENT == 0 {
            return Ok(PageWalkOutcome::NotPresent { level });
        }

        let address_field = entry & ADDRESS_FIELD_MASK;
        if address_field & !physical_mask != 0 {
            return Err(PageWalkError::InvalidEntry {
                level,
                error: PageTableEntryError::PhysicalAddressOutOfRange,
            });
        }
        if !config.nx_enabled && entry & NO_EXECUTE != 0 {
            return Err(PageWalkError::InvalidEntry {
                level,
                error: PageTableEntryError::NxDisabled,
            });
        }
        writable &= entry & WRITABLE != 0;
        user_accessible &= entry & USER != 0;
        executable &= entry & NO_EXECUTE == 0;

        let large_page = level_number > 1 && entry & PAGE_SIZE_OR_PAT != 0;
        let leaf_shift = if level_number == 1 {
            12
        } else if large_page && level_number == 2 && config.page_2m_supported {
            21
        } else if large_page && level_number == 3 && config.page_1g_supported {
            30
        } else if large_page && level_number <= 3 {
            return Err(PageWalkError::InvalidEntry {
                level,
                error: PageTableEntryError::LargePageUnsupported,
            });
        } else if large_page {
            return Err(PageWalkError::InvalidEntry {
                level,
                error: PageTableEntryError::LargePageAtInvalidLevel,
            });
        } else {
            table_physical = address_field;
            level_number -= 1;
            continue;
        };

        if large_page {
            let reserved_alignment_bits = ((1u64 << leaf_shift) - 1) & !0x1fff;
            if entry & reserved_alignment_bits != 0 {
                return Err(PageWalkError::InvalidEntry {
                    level,
                    error: PageTableEntryError::LargePageMisaligned,
                });
            }
        }
        let page_size = 1u64 << leaf_shift;
        let leaf_physical_base = address_field & !(page_size - 1);
        let leaf_physical_end =
            leaf_physical_base
                .checked_add(page_size)
                .ok_or(PageWalkError::InvalidEntry {
                    level,
                    error: PageTableEntryError::PhysicalAddressOutOfRange,
                })?;
        if !physical_range_fits_address_width(
            leaf_physical_base,
            leaf_physical_end,
            config.physical_address_bits,
        ) {
            return Err(PageWalkError::InvalidEntry {
                level,
                error: PageTableEntryError::PhysicalAddressOutOfRange,
            });
        }
        let pat_bit = if large_page {
            entry & LARGE_PAGE_PAT != 0
        } else {
            entry & PAGE_SIZE_OR_PAT != 0
        };
        let pat_index = (u8::from(pat_bit) << 2)
            | (u8::from(entry & CACHE_DISABLE != 0) << 1)
            | u8::from(entry & WRITE_THROUGH != 0);
        return Ok(PageWalkOutcome::Mapped(PageTranslation {
            physical_address: leaf_physical_base | (virtual_address & (page_size - 1)),
            leaf_physical_base,
            page_size,
            permissions: PagePermissions {
                writable,
                executable,
                user_accessible,
            },
            pat_index,
            raw_leaf_entry: entry,
        }));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagePermissions {
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
}

/// A mapping range whose arithmetic, address widths, alignment, and W^X policy passed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedMappingRange {
    virtual_start: u64,
    virtual_end: u64,
    physical_start: u64,
    physical_end: u64,
    physical_address_bits: u8,
    permissions: PagePermissions,
}

/// PAT selection for one physical extent, derived from supplied PAT/MTRR state.
///
/// This records a uniform effective type across the range, but does not inspect
/// existing mappings or prove that aliases use compatible cache attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedCacheAttributes {
    physical_start: u64,
    physical_end: u64,
    pat_index: u8,
    effective_type: EffectiveMemoryType,
}

impl SelectedCacheAttributes {
    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    pub const fn physical_end(self) -> u64 {
        self.physical_end
    }

    pub const fn pat_index(self) -> u8 {
        self.pat_index
    }

    pub const fn effective_type(self) -> EffectiveMemoryType {
        self.effective_type
    }
}

impl ValidatedMappingRange {
    pub const fn virtual_start(self) -> u64 {
        self.virtual_start
    }

    pub const fn virtual_end(self) -> u64 {
        self.virtual_end
    }

    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    pub const fn physical_end(self) -> u64 {
        self.physical_end
    }

    pub const fn permissions(self) -> PagePermissions {
        self.permissions
    }

    pub const fn length(self) -> u64 {
        self.virtual_end - self.virtual_start
    }

    /// Select PAT attributes that yield one effective type across this range.
    ///
    /// The supplied PAT/MTRR snapshot and `normal_caching` flag must reflect the
    /// active hardware state. This is a policy calculation only; it does not
    /// inspect existing mappings or detect cache-type aliases.
    pub fn select_cache_attributes(
        self,
        policy: CachePolicy,
        pat: PatLayout,
        mtrrs: &ValidatedMtrrLayout,
        normal_caching: bool,
    ) -> Result<SelectedCacheAttributes, MappingError> {
        if self.physical_address_bits != mtrrs.physical_address_bits {
            return Err(MappingError::MtrrPhysicalAddressWidthMismatch);
        }

        let effective_type = match policy {
            CachePolicy::WriteBack => EffectiveMemoryType::WriteBack,
            CachePolicy::Uncacheable => EffectiveMemoryType::Uncacheable,
            CachePolicy::WriteCombining => EffectiveMemoryType::WriteCombining,
        };
        let pat_index = mtrrs
            .select_pat_index_for_range(
                self.physical_start,
                self.length(),
                pat,
                effective_type,
                normal_caching,
            )
            .map_err(MappingError::CachePolicy)?;

        Ok(SelectedCacheAttributes {
            physical_start: self.physical_start,
            physical_end: self.physical_end,
            pat_index,
            effective_type,
        })
    }

    /// Encode a 4 KiB leaf PTE using attributes selected for this physical range.
    pub fn leaf_4k_entry_with_cache_attributes(
        self,
        page_offset: u64,
        cache_attributes: SelectedCacheAttributes,
        nx_enabled: bool,
    ) -> Result<PageTableEntry, MappingError> {
        if cache_attributes.physical_start != self.physical_start
            || cache_attributes.physical_end != self.physical_end
        {
            return Err(MappingError::CacheAttributesRangeMismatch);
        }
        self.leaf_4k_entry(page_offset, cache_attributes.pat_index, nx_enabled)
    }

    /// Encode a single 4 KiB leaf PTE within this validated range.
    ///
    /// `pat_index` is the raw three-bit PAT index; the caller must have verified
    /// that the active PAT MSR gives it the intended cache semantics. `nx_enabled`
    /// must reflect EFER.NXE, not merely CPUID support. This only creates entry
    /// bits—it neither owns the frame nor writes a page table.
    pub fn leaf_4k_entry(
        self,
        page_offset: u64,
        pat_index: u8,
        nx_enabled: bool,
    ) -> Result<PageTableEntry, MappingError> {
        if page_offset & (PAGE_SIZE - 1) != 0 {
            return Err(MappingError::UnalignedPageOffset);
        }
        if page_offset >= self.length() {
            return Err(MappingError::PageOffsetOutOfRange);
        }
        if self.physical_address_bits > MAX_PTE_PHYSICAL_ADDRESS_BITS {
            return Err(MappingError::InvalidPhysicalAddressWidth);
        }
        if pat_index > 7 {
            return Err(MappingError::InvalidPatIndex);
        }
        if !self.permissions.executable && !nx_enabled {
            return Err(MappingError::NxNotEnabled);
        }

        let physical_address = self
            .physical_start
            .checked_add(page_offset)
            .ok_or(MappingError::AddressOverflow)?;
        let mut bits = physical_address | PTE_PRESENT;
        if self.permissions.writable {
            bits |= PTE_WRITABLE;
        }
        if self.permissions.user_accessible {
            bits |= PTE_USER;
        }
        if pat_index & 0b001 != 0 {
            bits |= PTE_WRITE_THROUGH;
        }
        if pat_index & 0b010 != 0 {
            bits |= PTE_CACHE_DISABLE;
        }
        if pat_index & 0b100 != 0 {
            bits |= PTE_PAT_4K;
        }
        if !self.permissions.executable {
            bits |= PTE_NO_EXECUTE;
        }

        Ok(PageTableEntry(bits))
    }
}

/// Maximum x86_64 physical-address width representable by a 4 KiB PTE.
pub const MAX_PTE_PHYSICAL_ADDRESS_BITS: u8 = 52;
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_WRITE_THROUGH: u64 = 1 << 3;
const PTE_CACHE_DISABLE: u64 = 1 << 4;
const PTE_PAT_4K: u64 = 1 << 7;
const PTE_NO_EXECUTE: u64 = 1 << 63;

/// Raw bits for one x86_64 4 KiB leaf page-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePolicy {
    WriteBack,
    Uncacheable,
    WriteCombining,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatMemoryType {
    Uncacheable,
    WriteCombining,
    WriteThrough,
    WriteProtected,
    WriteBack,
    UncacheableMinus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveMemoryType {
    Uncacheable,
    WriteCombining,
    WriteThrough,
    WriteProtected,
    WriteBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatLayoutError {
    ReservedBits { index: u8 },
    ReservedMemoryType { index: u8, value: u8 },
}

/// Parsed PAT memory types from an `IA32_PAT` MSR value supplied by the caller.
///
/// Parsing does not read the MSR or establish that this is the active value. The
/// MTRR configuration may also affect the effective cache type for an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatLayout {
    memory_types: [u8; 8],
}

impl PatLayout {
    pub fn from_msr_value(value: u64) -> Result<Self, PatLayoutError> {
        let mut memory_types = [0; 8];
        for (index, memory_type) in memory_types.iter_mut().enumerate() {
            let entry = ((value >> (index * 8)) & 0xff) as u8;
            if entry & !0x07 != 0 {
                return Err(PatLayoutError::ReservedBits { index: index as u8 });
            }
            if entry == 0b010 || entry == 0b011 {
                return Err(PatLayoutError::ReservedMemoryType {
                    index: index as u8,
                    value: entry,
                });
            }
            *memory_type = entry;
        }
        Ok(Self { memory_types })
    }

    /// Return the first PAT index with the exact requested memory type.
    pub fn index_for(self, policy: CachePolicy) -> Option<u8> {
        let requested_type = match policy {
            CachePolicy::Uncacheable => 0b000,
            CachePolicy::WriteCombining => 0b001,
            CachePolicy::WriteBack => 0b110,
        };
        self.memory_types
            .iter()
            .position(|memory_type| *memory_type == requested_type)
            .map(|index| index as u8)
    }

    fn memory_type_at(self, index: u8) -> Result<PatMemoryType, EffectiveMemoryTypeError> {
        match self.memory_types.get(usize::from(index)).copied() {
            Some(0) => Ok(PatMemoryType::Uncacheable),
            Some(1) => Ok(PatMemoryType::WriteCombining),
            Some(4) => Ok(PatMemoryType::WriteThrough),
            Some(5) => Ok(PatMemoryType::WriteProtected),
            Some(6) => Ok(PatMemoryType::WriteBack),
            Some(7) => Ok(PatMemoryType::UncacheableMinus),
            Some(_) => unreachable!("PAT layouts reject reserved memory types"),
            None => Err(EffectiveMemoryTypeError::PatIndexOutOfRange { index }),
        }
    }
}

const IA32_MTRRCAP: u32 = 0x0000_00fe;
const IA32_MTRR_DEF_TYPE: u32 = 0x0000_02ff;
const IA32_MTRR_PHYSBASE0: u32 = 0x0000_0200;
const MTRRCAP_FIXED_SUPPORTED: u64 = 1 << 8;
const MTRRCAP_PRMRR_SUPPORTED: u64 = 1 << 12; // Recognized but not consumed by this MTRR policy.
const MTRRCAP_KNOWN_BITS: u64 = 0x0dff | MTRRCAP_PRMRR_SUPPORTED;
const FIXED_MTRR_REGISTER_INDICES: [u32; 11] = [
    0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
];

/// Maximum variable MTRR pairs retained in the fixed-capacity boot snapshot.
pub const MAX_CAPTURED_VARIABLE_MTRRS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtrrRegisterPair {
    pub base: u64,
    pub mask: u64,
}

/// Raw MTRR state captured for diagnostics; values still require policy validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtrrRegisters {
    pub capability: u64,
    pub default_type: u64,
    pub fixed_registers: Option<[u64; 11]>,
    pub variable_register_count: u8,
    pub variable_registers: [MtrrRegisterPair; MAX_CAPTURED_VARIABLE_MTRRS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtrrState {
    Unsupported,
    VariableRangeCapacityExceeded { reported_count: u8 },
    Captured(MtrrRegisters),
}

/// Capture a bounded register snapshot using a caller-provided MSR reader.
///
/// This helper performs no hardware access itself. A false support flag returns
/// without invoking the reader; an over-capacity count returns no partial data.
pub fn capture_mtrr_registers(supported: bool, mut read_msr: impl FnMut(u32) -> u64) -> MtrrState {
    if !supported {
        return MtrrState::Unsupported;
    }

    let capability = read_msr(IA32_MTRRCAP);
    let variable_register_count = (capability & 0xff) as u8;
    if usize::from(variable_register_count) > MAX_CAPTURED_VARIABLE_MTRRS {
        return MtrrState::VariableRangeCapacityExceeded {
            reported_count: variable_register_count,
        };
    }

    let default_type = read_msr(IA32_MTRR_DEF_TYPE);
    let fixed_registers = if capability & MTRRCAP_FIXED_SUPPORTED != 0 {
        let mut registers = [0; FIXED_MTRR_REGISTER_INDICES.len()];
        for (register, index) in registers.iter_mut().zip(FIXED_MTRR_REGISTER_INDICES) {
            *register = read_msr(index);
        }
        Some(registers)
    } else {
        None
    };

    let mut variable_registers =
        [MtrrRegisterPair { base: 0, mask: 0 }; MAX_CAPTURED_VARIABLE_MTRRS];
    for (range_index, registers) in variable_registers
        .iter_mut()
        .take(usize::from(variable_register_count))
        .enumerate()
    {
        let base_index = IA32_MTRR_PHYSBASE0 + 2 * range_index as u32;
        registers.base = read_msr(base_index);
        registers.mask = read_msr(base_index + 1);
    }

    MtrrState::Captured(MtrrRegisters {
        capability,
        default_type,
        fixed_registers,
        variable_register_count,
        variable_registers,
    })
}

pub const FIXED_MTRR_TYPE_COUNT: usize = 88;
const MAX_MTRR_PHYSICAL_ADDRESS_BITS: u8 = 52;
const MTRR_VALID: u64 = 1 << 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MtrrMemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

impl MtrrMemoryType {
    pub fn from_raw(value: u8) -> Result<Self, MtrrError> {
        match value {
            0 => Ok(Self::Uncacheable),
            1 => Ok(Self::WriteCombining),
            4 => Ok(Self::WriteThrough),
            5 => Ok(Self::WriteProtected),
            6 => Ok(Self::WriteBack),
            value => Err(MtrrError::ReservedMemoryType { value }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtrrError {
    InvalidPhysicalAddressWidth,
    ReservedCapabilityBits,
    ReservedDefaultTypeBits,
    ReservedBaseBits,
    ReservedMaskBits,
    UnsupportedDiscontinuousVariableMask,
    MisalignedVariableBase,
    InvalidVariableRange,
    ReservedMemoryType { value: u8 },
    FixedRangesUnavailable,
    FixedRegisterSupportMismatch,
    VariableRegisterCountMismatch,
    WriteCombiningUnsupported,
    PhysicalAddressOutOfRange,
    PhysicalAddressWidthMismatch,
    UndefinedOverlap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveMemoryTypeError {
    Mtrr(MtrrError),
    PatIndexOutOfRange { index: u8 },
    NonNormalCachingMode,
    EmptyRange,
    UnalignedRange,
    AddressOverflow,
    NoUniformPatIndex { requested: EffectiveMemoryType },
}

/// Decoded fixed MTRR memory types in ascending physical-address order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedMtrrRanges {
    memory_types: [MtrrMemoryType; FIXED_MTRR_TYPE_COUNT],
}

impl FixedMtrrRanges {
    /// Decode FIX64K_00000, FIX16K_80000/A0000, and FIX4K_C0000..F8000.
    pub fn from_msr_values(registers: [u64; 11]) -> Result<Self, MtrrError> {
        let mut memory_types = [MtrrMemoryType::Uncacheable; FIXED_MTRR_TYPE_COUNT];
        for (register_index, value) in registers.iter().enumerate() {
            for slot in 0..8 {
                let memory_type = ((value >> (slot * 8)) & 0xff) as u8;
                memory_types[register_index * 8 + slot] = MtrrMemoryType::from_raw(memory_type)?;
            }
        }
        Ok(Self { memory_types })
    }

    fn type_for_address(&self, address: u64) -> Option<MtrrMemoryType> {
        let index = if address < 0x80_000 {
            (address / 0x1_0000) as usize
        } else if address < 0xa0_000 {
            8 + ((address - 0x80_000) / 0x4000) as usize
        } else if address < 0xc0_000 {
            16 + ((address - 0xa0_000) / 0x4000) as usize
        } else if address < 0x10_0000 {
            24 + ((address - 0xc0_000) / 0x1000) as usize
        } else {
            return None;
        };
        Some(self.memory_types[index])
    }
}

/// One supported variable-range MTRR with a power-of-two mask and aligned base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariableMtrr {
    base_match: u64,
    address_mask: u64,
    range_start: u64,
    range_end: u64,
    physical_address_bits: u8,
    memory_type: MtrrMemoryType,
    enabled: bool,
}

impl VariableMtrr {
    /// Decode one IA32_MTRR_PHYSBASE/PHYSMASK pair. A clear valid bit returns `Ok(None)`.
    /// Discontinuous masks permitted by some CPUs are explicitly unsupported.
    pub fn from_msr_values(
        base: u64,
        mask: u64,
        physical_address_bits: u8,
    ) -> Result<Option<Self>, MtrrError> {
        if !(12..=MAX_MTRR_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
            return Err(MtrrError::InvalidPhysicalAddressWidth);
        }
        let physical_mask = ((1u64 << physical_address_bits) - 1) & !(PAGE_SIZE - 1);
        if base & !(physical_mask | 0xff) != 0 {
            return Err(MtrrError::ReservedBaseBits);
        }
        if mask & !(physical_mask | MTRR_VALID) != 0 {
            return Err(MtrrError::ReservedMaskBits);
        }
        let memory_type = MtrrMemoryType::from_raw((base & 0xff) as u8)?;
        if mask & MTRR_VALID == 0 {
            return Ok(None);
        }

        let address_mask = mask & physical_mask;
        let ignored_page_bits = (physical_mask ^ address_mask) >> 12;
        if ignored_page_bits & ignored_page_bits.wrapping_add(1) != 0 {
            return Err(MtrrError::UnsupportedDiscontinuousVariableMask);
        }
        let ignored_address_bits = physical_mask ^ address_mask;
        if base & ignored_address_bits != 0 {
            return Err(MtrrError::MisalignedVariableBase);
        }

        let range_start = base & address_mask;
        let range_size = ignored_address_bits + PAGE_SIZE;
        let range_end = range_start
            .checked_add(range_size)
            .filter(|end| *end <= (1u64 << physical_address_bits))
            .ok_or(MtrrError::InvalidVariableRange)?;

        Ok(Some(Self {
            base_match: range_start,
            address_mask,
            range_start,
            range_end,
            physical_address_bits,
            memory_type,
            enabled: true,
        }))
    }

    const fn inactive(physical_address_bits: u8) -> Self {
        Self {
            base_match: 0,
            address_mask: 0,
            range_start: 0,
            range_end: 0,
            physical_address_bits,
            memory_type: MtrrMemoryType::Uncacheable,
            enabled: false,
        }
    }

    fn matches(self, address: u64) -> bool {
        self.enabled && address & self.address_mask == self.base_match
    }
}

/// MTRR policy decoded from supplied register values; it does not access MSRs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtrrLayout<'a> {
    physical_address_bits: u8,
    enabled: bool,
    fixed_enabled: bool,
    default_type: MtrrMemoryType,
    fixed_ranges: Option<&'a FixedMtrrRanges>,
    variable_ranges: &'a [VariableMtrr],
}

impl<'a> MtrrLayout<'a> {
    pub fn new(
        physical_address_bits: u8,
        enabled: bool,
        fixed_enabled: bool,
        default_type: MtrrMemoryType,
        fixed_ranges: Option<&'a FixedMtrrRanges>,
        variable_ranges: &'a [VariableMtrr],
    ) -> Result<Self, MtrrError> {
        if !(12..=MAX_MTRR_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
            return Err(MtrrError::InvalidPhysicalAddressWidth);
        }
        if enabled && fixed_enabled && fixed_ranges.is_none() {
            return Err(MtrrError::FixedRangesUnavailable);
        }
        if variable_ranges
            .iter()
            .any(|range| range.physical_address_bits != physical_address_bits)
        {
            return Err(MtrrError::PhysicalAddressWidthMismatch);
        }

        Ok(Self {
            physical_address_bits,
            enabled,
            fixed_enabled,
            default_type,
            fixed_ranges,
            variable_ranges,
        })
    }

    fn next_boundary_after(&self, address: u64, end: u64) -> u64 {
        if !self.enabled {
            return end;
        }

        let mut next = end;
        if self.fixed_enabled {
            if let Some(boundary) = next_fixed_mtrr_boundary(address) {
                if boundary < next {
                    next = boundary;
                }
            }
        }
        for range in self.variable_ranges.iter().filter(|range| range.enabled) {
            for boundary in [range.range_start, range.range_end] {
                if boundary > address && boundary < next {
                    next = boundary;
                }
            }
        }
        next
    }

    /// Resolve the MTRR type for one physical address, rejecting undefined overlaps.
    pub fn memory_type_for(&self, address: u64) -> Result<MtrrMemoryType, MtrrError> {
        if address >= (1u64 << self.physical_address_bits) {
            return Err(MtrrError::PhysicalAddressOutOfRange);
        }
        if !self.enabled {
            return Ok(MtrrMemoryType::Uncacheable);
        }
        if self.fixed_enabled {
            if let Some(memory_type) = self
                .fixed_ranges
                .and_then(|ranges| ranges.type_for_address(address))
            {
                return Ok(memory_type);
            }
        }

        let mut matched_types = 0u8;
        for range in self.variable_ranges {
            if range.matches(address) {
                matched_types |= 1 << range.memory_type as u8;
            }
        }
        if matched_types == 0 {
            return Ok(self.default_type);
        }
        if matched_types & (1 << MtrrMemoryType::Uncacheable as u8) != 0 {
            return Ok(MtrrMemoryType::Uncacheable);
        }
        if matched_types.count_ones() == 1 {
            return MtrrMemoryType::from_raw(matched_types.trailing_zeros() as u8);
        }
        let write_back_and_through =
            (1 << MtrrMemoryType::WriteBack as u8) | (1 << MtrrMemoryType::WriteThrough as u8);
        if matched_types == write_back_and_through {
            return Ok(MtrrMemoryType::WriteThrough);
        }
        Err(MtrrError::UndefinedOverlap)
    }
}

fn next_fixed_mtrr_boundary(address: u64) -> Option<u64> {
    match address {
        0..0x80_000 => Some((address / 0x1_0000 + 1) * 0x1_0000),
        0x80_000..0xa0_000 => Some(0x80_000 + ((address - 0x80_000) / 0x4000 + 1) * 0x4000),
        0xa0_000..0xc0_000 => Some(0xa0_000 + ((address - 0xa0_000) / 0x4000 + 1) * 0x4000),
        0xc0_000..0x10_0000 => Some(0xc0_000 + ((address - 0xc0_000) / 0x1000 + 1) * 0x1000),
        _ => None,
    }
}

/// Fully decoded MTRR state. Construction rejects malformed or incomplete
/// captured register snapshots before they can influence a mapping policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedMtrrLayout {
    physical_address_bits: u8,
    enabled: bool,
    fixed_enabled: bool,
    default_type: MtrrMemoryType,
    fixed_ranges: Option<FixedMtrrRanges>,
    variable_ranges: [VariableMtrr; MAX_CAPTURED_VARIABLE_MTRRS],
}

impl MtrrRegisters {
    pub fn validated_layout(
        &self,
        physical_address_bits: u8,
    ) -> Result<ValidatedMtrrLayout, MtrrError> {
        if !(12..=MAX_MTRR_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
            return Err(MtrrError::InvalidPhysicalAddressWidth);
        }
        if self.capability & !MTRRCAP_KNOWN_BITS != 0 {
            return Err(MtrrError::ReservedCapabilityBits);
        }
        if self.default_type & !0x0cff != 0 {
            return Err(MtrrError::ReservedDefaultTypeBits);
        }

        let reported_count = (self.capability & 0xff) as usize;
        if reported_count > MAX_CAPTURED_VARIABLE_MTRRS
            || reported_count != usize::from(self.variable_register_count)
        {
            return Err(MtrrError::VariableRegisterCountMismatch);
        }

        let fixed_supported = self.capability & MTRRCAP_FIXED_SUPPORTED != 0;
        if fixed_supported != self.fixed_registers.is_some() {
            return Err(MtrrError::FixedRegisterSupportMismatch);
        }
        let enabled = self.default_type & MTRR_ENABLED != 0;
        let fixed_enabled = self.default_type & MTRR_FIXED_ENABLED != 0;
        if fixed_enabled && !fixed_supported {
            return Err(MtrrError::FixedRangesUnavailable);
        }

        let default_type = MtrrMemoryType::from_raw((self.default_type & 0xff) as u8)?;
        let write_combining_supported = self.capability & MTRRCAP_WRITE_COMBINING_SUPPORTED != 0;
        if default_type == MtrrMemoryType::WriteCombining && !write_combining_supported {
            return Err(MtrrError::WriteCombiningUnsupported);
        }

        let fixed_ranges = self
            .fixed_registers
            .map(FixedMtrrRanges::from_msr_values)
            .transpose()?;
        if fixed_ranges.as_ref().is_some_and(|ranges| {
            ranges
                .memory_types
                .contains(&MtrrMemoryType::WriteCombining)
        }) && !write_combining_supported
        {
            return Err(MtrrError::WriteCombiningUnsupported);
        }

        let mut variable_ranges =
            [VariableMtrr::inactive(physical_address_bits); MAX_CAPTURED_VARIABLE_MTRRS];
        for (index, pair) in self
            .variable_registers
            .iter()
            .take(reported_count)
            .enumerate()
        {
            if let Some(range) =
                VariableMtrr::from_msr_values(pair.base, pair.mask, physical_address_bits)?
            {
                if range.memory_type == MtrrMemoryType::WriteCombining && !write_combining_supported
                {
                    return Err(MtrrError::WriteCombiningUnsupported);
                }
                variable_ranges[index] = range;
            }
        }

        Ok(ValidatedMtrrLayout {
            physical_address_bits,
            enabled,
            fixed_enabled,
            default_type,
            fixed_ranges,
            variable_ranges,
        })
    }
}

impl ValidatedMtrrLayout {
    fn as_layout(&self) -> MtrrLayout<'_> {
        MtrrLayout {
            physical_address_bits: self.physical_address_bits,
            enabled: self.enabled,
            fixed_enabled: self.fixed_enabled,
            default_type: self.default_type,
            fixed_ranges: self.fixed_ranges.as_ref(),
            variable_ranges: &self.variable_ranges,
        }
    }

    pub fn memory_type_for(&self, address: u64) -> Result<MtrrMemoryType, MtrrError> {
        self.as_layout().memory_type_for(address)
    }

    /// Resolve the Intel SDM PAT/MTRR table for one address and PAT index.
    /// `normal_caching` must reflect CR0.CD=0 and CR0.NW=0.
    pub fn effective_memory_type_for(
        &self,
        address: u64,
        pat: PatLayout,
        pat_index: u8,
        normal_caching: bool,
    ) -> Result<EffectiveMemoryType, EffectiveMemoryTypeError> {
        if !normal_caching {
            return Err(EffectiveMemoryTypeError::NonNormalCachingMode);
        }
        let mtrr_type = self
            .memory_type_for(address)
            .map_err(EffectiveMemoryTypeError::Mtrr)?;
        let pat_type = pat.memory_type_at(pat_index)?;
        Ok(combine_mtrr_pat_types(mtrr_type, pat_type))
    }

    /// Select the lowest PAT index that yields one effective type across an
    /// aligned physical range. This checks MTRR transition boundaries, not aliases.
    pub fn select_pat_index_for_range(
        &self,
        physical_start: u64,
        length: u64,
        pat: PatLayout,
        requested: EffectiveMemoryType,
        normal_caching: bool,
    ) -> Result<u8, EffectiveMemoryTypeError> {
        if !normal_caching {
            return Err(EffectiveMemoryTypeError::NonNormalCachingMode);
        }
        if length == 0 {
            return Err(EffectiveMemoryTypeError::EmptyRange);
        }
        if (physical_start | length) & (PAGE_SIZE - 1) != 0 {
            return Err(EffectiveMemoryTypeError::UnalignedRange);
        }
        let end = physical_start
            .checked_add(length)
            .ok_or(EffectiveMemoryTypeError::AddressOverflow)?;
        if end > (1u64 << self.physical_address_bits) {
            return Err(EffectiveMemoryTypeError::Mtrr(
                MtrrError::PhysicalAddressOutOfRange,
            ));
        }

        let layout = self.as_layout();
        let mut candidates = u8::MAX;
        let mut address = physical_start;
        while address < end {
            let mtrr_type = layout
                .memory_type_for(address)
                .map_err(EffectiveMemoryTypeError::Mtrr)?;
            for index in 0..8 {
                let pat_type = pat.memory_type_at(index)?;
                if combine_mtrr_pat_types(mtrr_type, pat_type) != requested {
                    candidates &= !(1 << index);
                }
            }
            if candidates == 0 {
                return Err(EffectiveMemoryTypeError::NoUniformPatIndex { requested });
            }
            address = layout.next_boundary_after(address, end);
        }
        Ok(candidates.trailing_zeros() as u8)
    }
}

const MTRR_ENABLED: u64 = 1 << 11;
const MTRR_FIXED_ENABLED: u64 = 1 << 10;
const MTRRCAP_WRITE_COMBINING_SUPPORTED: u64 = 1 << 10;

const INTEL_PAT_MTRR_EFFECTIVE_TYPES: [[EffectiveMemoryType; 6]; 5] = [
    [
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
    ],
    [
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::Uncacheable,
    ],
    [
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::WriteThrough,
        EffectiveMemoryType::WriteThrough,
        EffectiveMemoryType::WriteProtected,
    ],
    [
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::WriteThrough,
        EffectiveMemoryType::WriteBack,
        EffectiveMemoryType::WriteProtected,
    ],
    [
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::Uncacheable,
        EffectiveMemoryType::WriteCombining,
        EffectiveMemoryType::WriteThrough,
        EffectiveMemoryType::WriteProtected,
        EffectiveMemoryType::WriteProtected,
    ],
];

fn combine_mtrr_pat_types(mtrr: MtrrMemoryType, pat: PatMemoryType) -> EffectiveMemoryType {
    use MtrrMemoryType as M;
    use PatMemoryType as P;

    // Intel SDM Table 11-7; rows are MTRR UC/WC/WT/WB/WP, columns PAT UC/UC-/WC/WT/WB/WP.
    let row = match mtrr {
        M::Uncacheable => 0,
        M::WriteCombining => 1,
        M::WriteThrough => 2,
        M::WriteBack => 3,
        M::WriteProtected => 4,
    };
    let column = match pat {
        P::Uncacheable => 0,
        P::UncacheableMinus => 1,
        P::WriteCombining => 2,
        P::WriteThrough => 3,
        P::WriteBack => 4,
        P::WriteProtected => 5,
    };
    INTEL_PAT_MTRR_EFFECTIVE_TYPES[row][column]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingError {
    EmptyRange,
    UnalignedRange,
    AddressOverflow,
    MtrrPhysicalAddressWidthMismatch,
    CachePolicy(EffectiveMemoryTypeError),
    CacheAttributesRangeMismatch,
    InvalidPhysicalAddressWidth,
    UnknownPhysicalAddressWidth,
    InvalidVirtualAddressWidth,
    PhysicalRangeOutOfBounds,
    NonCanonicalVirtualRange,
    CrossesCanonicalHole,
    WritableExecutable,
    UnalignedPageOffset,
    PageOffsetOutOfRange,
    InvalidPatIndex,
    NxNotEnabled,
}

/// Validate one contiguous range for a future 4 KiB page-mapping operation.
///
/// The physical-address width must be known; passing `None` is rejected rather
/// than treating an unknown bound as unbounded. Successful validation does not
/// establish that physical frames are owned by a caller or mapped in the HHDM.
pub fn validate_mapping_range(
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    permissions: PagePermissions,
    physical_address_bits: Option<u8>,
    virtual_address_bits: u8,
) -> Result<ValidatedMappingRange, MappingError> {
    if virtual_address_bits == 0 || virtual_address_bits > 64 {
        return Err(MappingError::InvalidVirtualAddressWidth);
    }
    let physical_address_bits =
        physical_address_bits.ok_or(MappingError::UnknownPhysicalAddressWidth)?;
    if physical_address_bits == 0 || physical_address_bits > 64 {
        return Err(MappingError::InvalidPhysicalAddressWidth);
    }
    if length == 0 {
        return Err(MappingError::EmptyRange);
    }
    if (virtual_start | physical_start | length) & (PAGE_SIZE - 1) != 0 {
        return Err(MappingError::UnalignedRange);
    }
    if permissions.writable && permissions.executable {
        return Err(MappingError::WritableExecutable);
    }

    let virtual_end = virtual_start
        .checked_add(length)
        .ok_or(MappingError::AddressOverflow)?;
    let physical_end = physical_start
        .checked_add(length)
        .ok_or(MappingError::AddressOverflow)?;
    if !physical_range_fits_address_width(physical_start, physical_end, physical_address_bits) {
        return Err(MappingError::PhysicalRangeOutOfBounds);
    }

    let last_virtual_address = virtual_end - 1;
    if !is_canonical_virtual_address(virtual_start, virtual_address_bits)
        || !is_canonical_virtual_address(last_virtual_address, virtual_address_bits)
    {
        return Err(MappingError::NonCanonicalVirtualRange);
    }
    if virtual_address_bits < 64
        && ((virtual_start ^ last_virtual_address) & (1u64 << (virtual_address_bits - 1))) != 0
    {
        return Err(MappingError::CrossesCanonicalHole);
    }

    Ok(ValidatedMappingRange {
        virtual_start,
        virtual_end,
        physical_start,
        physical_end,
        physical_address_bits,
        permissions,
    })
}

/// Maximum number of physical pages held by a candidate hierarchy.
pub const MAX_CANDIDATE_PAGE_TABLE_PAGES: usize = 32;
/// Maximum number of allocator-owned leaf frames tracked by a candidate hierarchy.
pub const MAX_CANDIDATE_MAPPINGS: usize = 256;

const PTE_ADDRESS_FIELD_MASK: u64 = 0x000f_ffff_ffff_f000;
const PTE_PAGE_SIZE: u64 = 1 << 7;

/// Storage access for table pages that have been prepared from owned frame tokens.
///
/// `prepare_table` must establish access to the complete writable frame and
/// return a copyable handle. Reads may fail before a mutation is committed;
/// `clear_table` and `write_entry` must not fail for a prepared handle. A kernel
/// backend may rely on a validated HHDM mapping here; a hardware fault remains
/// fatal and must not be converted into a partial-success return.
///
/// # Safety
/// Implementations must ensure a prepared handle refers to the exact complete
/// frame passed to `prepare_table`, with writable access for the duration of the
/// candidate's borrow of the memory backend. The unsafe operations must access
/// only that prepared frame and honor entry bounds.
pub unsafe trait CandidatePageTableMemory {
    type PreparedTable: Copy;
    type Error;

    fn prepare_table(&mut self, frame: &Frame) -> Result<Self::PreparedTable, Self::Error>;

    /// # Safety
    /// `table` must have been returned by this backend's `prepare_table`, and
    /// `index` must be less than 512.
    unsafe fn read_entry(&self, table: Self::PreparedTable, index: u16)
        -> Result<u64, Self::Error>;

    /// # Safety
    /// `table` must have been returned by this backend's `prepare_table`.
    unsafe fn clear_table(&mut self, table: Self::PreparedTable);

    /// # Safety
    /// `table` must have been returned by this backend's `prepare_table`, and
    /// `index` must be less than 512.
    unsafe fn write_entry(&mut self, table: Self::PreparedTable, index: u16, value: u64);
}

struct CandidateTable<P: Copy> {
    frame: Frame,
    prepared: Option<P>,
}

struct CandidateMapping {
    virtual_address: u64,
    frame: Frame,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateCreateErrorKind<E> {
    InvalidConfiguration,
    RootFrameOutOfRange,
    OutOfFrames,
    TableMemory(E),
}

/// Creation failures return any allocated root frame to the caller.
#[derive(Debug, PartialEq, Eq)]
pub struct CandidateCreateError<E> {
    pub cause: CandidateCreateErrorKind<E>,
    pub frame: Option<Frame>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateCloneError<ReaderError, MemoryError> {
    Active,
    Releasing,
    AlreadyCloned,
    InvalidConfiguration,
    InvalidSourceRoot,
    InvalidEntry { level: u8, index: u16 },
    TableCapacity,
    OutOfFrames,
    TableFrameOutOfRange,
    SourceRead(ReaderError),
    TableMemory(MemoryError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateMapErrorKind<E> {
    Active,
    Releasing,
    InvalidConfiguration,
    InvalidMapping,
    TableFrameOutOfRange,
    Mapping(MappingError),
    MappingCapacity,
    TableCapacity,
    OutOfFrames,
    TableMemory(E),
    MappingAlreadyPresent,
    LargePageConflict,
    UnownedIntermediateTable,
    InvalidIntermediateEntry,
    FrameAlreadyOwned,
}

/// A failed map operation returns the caller's leaf-frame token.
#[derive(Debug, PartialEq, Eq)]
pub struct CandidateMapFailure<E> {
    pub cause: CandidateMapErrorKind<E>,
    pub frame: Frame,
    /// Newly allocated table frames retained by the candidate because allocator
    /// metadata could not accept their rollback. They remain owned and unlinked.
    pub rollback_retained_table_frames: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateUnmapError<E> {
    Active,
    Releasing,
    InvalidConfiguration,
    InvalidVirtualAddress,
    NotMapped,
    LargePageConflict,
    UnownedIntermediateTable,
    InvalidIntermediateEntry,
    OwnershipMismatch,
    TableMemory(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidatePermissionError<E> {
    Active,
    Releasing,
    NotCloned,
    InvalidAddress,
    WritableExecutable,
    NotPresent,
    PhysicalMismatch,
    OwnedLeafMapping,
    LargePageConflict,
    UnownedIntermediateTable,
    InvalidIntermediateEntry,
    TableCapacity,
    OutOfFrames,
    TableFrameOutOfRange,
    TableMemory(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateReleaseError {
    ActiveRoot,
    Frame(FrameError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidatePageTableReadError<E> {
    UnownedTable,
    InvalidIndex,
    TableMemory(E),
}

/// A bounded, allocator-owned page-table hierarchy.
///
/// It supports 4 KiB mappings of allocator-issued leaf frames. All table pages
/// and explicitly owned leaf frames remain represented by non-copyable `Frame`
/// tokens. An optional inherited-hierarchy clone preserves its pre-existing
/// leaf mappings without claiming ownership of those leaf frames. Mapping
/// allocates and prepares every missing table before writing a parent or leaf
/// entry; allocation/read/prepare failures therefore leave candidate
/// translations unchanged. Unmap removes an explicitly owned leaf and returns
/// its frame, but retains empty intermediate tables until `release`.
///
/// The caller may install a fully validated hierarchy as the active CR3 with
/// `mark_active`. Active candidates reject mutation and release so page-table
/// frames cannot be returned while a CPU may still use them. Dropping this
/// value without calling `release` intentionally leaks held frames from the
/// allocator's perspective; an active root must remain alive for its full CR3
/// lifetime. This type never writes CR3 or modifies the source hierarchy.
#[must_use = "release the owned frames or keep the candidate page tables alive"]
pub struct CandidatePageTables<'memory, M: CandidatePageTableMemory> {
    memory: &'memory mut M,
    config: PageWalkConfig,
    tables: [Option<CandidateTable<M::PreparedTable>>; MAX_CANDIDATE_PAGE_TABLE_PAGES],
    mappings: [Option<CandidateMapping>; MAX_CANDIDATE_MAPPINGS],
    table_count: usize,
    mapping_count: usize,
    releasing: bool,
    active: bool,
    clone_started: bool,
}

impl<'memory, M: CandidatePageTableMemory> CandidatePageTables<'memory, M> {
    /// Allocate and zero a separate root page; this does not modify CR3.
    pub fn new(
        allocator: &mut FrameAllocator,
        memory: &'memory mut M,
        config: PageWalkConfig,
    ) -> Result<Self, CandidateCreateError<M::Error>> {
        if !candidate_config_is_valid(config) {
            return Err(CandidateCreateError {
                cause: CandidateCreateErrorKind::InvalidConfiguration,
                frame: None,
            });
        }
        let frame = allocator.allocate().ok_or(CandidateCreateError {
            cause: CandidateCreateErrorKind::OutOfFrames,
            frame: None,
        })?;
        let frame_end = frame.address().checked_add(PAGE_SIZE);
        if !frame_end.is_some_and(|end| {
            physical_range_fits_address_width(frame.address(), end, config.physical_address_bits)
        }) {
            return Err(CandidateCreateError {
                cause: CandidateCreateErrorKind::RootFrameOutOfRange,
                frame: Some(frame),
            });
        }
        let prepared = match memory.prepare_table(&frame) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(CandidateCreateError {
                    cause: CandidateCreateErrorKind::TableMemory(error),
                    frame: Some(frame),
                });
            }
        };
        // SAFETY: `prepared` was returned by this backend for the root frame,
        // which remains owned by the candidate for the backend borrow's duration.
        unsafe { memory.clear_table(prepared) };

        let mut candidate = Self {
            memory,
            config,
            tables: core::array::from_fn(|_| None),
            mappings: core::array::from_fn(|_| None),
            table_count: 1,
            mapping_count: 0,
            releasing: false,
            active: false,
            clone_started: false,
        };
        candidate.tables[0] = Some(CandidateTable {
            frame,
            prepared: Some(prepared),
        });
        Ok(candidate)
    }

    /// Mark this hierarchy active after installing its root in CR3.
    ///
    /// # Safety
    /// The CPU must currently be using this candidate's root in CR3. Do not
    /// mark it inactive until every CPU has stopped using that root.
    pub unsafe fn mark_active(&mut self) {
        self.active = true;
    }

    /// Mark the hierarchy inactive after switching CR3 away from its root.
    ///
    /// # Safety
    /// No CPU may currently use this hierarchy's root in CR3, and no CPU may
    /// resume using it until it is marked active again.
    pub unsafe fn mark_inactive(&mut self) {
        self.active = false;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn root_physical_address(&self) -> Option<u64> {
        match &self.tables[0] {
            Some(root) => Some(root.frame.address()),
            None => None,
        }
    }

    /// Walk this hierarchy while restricting table reads to frames it owns.
    pub fn walk(
        &self,
        virtual_address: u64,
    ) -> Result<PageWalkOutcome, PageWalkError<CandidatePageTableReadError<M::Error>>> {
        let Some(root) = self.tables[0].as_ref() else {
            return Err(PageWalkError::InvalidRoot);
        };
        let reader = CandidatePageTableReader { candidate: self };
        walk_virtual_address(
            &reader,
            Cr3Root {
                physical_address: root.frame.address(),
                low_bits: Cr3LowBits::CacheControls {
                    page_level_write_through: false,
                    page_level_cache_disable: false,
                },
            },
            virtual_address,
            self.config,
        )
    }

    /// Change permissions on one cloned inherited 4 KiB mapping.
    ///
    /// Huge-page mappings are split into owned lower-level tables as needed;
    /// equivalent physical mappings and cache attributes are retained for all
    /// unaffected pages. The target address must not belong to an explicitly
    /// owned leaf mapping, and this operation is only available before CR3
    /// activation so no TLB invalidation is needed.
    pub fn set_inherited_page_permissions(
        &mut self,
        allocator: &mut FrameAllocator,
        virtual_address: u64,
        expected_physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), CandidatePermissionError<M::Error>> {
        if self.active {
            return Err(CandidatePermissionError::Active);
        }
        if self.releasing {
            return Err(CandidatePermissionError::Releasing);
        }
        if !self.clone_started {
            return Err(CandidatePermissionError::NotCloned);
        }
        let expected_end = expected_physical_address.checked_add(PAGE_SIZE);
        if virtual_address & (PAGE_SIZE - 1) != 0
            || !is_canonical_virtual_address(virtual_address, self.config.virtual_address_bits)
            || expected_physical_address & (PAGE_SIZE - 1) != 0
            || !expected_end.is_some_and(|end| {
                physical_range_fits_address_width(
                    expected_physical_address,
                    end,
                    self.config.physical_address_bits,
                )
            })
        {
            return Err(CandidatePermissionError::InvalidAddress);
        }
        if permissions.writable && permissions.executable {
            return Err(CandidatePermissionError::WritableExecutable);
        }
        if self
            .mappings
            .iter()
            .flatten()
            .any(|mapping| mapping.virtual_address == virtual_address)
        {
            return Err(CandidatePermissionError::OwnedLeafMapping);
        }

        let indexes = page_table_indexes(virtual_address, self.config.levels);
        let mut table_slot = 0;
        for depth in 0..usize::from(self.config.levels) {
            let level_number = self.config.levels - depth as u8;
            let Some(table) = self.tables[table_slot].as_ref() else {
                return Err(CandidatePermissionError::InvalidIntermediateEntry);
            };
            let Some(prepared) = table.prepared else {
                return Err(CandidatePermissionError::InvalidIntermediateEntry);
            };
            let entry = self
                .read_table_entry(prepared, indexes[depth])
                .map_err(CandidatePermissionError::TableMemory)?;
            if entry & PTE_PRESENT == 0 {
                return Err(CandidatePermissionError::NotPresent);
            }

            if depth + 1 == usize::from(self.config.levels) {
                if entry & PTE_ADDRESS_FIELD_MASK != expected_physical_address {
                    return Err(CandidatePermissionError::PhysicalMismatch);
                }
                let mut updated = entry;
                if permissions.writable {
                    updated |= PTE_WRITABLE;
                } else {
                    updated &= !PTE_WRITABLE;
                }
                if permissions.user_accessible {
                    updated |= PTE_USER;
                } else {
                    updated &= !PTE_USER;
                }
                if permissions.executable {
                    updated &= !PTE_NO_EXECUTE;
                } else {
                    updated |= PTE_NO_EXECUTE;
                }
                // SAFETY: This is a cloned candidate-owned table and the leaf
                // index was derived from the aligned canonical virtual address.
                unsafe { self.memory.write_entry(prepared, indexes[depth], updated) };
                return Ok(());
            }

            if entry & PTE_PAGE_SIZE != 0 {
                table_slot = self.split_inherited_large_entry(
                    allocator,
                    table_slot,
                    prepared,
                    indexes[depth],
                    entry,
                    level_number,
                )?;
                continue;
            }
            let child_address = entry & PTE_ADDRESS_FIELD_MASK;
            let child_slot = self
                .tables
                .iter()
                .position(|table| {
                    table
                        .as_ref()
                        .is_some_and(|table| table.frame.address() == child_address)
                })
                .ok_or(CandidatePermissionError::UnownedIntermediateTable)?;
            table_slot = child_slot;
        }
        Err(CandidatePermissionError::InvalidIntermediateEntry)
    }

    /// Split one inherited large page while preserving its translations and
    /// cache bits, then link an owned child table in its place.
    fn split_inherited_large_entry(
        &mut self,
        allocator: &mut FrameAllocator,
        parent_slot: usize,
        parent_prepared: M::PreparedTable,
        index: u16,
        entry: u64,
        level_number: u8,
    ) -> Result<usize, CandidatePermissionError<M::Error>> {
        let page_size = match level_number {
            3 if self.config.page_1g_supported => 1 << 30,
            2 if self.config.page_2m_supported => 1 << 21,
            _ => return Err(CandidatePermissionError::LargePageConflict),
        };
        let child_page_size = if level_number == 3 {
            1 << 21
        } else {
            PAGE_SIZE
        };
        let reserved_alignment_bits = (page_size - 1) & !0x1fff;
        let base = (entry & PTE_ADDRESS_FIELD_MASK) & !(page_size - 1);
        let end = base
            .checked_add(page_size)
            .ok_or(CandidatePermissionError::InvalidIntermediateEntry)?;
        if entry & reserved_alignment_bits != 0
            || !physical_range_fits_address_width(base, end, self.config.physical_address_bits)
        {
            return Err(CandidatePermissionError::InvalidIntermediateEntry);
        }
        let slot = self
            .tables
            .iter()
            .position(Option::is_none)
            .ok_or(CandidatePermissionError::TableCapacity)?;
        let frame = allocator
            .allocate()
            .ok_or(CandidatePermissionError::OutOfFrames)?;
        let frame_end = frame.address().checked_add(PAGE_SIZE);
        if !frame_end.is_some_and(|frame_end| {
            physical_range_fits_address_width(
                frame.address(),
                frame_end,
                self.config.physical_address_bits,
            )
        }) {
            self.tables[slot] = Some(CandidateTable {
                frame,
                prepared: None,
            });
            self.table_count += 1;
            return Err(CandidatePermissionError::TableFrameOutOfRange);
        }
        let prepared = match self.memory.prepare_table(&frame) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.tables[slot] = Some(CandidateTable {
                    frame,
                    prepared: None,
                });
                self.table_count += 1;
                return Err(CandidatePermissionError::TableMemory(error));
            }
        };
        // SAFETY: The handle was just prepared for this allocator-owned frame.
        unsafe { self.memory.clear_table(prepared) };

        let large_pat = entry & (1 << 12);
        let inherited_flags = entry & !(PTE_ADDRESS_FIELD_MASK | PTE_PAGE_SIZE | (1 << 12));
        for child_index in 0..512u16 {
            let child_address = base + u64::from(child_index) * child_page_size;
            let child_format_bits = if child_page_size == PAGE_SIZE {
                if large_pat != 0 {
                    PTE_PAT_4K
                } else {
                    0
                }
            } else {
                PTE_PAGE_SIZE | large_pat
            };
            self.write_candidate_entry(
                prepared,
                child_index,
                child_address | inherited_flags | child_format_bits,
            );
        }
        self.tables[slot] = Some(CandidateTable {
            frame,
            prepared: Some(prepared),
        });
        self.table_count += 1;
        let parent_entry = (entry & !(PTE_ADDRESS_FIELD_MASK | PTE_PAGE_SIZE))
            | self.tables[slot]
                .as_ref()
                .expect("new split table is retained")
                .frame
                .address();
        self.write_candidate_entry(parent_prepared, index, parent_entry);
        let _ = parent_slot;
        Ok(slot)
    }

    /// Copy every present entry from an inherited hierarchy into this separate
    /// candidate root. All present intermediate tables are cloned into owned
    /// frames; shared same-level source tables are cloned once, while aliases
    /// across paging levels are rejected. Leaf entries and non-present software
    /// entries are preserved verbatim. On error the candidate root is cleared
    /// and remains releasable.
    pub fn clone_inherited_hierarchy<R: PageTableReader>(
        &mut self,
        allocator: &mut FrameAllocator,
        reader: &R,
        source_root: Cr3Root,
    ) -> Result<(), CandidateCloneError<R::Error, M::Error>> {
        if self.active {
            return Err(CandidateCloneError::Active);
        }
        if self.releasing {
            return Err(CandidateCloneError::Releasing);
        }
        if self.clone_started || self.table_count != 1 || self.mapping_count != 0 {
            return Err(CandidateCloneError::AlreadyCloned);
        }
        if !candidate_config_is_valid(self.config) {
            return Err(CandidateCloneError::InvalidConfiguration);
        }
        let source_physical = source_root.physical_address();
        let source_end = source_physical.checked_add(PAGE_SIZE);
        if source_physical & (PAGE_SIZE - 1) != 0
            || !source_end.is_some_and(|end| {
                physical_range_fits_address_width(
                    source_physical,
                    end,
                    self.config.physical_address_bits,
                )
            })
        {
            return Err(CandidateCloneError::InvalidSourceRoot);
        }
        let Some(root_prepared) = self.tables[0].as_ref().and_then(|root| root.prepared) else {
            return Err(CandidateCloneError::InvalidConfiguration);
        };

        self.clone_started = true;
        let mut source_tables = [None; MAX_CANDIDATE_PAGE_TABLE_PAGES];
        source_tables[0] = Some((source_physical, 0, self.config.levels));
        let result = self.clone_inherited_table(
            allocator,
            reader,
            &mut source_tables,
            source_physical,
            0,
            self.config.levels,
        );
        if result.is_err() {
            // SAFETY: `root_prepared` is the retained handle for the candidate's
            // owned root frame. Clear it so no partial subtree remains reachable.
            unsafe { self.memory.clear_table(root_prepared) };
        }
        result
    }

    pub const fn table_count(&self) -> usize {
        self.table_count
    }

    pub const fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// Map one validated extent backed by an allocator-owned frame token.
    pub fn map_owned_page(
        &mut self,
        allocator: &mut FrameAllocator,
        frame: Frame,
        mapping: ValidatedMappingRange,
        cache_attributes: SelectedCacheAttributes,
    ) -> Result<(), CandidateMapFailure<M::Error>> {
        macro_rules! fail {
            ($cause:expr, $retained:expr) => {
                return Err(CandidateMapFailure {
                    cause: $cause,
                    frame,
                    rollback_retained_table_frames: $retained,
                })
            };
        }

        if self.active {
            fail!(CandidateMapErrorKind::Active, 0);
        }
        if self.releasing {
            fail!(CandidateMapErrorKind::Releasing, 0);
        }
        if !candidate_config_is_valid(self.config) {
            fail!(CandidateMapErrorKind::InvalidConfiguration, 0);
        }
        let frame_address = frame.address();
        let Some(frame_end) = frame_address.checked_add(PAGE_SIZE) else {
            fail!(CandidateMapErrorKind::InvalidMapping, 0);
        };
        if mapping.length() != PAGE_SIZE
            || mapping.virtual_start & (PAGE_SIZE - 1) != 0
            || mapping.physical_start != frame_address
            || mapping.physical_end != frame_end
            || mapping.physical_address_bits != self.config.physical_address_bits
        {
            fail!(CandidateMapErrorKind::InvalidMapping, 0);
        }
        let leaf_entry = match mapping.leaf_4k_entry_with_cache_attributes(
            0,
            cache_attributes,
            self.config.nx_enabled,
        ) {
            Ok(entry) => entry.bits(),
            Err(error) => fail!(CandidateMapErrorKind::Mapping(error), 0),
        };
        if self
            .mappings
            .iter()
            .flatten()
            .any(|item| item.virtual_address == mapping.virtual_start)
        {
            fail!(CandidateMapErrorKind::MappingAlreadyPresent, 0);
        }
        if self
            .mappings
            .iter()
            .flatten()
            .any(|item| item.frame.address() == frame_address)
            || self
                .tables
                .iter()
                .flatten()
                .any(|table| table.frame.address() == frame_address)
        {
            fail!(CandidateMapErrorKind::FrameAlreadyOwned, 0);
        }
        let Some(mapping_slot) = self.mappings.iter().position(Option::is_none) else {
            fail!(CandidateMapErrorKind::MappingCapacity, 0);
        };

        let indexes = page_table_indexes(mapping.virtual_start, self.config.levels);
        let mut current_table_slot = 0;
        let mut missing_depth = None;
        let mut leaf_table_slot = None;
        let mut existing_parents = [(0usize, 0u16, 0u64); 4];
        let mut existing_parent_count = 0;

        for depth in 0..usize::from(self.config.levels) {
            let level_number = usize::from(self.config.levels) - depth;
            let Some(table) = self.tables[current_table_slot].as_ref() else {
                fail!(CandidateMapErrorKind::InvalidIntermediateEntry, 0);
            };
            let Some(prepared) = table.prepared else {
                fail!(CandidateMapErrorKind::InvalidIntermediateEntry, 0);
            };
            let entry = match self.read_table_entry(prepared, indexes[depth]) {
                Ok(entry) => entry,
                Err(error) => fail!(CandidateMapErrorKind::TableMemory(error), 0),
            };
            if level_number == 1 {
                if entry & PTE_PRESENT != 0 {
                    fail!(CandidateMapErrorKind::MappingAlreadyPresent, 0);
                }
                leaf_table_slot = Some(current_table_slot);
                break;
            }
            if entry & PTE_PRESENT == 0 {
                missing_depth = Some(depth);
                break;
            }
            if entry & PTE_PAGE_SIZE != 0 {
                fail!(CandidateMapErrorKind::LargePageConflict, 0);
            }
            let allowed = PTE_ADDRESS_FIELD_MASK | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            let physical_mask =
                ((1u64 << self.config.physical_address_bits) - 1) & !(PAGE_SIZE - 1);
            let child_address = entry & PTE_ADDRESS_FIELD_MASK;
            if entry & !allowed != 0
                || entry & PTE_WRITABLE == 0
                || child_address & !physical_mask != 0
            {
                fail!(CandidateMapErrorKind::InvalidIntermediateEntry, 0);
            }
            let Some(child_slot) = self.tables.iter().position(|table| {
                table
                    .as_ref()
                    .is_some_and(|table| table.frame.address() == child_address)
            }) else {
                fail!(CandidateMapErrorKind::UnownedIntermediateTable, 0);
            };
            existing_parents[existing_parent_count] = (current_table_slot, indexes[depth], entry);
            existing_parent_count += 1;
            current_table_slot = child_slot;
        }

        let new_table_count =
            missing_depth.map_or(0, |depth| usize::from(self.config.levels) - depth - 1);
        let mut new_slots = [usize::MAX; 4];
        let mut available_slots = [usize::MAX; 4];
        let mut available_count = 0;
        for (slot, table) in self.tables.iter().enumerate() {
            if table.is_none() && available_count < available_slots.len() {
                available_slots[available_count] = slot;
                available_count += 1;
            }
        }
        if available_count < new_table_count {
            fail!(CandidateMapErrorKind::TableCapacity, 0);
        }

        for allocated in 0..new_table_count {
            let Some(new_frame) = allocator.allocate() else {
                let retained = self.rollback_new_tables(allocator, &new_slots, allocated);
                fail!(CandidateMapErrorKind::OutOfFrames, retained);
            };
            let slot = available_slots[allocated];
            let frame_end = new_frame.address().checked_add(PAGE_SIZE);
            if !frame_end.is_some_and(|end| {
                physical_range_fits_address_width(
                    new_frame.address(),
                    end,
                    self.config.physical_address_bits,
                )
            }) {
                self.tables[slot] = Some(CandidateTable {
                    frame: new_frame,
                    prepared: None,
                });
                self.table_count += 1;
                new_slots[allocated] = slot;
                let retained = self.rollback_new_tables(allocator, &new_slots, allocated + 1);
                fail!(CandidateMapErrorKind::TableFrameOutOfRange, retained);
            }
            match self.memory.prepare_table(&new_frame) {
                Ok(prepared) => {
                    // SAFETY: The handle was just prepared for `new_frame`, which
                    // remains owned by this candidate and has not been linked yet.
                    unsafe { self.memory.clear_table(prepared) };
                    self.tables[slot] = Some(CandidateTable {
                        frame: new_frame,
                        prepared: Some(prepared),
                    });
                    self.table_count += 1;
                    new_slots[allocated] = slot;
                }
                Err(error) => {
                    self.tables[slot] = Some(CandidateTable {
                        frame: new_frame,
                        prepared: None,
                    });
                    self.table_count += 1;
                    new_slots[allocated] = slot;
                    let retained = self.rollback_new_tables(allocator, &new_slots, allocated + 1);
                    fail!(CandidateMapErrorKind::TableMemory(error), retained);
                }
            }
        }

        if mapping.permissions.user_accessible {
            for (table_slot, index, entry) in
                existing_parents.iter().take(existing_parent_count).copied()
            {
                if entry & PTE_USER == 0 {
                    let table = self.tables[table_slot]
                        .as_ref()
                        .expect("validated candidate table slot");
                    let prepared = table.prepared.expect("prepared candidate table");
                    // SAFETY: This handle belongs to a table retained by the
                    // candidate; `index` came from its validated walk path.
                    unsafe { self.memory.write_entry(prepared, index, entry | PTE_USER) };
                }
            }
        }

        let leaf_table_slot = if let Some(depth) = missing_depth {
            let mut parent_slot = current_table_slot;
            for allocated in 0..new_table_count {
                let child_slot = new_slots[allocated];
                let parent = self.tables[parent_slot]
                    .as_ref()
                    .expect("candidate parent table exists");
                let prepared = parent.prepared.expect("candidate parent is prepared");
                let child_address = self.tables[child_slot]
                    .as_ref()
                    .expect("candidate child table exists")
                    .frame
                    .address();
                let mut entry = child_address | PTE_PRESENT | PTE_WRITABLE;
                if mapping.permissions.user_accessible {
                    entry |= PTE_USER;
                }
                // SAFETY: `prepared` belongs to the candidate's owned parent
                // table and the index is one of the computed 9-bit indexes.
                unsafe {
                    self.memory
                        .write_entry(prepared, indexes[depth + allocated], entry)
                };
                parent_slot = child_slot;
            }
            parent_slot
        } else {
            leaf_table_slot.expect("complete candidate path reaches a leaf table")
        };
        let leaf_table = self.tables[leaf_table_slot]
            .as_ref()
            .expect("candidate leaf table exists");
        let leaf_prepared = leaf_table
            .prepared
            .expect("candidate leaf table is prepared");
        // SAFETY: The handle belongs to the candidate-owned leaf table and the
        // index is the final computed 9-bit virtual-address index.
        unsafe {
            self.memory.write_entry(
                leaf_prepared,
                indexes[usize::from(self.config.levels) - 1],
                leaf_entry,
            )
        };
        self.mappings[mapping_slot] = Some(CandidateMapping {
            virtual_address: mapping.virtual_start,
            frame,
        });
        self.mapping_count += 1;
        Ok(())
    }

    /// Remove one inactive-candidate leaf mapping and return its owned frame.
    pub fn unmap_owned_page(
        &mut self,
        virtual_address: u64,
    ) -> Result<Frame, CandidateUnmapError<M::Error>> {
        if self.active {
            return Err(CandidateUnmapError::Active);
        }
        if self.releasing {
            return Err(CandidateUnmapError::Releasing);
        }
        if !candidate_config_is_valid(self.config) {
            return Err(CandidateUnmapError::InvalidConfiguration);
        }
        if virtual_address & (PAGE_SIZE - 1) != 0
            || !is_canonical_virtual_address(virtual_address, self.config.virtual_address_bits)
        {
            return Err(CandidateUnmapError::InvalidVirtualAddress);
        }
        let mapping_slot = self
            .mappings
            .iter()
            .position(|mapping| {
                mapping
                    .as_ref()
                    .is_some_and(|mapping| mapping.virtual_address == virtual_address)
            })
            .ok_or(CandidateUnmapError::NotMapped)?;

        let indexes = page_table_indexes(virtual_address, self.config.levels);
        let mut current_table_slot = 0;
        for depth in 0..usize::from(self.config.levels) {
            let level_number = usize::from(self.config.levels) - depth;
            let Some(table) = self.tables[current_table_slot].as_ref() else {
                return Err(CandidateUnmapError::InvalidIntermediateEntry);
            };
            let Some(prepared) = table.prepared else {
                return Err(CandidateUnmapError::InvalidIntermediateEntry);
            };
            let entry = self
                .read_table_entry(prepared, indexes[depth])
                .map_err(CandidateUnmapError::TableMemory)?;
            if entry & PTE_PRESENT == 0 {
                return Err(CandidateUnmapError::OwnershipMismatch);
            }
            if level_number == 1 {
                let mapping = self.mappings[mapping_slot]
                    .as_ref()
                    .expect("mapping slot validated");
                if entry & PTE_ADDRESS_FIELD_MASK != mapping.frame.address() {
                    return Err(CandidateUnmapError::OwnershipMismatch);
                }
                // SAFETY: `prepared` belongs to this candidate-owned table and
                // `indexes[depth]` was derived from the aligned virtual address.
                unsafe { self.memory.write_entry(prepared, indexes[depth], 0) };
                let mapping = self.mappings[mapping_slot]
                    .take()
                    .expect("mapping slot validated");
                self.mapping_count -= 1;
                return Ok(mapping.frame);
            }
            if entry & PTE_PAGE_SIZE != 0 {
                return Err(CandidateUnmapError::LargePageConflict);
            }
            let allowed = PTE_ADDRESS_FIELD_MASK | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            let physical_mask =
                ((1u64 << self.config.physical_address_bits) - 1) & !(PAGE_SIZE - 1);
            let child_address = entry & PTE_ADDRESS_FIELD_MASK;
            if entry & !allowed != 0
                || entry & PTE_WRITABLE == 0
                || child_address & !physical_mask != 0
            {
                return Err(CandidateUnmapError::InvalidIntermediateEntry);
            }
            let Some(child_slot) = self.tables.iter().position(|table| {
                table
                    .as_ref()
                    .is_some_and(|table| table.frame.address() == child_address)
            }) else {
                return Err(CandidateUnmapError::UnownedIntermediateTable);
            };
            current_table_slot = child_slot;
        }
        Err(CandidateUnmapError::InvalidConfiguration)
    }

    /// Return all held frames to the allocator. Active roots are never released.
    /// On frame-release failure, returns the still-owned candidate so the caller
    /// can retry; it is permanently unavailable for mapping once release begins.
    pub fn release(
        mut self,
        allocator: &mut FrameAllocator,
    ) -> Result<(), CandidateReleaseFailure<'memory, M>> {
        if self.active {
            return Err(CandidateReleaseFailure {
                error: CandidateReleaseError::ActiveRoot,
                candidate: self,
            });
        }
        self.releasing = true;
        for slot in (0..self.tables.len()).rev() {
            let Some(table) = self.tables[slot].take() else {
                continue;
            };
            let CandidateTable { frame, prepared } = table;
            if let Err(error) = allocator.deallocate(frame) {
                self.tables[slot] = Some(CandidateTable {
                    frame: error.frame,
                    prepared,
                });
                return Err(CandidateReleaseFailure {
                    error: CandidateReleaseError::Frame(error.error),
                    candidate: self,
                });
            }
            self.table_count -= 1;
        }
        for slot in (0..self.mappings.len()).rev() {
            let Some(mapping) = self.mappings[slot].take() else {
                continue;
            };
            if let Err(error) = allocator.deallocate(mapping.frame) {
                self.mappings[slot] = Some(CandidateMapping {
                    virtual_address: mapping.virtual_address,
                    frame: error.frame,
                });
                return Err(CandidateReleaseFailure {
                    error: CandidateReleaseError::Frame(error.error),
                    candidate: self,
                });
            }
            self.mapping_count -= 1;
        }
        Ok(())
    }

    fn clone_inherited_table<R: PageTableReader>(
        &mut self,
        allocator: &mut FrameAllocator,
        reader: &R,
        source_tables: &mut [Option<(u64, usize, u8)>; MAX_CANDIDATE_PAGE_TABLE_PAGES],
        source_physical: u64,
        destination_slot: usize,
        level: u8,
    ) -> Result<(), CandidateCloneError<R::Error, M::Error>> {
        let destination_prepared = self.tables[destination_slot]
            .as_ref()
            .and_then(|table| table.prepared)
            .ok_or(CandidateCloneError::InvalidConfiguration)?;
        let physical_mask = ((1u64 << self.config.physical_address_bits) - 1) & !(PAGE_SIZE - 1);

        for index in 0..512u16 {
            let entry = reader
                .read_entry(source_physical, index)
                .map_err(CandidateCloneError::SourceRead)?;
            if entry & PTE_PRESENT == 0 {
                self.write_candidate_entry(destination_prepared, index, entry);
                continue;
            }
            let address_field = entry & PTE_ADDRESS_FIELD_MASK;
            if address_field & !physical_mask != 0
                || entry & PTE_NO_EXECUTE != 0 && !self.config.nx_enabled
            {
                return Err(CandidateCloneError::InvalidEntry { level, index });
            }

            if level == 1 {
                let leaf_end = address_field
                    .checked_add(PAGE_SIZE)
                    .ok_or(CandidateCloneError::InvalidEntry { level, index })?;
                if !physical_range_fits_address_width(
                    address_field,
                    leaf_end,
                    self.config.physical_address_bits,
                ) {
                    return Err(CandidateCloneError::InvalidEntry { level, index });
                }
                self.write_candidate_entry(destination_prepared, index, entry);
                continue;
            }

            if entry & PTE_PAGE_SIZE != 0 {
                let page_size = match level {
                    2 if self.config.page_2m_supported => 1 << 21,
                    3 if self.config.page_1g_supported => 1 << 30,
                    _ => return Err(CandidateCloneError::InvalidEntry { level, index }),
                };
                let reserved_alignment_bits = (page_size - 1) & !0x1fff;
                let base = address_field & !(page_size - 1);
                let Some(end) = base.checked_add(page_size) else {
                    return Err(CandidateCloneError::InvalidEntry { level, index });
                };
                if entry & reserved_alignment_bits != 0
                    || !physical_range_fits_address_width(
                        base,
                        end,
                        self.config.physical_address_bits,
                    )
                {
                    return Err(CandidateCloneError::InvalidEntry { level, index });
                }
                self.write_candidate_entry(destination_prepared, index, entry);
                continue;
            }

            let child_end = address_field
                .checked_add(PAGE_SIZE)
                .ok_or(CandidateCloneError::InvalidEntry { level, index })?;
            if !physical_range_fits_address_width(
                address_field,
                child_end,
                self.config.physical_address_bits,
            ) {
                return Err(CandidateCloneError::InvalidEntry { level, index });
            }
            let child_level = level - 1;
            let child_slot = if let Some((_, slot, existing_level)) = source_tables
                .iter()
                .flatten()
                .find(|(physical, _, _)| *physical == address_field)
            {
                if *existing_level != child_level {
                    return Err(CandidateCloneError::InvalidEntry { level, index });
                }
                *slot
            } else {
                let slot = self
                    .tables
                    .iter()
                    .position(Option::is_none)
                    .ok_or(CandidateCloneError::TableCapacity)?;
                let frame = allocator
                    .allocate()
                    .ok_or(CandidateCloneError::OutOfFrames)?;
                let frame_end = frame.address().checked_add(PAGE_SIZE);
                if !frame_end.is_some_and(|end| {
                    physical_range_fits_address_width(
                        frame.address(),
                        end,
                        self.config.physical_address_bits,
                    )
                }) {
                    self.tables[slot] = Some(CandidateTable {
                        frame,
                        prepared: None,
                    });
                    self.table_count += 1;
                    return Err(CandidateCloneError::TableFrameOutOfRange);
                }
                let prepared = match self.memory.prepare_table(&frame) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        self.tables[slot] = Some(CandidateTable {
                            frame,
                            prepared: None,
                        });
                        self.table_count += 1;
                        return Err(CandidateCloneError::TableMemory(error));
                    }
                };
                // SAFETY: The handle was just prepared for this allocator-owned
                // frame, which remains retained by the candidate.
                unsafe { self.memory.clear_table(prepared) };
                self.tables[slot] = Some(CandidateTable {
                    frame,
                    prepared: Some(prepared),
                });
                self.table_count += 1;
                source_tables[slot] = Some((address_field, slot, child_level));
                self.clone_inherited_table(
                    allocator,
                    reader,
                    source_tables,
                    address_field,
                    slot,
                    level - 1,
                )?;
                slot
            };
            let child_address = self.tables[child_slot]
                .as_ref()
                .ok_or(CandidateCloneError::InvalidConfiguration)?
                .frame
                .address();
            self.write_candidate_entry(
                destination_prepared,
                index,
                (entry & !PTE_ADDRESS_FIELD_MASK) | child_address,
            );
        }
        Ok(())
    }

    fn write_candidate_entry(&mut self, prepared: M::PreparedTable, index: u16, value: u64) {
        debug_assert!(index < 512);
        // SAFETY: All handles passed here are retained candidate tables, and
        // every index is generated by the bounded 0..512 clone loop or a
        // validated virtual-address walk.
        unsafe { self.memory.write_entry(prepared, index, value) };
    }

    fn read_table_entry(&self, prepared: M::PreparedTable, index: u16) -> Result<u64, M::Error> {
        debug_assert!(index < 512);
        // SAFETY: `prepared` is copied only from a table retained by this
        // candidate, and the index is either computed from a validated address
        // or checked by the page-table reader before this helper is called.
        unsafe { self.memory.read_entry(prepared, index) }
    }

    fn rollback_new_tables(
        &mut self,
        allocator: &mut FrameAllocator,
        slots: &[usize; 4],
        count: usize,
    ) -> usize {
        let mut retained = 0;
        for slot in slots[..count].iter().rev().copied() {
            let Some(table) = self.tables[slot].take() else {
                continue;
            };
            let CandidateTable { frame, prepared } = table;
            if let Err(error) = allocator.deallocate(frame) {
                self.tables[slot] = Some(CandidateTable {
                    frame: error.frame,
                    prepared,
                });
                retained += 1;
            } else {
                self.table_count -= 1;
            }
        }
        retained
    }
}

struct CandidatePageTableReader<'candidate, 'memory, M: CandidatePageTableMemory> {
    candidate: &'candidate CandidatePageTables<'memory, M>,
}

impl<M: CandidatePageTableMemory> PageTableReader for CandidatePageTableReader<'_, '_, M> {
    type Error = CandidatePageTableReadError<M::Error>;

    fn read_entry(&self, table_physical: u64, index: u16) -> Result<u64, Self::Error> {
        if index >= 512 {
            return Err(CandidatePageTableReadError::InvalidIndex);
        }
        let prepared = self
            .candidate
            .tables
            .iter()
            .flatten()
            .find(|table| table.frame.address() == table_physical)
            .and_then(|table| table.prepared)
            .ok_or(CandidatePageTableReadError::UnownedTable)?;
        self.candidate
            .read_table_entry(prepared, index)
            .map_err(CandidatePageTableReadError::TableMemory)
    }
}

/// Failure to return a page-table or mapped frame; `candidate` retains it.
pub struct CandidateReleaseFailure<'memory, M: CandidatePageTableMemory> {
    pub error: CandidateReleaseError,
    pub candidate: CandidatePageTables<'memory, M>,
}

impl<M: CandidatePageTableMemory> core::fmt::Debug for CandidateReleaseFailure<'_, M> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CandidateReleaseFailure")
            .field("error", &self.error)
            .field("table_count", &self.candidate.table_count)
            .field("mapping_count", &self.candidate.mapping_count)
            .finish()
    }
}

fn candidate_config_is_valid(config: PageWalkConfig) -> bool {
    (config.levels == 4 || config.levels == 5)
        && config.virtual_address_bits == if config.levels == 4 { 48 } else { 57 }
        && (12..=MAX_PTE_PHYSICAL_ADDRESS_BITS).contains(&config.physical_address_bits)
        && config.nx_enabled
}

fn page_table_indexes(virtual_address: u64, levels: u8) -> [u16; 5] {
    let mut indexes = [0; 5];
    for (depth, index) in indexes.iter_mut().take(usize::from(levels)).enumerate() {
        let level_number = usize::from(levels) - depth;
        let shift = 12 + 9 * (level_number - 1);
        *index = ((virtual_address >> shift) & 0x1ff) as u16;
    }
    indexes
}

#[cfg(test)]
mod tests {
    use super::{
        capture_mtrr_registers, encode_cr3_value, inherited_cr3_root_hhdm_address, parse_cr3_root,
        validate_mapping_range, CachePolicy, CandidateCloneError, CandidateCreateErrorKind,
        CandidateMapErrorKind, CandidatePageTableMemory, CandidatePageTableReadError,
        CandidatePageTables, CandidateReleaseError, CandidateUnmapError, Cr3Error, Cr3LowBits,
        Cr3RootAccessError, EffectiveMemoryType, EffectiveMemoryTypeError, FixedMtrrRanges,
        MappingError, MtrrError, MtrrLayout, MtrrMemoryType, MtrrRegisterPair, MtrrRegisters,
        MtrrState, PageLevel, PagePermissions, PageTableEntryError, PageTableReader,
        PageTranslation, PageWalkConfig, PageWalkError, PageWalkOutcome, PatLayout,
        ValidatedMappingRange, VariableMtrr, MAX_CANDIDATE_PAGE_TABLE_PAGES,
        MAX_CAPTURED_VARIABLE_MTRRS, PAGE_SIZE,
    };
    use core::cell::Cell;

    use crate::frame::{Frame, FrameAllocator, FrameError};
    use crate::memory::{HhdmAddressError, MemoryMap, RawMemoryRegion};

    #[derive(Clone, Copy)]
    struct SyntheticEntry {
        table: u64,
        index: u16,
        value: u64,
    }

    impl SyntheticEntry {
        const EMPTY: Self = Self {
            table: 0,
            index: 0,
            value: 0,
        };
    }

    struct SyntheticReader {
        entries: [SyntheticEntry; 16],
        count: usize,
    }

    impl SyntheticReader {
        fn new() -> Self {
            Self {
                entries: [SyntheticEntry::EMPTY; 16],
                count: 0,
            }
        }

        fn set(&mut self, table: u64, index: u16, value: u64) {
            self.entries[self.count] = SyntheticEntry {
                table,
                index,
                value,
            };
            self.count += 1;
        }
    }

    impl PageTableReader for SyntheticReader {
        type Error = ();

        fn read_entry(&self, table_physical: u64, index: u16) -> Result<u64, Self::Error> {
            Ok(self.entries[..self.count]
                .iter()
                .find(|entry| entry.table == table_physical && entry.index == index)
                .map_or(0, |entry| entry.value))
        }
    }

    #[derive(Clone, Copy)]
    struct CandidateTestPage {
        physical: u64,
        entries: [u64; 512],
    }

    impl CandidateTestPage {
        const EMPTY: Self = Self {
            physical: 0,
            entries: [0; 512],
        };
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CandidateTestMemoryError {
        MissingPage,
        Capacity,
        InjectedPrepareFailure,
    }

    struct CandidateTestMemory {
        pages: [CandidateTestPage; MAX_CANDIDATE_PAGE_TABLE_PAGES],
        page_count: usize,
        prepare_count: usize,
        fail_prepare_at: Option<usize>,
        foreign_child: Option<(u16, u64)>,
    }

    impl CandidateTestMemory {
        fn new() -> Self {
            Self {
                pages: [CandidateTestPage::EMPTY; MAX_CANDIDATE_PAGE_TABLE_PAGES],
                page_count: 0,
                prepare_count: 0,
                fail_prepare_at: None,
                foreign_child: None,
            }
        }

        fn page(&self, physical: u64) -> Result<&CandidateTestPage, CandidateTestMemoryError> {
            self.pages[..self.page_count]
                .iter()
                .find(|page| page.physical == physical)
                .ok_or(CandidateTestMemoryError::MissingPage)
        }

        fn page_mut(
            &mut self,
            physical: u64,
        ) -> Result<&mut CandidateTestPage, CandidateTestMemoryError> {
            self.pages[..self.page_count]
                .iter_mut()
                .find(|page| page.physical == physical)
                .ok_or(CandidateTestMemoryError::MissingPage)
        }
    }

    // SAFETY: Prepared handles are the exact physical-frame keys stored in this
    // bounded in-memory test backend, and every unsafe operation validates the
    // key and the requested entry index before accessing its backing array.
    unsafe impl CandidatePageTableMemory for CandidateTestMemory {
        type PreparedTable = u64;
        type Error = CandidateTestMemoryError;

        fn prepare_table(&mut self, frame: &Frame) -> Result<Self::PreparedTable, Self::Error> {
            self.prepare_count += 1;
            if self.fail_prepare_at == Some(self.prepare_count) {
                return Err(CandidateTestMemoryError::InjectedPrepareFailure);
            }
            if self.pages[..self.page_count]
                .iter()
                .any(|page| page.physical == frame.address())
            {
                return Ok(frame.address());
            }
            if self.page_count == self.pages.len() {
                return Err(CandidateTestMemoryError::Capacity);
            }
            self.pages[self.page_count] = CandidateTestPage {
                physical: frame.address(),
                entries: [0; 512],
            };
            self.page_count += 1;
            Ok(frame.address())
        }

        unsafe fn read_entry(
            &self,
            table: Self::PreparedTable,
            index: u16,
        ) -> Result<u64, Self::Error> {
            if self.page_count > 0 && self.pages[0].physical == table {
                if let Some((foreign_index, foreign_address)) = self.foreign_child {
                    if foreign_index == index {
                        return Ok(foreign_address | 0x3);
                    }
                }
            }
            self.page(table)?
                .entries
                .get(usize::from(index))
                .copied()
                .ok_or(CandidateTestMemoryError::MissingPage)
        }

        unsafe fn clear_table(&mut self, table: Self::PreparedTable) {
            self.page_mut(table)
                .expect("prepared test table exists")
                .entries = [0; 512];
        }

        unsafe fn write_entry(&mut self, table: Self::PreparedTable, index: u16, value: u64) {
            *self
                .page_mut(table)
                .expect("prepared test table exists")
                .entries
                .get_mut(usize::from(index))
                .expect("candidate checked the test table index") = value;
        }
    }

    fn candidate_allocator(frame_count: usize) -> FrameAllocator {
        let map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: 0x10_0000,
            length: PAGE_SIZE * frame_count as u64,
            kind: 0,
        }])
        .unwrap();
        FrameAllocator::from_memory_map(&map).unwrap()
    }

    fn candidate_mapping(
        frame: &Frame,
        virtual_address: u64,
        permissions: PagePermissions,
    ) -> (ValidatedMappingRange, super::SelectedCacheAttributes) {
        let virtual_address_bits = if super::is_canonical_virtual_address(virtual_address, 48) {
            48
        } else {
            57
        };
        let mapping = validate_mapping_range(
            virtual_address,
            frame.address(),
            PAGE_SIZE,
            permissions,
            Some(40),
            virtual_address_bits,
        )
        .unwrap();
        let pat = PatLayout::from_msr_value(0x0606_0606_0606_0606).unwrap();
        let mtrrs = empty_mtrr_registers(0, (1 << 11) | MtrrMemoryType::WriteBack as u64)
            .validated_layout(40)
            .unwrap();
        let attributes = mapping
            .select_cache_attributes(CachePolicy::WriteBack, pat, &mtrrs, true)
            .unwrap();
        (mapping, attributes)
    }

    fn four_level_walk_config() -> PageWalkConfig {
        PageWalkConfig {
            levels: 4,
            physical_address_bits: 40,
            virtual_address_bits: 48,
            nx_enabled: true,
            page_2m_supported: true,
            page_1g_supported: true,
        }
    }

    const KERNEL_READ_ONLY: PagePermissions = PagePermissions {
        writable: false,
        executable: false,
        user_accessible: false,
    };

    fn variable_mtrr(base: u64, size: u64, memory_type: MtrrMemoryType) -> VariableMtrr {
        let physical_address_bits = 36;
        let physical_mask = ((1u64 << physical_address_bits) - 1) & !(PAGE_SIZE - 1);
        let mask = physical_mask & !(size - 1) | (1 << 11);
        VariableMtrr::from_msr_values(base | memory_type as u8 as u64, mask, physical_address_bits)
            .unwrap()
            .unwrap()
    }

    fn empty_mtrr_registers(capability: u64, default_type: u64) -> MtrrRegisters {
        MtrrRegisters {
            capability,
            default_type,
            fixed_registers: if capability & (1 << 8) != 0 {
                Some([MtrrMemoryType::WriteBack as u64 * 0x0101_0101_0101_0101; 11])
            } else {
                None
            },
            variable_register_count: (capability & 0xff) as u8,
            variable_registers: [MtrrRegisterPair { base: 0, mask: 0 };
                MAX_CAPTURED_VARIABLE_MTRRS],
        }
    }

    #[test]
    fn mtrr_capture_is_gated_by_support() {
        let state = capture_mtrr_registers(false, |_| panic!("read MSR without MTRR support"));
        assert_eq!(state, MtrrState::Unsupported);
    }

    #[test]
    fn captures_supported_fixed_and_variable_mtrr_registers() {
        let reads = Cell::new(0);
        let state = capture_mtrr_registers(true, |index| {
            reads.set(reads.get() + 1);
            match index {
                0xfe => 2 | (1 << 8),
                0x2ff => 0xc06,
                _ => u64::from(index),
            }
        });

        let MtrrState::Captured(registers) = state else {
            panic!("expected a complete MTRR snapshot");
        };
        assert_eq!(reads.get(), 2 + 11 + 4);
        assert_eq!(registers.capability, 2 | (1 << 8));
        assert_eq!(registers.default_type, 0xc06);
        assert_eq!(registers.variable_register_count, 2);
        let fixed = registers
            .fixed_registers
            .expect("fixed ranges are supported");
        assert_eq!(fixed[0], 0x250);
        assert_eq!(fixed[10], 0x26f);
        assert_eq!(registers.variable_registers[0].base, 0x200);
        assert_eq!(registers.variable_registers[0].mask, 0x201);
        assert_eq!(registers.variable_registers[1].base, 0x202);
        assert_eq!(registers.variable_registers[1].mask, 0x203);
        assert_eq!(
            registers.variable_registers[2],
            MtrrRegisterPair { base: 0, mask: 0 }
        );
    }

    #[test]
    fn mtrr_capture_reports_capacity_excess_without_partial_reads() {
        let reads = Cell::new(0);
        let state = capture_mtrr_registers(true, |index| {
            reads.set(reads.get() + 1);
            if index == 0xfe {
                (MAX_CAPTURED_VARIABLE_MTRRS as u64) + 1
            } else {
                0
            }
        });

        assert_eq!(
            state,
            MtrrState::VariableRangeCapacityExceeded {
                reported_count: (MAX_CAPTURED_VARIABLE_MTRRS + 1) as u8,
            }
        );
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn mtrr_capture_skips_unsupported_fixed_registers() {
        let reads = Cell::new(0);
        let state = capture_mtrr_registers(true, |index| {
            reads.set(reads.get() + 1);
            match index {
                0xfe => 1,
                0x2ff => 0xc06,
                _ => u64::from(index),
            }
        });

        let MtrrState::Captured(registers) = state else {
            panic!("expected a complete MTRR snapshot");
        };
        assert_eq!(reads.get(), 4);
        assert_eq!(registers.fixed_registers, None);
        assert_eq!(registers.variable_register_count, 1);
        assert_eq!(registers.variable_registers[0].base, 0x200);
        assert_eq!(registers.variable_registers[0].mask, 0x201);
    }

    #[test]
    fn decodes_cr3_root_with_pcid_enabled() {
        let root = parse_cr3_root(0x1234_5000 | 0x0abc, Some(48), true).unwrap();
        assert_eq!(root.physical_address(), 0x1234_5000);
        assert_eq!(root.low_bits(), Cr3LowBits::Pcid(0x0abc));
    }

    #[test]
    fn walks_four_level_tables_and_folds_permissions_and_pat_bits() {
        let root = parse_cr3_root(0x1000, Some(40), false).unwrap();
        let address = 0xffff_8000_0000_1234;
        let mut reader = SyntheticReader::new();
        reader.set(0x1000, 256, 0x2000 | 0b111);
        reader.set(0x2000, 0, 0x3000 | 0b111);
        reader.set(0x3000, 0, 0x4000 | 0b001);
        reader.set(0x4000, 1, 0x8000 | 0b111 | (1 << 3) | (1 << 7));

        let result =
            super::walk_virtual_address(&reader, root, address, four_level_walk_config()).unwrap();
        assert_eq!(
            result,
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: 0x8234,
                leaf_physical_base: 0x8000,
                page_size: PAGE_SIZE,
                permissions: PagePermissions {
                    writable: false,
                    executable: true,
                    user_accessible: false,
                },
                pat_index: 5,
                raw_leaf_entry: 0x8000 | 0b111 | (1 << 3) | (1 << 7),
            })
        );
    }

    #[test]
    fn walks_five_levels_and_2mib_leaf_pages() {
        let root = parse_cr3_root(0x1000, Some(40), false).unwrap();
        let address = 0xff00_0000_0020_1234;
        let mut reader = SyntheticReader::new();
        reader.set(0x1000, 256, 0x2000 | 0b11);
        reader.set(0x2000, 0, 0x3000 | 0b11);
        reader.set(0x3000, 0, 0x4000 | 0b11);
        reader.set(0x4000, 1, 0x400000 | 0x83 | (1 << 12));
        let config = PageWalkConfig {
            levels: 5,
            virtual_address_bits: 57,
            ..four_level_walk_config()
        };

        assert_eq!(
            super::walk_virtual_address(&reader, root, address, config).unwrap(),
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: 0x401234,
                leaf_physical_base: 0x400000,
                page_size: 1 << 21,
                permissions: PagePermissions {
                    writable: true,
                    executable: true,
                    user_accessible: false,
                },
                pat_index: 4,
                raw_leaf_entry: 0x400000 | 0x83 | (1 << 12),
            })
        );
    }

    #[test]
    fn walks_a_one_gibibyte_leaf_and_extracts_large_page_pat() {
        let root = parse_cr3_root(0x1000, Some(40), false).unwrap();
        let address = 0xffff_8000_4000_1234;
        let mut reader = SyntheticReader::new();
        reader.set(0x1000, 256, 0x2000 | 0b11);
        reader.set(0x2000, 1, 0x8000_0000 | 0x83 | (1 << 12));

        assert_eq!(
            super::walk_virtual_address(&reader, root, address, four_level_walk_config()).unwrap(),
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: 0x8000_1234,
                leaf_physical_base: 0x8000_0000,
                page_size: 1 << 30,
                permissions: PagePermissions {
                    writable: true,
                    executable: true,
                    user_accessible: false,
                },
                pat_index: 4,
                raw_leaf_entry: 0x8000_0000 | 0x83 | (1 << 12),
            })
        );

        assert_eq!(
            super::walk_virtual_address(
                &reader,
                root,
                address,
                PageWalkConfig {
                    page_1g_supported: false,
                    ..four_level_walk_config()
                },
            ),
            Err(PageWalkError::InvalidEntry {
                level: PageLevel::Pdpt,
                error: PageTableEntryError::LargePageUnsupported,
            })
        );
    }

    #[test]
    fn rejects_invalid_page_walk_inputs_and_leaf_encodings() {
        let root = parse_cr3_root(0x1000, Some(40), false).unwrap();
        let mut reader = SyntheticReader::new();
        assert_eq!(
            super::walk_virtual_address(
                &reader,
                root,
                0x0000_8000_0000_0000,
                four_level_walk_config(),
            ),
            Err(PageWalkError::NonCanonicalAddress)
        );
        assert_eq!(
            super::walk_virtual_address(
                &reader,
                root,
                0xffff_8000_0000_0000,
                PageWalkConfig {
                    levels: 4,
                    physical_address_bits: 40,
                    virtual_address_bits: 57,
                    ..four_level_walk_config()
                },
            ),
            Err(PageWalkError::InvalidConfiguration)
        );
        reader.set(0x1000, 256, 0x2000 | 0b11 | (1 << 63));
        assert_eq!(
            super::walk_virtual_address(
                &reader,
                root,
                0xffff_8000_0000_0000,
                PageWalkConfig {
                    nx_enabled: false,
                    ..four_level_walk_config()
                }
            ),
            Err(PageWalkError::InvalidEntry {
                level: PageLevel::Pml4,
                error: PageTableEntryError::NxDisabled,
            })
        );
    }

    #[test]
    fn reports_missing_page_table_entries_without_following_them() {
        let root = parse_cr3_root(0x1000, Some(40), false).unwrap();
        let reader = SyntheticReader::new();
        assert_eq!(
            super::walk_virtual_address(
                &reader,
                root,
                0xffff_8000_0000_0000,
                four_level_walk_config(),
            )
            .unwrap(),
            PageWalkOutcome::NotPresent {
                level: PageLevel::Pml4,
            }
        );
    }

    #[test]
    fn validates_inherited_root_hhdm_location_before_any_dereference() {
        let offset = 0xffff_8000_0000_0000;
        let root = parse_cr3_root(0x20_0000, Some(40), false).unwrap();
        let bootloader_map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: 0x20_0000,
            length: PAGE_SIZE,
            kind: 5,
        }])
        .unwrap();

        assert_eq!(
            inherited_cr3_root_hhdm_address(root, &bootloader_map, offset, Some(40), 48),
            Ok(offset + 0x20_0000)
        );
        assert_eq!(
            inherited_cr3_root_hhdm_address(root, &bootloader_map, offset, None, 48),
            Err(Cr3RootAccessError::Hhdm(
                HhdmAddressError::UnknownPhysicalAddressWidth
            ))
        );

        let usable_map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: 0x20_0000,
            length: PAGE_SIZE,
            kind: 0,
        }])
        .unwrap();
        assert_eq!(
            inherited_cr3_root_hhdm_address(root, &usable_map, offset, Some(40), 48),
            Err(Cr3RootAccessError::NotBootloaderReclaimable)
        );
    }

    #[test]
    fn encodes_cr3_values_preserving_low_bit_mode_and_flushing_pcid() {
        assert_eq!(
            encode_cr3_value(
                0x12_3000,
                super::Cr3LowBits::CacheControls {
                    page_level_write_through: true,
                    page_level_cache_disable: true,
                },
                40,
            ),
            Ok(0x12_3018),
        );
        assert_eq!(
            encode_cr3_value(0x12_3000, super::Cr3LowBits::Pcid(0x123), 40),
            Ok(0x12_3123),
        );
        assert_eq!(
            encode_cr3_value(0x12_3001, super::Cr3LowBits::Pcid(0), 40),
            Err(Cr3Error::InvalidRootAddress),
        );
        assert_eq!(
            encode_cr3_value(1 << 40, super::Cr3LowBits::Pcid(0), 40),
            Err(Cr3Error::InvalidRootAddress),
        );
        assert_eq!(
            encode_cr3_value(0x12_3000, super::Cr3LowBits::Pcid(0x1000), 40),
            Err(Cr3Error::ReservedBits),
        );
    }

    #[test]
    fn decodes_cr3_cache_controls_without_pcid() {
        let root = parse_cr3_root(0x1234_5000 | (1 << 3) | (1 << 4), Some(48), false).unwrap();
        assert_eq!(root.physical_address(), 0x1234_5000);
        assert_eq!(
            root.low_bits(),
            Cr3LowBits::CacheControls {
                page_level_write_through: true,
                page_level_cache_disable: true,
            }
        );
    }

    #[test]
    fn rejects_cr3_reserved_bits_and_invalid_address_widths() {
        assert_eq!(
            parse_cr3_root(0x1000 | 1, Some(48), false),
            Err(Cr3Error::ReservedBits)
        );
        assert_eq!(
            parse_cr3_root(1 << 40, Some(40), true),
            Err(Cr3Error::ReservedBits)
        );
        assert_eq!(
            parse_cr3_root(0x1000, None, false),
            Err(Cr3Error::UnknownPhysicalAddressWidth)
        );
        assert_eq!(
            parse_cr3_root(0x1000, Some(53), false),
            Err(Cr3Error::InvalidPhysicalAddressWidth)
        );
    }

    #[test]
    fn resolves_variable_mtrr_ranges_and_default_type() {
        let ranges = [variable_mtrr(
            0x20_0000,
            0x20_0000,
            MtrrMemoryType::WriteBack,
        )];
        let layout =
            MtrrLayout::new(36, true, false, MtrrMemoryType::Uncacheable, None, &ranges).unwrap();

        assert_eq!(
            layout.memory_type_for(0x20_0000),
            Ok(MtrrMemoryType::WriteBack)
        );
        assert_eq!(
            layout.memory_type_for(0x3f_ffff),
            Ok(MtrrMemoryType::WriteBack)
        );
        assert_eq!(
            layout.memory_type_for(0x40_0000),
            Ok(MtrrMemoryType::Uncacheable)
        );
        assert_eq!(
            layout.memory_type_for(1u64 << 36),
            Err(MtrrError::PhysicalAddressOutOfRange)
        );
    }

    #[test]
    fn fixed_mtrrs_override_variable_and_default_ranges_below_one_mib() {
        let mut registers = [0; 11];
        registers[2] = MtrrMemoryType::WriteThrough as u64;
        let fixed = FixedMtrrRanges::from_msr_values(registers).unwrap();
        let variable = [variable_mtrr(0, 0x10_0000, MtrrMemoryType::WriteBack)];
        let layout = MtrrLayout::new(
            36,
            true,
            true,
            MtrrMemoryType::WriteBack,
            Some(&fixed),
            &variable,
        )
        .unwrap();

        assert_eq!(
            layout.memory_type_for(0xa_0000),
            Ok(MtrrMemoryType::WriteThrough)
        );
        assert_eq!(
            layout.memory_type_for(0xa_4000),
            Ok(MtrrMemoryType::Uncacheable)
        );
        assert_eq!(
            layout.memory_type_for(0x10_0000),
            Ok(MtrrMemoryType::WriteBack)
        );
    }

    #[test]
    fn resolves_defined_variable_mtrr_overlaps_and_rejects_undefined_ones() {
        let write_back_through = [
            variable_mtrr(0x20_0000, 0x20_0000, MtrrMemoryType::WriteBack),
            variable_mtrr(0x20_0000, 0x20_0000, MtrrMemoryType::WriteThrough),
        ];
        let layout = MtrrLayout::new(
            36,
            true,
            false,
            MtrrMemoryType::Uncacheable,
            None,
            &write_back_through,
        )
        .unwrap();
        assert_eq!(
            layout.memory_type_for(0x20_0000),
            Ok(MtrrMemoryType::WriteThrough)
        );

        let uncacheable_override = [
            write_back_through[0],
            variable_mtrr(0x20_0000, 0x20_0000, MtrrMemoryType::Uncacheable),
        ];
        let layout = MtrrLayout::new(
            36,
            true,
            false,
            MtrrMemoryType::WriteBack,
            None,
            &uncacheable_override,
        )
        .unwrap();
        assert_eq!(
            layout.memory_type_for(0x20_0000),
            Ok(MtrrMemoryType::Uncacheable)
        );

        let undefined = [
            variable_mtrr(0x20_0000, 0x20_0000, MtrrMemoryType::WriteCombining),
            variable_mtrr(0x20_0000, 0x20_0000, MtrrMemoryType::WriteProtected),
        ];
        let layout =
            MtrrLayout::new(36, true, false, MtrrMemoryType::WriteBack, None, &undefined).unwrap();
        assert_eq!(
            layout.memory_type_for(0x20_0000),
            Err(MtrrError::UndefinedOverlap)
        );
    }

    #[test]
    fn disabled_mtrrs_force_uncacheable_and_bad_registers_are_rejected() {
        let layout =
            MtrrLayout::new(36, false, true, MtrrMemoryType::WriteBack, None, &[]).unwrap();
        assert_eq!(
            layout.memory_type_for(0x20_0000),
            Ok(MtrrMemoryType::Uncacheable)
        );
        assert_eq!(
            MtrrLayout::new(36, true, true, MtrrMemoryType::WriteBack, None, &[]),
            Err(MtrrError::FixedRangesUnavailable)
        );
        assert_eq!(
            VariableMtrr::from_msr_values(0x1000 | 0x200, 0, 36),
            Err(MtrrError::ReservedBaseBits)
        );
        assert_eq!(
            VariableMtrr::from_msr_values(0x1000 | 6, 1 << 10, 36),
            Err(MtrrError::ReservedMaskBits)
        );
        assert_eq!(VariableMtrr::from_msr_values(0x1000 | 6, 0, 36), Ok(None));
        let width_mismatch = [variable_mtrr(
            0x20_0000,
            0x20_0000,
            MtrrMemoryType::WriteBack,
        )];
        assert_eq!(
            MtrrLayout::new(
                35,
                true,
                false,
                MtrrMemoryType::WriteBack,
                None,
                &width_mismatch,
            ),
            Err(MtrrError::PhysicalAddressWidthMismatch)
        );
        assert_eq!(
            VariableMtrr::from_msr_values(0x1000 | 2, 1 << 11, 36),
            Err(MtrrError::ReservedMemoryType { value: 2 })
        );
        let mut invalid_fixed = [0; 11];
        invalid_fixed[0] = 2;
        assert_eq!(
            FixedMtrrRanges::from_msr_values(invalid_fixed),
            Err(MtrrError::ReservedMemoryType { value: 2 })
        );
    }

    #[test]
    fn accepts_aligned_ranges_at_canonical_boundaries() {
        let lower = validate_mapping_range(
            0x0000_7fff_ffff_e000,
            0x1000,
            0x2000,
            KERNEL_READ_ONLY,
            Some(14),
            48,
        )
        .unwrap();
        assert_eq!(
            lower,
            ValidatedMappingRange {
                virtual_start: 0x0000_7fff_ffff_e000,
                virtual_end: 0x0000_8000_0000_0000,
                physical_start: 0x1000,
                physical_end: 0x3000,
                physical_address_bits: 14,
                permissions: KERNEL_READ_ONLY,
            }
        );

        let upper = validate_mapping_range(
            0xffff_8000_0000_0000,
            0,
            PAGE_SIZE,
            KERNEL_READ_ONLY,
            Some(12),
            48,
        )
        .unwrap();
        assert_eq!(upper.virtual_end(), 0xffff_8000_0000_1000);
    }

    #[test]
    fn rejects_empty_and_unaligned_ranges() {
        assert_eq!(
            validate_mapping_range(0x1000, 0x2000, 0, KERNEL_READ_ONLY, Some(32), 48),
            Err(MappingError::EmptyRange)
        );
        assert_eq!(
            validate_mapping_range(0x1001, 0x2000, PAGE_SIZE, KERNEL_READ_ONLY, Some(32), 48),
            Err(MappingError::UnalignedRange)
        );
        assert_eq!(
            validate_mapping_range(
                0x1000,
                0x2000,
                PAGE_SIZE + 1,
                KERNEL_READ_ONLY,
                Some(32),
                48
            ),
            Err(MappingError::UnalignedRange)
        );
    }

    #[test]
    fn requires_known_valid_address_widths_and_bounded_physical_ranges() {
        assert_eq!(
            validate_mapping_range(0x1000, 0x1000, PAGE_SIZE, KERNEL_READ_ONLY, None, 48),
            Err(MappingError::UnknownPhysicalAddressWidth)
        );
        assert_eq!(
            validate_mapping_range(0x1000, 0x1000, PAGE_SIZE, KERNEL_READ_ONLY, Some(0), 48),
            Err(MappingError::InvalidPhysicalAddressWidth)
        );
        assert_eq!(
            validate_mapping_range(0x1000, 0x1000, PAGE_SIZE, KERNEL_READ_ONLY, Some(52), 0),
            Err(MappingError::InvalidVirtualAddressWidth)
        );
        assert_eq!(
            validate_mapping_range(
                0x1000,
                0x1000,
                PAGE_SIZE * 2,
                KERNEL_READ_ONLY,
                Some(13),
                48
            ),
            Err(MappingError::PhysicalRangeOutOfBounds)
        );
    }

    #[test]
    fn rejects_noncanonical_ranges_and_ranges_crossing_the_canonical_hole() {
        assert_eq!(
            validate_mapping_range(
                0x0000_8000_0000_0000,
                0,
                PAGE_SIZE,
                KERNEL_READ_ONLY,
                Some(52),
                48
            ),
            Err(MappingError::NonCanonicalVirtualRange)
        );

        let crosses_hole = (0xffff_8000_0000_1000u64) - 0x0000_7fff_ffff_f000;
        assert_eq!(
            validate_mapping_range(
                0x0000_7fff_ffff_f000,
                0,
                crosses_hole,
                KERNEL_READ_ONLY,
                Some(64),
                48,
            ),
            Err(MappingError::CrossesCanonicalHole)
        );
    }

    fn pat_value(entries: [u8; 8]) -> u64 {
        entries.iter().enumerate().fold(0, |value, (index, entry)| {
            value | ((*entry as u64) << (index * 8))
        })
    }

    #[test]
    fn resolves_cache_policies_from_the_supplied_pat_layout() {
        let pat = pat_value([6, 4, 7, 0, 6, 1, 7, 0]);
        let layout = super::PatLayout::from_msr_value(pat).unwrap();
        assert_eq!(layout.index_for(super::CachePolicy::WriteBack), Some(0));
        assert_eq!(layout.index_for(super::CachePolicy::Uncacheable), Some(3));
        assert_eq!(
            layout.index_for(super::CachePolicy::WriteCombining),
            Some(5)
        );

        let without_write_combining =
            super::PatLayout::from_msr_value(pat_value([6, 4, 7, 0, 6, 4, 7, 0])).unwrap();
        assert_eq!(
            without_write_combining.index_for(super::CachePolicy::WriteCombining),
            None
        );
    }

    #[test]
    fn combines_every_documented_pat_and_mtrr_pair() {
        use EffectiveMemoryType as E;
        use MtrrMemoryType as M;

        let pat = PatLayout::from_msr_value(pat_value([0, 7, 1, 4, 6, 5, 0, 0])).unwrap();
        let rows = [
            (
                M::Uncacheable,
                [
                    E::Uncacheable,
                    E::Uncacheable,
                    E::WriteCombining,
                    E::Uncacheable,
                    E::Uncacheable,
                    E::Uncacheable,
                ],
            ),
            (
                M::WriteCombining,
                [
                    E::Uncacheable,
                    E::WriteCombining,
                    E::WriteCombining,
                    E::Uncacheable,
                    E::WriteCombining,
                    E::Uncacheable,
                ],
            ),
            (
                M::WriteThrough,
                [
                    E::Uncacheable,
                    E::Uncacheable,
                    E::WriteCombining,
                    E::WriteThrough,
                    E::WriteThrough,
                    E::WriteProtected,
                ],
            ),
            (
                M::WriteBack,
                [
                    E::Uncacheable,
                    E::Uncacheable,
                    E::WriteCombining,
                    E::WriteThrough,
                    E::WriteBack,
                    E::WriteProtected,
                ],
            ),
            (
                M::WriteProtected,
                [
                    E::Uncacheable,
                    E::Uncacheable,
                    E::WriteCombining,
                    E::WriteThrough,
                    E::WriteProtected,
                    E::WriteProtected,
                ],
            ),
        ];

        for (mtrr_type, expected) in rows {
            let registers = empty_mtrr_registers(1 << 10, (1 << 11) | mtrr_type as u64);
            let layout = registers.validated_layout(36).unwrap();
            for (pat_index, expected_type) in expected.into_iter().enumerate() {
                assert_eq!(
                    layout.effective_memory_type_for(0x20_0000, pat, pat_index as u8, true),
                    Ok(expected_type),
                    "MTRR={mtrr_type:?}, PAT index={pat_index}"
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_effective_cache_type_inputs() {
        let registers = empty_mtrr_registers(0, (1 << 11) | MtrrMemoryType::WriteBack as u64);
        let layout = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 4, 7, 0, 6, 1, 7, 0])).unwrap();

        assert_eq!(
            layout.effective_memory_type_for(0, pat, 8, true),
            Err(EffectiveMemoryTypeError::PatIndexOutOfRange { index: 8 })
        );
        assert_eq!(
            layout.effective_memory_type_for(0, pat, 0, false),
            Err(EffectiveMemoryTypeError::NonNormalCachingMode)
        );
        assert_eq!(
            layout.effective_memory_type_for(1u64 << 36, pat, 0, true),
            Err(EffectiveMemoryTypeError::Mtrr(
                MtrrError::PhysicalAddressOutOfRange
            ))
        );
    }

    #[test]
    fn selects_a_pat_index_that_is_uniform_across_variable_mtrr_segments() {
        let capability = 1 | (1 << 10);
        let mut registers =
            empty_mtrr_registers(capability, (1 << 11) | MtrrMemoryType::WriteBack as u64);
        let physical_mask = ((1u64 << 36) - 1) & !(PAGE_SIZE - 1);
        registers.variable_registers[0] = MtrrRegisterPair {
            base: 0x20_0000 | MtrrMemoryType::WriteThrough as u64,
            mask: (physical_mask & !(0x20_0000 - 1)) | (1 << 11),
        };
        let layout = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 0, 1, 4, 6, 1, 7, 0])).unwrap();

        assert_eq!(
            layout.select_pat_index_for_range(
                0x1f_f000,
                PAGE_SIZE * 2,
                pat,
                EffectiveMemoryType::WriteCombining,
                true,
            ),
            Ok(2)
        );
    }

    #[test]
    fn rejects_range_when_fixed_mtrrs_prevent_one_uniform_pat_index() {
        let mut registers = empty_mtrr_registers(
            1 << 8,
            (1 << 11) | (1 << 10) | MtrrMemoryType::WriteBack as u64,
        );
        registers.fixed_registers.as_mut().unwrap()[0] = MtrrMemoryType::WriteBack as u64;
        let layout = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 0, 1, 4, 6, 1, 7, 0])).unwrap();

        assert_eq!(
            layout.select_pat_index_for_range(
                0,
                0x20_000,
                pat,
                EffectiveMemoryType::WriteBack,
                true,
            ),
            Err(EffectiveMemoryTypeError::NoUniformPatIndex {
                requested: EffectiveMemoryType::WriteBack,
            })
        );
    }

    #[test]
    fn rejects_invalid_effective_cache_type_ranges() {
        let registers = empty_mtrr_registers(0, (1 << 11) | MtrrMemoryType::WriteBack as u64);
        let layout = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 0, 1, 4, 6, 1, 7, 0])).unwrap();
        let requested = EffectiveMemoryType::WriteBack;

        assert_eq!(
            layout.select_pat_index_for_range(0, 0, pat, requested, true),
            Err(EffectiveMemoryTypeError::EmptyRange)
        );
        assert_eq!(
            layout.select_pat_index_for_range(1, PAGE_SIZE, pat, requested, true),
            Err(EffectiveMemoryTypeError::UnalignedRange)
        );
        assert_eq!(
            layout.select_pat_index_for_range(
                u64::MAX & !(PAGE_SIZE - 1),
                PAGE_SIZE,
                pat,
                requested,
                true,
            ),
            Err(EffectiveMemoryTypeError::AddressOverflow)
        );
        assert_eq!(
            layout.select_pat_index_for_range(1 << 36, PAGE_SIZE, pat, requested, true),
            Err(EffectiveMemoryTypeError::Mtrr(
                MtrrError::PhysicalAddressOutOfRange
            ))
        );
        assert_eq!(
            layout.select_pat_index_for_range(0, PAGE_SIZE, pat, requested, false),
            Err(EffectiveMemoryTypeError::NonNormalCachingMode)
        );
    }

    #[test]
    fn validates_captured_mtrr_snapshot_before_resolution() {
        let registers = empty_mtrr_registers(
            (1 << 12) | (1 << 10) | (1 << 8) | 1,
            (1 << 11) | (1 << 10) | MtrrMemoryType::WriteBack as u64,
        );
        let layout = registers.validated_layout(36).unwrap();
        assert_eq!(layout.memory_type_for(0), Ok(MtrrMemoryType::WriteBack));
        assert_eq!(
            layout.memory_type_for(0x10_0000),
            Ok(MtrrMemoryType::WriteBack)
        );

        let mut invalid = empty_mtrr_registers(0, 1 << 11);
        invalid.capability |= 1 << 9;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::ReservedCapabilityBits)
        );

        let mut invalid = empty_mtrr_registers(0, 1 << 11);
        invalid.capability |= 1 << 13;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::ReservedCapabilityBits)
        );

        let mut invalid = empty_mtrr_registers(0, 1 << 11);
        invalid.default_type |= 1 << 12;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::ReservedDefaultTypeBits)
        );

        let mut invalid = empty_mtrr_registers(0, 1 << 11);
        invalid.variable_register_count = 1;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::VariableRegisterCountMismatch)
        );

        let mut invalid = empty_mtrr_registers(1 << 8, 1 << 11);
        invalid.fixed_registers = None;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::FixedRegisterSupportMismatch)
        );

        let invalid = empty_mtrr_registers(0, (1 << 11) | MtrrMemoryType::WriteCombining as u64);
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::WriteCombiningUnsupported)
        );

        let mut invalid = empty_mtrr_registers(1 << 8, (1 << 11) | 6);
        invalid.fixed_registers.as_mut().unwrap()[0] =
            MtrrMemoryType::WriteCombining as u64 * 0x0101_0101_0101_0101;
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::WriteCombiningUnsupported)
        );

        let mut invalid = empty_mtrr_registers(1, (1 << 11) | 6);
        let physical_mask = ((1u64 << 36) - 1) & !(PAGE_SIZE - 1);
        invalid.variable_registers[0] = MtrrRegisterPair {
            base: 0x20_0000 | MtrrMemoryType::WriteCombining as u64,
            mask: (physical_mask & !(0x20_0000 - 1)) | (1 << 11),
        };
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::WriteCombiningUnsupported)
        );

        let invalid = empty_mtrr_registers(0, (1 << 11) | (1 << 10));
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::FixedRangesUnavailable)
        );

        let mut invalid = empty_mtrr_registers(1, 1 << 11);
        let physical_mask = ((1u64 << 36) - 1) & !(PAGE_SIZE - 1);
        invalid.variable_registers[0] = MtrrRegisterPair {
            base: MtrrMemoryType::WriteBack as u64,
            mask: (physical_mask ^ (1 << 13)) | (1 << 11),
        };
        assert_eq!(
            invalid.validated_layout(36),
            Err(MtrrError::UnsupportedDiscontinuousVariableMask)
        );
    }

    #[test]
    fn rejects_misaligned_variable_mtrr_bases() {
        let physical_address_bits = 36;
        let physical_mask = ((1u64 << physical_address_bits) - 1) & !(PAGE_SIZE - 1);
        let mask = physical_mask & !(0x2000 - 1) | (1 << 11);
        assert_eq!(
            VariableMtrr::from_msr_values(
                0x1000 | MtrrMemoryType::WriteBack as u64,
                mask,
                physical_address_bits,
            ),
            Err(MtrrError::MisalignedVariableBase)
        );
    }

    #[test]
    fn rejects_reserved_pat_entries() {
        assert_eq!(
            super::PatLayout::from_msr_value(0x08),
            Err(super::PatLayoutError::ReservedBits { index: 0 })
        );
        assert_eq!(
            super::PatLayout::from_msr_value(0b010 << 24),
            Err(super::PatLayoutError::ReservedMemoryType {
                index: 3,
                value: 0b010,
            })
        );
    }

    #[test]
    fn selects_uniform_cache_attributes_for_a_mapping_range_and_encodes_each_leaf() {
        let capability = 1 | (1 << 10);
        let mut registers =
            empty_mtrr_registers(capability, (1 << 11) | MtrrMemoryType::WriteBack as u64);
        let physical_mask = ((1u64 << 36) - 1) & !(PAGE_SIZE - 1);
        registers.variable_registers[0] = MtrrRegisterPair {
            base: 0x20_0000 | MtrrMemoryType::WriteThrough as u64,
            mask: (physical_mask & !(0x20_0000 - 1)) | (1 << 11),
        };
        let mtrrs = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 0, 1, 4, 6, 1, 7, 0])).unwrap();
        let mapping = validate_mapping_range(
            0x4000,
            0x1f_f000,
            PAGE_SIZE * 2,
            KERNEL_READ_ONLY,
            Some(36),
            48,
        )
        .unwrap();
        let attributes = mapping
            .select_cache_attributes(CachePolicy::WriteCombining, pat, &mtrrs, true)
            .unwrap();

        assert_eq!(attributes.physical_start(), 0x1f_f000);
        assert_eq!(attributes.physical_end(), 0x20_1000);
        assert_eq!(attributes.pat_index(), 2);
        assert_eq!(
            attributes.effective_type(),
            EffectiveMemoryType::WriteCombining
        );
        for offset in [0, PAGE_SIZE] {
            assert_eq!(
                mapping
                    .leaf_4k_entry_with_cache_attributes(offset, attributes, true)
                    .unwrap()
                    .bits()
                    & ((1 << 3) | (1 << 4) | (1 << 7)),
                1 << 4
            );
        }

        let other_mapping = validate_mapping_range(
            0x8000,
            0x30_0000,
            PAGE_SIZE * 2,
            KERNEL_READ_ONLY,
            Some(36),
            48,
        )
        .unwrap();
        assert_eq!(
            other_mapping.leaf_4k_entry_with_cache_attributes(0, attributes, true),
            Err(MappingError::CacheAttributesRangeMismatch)
        );
    }

    #[test]
    fn rejects_cache_attribute_selection_when_physical_widths_disagree() {
        let registers = empty_mtrr_registers(0, (1 << 11) | MtrrMemoryType::WriteBack as u64);
        let mtrrs = registers.validated_layout(36).unwrap();
        let pat = PatLayout::from_msr_value(pat_value([6, 0, 1, 4, 6, 1, 7, 0])).unwrap();
        let mapping =
            validate_mapping_range(0x4000, 0x20_0000, PAGE_SIZE, KERNEL_READ_ONLY, Some(37), 48)
                .unwrap();

        assert_eq!(
            mapping.select_cache_attributes(CachePolicy::WriteBack, pat, &mtrrs, true),
            Err(MappingError::MtrrPhysicalAddressWidthMismatch)
        );
    }

    #[test]
    fn encodes_4k_leaf_permissions_nx_and_pat_index_bits() {
        let writable_user_page = PagePermissions {
            writable: true,
            executable: false,
            user_accessible: true,
        };
        let mapping = validate_mapping_range(
            0x4000,
            0x20_0000,
            PAGE_SIZE * 2,
            writable_user_page,
            Some(52),
            48,
        )
        .unwrap();

        let first = mapping.leaf_4k_entry(0, 0b101, true).unwrap().bits();
        assert_eq!(
            first,
            0x20_0000 | (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 7) | (1 << 63)
        );
        let second = mapping
            .leaf_4k_entry(PAGE_SIZE, 0b101, true)
            .unwrap()
            .bits();
        assert_eq!(second & 0x000f_ffff_ffff_f000, 0x20_1000);
        assert_eq!(second & (1 << 63), 1 << 63);

        let all_pat_bits = mapping.leaf_4k_entry(0, 0b111, true).unwrap().bits()
            & ((1 << 3) | (1 << 4) | (1 << 7));
        assert_eq!(all_pat_bits, (1 << 3) | (1 << 4) | (1 << 7));
    }

    #[test]
    fn rejects_unencodable_leaf_attributes_and_page_offsets() {
        let mapping =
            validate_mapping_range(0x4000, 0x20_0000, PAGE_SIZE, KERNEL_READ_ONLY, Some(52), 48)
                .unwrap();
        assert_eq!(
            mapping.leaf_4k_entry(0, 8, true),
            Err(MappingError::InvalidPatIndex)
        );
        assert_eq!(
            mapping.leaf_4k_entry(0, 0, false),
            Err(MappingError::NxNotEnabled)
        );
        assert_eq!(
            mapping.leaf_4k_entry(1, 0, true),
            Err(MappingError::UnalignedPageOffset)
        );
        assert_eq!(
            mapping.leaf_4k_entry(PAGE_SIZE, 0, true),
            Err(MappingError::PageOffsetOutOfRange)
        );

        let too_wide =
            validate_mapping_range(0x4000, 0x20_0000, PAGE_SIZE, KERNEL_READ_ONLY, Some(53), 48)
                .unwrap();
        assert_eq!(
            too_wide.leaf_4k_entry(0, 0, true),
            Err(MappingError::InvalidPhysicalAddressWidth)
        );
    }

    #[test]
    fn executable_leaf_does_not_set_nx() {
        let executable = PagePermissions {
            writable: false,
            executable: true,
            user_accessible: false,
        };
        let mapping =
            validate_mapping_range(0x4000, 0x20_0000, PAGE_SIZE, executable, Some(52), 48).unwrap();
        let entry = mapping.leaf_4k_entry(0, 0, false).unwrap().bits();
        assert_eq!(entry, 0x20_0000 | 1);
    }

    #[test]
    fn candidate_page_tables_reject_root_frames_outside_the_configured_width() {
        let high_address = 1u64 << 40;
        let map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: high_address,
            length: PAGE_SIZE,
            kind: 0,
        }])
        .unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&map).unwrap();
        let mut memory = CandidateTestMemory::new();
        let failure =
            match CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config()) {
                Err(error) => error,
                Ok(_) => panic!("candidate creation accepted an out-of-range root frame"),
            };
        assert_eq!(failure.cause, CandidateCreateErrorKind::RootFrameOutOfRange);
        let frame = failure
            .frame
            .expect("root token is returned on validation failure");
        assert_eq!(frame.address(), high_address);
        allocator.deallocate(frame).unwrap();
        assert_eq!(allocator.free_frames(), 1);
    }

    #[test]
    fn candidate_mapping_rejects_out_of_width_table_frames_transactionally() {
        let high_address = 1u64 << 40;
        let map = MemoryMap::from_raw(&[
            RawMemoryRegion {
                base: 0x10_0000,
                length: PAGE_SIZE,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x10_1000,
                length: PAGE_SIZE,
                kind: 0,
            },
            RawMemoryRegion {
                base: high_address,
                length: PAGE_SIZE,
                kind: 0,
            },
        ])
        .unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&map).unwrap();
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let frame = allocator.allocate().unwrap();
        assert_eq!(frame.address(), 0x10_1000);
        let (mapping, attributes) = candidate_mapping(
            &frame,
            0xffff_9000_0000_1000,
            PagePermissions {
                writable: false,
                executable: false,
                user_accessible: false,
            },
        );
        let free_before_map = allocator.free_frames();

        let failure = candidate
            .map_owned_page(&mut allocator, frame, mapping, attributes)
            .unwrap_err();
        assert_eq!(failure.cause, CandidateMapErrorKind::TableFrameOutOfRange);
        assert_eq!(failure.rollback_retained_table_frames, 0);
        assert_eq!(candidate.table_count(), 1);
        assert_eq!(candidate.mapping_count(), 0);
        assert_eq!(allocator.free_frames(), free_before_map);
        allocator.deallocate(failure.frame).unwrap();
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), 3);
    }

    #[test]
    fn candidate_walk_rejects_intermediate_tables_without_owned_tokens() {
        let mut allocator = candidate_allocator(2);
        let foreign_frame = allocator.allocate().unwrap();
        let virtual_address = 0xffff_9000_0000_1000;
        let root_index = super::page_table_indexes(virtual_address, 4)[0];
        let mut memory = CandidateTestMemory::new();
        memory.foreign_child = Some((root_index, foreign_frame.address()));
        let candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();

        assert_eq!(
            candidate.walk(virtual_address),
            Err(PageWalkError::Reader(
                CandidatePageTableReadError::UnownedTable
            ))
        );
        candidate.release(&mut allocator).unwrap();
        allocator.deallocate(foreign_frame).unwrap();
        assert_eq!(allocator.free_frames(), 2);
    }

    #[test]
    fn candidate_release_failure_retains_owned_frames_for_retry() {
        const TOTAL_FRAMES: usize = 513;
        let mut allocator = candidate_allocator(TOTAL_FRAMES);
        let mut memory = CandidateTestMemory::new();
        let candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let mut remaining_frames: [Option<Frame>; TOTAL_FRAMES - 1] =
            core::array::from_fn(|_| Some(allocator.allocate().unwrap()));
        for index in (1..remaining_frames.len()).step_by(2) {
            allocator
                .deallocate(remaining_frames[index].take().unwrap())
                .unwrap();
        }

        let failure = match candidate.release(&mut allocator) {
            Err(failure) => failure,
            Ok(()) => panic!("release unexpectedly fit a full range table"),
        };
        assert_eq!(
            failure.error,
            CandidateReleaseError::Frame(FrameError::RangeTableFull)
        );
        assert_eq!(failure.candidate.table_count(), 1);
        assert_eq!(failure.candidate.mapping_count(), 0);

        allocator
            .deallocate(remaining_frames[0].take().unwrap())
            .unwrap();
        failure.candidate.release(&mut allocator).unwrap();
        for frame in remaining_frames.into_iter().flatten() {
            allocator.deallocate(frame).unwrap();
        }
        assert_eq!(allocator.free_frames(), TOTAL_FRAMES as u64);
    }

    #[test]
    fn active_candidate_rejects_mutation_and_release_until_deactivated() {
        let mut allocator = candidate_allocator(4);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let root = candidate.root_physical_address();
        // SAFETY: This is a synthetic test of the active-state guard; no CPU
        // actually uses the test candidate's root.
        unsafe { candidate.mark_active() };
        assert!(candidate.is_active());
        assert!(matches!(
            candidate.unmap_owned_page(0xffff_9000_0000_1000),
            Err(CandidateUnmapError::Active)
        ));

        let failure = candidate.release(&mut allocator).unwrap_err();
        assert_eq!(failure.error, CandidateReleaseError::ActiveRoot);
        let mut candidate = failure.candidate;
        assert_eq!(candidate.root_physical_address(), root);
        // SAFETY: The synthetic test never installed this root in CR3.
        unsafe { candidate.mark_inactive() };
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), 4);
    }

    #[test]
    fn candidate_clone_preserves_inherited_entries_and_shared_tables() {
        let total_frames = 8;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let virtual_address = 0xffff_9000_0000_1000;
        let indexes = super::page_table_indexes(virtual_address, 4);
        let source_root = 0x8000;
        let mut reader = SyntheticReader::new();
        reader.set(source_root, indexes[0], 0x9000 | 0x3);
        reader.set(source_root, indexes[0] + 1, 0x9000 | 0x3);
        reader.set(0x9000, indexes[1], 0xa000 | 0x3);
        reader.set(0xa000, indexes[2], 0xb000 | 0x3);
        reader.set(0xb000, indexes[3], 0x20_0000 | 0x3 | (1 << 63));

        let root = parse_cr3_root(source_root, Some(40), false).unwrap();
        candidate
            .clone_inherited_hierarchy(&mut allocator, &reader, root)
            .unwrap();
        assert_eq!(candidate.table_count(), 4);
        assert_eq!(
            candidate.walk(virtual_address).unwrap(),
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: 0x20_0000,
                leaf_physical_base: 0x20_0000,
                page_size: PAGE_SIZE,
                permissions: PagePermissions {
                    writable: true,
                    executable: false,
                    user_accessible: false,
                },
                pat_index: 0,
                raw_leaf_entry: 0x20_0000 | 0x3 | (1 << 63),
            })
        );

        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn inherited_large_page_permission_change_splits_and_preserves_cache_type() {
        let total_frames = 16;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let virtual_address = 0xffff_9000_0000_1000;
        let indexes = super::page_table_indexes(virtual_address, 4);
        let source_root = 0x8000;
        let mut reader = SyntheticReader::new();
        reader.set(source_root, indexes[0], 0x9000 | 0x3);
        reader.set(0x9000, indexes[1], 0xa000 | 0x3);
        reader.set(0xa000, indexes[2], 0x20_0000 | 0x3 | (1 << 7) | (1 << 12));
        let root = parse_cr3_root(source_root, Some(40), false).unwrap();
        candidate
            .clone_inherited_hierarchy(&mut allocator, &reader, root)
            .unwrap();

        candidate
            .set_inherited_page_permissions(
                &mut allocator,
                virtual_address,
                0x20_1000,
                PagePermissions {
                    writable: false,
                    executable: false,
                    user_accessible: false,
                },
            )
            .unwrap();
        let protected = match candidate.walk(virtual_address).unwrap() {
            PageWalkOutcome::Mapped(translation) => translation,
            PageWalkOutcome::NotPresent { .. } => panic!("split mapping disappeared"),
        };
        assert_eq!(protected.physical_address, 0x20_1000);
        assert_eq!(protected.page_size, PAGE_SIZE);
        assert_eq!(
            protected.permissions,
            PagePermissions {
                writable: false,
                executable: false,
                user_accessible: false,
            }
        );
        assert_eq!(protected.pat_index, 4);

        let neighbor = match candidate.walk(virtual_address + PAGE_SIZE).unwrap() {
            PageWalkOutcome::Mapped(translation) => translation,
            PageWalkOutcome::NotPresent { .. } => panic!("neighbor mapping disappeared"),
        };
        assert_eq!(neighbor.physical_address, 0x20_2000);
        assert_eq!(neighbor.page_size, PAGE_SIZE);
        assert_eq!(neighbor.permissions.writable, true);
        assert_eq!(neighbor.permissions.executable, true);
        assert_eq!(neighbor.pat_index, 4);

        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn inherited_one_gibibyte_permission_change_splits_preserving_pat() {
        let total_frames = 16;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let virtual_address = 0xffff_9000_0040_1000;
        let indexes = super::page_table_indexes(virtual_address, 4);
        let source_root = 0x8000;
        let mut reader = SyntheticReader::new();
        reader.set(source_root, indexes[0], 0x9000 | 0x3);
        reader.set(0x9000, indexes[1], 0x4000_0000 | 0x3 | (1 << 7) | (1 << 12));
        let root = parse_cr3_root(source_root, Some(40), false).unwrap();
        candidate
            .clone_inherited_hierarchy(&mut allocator, &reader, root)
            .unwrap();

        candidate
            .set_inherited_page_permissions(
                &mut allocator,
                virtual_address,
                0x4040_1000,
                PagePermissions {
                    writable: false,
                    executable: false,
                    user_accessible: false,
                },
            )
            .unwrap();
        let protected = match candidate.walk(virtual_address).unwrap() {
            PageWalkOutcome::Mapped(translation) => translation,
            PageWalkOutcome::NotPresent { .. } => panic!("split mapping disappeared"),
        };
        assert_eq!(protected.physical_address, 0x4040_1000);
        assert_eq!(protected.page_size, PAGE_SIZE);
        assert_eq!(protected.pat_index, 4);
        assert!(!protected.permissions.writable);
        assert!(!protected.permissions.executable);

        let neighboring_large_page = match candidate.walk(virtual_address + (1 << 21)).unwrap() {
            PageWalkOutcome::Mapped(translation) => translation,
            PageWalkOutcome::NotPresent { .. } => panic!("neighbor mapping disappeared"),
        };
        assert_eq!(neighboring_large_page.page_size, 1 << 21);
        assert_eq!(neighboring_large_page.pat_index, 4);
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn candidate_clone_rejects_invalid_large_page_entries_and_clears_root() {
        let mut allocator = candidate_allocator(4);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let source_root = 0x8000;
        let virtual_address = 0xffff_9000_0000_1000;
        let root_index = super::page_table_indexes(virtual_address, 4)[0];
        let mut reader = SyntheticReader::new();
        reader.set(source_root, root_index, 0x9000 | 0x3 | (1 << 7));
        let root = parse_cr3_root(source_root, Some(40), false).unwrap();

        assert_eq!(
            candidate.clone_inherited_hierarchy(&mut allocator, &reader, root),
            Err(CandidateCloneError::InvalidEntry {
                level: 4,
                index: root_index,
            })
        );
        assert_eq!(candidate.table_count(), 1);
        assert_eq!(
            candidate.walk(virtual_address).unwrap(),
            PageWalkOutcome::NotPresent {
                level: PageLevel::Pml4,
            }
        );
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), 4);
    }

    #[test]
    fn candidate_page_tables_require_nx_and_report_unmapped_pages() {
        let mut allocator = candidate_allocator(2);
        let mut memory = CandidateTestMemory::new();
        let invalid = CandidatePageTables::new(
            &mut allocator,
            &mut memory,
            PageWalkConfig {
                nx_enabled: false,
                ..four_level_walk_config()
            },
        );
        let error = match invalid {
            Err(error) => error,
            Ok(_) => panic!("candidate creation unexpectedly accepted disabled NX"),
        };
        assert_eq!(error.cause, CandidateCreateErrorKind::InvalidConfiguration);
        assert_eq!(error.frame, None);

        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        assert_eq!(
            candidate.unmap_owned_page(0xffff_9000_0000_1000),
            Err(CandidateUnmapError::NotMapped)
        );
        assert!(candidate.release(&mut allocator).is_ok());
    }

    #[test]
    fn candidate_page_tables_map_unmap_and_release_owned_frames() {
        let total_frames = 8;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let root = candidate.root_physical_address().unwrap();
        assert_eq!(candidate.root_physical_address(), Some(root));
        let frame = allocator.allocate().unwrap();
        let physical = frame.address();
        let virtual_address = 0xffff_9000_0000_1000;
        let permissions = PagePermissions {
            writable: true,
            executable: false,
            user_accessible: true,
        };
        let (mapping, attributes) = candidate_mapping(&frame, virtual_address, permissions);

        candidate
            .map_owned_page(&mut allocator, frame, mapping, attributes)
            .unwrap();
        assert_eq!(candidate.table_count(), 4);
        assert_eq!(candidate.mapping_count(), 1);

        assert_eq!(
            candidate.walk(virtual_address).unwrap(),
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: physical,
                leaf_physical_base: physical,
                page_size: PAGE_SIZE,
                permissions,
                pat_index: 0,
                raw_leaf_entry: physical | 0x3 | (1 << 2) | (1 << 63),
            })
        );

        let duplicate_frame = allocator.allocate().unwrap();
        let (duplicate_mapping, duplicate_attributes) =
            candidate_mapping(&duplicate_frame, virtual_address, permissions);
        let free_before_duplicate = allocator.free_frames();
        let failure = candidate
            .map_owned_page(
                &mut allocator,
                duplicate_frame,
                duplicate_mapping,
                duplicate_attributes,
            )
            .unwrap_err();
        assert_eq!(failure.cause, CandidateMapErrorKind::MappingAlreadyPresent);
        assert_eq!(candidate.mapping_count(), 1);
        assert_eq!(allocator.free_frames(), free_before_duplicate);
        allocator.deallocate(failure.frame).unwrap();

        let returned = candidate.unmap_owned_page(virtual_address).unwrap();
        assert_eq!(returned.address(), physical);
        assert_eq!(candidate.mapping_count(), 0);
        assert_eq!(
            candidate.walk(virtual_address).unwrap(),
            PageWalkOutcome::NotPresent {
                level: PageLevel::Pt,
            }
        );
        allocator.deallocate(returned).unwrap();
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn candidate_page_table_mapping_rolls_back_on_frame_exhaustion() {
        let total_frames = 4;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let frame = allocator.allocate().unwrap();
        let virtual_address = 0xffff_9000_0000_1000;
        let (mapping, attributes) = candidate_mapping(
            &frame,
            virtual_address,
            PagePermissions {
                writable: false,
                executable: false,
                user_accessible: false,
            },
        );
        let free_before_map = allocator.free_frames();

        let failure = candidate
            .map_owned_page(&mut allocator, frame, mapping, attributes)
            .unwrap_err();
        assert_eq!(failure.cause, CandidateMapErrorKind::OutOfFrames);
        assert_eq!(failure.rollback_retained_table_frames, 0);
        assert_eq!(allocator.free_frames(), free_before_map);
        assert_eq!(candidate.table_count(), 1);
        assert_eq!(candidate.mapping_count(), 0);
        allocator.deallocate(failure.frame).unwrap();
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn candidate_page_table_mapping_rolls_back_after_prepare_failure() {
        let total_frames = 8;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        memory.fail_prepare_at = Some(3);
        let mut candidate =
            CandidatePageTables::new(&mut allocator, &mut memory, four_level_walk_config())
                .unwrap();
        let frame = allocator.allocate().unwrap();
        let virtual_address = 0xffff_9000_0000_1000;
        let (mapping, attributes) = candidate_mapping(
            &frame,
            virtual_address,
            PagePermissions {
                writable: false,
                executable: false,
                user_accessible: false,
            },
        );
        let free_before_map = allocator.free_frames();

        let failure = candidate
            .map_owned_page(&mut allocator, frame, mapping, attributes)
            .unwrap_err();
        assert_eq!(
            failure.cause,
            CandidateMapErrorKind::TableMemory(CandidateTestMemoryError::InjectedPrepareFailure)
        );
        assert_eq!(failure.rollback_retained_table_frames, 0);
        assert_eq!(allocator.free_frames(), free_before_map);
        assert_eq!(candidate.table_count(), 1);
        assert_eq!(candidate.mapping_count(), 0);
        allocator.deallocate(failure.frame).unwrap();
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn candidate_page_tables_support_five_level_virtual_paths() {
        let total_frames = 8;
        let mut allocator = candidate_allocator(total_frames);
        let mut memory = CandidateTestMemory::new();
        let config = PageWalkConfig {
            levels: 5,
            virtual_address_bits: 57,
            ..four_level_walk_config()
        };
        let mut candidate = CandidatePageTables::new(&mut allocator, &mut memory, config).unwrap();
        let root = candidate.root_physical_address().unwrap();
        assert_eq!(candidate.root_physical_address(), Some(root));
        let frame = allocator.allocate().unwrap();
        let physical = frame.address();
        let virtual_address = 0xff00_0000_0020_1000;
        let (mapping, attributes) = candidate_mapping(
            &frame,
            virtual_address,
            PagePermissions {
                writable: false,
                executable: true,
                user_accessible: false,
            },
        );

        candidate
            .map_owned_page(&mut allocator, frame, mapping, attributes)
            .unwrap();
        assert_eq!(candidate.table_count(), 5);
        assert_eq!(
            candidate.walk(virtual_address).unwrap(),
            PageWalkOutcome::Mapped(PageTranslation {
                physical_address: physical,
                leaf_physical_base: physical,
                page_size: PAGE_SIZE,
                permissions: PagePermissions {
                    writable: false,
                    executable: true,
                    user_accessible: false,
                },
                pat_index: 0,
                raw_leaf_entry: physical | 0x1,
            })
        );
        candidate.release(&mut allocator).unwrap();
        assert_eq!(allocator.free_frames(), total_frames as u64);
    }

    #[test]
    fn rejects_arithmetic_overflow_and_writable_executable_ranges() {
        assert_eq!(
            validate_mapping_range(
                u64::MAX - (PAGE_SIZE - 1),
                0,
                PAGE_SIZE,
                KERNEL_READ_ONLY,
                Some(64),
                64
            ),
            Err(MappingError::AddressOverflow)
        );
        assert_eq!(
            validate_mapping_range(
                0x1000,
                u64::MAX - (PAGE_SIZE - 1),
                PAGE_SIZE,
                KERNEL_READ_ONLY,
                Some(64),
                64
            ),
            Err(MappingError::AddressOverflow)
        );

        let writable_executable = PagePermissions {
            writable: true,
            executable: true,
            user_accessible: false,
        };
        assert_eq!(
            validate_mapping_range(0x1000, 0x2000, PAGE_SIZE, writable_executable, Some(52), 48),
            Err(MappingError::WritableExecutable)
        );
    }
}
