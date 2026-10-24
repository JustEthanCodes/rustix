//! Allocation-free validation for virtual addresses and physical memory maps.

/// Limine's memory-map type for ordinary usable RAM.
pub const MEMORY_MAP_USABLE: u64 = 0;
/// Maximum number of memory regions retained in the boot snapshot.
pub const MAX_MEMORY_REGIONS: usize = 256;
/// Minimum x86_64 initial stack size guaranteed by the Limine protocol.
pub const LIMINE_X86_64_MIN_STACK_SIZE: u64 = 64 * 1024;

/// Check whether an address is canonical for a sign-extended virtual width.
///
/// Widths outside `1..=64` are rejected. A 64-bit width accepts every address.
pub const fn is_canonical_virtual_address(address: u64, address_bits: u8) -> bool {
    if address_bits == 0 || address_bits > 64 {
        return false;
    }
    if address_bits == 64 {
        return true;
    }

    let sign_bit = (address >> (address_bits - 1)) & 1;
    let upper_bits = address >> address_bits;
    let expected_upper_bits = if sign_bit == 0 {
        0
    } else {
        u64::MAX >> address_bits
    };
    upper_bits == expected_upper_bits
}

/// Check that a non-empty half-open physical range fits an address width.
pub const fn physical_range_fits_address_width(start: u64, end: u64, address_bits: u8) -> bool {
    if start >= end || address_bits == 0 || address_bits > 64 {
        return false;
    }
    address_bits == 64 || end <= (1u64 << address_bits)
}

/// Return the physical end of the linker-defined kernel image span, if valid.
///
/// Limine reports the load bases while the linker supplies the virtual span.
/// This validates that both sources agree on the virtual base and that the
/// relocated half-open physical range fits the known address widths.
pub const fn kernel_image_physical_end(
    physical_base: u64,
    reported_virtual_base: u64,
    linked_virtual_start: u64,
    linked_virtual_end: u64,
    physical_bits: Option<u8>,
    virtual_bits: u8,
) -> Option<u64> {
    if linked_virtual_start != reported_virtual_base
        || linked_virtual_start >= linked_virtual_end
        || physical_base & 0xfff != 0
        || linked_virtual_start & 0xfff != 0
    {
        return None;
    }

    let virtual_last = linked_virtual_end - 1;
    if !is_canonical_virtual_address(linked_virtual_start, virtual_bits)
        || !is_canonical_virtual_address(virtual_last, virtual_bits)
    {
        return None;
    }
    let sign_bit = 1u64 << (virtual_bits - 1);
    if linked_virtual_start & sign_bit != virtual_last & sign_bit {
        return None;
    }

    let image_size = linked_virtual_end - linked_virtual_start;
    let Some(physical_end) = physical_base.checked_add(image_size) else {
        return None;
    };
    if let Some(bits) = physical_bits {
        if !physical_range_fits_address_width(physical_base, physical_end, bits) {
            return None;
        }
    }
    Some(physical_end)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelImageVirtualSegments {
    pub text: (u64, u64),
    pub rodata: (u64, u64),
    pub data: (u64, u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelImageSegment {
    pub virtual_start: u64,
    pub virtual_end: u64,
    pub physical_start: u64,
    pub physical_end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelImageSegments {
    pub text: KernelImageSegment,
    pub rodata: KernelImageSegment,
    pub data: KernelImageSegment,
}

/// Validate page-aligned PT_LOAD mapping spans and translate them to physical ranges.
///
/// The three spans must be contiguous, ordered text/rodata/data ranges that cover
/// the linker-defined image after rounding its final byte to a 4 KiB boundary.
/// This validates linker metadata; it does not prove that inherited page tables
/// map these ranges or that their backing frames are owned by Rustix.
pub const fn kernel_image_segments(
    physical_base: u64,
    reported_virtual_base: u64,
    image_virtual_start: u64,
    image_virtual_end: u64,
    virtual_segments: KernelImageVirtualSegments,
    physical_bits: Option<u8>,
    virtual_bits: u8,
) -> Option<KernelImageSegments> {
    let Some(_) = kernel_image_physical_end(
        physical_base,
        reported_virtual_base,
        image_virtual_start,
        image_virtual_end,
        physical_bits,
        virtual_bits,
    ) else {
        return None;
    };

    let (text_start, text_end) = virtual_segments.text;
    let (rodata_start, rodata_end) = virtual_segments.rodata;
    let (data_start, data_end) = virtual_segments.data;
    if text_start != image_virtual_start
        || text_start >= text_end
        || text_end != rodata_start
        || rodata_start >= rodata_end
        || rodata_end != data_start
        || data_start >= image_virtual_end
        || image_virtual_end > data_end
    {
        return None;
    }

    let Some(rounded_image_end) = image_virtual_end.checked_add(0xfff) else {
        return None;
    };
    let rounded_image_end = rounded_image_end & !0xfff;
    if data_end != rounded_image_end
        || text_start & 0xfff != 0
        || text_end & 0xfff != 0
        || rodata_start & 0xfff != 0
        || rodata_end & 0xfff != 0
        || data_start & 0xfff != 0
        || data_end & 0xfff != 0
    {
        return None;
    }

    let mapped_last_virtual = data_end - 1;
    if !is_canonical_virtual_address(image_virtual_start, virtual_bits)
        || !is_canonical_virtual_address(mapped_last_virtual, virtual_bits)
    {
        return None;
    }
    if virtual_bits < 64
        && ((image_virtual_start ^ mapped_last_virtual) & (1u64 << (virtual_bits - 1))) != 0
    {
        return None;
    }

    let Some(mapped_physical_end) = physical_base.checked_add(data_end - image_virtual_start)
    else {
        return None;
    };
    if let Some(bits) = physical_bits {
        if !physical_range_fits_address_width(physical_base, mapped_physical_end, bits) {
            return None;
        }
    }

    let Some(text_physical_start) = physical_base.checked_add(text_start - image_virtual_start)
    else {
        return None;
    };
    let Some(text_physical_end) = physical_base.checked_add(text_end - image_virtual_start) else {
        return None;
    };
    let Some(rodata_physical_start) = physical_base.checked_add(rodata_start - image_virtual_start)
    else {
        return None;
    };
    let Some(rodata_physical_end) = physical_base.checked_add(rodata_end - image_virtual_start)
    else {
        return None;
    };
    let Some(data_physical_start) = physical_base.checked_add(data_start - image_virtual_start)
    else {
        return None;
    };

    Some(KernelImageSegments {
        text: KernelImageSegment {
            virtual_start: text_start,
            virtual_end: text_end,
            physical_start: text_physical_start,
            physical_end: text_physical_end,
        },
        rodata: KernelImageSegment {
            virtual_start: rodata_start,
            virtual_end: rodata_end,
            physical_start: rodata_physical_start,
            physical_end: rodata_physical_end,
        },
        data: KernelImageSegment {
            virtual_start: data_start,
            virtual_end: data_end,
            physical_start: data_physical_start,
            physical_end: mapped_physical_end,
        },
    })
}

/// Derive the requested initial x86_64 stack span below Limine's entry RSP.
///
/// The SysV entry stack has an 8-byte return-address slot, so `entry_rsp + 8`
/// is the exclusive top. The requested span must be at least the protocol's
/// 64 KiB minimum; callers should pass the size actually requested from Limine.
pub const fn limine_x86_64_stack_bounds(
    entry_rsp: u64,
    virtual_bits: u8,
    stack_size: u64,
) -> Option<(u64, u64)> {
    if entry_rsp & 0xf != 8 {
        return None;
    }
    let Some(stack_end) = entry_rsp.checked_add(8) else {
        return None;
    };
    if stack_size < LIMINE_X86_64_MIN_STACK_SIZE {
        return None;
    }
    let Some(stack_start) = stack_end.checked_sub(stack_size) else {
        return None;
    };
    let stack_last = stack_end - 1;
    if !is_canonical_virtual_address(stack_start, virtual_bits)
        || !is_canonical_virtual_address(stack_last, virtual_bits)
    {
        return None;
    }
    let sign_bit = 1u64 << (virtual_bits - 1);
    if stack_start & sign_bit != stack_last & sign_bit {
        return None;
    }
    Some((stack_start, stack_end))
}

/// Validate the page-rounded HHDM span for one Limine base-revision-3 region.
///
/// `physical_bits` is `None` only when CPUID does not report the width. This
/// checks arithmetic and canonicality, not whether the inherited page tables
/// actually contain the mapping.
pub const fn limine_v3_hhdm_range_is_valid(
    offset: u64,
    physical_start: u64,
    physical_end: u64,
    physical_bits: Option<u8>,
    virtual_bits: u8,
) -> bool {
    const PAGE_SIZE: u64 = 4096;
    const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

    if physical_start >= physical_end
        || offset & (PAGE_SIZE - 1) != 0
        || (virtual_bits != 48 && virtual_bits != 57)
        || !is_canonical_virtual_address(offset, virtual_bits)
    {
        return false;
    }
    if let Some(bits) = physical_bits {
        if !physical_range_fits_address_width(physical_start, physical_end, bits) {
            return false;
        }
    }

    let mapped_start = physical_start & PAGE_MASK;
    let Some(rounded_end) = physical_end.checked_add(PAGE_SIZE - 1) else {
        return false;
    };
    let mapped_end = rounded_end & PAGE_MASK;
    if mapped_start >= mapped_end {
        return false;
    }
    if let Some(bits) = physical_bits {
        if !physical_range_fits_address_width(mapped_start, mapped_end, bits) {
            return false;
        }
    }

    let Some(virtual_start) = offset.checked_add(mapped_start) else {
        return false;
    };
    let Some(virtual_last) = offset.checked_add(mapped_end - 1) else {
        return false;
    };
    if !is_canonical_virtual_address(virtual_start, virtual_bits)
        || !is_canonical_virtual_address(virtual_last, virtual_bits)
    {
        return false;
    }

    let sign_bit = 1u64 << (virtual_bits - 1);
    virtual_start & sign_bit == virtual_last & sign_bit
}

/// Classification of a physical memory region from the Limine memory map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    BadMemory,
    BootloaderReclaimable,
    ExecutableAndModules,
    Framebuffer,
    Unknown(u64),
}

impl RegionKind {
    /// Whether Limine base revision 3 includes this type in the HHDM.
    pub const fn is_mapped_by_limine_v3_hhdm(self) -> bool {
        matches!(
            self,
            Self::Usable
                | Self::BootloaderReclaimable
                | Self::ExecutableAndModules
                | Self::Framebuffer
        )
    }

    const fn from_limine(kind: u64) -> Self {
        match kind {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaimable,
            3 => Self::AcpiNvs,
            4 => Self::BadMemory,
            5 => Self::BootloaderReclaimable,
            6 => Self::ExecutableAndModules,
            7 => Self::Framebuffer,
            unknown => Self::Unknown(unknown),
        }
    }
}

/// Unvalidated region fields copied from a boot protocol response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawMemoryRegion {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

/// Validated half-open physical address range `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalRegion {
    start: u64,
    end: u64,
    kind: RegionKind,
}

impl PhysicalRegion {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        kind: RegionKind::Unknown(0),
    };

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn end(&self) -> u64 {
        self.end
    }

    pub const fn length(&self) -> u64 {
        self.end - self.start
    }

    pub const fn kind(&self) -> RegionKind {
        self.kind
    }
}

/// Errors produced when a memory map is malformed or exceeds kernel capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryMapError {
    EmptyMap,
    TooManyRegions,
    EmptyRegion { index: usize },
    AddressOverflow { index: usize },
    OverlappingRegions { first: usize, second: usize },
    UsableTotalOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HhdmAddressError {
    UnknownPhysicalAddressWidth,
    EmptyRange,
    UnalignedRange,
    AddressOverflow,
    NotUsable,
    NotLimineMapped,
    InvalidHhdmRange,
}

/// Validated, allocation-free snapshot of the physical memory map.
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryMap {
    regions: [PhysicalRegion; MAX_MEMORY_REGIONS],
    region_count: usize,
    usable_bytes: u64,
}

impl MemoryMap {
    const EMPTY: Self = Self {
        regions: [PhysicalRegion::EMPTY; MAX_MEMORY_REGIONS],
        region_count: 0,
        usable_bytes: 0,
    };

    pub fn from_raw(regions: &[RawMemoryRegion]) -> Result<Self, MemoryMapError> {
        let mut builder = MemoryMapBuilder::new();
        for region in regions {
            builder.push(region.base, region.length, region.kind)?;
        }
        builder.finish()
    }

    pub fn regions(&self) -> &[PhysicalRegion] {
        &self.regions[..self.region_count]
    }

    pub fn range_is_within_region_kind(&self, start: u64, end: u64, kind: RegionKind) -> bool {
        start < end
            && self
                .regions()
                .iter()
                .any(|region| region.start <= start && end <= region.end && region.kind == kind)
    }

    /// Calculate the Limine base-revision-3 HHDM address of a page-aligned
    /// extent wholly contained in one region that Limine maps into the HHDM.
    ///
    /// This validates metadata and relies on the Limine handoff contract for the
    /// actual mapping; it does not inspect inherited page tables or make the
    /// returned integer safe to dereference by itself.
    pub fn limine_hhdm_address(
        &self,
        hhdm_offset: u64,
        physical_start: u64,
        length: u64,
        physical_address_bits: Option<u8>,
        virtual_address_bits: u8,
    ) -> Result<u64, HhdmAddressError> {
        const PAGE_SIZE: u64 = 4096;

        let physical_address_bits =
            physical_address_bits.ok_or(HhdmAddressError::UnknownPhysicalAddressWidth)?;
        if length == 0 {
            return Err(HhdmAddressError::EmptyRange);
        }
        if (physical_start | length) & (PAGE_SIZE - 1) != 0 {
            return Err(HhdmAddressError::UnalignedRange);
        }
        let physical_end = physical_start
            .checked_add(length)
            .ok_or(HhdmAddressError::AddressOverflow)?;
        if !self.regions().iter().any(|region| {
            region.start <= physical_start
                && physical_end <= region.end
                && region.kind.is_mapped_by_limine_v3_hhdm()
        }) {
            return Err(HhdmAddressError::NotLimineMapped);
        }
        if !limine_v3_hhdm_range_is_valid(
            hhdm_offset,
            physical_start,
            physical_end,
            Some(physical_address_bits),
            virtual_address_bits,
        ) {
            return Err(HhdmAddressError::InvalidHhdmRange);
        }
        hhdm_offset
            .checked_add(physical_start)
            .ok_or(HhdmAddressError::InvalidHhdmRange)
    }

    /// Calculate the HHDM address of a page-aligned extent wholly contained in
    /// validated `Usable` memory.
    pub fn usable_hhdm_address(
        &self,
        hhdm_offset: u64,
        physical_start: u64,
        length: u64,
        physical_address_bits: Option<u8>,
        virtual_address_bits: u8,
    ) -> Result<u64, HhdmAddressError> {
        const PAGE_SIZE: u64 = 4096;

        if length == 0 {
            return Err(HhdmAddressError::EmptyRange);
        }
        if (physical_start | length) & (PAGE_SIZE - 1) != 0 {
            return Err(HhdmAddressError::UnalignedRange);
        }
        let physical_end = physical_start
            .checked_add(length)
            .ok_or(HhdmAddressError::AddressOverflow)?;
        if !self.range_is_within_region_kind(physical_start, physical_end, RegionKind::Usable) {
            return Err(HhdmAddressError::NotUsable);
        }
        self.limine_hhdm_address(
            hhdm_offset,
            physical_start,
            length,
            physical_address_bits,
            virtual_address_bits,
        )
    }

    pub const fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }
}

/// Incremental validator used to copy loader entries without an intermediate heap.
pub struct MemoryMapBuilder {
    map: MemoryMap,
}

impl MemoryMapBuilder {
    pub const fn new() -> Self {
        Self {
            map: MemoryMap::EMPTY,
        }
    }

    pub fn push(&mut self, base: u64, length: u64, raw_kind: u64) -> Result<(), MemoryMapError> {
        let index = self.map.region_count;
        if index == MAX_MEMORY_REGIONS {
            return Err(MemoryMapError::TooManyRegions);
        }
        if length == 0 {
            return Err(MemoryMapError::EmptyRegion { index });
        }
        let end = base
            .checked_add(length)
            .ok_or(MemoryMapError::AddressOverflow { index })?;
        let kind = RegionKind::from_limine(raw_kind);

        for (other_index, other) in self.map.regions().iter().enumerate() {
            if base < other.end && other.start < end {
                return Err(MemoryMapError::OverlappingRegions {
                    first: other_index,
                    second: index,
                });
            }
        }

        let usable_bytes = if kind == RegionKind::Usable {
            self.map
                .usable_bytes
                .checked_add(length)
                .ok_or(MemoryMapError::UsableTotalOverflow)?
        } else {
            self.map.usable_bytes
        };

        self.map.regions[index] = PhysicalRegion {
            start: base,
            end,
            kind,
        };
        self.map.region_count += 1;
        self.map.usable_bytes = usable_bytes;
        Ok(())
    }

    pub fn finish(self) -> Result<MemoryMap, MemoryMapError> {
        if self.map.region_count == 0 {
            Err(MemoryMapError::EmptyMap)
        } else {
            Ok(self.map)
        }
    }
}

impl Default for MemoryMapBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Add an already-validated usable region length to a running total.
///
/// Non-usable regions leave the total unchanged. `None` signals arithmetic
/// overflow so callers can report malformed or unrepresentable maps.
pub const fn add_usable_bytes(total: u64, region_kind: u64, region_length: u64) -> Option<u64> {
    if region_kind == MEMORY_MAP_USABLE {
        total.checked_add(region_length)
    } else {
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use super::{
        add_usable_bytes, is_canonical_virtual_address, kernel_image_physical_end,
        kernel_image_segments, limine_v3_hhdm_range_is_valid, limine_x86_64_stack_bounds,
        physical_range_fits_address_width, HhdmAddressError, KernelImageSegment,
        KernelImageSegments, KernelImageVirtualSegments, MemoryMap, MemoryMapBuilder,
        MemoryMapError, RawMemoryRegion, RegionKind, LIMINE_X86_64_MIN_STACK_SIZE,
        MAX_MEMORY_REGIONS, MEMORY_MAP_USABLE,
    };

    #[test]
    fn canonical_virtual_addresses_follow_the_selected_width() {
        assert!(is_canonical_virtual_address(0x0000_7fff_ffff_ffff, 48));
        assert!(!is_canonical_virtual_address(0x0000_8000_0000_0000, 48));
        assert!(is_canonical_virtual_address(0xffff_8000_0000_0000, 48));
        assert!(!is_canonical_virtual_address(0xffff_7fff_ffff_ffff, 48));

        assert!(is_canonical_virtual_address(0x00ff_ffff_ffff_ffff, 57));
        assert!(!is_canonical_virtual_address(0x0100_0000_0000_0000, 57));
        assert!(is_canonical_virtual_address(0xff00_0000_0000_0000, 57));
        assert!(!is_canonical_virtual_address(0xfeff_ffff_ffff_ffff, 57));
        assert!(!is_canonical_virtual_address(0, 0));
        assert!(!is_canonical_virtual_address(0, 65));
    }

    #[test]
    fn physical_ranges_fit_the_reported_address_width() {
        assert!(physical_range_fits_address_width(0x1000, 1 << 40, 40));
        assert!(!physical_range_fits_address_width(
            0x1000,
            (1 << 40) + 1,
            40
        ));
        assert!(!physical_range_fits_address_width(1, 1, 40));
        assert!(!physical_range_fits_address_width(0, 1, 0));
        assert!(!physical_range_fits_address_width(0, 1, 65));
        assert!(physical_range_fits_address_width(
            u64::MAX - 1,
            u64::MAX,
            64
        ));
    }

    #[test]
    fn relocates_and_validates_the_linker_defined_kernel_image_span() {
        let virtual_base = 0xffff_ffff_8000_0000;
        let virtual_end = 0xffff_ffff_8002_5050;
        assert_eq!(
            kernel_image_physical_end(
                0x0fee_3000,
                virtual_base,
                virtual_base,
                virtual_end,
                Some(40),
                48,
            ),
            Some(0x0ff0_8050)
        );
        assert_eq!(
            kernel_image_physical_end(
                0x1000,
                virtual_base + 0x1000,
                virtual_base,
                virtual_end,
                Some(40),
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_physical_end(0x1000, virtual_base, virtual_base, virtual_base, None, 48),
            None
        );
        assert_eq!(
            kernel_image_physical_end(
                0xffff_ffff_ffff_f000,
                virtual_base,
                virtual_base,
                virtual_base + 0x2000,
                None,
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_physical_end(
                0x1001,
                virtual_base,
                virtual_base,
                virtual_base + 0x1000,
                None,
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_physical_end(
                (1 << 40) - 0x1000,
                virtual_base,
                virtual_base,
                virtual_base + 0x2000,
                Some(40),
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_physical_end(
                0x1000,
                0x0000_7fff_ffff_f000,
                0x0000_7fff_ffff_f000,
                0xffff_8000_0000_1000,
                None,
                48,
            ),
            None
        );
    }

    #[test]
    fn validates_and_relocates_page_aligned_kernel_load_segments() {
        let virtual_start = 0xffff_ffff_8000_0000;
        let virtual_end = 0xffff_ffff_8000_5050;
        let segments = kernel_image_segments(
            0x20_0000,
            virtual_start,
            virtual_start,
            virtual_end,
            KernelImageVirtualSegments {
                text: (virtual_start, virtual_start + 0x2000),
                rodata: (virtual_start + 0x2000, virtual_start + 0x4000),
                data: (virtual_start + 0x4000, virtual_start + 0x6000),
            },
            Some(40),
            48,
        )
        .unwrap();

        assert_eq!(
            segments,
            KernelImageSegments {
                text: KernelImageSegment {
                    virtual_start,
                    virtual_end: virtual_start + 0x2000,
                    physical_start: 0x20_0000,
                    physical_end: 0x20_2000,
                },
                rodata: KernelImageSegment {
                    virtual_start: virtual_start + 0x2000,
                    virtual_end: virtual_start + 0x4000,
                    physical_start: 0x20_2000,
                    physical_end: 0x20_4000,
                },
                data: KernelImageSegment {
                    virtual_start: virtual_start + 0x4000,
                    virtual_end: virtual_start + 0x6000,
                    physical_start: 0x20_4000,
                    physical_end: 0x20_6000,
                },
            }
        );
    }

    #[test]
    fn rejects_invalid_page_aligned_kernel_load_segments() {
        let virtual_start = 0xffff_ffff_8000_0000;
        let virtual_end = virtual_start + 0x5050;
        let valid = KernelImageVirtualSegments {
            text: (virtual_start, virtual_start + 0x2000),
            rodata: (virtual_start + 0x2000, virtual_start + 0x4000),
            data: (virtual_start + 0x4000, virtual_start + 0x6000),
        };
        assert_eq!(
            kernel_image_segments(
                0x20_0000,
                virtual_start,
                virtual_start,
                virtual_end,
                KernelImageVirtualSegments {
                    rodata: (virtual_start + 0x3000, virtual_start + 0x4000),
                    ..valid
                },
                Some(40),
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_segments(
                0x20_0000,
                virtual_start,
                virtual_start,
                virtual_end,
                KernelImageVirtualSegments {
                    text: (virtual_start, virtual_start + 0x2001),
                    rodata: (virtual_start + 0x2001, virtual_start + 0x4000),
                    ..valid
                },
                Some(40),
                48,
            ),
            None
        );
        assert_eq!(
            kernel_image_segments(
                0x20_0000,
                virtual_start,
                virtual_start,
                virtual_end,
                KernelImageVirtualSegments {
                    data: (virtual_start + 0x4000, virtual_start + 0x5000),
                    ..valid
                },
                Some(40),
                48,
            ),
            None
        );
    }

    #[test]
    fn derives_protocol_guaranteed_initial_stack_bounds() {
        let entry_rsp = 0xffff_8000_0001_fff8;
        assert_eq!(
            limine_x86_64_stack_bounds(entry_rsp, 48, LIMINE_X86_64_MIN_STACK_SIZE),
            Some((0xffff_8000_0001_0000, 0xffff_8000_0002_0000))
        );
        assert_eq!(
            limine_x86_64_stack_bounds(0x0000_7fff_ffff_fff8, 48, LIMINE_X86_64_MIN_STACK_SIZE,),
            Some((0x0000_7fff_ffff_0000, 0x0000_8000_0000_0000))
        );
        assert_eq!(
            limine_x86_64_stack_bounds(entry_rsp, 57, LIMINE_X86_64_MIN_STACK_SIZE),
            Some((0xffff_8000_0001_0000, 0xffff_8000_0002_0000))
        );
        assert_eq!(
            limine_x86_64_stack_bounds(entry_rsp, 48, LIMINE_X86_64_MIN_STACK_SIZE - 1),
            None
        );
        let large_stack_top = 0xffff_8000_0006_0000;
        assert_eq!(
            limine_x86_64_stack_bounds(large_stack_top - 8, 48, 256 * 1024),
            Some((0xffff_8000_0002_0000, large_stack_top))
        );
        assert_eq!(
            limine_x86_64_stack_bounds(entry_rsp & !0xf, 48, LIMINE_X86_64_MIN_STACK_SIZE),
            None
        );
        assert_eq!(
            limine_x86_64_stack_bounds(u64::MAX - 7, 64, LIMINE_X86_64_MIN_STACK_SIZE),
            None
        );
        assert_eq!(
            limine_x86_64_stack_bounds(0x0000_8000_0000_0008, 48, LIMINE_X86_64_MIN_STACK_SIZE),
            None
        );
        assert_eq!(
            limine_x86_64_stack_bounds(0x10008, 48, LIMINE_X86_64_MIN_STACK_SIZE),
            Some((0x10, 0x10010))
        );
    }

    #[test]
    fn validates_page_rounded_limine_hhdm_ranges_without_accessing_them() {
        let offset = 0xffff_8000_0000_0000;
        assert!(limine_v3_hhdm_range_is_valid(
            offset,
            0x1234,
            0x2345,
            Some(40),
            48
        ));
        assert!(limine_v3_hhdm_range_is_valid(
            offset, 0x1234, 0x2345, None, 48
        ));
        assert!(!limine_v3_hhdm_range_is_valid(
            offset,
            0x1234,
            (1 << 40) + 1,
            Some(40),
            48
        ));
        assert!(!limine_v3_hhdm_range_is_valid(
            u64::MAX - 0x0fff,
            0x1000,
            0x2000,
            None,
            48
        ));
        assert!(!limine_v3_hhdm_range_is_valid(
            0x0000_8000_0000_0000,
            0x1000,
            0x2000,
            None,
            48
        ));
        assert!(!limine_v3_hhdm_range_is_valid(
            0,
            0x0000_7fff_ffff_f000,
            0x0000_8000_0000_1000,
            Some(64),
            48
        ));
        assert!(!limine_v3_hhdm_range_is_valid(
            offset, 0x1000, 0x2000, None, 46
        ));
    }

    #[test]
    fn calculates_usable_hhdm_addresses_only_for_validated_owned_ranges() {
        let map = MemoryMap::from_raw(&[
            RawMemoryRegion {
                base: 0x10_0000,
                length: 0x3000,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x10_3000,
                length: 0x1000,
                kind: 1,
            },
        ])
        .unwrap();
        let offset = 0xffff_8000_0000_0000;

        assert_eq!(
            map.usable_hhdm_address(offset, 0x10_1000, 0x1000, Some(40), 48),
            Ok(offset + 0x10_1000)
        );
        assert_eq!(
            map.usable_hhdm_address(offset, 0x10_3000, 0x1000, Some(40), 48),
            Err(HhdmAddressError::NotUsable)
        );
        assert_eq!(
            map.usable_hhdm_address(offset, 0x10_0001, 0x1000, Some(40), 48),
            Err(HhdmAddressError::UnalignedRange)
        );
        assert_eq!(
            map.usable_hhdm_address(offset, 0x10_0000, 0, Some(40), 48),
            Err(HhdmAddressError::EmptyRange)
        );
        assert_eq!(
            map.usable_hhdm_address(offset, 0x10_0000, 0x1000, None, 48),
            Err(HhdmAddressError::UnknownPhysicalAddressWidth)
        );
        assert_eq!(
            map.usable_hhdm_address(offset, u64::MAX & !0xfff, 0x1000, Some(64), 48),
            Err(HhdmAddressError::AddressOverflow)
        );
        assert_eq!(
            map.usable_hhdm_address(0x0000_8000_0000_0000, 0x10_0000, 0x1000, Some(40), 48),
            Err(HhdmAddressError::InvalidHhdmRange)
        );
    }

    #[test]
    fn classifies_limine_v3_hhdm_region_types() {
        assert!(RegionKind::Usable.is_mapped_by_limine_v3_hhdm());
        assert!(RegionKind::BootloaderReclaimable.is_mapped_by_limine_v3_hhdm());
        assert!(RegionKind::ExecutableAndModules.is_mapped_by_limine_v3_hhdm());
        assert!(RegionKind::Framebuffer.is_mapped_by_limine_v3_hhdm());
        assert!(!RegionKind::Reserved.is_mapped_by_limine_v3_hhdm());
        assert!(!RegionKind::AcpiReclaimable.is_mapped_by_limine_v3_hhdm());
        assert!(!RegionKind::AcpiNvs.is_mapped_by_limine_v3_hhdm());
        assert!(!RegionKind::BadMemory.is_mapped_by_limine_v3_hhdm());
        assert!(!RegionKind::Unknown(99).is_mapped_by_limine_v3_hhdm());
    }

    #[test]
    fn counts_only_usable_regions() {
        assert_eq!(add_usable_bytes(4096, MEMORY_MAP_USABLE, 2048), Some(6144));
        assert_eq!(add_usable_bytes(4096, 1, 2048), Some(4096));
    }

    #[test]
    fn reports_total_overflow() {
        assert_eq!(add_usable_bytes(u64::MAX - 4, MEMORY_MAP_USABLE, 8), None);
    }

    #[test]
    fn validates_ranges_and_preserves_all_region_kinds() {
        let raw = [
            RawMemoryRegion {
                base: 0x1000,
                length: 0x2000,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x4000,
                length: 0x1000,
                kind: 5,
            },
            RawMemoryRegion {
                base: 0x5000,
                length: 0x1000,
                kind: 99,
            },
        ];
        let map = MemoryMap::from_raw(&raw).unwrap();

        assert_eq!(map.usable_bytes(), 0x2000);
        assert_eq!(map.regions()[0].start(), 0x1000);
        assert_eq!(map.regions()[0].end(), 0x3000);
        assert_eq!(map.regions()[0].length(), 0x2000);
        assert_eq!(map.regions()[0].kind(), RegionKind::Usable);
        assert_eq!(map.regions()[1].kind(), RegionKind::BootloaderReclaimable);
        assert_eq!(map.regions()[2].kind(), RegionKind::Unknown(99));
    }

    #[test]
    fn rejects_empty_zero_length_overflowing_and_overlapping_maps() {
        assert_eq!(MemoryMap::from_raw(&[]), Err(MemoryMapError::EmptyMap));
        assert_eq!(
            MemoryMap::from_raw(&[RawMemoryRegion {
                base: 0,
                length: 0,
                kind: 0
            }]),
            Err(MemoryMapError::EmptyRegion { index: 0 })
        );
        let overflowing = [RawMemoryRegion {
            base: u64::MAX - 3,
            length: 8,
            kind: 0,
        }];
        assert_eq!(
            MemoryMap::from_raw(&overflowing),
            Err(MemoryMapError::AddressOverflow { index: 0 })
        );

        let overlap = [
            RawMemoryRegion {
                base: 0x1000,
                length: 0x2000,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x2fff,
                length: 0x1000,
                kind: 1,
            },
        ];
        assert_eq!(
            MemoryMap::from_raw(&overlap),
            Err(MemoryMapError::OverlappingRegions {
                first: 0,
                second: 1
            })
        );
    }

    #[test]
    fn checks_that_a_range_is_contained_in_one_memory_region_kind() {
        let map = MemoryMap::from_raw(&[
            RawMemoryRegion {
                base: 0x1000,
                length: 0x10000,
                kind: 5,
            },
            RawMemoryRegion {
                base: 0x20000,
                length: 0x1000,
                kind: 1,
            },
        ])
        .unwrap();
        assert!(map.range_is_within_region_kind(0x2000, 0x8000, RegionKind::BootloaderReclaimable));
        assert!(!map.range_is_within_region_kind(
            0x1000,
            0x20000,
            RegionKind::BootloaderReclaimable
        ));
        assert!(!map.range_is_within_region_kind(0x2000, 0x8000, RegionKind::Usable));
    }

    #[test]
    fn accepts_adjacent_ranges_and_rejects_excess_entries() {
        let adjacent = [
            RawMemoryRegion {
                base: 0x1000,
                length: 0x1000,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x2000,
                length: 0x1000,
                kind: 1,
            },
        ];
        assert!(MemoryMap::from_raw(&adjacent).is_ok());

        let mut builder = MemoryMapBuilder::new();
        for index in 0..MAX_MEMORY_REGIONS {
            builder.push((index as u64) * 0x2000, 0x1000, 1).unwrap();
        }
        assert_eq!(
            builder.push(0x1_0000_0000, 0x1000, 1),
            Err(MemoryMapError::TooManyRegions)
        );
    }
}
