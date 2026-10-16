//! Architecture-independent validation and accounting for physical memory maps.

/// Limine's memory-map type for ordinary usable RAM.
pub const MEMORY_MAP_USABLE: u64 = 0;
/// Maximum number of memory regions retained in the boot snapshot.
pub const MAX_MEMORY_REGIONS: usize = 256;

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
        add_usable_bytes, MemoryMap, MemoryMapBuilder, MemoryMapError, RawMemoryRegion, RegionKind,
        MAX_MEMORY_REGIONS, MEMORY_MAP_USABLE,
    };

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
