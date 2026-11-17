//! Fixed-capacity physical frame allocator built from validated memory regions.
//!
//! This module assigns physical frame addresses only. It does not map or access
//! them, and it never promotes loader- or firmware-reclaimable memory to free RAM.

use crate::memory::{HhdmAddressError, MemoryMap, RegionKind, MAX_MEMORY_REGIONS};

/// The current x86_64 base page size used by Rustix.
pub const FRAME_SIZE: u64 = 4096;
/// Keep the first MiB unavailable even if a loader labels it usable.
pub const LOW_MEMORY_RESERVED_END: u64 = 0x10_0000;
/// Maximum number of disjoint ranges kept in each fixed range table.
pub const MAX_FRAME_RANGES: usize = MAX_MEMORY_REGIONS;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame(u64);

impl Frame {
    /// Physical address of the beginning of this frame.
    pub const fn address(&self) -> u64 {
        self.0
    }

    /// Calculate this owned frame's Limine HHDM address from validated metadata.
    ///
    /// This returns a numeric address only. Dereferencing it still relies on the
    /// Limine base-revision-3 HHDM guarantee and a narrow unsafe access boundary.
    pub fn hhdm_address(
        &self,
        memory_map: &MemoryMap,
        hhdm_offset: u64,
        physical_address_bits: Option<u8>,
        virtual_address_bits: u8,
    ) -> Result<u64, HhdmAddressError> {
        memory_map.usable_hhdm_address(
            hhdm_offset,
            self.0,
            FRAME_SIZE,
            physical_address_bits,
            virtual_address_bits,
        )
    }

    #[cfg(test)]
    const fn from_address(address: u64) -> Self {
        Self(address)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    RangeTableFull,
    RangeOverlap,
    UnalignedFrame,
    NotManaged,
    AlreadyFree,
    AccountingOverflow,
    /// A half-open exclusion span was empty, inverted, or exceeded the
    /// supported exclusion count.
    InvalidExclusion,
}

/// A rejected deallocation that returns ownership of the frame to the caller.
#[derive(Debug, PartialEq, Eq)]
pub struct DeallocationError {
    pub error: FrameError,
    pub frame: Frame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameRange {
    start: u64,
    end: u64,
}

impl FrameRange {
    const EMPTY: Self = Self { start: 0, end: 0 };
}

/// A bounded allocator over only validated `Usable` memory-map ranges.
///
/// For a given physical map, callers must use only one allocator instance as
/// the allocation authority; the type does not enforce this uniqueness. Within
/// that instance, each eligible frame is owned by the allocator while free, or
/// by the non-copyable `Frame` token returned by `allocate` while allocated. A
/// frame address is an identifier only; this allocator does not map or access it.
/// Both range tables are sorted, disjoint, page-aligned half-open ranges. The
/// allocator returns `None` on frame exhaustion and reports metadata exhaustion
/// explicitly without changing state or consuming the caller's frame token.
pub struct FrameAllocator {
    managed: [FrameRange; MAX_FRAME_RANGES],
    managed_count: usize,
    free: [FrameRange; MAX_FRAME_RANGES],
    free_count: usize,
    managed_frames: u64,
    free_frames: u64,
}

impl FrameAllocator {
    const EMPTY: Self = Self {
        managed: [FrameRange::EMPTY; MAX_FRAME_RANGES],
        managed_count: 0,
        free: [FrameRange::EMPTY; MAX_FRAME_RANGES],
        free_count: 0,
        managed_frames: 0,
        free_frames: 0,
    };

    /// Build allocator metadata without allocating or touching physical memory.
    ///
    /// The caller must ensure there is only one allocator instance per physical
    /// map; constructing multiple instances would duplicate allocation authority.
    pub fn from_memory_map(map: &MemoryMap) -> Result<Self, FrameError> {
        Self::from_memory_map_excluding(map, &[])
    }

    /// Build allocator metadata like [`Self::from_memory_map`], additionally
    /// excluding half-open physical spans that must never be handed out as free
    /// frames.
    ///
    /// This exists to defend the kernel against a loader that mislabels
    /// kernel-owned pages (for example the kernel image or the boot stack) as
    /// `Usable`; such spans are subtracted from every otherwise-usable region
    /// before frames are accounted. Up to seven exclusions are supported;
    /// each must satisfy `start < end` with checked arithmetic.
    pub fn from_memory_map_excluding(
        map: &MemoryMap,
        exclusions: &[(u64, u64)],
    ) -> Result<Self, FrameError> {
        const MAX_EXCLUSIONS: usize = 7;
        const MAX_PIECES: usize = MAX_EXCLUSIONS + 1;

        if exclusions.len() > MAX_EXCLUSIONS {
            return Err(FrameError::RangeTableFull);
        }
        for &(start, end) in exclusions {
            if start >= end {
                return Err(FrameError::InvalidExclusion);
            }
        }

        let mut allocator = Self::EMPTY;
        let page_mask = !(FRAME_SIZE - 1);

        for region in map.regions() {
            if region.kind() != RegionKind::Usable {
                continue;
            }

            let region_start = region.start().max(LOW_MEMORY_RESERVED_END);
            let region_end = region.end();

            let mut pieces = [(0u64, 0u64); MAX_PIECES];
            pieces[0] = (region_start, region_end);
            let mut piece_count = 1usize;
            for &(exclusion_start, exclusion_end) in exclusions {
                let mut next = [(0u64, 0u64); MAX_PIECES];
                let mut next_count = 0usize;
                for &(piece_start, piece_end) in pieces.iter().take(piece_count) {
                    if exclusion_end <= piece_start || exclusion_start >= piece_end {
                        next[next_count] = (piece_start, piece_end);
                        next_count += 1;
                        continue;
                    }
                    if piece_start < exclusion_start && next_count < MAX_PIECES {
                        next[next_count] = (piece_start, exclusion_start);
                        next_count += 1;
                    }
                    if exclusion_end < piece_end && next_count < MAX_PIECES {
                        next[next_count] = (exclusion_end, piece_end);
                        next_count += 1;
                    }
                }
                pieces[..next_count].copy_from_slice(&next[..next_count]);
                piece_count = next_count;
            }

            for &(piece_start, piece_end) in pieces.iter().take(piece_count) {
                let Some(start) = piece_start
                    .checked_add(FRAME_SIZE - 1)
                    .map(|address| address & page_mask)
                else {
                    continue;
                };
                let end = piece_end & page_mask;
                if start >= end {
                    continue;
                }

                let range = FrameRange { start, end };
                Self::insert_range(&mut allocator.managed, &mut allocator.managed_count, range)?;
                Self::insert_range(&mut allocator.free, &mut allocator.free_count, range)?;

                let frames = (end - start) / FRAME_SIZE;
                allocator.managed_frames = allocator
                    .managed_frames
                    .checked_add(frames)
                    .ok_or(FrameError::AccountingOverflow)?;
                allocator.free_frames = allocator
                    .free_frames
                    .checked_add(frames)
                    .ok_or(FrameError::AccountingOverflow)?;
            }
        }

        Ok(allocator)
    }

    /// Number of complete frames inside eligible usable regions.
    pub const fn managed_frames(&self) -> u64 {
        self.managed_frames
    }

    /// Number of currently unallocated frames.
    pub const fn free_frames(&self) -> u64 {
        self.free_frames
    }

    /// Allocate the lowest-address available frame, or return `None` on exhaustion.
    pub fn allocate(&mut self) -> Option<Frame> {
        if self.free_count == 0 {
            return None;
        }

        let address = self.free[0].start;
        self.free[0].start += FRAME_SIZE;
        debug_assert!(self.free_frames > 0);
        self.free_frames = self.free_frames.saturating_sub(1);
        if self.free[0].start == self.free[0].end {
            Self::remove_range(&mut self.free, &mut self.free_count, 0);
        }
        Some(Frame(address))
    }

    /// Return a frame to the allocator, merging adjacent free ranges.
    ///
    /// On error, the returned `DeallocationError` retains the frame token so the
    /// caller can retry or otherwise preserve ownership. Failed returns do not
    /// change allocator state.
    pub fn deallocate(&mut self, frame: Frame) -> Result<(), DeallocationError> {
        let address = frame.address();
        if address & (FRAME_SIZE - 1) != 0 {
            return Err(DeallocationError {
                error: FrameError::UnalignedFrame,
                frame,
            });
        }
        let Some(end) = address.checked_add(FRAME_SIZE) else {
            return Err(DeallocationError {
                error: FrameError::NotManaged,
                frame,
            });
        };
        if !self
            .managed
            .iter()
            .take(self.managed_count)
            .any(|range| range.start <= address && end <= range.end)
        {
            return Err(DeallocationError {
                error: FrameError::NotManaged,
                frame,
            });
        }
        if self
            .free
            .iter()
            .take(self.free_count)
            .any(|range| address < range.end && range.start < end)
        {
            return Err(DeallocationError {
                error: FrameError::AlreadyFree,
                frame,
            });
        }

        let Some(new_free_count) = self.free_frames.checked_add(1) else {
            return Err(DeallocationError {
                error: FrameError::AccountingOverflow,
                frame,
            });
        };
        if let Err(error) = Self::insert_range(
            &mut self.free,
            &mut self.free_count,
            FrameRange {
                start: address,
                end,
            },
        ) {
            return Err(DeallocationError { error, frame });
        }
        self.free_frames = new_free_count;
        Ok(())
    }

    fn insert_range(
        ranges: &mut [FrameRange; MAX_FRAME_RANGES],
        count: &mut usize,
        incoming: FrameRange,
    ) -> Result<(), FrameError> {
        let mut index = 0;
        while index < *count && ranges[index].start < incoming.start {
            index += 1;
        }

        if (index > 0 && ranges[index - 1].end > incoming.start)
            || (index < *count && incoming.end > ranges[index].start)
        {
            return Err(FrameError::RangeOverlap);
        }

        let joins_previous = index > 0 && ranges[index - 1].end == incoming.start;
        let joins_next = index < *count && incoming.end == ranges[index].start;
        match (joins_previous, joins_next) {
            (true, true) => {
                ranges[index - 1].end = ranges[index].end;
                Self::remove_range(ranges, count, index);
            }
            (true, false) => ranges[index - 1].end = incoming.end,
            (false, true) => ranges[index].start = incoming.start,
            (false, false) => {
                if *count == MAX_FRAME_RANGES {
                    return Err(FrameError::RangeTableFull);
                }
                for move_index in (index..*count).rev() {
                    ranges[move_index + 1] = ranges[move_index];
                }
                ranges[index] = incoming;
                *count += 1;
            }
        }
        Ok(())
    }

    fn remove_range(ranges: &mut [FrameRange; MAX_FRAME_RANGES], count: &mut usize, index: usize) {
        for move_index in index..(*count - 1) {
            ranges[move_index] = ranges[move_index + 1];
        }
        debug_assert!(*count > 0);
        *count -= 1;
        ranges[*count] = FrameRange::EMPTY;
    }
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use super::{
        DeallocationError, Frame, FrameAllocator, FrameError, FRAME_SIZE, LOW_MEMORY_RESERVED_END,
        MAX_FRAME_RANGES,
    };
    use crate::memory::{MemoryMap, RawMemoryRegion};

    fn allocator_for(regions: &[RawMemoryRegion]) -> FrameAllocator {
        let map = MemoryMap::from_raw(regions).unwrap();
        FrameAllocator::from_memory_map(&map).unwrap()
    }

    #[test]
    fn aligns_usable_ranges_and_ignores_reserved_regions() {
        let regions = [
            RawMemoryRegion {
                base: 0x10_0003,
                length: 0x5000,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x10_8000,
                length: 0x2000,
                kind: 1,
            },
            RawMemoryRegion {
                base: 0x11_0000,
                length: 0x1000,
                kind: 0,
            },
        ];
        let map = MemoryMap::from_raw(&regions).unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&map).unwrap();

        assert_eq!(allocator.managed_frames(), 5);
        assert_eq!(allocator.free_frames(), 5);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_1000);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_2000);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_3000);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_4000);
        assert_eq!(allocator.allocate().unwrap().address(), 0x11_0000);
        assert_eq!(allocator.allocate(), None);
        assert_eq!(allocator.free_frames(), 0);
    }

    #[test]
    fn translates_only_allocator_owned_frames_inside_usable_ranges() {
        let regions = [RawMemoryRegion {
            base: 0x10_0000,
            length: FRAME_SIZE * 2,
            kind: 0,
        }];
        let map = MemoryMap::from_raw(&regions).unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&map).unwrap();
        let frame = allocator.allocate().unwrap();
        let hhdm_offset = 0xffff_8000_0000_0000;

        assert_eq!(
            frame.hhdm_address(&map, hhdm_offset, Some(40), 48),
            Ok(hhdm_offset + frame.address())
        );
    }

    #[test]
    fn reserves_low_memory_and_discards_partial_pages() {
        let regions = [RawMemoryRegion {
            base: 0,
            length: 0x20_0064,
            kind: 0,
        }];
        let mut allocator = allocator_for(&regions);

        assert_eq!(allocator.managed_frames(), 256);
        assert_eq!(allocator.free_frames(), 256);
        assert_eq!(
            allocator.allocate().unwrap().address(),
            LOW_MEMORY_RESERVED_END
        );
    }

    #[test]
    fn deallocation_rejects_bad_frames_and_coalesces_neighbors() {
        let regions = [RawMemoryRegion {
            base: 0x10_0000,
            length: FRAME_SIZE * 4,
            kind: 0,
        }];
        let mut allocator = allocator_for(&regions);
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        let third = allocator.allocate().unwrap();

        assert_eq!(
            allocator.deallocate(Frame::from_address(first.address() + 1)),
            Err(DeallocationError {
                error: FrameError::UnalignedFrame,
                frame: Frame::from_address(first.address() + 1),
            })
        );
        assert_eq!(
            allocator.deallocate(Frame::from_address(0x20_0000)),
            Err(DeallocationError {
                error: FrameError::NotManaged,
                frame: Frame::from_address(0x20_0000),
            })
        );

        allocator.deallocate(second).unwrap();
        allocator.deallocate(third).unwrap();
        allocator.deallocate(first).unwrap();
        assert_eq!(allocator.free_frames(), 4);
        let reused = allocator.allocate().unwrap();
        assert_eq!(reused.address(), 0x10_0000);
        allocator.deallocate(reused).unwrap();
        assert_eq!(
            allocator.deallocate(Frame::from_address(0x10_0000)),
            Err(DeallocationError {
                error: FrameError::AlreadyFree,
                frame: Frame::from_address(0x10_0000),
            })
        );
    }

    #[test]
    fn failed_deallocation_preserves_free_ranges_and_returns_frame_tokens() {
        let regions = [RawMemoryRegion {
            base: 0x10_0000,
            length: FRAME_SIZE * 4,
            kind: 0,
        }];
        let mut allocator = allocator_for(&regions);
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        assert_eq!(first.address(), 0x10_0000);
        assert_eq!(second.address(), 0x10_1000);

        for (frame, expected_error) in [
            (
                Frame::from_address(first.address() + 1),
                FrameError::UnalignedFrame,
            ),
            (Frame::from_address(0x20_0000), FrameError::NotManaged),
            (Frame::from_address(0x10_2000), FrameError::AlreadyFree),
        ] {
            let address = frame.address();
            let error = allocator.deallocate(frame).unwrap_err();
            assert_eq!(error.error, expected_error);
            assert_eq!(error.frame.address(), address);
            assert_eq!(allocator.free_frames(), 2);
        }

        let next = allocator.allocate().unwrap();
        assert_eq!(next.address(), 0x10_2000);
        assert_eq!(allocator.free_frames(), 1);
        allocator.deallocate(next).unwrap();
        assert_eq!(allocator.free_frames(), 2);
    }

    #[test]
    fn adjacent_usable_ranges_are_coalesced() {
        let regions = [
            RawMemoryRegion {
                base: 0x10_0000,
                length: FRAME_SIZE,
                kind: 0,
            },
            RawMemoryRegion {
                base: 0x10_1000,
                length: FRAME_SIZE,
                kind: 0,
            },
        ];
        let mut allocator = allocator_for(&regions);

        assert_eq!(allocator.managed_frames(), 2);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_0000);
        assert_eq!(allocator.allocate().unwrap().address(), 0x10_1000);
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn exclusion_spans_are_subtracted_before_frames_are_accounted() {
        let regions = [RawMemoryRegion {
            base: 0x10_0000,
            length: FRAME_SIZE * 8,
            kind: 0,
        }];
        let map = MemoryMap::from_raw(&regions).unwrap();
        // Exclude the second and third pages entirely.
        let allocator =
            FrameAllocator::from_memory_map_excluding(&map, &[(0x10_1000, 0x10_3000)]).unwrap();
        assert_eq!(allocator.managed_frames(), 6);
        assert_eq!(allocator.free_frames(), 6);

        // Exclude a non-page-aligned span; page-granularity truncation must not
        // allocate any frame that overlaps the exclusion.
        let allocator =
            FrameAllocator::from_memory_map_excluding(&map, &[(0x10_1234, 0x10_5678)]).unwrap();
        let mut allocated = allocator;
        while let Some(frame) = allocated.allocate() {
            let frame_end = frame.address().checked_add(FRAME_SIZE).unwrap();
            assert!(
                frame_end <= 0x10_1234 || 0x10_5678 <= frame.address(),
                "frame at {:#x} overlaps the exclusion",
                frame.address()
            );
        }
        // An exclusion covering the whole region leaves no allocatable frame.
        let allocator =
            FrameAllocator::from_memory_map_excluding(&map, &[(0x10_0000, 0x18_0000)]).unwrap();
        assert_eq!(allocator.managed_frames(), 0);

        // Invalid exclusions and too many exclusions are rejected.
        assert!(matches!(
            FrameAllocator::from_memory_map_excluding(&map, &[(0x4000, 0x4000)]),
            Err(FrameError::InvalidExclusion)
        ));
        let many = [(0x20_0000u64, 0x20_1000u64); 8];
        assert!(matches!(
            FrameAllocator::from_memory_map_excluding(&map, &many),
            Err(FrameError::RangeTableFull)
        ));
    }

    #[test]
    fn fragmentation_is_bounded_by_the_fixed_range_table() {
        let frame_count = MAX_FRAME_RANGES * 2 + 1;
        let regions = [RawMemoryRegion {
            base: 0x10_0000,
            length: FRAME_SIZE * frame_count as u64,
            kind: 0,
        }];
        let mut allocator = allocator_for(&regions);
        let mut allocated: [Frame; MAX_FRAME_RANGES * 2 + 1] =
            core::array::from_fn(|_| Frame::from_address(0));

        for frame in &mut allocated {
            *frame = allocator.allocate().unwrap();
        }
        let mut rejected = None;
        for index in (0..allocated.len()).step_by(2) {
            let frame = core::mem::replace(&mut allocated[index], Frame::from_address(0));
            let result = allocator.deallocate(frame);
            if index == MAX_FRAME_RANGES * 2 {
                let error = result.unwrap_err();
                assert_eq!(error.error, FrameError::RangeTableFull);
                assert_eq!(error.frame.address(), 0x10_0000 + index as u64 * FRAME_SIZE);
                assert_eq!(allocator.free_frames(), MAX_FRAME_RANGES as u64);
                rejected = Some(error.frame);
            } else {
                assert_eq!(result, Ok(()));
            }
        }

        let neighbor = core::mem::replace(
            &mut allocated[MAX_FRAME_RANGES * 2 - 1],
            Frame::from_address(0),
        );
        allocator.deallocate(neighbor).unwrap();
        allocator.deallocate(rejected.unwrap()).unwrap();
        assert_eq!(allocator.free_frames(), MAX_FRAME_RANGES as u64 + 2);
    }
}
