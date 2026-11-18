//! Bounded parser for statically linked x86_64 ELF64 executables.
//!
//! This validates image metadata only. It does not allocate frames, apply
//! relocations, or install mappings into a process address space.

use core::convert::TryFrom;

pub const ELF64_HEADER_SIZE: usize = 64;
pub const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
pub const MAX_ELF_PROGRAM_HEADERS: usize = 64;
pub const MAX_ELF_LOAD_SEGMENTS: usize = 16;
pub const MAX_ELF_LOAD_PAGES: usize = 64;
pub const PAGE_SIZE: u64 = 4096;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_EXECUTE: u32 = 1;
const PF_WRITE: u32 = 2;
const PF_READ: u32 = 4;
const PF_MASK: u32 = PF_EXECUTE | PF_WRITE | PF_READ;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedByteOrder,
    UnsupportedVersion,
    UnsupportedObjectType,
    UnsupportedMachine,
    InvalidAddressWidth,
    InvalidHeaderSize,
    InvalidProgramHeaderSize,
    TooManyProgramHeaders,
    InvalidProgramHeaderTable,
    UnsupportedDynamicSegment,
    UnsupportedTlsSegment,
    ExecutableStackUnsupported,
    UnsupportedSegmentFlags,
    SegmentNotReadable,
    TooManyLoadSegments,
    InvalidSegmentSize,
    InvalidFileRange,
    InvalidVirtualRange,
    InvalidAlignment,
    WritableExecutableSegment,
    OverlappingLoadSegments,
    ImageTooLarge,
    NoLoadSegments,
    EntryNotExecutable,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ElfPagePopulationError<E> {
    InvalidSegment,
    InvalidPage,
    FrameMemory(E),
}

#[derive(Debug, Eq, PartialEq)]
pub enum ElfLoadError<CacheError, TableError, FrameMemoryError> {
    OutOfFrames,
    Mapping(crate::paging::MappingError),
    CachePolicy(CacheError),
    Populate(ElfPagePopulationError<FrameMemoryError>),
    Map(crate::paging::ProcessPageMapError<TableError>),
}

/// A loader failure may leave earlier pages mapped in the inactive process root.
/// The caller owns `frame`, if present, and must reclaim it. Destroy the newly
/// created process root to reclaim `mapped_pages` and any retained page tables.
#[derive(Debug, Eq, PartialEq)]
pub struct ElfLoadFailure<CacheError, TableError, FrameMemoryError> {
    pub cause: ElfLoadError<CacheError, TableError, FrameMemoryError>,
    pub frame: Option<crate::frame::Frame>,
    pub mapped_pages: usize,
    pub rollback_retained_table_frames: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedElf {
    pub entry_point: u64,
    pub mapped_pages: usize,
}

/// One validated, page-aligned PT_LOAD segment in a static executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf64LoadSegment {
    virtual_start: u64,
    virtual_end: u64,
    file_offset: usize,
    file_size: usize,
    memory_size: usize,
    page_end: u64,
    flags: u32,
}

impl Elf64LoadSegment {
    pub const fn virtual_start(self) -> u64 {
        self.virtual_start
    }

    pub const fn virtual_end(self) -> u64 {
        self.virtual_end
    }

    pub const fn file_offset(self) -> usize {
        self.file_offset
    }

    pub const fn file_size(self) -> usize {
        self.file_size
    }

    pub const fn memory_size(self) -> usize {
        self.memory_size
    }

    pub const fn page_end(self) -> u64 {
        self.page_end
    }

    pub const fn page_count(self) -> usize {
        ((self.page_end - self.virtual_start) / PAGE_SIZE) as usize
    }

    pub const fn writable(self) -> bool {
        self.flags & PF_WRITE != 0
    }

    pub const fn executable(self) -> bool {
        self.flags & PF_EXECUTE != 0
    }
}

/// A validated view into a static ELF64 image with fixed-capacity PT_LOAD metadata.
#[derive(Debug, Eq, PartialEq)]
pub struct Elf64Image<'a> {
    bytes: &'a [u8],
    entry_point: u64,
    segments: [Option<Elf64LoadSegment>; MAX_ELF_LOAD_SEGMENTS],
    segment_count: usize,
    load_page_count: usize,
}

impl<'a> Elf64Image<'a> {
    pub fn parse(bytes: &'a [u8], virtual_address_bits: u8) -> Result<Self, ElfError> {
        if bytes.len() < ELF64_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader);
        }
        if bytes.get(0..4) != Some(&b"\x7fELF"[..]) {
            return Err(ElfError::InvalidMagic);
        }
        if bytes[4] != 2 {
            return Err(ElfError::UnsupportedClass);
        }
        if bytes[5] != 1 {
            return Err(ElfError::UnsupportedByteOrder);
        }
        if bytes[6] != 1 || read_u32(bytes, 20) != Some(1) {
            return Err(ElfError::UnsupportedVersion);
        }
        if read_u16(bytes, 16) != Some(ET_EXEC) {
            return Err(ElfError::UnsupportedObjectType);
        }
        if read_u16(bytes, 18) != Some(EM_X86_64) {
            return Err(ElfError::UnsupportedMachine);
        }
        if !matches!(virtual_address_bits, 48 | 57) {
            return Err(ElfError::InvalidAddressWidth);
        }
        if read_u16(bytes, 52) != Some(ELF64_HEADER_SIZE as u16) {
            return Err(ElfError::InvalidHeaderSize);
        }
        if read_u16(bytes, 54) != Some(ELF64_PROGRAM_HEADER_SIZE as u16) {
            return Err(ElfError::InvalidProgramHeaderSize);
        }

        let entry_point = read_u64(bytes, 24).ok_or(ElfError::TruncatedHeader)?;
        let program_header_offset = read_u64(bytes, 32).ok_or(ElfError::TruncatedHeader)?;
        let program_header_count =
            usize::from(read_u16(bytes, 56).ok_or(ElfError::TruncatedHeader)?);
        if program_header_count > MAX_ELF_PROGRAM_HEADERS {
            return Err(ElfError::TooManyProgramHeaders);
        }
        let program_header_offset = usize::try_from(program_header_offset)
            .map_err(|_| ElfError::InvalidProgramHeaderTable)?;
        let program_header_bytes = program_header_count
            .checked_mul(ELF64_PROGRAM_HEADER_SIZE)
            .ok_or(ElfError::InvalidProgramHeaderTable)?;
        let program_header_end = program_header_offset
            .checked_add(program_header_bytes)
            .filter(|end| *end <= bytes.len())
            .ok_or(ElfError::InvalidProgramHeaderTable)?;

        let lower_half_end = 1u64 << (virtual_address_bits - 1);
        let mut image = Self {
            bytes,
            entry_point,
            segments: [None; MAX_ELF_LOAD_SEGMENTS],
            segment_count: 0,
            load_page_count: 0,
        };

        for header_offset in
            (program_header_offset..program_header_end).step_by(ELF64_PROGRAM_HEADER_SIZE)
        {
            let kind = read_u32(bytes, header_offset).ok_or(ElfError::InvalidProgramHeaderTable)?;
            match kind {
                PT_DYNAMIC | PT_INTERP => return Err(ElfError::UnsupportedDynamicSegment),
                PT_TLS => return Err(ElfError::UnsupportedTlsSegment),
                PT_GNU_STACK => {
                    let flags = read_u32(bytes, header_offset + 4)
                        .ok_or(ElfError::InvalidProgramHeaderTable)?;
                    if flags & PF_EXECUTE != 0 {
                        return Err(ElfError::ExecutableStackUnsupported);
                    }
                }
                PT_LOAD => {
                    image.add_load_segment(header_offset, virtual_address_bits, lower_half_end)?
                }
                _ => {}
            }
        }

        if image.segment_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        if !image.segments().any(|segment| {
            segment.executable()
                && !segment.writable()
                && entry_point >= segment.virtual_start
                && entry_point < segment.virtual_end
        }) {
            return Err(ElfError::EntryNotExecutable);
        }
        Ok(image)
    }

    fn add_load_segment(
        &mut self,
        header_offset: usize,
        virtual_address_bits: u8,
        lower_half_end: u64,
    ) -> Result<(), ElfError> {
        if self.segment_count == MAX_ELF_LOAD_SEGMENTS {
            return Err(ElfError::TooManyLoadSegments);
        }
        let flags =
            read_u32(self.bytes, header_offset + 4).ok_or(ElfError::InvalidProgramHeaderTable)?;
        if flags & !PF_MASK != 0 {
            return Err(ElfError::UnsupportedSegmentFlags);
        }
        if flags & PF_READ == 0 {
            return Err(ElfError::SegmentNotReadable);
        }
        if flags & (PF_WRITE | PF_EXECUTE) == (PF_WRITE | PF_EXECUTE) {
            return Err(ElfError::WritableExecutableSegment);
        }

        let file_offset =
            read_u64(self.bytes, header_offset + 8).ok_or(ElfError::InvalidProgramHeaderTable)?;
        let virtual_start =
            read_u64(self.bytes, header_offset + 16).ok_or(ElfError::InvalidProgramHeaderTable)?;
        let file_size =
            read_u64(self.bytes, header_offset + 32).ok_or(ElfError::InvalidProgramHeaderTable)?;
        let memory_size =
            read_u64(self.bytes, header_offset + 40).ok_or(ElfError::InvalidProgramHeaderTable)?;
        let alignment =
            read_u64(self.bytes, header_offset + 48).ok_or(ElfError::InvalidProgramHeaderTable)?;

        if file_size > memory_size {
            return Err(ElfError::InvalidSegmentSize);
        }
        if memory_size == 0 {
            if file_size == 0 {
                return Ok(());
            }
            return Err(ElfError::InvalidSegmentSize);
        }
        if (file_offset | virtual_start) & (PAGE_SIZE - 1) != 0 {
            return Err(ElfError::InvalidAlignment);
        }
        if alignment > 1
            && (!alignment.is_power_of_two()
                || file_offset % alignment != virtual_start % alignment)
        {
            return Err(ElfError::InvalidAlignment);
        }

        let file_offset = usize::try_from(file_offset).map_err(|_| ElfError::InvalidFileRange)?;
        let file_size = usize::try_from(file_size).map_err(|_| ElfError::InvalidFileRange)?;
        if file_offset
            .checked_add(file_size)
            .is_none_or(|end| end > self.bytes.len())
        {
            return Err(ElfError::InvalidFileRange);
        }

        let virtual_end = virtual_start
            .checked_add(memory_size)
            .ok_or(ElfError::InvalidVirtualRange)?;
        let last_virtual = virtual_end - 1;
        if virtual_start < PAGE_SIZE
            || virtual_start >= lower_half_end
            || last_virtual >= lower_half_end
            || !is_canonical(virtual_start, virtual_address_bits)
            || !is_canonical(last_virtual, virtual_address_bits)
        {
            return Err(ElfError::InvalidVirtualRange);
        }
        let page_end = virtual_end
            .checked_add(PAGE_SIZE - 1)
            .map(|end| end & !(PAGE_SIZE - 1))
            .filter(|end| *end <= lower_half_end)
            .ok_or(ElfError::InvalidVirtualRange)?;
        let page_count_u64 = (page_end - virtual_start) / PAGE_SIZE;
        let page_count = usize::try_from(page_count_u64).map_err(|_| ElfError::ImageTooLarge)?;
        self.load_page_count = self
            .load_page_count
            .checked_add(page_count)
            .filter(|count| *count <= MAX_ELF_LOAD_PAGES)
            .ok_or(ElfError::ImageTooLarge)?;
        if self
            .segments()
            .any(|segment| virtual_start < segment.page_end && segment.virtual_start < page_end)
        {
            return Err(ElfError::OverlappingLoadSegments);
        }

        let memory_size = usize::try_from(memory_size).map_err(|_| ElfError::ImageTooLarge)?;
        self.segments[self.segment_count] = Some(Elf64LoadSegment {
            virtual_start,
            virtual_end,
            file_offset,
            file_size,
            memory_size,
            page_end,
            flags,
        });
        self.segment_count += 1;
        Ok(())
    }

    pub const fn entry_point(&self) -> u64 {
        self.entry_point
    }

    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    pub const fn load_page_count(&self) -> usize {
        self.load_page_count
    }

    pub fn segments(&self) -> impl Iterator<Item = Elf64LoadSegment> + '_ {
        self.segments[..self.segment_count]
            .iter()
            .flatten()
            .copied()
    }

    pub fn segment_file_bytes(&self, index: usize) -> Option<&'a [u8]> {
        let segment = self.segments.get(index)?.as_ref()?;
        let end = segment.file_offset.checked_add(segment.file_size)?;
        self.bytes.get(segment.file_offset..end)
    }

    /// Populate one page of a validated load segment, zero-filling bytes not
    /// covered by the segment's file payload (including BSS).
    pub fn populate_segment_page<U: crate::paging::UserFrameMemory>(
        &self,
        segment_index: usize,
        page_index: usize,
        frame: &crate::frame::Frame,
        user_memory: &mut U,
    ) -> Result<(), ElfPagePopulationError<U::Error>> {
        let segment = self
            .segments
            .get(segment_index)
            .and_then(Option::as_ref)
            .copied()
            .ok_or(ElfPagePopulationError::InvalidSegment)?;
        if page_index >= segment.page_count() {
            return Err(ElfPagePopulationError::InvalidPage);
        }

        let page_offset = page_index
            .checked_mul(PAGE_SIZE as usize)
            .ok_or(ElfPagePopulationError::InvalidPage)?;
        let file_end = page_offset
            .checked_add(PAGE_SIZE as usize)
            .ok_or(ElfPagePopulationError::InvalidPage)?
            .min(segment.file_size);
        let file_start = page_offset.min(file_end);
        let mut page = [0; PAGE_SIZE as usize];
        if file_start < file_end {
            let bytes = self
                .segment_file_bytes(segment_index)
                .ok_or(ElfPagePopulationError::InvalidSegment)?;
            let source = bytes
                .get(file_start..file_end)
                .ok_or(ElfPagePopulationError::InvalidSegment)?;
            page[..source.len()].copy_from_slice(source);
        }
        user_memory
            .copy_to_frame(frame, 0, &page)
            .map_err(ElfPagePopulationError::FrameMemory)
    }

    /// Allocate, populate, and map every validated PT_LOAD page into an inactive
    /// process root. Cache attributes are selected separately for each exact
    /// physical page by `select_cache_attributes`.
    ///
    /// On failure, pages already installed remain owned by the process root and
    /// are reported in `mapped_pages`; any returned frame remains caller-owned.
    /// Destroy a newly created root to reclaim partial mappings and retained page
    /// tables before abandoning a failed load.
    pub fn load_into_process_root<M, U, F, CacheError>(
        &self,
        roots: &mut crate::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
        allocator: &mut crate::frame::FrameAllocator,
        handle: crate::paging::ProcessAddressSpaceHandle,
        user_memory: &mut U,
        mut select_cache_attributes: F,
    ) -> Result<LoadedElf, ElfLoadFailure<CacheError, M::Error, U::Error>>
    where
        M: crate::paging::CandidatePageTableMemory,
        U: crate::paging::UserFrameMemory,
        F: FnMut(
            crate::paging::ValidatedMappingRange,
        ) -> Result<crate::paging::SelectedCacheAttributes, CacheError>,
    {
        use crate::paging::{validate_mapping_range, PagePermissions, PAGE_SIZE};

        let config = roots.page_walk_config();
        let mut mapped_pages = 0;
        for (segment_index, segment) in self.segments().enumerate() {
            let permissions = PagePermissions {
                writable: segment.writable(),
                executable: segment.executable(),
                user_accessible: true,
            };
            for page_index in 0..segment.page_count() {
                let virtual_address = u64::try_from(page_index)
                    .ok()
                    .and_then(|index| index.checked_mul(PAGE_SIZE))
                    .and_then(|offset| segment.virtual_start().checked_add(offset));
                let Some(virtual_address) = virtual_address else {
                    return Err(ElfLoadFailure {
                        cause: ElfLoadError::Mapping(crate::paging::MappingError::AddressOverflow),
                        frame: None,
                        mapped_pages,
                        rollback_retained_table_frames: 0,
                    });
                };
                let Some(frame) = allocator.allocate() else {
                    return Err(ElfLoadFailure {
                        cause: ElfLoadError::OutOfFrames,
                        frame: None,
                        mapped_pages,
                        rollback_retained_table_frames: 0,
                    });
                };
                let mapping = match validate_mapping_range(
                    virtual_address,
                    frame.address(),
                    PAGE_SIZE,
                    permissions,
                    Some(config.physical_address_bits),
                    config.virtual_address_bits,
                ) {
                    Ok(mapping) => mapping,
                    Err(error) => {
                        return Err(ElfLoadFailure {
                            cause: ElfLoadError::Mapping(error),
                            frame: Some(frame),
                            mapped_pages,
                            rollback_retained_table_frames: 0,
                        });
                    }
                };
                let cache_attributes = match select_cache_attributes(mapping) {
                    Ok(attributes) => attributes,
                    Err(error) => {
                        return Err(ElfLoadFailure {
                            cause: ElfLoadError::CachePolicy(error),
                            frame: Some(frame),
                            mapped_pages,
                            rollback_retained_table_frames: 0,
                        });
                    }
                };
                if let Err(error) =
                    self.populate_segment_page(segment_index, page_index, &frame, user_memory)
                {
                    return Err(ElfLoadFailure {
                        cause: ElfLoadError::Populate(error),
                        frame: Some(frame),
                        mapped_pages,
                        rollback_retained_table_frames: 0,
                    });
                }
                if let Err(failure) =
                    roots.map_user_page(allocator, handle, frame, mapping, cache_attributes)
                {
                    return Err(ElfLoadFailure {
                        cause: ElfLoadError::Map(failure.cause),
                        frame: Some(failure.frame),
                        mapped_pages,
                        rollback_retained_table_frames: failure.rollback_retained_table_frames,
                    });
                }
                mapped_pages += 1;
            }
        }
        Ok(LoadedElf {
            entry_point: self.entry_point(),
            mapped_pages,
        })
    }
}

fn is_canonical(address: u64, address_bits: u8) -> bool {
    let sign_bit = (address >> (address_bits - 1)) & 1;
    let upper_bits = address >> address_bits;
    let expected_upper_bits = if sign_bit == 0 {
        0
    } else {
        u64::MAX >> address_bits
    };
    upper_bits == expected_upper_bits
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes = bytes.get(offset..end)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::{Elf64Image, ElfError, ElfPagePopulationError, MAX_ELF_LOAD_PAGES, PAGE_SIZE};
    use crate::frame::{Frame, FrameAllocator};
    use crate::memory::{MemoryMap, RawMemoryRegion};

    const FILE_SIZE: usize = 0x3000;
    const CODE_PH: usize = 64;
    const DATA_PH: usize = CODE_PH + 56;

    fn valid_elf() -> [u8; FILE_SIZE] {
        let mut bytes = [0; FILE_SIZE];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 24, 0x4000_0000);
        put_u64(&mut bytes, 32, CODE_PH as u64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 2);
        set_load_segment(&mut bytes, CODE_PH, 5, 0x1000, 0x4000_0000, 64, 128, 0x1000);
        set_load_segment(
            &mut bytes,
            DATA_PH,
            6,
            0x2000,
            0x4000_1000,
            128,
            0x1800,
            0x1000,
        );
        bytes[0x1000..0x1040].fill(0x90);
        bytes[0x2000..0x2080].fill(0x5a);
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn set_load_segment(
        bytes: &mut [u8],
        header: usize,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        put_u32(bytes, header, 1);
        put_u32(bytes, header + 4, flags);
        put_u64(bytes, header + 8, file_offset);
        put_u64(bytes, header + 16, virtual_address);
        put_u64(bytes, header + 32, file_size);
        put_u64(bytes, header + 40, memory_size);
        put_u64(bytes, header + 48, alignment);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SyntheticFrameError {
        WrongFrame,
        OutOfBounds,
    }

    struct SyntheticFrameMemory {
        frame_address: u64,
        bytes: [u8; PAGE_SIZE as usize],
    }

    // SAFETY: This test backend accesses only its matching synthetic frame token
    // and enforces page bounds for every operation.
    unsafe impl crate::paging::UserFrameMemory for SyntheticFrameMemory {
        type Error = SyntheticFrameError;

        fn copy_from_frame(
            &mut self,
            frame: &Frame,
            offset: usize,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let end = offset
                .checked_add(destination.len())
                .filter(|end| *end <= self.bytes.len())
                .ok_or(SyntheticFrameError::OutOfBounds)?;
            if frame.address() != self.frame_address {
                return Err(SyntheticFrameError::WrongFrame);
            }
            destination.copy_from_slice(&self.bytes[offset..end]);
            Ok(())
        }

        fn copy_to_frame(
            &mut self,
            frame: &Frame,
            offset: usize,
            source: &[u8],
        ) -> Result<(), Self::Error> {
            let end = offset
                .checked_add(source.len())
                .filter(|end| *end <= self.bytes.len())
                .ok_or(SyntheticFrameError::OutOfBounds)?;
            if frame.address() != self.frame_address {
                return Err(SyntheticFrameError::WrongFrame);
            }
            self.bytes[offset..end].copy_from_slice(source);
            Ok(())
        }
    }

    #[test]
    fn zero_user_frame_clears_the_complete_frame() {
        let memory_map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: 0x10_0000,
            length: PAGE_SIZE,
            kind: 0,
        }])
        .unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&memory_map).unwrap();
        let frame = allocator.allocate().unwrap();
        let mut user_memory = SyntheticFrameMemory {
            frame_address: frame.address(),
            bytes: [0xa5; PAGE_SIZE as usize],
        };

        crate::paging::zero_user_frame(&frame, &mut user_memory).unwrap();

        assert!(user_memory.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn parses_static_x86_64_load_segments_and_exposes_file_bytes() {
        let bytes = valid_elf();
        let image = Elf64Image::parse(&bytes, 48).unwrap();
        assert_eq!(image.entry_point(), 0x4000_0000);
        assert_eq!(image.segment_count(), 2);
        assert_eq!(image.load_page_count(), 3);
        let mut segments = image.segments();
        let code = segments.next().unwrap();
        let data = segments.next().unwrap();
        assert!(segments.next().is_none());
        assert_eq!(code.virtual_start(), 0x4000_0000);
        assert!(code.executable());
        assert!(!code.writable());
        assert_eq!(data.virtual_start(), 0x4000_1000);
        assert!(data.writable());
        assert!(!data.executable());
        assert_eq!(data.virtual_end(), 0x4000_2800);
        assert_eq!(data.memory_size(), 0x1800);
        assert_eq!(data.page_end(), 0x4000_3000);
        assert_eq!(image.segment_file_bytes(1).unwrap(), &[0x5a; 128]);
    }

    #[test]
    fn populates_file_bytes_and_zero_fills_each_segment_page() {
        let bytes = valid_elf();
        let image = Elf64Image::parse(&bytes, 48).unwrap();
        let memory_map = MemoryMap::from_raw(&[RawMemoryRegion {
            base: 0x10_0000,
            length: PAGE_SIZE * 2,
            kind: 0,
        }])
        .unwrap();
        let mut allocator = FrameAllocator::from_memory_map(&memory_map).unwrap();
        let frame = allocator.allocate().unwrap();
        let mut user_memory = SyntheticFrameMemory {
            frame_address: frame.address(),
            bytes: [0xa5; PAGE_SIZE as usize],
        };

        image
            .populate_segment_page(1, 0, &frame, &mut user_memory)
            .unwrap();
        assert_eq!(&user_memory.bytes[..128], &[0x5a; 128]);
        assert!(user_memory.bytes[128..].iter().all(|byte| *byte == 0));

        user_memory.bytes.fill(0xa5);
        image
            .populate_segment_page(1, 1, &frame, &mut user_memory)
            .unwrap();
        assert!(user_memory.bytes.iter().all(|byte| *byte == 0));
        assert_eq!(
            image.populate_segment_page(1, 2, &frame, &mut user_memory),
            Err(ElfPagePopulationError::InvalidPage)
        );
        assert_eq!(
            image.populate_segment_page(16, 0, &frame, &mut user_memory),
            Err(ElfPagePopulationError::InvalidSegment)
        );
    }

    #[test]
    fn rejects_bad_identification_machine_and_object_type() {
        let mut bytes = valid_elf();
        bytes[4] = 1;
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedClass)
        );
        let mut bytes = valid_elf();
        put_u16(&mut bytes, 18, 3);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedMachine)
        );
        let mut bytes = valid_elf();
        put_u16(&mut bytes, 16, 3);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedObjectType)
        );
    }

    #[test]
    fn rejects_truncated_header_and_program_header_table() {
        assert_eq!(
            Elf64Image::parse(&[0; 32], 48),
            Err(ElfError::TruncatedHeader)
        );
        let mut bytes = valid_elf();
        put_u64(&mut bytes, 32, u64::MAX);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidProgramHeaderTable)
        );
        let mut bytes = valid_elf();
        put_u16(&mut bytes, 56, u16::MAX);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::TooManyProgramHeaders)
        );
    }

    #[test]
    fn rejects_segment_file_bounds_and_size_mismatch() {
        let mut bytes = valid_elf();
        set_load_segment(
            &mut bytes,
            CODE_PH,
            5,
            0x1000,
            0x4000_0000,
            129,
            128,
            0x1000,
        );
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidSegmentSize)
        );
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 5, 0x3000, 0x4000_0000, 64, 128, 0x1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidFileRange)
        );
    }

    #[test]
    fn rejects_writable_executable_or_unreadable_load_segments() {
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 7, 0x1000, 0x4000_0000, 64, 128, 0x1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::WritableExecutableSegment)
        );
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 1, 0x1000, 0x4000_0000, 64, 128, 0x1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::SegmentNotReadable)
        );
    }

    #[test]
    fn rejects_unaligned_and_overlapping_load_pages() {
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 5, 0x1001, 0x4000_0000, 64, 128, 0x1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidAlignment)
        );
        let mut bytes = valid_elf();
        set_load_segment(
            &mut bytes,
            DATA_PH,
            6,
            0x2000,
            0x4000_0000,
            128,
            0x1000,
            0x1000,
        );
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::OverlappingLoadSegments)
        );
    }

    #[test]
    fn rejects_user_range_overflow_noncanonical_and_unexecutable_entry() {
        let mut bytes = valid_elf();
        put_u64(&mut bytes, 24, 0x8000_0000_0000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::EntryNotExecutable)
        );
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 5, 0x1000, !0xfff, 64, 128, 0x1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidVirtualRange)
        );
        let mut bytes = valid_elf();
        put_u64(&mut bytes, 24, 0x4000_1000);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::EntryNotExecutable)
        );
    }

    #[test]
    fn rejects_dynamic_tls_and_executable_stack_program_headers() {
        let mut bytes = valid_elf();
        put_u32(&mut bytes, CODE_PH, 3);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedDynamicSegment)
        );
        let mut bytes = valid_elf();
        put_u32(&mut bytes, DATA_PH, 7);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedTlsSegment)
        );
        let mut bytes = valid_elf();
        put_u32(&mut bytes, DATA_PH, 0x6474_e551);
        put_u32(&mut bytes, DATA_PH + 4, 7);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::ExecutableStackUnsupported)
        );
    }

    #[test]
    fn rejects_invalid_header_encoding_and_sizes() {
        let mut bytes = valid_elf();
        bytes[0] = 0;
        assert_eq!(Elf64Image::parse(&bytes, 48), Err(ElfError::InvalidMagic));
        let mut bytes = valid_elf();
        bytes[5] = 2;
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedByteOrder)
        );
        let mut bytes = valid_elf();
        bytes[6] = 0;
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedVersion)
        );
        let mut bytes = valid_elf();
        put_u16(&mut bytes, 52, 63);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidHeaderSize)
        );
        let mut bytes = valid_elf();
        put_u16(&mut bytes, 54, 55);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidProgramHeaderSize)
        );
    }

    #[test]
    fn rejects_invalid_segment_flags_alignment_and_empty_load_table() {
        let mut bytes = valid_elf();
        set_load_segment(
            &mut bytes,
            CODE_PH,
            0x8,
            0x1000,
            0x4000_0000,
            64,
            128,
            0x1000,
        );
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::UnsupportedSegmentFlags)
        );
        let mut bytes = valid_elf();
        set_load_segment(&mut bytes, CODE_PH, 5, 0x1000, 0x4000_0000, 64, 128, 0x1800);
        assert_eq!(
            Elf64Image::parse(&bytes, 48),
            Err(ElfError::InvalidAlignment)
        );
        let mut bytes = valid_elf();
        put_u32(&mut bytes, CODE_PH, 0);
        put_u32(&mut bytes, DATA_PH, 0);
        assert_eq!(Elf64Image::parse(&bytes, 48), Err(ElfError::NoLoadSegments));
    }

    #[test]
    fn enforces_fixed_load_page_capacity_and_address_width() {
        assert_eq!(
            Elf64Image::parse(&valid_elf(), 47),
            Err(ElfError::InvalidAddressWidth)
        );
        assert_eq!(MAX_ELF_LOAD_PAGES, 64);
        let mut bytes = valid_elf();
        set_load_segment(
            &mut bytes,
            DATA_PH,
            6,
            0x2000,
            0x4000_1000,
            128,
            65 * 4096,
            0x1000,
        );
        assert_eq!(Elf64Image::parse(&bytes, 48), Err(ElfError::ImageTooLarge));
    }
}
