//! Bounded, allocation-free ACPI structure validation and MADT parsing.
//!
//! Parsers consume byte slices, and bounded table traversal uses an explicit
//! platform reader contract. This module never maps or dereferences physical
//! addresses and does not initialize APICs.

pub const MAX_ACPI_STRUCTURE_SIZE: usize = 64 * 1024;
const RSDP_V1_SIZE: usize = 20;
const RSDP_V2_MIN_SIZE: usize = 36;
const SDT_HEADER_SIZE: usize = 36;
const MADT_FIXED_SIZE: usize = 44;
const MAX_MADT_ENTRIES: usize = 256;
pub const MAX_ACPI_ROOT_ENTRIES: usize = 1024;
const MAX_LOCAL_APICS: usize = 16;
const MAX_IO_APICS: usize = 8;
const MAX_INTERRUPT_OVERRIDES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    StructureTooShort,
    StructureTooLarge,
    InvalidRsdpSignature,
    InvalidRsdpChecksum,
    InvalidExtendedRsdpLength,
    InvalidExtendedRsdpChecksum,
    UnsupportedRsdpRevision(u8),
    InvalidSdtLength,
    InvalidSdtChecksum,
    NotRootPointerTable,
    InvalidRootPointerTableLength,
    TooManyRootPointers,
    NullRootPointer,
    NotMadt,
    InvalidMadtLength,
    InvalidMadtEntryLength,
    TooManyMadtEntries,
    MadtCapacityExceeded,
    UnsupportedMadtEntryType(u8),
    InvalidLocalApicFlags,
    DuplicateLocalApic,
    InvalidIoApicAddress,
    DuplicateIoApicId,
    InvalidInterruptOverrideFlags,
    DuplicateInterruptOverride,
    InvalidLocalApicAddress,
    DuplicateLocalApicAddressOverride,
}

/// Physical-memory access supplied by the platform-specific ACPI integration.
///
/// # Safety
///
/// Implementations of `read` must validate every requested physical extent
/// against ACPI table memory-map metadata before reading it. `read_rsdp` may
/// additionally support the bounded legacy x86 reserved firmware window for
/// the RSDP itself; it must not extend that exception to root or child tables.
/// Both methods must copy only from checked, read-only, non-executable mappings,
/// ensure the complete extent is readable, and initialize all of `output` before
/// returning `Ok`. This module never creates mappings or dereferences physical
/// addresses itself.
pub unsafe trait AcpiPhysicalReader {
    type Error;

    fn read(&mut self, physical_start: u64, output: &mut [u8]) -> Result<(), Self::Error>;

    fn read_rsdp(&mut self, physical_start: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        self.read(physical_start, output)
    }
}

/// Failure while traversing ACPI tables from a physical RSDP address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiReadError<E> {
    Reader(E),
    Parse(AcpiError),
    InvalidPhysicalExtent,
    ZeroRootPointer,
    MissingMadt,
}

/// Validated root-system-description pointer fields copied out of the ACPI bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    pub revision: u8,
    pub rsdt_address: u32,
    pub xsdt_address: Option<u64>,
}

impl Rsdp {
    /// Validate an RSDP byte slice and copy its table addresses.
    ///
    /// ACPI 1.0 (revision 0) structures use the 20-byte legacy checksum. ACPI
    /// 2.0+ structures must include and pass the extended checksum.
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        if bytes.len() < RSDP_V1_SIZE {
            return Err(AcpiError::StructureTooShort);
        }
        if bytes[..8] != *b"RSD PTR " {
            return Err(AcpiError::InvalidRsdpSignature);
        }
        if !checksum_is_valid(&bytes[..RSDP_V1_SIZE]) {
            return Err(AcpiError::InvalidRsdpChecksum);
        }

        let revision = bytes[15];
        let rsdt_address = read_u32(bytes, 16);
        if revision == 0 {
            return Ok(Self {
                revision,
                rsdt_address,
                xsdt_address: None,
            });
        }
        if revision < 2 {
            return Err(AcpiError::UnsupportedRsdpRevision(revision));
        }
        if bytes.len() < RSDP_V2_MIN_SIZE {
            return Err(AcpiError::StructureTooShort);
        }

        let length = read_u32(bytes, 20) as usize;
        if !(RSDP_V2_MIN_SIZE..=MAX_ACPI_STRUCTURE_SIZE).contains(&length) || length > bytes.len() {
            return Err(AcpiError::InvalidExtendedRsdpLength);
        }
        if !checksum_is_valid(&bytes[..length]) {
            return Err(AcpiError::InvalidExtendedRsdpChecksum);
        }

        Ok(Self {
            revision,
            rsdt_address,
            xsdt_address: Some(read_u64(bytes, 24)),
        })
    }
}

/// A system-description table whose advertised length and checksum were checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sdt<'a> {
    bytes: &'a [u8],
    pub signature: [u8; 4],
    pub revision: u8,
}

impl<'a> Sdt<'a> {
    /// Validate an SDT header, bounded length, and checksum.
    ///
    /// Bytes following the advertised table length are ignored. The caller must
    /// still ensure that the complete advertised table is in the supplied slice.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, AcpiError> {
        if bytes.len() < SDT_HEADER_SIZE {
            return Err(AcpiError::StructureTooShort);
        }
        let length = read_u32(bytes, 4) as usize;
        if length < SDT_HEADER_SIZE {
            return Err(AcpiError::InvalidSdtLength);
        }
        if length > MAX_ACPI_STRUCTURE_SIZE {
            return Err(AcpiError::StructureTooLarge);
        }
        if length > bytes.len() {
            return Err(AcpiError::InvalidSdtLength);
        }
        if !checksum_is_valid(&bytes[..length]) {
            return Err(AcpiError::InvalidSdtChecksum);
        }

        Ok(Self {
            bytes: &bytes[..length],
            signature: [bytes[0], bytes[1], bytes[2], bytes[3]],
            revision: bytes[8],
        })
    }

    pub const fn length(&self) -> usize {
        self.bytes.len()
    }

    pub fn root_pointer_table(self) -> Result<RootPointerTable<'a>, AcpiError> {
        RootPointerTable::parse(self)
    }
}

/// Bounded, zero-allocation view of an ACPI RSDT or XSDT address array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootPointerTable<'a> {
    bytes: &'a [u8],
    entry_width: usize,
    entry_count: usize,
}

impl<'a> RootPointerTable<'a> {
    pub fn parse(table: Sdt<'a>) -> Result<Self, AcpiError> {
        let entry_width = match table.signature {
            [b'R', b'S', b'D', b'T'] => 4,
            [b'X', b'S', b'D', b'T'] => 8,
            _ => return Err(AcpiError::NotRootPointerTable),
        };
        let payload_length = table.bytes.len() - SDT_HEADER_SIZE;
        if payload_length % entry_width != 0 {
            return Err(AcpiError::InvalidRootPointerTableLength);
        }
        let entry_count = payload_length / entry_width;
        if entry_count > MAX_ACPI_ROOT_ENTRIES {
            return Err(AcpiError::TooManyRootPointers);
        }
        let pointers = &table.bytes[SDT_HEADER_SIZE..];
        for index in 0..entry_count {
            let offset = index * entry_width;
            let address = if entry_width == 4 {
                read_u32(pointers, offset) as u64
            } else {
                read_u64(pointers, offset)
            };
            if address == 0 {
                return Err(AcpiError::NullRootPointer);
            }
        }
        Ok(Self {
            bytes: pointers,
            entry_width,
            entry_count,
        })
    }

    pub const fn is_xsdt(&self) -> bool {
        self.entry_width == 8
    }

    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn address_at(&self, index: usize) -> Option<u64> {
        if index >= self.entry_count {
            return None;
        }
        let offset = index.checked_mul(self.entry_width)?;
        Some(if self.entry_width == 4 {
            read_u32(self.bytes, offset) as u64
        } else {
            read_u64(self.bytes, offset)
        })
    }
}

/// Read, validate, and parse the MADT reachable from a physical RSDP address.
///
/// The caller provides fixed-size scratch storage; no allocation or physical
/// mapping is performed here. Root tables are limited by
/// [`MAX_ACPI_ROOT_ENTRIES`], and each individual ACPI structure is limited by
/// [`MAX_ACPI_STRUCTURE_SIZE`].
pub fn read_madt<R: AcpiPhysicalReader>(
    reader: &mut R,
    rsdp_physical: u64,
    scratch: &mut [u8; MAX_ACPI_STRUCTURE_SIZE],
) -> Result<Madt, AcpiReadError<R::Error>> {
    read_rsdp(reader, rsdp_physical, &mut scratch[..RSDP_V1_SIZE])?;
    let revision = scratch[15];
    let rsdp = if revision >= 2 {
        read_rsdp(reader, rsdp_physical, &mut scratch[..RSDP_V2_MIN_SIZE])?;
        let advertised_length = read_u32(scratch, 20) as usize;
        if !(RSDP_V2_MIN_SIZE..=MAX_ACPI_STRUCTURE_SIZE).contains(&advertised_length) {
            return Err(AcpiReadError::Parse(AcpiError::InvalidExtendedRsdpLength));
        }
        read_rsdp(reader, rsdp_physical, &mut scratch[..advertised_length])?;
        Rsdp::parse(&scratch[..advertised_length]).map_err(AcpiReadError::Parse)?
    } else {
        Rsdp::parse(&scratch[..RSDP_V1_SIZE]).map_err(AcpiReadError::Parse)?
    };

    let (root_physical, expect_xsdt) = match rsdp.xsdt_address {
        Some(address) if address != 0 => (address, true),
        _ if rsdp.rsdt_address != 0 => (u64::from(rsdp.rsdt_address), false),
        _ => return Err(AcpiReadError::ZeroRootPointer),
    };

    read_physical(reader, root_physical, &mut scratch[..SDT_HEADER_SIZE])?;
    let root_length = checked_sdt_length(scratch)?;
    read_physical(reader, root_physical, &mut scratch[..root_length])?;
    let root_sdt = Sdt::parse(&scratch[..root_length]).map_err(AcpiReadError::Parse)?;
    let root_table = root_sdt
        .root_pointer_table()
        .map_err(AcpiReadError::Parse)?;
    if root_table.is_xsdt() != expect_xsdt {
        return Err(AcpiReadError::Parse(AcpiError::NotRootPointerTable));
    }

    let mut child_addresses = [0u64; MAX_ACPI_ROOT_ENTRIES];
    let child_count = root_table.entry_count();
    for (index, address) in child_addresses[..child_count].iter_mut().enumerate() {
        *address = root_table.address_at(index).ok_or(AcpiReadError::Parse(
            AcpiError::InvalidRootPointerTableLength,
        ))?;
    }

    for child_physical in child_addresses[..child_count].iter().copied() {
        read_physical(reader, child_physical, &mut scratch[..SDT_HEADER_SIZE])?;
        if scratch[..4] != *b"APIC" {
            continue;
        }
        let child_length = checked_sdt_length(scratch)?;
        read_physical(reader, child_physical, &mut scratch[..child_length])?;
        let child_sdt = Sdt::parse(&scratch[..child_length]).map_err(AcpiReadError::Parse)?;
        return Madt::parse(child_sdt).map_err(AcpiReadError::Parse);
    }

    Err(AcpiReadError::MissingMadt)
}

fn read_rsdp<R: AcpiPhysicalReader>(
    reader: &mut R,
    physical_start: u64,
    output: &mut [u8],
) -> Result<(), AcpiReadError<R::Error>> {
    let length = u64::try_from(output.len()).map_err(|_| AcpiReadError::InvalidPhysicalExtent)?;
    physical_start
        .checked_add(length)
        .ok_or(AcpiReadError::InvalidPhysicalExtent)?;
    reader
        .read_rsdp(physical_start, output)
        .map_err(AcpiReadError::Reader)
}

fn read_physical<R: AcpiPhysicalReader>(
    reader: &mut R,
    physical_start: u64,
    output: &mut [u8],
) -> Result<(), AcpiReadError<R::Error>> {
    let length = u64::try_from(output.len()).map_err(|_| AcpiReadError::InvalidPhysicalExtent)?;
    physical_start
        .checked_add(length)
        .ok_or(AcpiReadError::InvalidPhysicalExtent)?;
    reader
        .read(physical_start, output)
        .map_err(AcpiReadError::Reader)
}

fn checked_sdt_length<E>(header: &[u8]) -> Result<usize, AcpiReadError<E>> {
    if header.len() < SDT_HEADER_SIZE {
        return Err(AcpiReadError::Parse(AcpiError::StructureTooShort));
    }
    let length = read_u32(header, 4) as usize;
    if length < SDT_HEADER_SIZE {
        return Err(AcpiReadError::Parse(AcpiError::InvalidSdtLength));
    }
    if length > MAX_ACPI_STRUCTURE_SIZE {
        return Err(AcpiReadError::Parse(AcpiError::StructureTooLarge));
    }
    Ok(length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    pub processor_uid: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic {
    pub apic_id: u8,
    pub physical_address: u32,
    pub global_system_interrupt_base: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptSourceOverride {
    pub bus: u8,
    pub source: u8,
    pub global_system_interrupt: u32,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptPolarity {
    ActiveHigh,
    ActiveLow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptTrigger {
    Edge,
    Level,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedIsaInterrupt {
    pub source: u8,
    pub global_system_interrupt: u32,
    pub polarity: InterruptPolarity,
    pub trigger: InterruptTrigger,
}

/// Fixed-capacity, copied data from an xAPIC-compatible MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Madt {
    pub local_apic_address: u64,
    pub flags: u32,
    local_apics: [Option<LocalApic>; MAX_LOCAL_APICS],
    local_apic_count: usize,
    io_apics: [Option<IoApic>; MAX_IO_APICS],
    io_apic_count: usize,
    interrupt_overrides: [Option<InterruptSourceOverride>; MAX_INTERRUPT_OVERRIDES],
    interrupt_override_count: usize,
}

impl Madt {
    /// Parse the known xAPIC MADT records into bounded owned arrays.
    ///
    /// Unknown record types are skipped after validating their common header.
    /// x2APIC processor records are rejected because this parser does not yet
    /// establish x2APIC mode or destination-ID policy.
    pub fn parse(table: Sdt<'_>) -> Result<Self, AcpiError> {
        if table.signature != *b"APIC" {
            return Err(AcpiError::NotMadt);
        }
        if table.bytes.len() < MADT_FIXED_SIZE {
            return Err(AcpiError::InvalidMadtLength);
        }

        let mut madt = Self {
            local_apic_address: read_u32(table.bytes, SDT_HEADER_SIZE) as u64,
            flags: read_u32(table.bytes, SDT_HEADER_SIZE + 4),
            local_apics: [None; MAX_LOCAL_APICS],
            local_apic_count: 0,
            io_apics: [None; MAX_IO_APICS],
            io_apic_count: 0,
            interrupt_overrides: [None; MAX_INTERRUPT_OVERRIDES],
            interrupt_override_count: 0,
        };

        let mut local_apic_address_override_seen = false;
        let mut offset = MADT_FIXED_SIZE;
        let mut entry_count = 0;
        while offset < table.bytes.len() {
            if table.bytes.len() - offset < 2 {
                return Err(AcpiError::InvalidMadtEntryLength);
            }
            let entry_type = table.bytes[offset];
            let entry_length = table.bytes[offset + 1] as usize;
            if entry_length < 2 || entry_length > table.bytes.len() - offset {
                return Err(AcpiError::InvalidMadtEntryLength);
            }
            entry_count += 1;
            if entry_count > MAX_MADT_ENTRIES {
                return Err(AcpiError::TooManyMadtEntries);
            }

            let entry = &table.bytes[offset..offset + entry_length];
            match entry_type {
                0 => {
                    require_entry_length(entry_length, 8)?;
                    let processor_uid = entry[2];
                    let apic_id = entry[3];
                    let flags = read_u32(entry, 4);
                    if flags & !0x3 != 0 {
                        return Err(AcpiError::InvalidLocalApicFlags);
                    }
                    if madt
                        .local_apics()
                        .any(|cpu| cpu.processor_uid == processor_uid || cpu.apic_id == apic_id)
                    {
                        return Err(AcpiError::DuplicateLocalApic);
                    }
                    push(
                        &mut madt.local_apics,
                        &mut madt.local_apic_count,
                        LocalApic {
                            processor_uid,
                            apic_id,
                            flags,
                        },
                    )?;
                }
                1 => {
                    require_entry_length(entry_length, 12)?;
                    let apic_id = entry[2];
                    let physical_address = read_u32(entry, 4);
                    if physical_address == 0 || physical_address & 0xfff != 0 {
                        return Err(AcpiError::InvalidIoApicAddress);
                    }
                    if madt.io_apics().any(|io_apic| io_apic.apic_id == apic_id) {
                        return Err(AcpiError::DuplicateIoApicId);
                    }
                    push(
                        &mut madt.io_apics,
                        &mut madt.io_apic_count,
                        IoApic {
                            apic_id,
                            physical_address,
                            global_system_interrupt_base: read_u32(entry, 8),
                        },
                    )?;
                }
                2 => {
                    require_entry_length(entry_length, 10)?;
                    let bus = entry[2];
                    let source = entry[3];
                    let flags = read_u16(entry, 8);
                    if flags & !0x000f != 0 || flags & 0x3 == 0x2 || (flags >> 2) & 0x3 == 0x2 {
                        return Err(AcpiError::InvalidInterruptOverrideFlags);
                    }
                    if madt.interrupt_overrides().any(|override_entry| {
                        override_entry.bus == bus && override_entry.source == source
                    }) {
                        return Err(AcpiError::DuplicateInterruptOverride);
                    }
                    push(
                        &mut madt.interrupt_overrides,
                        &mut madt.interrupt_override_count,
                        InterruptSourceOverride {
                            bus,
                            source,
                            global_system_interrupt: read_u32(entry, 4),
                            flags,
                        },
                    )?;
                }
                5 => {
                    require_entry_length(entry_length, 12)?;
                    if local_apic_address_override_seen {
                        return Err(AcpiError::DuplicateLocalApicAddressOverride);
                    }
                    local_apic_address_override_seen = true;
                    madt.local_apic_address = read_u64(entry, 4);
                }
                9 => return Err(AcpiError::UnsupportedMadtEntryType(entry_type)),
                _ => {}
            }
            offset += entry_length;
        }
        if madt.local_apic_address == 0 || madt.local_apic_address & 0xfff != 0 {
            return Err(AcpiError::InvalidLocalApicAddress);
        }

        Ok(madt)
    }

    pub fn local_apics(&self) -> impl Iterator<Item = LocalApic> + '_ {
        self.local_apics[..self.local_apic_count]
            .iter()
            .filter_map(|entry| *entry)
    }

    pub fn io_apics(&self) -> impl Iterator<Item = IoApic> + '_ {
        self.io_apics[..self.io_apic_count]
            .iter()
            .filter_map(|entry| *entry)
    }

    pub fn interrupt_overrides(&self) -> impl Iterator<Item = InterruptSourceOverride> + '_ {
        self.interrupt_overrides[..self.interrupt_override_count]
            .iter()
            .filter_map(|entry| *entry)
    }

    /// Resolve an ISA IRQ source using its MADT override or ISA defaults.
    /// Conforming ISA flags default to active-high, edge-triggered delivery.
    pub fn resolve_isa_interrupt(&self, source: u8) -> ResolvedIsaInterrupt {
        let override_entry = self
            .interrupt_overrides()
            .find(|entry| entry.bus == 0 && entry.source == source);
        let (global_system_interrupt, flags) = override_entry
            .map(|entry| (entry.global_system_interrupt, entry.flags))
            .unwrap_or((u32::from(source), 0));
        let polarity = match flags & 0x3 {
            3 => InterruptPolarity::ActiveLow,
            _ => InterruptPolarity::ActiveHigh,
        };
        let trigger = match (flags >> 2) & 0x3 {
            3 => InterruptTrigger::Level,
            _ => InterruptTrigger::Edge,
        };
        ResolvedIsaInterrupt {
            source,
            global_system_interrupt,
            polarity,
            trigger,
        }
    }
}

fn require_entry_length(actual: usize, expected: usize) -> Result<(), AcpiError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AcpiError::InvalidMadtEntryLength)
    }
}

fn push<T: Copy, const N: usize>(
    entries: &mut [Option<T>; N],
    count: &mut usize,
    value: T,
) -> Result<(), AcpiError> {
    let Some(slot) = entries.get_mut(*count) else {
        return Err(AcpiError::MadtCapacityExceeded);
    };
    *slot = Some(value);
    *count += 1;
    Ok(())
}

fn checksum_is_valid(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::{
        read_madt, AcpiError, AcpiPhysicalReader, AcpiReadError, Madt, Rsdp, Sdt,
        MAX_ACPI_ROOT_ENTRIES, MAX_ACPI_STRUCTURE_SIZE, RSDP_V1_SIZE,
    };
    use core::assert_eq;
    extern crate std;

    fn set_checksum(bytes: &mut [u8], checksum_offset: usize, covered_length: usize) {
        bytes[checksum_offset] = 0;
        let sum = bytes[..covered_length]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[checksum_offset] = 0u8.wrapping_sub(sum);
    }

    fn make_sdt(signature: [u8; 4], body: &[u8]) -> std::vec::Vec<u8> {
        let length = 36 + body.len();
        let mut bytes = std::vec![0; length];
        bytes[..4].copy_from_slice(&signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
        bytes[10..16].copy_from_slice(b"RUSTIX");
        bytes[16..24].copy_from_slice(b"RUSTIX01");
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(b"RUST");
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[36..].copy_from_slice(body);
        set_checksum(&mut bytes, 9, length);
        bytes
    }

    #[derive(Default)]
    struct FakeReader {
        regions: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
        fail_address: Option<u64>,
    }

    impl FakeReader {
        fn add_region(&mut self, address: u64, bytes: std::vec::Vec<u8>) {
            self.regions.push((address, bytes));
        }
    }

    // The fixture regions stand in for memory-map-validated, readable ACPI extents.
    unsafe impl AcpiPhysicalReader for FakeReader {
        type Error = &'static str;

        fn read(&mut self, physical_start: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_address == Some(physical_start) {
                return Err("injected read failure");
            }
            for (base, bytes) in &self.regions {
                let Some(offset) = physical_start.checked_sub(*base) else {
                    continue;
                };
                let Ok(offset) = usize::try_from(offset) else {
                    continue;
                };
                let Some(end) = offset.checked_add(output.len()) else {
                    continue;
                };
                if end <= bytes.len() {
                    output.copy_from_slice(&bytes[offset..end]);
                    return Ok(());
                }
            }
            Err("unmapped fixture address")
        }
    }

    fn make_rsdp(root_address: u64, xsdt: bool) -> std::vec::Vec<u8> {
        if xsdt {
            let mut bytes = std::vec![0; 36];
            bytes[..8].copy_from_slice(b"RSD PTR ");
            bytes[9..15].copy_from_slice(b"RUSTIX");
            bytes[15] = 2;
            bytes[16..20].copy_from_slice(&0x7000u32.to_le_bytes());
            bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
            bytes[24..32].copy_from_slice(&root_address.to_le_bytes());
            set_checksum(&mut bytes, 8, RSDP_V1_SIZE);
            let length = bytes.len();
            set_checksum(&mut bytes, 32, length);
            bytes
        } else {
            let mut bytes = std::vec![0; RSDP_V1_SIZE];
            bytes[..8].copy_from_slice(b"RSD PTR ");
            bytes[9..15].copy_from_slice(b"RUSTIX");
            bytes[16..20].copy_from_slice(&(root_address as u32).to_le_bytes());
            set_checksum(&mut bytes, 8, RSDP_V1_SIZE);
            bytes
        }
    }

    fn traversal_fixture(xsdt: bool, child_signature: [u8; 4]) -> FakeReader {
        let rsdp_address = 0x1000;
        let root_address = if xsdt { 0x2_0000_0000 } else { 0x2000 };
        let child_address = 0x3000;
        let mut child_body = std::vec![0; 8];
        child_body[..4].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        let child = make_sdt(child_signature, &child_body);
        let root_body = if xsdt {
            root_address_entry_u64(child_address)
        } else {
            root_address_entry_u32(child_address)
        };
        let root = make_sdt(if xsdt { *b"XSDT" } else { *b"RSDT" }, &root_body);

        let mut reader = FakeReader::default();
        reader.add_region(rsdp_address, make_rsdp(root_address, xsdt));
        reader.add_region(root_address, root);
        reader.add_region(child_address, child);
        reader
    }

    fn root_address_entry_u32(address: u64) -> std::vec::Vec<u8> {
        (address as u32).to_le_bytes().to_vec()
    }

    fn root_address_entry_u64(address: u64) -> std::vec::Vec<u8> {
        address.to_le_bytes().to_vec()
    }

    #[test]
    fn traverses_rsdt_and_xsdt_to_madt() {
        for xsdt in [false, true] {
            let mut reader = traversal_fixture(xsdt, *b"APIC");
            let mut scratch = [0; MAX_ACPI_STRUCTURE_SIZE];
            let madt = read_madt(&mut reader, 0x1000, &mut scratch).unwrap();
            assert_eq!(madt.local_apic_address, 0xfee0_0000);
        }
    }

    #[test]
    fn reports_madt_traversal_failures() {
        let mut reader = traversal_fixture(false, *b"APIC");
        reader.regions[2].1[9] ^= 1;
        let mut scratch = [0; MAX_ACPI_STRUCTURE_SIZE];
        assert_eq!(
            read_madt(&mut reader, 0x1000, &mut scratch),
            Err(AcpiReadError::Parse(AcpiError::InvalidSdtChecksum))
        );

        let mut reader = traversal_fixture(true, *b"SSDT");
        assert_eq!(
            read_madt(&mut reader, 0x1000, &mut scratch),
            Err(AcpiReadError::MissingMadt)
        );

        let mut reader = traversal_fixture(false, *b"APIC");
        reader.fail_address = Some(0x2000);
        assert_eq!(
            read_madt(&mut reader, 0x1000, &mut scratch),
            Err(AcpiReadError::Reader("injected read failure"))
        );

        let mut reader = FakeReader::default();
        assert_eq!(
            read_madt(&mut reader, u64::MAX - 10, &mut scratch),
            Err(AcpiReadError::InvalidPhysicalExtent)
        );

        reader.add_region(0x1000, make_rsdp(0, false));
        assert_eq!(
            read_madt(&mut reader, 0x1000, &mut scratch),
            Err(AcpiReadError::ZeroRootPointer)
        );
    }

    #[test]
    fn parses_and_checksums_acpi_10_rsdp() {
        let mut bytes = [0u8; 20];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[9..15].copy_from_slice(b"RUSTIX");
        bytes[15] = 0;
        bytes[16..20].copy_from_slice(&0x1234_5000u32.to_le_bytes());
        set_checksum(&mut bytes, 8, RSDP_V1_SIZE);

        assert_eq!(
            Rsdp::parse(&bytes),
            Ok(Rsdp {
                revision: 0,
                rsdt_address: 0x1234_5000,
                xsdt_address: None,
            })
        );
        bytes[10] ^= 1;
        assert_eq!(Rsdp::parse(&bytes), Err(AcpiError::InvalidRsdpChecksum));
    }

    #[test]
    fn validates_extended_rsdp_length_and_checksum() {
        let mut bytes = [0u8; 36];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[9..15].copy_from_slice(b"RUSTIX");
        bytes[15] = 2;
        bytes[16..20].copy_from_slice(&0x1234_5000u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x1234_5678_9000u64.to_le_bytes());
        set_checksum(&mut bytes, 8, RSDP_V1_SIZE);
        set_checksum(&mut bytes, 32, 36);

        assert_eq!(
            Rsdp::parse(&bytes),
            Ok(Rsdp {
                revision: 2,
                rsdt_address: 0x1234_5000,
                xsdt_address: Some(0x1234_5678_9000),
            })
        );
        bytes[20..24].copy_from_slice(&(MAX_ACPI_STRUCTURE_SIZE as u32 + 1).to_le_bytes());
        assert_eq!(
            Rsdp::parse(&bytes),
            Err(AcpiError::InvalidExtendedRsdpLength)
        );
    }

    #[test]
    fn validates_sdt_length_and_checksum() {
        let bytes = make_sdt(*b"TEST", &[1, 2, 3]);
        let table = Sdt::parse(&bytes).unwrap();
        assert_eq!(table.signature, *b"TEST");
        assert_eq!(table.length(), 39);

        let mut corrupt = bytes;
        corrupt[36] ^= 1;
        assert_eq!(Sdt::parse(&corrupt), Err(AcpiError::InvalidSdtChecksum));
    }

    #[test]
    fn parses_bounded_rsdt_and_xsdt_pointer_arrays() {
        let mut rsdt_body = std::vec::Vec::new();
        rsdt_body.extend_from_slice(&0x1234_5000u32.to_le_bytes());
        rsdt_body.extend_from_slice(&0x2345_6000u32.to_le_bytes());
        let bytes = make_sdt(*b"RSDT", &rsdt_body);
        let pointers = Sdt::parse(&bytes).unwrap().root_pointer_table().unwrap();
        assert!(!pointers.is_xsdt());
        assert_eq!(pointers.entry_count(), 2);
        assert_eq!(pointers.address_at(0), Some(0x1234_5000));
        assert_eq!(pointers.address_at(1), Some(0x2345_6000));
        assert_eq!(pointers.address_at(2), None);

        let bytes = make_sdt(*b"XSDT", &0x1_2345_6000u64.to_le_bytes());
        let pointers = Sdt::parse(&bytes).unwrap().root_pointer_table().unwrap();
        assert!(pointers.is_xsdt());
        assert_eq!(pointers.address_at(0), Some(0x1_2345_6000));
    }

    #[test]
    fn rejects_malformed_rsdt_xsdt_pointers_and_capacity_overflow() {
        let bytes = make_sdt(*b"RSDT", &[1, 2, 3, 4, 5]);
        assert_eq!(
            Sdt::parse(&bytes).unwrap().root_pointer_table(),
            Err(AcpiError::InvalidRootPointerTableLength)
        );

        let bytes = make_sdt(*b"XSDT", &0u64.to_le_bytes());
        assert_eq!(
            Sdt::parse(&bytes).unwrap().root_pointer_table(),
            Err(AcpiError::NullRootPointer)
        );

        let mut pointers = std::vec![0x1000u32; MAX_ACPI_ROOT_ENTRIES + 1];
        let body = pointers
            .drain(..)
            .flat_map(u32::to_le_bytes)
            .collect::<std::vec::Vec<_>>();
        let bytes = make_sdt(*b"RSDT", &body);
        assert_eq!(
            Sdt::parse(&bytes).unwrap().root_pointer_table(),
            Err(AcpiError::TooManyRootPointers)
        );
    }

    #[test]
    fn parses_madt_devices_overrides_and_address_override() {
        let mut body = std::vec![0; 8];
        body[0..4].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        body[4..8].copy_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0, 8, 1, 2, 1, 0, 0, 0]);
        body.extend_from_slice(&[1, 12, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        body[20..24].copy_from_slice(&0xfec0_0000u32.to_le_bytes());
        body[24..28].copy_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]);
        body[32..36].copy_from_slice(&9u32.to_le_bytes());
        body.extend_from_slice(&[5, 12, 0, 0]);
        body.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());

        let bytes = make_sdt(*b"APIC", &body);
        let madt = Madt::parse(Sdt::parse(&bytes).unwrap()).unwrap();
        assert_eq!(madt.local_apic_address, 0x1_0000_0000);
        assert_eq!(madt.flags, 1);
        assert_eq!(
            madt.local_apics().collect::<std::vec::Vec<_>>(),
            [super::LocalApic {
                processor_uid: 1,
                apic_id: 2,
                flags: 1,
            }]
        );
        assert_eq!(
            madt.io_apics().collect::<std::vec::Vec<_>>(),
            [super::IoApic {
                apic_id: 3,
                physical_address: 0xfec0_0000,
                global_system_interrupt_base: 0,
            }]
        );
        assert_eq!(
            madt.interrupt_overrides().collect::<std::vec::Vec<_>>(),
            [super::InterruptSourceOverride {
                bus: 0,
                source: 0,
                global_system_interrupt: 9,
                flags: 0,
            }]
        );
        assert_eq!(
            madt.resolve_isa_interrupt(0),
            super::ResolvedIsaInterrupt {
                source: 0,
                global_system_interrupt: 9,
                polarity: super::InterruptPolarity::ActiveHigh,
                trigger: super::InterruptTrigger::Edge,
            }
        );
        assert_eq!(
            madt.resolve_isa_interrupt(1),
            super::ResolvedIsaInterrupt {
                source: 1,
                global_system_interrupt: 1,
                polarity: super::InterruptPolarity::ActiveHigh,
                trigger: super::InterruptTrigger::Edge,
            }
        );
    }

    #[test]
    fn rejects_truncated_and_unsupported_madt_records() {
        let mut body = std::vec![0; 8];
        body.extend_from_slice(&[1, 11, 0, 0]);
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::InvalidMadtEntryLength)
        );

        let mut body = std::vec![0; 8];
        body.extend_from_slice(&[9, 2]);
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::UnsupportedMadtEntryType(9))
        );
    }

    #[test]
    fn rejects_invalid_or_duplicate_madt_routing_records() {
        let mut body = std::vec![0; 8];
        body.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 2, 0]);
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::InvalidInterruptOverrideFlags)
        );

        let mut body = std::vec![0; 8];
        body.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&[2, 10, 0, 0, 3, 0, 0, 0, 0, 0]);
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::DuplicateInterruptOverride)
        );

        let mut body = std::vec![0; 8];
        body.extend_from_slice(&[0, 8, 1, 2, 4, 0, 0, 0]);
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::InvalidLocalApicFlags)
        );
    }

    #[test]
    fn reports_fixed_madt_capacity_exhaustion() {
        let mut body = std::vec![0; 8];
        for apic_id in 0..17u8 {
            body.extend_from_slice(&[0, 8, apic_id, apic_id, 1, 0, 0, 0]);
        }
        let bytes = make_sdt(*b"APIC", &body);
        assert_eq!(
            Madt::parse(Sdt::parse(&bytes).unwrap()),
            Err(AcpiError::MadtCapacityExceeded)
        );
    }
}
