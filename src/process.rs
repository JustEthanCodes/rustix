//! Fixed-capacity process identity and parent/child exit-state policy.
//!
//! This module does not own address spaces or block in the scheduler. Callers
//! must pair each process ID with its root and retry `try_wait` after a child
//! state change; a `Running` result means a syscall caller still has to block.

pub const MAX_PROCESSES: usize = 4;
pub const MAX_PROCESS_DESCRIPTORS: usize = 8;

/// ID zero belongs to the kernel supervisor and is never assigned to userspace.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub const KERNEL_PROCESS_ID: ProcessId = ProcessId(0);

pub const MAX_USER_REGIONS: usize = 32;
pub const USER_ANONYMOUS_MAP_START: u64 = 0x0000_4000_0000_0000;
pub const USER_ANONYMOUS_MAP_END: u64 = 0x0000_4000_0100_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserRegionKind {
    Image,
    Stack,
    Guard,
    Anonymous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserRegion {
    start: u64,
    end: u64,
    kind: UserRegionKind,
}

impl UserRegion {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn length(self) -> u64 {
        self.end - self.start
    }

    pub const fn kind(self) -> UserRegionKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserStackLayout {
    stack_region: UserRegion,
    guard_region: UserRegion,
    stack_pointer: u64,
}

impl UserStackLayout {
    pub const fn stack_region(self) -> UserRegion {
        self.stack_region
    }

    pub const fn guard_region(self) -> UserRegion {
        self.guard_region
    }

    pub const fn stack_pointer(self) -> u64 {
        self.stack_pointer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserRegionError {
    InvalidAddressWidth,
    EmptyRange,
    UnalignedRange,
    AddressOverflow,
    NonCanonicalRange,
    Overlap,
    Capacity,
    AnonymousAddressSpaceExhausted,
    NotAnonymousRegion,
}

/// Bounded user virtual-region reservations for one address space.
///
/// Region reservations are metadata only: page ownership and page-table changes
/// remain the responsibility of the process-root mapping APIs. Guard regions are
/// reserved here but intentionally have no backing mapping.
#[derive(Clone, Copy)]
pub struct UserRegionTable {
    regions: [Option<UserRegion>; MAX_USER_REGIONS],
}

impl UserRegionTable {
    pub const fn new() -> Self {
        Self {
            regions: [None; MAX_USER_REGIONS],
        }
    }

    /// Reserve a page-aligned lower-half range, including an unmapped guard range.
    pub fn reserve(
        &mut self,
        start: u64,
        length: u64,
        kind: UserRegionKind,
        virtual_address_bits: u8,
    ) -> Result<UserRegion, UserRegionError> {
        validate_user_region_range(start, length, virtual_address_bits)?;
        let end = start
            .checked_add(length)
            .ok_or(UserRegionError::AddressOverflow)?;
        if self
            .regions
            .iter()
            .flatten()
            .any(|region| start < region.end && region.start < end)
        {
            return Err(UserRegionError::Overlap);
        }
        let slot = self
            .regions
            .iter()
            .position(Option::is_none)
            .ok_or(UserRegionError::Capacity)?;
        let region = UserRegion { start, end, kind };
        self.regions[slot] = Some(region);
        Ok(region)
    }

    /// Transactionally reserve validated ELF load pages, a stack, and its guard.
    ///
    /// `stack_base` is the low address of the mapped stack. The initial stack
    /// pointer is the one-past end address. No page tables or backing frames are
    /// changed; the caller remains responsible for loading the image and mapping
    /// the stack. At least one stack and one guard page are required.
    pub fn reserve_elf_layout(
        &mut self,
        image: &crate::elf::Elf64Image<'_>,
        stack_base: u64,
        stack_pages: u64,
        guard_pages: u64,
        virtual_address_bits: u8,
    ) -> Result<UserStackLayout, UserRegionError> {
        if stack_pages == 0 || guard_pages == 0 {
            return Err(UserRegionError::EmptyRange);
        }
        let page_size = crate::paging::PAGE_SIZE;
        let stack_length = stack_pages
            .checked_mul(page_size)
            .ok_or(UserRegionError::AddressOverflow)?;
        let guard_length = guard_pages
            .checked_mul(page_size)
            .ok_or(UserRegionError::AddressOverflow)?;
        let guard_base = stack_base
            .checked_sub(guard_length)
            .ok_or(UserRegionError::AddressOverflow)?;
        let stack_pointer = stack_base
            .checked_add(stack_length)
            .ok_or(UserRegionError::AddressOverflow)?;

        let mut staged = *self;
        for segment in image.segments() {
            let page_count = u64::try_from(segment.page_count())
                .map_err(|_| UserRegionError::AddressOverflow)?;
            let length = page_count
                .checked_mul(page_size)
                .ok_or(UserRegionError::AddressOverflow)?;
            staged.reserve(
                segment.virtual_start(),
                length,
                UserRegionKind::Image,
                virtual_address_bits,
            )?;
        }
        let guard_region = staged.reserve(
            guard_base,
            guard_length,
            UserRegionKind::Guard,
            virtual_address_bits,
        )?;
        let stack_region = staged.reserve(
            stack_base,
            stack_length,
            UserRegionKind::Stack,
            virtual_address_bits,
        )?;
        *self = staged;
        Ok(UserStackLayout {
            stack_region,
            guard_region,
            stack_pointer,
        })
    }

    /// Reserve the first free range in the bounded anonymous-map window.
    ///
    /// The requested byte length is rounded up to a page. Allocations are
    /// read/write, non-executable by policy; this table does not install PTEs.
    pub fn allocate_anonymous(
        &mut self,
        requested_length: u64,
        virtual_address_bits: u8,
    ) -> Result<UserRegion, UserRegionError> {
        if requested_length == 0 {
            return Err(UserRegionError::EmptyRange);
        }
        if !matches!(virtual_address_bits, 48 | 57) {
            return Err(UserRegionError::InvalidAddressWidth);
        }
        if self.regions.iter().all(Option::is_some) {
            return Err(UserRegionError::Capacity);
        }
        let page_size = crate::paging::PAGE_SIZE;
        let length = requested_length
            .checked_add(page_size - 1)
            .ok_or(UserRegionError::AddressOverflow)?
            & !(page_size - 1);
        let mut candidate = USER_ANONYMOUS_MAP_START;
        loop {
            let end = candidate
                .checked_add(length)
                .ok_or(UserRegionError::AddressOverflow)?;
            if end > USER_ANONYMOUS_MAP_END {
                return Err(UserRegionError::AnonymousAddressSpaceExhausted);
            }
            let overlap = self
                .regions
                .iter()
                .flatten()
                .filter(|region| candidate < region.end && region.start < end)
                .min_by_key(|region| region.end);
            if let Some(region) = overlap {
                candidate = region.end;
                continue;
            }
            return self.reserve(
                candidate,
                length,
                UserRegionKind::Anonymous,
                virtual_address_bits,
            );
        }
    }

    /// Release only an exact anonymous reservation; image, stack, and guard
    /// regions cannot be released through this operation.
    pub fn release_anonymous(
        &mut self,
        start: u64,
        length: u64,
    ) -> Result<UserRegion, UserRegionError> {
        if length == 0 {
            return Err(UserRegionError::EmptyRange);
        }
        if (start | length) & (crate::paging::PAGE_SIZE - 1) != 0 {
            return Err(UserRegionError::UnalignedRange);
        }
        let end = start
            .checked_add(length)
            .ok_or(UserRegionError::AddressOverflow)?;
        let slot = self.regions.iter().position(|region| {
            region.is_some_and(|region| {
                region.start == start
                    && region.end == end
                    && region.kind == UserRegionKind::Anonymous
            })
        });
        let Some(slot) = slot else {
            return Err(UserRegionError::NotAnonymousRegion);
        };
        Ok(self.regions[slot]
            .take()
            .expect("matching anonymous reservation remains present"))
    }

    pub fn regions(&self) -> impl Iterator<Item = UserRegion> + '_ {
        self.regions.iter().flatten().copied()
    }
}

impl Default for UserRegionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of pages accepted for a process's initial user stack.
pub const MAX_INITIAL_USER_STACK_PAGES: u64 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserProgramPrepareErrorKind {
    InvalidElf,
    RootCreation,
    RegionReservation,
    ElfLoad,
    StackGuard,
    StackAllocation,
    StackInitialization,
    StackMapping,
    InvalidInitialState,
    InvalidIretFrame,
    CachePolicy(&'static str),
}

impl UserProgramPrepareErrorKind {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidElf => "ELF image validation failed",
            Self::RootCreation => "process root creation failed",
            Self::RegionReservation => "ELF, stack, or guard reservation failed",
            Self::ElfLoad => "ELF image could not be loaded",
            Self::StackGuard => "stack guard is not unmapped",
            Self::StackAllocation => "no frame available for the user stack",
            Self::StackInitialization => "user stack frame could not be zeroed",
            Self::StackMapping => "user stack page could not be mapped",
            Self::InvalidInitialState => "ELF entry or user stack failed validation",
            Self::InvalidIretFrame => "initial user IRET frame was rejected",
            Self::CachePolicy(message) => message,
        }
    }
}

/// Resources that a caller must retry cleaning up when preparation fails.
/// `process` remains owned by `roots`; `frame` is an allocated frame that was
/// not installed in that process root.
#[must_use = "retry cleanup for any process root or frame retained by this error"]
pub struct UserProgramPrepareError {
    pub kind: UserProgramPrepareErrorKind,
    pub process: Option<crate::paging::ProcessAddressSpaceHandle>,
    pub frame: Option<crate::frame::Frame>,
}

impl UserProgramPrepareError {
    /// Retry reclaiming every resource retained by this failure.
    pub fn cleanup<M: crate::paging::CandidatePageTableMemory>(
        mut self,
        roots: &mut crate::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
        allocator: &mut crate::frame::FrameAllocator,
    ) -> Result<(), Self> {
        if let Some(process) = self.process.take() {
            if roots.destroy(allocator, process).is_err() {
                self.process = Some(process);
                return Err(self);
            }
        }
        if let Some(frame) = self.frame.take() {
            if let Err(error) = allocator.deallocate(frame) {
                self.frame = Some(error.frame);
                return Err(self);
            }
        }
        Ok(())
    }
}

impl core::fmt::Debug for UserProgramPrepareError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UserProgramPrepareError")
            .field("kind", &self.kind)
            .field("process_retained", &self.process.is_some())
            .field("frame_retained", &self.frame.is_some())
            .finish()
    }
}

/// A loaded ELF image and its validated initial Ring 3 entry state.
pub struct PreparedUserProgram {
    pub process: crate::paging::ProcessAddressSpaceHandle,
    pub regions: UserRegionTable,
    pub user_frame: crate::syscall::ValidatedUserIretFrame,
}

fn cleanup_failed_user_program<M: crate::paging::CandidatePageTableMemory>(
    roots: &mut crate::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    allocator: &mut crate::frame::FrameAllocator,
    process: crate::paging::ProcessAddressSpaceHandle,
    kind: UserProgramPrepareErrorKind,
    frame: Option<crate::frame::Frame>,
) -> UserProgramPrepareError {
    let retained_process = roots.destroy(allocator, process).err().map(|_| process);
    let retained_frame = frame.and_then(|frame| match allocator.deallocate(frame) {
        Ok(()) => None,
        Err(error) => Some(error.frame),
    });
    UserProgramPrepareError {
        kind,
        process: retained_process,
        frame: retained_frame,
    }
}

/// Load a static ELF image into a fresh process root and prepare its guarded,
/// zero-filled initial user stack. All limits are explicit and failures return
/// any root or frame whose ownership could not be reclaimed.
#[allow(clippy::too_many_arguments)]
pub fn prepare_user_program<M, U, F>(
    roots: &mut crate::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    allocator: &mut crate::frame::FrameAllocator,
    user_memory: &mut U,
    image_bytes: &[u8],
    stack_base: u64,
    stack_pages: u64,
    guard_pages: u64,
    physical_address_bits: u8,
    virtual_address_bits: u8,
    user_code_selector: u16,
    user_data_selector: u16,
    select_cache: &mut F,
) -> Result<PreparedUserProgram, UserProgramPrepareError>
where
    M: crate::paging::CandidatePageTableMemory,
    U: crate::paging::UserFrameMemory,
    F: FnMut(
        crate::paging::ValidatedMappingRange,
    ) -> Result<crate::paging::SelectedCacheAttributes, &'static str>,
{
    use crate::paging::{validate_mapping_range, PagePermissions, PAGE_SIZE};

    let image = crate::elf::Elf64Image::parse(image_bytes, virtual_address_bits).map_err(|_| {
        UserProgramPrepareError {
            kind: UserProgramPrepareErrorKind::InvalidElf,
            process: None,
            frame: None,
        }
    })?;
    if stack_pages == 0 || stack_pages > MAX_INITIAL_USER_STACK_PAGES || guard_pages == 0 {
        return Err(UserProgramPrepareError {
            kind: UserProgramPrepareErrorKind::RegionReservation,
            process: None,
            frame: None,
        });
    }
    let process = match roots.create(allocator) {
        Ok(process) => process,
        Err(failure) => {
            let frame = failure.frame;
            let frame = frame.and_then(|frame| match allocator.deallocate(frame) {
                Ok(()) => None,
                Err(error) => Some(error.frame),
            });
            return Err(UserProgramPrepareError {
                kind: UserProgramPrepareErrorKind::RootCreation,
                process: None,
                frame,
            });
        }
    };
    let mut regions = UserRegionTable::new();
    let stack_layout = match regions.reserve_elf_layout(
        &image,
        stack_base,
        stack_pages,
        guard_pages,
        virtual_address_bits,
    ) {
        Ok(layout) => layout,
        Err(_) => {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::RegionReservation,
                None,
            ));
        }
    };
    if let Err(failure) =
        image.load_into_process_root(roots, allocator, process, user_memory, &mut *select_cache)
    {
        return Err(cleanup_failed_user_program(
            roots,
            allocator,
            process,
            UserProgramPrepareErrorKind::ElfLoad,
            failure.frame,
        ));
    }

    let mut guard_probe = [0u8; 1];
    // SAFETY: The scratch byte is kernel stack storage, disjoint from user frames.
    // The reserved guard range must have no mapped user backing.
    match unsafe {
        roots.copy_from_user(
            process,
            stack_layout.guard_region().start(),
            &mut guard_probe,
            user_memory,
        )
    } {
        Err(failure) if matches!(failure.cause, crate::paging::ProcessUserCopyError::Unmapped) => {}
        _ => {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::StackGuard,
                None,
            ));
        }
    }

    for offset in (0..stack_layout.stack_region().length()).step_by(PAGE_SIZE as usize) {
        let frame = match allocator.allocate() {
            Some(frame) => frame,
            None => {
                return Err(cleanup_failed_user_program(
                    roots,
                    allocator,
                    process,
                    UserProgramPrepareErrorKind::StackAllocation,
                    None,
                ));
            }
        };
        if crate::paging::zero_user_frame(&frame, user_memory).is_err() {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::StackInitialization,
                Some(frame),
            ));
        }
        let Some(virtual_address) = stack_layout.stack_region().start().checked_add(offset) else {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::StackMapping,
                Some(frame),
            ));
        };
        let mapping = match validate_mapping_range(
            virtual_address,
            frame.address(),
            PAGE_SIZE,
            PagePermissions {
                writable: true,
                executable: false,
                user_accessible: true,
            },
            Some(physical_address_bits),
            virtual_address_bits,
        ) {
            Ok(mapping) => mapping,
            Err(_) => {
                return Err(cleanup_failed_user_program(
                    roots,
                    allocator,
                    process,
                    UserProgramPrepareErrorKind::StackMapping,
                    Some(frame),
                ));
            }
        };
        let cache_attributes = match select_cache(mapping) {
            Ok(attributes) => attributes,
            Err(message) => {
                return Err(cleanup_failed_user_program(
                    roots,
                    allocator,
                    process,
                    UserProgramPrepareErrorKind::CachePolicy(message),
                    Some(frame),
                ));
            }
        };
        if let Err(failure) =
            roots.map_user_page(allocator, process, frame, mapping, cache_attributes)
        {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::StackMapping,
                Some(failure.frame),
            ));
        }
    }

    if roots
        .validate_initial_user_state(process, image.entry_point(), stack_layout.stack_pointer())
        .is_err()
    {
        return Err(cleanup_failed_user_program(
            roots,
            allocator,
            process,
            UserProgramPrepareErrorKind::InvalidInitialState,
            None,
        ));
    }
    let raw_frame = crate::syscall::UserIretFrame {
        instruction_pointer: image.entry_point(),
        code_selector: u64::from(user_code_selector),
        flags: crate::syscall::SAFE_USER_RFLAGS,
        stack_pointer: stack_layout.stack_pointer(),
        stack_selector: u64::from(user_data_selector),
    };
    let user_frame = match crate::syscall::sanitize_user_iret_frame(raw_frame, virtual_address_bits)
    {
        Ok(frame) => frame,
        Err(_) => {
            return Err(cleanup_failed_user_program(
                roots,
                allocator,
                process,
                UserProgramPrepareErrorKind::InvalidIretFrame,
                None,
            ));
        }
    };

    Ok(PreparedUserProgram {
        process,
        regions,
        user_frame,
    })
}

fn validate_user_region_range(
    start: u64,
    length: u64,
    virtual_address_bits: u8,
) -> Result<(), UserRegionError> {
    if !matches!(virtual_address_bits, 48 | 57) {
        return Err(UserRegionError::InvalidAddressWidth);
    }
    if length == 0 {
        return Err(UserRegionError::EmptyRange);
    }
    let page_size = crate::paging::PAGE_SIZE;
    if (start | length) & (page_size - 1) != 0 {
        return Err(UserRegionError::UnalignedRange);
    }
    let end = start
        .checked_add(length)
        .ok_or(UserRegionError::AddressOverflow)?;
    let lower_half_end = 1u64 << (virtual_address_bits - 1);
    if start >= lower_half_end
        || end > lower_half_end
        || !crate::memory::is_canonical_virtual_address(start, virtual_address_bits)
        || !crate::memory::is_canonical_virtual_address(end - 1, virtual_address_bits)
    {
        return Err(UserRegionError::NonCanonicalRange);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Running,
    Exited(i32),
}

/// A nonblocking observation of a child. `try_wait` reaps an exited child; `peek_wait` does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitResult {
    Running { pid: ProcessId },
    Exited { pid: ProcessId, status: i32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTableError {
    Capacity,
    InitialProcessAlreadyExists,
    InvalidProcess,
    InvalidParent,
    ParentExited,
    AlreadyExited,
    NoChild,
    ChildStillRunning,
    BadFileDescriptor,
    DescriptorTableFull,
    ProcessIdExhausted,
}

#[derive(Clone, Copy)]
struct ProcessRecord {
    pid: ProcessId,
    parent: ProcessId,
    state: ProcessState,
    descriptors: [Option<crate::syscall::ConsoleStream>; MAX_PROCESS_DESCRIPTORS],
}

fn initial_console_descriptors() -> [Option<crate::syscall::ConsoleStream>; MAX_PROCESS_DESCRIPTORS]
{
    let mut descriptors = [None; MAX_PROCESS_DESCRIPTORS];
    descriptors[1] = Some(crate::syscall::ConsoleStream::Stdout);
    descriptors[2] = Some(crate::syscall::ConsoleStream::Stderr);
    descriptors
}

/// Bounded, allocation-free process lifecycle records for the first user slice.
///
/// Exited records remain waitable zombies until their parent calls `try_wait`.
/// If a parent exits first, its children are reparented to the kernel supervisor
/// so their exit records remain reapable. This table models only inherited console
/// stream descriptors; file objects and address-space ownership live elsewhere.
pub struct ProcessTable {
    records: [Option<ProcessRecord>; MAX_PROCESSES],
    next_pid: Option<u64>,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            records: [None; MAX_PROCESSES],
            next_pid: Some(1),
        }
    }

    /// Register the one boot-created process under the kernel supervisor.
    pub fn create_initial(&mut self) -> Result<ProcessId, ProcessTableError> {
        if self
            .records
            .iter()
            .flatten()
            .any(|record| record.parent == KERNEL_PROCESS_ID)
        {
            return Err(ProcessTableError::InitialProcessAlreadyExists);
        }
        self.insert(KERNEL_PROCESS_ID, initial_console_descriptors())
    }

    /// Register a child of a currently running process.
    pub fn spawn(&mut self, parent: ProcessId) -> Result<ProcessId, ProcessTableError> {
        let parent_record = self
            .record(parent)
            .ok_or(ProcessTableError::InvalidParent)?;
        if parent_record.state != ProcessState::Running {
            return Err(ProcessTableError::ParentExited);
        }
        self.insert(parent, parent_record.descriptors)
    }

    /// Record an exit status without reclaiming the process identity.
    pub fn exit(&mut self, pid: ProcessId, status: i32) -> Result<(), ProcessTableError> {
        let index = self
            .records
            .iter()
            .position(|record| record.is_some_and(|record| record.pid == pid))
            .ok_or(ProcessTableError::InvalidProcess)?;
        let record = self.records[index]
            .as_mut()
            .expect("process slot was found");
        if record.state != ProcessState::Running {
            return Err(ProcessTableError::AlreadyExited);
        }
        record.state = ProcessState::Exited(status);
        record.descriptors = [None; MAX_PROCESS_DESCRIPTORS];
        for child in self.records.iter_mut().flatten() {
            if child.parent == pid {
                child.parent = KERNEL_PROCESS_ID;
            }
        }
        Ok(())
    }

    /// Inspect a matching child without consuming an exited record.
    ///
    /// `child_pid == 0` selects any child, preferring the lowest-PID exited child.
    /// This split lets callers validate/copy exit status before reaping a zombie.
    pub fn peek_wait(
        &self,
        parent: ProcessId,
        child_pid: u64,
    ) -> Result<WaitResult, ProcessTableError> {
        if parent != KERNEL_PROCESS_ID {
            let parent_record = self
                .record(parent)
                .ok_or(ProcessTableError::InvalidParent)?;
            if parent_record.state != ProcessState::Running {
                return Err(ProcessTableError::ParentExited);
            }
        }

        let mut found_child = false;
        let mut running: Option<ProcessId> = None;
        let mut exited: Option<(ProcessId, i32)> = None;
        for record in self.records.iter().flatten().filter(|record| {
            record.parent == parent && (child_pid == 0 || record.pid.get() == child_pid)
        }) {
            found_child = true;
            match record.state {
                ProcessState::Running => {
                    if running.is_none_or(|pid| record.pid < pid) {
                        running = Some(record.pid);
                    }
                }
                ProcessState::Exited(status) => {
                    if exited.is_none_or(|(pid, _)| record.pid < pid) {
                        exited = Some((record.pid, status));
                    }
                }
            }
        }

        if let Some((pid, status)) = exited {
            return Ok(WaitResult::Exited { pid, status });
        }
        if let Some(pid) = running {
            return Ok(WaitResult::Running { pid });
        }
        if found_child {
            unreachable!("a matching child must be running or exited");
        }
        Err(ProcessTableError::NoChild)
    }

    /// Reap one specific exited child after its status has been consumed.
    pub fn reap_exited(
        &mut self,
        parent: ProcessId,
        child_pid: ProcessId,
    ) -> Result<WaitResult, ProcessTableError> {
        let result = self.peek_wait(parent, child_pid.get())?;
        let WaitResult::Exited { pid, status } = result else {
            return Err(ProcessTableError::ChildStillRunning);
        };
        let index = self
            .records
            .iter()
            .position(|record| {
                record.is_some_and(|record| record.pid == pid && record.parent == parent)
            })
            .ok_or(ProcessTableError::NoChild)?;
        self.records[index] = None;
        Ok(WaitResult::Exited { pid, status })
    }

    /// Inspect or reap a matching child without blocking.
    ///
    /// `child_pid == 0` selects any child, preferring the lowest-PID exited child.
    pub fn try_wait(
        &mut self,
        parent: ProcessId,
        child_pid: u64,
    ) -> Result<WaitResult, ProcessTableError> {
        let result = self.peek_wait(parent, child_pid)?;
        if let WaitResult::Exited { pid, .. } = result {
            let _ = self.reap_exited(parent, pid)?;
        }
        Ok(result)
    }

    pub fn state(&self, pid: ProcessId) -> Option<ProcessState> {
        self.record(pid).map(|record| record.state)
    }

    pub fn live_records(&self) -> usize {
        self.records.iter().flatten().count()
    }

    /// Resolve one live descriptor to its bounded console-stream target.
    pub fn descriptor_stream(
        &self,
        pid: ProcessId,
        descriptor: u64,
    ) -> Option<crate::syscall::ConsoleStream> {
        let descriptor = usize::try_from(descriptor).ok()?;
        self.record(pid)?
            .descriptors
            .get(descriptor)
            .copied()
            .flatten()
    }

    /// Close one descriptor without affecting duplicated descriptors to the same stream.
    pub fn close_descriptor(
        &mut self,
        pid: ProcessId,
        descriptor: u64,
    ) -> Result<(), ProcessTableError> {
        let descriptor =
            usize::try_from(descriptor).map_err(|_| ProcessTableError::BadFileDescriptor)?;
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| record.pid == pid)
            .ok_or(ProcessTableError::InvalidProcess)?;
        if record.state != ProcessState::Running {
            return Err(ProcessTableError::AlreadyExited);
        }
        let entry = record
            .descriptors
            .get_mut(descriptor)
            .ok_or(ProcessTableError::BadFileDescriptor)?;
        entry.take().ok_or(ProcessTableError::BadFileDescriptor)?;
        Ok(())
    }

    /// Duplicate a descriptor into the lowest free slot at or above descriptor 3.
    pub fn duplicate_descriptor(
        &mut self,
        pid: ProcessId,
        descriptor: u64,
    ) -> Result<u64, ProcessTableError> {
        let source = self
            .descriptor_stream(pid, descriptor)
            .ok_or(ProcessTableError::BadFileDescriptor)?;
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| record.pid == pid)
            .ok_or(ProcessTableError::InvalidProcess)?;
        if record.state != ProcessState::Running {
            return Err(ProcessTableError::AlreadyExited);
        }
        let slot = record
            .descriptors
            .iter()
            .enumerate()
            .skip(3)
            .find_map(|(index, descriptor)| descriptor.is_none().then_some(index))
            .ok_or(ProcessTableError::DescriptorTableFull)?;
        record.descriptors[slot] = Some(source);
        Ok(slot as u64)
    }

    fn insert(
        &mut self,
        parent: ProcessId,
        descriptors: [Option<crate::syscall::ConsoleStream>; MAX_PROCESS_DESCRIPTORS],
    ) -> Result<ProcessId, ProcessTableError> {
        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(ProcessTableError::Capacity)?;
        let pid = self.next_pid.ok_or(ProcessTableError::ProcessIdExhausted)?;
        self.next_pid = pid.checked_add(1);
        let pid = ProcessId(pid);
        self.records[slot] = Some(ProcessRecord {
            pid,
            parent,
            state: ProcessState::Running,
            descriptors,
        });
        Ok(pid)
    }

    fn record(&self, pid: ProcessId) -> Option<&ProcessRecord> {
        self.records
            .iter()
            .flatten()
            .find(|record| record.pid == pid)
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ProcessState, ProcessTable, ProcessTableError, UserRegionError, UserRegionKind,
        UserRegionTable, WaitResult, KERNEL_PROCESS_ID, MAX_PROCESSES, MAX_PROCESS_DESCRIPTORS,
        USER_ANONYMOUS_MAP_START,
    };

    #[test]
    fn child_exit_status_is_retained_until_exact_wait_reaps_it() {
        let mut processes = ProcessTable::new();
        let init = processes.create_initial().unwrap();
        let child = processes.spawn(init).unwrap();

        assert_eq!(
            processes.try_wait(init, child.get()),
            Ok(WaitResult::Running { pid: child })
        );
        processes.exit(child, -17).unwrap();
        assert_eq!(processes.state(child), Some(ProcessState::Exited(-17)));
        assert_eq!(
            processes.try_wait(init, child.get()),
            Ok(WaitResult::Exited {
                pid: child,
                status: -17,
            })
        );
        assert_eq!(processes.state(child), None);
        assert_eq!(
            processes.try_wait(init, child.get()),
            Err(ProcessTableError::NoChild)
        );
    }

    #[test]
    fn peek_wait_keeps_a_zombie_until_status_consumption_succeeds() {
        let mut processes = ProcessTable::new();
        let parent = processes.create_initial().unwrap();
        let child = processes.spawn(parent).unwrap();
        processes.exit(child, 41).unwrap();

        assert_eq!(
            processes.peek_wait(parent, child.get()),
            Ok(WaitResult::Exited {
                pid: child,
                status: 41,
            })
        );
        assert_eq!(processes.state(child), Some(ProcessState::Exited(41)));
        assert_eq!(
            processes.reap_exited(parent, child),
            Ok(WaitResult::Exited {
                pid: child,
                status: 41,
            })
        );
        assert_eq!(processes.state(child), None);
        assert_eq!(
            processes.reap_exited(parent, child),
            Err(ProcessTableError::NoChild)
        );
    }

    #[test]
    fn reaping_a_running_child_is_rejected_without_mutation() {
        let mut processes = ProcessTable::new();
        let parent = processes.create_initial().unwrap();
        let child = processes.spawn(parent).unwrap();

        assert_eq!(
            processes.reap_exited(parent, child),
            Err(ProcessTableError::ChildStillRunning)
        );
        assert_eq!(processes.state(child), Some(ProcessState::Running));
    }

    #[test]
    fn wait_any_prefers_the_lowest_pid_zombie_and_keeps_running_children() {
        let mut processes = ProcessTable::new();
        let init = processes.create_initial().unwrap();
        let first = processes.spawn(init).unwrap();
        let second = processes.spawn(init).unwrap();
        processes.exit(second, 23).unwrap();

        assert_eq!(
            processes.try_wait(init, 0),
            Ok(WaitResult::Exited {
                pid: second,
                status: 23,
            })
        );
        assert_eq!(
            processes.try_wait(init, 0),
            Ok(WaitResult::Running { pid: first })
        );
    }

    #[test]
    fn exiting_parent_reparents_children_to_kernel_supervisor() {
        let mut processes = ProcessTable::new();
        let init = processes.create_initial().unwrap();
        let child = processes.spawn(init).unwrap();
        processes.exit(init, 0).unwrap();

        assert_eq!(
            processes.try_wait(KERNEL_PROCESS_ID, 0),
            Ok(WaitResult::Exited {
                pid: init,
                status: 0,
            })
        );
        processes.exit(child, 7).unwrap();
        assert_eq!(
            processes.try_wait(KERNEL_PROCESS_ID, child.get()),
            Ok(WaitResult::Exited {
                pid: child,
                status: 7,
            })
        );
    }

    #[test]
    fn capacity_and_invalid_lifecycle_operations_are_explicit() {
        let mut processes = ProcessTable::new();
        assert_eq!(
            processes.spawn(KERNEL_PROCESS_ID),
            Err(ProcessTableError::InvalidParent)
        );
        let init = processes.create_initial().unwrap();
        assert_eq!(
            processes.create_initial(),
            Err(ProcessTableError::InitialProcessAlreadyExists)
        );
        let children: [Option<super::ProcessId>; MAX_PROCESSES - 1] =
            core::array::from_fn(|_| None);
        let mut children = children;
        for child in &mut children {
            *child = Some(processes.spawn(init).unwrap());
        }
        assert_eq!(processes.live_records(), MAX_PROCESSES);
        assert_eq!(processes.spawn(init), Err(ProcessTableError::Capacity));

        let child = children[0].unwrap();
        processes.exit(child, 1).unwrap();
        assert_eq!(
            processes.exit(child, 2),
            Err(ProcessTableError::AlreadyExited)
        );
        assert_eq!(processes.spawn(child), Err(ProcessTableError::ParentExited));
    }

    #[test]
    fn descriptors_start_with_console_streams_and_are_inherited_by_children() {
        use crate::syscall::ConsoleStream;

        let mut processes = ProcessTable::new();
        let parent = processes.create_initial().unwrap();
        assert_eq!(processes.descriptor_stream(parent, 0), None);
        assert_eq!(
            processes.descriptor_stream(parent, 1),
            Some(ConsoleStream::Stdout)
        );
        assert_eq!(
            processes.descriptor_stream(parent, 2),
            Some(ConsoleStream::Stderr)
        );

        let duplicate = processes.duplicate_descriptor(parent, 1).unwrap();
        assert_eq!(duplicate, 3);
        let child = processes.spawn(parent).unwrap();
        assert_eq!(
            processes.descriptor_stream(child, 1),
            Some(ConsoleStream::Stdout)
        );
        assert_eq!(
            processes.descriptor_stream(child, 3),
            Some(ConsoleStream::Stdout)
        );

        processes.close_descriptor(parent, 1).unwrap();
        assert_eq!(processes.descriptor_stream(parent, 1), None);
        assert_eq!(
            processes.descriptor_stream(parent, 3),
            Some(ConsoleStream::Stdout)
        );
        assert_eq!(
            processes.descriptor_stream(child, 1),
            Some(ConsoleStream::Stdout)
        );
    }

    #[test]
    fn descriptor_operations_reject_invalid_entries_reuse_slots_and_report_capacity() {
        let mut processes = ProcessTable::new();
        let process = processes.create_initial().unwrap();
        assert_eq!(processes.descriptor_stream(process, u64::MAX), None);
        assert_eq!(
            processes.close_descriptor(process, 0),
            Err(ProcessTableError::BadFileDescriptor)
        );
        assert_eq!(
            processes.duplicate_descriptor(process, 0),
            Err(ProcessTableError::BadFileDescriptor)
        );

        let first = processes.duplicate_descriptor(process, 1).unwrap();
        processes.close_descriptor(process, first).unwrap();
        assert_eq!(processes.descriptor_stream(process, first), None);
        assert_eq!(processes.duplicate_descriptor(process, 2), Ok(first));
        for descriptor in [4, 5, 6, 7] {
            assert_eq!(processes.duplicate_descriptor(process, 1), Ok(descriptor));
        }
        assert_eq!(
            processes.duplicate_descriptor(process, 1),
            Err(ProcessTableError::DescriptorTableFull)
        );
        assert_eq!(
            processes.close_descriptor(process, u64::MAX),
            Err(ProcessTableError::BadFileDescriptor)
        );
    }

    #[test]
    fn exiting_process_closes_all_descriptors_and_children_keep_their_copies() {
        let mut processes = ProcessTable::new();
        let parent = processes.create_initial().unwrap();
        let child = processes.spawn(parent).unwrap();
        processes.duplicate_descriptor(parent, 1).unwrap();

        processes.exit(parent, 0).unwrap();
        for descriptor in 0..MAX_PROCESS_DESCRIPTORS as u64 {
            assert_eq!(processes.descriptor_stream(parent, descriptor), None);
        }
        assert_eq!(
            processes.descriptor_stream(child, 1),
            Some(crate::syscall::ConsoleStream::Stdout)
        );
    }

    #[test]
    fn anonymous_regions_round_up_skip_reserved_ranges_and_reuse_after_release() {
        let mut regions = UserRegionTable::new();
        regions
            .reserve(
                USER_ANONYMOUS_MAP_START,
                crate::paging::PAGE_SIZE,
                UserRegionKind::Guard,
                48,
            )
            .unwrap();

        let anonymous = regions.allocate_anonymous(1, 48).unwrap();
        assert_eq!(
            anonymous.start(),
            USER_ANONYMOUS_MAP_START + crate::paging::PAGE_SIZE
        );
        assert_eq!(anonymous.length(), crate::paging::PAGE_SIZE);
        assert_eq!(anonymous.kind(), UserRegionKind::Anonymous);
        assert_eq!(
            regions.release_anonymous(anonymous.start(), anonymous.length()),
            Ok(anonymous)
        );

        let reused = regions
            .allocate_anonymous(crate::paging::PAGE_SIZE, 48)
            .unwrap();
        assert_eq!(reused.start(), anonymous.start());
    }

    #[test]
    fn anonymous_regions_cannot_overlap_reserved_or_release_nonanonymous_ranges() {
        let mut regions = UserRegionTable::new();
        let stack = regions
            .reserve(
                0x7000_0000,
                crate::paging::PAGE_SIZE,
                UserRegionKind::Stack,
                48,
            )
            .unwrap();
        assert_eq!(
            regions.reserve(stack.start(), stack.length(), UserRegionKind::Anonymous, 48),
            Err(UserRegionError::Overlap)
        );
        assert_eq!(
            regions.release_anonymous(stack.start(), stack.length()),
            Err(UserRegionError::NotAnonymousRegion)
        );
    }

    #[test]
    fn user_regions_reject_invalid_width_alignment_overflow_and_upper_half() {
        let mut regions = UserRegionTable::new();
        assert_eq!(
            regions.reserve(0x1000, crate::paging::PAGE_SIZE, UserRegionKind::Image, 47),
            Err(UserRegionError::InvalidAddressWidth)
        );
        assert_eq!(
            regions.reserve(0x1001, crate::paging::PAGE_SIZE, UserRegionKind::Image, 48),
            Err(UserRegionError::UnalignedRange)
        );
        assert_eq!(
            regions.reserve(
                u64::MAX - (crate::paging::PAGE_SIZE - 1),
                crate::paging::PAGE_SIZE,
                UserRegionKind::Image,
                48
            ),
            Err(UserRegionError::AddressOverflow)
        );
        assert_eq!(
            regions.reserve(
                0x0000_8000_0000_0000,
                crate::paging::PAGE_SIZE,
                UserRegionKind::Image,
                48
            ),
            Err(UserRegionError::NonCanonicalRange)
        );
        assert_eq!(
            regions.allocate_anonymous(0, 48),
            Err(UserRegionError::EmptyRange)
        );
    }

    #[test]
    fn anonymous_region_capacity_and_window_exhaustion_are_explicit() {
        let mut regions = UserRegionTable::new();
        for slot in 0..super::MAX_USER_REGIONS {
            regions
                .reserve(
                    0x1000_0000 + slot as u64 * crate::paging::PAGE_SIZE,
                    crate::paging::PAGE_SIZE,
                    UserRegionKind::Image,
                    48,
                )
                .unwrap();
        }
        assert_eq!(
            regions.allocate_anonymous(crate::paging::PAGE_SIZE, 48),
            Err(UserRegionError::Capacity)
        );

        let mut full_window = UserRegionTable::new();
        full_window
            .reserve(
                USER_ANONYMOUS_MAP_START,
                super::USER_ANONYMOUS_MAP_END - USER_ANONYMOUS_MAP_START,
                UserRegionKind::Guard,
                48,
            )
            .unwrap();
        assert_eq!(
            full_window.allocate_anonymous(crate::paging::PAGE_SIZE, 48),
            Err(UserRegionError::AnonymousAddressSpaceExhausted)
        );
    }
}
