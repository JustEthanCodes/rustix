#![no_std]

//! Small `no_std` wrappers for the stable Rustix syscall ABI v1.
//!
//! The raw syscall entry accepts register-sized values and never dereferences
//! them in Rust; the kernel validates all user pointers before access. Prefer
//! the typed wrappers when they match the operation being performed.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(target_arch = "x86_64"))]
compile_error!("rustix-user currently supports x86_64 only");

pub const ABI_VERSION: u64 = 0x0001_0001;
pub const SYS_ABI_VERSION: u64 = 0;
pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;
pub const SYS_WAIT: u64 = 3;
pub const SYS_MMAP: u64 = 4;
pub const SYS_MUNMAP: u64 = 5;
pub const SYS_CLOSE: u64 = 6;
pub const SYS_DUP: u64 = 7;
pub const SYS_MMAP_REGION: u64 = 8;
pub const SYS_MUNMAP_REGION: u64 = 9;
pub const SYS_SPAWN: u64 = 10;
pub const SYS_EXEC: u64 = 11;
pub const USER_PAGE_SIZE: usize = 4096;
pub const MAX_MAPPED_REGION_SIZE: usize = 1024 * 1024;
pub const MAX_SPAWN_IMAGE_SIZE: usize = 1024 * 1024;
pub const MAX_INITIAL_STACK_PAGES: usize = 16;

pub const STDOUT: u64 = 1;
pub const STDERR: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallError {
    InvalidArgument,
    BadFileDescriptor,
    Fault,
    OutOfMemory,
    NoChild,
    Interrupted,
    Io,
    NotImplemented,
    ArgumentListTooLong,
    Overflow,
    NotSupported,
    TooManyOpenFiles,
    ResultOutOfRange,
    Unknown(i64),
}

/// Invoke one v1 syscall using the documented x86_64 register convention.
///
/// This low-level entry is safe because pointer values are passed opaquely to
/// the kernel, which validates ranges and permissions before dereferencing.
/// Prefer [`write`], [`wait`], and [`exit`] when possible.
#[inline]
pub fn syscall(number: u64, arguments: [u64; 6]) -> i64 {
    let [first, second, third, fourth, fifth, sixth] = arguments;
    let result: u64;
    // SAFETY: The v1 ABI assigns RAX and the six argument registers exactly as
    // declared here. Rustix's DPL-3 gate and entry stub preserve Rust's memory
    // validity invariants by treating user pointers as integers in the kernel.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            in("r8") fifth,
            in("r9") sixth,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    result as i64
}

pub fn abi_version() -> Result<u64, SyscallError> {
    decode_result(syscall(SYS_ABI_VERSION, [0; 6]))
}

/// Write one buffer to a v1 file descriptor. A successful short write is valid.
pub fn write(file_descriptor: u64, bytes: &[u8]) -> Result<usize, SyscallError> {
    let result = decode_result(syscall(
        SYS_WRITE,
        [
            file_descriptor,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ],
    ))?;
    usize::try_from(result).map_err(|_| SyscallError::ResultOutOfRange)
}

/// Close a process-local descriptor.
pub fn close(file_descriptor: u64) -> Result<(), SyscallError> {
    match decode_result(syscall(SYS_CLOSE, [file_descriptor, 0, 0, 0, 0, 0]))? {
        0 => Ok(()),
        _ => Err(SyscallError::ResultOutOfRange),
    }
}

/// Duplicate a descriptor into the lowest available descriptor slot.
pub fn dup(file_descriptor: u64) -> Result<u64, SyscallError> {
    decode_result(syscall(SYS_DUP, [file_descriptor, 0, 0, 0, 0, 0]))
}

/// Spawn a child process from a static ELF image with a bounded initial stack.
pub fn spawn(image: &[u8], stack_pages: usize) -> Result<u64, SyscallError> {
    spawn_with(image.as_ptr() as u64, image.len(), stack_pages, syscall)
}

fn spawn_with(
    image_address: u64,
    image_length: usize,
    stack_pages: usize,
    invoke: impl FnOnce(u64, [u64; 6]) -> i64,
) -> Result<u64, SyscallError> {
    if image_length == 0 || !(1..=MAX_INITIAL_STACK_PAGES).contains(&stack_pages) {
        return Err(SyscallError::InvalidArgument);
    }
    if image_length > MAX_SPAWN_IMAGE_SIZE {
        return Err(SyscallError::ArgumentListTooLong);
    }

    decode_result(invoke(
        SYS_SPAWN,
        [
            image_address,
            image_length as u64,
            stack_pages as u64,
            0,
            0,
            0,
        ],
    ))
}

/// Replace the calling process's image with a static ELF (syscall 11).
///
/// On success this call never returns: the process resumes Ring 3 at the
/// replacement image's entry with a fresh zero-filled stack, keeping its PID,
/// descriptors, parent, and children. The returned `Ok` value is uninhabited.
/// On failure the original image continues and the error is returned. The
/// kernel preserves the user x87/SSE state across a successful exec.
pub fn exec(image: &[u8], stack_pages: usize) -> Result<core::convert::Infallible, SyscallError> {
    exec_with(image.as_ptr() as u64, image.len(), stack_pages, syscall)
}

fn exec_with(
    image_address: u64,
    image_length: usize,
    stack_pages: usize,
    invoke: impl FnOnce(u64, [u64; 6]) -> i64,
) -> Result<core::convert::Infallible, SyscallError> {
    if image_length == 0 || !(1..=MAX_INITIAL_STACK_PAGES).contains(&stack_pages) {
        return Err(SyscallError::InvalidArgument);
    }
    if image_length > MAX_SPAWN_IMAGE_SIZE {
        return Err(SyscallError::ArgumentListTooLong);
    }
    let result = invoke(
        SYS_EXEC,
        [
            image_address,
            image_length as u64,
            stack_pages as u64,
            0,
            0,
            0,
        ],
    );
    // A successful exec replaces the process and never returns here; any
    // nonnegative result would be a kernel contract violation.
    match decode_result(result) {
        Err(error) => Err(error),
        Ok(_) => Err(SyscallError::NotImplemented),
    }
}

/// A single page returned by the anonymous mapping syscall.
///
/// The pointer is raw: callers must not dereference it unless they uphold the
/// normal pointer validity and aliasing requirements. `munmap` consumes the
/// handle so safe code cannot accidentally release the same mapping twice.
pub struct MappedRegion {
    address: u64,
}

impl MappedRegion {
    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn length(&self) -> usize {
        USER_PAGE_SIZE
    }

    pub const fn as_mut_ptr(&self) -> *mut u8 {
        self.address as *mut u8
    }
}

/// Map one zero-filled read/write, non-executable anonymous user page.
///
/// `requested_length` must be in `1..=USER_PAGE_SIZE`; the kernel maps one page
/// and returns a `MappedRegion` whose length is exactly one page.
pub fn mmap(requested_length: usize) -> Result<MappedRegion, SyscallError> {
    let address = decode_result(syscall(SYS_MMAP, [requested_length as u64, 0, 0, 0, 0, 0]))?;
    Ok(MappedRegion { address })
}

/// Unmap one page previously returned by [`mmap`].
pub fn munmap(region: MappedRegion) -> Result<(), SyscallError> {
    match decode_result(syscall(
        SYS_MUNMAP,
        [region.address, USER_PAGE_SIZE as u64, 0, 0, 0, 0],
    ))? {
        0 => Ok(()),
        _ => Err(SyscallError::ResultOutOfRange),
    }
}

/// A bounded multi-page anonymous mapping returned by [`mmap_region`].
pub struct MappedPages {
    address: u64,
    length: usize,
}

impl MappedPages {
    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn length(&self) -> usize {
        self.length
    }

    pub const fn as_mut_ptr(&self) -> *mut u8 {
        self.address as *mut u8
    }
}

/// Map a zero-filled read/write, non-executable anonymous region.
///
/// The requested size is rounded up to a 4096-byte page. The current bounded
/// ABI supports regions up to [`MAX_MAPPED_REGION_SIZE`] bytes.
pub fn mmap_region(requested_length: usize) -> Result<MappedPages, SyscallError> {
    let address = decode_result(syscall(
        SYS_MMAP_REGION,
        [requested_length as u64, 0, 0, 0, 0, 0],
    ))?;
    let rounded_length = requested_length
        .checked_add(USER_PAGE_SIZE - 1)
        .ok_or(SyscallError::Overflow)?
        & !(USER_PAGE_SIZE - 1);
    Ok(MappedPages {
        address,
        length: rounded_length,
    })
}

/// Unmap an exact region returned by [`mmap_region`].
pub fn munmap_region(region: MappedPages) -> Result<(), SyscallError> {
    match decode_result(syscall(
        SYS_MUNMAP_REGION,
        [region.address, region.length as u64, 0, 0, 0, 0],
    ))? {
        0 => Ok(()),
        _ => Err(SyscallError::ResultOutOfRange),
    }
}

/// Write all bytes, retrying successful short writes.
///
/// A zero-length write before the buffer is complete is reported as [`SyscallError::Io`]
/// to avoid an infinite loop.
pub fn write_all(file_descriptor: u64, bytes: &[u8]) -> Result<(), SyscallError> {
    write_all_with(bytes, |remaining| write(file_descriptor, remaining))
}

/// Format directly to a file descriptor without allocating.
///
/// Formatting stops at the first write failure and returns its syscall error.
pub fn write_fmt(
    file_descriptor: u64,
    arguments: core::fmt::Arguments<'_>,
) -> Result<(), SyscallError> {
    write_fmt_with(arguments, |bytes| write(file_descriptor, bytes))
}

/// Best-effort panic reporting to stderr followed by process exit status 127.
pub fn panic_exit(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = write_fmt(STDERR, format_args!("rustix: panic: {info}\n"));
    exit(127)
}

fn write_all_with<W>(mut remaining: &[u8], mut write: W) -> Result<(), SyscallError>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    while !remaining.is_empty() {
        let written = write(remaining)?;
        if written == 0 {
            return Err(SyscallError::Io);
        }
        if written > remaining.len() {
            return Err(SyscallError::ResultOutOfRange);
        }
        remaining = &remaining[written..];
    }
    Ok(())
}

fn write_fmt_with<W>(arguments: core::fmt::Arguments<'_>, write: W) -> Result<(), SyscallError>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    let mut output = SyscallFormatter { write, error: None };
    match core::fmt::write(&mut output, arguments) {
        Ok(()) => Ok(()),
        Err(_) => Err(output.error.unwrap_or(SyscallError::Io)),
    }
}

struct SyscallFormatter<W> {
    write: W,
    error: Option<SyscallError>,
}

impl<W> core::fmt::Write for SyscallFormatter<W>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        match write_all_with(text.as_bytes(), |remaining| (self.write)(remaining)) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.error = Some(error);
                Err(core::fmt::Error)
            }
        }
    }
}

/// Wait for a child and optionally copy its signed 32-bit status to `status`.
///
/// The current kernel probe supports already-exited children; a running child
/// returns [`SyscallError::NotSupported`] until blocking process scheduling is
/// integrated.
pub fn wait(child_pid: u64, status: Option<&mut i32>) -> Result<u64, SyscallError> {
    let status_address = status.map_or(0, |status| status as *mut i32 as u64);
    decode_result(syscall(SYS_WAIT, [child_pid, status_address, 0, 0, 0, 0]))
}

/// Exit the current process. The kernel ABI does not return from a successful exit.
pub fn exit(status: i32) -> ! {
    let _ = syscall(SYS_EXIT, [status as u32 as u64, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

/// Run a process `main` and exit with its status.
///
/// Applications define `_start` as a call to this helper so `main` can return
/// normally instead of managing the exit syscall itself.
pub fn run_main(main: fn() -> i32) -> ! {
    exit(main())
}

pub const HEAP_PAGE_SIZE: usize = USER_PAGE_SIZE;
const HEAP_MIN_BLOCK: usize = 16;
const HEAP_MAX_BLOCK: usize = 2048;
const HEAP_CLASS_COUNT: usize = 8;

/// Source of page-sized, page-aligned, zeroed read/write memory for the heap.
pub trait PageSource {
    fn allocate_page(&mut self) -> Option<NonNull<u8>>;
}

/// Page source backed by one `mmap` syscall per page. Pages are never returned.
pub struct MmapPages;

impl PageSource for MmapPages {
    fn allocate_page(&mut self) -> Option<NonNull<u8>> {
        let region = mmap(1).ok()?;
        if region.address() % HEAP_PAGE_SIZE as u64 != 0 {
            let _ = munmap(region);
            return None;
        }
        NonNull::new(region.as_mut_ptr())
    }
}

/// Power-of-two size-class allocator for requests up to 2048 bytes.
///
/// Each class keeps an intrusive free list. Blocks are carved from whole pages,
/// so a block whose size is at least its alignment is naturally aligned. Freed
/// blocks are reused by their class; pages are never returned to the kernel.
/// Requests larger than 2048 bytes or requiring alignment above 2048 bytes return null.
pub struct SizeClassHeap<P> {
    pages: P,
    free: [Option<NonNull<FreeBlock>>; HEAP_CLASS_COUNT],
}

struct FreeBlock {
    next: Option<NonNull<FreeBlock>>,
}

impl<P: PageSource> SizeClassHeap<P> {
    pub const fn new(pages: P) -> Self {
        Self {
            pages,
            free: [None; HEAP_CLASS_COUNT],
        }
    }

    /// Return a block satisfying `layout`, or null when the request is out of
    /// range or no page can be obtained.
    pub fn allocate(&mut self, layout: Layout) -> *mut u8 {
        let Some(class) = size_class(layout) else {
            return null_mut();
        };
        if self.free[class].is_none() && !self.refill(class) {
            return null_mut();
        }
        let Some(block) = self.free[class] else {
            return null_mut();
        };
        // SAFETY: Every node on a free list was written by `refill` or
        // `deallocate` as an unused, exclusively owned block of this heap.
        self.free[class] = unsafe { block.as_ref().next };
        block.cast::<u8>().as_ptr()
    }

    /// Return a block to its size class.
    ///
    /// `pointer` must come from [`SizeClassHeap::allocate`] on this heap with the
    /// same `layout`, and must not be used afterward.
    pub fn deallocate(&mut self, pointer: NonNull<u8>, layout: Layout) {
        let Some(class) = size_class(layout) else {
            return;
        };
        let node = pointer.cast::<FreeBlock>();
        // SAFETY: The caller returns a block previously handed out for this
        // class, so it is at least `HEAP_MIN_BLOCK` bytes, suitably aligned,
        // and no longer in use.
        unsafe {
            node.as_ptr().write(FreeBlock {
                next: self.free[class],
            });
        }
        self.free[class] = Some(node);
    }

    fn refill(&mut self, class: usize) -> bool {
        let Some(page) = self.pages.allocate_page() else {
            return false;
        };
        let block_size = HEAP_MIN_BLOCK << class;
        for index in (0..HEAP_PAGE_SIZE / block_size).rev() {
            // SAFETY: `page` is an owned, page-sized mapping and `index` keeps
            // `offset + block_size` within it. Page alignment and the power-of-two
            // block size make the node aligned for `FreeBlock`.
            let node = unsafe { page.as_ptr().add(index * block_size) }.cast::<FreeBlock>();
            // SAFETY: `node` is inside the page and is not yet visible to any user.
            unsafe {
                node.write(FreeBlock {
                    next: self.free[class],
                });
            }
            self.free[class] = NonNull::new(node);
        }
        true
    }
}

fn size_class(layout: Layout) -> Option<usize> {
    if layout.align() > HEAP_PAGE_SIZE {
        return None;
    }
    let block = layout
        .size()
        .max(layout.align())
        .max(HEAP_MIN_BLOCK)
        .checked_next_power_of_two()?;
    if block > HEAP_MAX_BLOCK {
        return None;
    }
    Some((block / HEAP_MIN_BLOCK).trailing_zeros() as usize)
}

/// Global allocator for Rustix user processes.
///
/// Declare one with `#[global_allocator]` in an application that uses `alloc`.
/// Access is serialized by a spin lock, so the type may be shared safely.
pub struct UserAllocator {
    locked: AtomicBool,
    heap: UnsafeCell<SizeClassHeap<MmapPages>>,
}

// SAFETY: `heap` is only accessed inside `with_heap`, which holds `locked` for the
// full duration of the access, so there is never more than one live `&mut` to it.
unsafe impl Sync for UserAllocator {}

impl UserAllocator {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(SizeClassHeap::new(MmapPages)),
        }
    }

    fn with_heap<R>(&self, operation: impl FnOnce(&mut SizeClassHeap<MmapPages>) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: The acquired `locked` flag grants exclusive access until the
        // release store below, and the reference does not escape `operation`.
        let result = operation(unsafe { &mut *self.heap.get() });
        self.locked.store(false, Ordering::Release);
        result
    }
}

// SAFETY: Allocation and deallocation follow the `GlobalAlloc` contract: blocks
// returned by `alloc` satisfy `layout`, and `dealloc` is only given blocks from
// the same size class.
unsafe impl GlobalAlloc for UserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with_heap(|heap| heap.allocate(layout))
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if let Some(pointer) = NonNull::new(pointer) {
            self.with_heap(|heap| heap.deallocate(pointer, layout));
        }
    }
}

fn decode_result(result: i64) -> Result<u64, SyscallError> {
    if result >= 0 {
        return Ok(result as u64);
    }
    match result.checked_neg() {
        Some(1) => Err(SyscallError::InvalidArgument),
        Some(2) => Err(SyscallError::BadFileDescriptor),
        Some(3) => Err(SyscallError::Fault),
        Some(4) => Err(SyscallError::OutOfMemory),
        Some(5) => Err(SyscallError::NoChild),
        Some(6) => Err(SyscallError::Interrupted),
        Some(7) => Err(SyscallError::Io),
        Some(8) => Err(SyscallError::NotImplemented),
        Some(9) => Err(SyscallError::ArgumentListTooLong),
        Some(10) => Err(SyscallError::Overflow),
        Some(11) => Err(SyscallError::NotSupported),
        Some(12) => Err(SyscallError::TooManyOpenFiles),
        _ => Err(SyscallError::Unknown(result)),
    }
}

#[cfg(test)]
mod heap_tests {
    use super::{PageSource, SizeClassHeap, HEAP_PAGE_SIZE};
    use core::alloc::Layout;
    use core::ptr::NonNull;

    #[repr(align(4096))]
    struct Page([u8; HEAP_PAGE_SIZE]);

    struct Arena<'a> {
        pages: &'a mut [Page],
        next: usize,
    }

    impl PageSource for Arena<'_> {
        fn allocate_page(&mut self) -> Option<NonNull<u8>> {
            let page = self.pages.get_mut(self.next)?;
            self.next += 1;
            NonNull::new(page.0.as_mut_ptr())
        }
    }

    fn arena(pages: &mut [Page]) -> SizeClassHeap<Arena<'_>> {
        SizeClassHeap::new(Arena { pages, next: 0 })
    }

    #[test]
    fn rounds_to_aligned_blocks_and_reuses_freed_blocks() {
        let mut storage: [Page; 2] = core::array::from_fn(|_| Page([0; HEAP_PAGE_SIZE]));
        let mut heap = arena(&mut storage);
        let layout = Layout::from_size_align(40, 8).unwrap();
        let first = heap.allocate(layout);
        assert!(!first.is_null());
        assert_eq!(first as usize % 64, 0);
        heap.deallocate(NonNull::new(first).unwrap(), layout);
        assert_eq!(heap.allocate(layout), first);
    }

    #[test]
    fn honors_large_alignment_within_a_page() {
        let mut storage: [Page; 1] = core::array::from_fn(|_| Page([0; HEAP_PAGE_SIZE]));
        let mut heap = arena(&mut storage);
        let layout = Layout::from_size_align(16, 1024).unwrap();
        let block = heap.allocate(layout);
        assert!(!block.is_null());
        assert_eq!(block as usize % 1024, 0);
    }

    #[test]
    fn rejects_oversized_overaligned_and_exhausted_requests() {
        let mut storage: [Page; 1] = core::array::from_fn(|_| Page([0; HEAP_PAGE_SIZE]));
        let mut heap = arena(&mut storage);
        assert!(heap
            .allocate(Layout::from_size_align(2049, 8).unwrap())
            .is_null());
        assert!(heap
            .allocate(Layout::from_size_align(8, 8192).unwrap())
            .is_null());
        // One page holds two 2048-byte blocks; the third needs a page the arena lacks.
        let max = Layout::from_size_align(2048, 8).unwrap();
        assert!(!heap.allocate(max).is_null());
        assert!(!heap.allocate(max).is_null());
        assert!(heap.allocate(max).is_null());
    }

    #[test]
    fn keeps_size_classes_separate() {
        let mut storage: [Page; 2] = core::array::from_fn(|_| Page([0; HEAP_PAGE_SIZE]));
        let mut heap = arena(&mut storage);
        let small = Layout::from_size_align(16, 16).unwrap();
        let large = Layout::from_size_align(512, 16).unwrap();
        let small_block = heap.allocate(small);
        heap.deallocate(NonNull::new(small_block).unwrap(), small);
        let large_block = heap.allocate(large);
        assert_ne!(large_block, small_block);
        assert!(!large_block.is_null());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_result, exec_with, spawn_with, write_all_with, write_fmt_with, SyscallError,
        ABI_VERSION, MAX_INITIAL_STACK_PAGES, MAX_SPAWN_IMAGE_SIZE, SYS_EXEC, SYS_SPAWN,
    };

    #[test]
    fn decodes_nonnegative_results_and_stable_v1_errors() {
        assert_eq!(decode_result(ABI_VERSION as i64), Ok(ABI_VERSION));
        assert_eq!(decode_result(0), Ok(0));
        assert_eq!(decode_result(-3), Err(SyscallError::Fault));
        assert_eq!(decode_result(-5), Err(SyscallError::NoChild));
        assert_eq!(decode_result(-11), Err(SyscallError::NotSupported));
        assert_eq!(decode_result(-12), Err(SyscallError::TooManyOpenFiles));
        assert_eq!(decode_result(-13), Err(SyscallError::Unknown(-13)));
        assert_eq!(
            decode_result(i64::MIN),
            Err(SyscallError::Unknown(i64::MIN))
        );
    }

    #[test]
    fn spawn_encodes_the_image_and_stack_arguments() {
        let image_address = 0x4000;
        let image_length = MAX_SPAWN_IMAGE_SIZE;
        let stack_pages = MAX_INITIAL_STACK_PAGES;
        let result = spawn_with(
            image_address,
            image_length,
            stack_pages,
            |number, arguments| {
                assert_eq!(number, SYS_SPAWN);
                assert_eq!(
                    arguments,
                    [
                        image_address,
                        image_length as u64,
                        stack_pages as u64,
                        0,
                        0,
                        0
                    ]
                );
                42
            },
        );
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn spawn_rejects_invalid_bounds_before_invoking_the_syscall() {
        for (image_address, image_length, stack_pages, expected) in [
            (0x4000, 0, 1, SyscallError::InvalidArgument),
            (
                0x4000,
                MAX_SPAWN_IMAGE_SIZE + 1,
                1,
                SyscallError::ArgumentListTooLong,
            ),
            (0x4000, 1, 0, SyscallError::InvalidArgument),
            (
                0x4000,
                1,
                MAX_INITIAL_STACK_PAGES + 1,
                SyscallError::InvalidArgument,
            ),
        ] {
            let result = spawn_with(image_address, image_length, stack_pages, |_, _| {
                panic!("invalid spawn arguments must not invoke the syscall")
            });
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn spawn_decodes_syscall_success_and_existing_error_numbers() {
        assert_eq!(spawn_with(0x4000, 1, 1, |_, _| 7), Ok(7));
        assert_eq!(
            spawn_with(0x4000, 1, 1, |_, _| -9),
            Err(SyscallError::ArgumentListTooLong)
        );
        assert_eq!(
            spawn_with(0x4000, 1, 1, |_, _| -3),
            Err(SyscallError::Fault)
        );
    }

    #[test]
    fn exec_encodes_the_image_and_stack_arguments_and_reports_failures() {
        let image_address = 0x4000;
        let image_length = MAX_SPAWN_IMAGE_SIZE;
        let stack_pages = MAX_INITIAL_STACK_PAGES;
        let result = exec_with(
            image_address,
            image_length,
            stack_pages,
            |number, arguments| {
                assert_eq!(number, SYS_EXEC);
                assert_eq!(
                    arguments,
                    [
                        image_address,
                        image_length as u64,
                        stack_pages as u64,
                        0,
                        0,
                        0
                    ]
                );
                -3
            },
        );
        assert_eq!(result, Err(SyscallError::Fault));
        assert_eq!(
            exec_with(0x4000, 1, 1, |_, _| -1),
            Err(SyscallError::InvalidArgument)
        );
        assert_eq!(
            exec_with(0x4000, 1, 1, |_, _| -4),
            Err(SyscallError::OutOfMemory)
        );
    }

    #[test]
    fn exec_rejects_invalid_bounds_before_invoking_the_syscall() {
        for (image_length, stack_pages, expected) in [
            (0, 1, SyscallError::InvalidArgument),
            (
                MAX_SPAWN_IMAGE_SIZE + 1,
                1,
                SyscallError::ArgumentListTooLong,
            ),
            (1, 0, SyscallError::InvalidArgument),
            (
                1,
                MAX_INITIAL_STACK_PAGES + 1,
                SyscallError::InvalidArgument,
            ),
        ] {
            let result = exec_with(0x4000, image_length, stack_pages, |_, _| {
                panic!("invalid exec arguments must not invoke the syscall")
            });
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn write_all_retries_short_writes_until_complete() {
        let mut output = [0; 5];
        let mut output_length = 0;
        let result = write_all_with(b"hello", |remaining| {
            let count = remaining.len().min(2);
            output[output_length..output_length + count].copy_from_slice(&remaining[..count]);
            output_length += count;
            Ok(count)
        });
        assert_eq!(result, Ok(()));
        assert_eq!(&output[..output_length], b"hello");
    }

    #[test]
    fn write_all_rejects_zero_and_impossible_write_counts() {
        assert_eq!(write_all_with(b"x", |_| Ok(0)), Err(SyscallError::Io));
        assert_eq!(
            write_all_with(b"x", |_| Ok(2)),
            Err(SyscallError::ResultOutOfRange)
        );
        assert_eq!(
            write_all_with(b"x", |_| Err(SyscallError::Fault)),
            Err(SyscallError::Fault)
        );
    }

    #[test]
    fn formatting_is_allocation_free_and_preserves_write_errors() {
        let mut output = [0; 8];
        let mut output_length = 0;
        let result = write_fmt_with(format_args!("value={}", 42), |remaining| {
            let count = remaining.len().min(3);
            output[output_length..output_length + count].copy_from_slice(&remaining[..count]);
            output_length += count;
            Ok(count)
        });
        assert_eq!(result, Ok(()));
        assert_eq!(&output[..output_length], b"value=42");

        assert_eq!(
            write_fmt_with(format_args!("failure"), |_| Err(SyscallError::Fault)),
            Err(SyscallError::Fault)
        );
    }
}
