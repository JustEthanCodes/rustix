//! A bounded kernel heap with a static bootstrap arena and optional frame-backed growth.
//!
//! The bootstrap arena is 256 KiB and tracks at most 128 allocations. An optional
//! extension maps pages on demand inside a caller-reserved virtual range, with
//! its own fixed allocation table and a caller-supplied transactional mapper.
//! Growth is bounded; allocation fails when either arena or metadata is full.
//!
//! The global wrapper serializes access with a spin lock. Allocation is not
//! permitted from interrupt or exception context: an interrupt that preempts a
//! lock holder could otherwise deadlock. IRQ handlers must remain allocation-free.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

/// Fixed capacity of the initial BSS-backed kernel heap.
pub const KERNEL_HEAP_CAPACITY: usize = 256 * 1024;
/// Maximum number of live allocations tracked by the initial kernel heap.
pub const KERNEL_HEAP_MAX_ALLOCATIONS: usize = 128;

/// The statically allocated heap type used by the kernel binary.
pub type KernelHeap = LockedHeap<KERNEL_HEAP_CAPACITY, KERNEL_HEAP_MAX_ALLOCATIONS>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeapError {
    ZeroSizedAllocation,
    AllocationTableFull,
    OutOfMemory,
    AddressOverflow,
    InvalidPointer,
    LayoutMismatch,
}

#[derive(Clone, Copy)]
struct Allocation {
    start: usize,
    size: usize,
    alignment: usize,
}

struct FixedHeap<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> {
    arena: [u8; HEAP_SIZE],
    allocations: [Option<Allocation>; MAX_ALLOCATIONS],
}

impl<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> FixedHeap<HEAP_SIZE, MAX_ALLOCATIONS> {
    const fn new() -> Self {
        Self {
            arena: [0; HEAP_SIZE],
            allocations: [None; MAX_ALLOCATIONS],
        }
    }

    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, HeapError> {
        if layout.size() == 0 {
            return Err(HeapError::ZeroSizedAllocation);
        }
        let slot = self
            .allocations
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::AllocationTableFull)?;
        let start = self.find_gap(layout)?;
        self.allocations[slot] = Some(Allocation {
            start,
            size: layout.size(),
            alignment: layout.align(),
        });

        let pointer = self.arena.as_mut_ptr().wrapping_add(start);
        NonNull::new(pointer).ok_or(HeapError::AddressOverflow)
    }

    fn deallocate(&mut self, pointer: NonNull<u8>, layout: Layout) -> Result<(), HeapError> {
        if layout.size() == 0 {
            return Err(HeapError::ZeroSizedAllocation);
        }
        let arena_start = self.arena.as_ptr() as usize;
        let allocation_start = (pointer.as_ptr() as usize)
            .checked_sub(arena_start)
            .filter(|offset| *offset < HEAP_SIZE)
            .ok_or(HeapError::InvalidPointer)?;

        for allocation in &mut self.allocations {
            let Some(active) = *allocation else {
                continue;
            };
            if active.start != allocation_start {
                continue;
            }
            if active.size != layout.size() || active.alignment != layout.align() {
                return Err(HeapError::LayoutMismatch);
            }
            *allocation = None;
            return Ok(());
        }
        Err(HeapError::InvalidPointer)
    }

    fn find_gap(&self, layout: Layout) -> Result<usize, HeapError> {
        let arena_start = self.arena.as_ptr() as usize;
        let mut candidate = 0usize;

        loop {
            let candidate_address = arena_start
                .checked_add(candidate)
                .ok_or(HeapError::AddressOverflow)?;
            let aligned_address = candidate_address
                .checked_add(layout.align() - 1)
                .ok_or(HeapError::AddressOverflow)?
                & !(layout.align() - 1);
            let start = aligned_address
                .checked_sub(arena_start)
                .ok_or(HeapError::AddressOverflow)?;
            let end = start
                .checked_add(layout.size())
                .ok_or(HeapError::AddressOverflow)?;
            if end > HEAP_SIZE {
                return Err(HeapError::OutOfMemory);
            }

            let mut conflicting_end = None;
            for allocation in self.allocations.iter().flatten() {
                let allocation_end = allocation
                    .start
                    .checked_add(allocation.size)
                    .ok_or(HeapError::AddressOverflow)?;
                if start < allocation_end && allocation.start < end {
                    conflicting_end = Some(
                        conflicting_end
                            .map_or(allocation_end, |end: usize| end.max(allocation_end)),
                    );
                }
            }

            match conflicting_end {
                Some(end) => candidate = end,
                None => return Ok(start),
            }
        }
    }
}

pub type HeapPageMapper = unsafe fn(context: *mut (), first_page: usize, page_count: usize) -> bool;

struct FrameBackedHeap<const MAX_ALLOCATIONS: usize> {
    base: usize,
    capacity_pages: usize,
    mapped_pages: usize,
    allocations: [Option<Allocation>; MAX_ALLOCATIONS],
    context: *mut (),
    map_pages: Option<HeapPageMapper>,
}

impl<const MAX_ALLOCATIONS: usize> FrameBackedHeap<MAX_ALLOCATIONS> {
    const fn new() -> Self {
        Self {
            base: 0,
            capacity_pages: 0,
            mapped_pages: 0,
            allocations: [None; MAX_ALLOCATIONS],
            context: core::ptr::null_mut(),
            map_pages: None,
        }
    }

    fn configure(
        &mut self,
        base: usize,
        capacity_pages: usize,
        context: *mut (),
        map_pages: HeapPageMapper,
    ) -> Result<(), FrameHeapInitError> {
        let capacity = capacity_pages
            .checked_mul(PAGE_BYTES)
            .and_then(|bytes| base.checked_add(bytes));
        if self.map_pages.is_some()
            || base == 0
            || base % PAGE_BYTES != 0
            || capacity_pages == 0
            || capacity.is_none()
        {
            return Err(if self.map_pages.is_some() {
                FrameHeapInitError::AlreadyConfigured
            } else {
                FrameHeapInitError::InvalidRange
            });
        }
        self.base = base;
        self.capacity_pages = capacity_pages;
        self.context = context;
        self.map_pages = Some(map_pages);
        Ok(())
    }

    fn contains_pointer(&self, pointer: usize) -> bool {
        self.capacity_pages
            .checked_mul(PAGE_BYTES)
            .and_then(|capacity| self.base.checked_add(capacity).map(|end| (capacity, end)))
            .is_some_and(|(capacity, end)| capacity != 0 && (self.base..end).contains(&pointer))
    }

    fn allocate(&mut self, layout: Layout) -> Result<NonNull<u8>, HeapError> {
        if layout.size() == 0 {
            return Err(HeapError::ZeroSizedAllocation);
        }
        let map_pages = self.map_pages.ok_or(HeapError::OutOfMemory)?;
        let slot = self
            .allocations
            .iter()
            .position(Option::is_none)
            .ok_or(HeapError::AllocationTableFull)?;
        let start = self.find_gap(layout)?;
        let end = start
            .checked_add(layout.size())
            .ok_or(HeapError::AddressOverflow)?;
        let required_pages = end
            .checked_add(PAGE_BYTES - 1)
            .ok_or(HeapError::AddressOverflow)?
            / PAGE_BYTES;
        if required_pages > self.mapped_pages {
            let first_page = self.mapped_pages;
            let page_count = required_pages - first_page;
            // SAFETY: Configuration is unsafe at the public boundary. The
            // mapper contract requires an all-or-nothing mapping of this range.
            if !unsafe { map_pages(self.context, first_page, page_count) } {
                return Err(HeapError::OutOfMemory);
            }
            self.mapped_pages = required_pages;
        }

        self.allocations[slot] = Some(Allocation {
            start,
            size: layout.size(),
            alignment: layout.align(),
        });
        let pointer = self
            .base
            .checked_add(start)
            .ok_or(HeapError::AddressOverflow)?;
        NonNull::new(pointer as *mut u8).ok_or(HeapError::AddressOverflow)
    }

    fn deallocate(&mut self, pointer: NonNull<u8>, layout: Layout) -> Result<(), HeapError> {
        if layout.size() == 0 {
            return Err(HeapError::ZeroSizedAllocation);
        }
        let allocation_start = (pointer.as_ptr() as usize)
            .checked_sub(self.base)
            .filter(|offset| *offset < self.capacity_pages.saturating_mul(PAGE_BYTES))
            .ok_or(HeapError::InvalidPointer)?;
        for allocation in &mut self.allocations {
            let Some(active) = *allocation else {
                continue;
            };
            if active.start != allocation_start {
                continue;
            }
            if active.size != layout.size() || active.alignment != layout.align() {
                return Err(HeapError::LayoutMismatch);
            }
            *allocation = None;
            return Ok(());
        }
        Err(HeapError::InvalidPointer)
    }

    fn find_gap(&self, layout: Layout) -> Result<usize, HeapError> {
        let capacity = self
            .capacity_pages
            .checked_mul(PAGE_BYTES)
            .ok_or(HeapError::AddressOverflow)?;
        let mut candidate = 0usize;
        loop {
            let candidate_address = self
                .base
                .checked_add(candidate)
                .ok_or(HeapError::AddressOverflow)?;
            let aligned_address = candidate_address
                .checked_add(layout.align() - 1)
                .ok_or(HeapError::AddressOverflow)?
                & !(layout.align() - 1);
            let start = aligned_address
                .checked_sub(self.base)
                .ok_or(HeapError::AddressOverflow)?;
            let end = start
                .checked_add(layout.size())
                .ok_or(HeapError::AddressOverflow)?;
            if end > capacity {
                return Err(HeapError::OutOfMemory);
            }
            let mut conflicting_end = None;
            for allocation in self.allocations.iter().flatten() {
                let allocation_end = allocation
                    .start
                    .checked_add(allocation.size)
                    .ok_or(HeapError::AddressOverflow)?;
                if start < allocation_end && allocation.start < end {
                    conflicting_end = Some(
                        conflicting_end
                            .map_or(allocation_end, |current: usize| current.max(allocation_end)),
                    );
                }
            }
            match conflicting_end {
                Some(end) => candidate = end,
                None => return Ok(start),
            }
        }
    }
}

const PAGE_BYTES: usize = 4096;

/// Errors reported while installing the optional frame-backed heap region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameHeapInitError {
    InvalidRange,
    AlreadyConfigured,
}

/// A `GlobalAlloc` wrapper for the fixed bootstrap arena and bounded growth region.
///
/// The bootstrap arena and callback context must remain at stable addresses for
/// the lifetime of allocations. The growth callback must map the complete page
/// range transactionally and must not allocate or call this heap recursively.
pub struct LockedHeap<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> {
    locked: AtomicBool,
    heap: UnsafeCell<FixedHeap<HEAP_SIZE, MAX_ALLOCATIONS>>,
    growth: UnsafeCell<FrameBackedHeap<MAX_ALLOCATIONS>>,
}

// SAFETY: `heap` is accessed mutably only while the Acquire/Release spin lock
// is held. The allocator is not IRQ-safe; callers must follow the module's
// interrupt-context restriction.
unsafe impl<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> Sync
    for LockedHeap<HEAP_SIZE, MAX_ALLOCATIONS>
{
}

impl<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> LockedHeap<HEAP_SIZE, MAX_ALLOCATIONS> {
    /// Construct an empty allocator. The backing arena is zero-initialized BSS.
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(FixedHeap::new()),
            growth: UnsafeCell::new(FrameBackedHeap::new()),
        }
    }

    /// Configure one reserved virtual range for demand-mapped heap growth.
    ///
    /// # Safety
    ///
    /// The caller must reserve the complete range exclusively, keep `context`
    /// alive and stable until the allocator is no longer used, and provide a
    /// mapper that atomically maps all requested pages or leaves the range
    /// unchanged. The mapper must not allocate or re-enter this allocator.
    pub unsafe fn initialize_frame_backed_region(
        &self,
        base: usize,
        capacity_pages: usize,
        context: *mut (),
        map_pages: HeapPageMapper,
    ) -> Result<(), FrameHeapInitError> {
        let _lock = self.acquire();
        // SAFETY: The lock grants exclusive access to the growth configuration.
        let growth = unsafe { &mut *self.growth.get() };
        growth.configure(base, capacity_pages, context, map_pages)
    }

    fn acquire(&self) -> HeapLock<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        HeapLock {
            locked: &self.locked,
        }
    }
}

struct HeapLock<'a> {
    locked: &'a AtomicBool,
}

impl Drop for HeapLock<'_> {
    fn drop(&mut self) {
        self.locked.store(false, Ordering::Release);
    }
}

unsafe impl<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> GlobalAlloc
    for LockedHeap<HEAP_SIZE, MAX_ALLOCATIONS>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _lock = self.acquire();
        // SAFETY: The lock grants exclusive access to both allocator regions.
        let heap = unsafe { &mut *self.heap.get() };
        // SAFETY: The same lock exclusively protects the growth metadata and
        // callback configuration. Its mapper contract forbids allocator reentry.
        let growth = unsafe { &mut *self.growth.get() };
        heap.allocate(layout)
            .or_else(|_| growth.allocate(layout))
            .map(NonNull::as_ptr)
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some(pointer) = NonNull::new(pointer) else {
            return;
        };
        let _lock = self.acquire();
        // SAFETY: The lock grants exclusive access to both allocator regions. The
        // GlobalAlloc caller must provide a live allocation and its original layout.
        let heap = unsafe { &mut *self.heap.get() };
        // SAFETY: The same lock exclusively protects growth allocation metadata.
        let growth = unsafe { &mut *self.growth.get() };
        if growth.contains_pointer(pointer.as_ptr() as usize) {
            let _ = growth.deallocate(pointer, layout);
        } else {
            let _ = heap.deallocate(pointer, layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;
    use core::assert_eq;

    use super::{FixedHeap, FrameBackedHeap, HeapError, PAGE_BYTES};

    #[repr(align(4096))]
    struct TestRegion([u8; PAGE_BYTES * 2]);

    #[derive(Default)]
    struct MapTrace {
        mapped_pages: usize,
        fail: bool,
    }

    unsafe fn test_map_pages(context: *mut (), _first_page: usize, page_count: usize) -> bool {
        // SAFETY: Tests pass a live, exclusively used `MapTrace` pointer.
        let trace = unsafe { &mut *context.cast::<MapTrace>() };
        if trace.fail {
            return false;
        }
        trace.mapped_pages += page_count;
        true
    }

    #[test]
    fn honors_layout_alignment_and_reuses_freed_allocations() {
        let mut heap = FixedHeap::<256, 4>::new();
        let layout = Layout::from_size_align(37, 64).unwrap();
        let allocation = heap.allocate(layout).unwrap();
        assert_eq!(allocation.as_ptr() as usize % layout.align(), 0);

        // SAFETY: The pointer names a live allocation of the requested size.
        unsafe { allocation.as_ptr().write_bytes(0xa5, layout.size()) };
        for index in 0..layout.size() {
            // SAFETY: `index` is bounded by the live allocation's size.
            assert_eq!(unsafe { allocation.as_ptr().add(index).read() }, 0xa5);
        }

        heap.deallocate(allocation, layout).unwrap();
        let reused = heap.allocate(layout).unwrap();
        assert_eq!(reused, allocation);
        heap.deallocate(reused, layout).unwrap();
    }

    #[test]
    fn reports_arena_exhaustion_and_reuses_a_coalesced_gap() {
        let mut heap = FixedHeap::<128, 4>::new();
        let full_layout = Layout::from_size_align(64, 1).unwrap();
        let first = heap.allocate(full_layout).unwrap();
        let second = heap.allocate(full_layout).unwrap();
        assert_eq!(
            heap.allocate(Layout::from_size_align(1, 1).unwrap()),
            Err(HeapError::OutOfMemory)
        );

        heap.deallocate(first, full_layout).unwrap();
        let smaller_layout = Layout::from_size_align(32, 1).unwrap();
        let reused = heap.allocate(smaller_layout).unwrap();
        assert_eq!(reused, first);
        heap.deallocate(reused, smaller_layout).unwrap();
        heap.deallocate(second, full_layout).unwrap();
    }

    #[test]
    fn reports_allocation_metadata_exhaustion() {
        let mut heap = FixedHeap::<128, 1>::new();
        let layout = Layout::from_size_align(8, 1).unwrap();
        let allocation = heap.allocate(layout).unwrap();
        assert_eq!(heap.allocate(layout), Err(HeapError::AllocationTableFull));
        heap.deallocate(allocation, layout).unwrap();
        assert!(heap.allocate(layout).is_ok());
    }

    #[test]
    fn rejects_invalid_pointer_and_layout_without_releasing_memory() {
        let mut heap = FixedHeap::<128, 4>::new();
        let layout = Layout::from_size_align(16, 8).unwrap();
        let allocation = heap.allocate(layout).unwrap();
        let wrong_layout = Layout::from_size_align(8, 8).unwrap();
        assert_eq!(
            heap.deallocate(allocation, wrong_layout),
            Err(HeapError::LayoutMismatch)
        );
        assert_eq!(
            heap.deallocate(NonNull::dangling(), layout),
            Err(HeapError::InvalidPointer)
        );
        heap.deallocate(allocation, layout).unwrap();
        assert_eq!(
            heap.deallocate(allocation, layout),
            Err(HeapError::InvalidPointer)
        );
    }

    #[test]
    fn frame_backed_heap_maps_on_demand_and_reuses_freed_allocations() {
        let mut region = TestRegion([0; PAGE_BYTES * 2]);
        let mut trace = MapTrace::default();
        let mut heap = FrameBackedHeap::<4>::new();
        heap.configure(
            region.0.as_mut_ptr() as usize,
            2,
            core::ptr::addr_of_mut!(trace).cast(),
            test_map_pages,
        )
        .unwrap();
        let layout = Layout::from_size_align(5000, 16).unwrap();
        let allocation = heap.allocate(layout).unwrap();
        assert_eq!(allocation.as_ptr() as usize % layout.align(), 0);
        assert_eq!(trace.mapped_pages, 2);
        assert_eq!(heap.mapped_pages, 2);
        // SAFETY: The test mapper records a successful mapping of the complete
        // aligned in-memory region used as the backing store for this heap.
        unsafe { allocation.as_ptr().add(4999).write(0xa5) };
        // SAFETY: The final byte lies within the live 5000-byte allocation.
        assert_eq!(unsafe { allocation.as_ptr().add(4999).read() }, 0xa5);
        heap.deallocate(allocation, layout).unwrap();
        let reused = heap.allocate(layout).unwrap();
        assert_eq!(reused, allocation);
        assert_eq!(trace.mapped_pages, 2);
        heap.deallocate(reused, layout).unwrap();
    }

    #[test]
    fn failed_frame_backed_growth_leaves_heap_metadata_unchanged() {
        let mut region = TestRegion([0; PAGE_BYTES * 2]);
        let mut trace = MapTrace {
            mapped_pages: 0,
            fail: true,
        };
        let mut heap = FrameBackedHeap::<2>::new();
        heap.configure(
            region.0.as_mut_ptr() as usize,
            2,
            core::ptr::addr_of_mut!(trace).cast(),
            test_map_pages,
        )
        .unwrap();
        let layout = Layout::from_size_align(PAGE_BYTES + 1, 1).unwrap();
        assert_eq!(heap.allocate(layout), Err(HeapError::OutOfMemory));
        assert_eq!(heap.mapped_pages, 0);
        assert!(heap.allocations.iter().all(Option::is_none));
        assert_eq!(trace.mapped_pages, 0);

        trace.fail = false;
        let allocation = heap.allocate(layout).unwrap();
        assert_eq!(heap.mapped_pages, 2);
        assert_eq!(trace.mapped_pages, 2);
        heap.deallocate(allocation, layout).unwrap();
    }

    #[test]
    fn rejects_zero_sized_layouts() {
        let mut heap = FixedHeap::<128, 4>::new();
        let layout = Layout::from_size_align(0, 8).unwrap();
        assert_eq!(heap.allocate(layout), Err(HeapError::ZeroSizedAllocation));
    }

    use core::ptr::NonNull;
}
