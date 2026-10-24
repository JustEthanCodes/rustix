//! A bounded kernel heap backed by a static, page-mapped kernel data arena.
//!
//! The arena is 256 KiB and tracks at most 128 simultaneous allocations. It
//! uses first-fit placement with the requested `Layout` alignment, reclaims
//! exact allocations on free, and returns allocation failure when either the
//! arena or metadata table is exhausted. It never grows or requests frames.
//!
//! The global wrapper serializes access with a spin lock. Allocation is not
//! permitted from interrupt context: an interrupt that preempts a lock holder
//! could otherwise deadlock. The current kernel is single-core and keeps
//! maskable interrupts disabled; future IRQ or scheduling support must provide
//! an IRQ-safe allocation policy before allocating in those contexts.

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

/// A `GlobalAlloc` wrapper for the fixed kernel arena.
///
/// The lock prevents concurrent mutation of allocation metadata. The arena
/// storage must remain at a stable address while allocations are live; the
/// kernel's `#[global_allocator]` static has that property.
pub struct LockedHeap<const HEAP_SIZE: usize, const MAX_ALLOCATIONS: usize> {
    locked: AtomicBool,
    heap: UnsafeCell<FixedHeap<HEAP_SIZE, MAX_ALLOCATIONS>>,
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
        }
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
        // SAFETY: The lock grants exclusive access to the heap state.
        let heap = unsafe { &mut *self.heap.get() };
        heap.allocate(layout)
            .map(NonNull::as_ptr)
            .unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some(pointer) = NonNull::new(pointer) else {
            return;
        };
        let _lock = self.acquire();
        // SAFETY: The lock grants exclusive access to the heap state. The
        // GlobalAlloc caller must provide a live allocation and its original layout.
        let heap = unsafe { &mut *self.heap.get() };
        let _ = heap.deallocate(pointer, layout);
    }
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;
    use core::assert_eq;

    use super::{FixedHeap, HeapError};

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
    fn rejects_zero_sized_layouts() {
        let mut heap = FixedHeap::<128, 4>::new();
        let layout = Layout::from_size_align(0, 8).unwrap();
        assert_eq!(heap.allocate(layout), Err(HeapError::ZeroSizedAllocation));
    }

    use core::ptr::NonNull;
}
