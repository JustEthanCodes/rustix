//! Host-testable ownership for x86 interrupt vectors reserved for device IRQs.
//!
//! Architectural exceptions occupy vectors 0–31. The upper range 0xf0–0xff is
//! kept unavailable for future local-APIC/spurious vectors, and 0x80 is reserved
//! for the planned user syscall gate. Allocated device vectors therefore come
//! from 0x20–0xef except 0x80. This allocator does not install IDT gates,
//! configure a controller, or enable interrupt delivery.

pub const FIRST_DEVICE_VECTOR: u8 = 0x20;
pub const LAST_DEVICE_VECTOR: u8 = 0xef;
pub const SYSCALL_VECTOR: u8 = 0x80;
const VECTOR_COUNT: usize = 256;
const VECTOR_BITMAP_WORDS: usize = VECTOR_COUNT / u64::BITS as usize;

/// A vector allocation token. Tokens are not `Copy` or `Clone` and must be
/// returned to the allocator instance that produced them.
#[derive(Debug, PartialEq, Eq)]
pub struct InterruptVector(u8);

impl InterruptVector {
    pub const fn number(&self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorReleaseError {
    ReservedVector,
    NotAllocated,
}

/// Failure to return a token preserves ownership by returning that token.
#[derive(Debug, PartialEq, Eq)]
pub struct VectorReleaseFailure {
    pub error: VectorReleaseError,
    pub vector: InterruptVector,
}

/// Fixed-capacity allocator for device vectors 0x20 through 0xef except 0x80.
///
/// Only one allocator may manage a given CPU's vector namespace. The caller is
/// responsible for keeping it alive while any returned tokens are in use.
pub struct InterruptVectorAllocator {
    allocated: [u64; VECTOR_BITMAP_WORDS],
    allocated_count: usize,
}

impl InterruptVectorAllocator {
    pub const fn new() -> Self {
        let mut allocated = [u64::MAX; VECTOR_BITMAP_WORDS];
        let mut vector = FIRST_DEVICE_VECTOR;
        while vector <= LAST_DEVICE_VECTOR {
            if vector != SYSCALL_VECTOR {
                let word = vector as usize / u64::BITS as usize;
                let bit = vector as usize % u64::BITS as usize;
                allocated[word] &= !(1u64 << bit);
            }
            vector += 1;
        }
        Self {
            allocated,
            allocated_count: 0,
        }
    }

    pub fn allocate(&mut self) -> Option<InterruptVector> {
        for number in FIRST_DEVICE_VECTOR..=LAST_DEVICE_VECTOR {
            if number == SYSCALL_VECTOR {
                continue;
            }
            let word = number as usize / u64::BITS as usize;
            let bit = number as usize % u64::BITS as usize;
            let mask = 1u64 << bit;
            if self.allocated[word] & mask == 0 {
                self.allocated[word] |= mask;
                self.allocated_count += 1;
                return Some(InterruptVector(number));
            }
        }
        None
    }

    pub fn release(&mut self, vector: InterruptVector) -> Result<(), VectorReleaseFailure> {
        if !(FIRST_DEVICE_VECTOR..=LAST_DEVICE_VECTOR).contains(&vector.0)
            || vector.0 == SYSCALL_VECTOR
        {
            return Err(VectorReleaseFailure {
                error: VectorReleaseError::ReservedVector,
                vector,
            });
        }
        let word = vector.0 as usize / u64::BITS as usize;
        let bit = vector.0 as usize % u64::BITS as usize;
        let mask = 1u64 << bit;
        if self.allocated[word] & mask == 0 {
            return Err(VectorReleaseFailure {
                error: VectorReleaseError::NotAllocated,
                vector,
            });
        }
        self.allocated[word] &= !mask;
        debug_assert!(self.allocated_count > 0);
        self.allocated_count = self.allocated_count.saturating_sub(1);
        Ok(())
    }

    pub const fn allocated_count(&self) -> usize {
        self.allocated_count
    }
}

impl Default for InterruptVectorAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InterruptVectorAllocator, VectorReleaseError, FIRST_DEVICE_VECTOR, LAST_DEVICE_VECTOR,
        SYSCALL_VECTOR,
    };
    use core::assert_eq;

    #[test]
    fn allocates_only_from_the_device_vector_range() {
        let mut allocator = InterruptVectorAllocator::new();
        let first = allocator.allocate().unwrap();
        assert_eq!(first.number(), FIRST_DEVICE_VECTOR);

        for expected in (FIRST_DEVICE_VECTOR + 1)..=LAST_DEVICE_VECTOR {
            if expected != SYSCALL_VECTOR {
                assert_eq!(allocator.allocate().unwrap().number(), expected);
            }
        }
        assert_eq!(allocator.allocated_count(), 207);
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn syscall_vector_is_never_allocated_or_released_as_a_device_vector() {
        let mut allocator = InterruptVectorAllocator::new();
        let mut count = 0;
        while let Some(vector) = allocator.allocate() {
            assert_ne!(vector.number(), SYSCALL_VECTOR);
            count += 1;
        }
        assert_eq!(count, 207);
        assert_eq!(allocator.allocated_count(), 207);

        let failure = allocator
            .release(super::InterruptVector(SYSCALL_VECTOR))
            .unwrap_err();
        assert_eq!(failure.error, VectorReleaseError::ReservedVector);
        assert_eq!(failure.vector.number(), SYSCALL_VECTOR);
        assert_eq!(allocator.allocated_count(), 207);
    }

    #[test]
    fn released_vectors_are_reused_without_leaking_tokens_on_failure() {
        let mut allocator = InterruptVectorAllocator::new();
        let token = allocator.allocate().unwrap();
        let number = token.number();
        assert_eq!(allocator.allocated_count(), 1);

        allocator.release(token).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.allocate().unwrap().number(), number);
    }

    #[test]
    fn allocation_exhaustion_is_bounded_and_deterministic() {
        let mut allocator = InterruptVectorAllocator::new();
        let mut count = 0;
        while allocator.allocate().is_some() {
            count += 1;
        }
        assert_eq!(count, 207);
        assert_eq!(allocator.allocated_count(), count);
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn failed_release_returns_the_unmodified_vector_token() {
        let mut first = InterruptVectorAllocator::new();
        let mut second = InterruptVectorAllocator::new();
        let token = first.allocate().unwrap();
        let failure = second.release(token).unwrap_err();
        assert_eq!(failure.error, VectorReleaseError::NotAllocated);
        assert_eq!(failure.vector.number(), FIRST_DEVICE_VECTOR);
        assert_eq!(second.allocated_count(), 0);
        assert_eq!(first.allocated_count(), 1);
    }
}
