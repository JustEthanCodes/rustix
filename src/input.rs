//! Bounded single-producer/single-consumer input queues for device IRQ paths.
//!
//! Each queue has one producer (its device IRQ handler) and one consumer on the
//! bootstrap CPU. Producers never wait or allocate; full queues drop the newest
//! byte and increment a saturating overflow counter.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const INPUT_QUEUE_CAPACITY: usize = 256;

pub static UART_INPUT: ByteRing<INPUT_QUEUE_CAPACITY> = ByteRing::new();
pub static KEYBOARD_INPUT: ByteRing<INPUT_QUEUE_CAPACITY> = ByteRing::new();
pub static INPUT_EVENT_PENDING: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// A fixed-capacity SPSC queue. Its producer and consumer must remain unique.
pub struct ByteRing<const CAPACITY: usize> {
    bytes: [AtomicU8; CAPACITY],
    head: AtomicUsize,
    tail: AtomicUsize,
    overflows: AtomicUsize,
}

impl<const CAPACITY: usize> ByteRing<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            bytes: [const { AtomicU8::new(0) }; CAPACITY],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            overflows: AtomicUsize::new(0),
        }
    }

    /// Push without waiting. Returns false when the queue is full.
    pub fn try_push(&self, byte: u8) -> bool {
        if CAPACITY == 0 {
            self.increment_overflows();
            return false;
        }
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= CAPACITY {
            self.increment_overflows();
            return false;
        }
        self.bytes[head % CAPACITY].store(byte, Ordering::Relaxed);
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Pop one byte if available; this never waits.
    pub fn try_pop(&self) -> Option<u8> {
        if CAPACITY == 0 {
            return None;
        }
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let byte = self.bytes[tail % CAPACITY].load(Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(byte)
    }

    pub fn overflow_count(&self) -> usize {
        self.overflows.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    fn increment_overflows(&self) {
        let _ = self
            .overflows
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
    }
}

impl<const CAPACITY: usize> Default for ByteRing<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteRing;
    use core::assert_eq;

    #[test]
    fn bounded_queue_preserves_order_and_reports_overflow() {
        let queue = ByteRing::<3>::new();
        assert!(queue.is_empty());
        assert!(queue.try_push(b'a'));
        assert!(queue.try_push(b'b'));
        assert!(queue.try_push(b'c'));
        assert!(!queue.try_push(b'd'));
        assert_eq!(queue.overflow_count(), 1);
        assert_eq!(queue.try_pop(), Some(b'a'));
        assert!(queue.try_push(b'd'));
        assert_eq!(queue.try_pop(), Some(b'b'));
        assert_eq!(queue.try_pop(), Some(b'c'));
        assert_eq!(queue.try_pop(), Some(b'd'));
        assert_eq!(queue.try_pop(), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn zero_capacity_queue_fails_without_dividing_or_waiting() {
        let queue = ByteRing::<0>::new();
        assert!(!queue.try_push(1));
        assert_eq!(queue.try_pop(), None);
        assert_eq!(queue.overflow_count(), 1);
    }
}
