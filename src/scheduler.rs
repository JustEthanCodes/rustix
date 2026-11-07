//! Fixed-capacity policy state for single-vCPU cooperative threads.
//!
//! This module does not own stacks, switch CPU contexts, access hardware, or
//! synchronize against interrupts. One owner on one CPU must serialize every
//! call. A thread is either ready, the sole running thread, blocked on exactly
//! one live wait queue, or exited. Exited slots remain occupied until `reap`.
//! Dispatch scans slots in deterministic round-robin order; waiters are woken
//! in FIFO order. All storage is inline and bounded by the const capacities.

/// Opaque identity for a thread slot allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadId {
    slot: usize,
    generation: u64,
}

impl ThreadId {
    pub const fn slot_index(self) -> usize {
        self.slot
    }
}

/// Build the fresh stack frame consumed by the x86_64 cooperative switch.
///
/// The saved-register order is R15, R14, R13, R12, RBP, RBX, followed by the
/// trampoline return address. The returned address is 16-byte aligned; after
/// six pops and `ret`, the trampoline observes the SysV entry alignment
/// (`RSP % 16 == 8`). This helper only prepares bounded inline stack storage.
pub fn initialize_thread_context_stack(
    stack: &mut [usize],
    saved_registers: [usize; 6],
    trampoline: usize,
) -> Option<usize> {
    const REGISTER_SLOTS: usize = 6;
    const FRAME_SLOTS: usize = REGISTER_SLOTS + 1;
    let word_size = core::mem::size_of::<usize>();
    let frame_bytes = FRAME_SLOTS.checked_mul(word_size)?;
    let stack_bytes = stack.len().checked_mul(word_size)?;
    let stack_start = stack.as_mut_ptr() as usize;
    let stack_end = stack_start.checked_add(stack_bytes)?;
    let frame_start = stack_end.checked_sub(frame_bytes)? & !15usize;
    let frame_offset = frame_start.checked_sub(stack_start)?;
    if frame_offset % word_size != 0 {
        return None;
    }
    let first_slot = frame_offset / word_size;
    let frame_end = first_slot.checked_add(FRAME_SLOTS)?;
    if frame_end > stack.len() || frame_start & 15 != 0 {
        return None;
    }

    stack[first_slot..first_slot + REGISTER_SLOTS].copy_from_slice(&saved_registers);
    stack[first_slot + REGISTER_SLOTS] = trampoline;
    Some(frame_start)
}

/// Opaque identity for a wait-queue allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitQueueId {
    slot: usize,
    generation: u64,
}

/// Lifecycle state of a live thread slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked(WaitQueueId),
    Exited,
}

/// Failures are explicit; rejected operations leave policy state unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    ThreadCapacityFull,
    WaitQueueCapacityFull,
    WaiterCapacityFull,
    InvalidThread,
    InvalidWaitQueue,
    NoCurrentThread,
    CurrentThreadRunning,
    ThreadNotExited,
    WaitQueueNotEmpty,
    GenerationExhausted,
    InvalidTransition,
}

#[derive(Clone, Copy)]
struct ThreadSlot {
    generation: u64,
    state: Option<ThreadState>,
}

impl ThreadSlot {
    const EMPTY: Self = Self {
        generation: 0,
        state: None,
    };
}

#[derive(Clone, Copy)]
struct WaitQueue<const WAITERS: usize> {
    generation: u64,
    active: bool,
    waiters: [Option<ThreadId>; WAITERS],
    len: usize,
}

impl<const WAITERS: usize> WaitQueue<WAITERS> {
    const EMPTY: Self = Self {
        generation: 0,
        active: false,
        waiters: [None; WAITERS],
        len: 0,
    };
}

/// Bounded scheduler policy with no allocation or architecture dependencies.
///
/// `THREADS` bounds all live threads, including exited threads not yet reaped;
/// `QUEUES` bounds live wait queues; and `WAITERS` bounds each queue. The
/// scheduler enforces at most one running thread and consistent blocked/queue
/// membership, but its single-owner/single-CPU contract is caller-enforced.
pub struct Scheduler<const THREADS: usize, const QUEUES: usize, const WAITERS: usize> {
    threads: [ThreadSlot; THREADS],
    queues: [WaitQueue<WAITERS>; QUEUES],
    current: Option<ThreadId>,
    next_ready: usize,
}

impl<const THREADS: usize, const QUEUES: usize, const WAITERS: usize>
    Scheduler<THREADS, QUEUES, WAITERS>
{
    /// Create an empty scheduler. Zero capacities are permitted and fail
    /// explicitly when the corresponding resource is requested.
    pub const fn new() -> Self {
        Self {
            threads: [ThreadSlot::EMPTY; THREADS],
            queues: [WaitQueue::EMPTY; QUEUES],
            current: None,
            next_ready: 0,
        }
    }

    /// Add a ready thread, returning its generation-checked slot identity.
    pub fn create_thread(&mut self) -> Result<ThreadId, SchedulerError> {
        let mut generation_exhausted = false;
        for (index, slot) in self.threads.iter_mut().enumerate() {
            if slot.state.is_some() {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                generation_exhausted = true;
                continue;
            };
            slot.generation = generation;
            slot.state = Some(ThreadState::Ready);
            return Ok(ThreadId {
                slot: index,
                generation,
            });
        }
        if generation_exhausted {
            Err(SchedulerError::GenerationExhausted)
        } else {
            Err(SchedulerError::ThreadCapacityFull)
        }
    }

    /// Current running thread, if any.
    pub const fn current(&self) -> Option<ThreadId> {
        self.current
    }

    /// Query a live thread's lifecycle state. Stale and unknown IDs are rejected.
    pub fn state(&self, thread: ThreadId) -> Result<ThreadState, SchedulerError> {
        let slot = self.thread_slot(thread)?;
        slot.state.ok_or(SchedulerError::InvalidThread)
    }

    /// Select the next ready thread when the CPU has no running thread.
    pub fn dispatch(&mut self) -> Result<Option<ThreadId>, SchedulerError> {
        if self.current.is_some() {
            return Err(SchedulerError::CurrentThreadRunning);
        }
        Ok(self.select_ready())
    }

    /// Cooperatively yield the running thread and dispatch the next ready one.
    pub fn yield_current(&mut self) -> Result<ThreadId, SchedulerError> {
        let current = self.current.ok_or(SchedulerError::NoCurrentThread)?;
        let slot = self.thread_slot_mut(current)?;
        if slot.state != Some(ThreadState::Running) {
            return Err(SchedulerError::InvalidTransition);
        }
        slot.state = Some(ThreadState::Ready);
        self.current = None;
        self.select_ready().ok_or(SchedulerError::InvalidTransition)
    }

    /// Exit the running thread and dispatch another ready thread, if one exists.
    /// The exited slot remains unavailable until explicitly reaped.
    pub fn exit_current(&mut self) -> Result<Option<ThreadId>, SchedulerError> {
        let current = self.current.ok_or(SchedulerError::NoCurrentThread)?;
        let slot = self.thread_slot_mut(current)?;
        if slot.state != Some(ThreadState::Running) {
            return Err(SchedulerError::InvalidTransition);
        }
        slot.state = Some(ThreadState::Exited);
        self.current = None;
        Ok(self.select_ready())
    }

    /// Release an exited thread slot so it can be reused with a new ID.
    pub fn reap(&mut self, thread: ThreadId) -> Result<(), SchedulerError> {
        let slot = self.thread_slot_mut(thread)?;
        if slot.state != Some(ThreadState::Exited) {
            return Err(SchedulerError::ThreadNotExited);
        }
        slot.state = None;
        Ok(())
    }

    /// Create an empty bounded wait queue.
    pub fn create_wait_queue(&mut self) -> Result<WaitQueueId, SchedulerError> {
        let mut generation_exhausted = false;
        for (index, queue) in self.queues.iter_mut().enumerate() {
            if queue.active {
                continue;
            }
            let Some(generation) = queue.generation.checked_add(1) else {
                generation_exhausted = true;
                continue;
            };
            queue.generation = generation;
            queue.active = true;
            queue.len = 0;
            queue.waiters.fill(None);
            return Ok(WaitQueueId {
                slot: index,
                generation,
            });
        }
        if generation_exhausted {
            Err(SchedulerError::GenerationExhausted)
        } else {
            Err(SchedulerError::WaitQueueCapacityFull)
        }
    }

    /// Destroy an empty queue. A queue with sleepers cannot be destroyed.
    pub fn destroy_wait_queue(&mut self, queue: WaitQueueId) -> Result<(), SchedulerError> {
        let queue = self.queue_slot_mut(queue)?;
        if queue.len != 0 {
            return Err(SchedulerError::WaitQueueNotEmpty);
        }
        queue.active = false;
        Ok(())
    }

    /// Block the running thread on a queue, then dispatch another ready thread.
    /// A full or invalid queue leaves the current thread running.
    pub fn sleep_current(
        &mut self,
        queue_id: WaitQueueId,
    ) -> Result<Option<ThreadId>, SchedulerError> {
        let queue = self.queue_slot(queue_id)?;
        if queue.len == WAITERS {
            return Err(SchedulerError::WaiterCapacityFull);
        }
        let current = self.current.ok_or(SchedulerError::NoCurrentThread)?;
        let thread = self.thread_slot(current)?;
        if thread.state != Some(ThreadState::Running) {
            return Err(SchedulerError::InvalidTransition);
        }

        let queue = &mut self.queues[queue_id.slot];
        queue.waiters[queue.len] = Some(current);
        queue.len += 1;
        self.threads[current.slot].state = Some(ThreadState::Blocked(queue_id));
        self.current = None;
        Ok(self.select_ready())
    }

    /// Wake the oldest waiter, making it ready but not preempting the current
    /// thread. Returns `None` when the valid queue has no waiters.
    pub fn wake_one(&mut self, queue_id: WaitQueueId) -> Result<Option<ThreadId>, SchedulerError> {
        let queue = self.queue_slot(queue_id)?;
        if queue.len == 0 {
            return Ok(None);
        }
        let thread_id = queue.waiters[0].ok_or(SchedulerError::InvalidTransition)?;
        let thread = self.thread_slot(thread_id)?;
        if thread.state != Some(ThreadState::Blocked(queue_id)) {
            return Err(SchedulerError::InvalidTransition);
        }

        let queue = &mut self.queues[queue_id.slot];
        for index in 1..queue.len {
            queue.waiters[index - 1] = queue.waiters[index];
        }
        queue.len -= 1;
        queue.waiters[queue.len] = None;
        self.threads[thread_id.slot].state = Some(ThreadState::Ready);
        Ok(Some(thread_id))
    }

    /// Wake every waiter in FIFO order, making them ready without preemption.
    pub fn wake_all(&mut self, queue_id: WaitQueueId) -> Result<usize, SchedulerError> {
        let queue = self.queue_slot(queue_id)?;
        let count = queue.len;

        for waiter in queue.waiters[..count].iter().flatten() {
            let thread = self.thread_slot(*waiter)?;
            if thread.state != Some(ThreadState::Blocked(queue_id)) {
                return Err(SchedulerError::InvalidTransition);
            }
        }

        for waiter in self.queues[queue_id.slot].waiters[..count].iter().flatten() {
            self.threads[waiter.slot].state = Some(ThreadState::Ready);
        }
        let queue = &mut self.queues[queue_id.slot];
        queue.waiters.fill(None);
        queue.len = 0;
        Ok(count)
    }

    fn select_ready(&mut self) -> Option<ThreadId> {
        if THREADS == 0 {
            return None;
        }
        for offset in 0..THREADS {
            let index = (self.next_ready + offset) % THREADS;
            if self.threads[index].state == Some(ThreadState::Ready) {
                let thread = ThreadId {
                    slot: index,
                    generation: self.threads[index].generation,
                };
                self.threads[index].state = Some(ThreadState::Running);
                self.current = Some(thread);
                self.next_ready = (index + 1) % THREADS;
                return Some(thread);
            }
        }
        None
    }

    fn thread_slot(&self, thread: ThreadId) -> Result<&ThreadSlot, SchedulerError> {
        self.threads
            .get(thread.slot)
            .filter(|slot| slot.generation == thread.generation && slot.state.is_some())
            .ok_or(SchedulerError::InvalidThread)
    }

    fn thread_slot_mut(&mut self, thread: ThreadId) -> Result<&mut ThreadSlot, SchedulerError> {
        self.threads
            .get_mut(thread.slot)
            .filter(|slot| slot.generation == thread.generation && slot.state.is_some())
            .ok_or(SchedulerError::InvalidThread)
    }

    fn queue_slot(&self, queue: WaitQueueId) -> Result<&WaitQueue<WAITERS>, SchedulerError> {
        self.queues
            .get(queue.slot)
            .filter(|slot| slot.active && slot.generation == queue.generation)
            .ok_or(SchedulerError::InvalidWaitQueue)
    }

    fn queue_slot_mut(
        &mut self,
        queue: WaitQueueId,
    ) -> Result<&mut WaitQueue<WAITERS>, SchedulerError> {
        self.queues
            .get_mut(queue.slot)
            .filter(|slot| slot.active && slot.generation == queue.generation)
            .ok_or(SchedulerError::InvalidWaitQueue)
    }
}

impl<const THREADS: usize, const QUEUES: usize, const WAITERS: usize> Default
    for Scheduler<THREADS, QUEUES, WAITERS>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{initialize_thread_context_stack, Scheduler, SchedulerError, ThreadState};
    use core::assert_eq;

    type TestScheduler = Scheduler<3, 2, 2>;

    #[test]
    fn fresh_context_frame_has_sysv_alignment_and_saved_register_order() {
        let mut stack = [0usize; 32];
        let registers = [15, 14, 13, 12, 5, 3];
        let trampoline = 0x1234_5678usize;
        let rsp = initialize_thread_context_stack(&mut stack, registers, trampoline).unwrap();
        let first_slot = (rsp - stack.as_ptr() as usize) / core::mem::size_of::<usize>();

        assert_eq!(rsp & 15, 0);
        assert_eq!((rsp + 7 * core::mem::size_of::<usize>()) & 15, 8);
        assert_eq!(&stack[first_slot..first_slot + 6], &registers);
        assert_eq!(stack[first_slot + 6], trampoline);
    }

    #[test]
    fn fresh_context_frame_rejects_insufficient_stack_without_writing() {
        let mut stack = [usize::MAX; 6];
        assert_eq!(
            initialize_thread_context_stack(&mut stack, [0; 6], 0x1234),
            None
        );
        assert_eq!(stack, [usize::MAX; 6]);
    }

    #[test]
    fn round_robin_dispatch_yield_and_exit_follow_lifecycle() {
        let mut scheduler = TestScheduler::new();
        let first = scheduler.create_thread().unwrap();
        let second = scheduler.create_thread().unwrap();
        let third = scheduler.create_thread().unwrap();

        assert_eq!(scheduler.state(first), Ok(ThreadState::Ready));
        assert_eq!(scheduler.dispatch(), Ok(Some(first)));
        assert_eq!(scheduler.current(), Some(first));
        assert_eq!(scheduler.state(first), Ok(ThreadState::Running));
        assert_eq!(
            scheduler.dispatch(),
            Err(SchedulerError::CurrentThreadRunning)
        );

        assert_eq!(scheduler.yield_current(), Ok(second));
        assert_eq!(scheduler.state(first), Ok(ThreadState::Ready));
        assert_eq!(scheduler.yield_current(), Ok(third));
        assert_eq!(scheduler.exit_current(), Ok(Some(first)));
        assert_eq!(scheduler.state(third), Ok(ThreadState::Exited));
        assert_eq!(scheduler.reap(third), Ok(()));
        assert_eq!(scheduler.state(third), Err(SchedulerError::InvalidThread));

        let replacement = scheduler.create_thread().unwrap();
        assert_ne!(replacement, third);
        assert_eq!(scheduler.state(replacement), Ok(ThreadState::Ready));
    }

    #[test]
    fn final_thread_can_yield_to_itself_and_exit_to_idle() {
        let mut scheduler = Scheduler::<1, 0, 0>::new();
        let only = scheduler.create_thread().unwrap();
        assert_eq!(scheduler.dispatch(), Ok(Some(only)));
        assert_eq!(scheduler.yield_current(), Ok(only));
        assert_eq!(scheduler.exit_current(), Ok(None));
        assert_eq!(scheduler.current(), None);
        assert_eq!(scheduler.dispatch(), Ok(None));
        assert_eq!(scheduler.reap(only), Ok(()));
    }

    #[test]
    fn queues_wake_in_fifo_order_and_do_not_preempt() {
        let mut scheduler = TestScheduler::new();
        let queue = scheduler.create_wait_queue().unwrap();
        let first = scheduler.create_thread().unwrap();
        let second = scheduler.create_thread().unwrap();
        let third = scheduler.create_thread().unwrap();

        assert_eq!(scheduler.dispatch(), Ok(Some(first)));
        assert_eq!(scheduler.sleep_current(queue), Ok(Some(second)));
        assert_eq!(scheduler.state(first), Ok(ThreadState::Blocked(queue)));
        assert_eq!(scheduler.sleep_current(queue), Ok(Some(third)));
        assert_eq!(scheduler.state(second), Ok(ThreadState::Blocked(queue)));
        assert_eq!(scheduler.wake_one(queue), Ok(Some(first)));
        assert_eq!(scheduler.current(), Some(third));
        assert_eq!(scheduler.state(first), Ok(ThreadState::Ready));
        assert_eq!(scheduler.wake_one(queue), Ok(Some(second)));
        assert_eq!(scheduler.wake_one(queue), Ok(None));

        assert_eq!(scheduler.exit_current(), Ok(Some(first)));
        assert_eq!(scheduler.exit_current(), Ok(Some(second)));
        assert_eq!(scheduler.exit_current(), Ok(None));
    }

    #[test]
    fn wake_all_makes_every_waiter_ready_and_queue_can_be_reused() {
        let mut scheduler = TestScheduler::new();
        let queue = scheduler.create_wait_queue().unwrap();
        let a = scheduler.create_thread().unwrap();
        let b = scheduler.create_thread().unwrap();
        let c = scheduler.create_thread().unwrap();

        scheduler.dispatch().unwrap();
        scheduler.sleep_current(queue).unwrap();
        scheduler.sleep_current(queue).unwrap();
        assert_eq!(scheduler.wake_all(queue), Ok(2));
        assert_eq!(scheduler.state(a), Ok(ThreadState::Ready));
        assert_eq!(scheduler.state(b), Ok(ThreadState::Ready));
        assert_eq!(scheduler.state(c), Ok(ThreadState::Running));
        assert_eq!(scheduler.wake_all(queue), Ok(0));
        assert_eq!(scheduler.destroy_wait_queue(queue), Ok(()));

        let reused = scheduler.create_wait_queue().unwrap();
        assert_ne!(queue, reused);
        assert_eq!(
            scheduler.wake_one(queue),
            Err(SchedulerError::InvalidWaitQueue)
        );
        assert_eq!(scheduler.wake_one(reused), Ok(None));
    }

    #[test]
    fn capacity_and_invalid_operations_are_explicit_and_non_mutating() {
        let mut scheduler = Scheduler::<1, 1, 1>::new();
        assert_eq!(
            scheduler.yield_current(),
            Err(SchedulerError::NoCurrentThread)
        );
        assert_eq!(
            scheduler.exit_current(),
            Err(SchedulerError::NoCurrentThread)
        );

        let queue = scheduler.create_wait_queue().unwrap();
        assert_eq!(
            scheduler.create_wait_queue(),
            Err(SchedulerError::WaitQueueCapacityFull)
        );
        assert_eq!(
            scheduler.sleep_current(queue),
            Err(SchedulerError::NoCurrentThread)
        );
        let thread = scheduler.create_thread().unwrap();
        assert_eq!(
            scheduler.create_thread(),
            Err(SchedulerError::ThreadCapacityFull)
        );
        assert_eq!(scheduler.reap(thread), Err(SchedulerError::ThreadNotExited));
        assert_eq!(scheduler.state(thread), Ok(ThreadState::Ready));

        scheduler.dispatch().unwrap();
        scheduler.sleep_current(queue).unwrap();
        assert_eq!(
            scheduler.destroy_wait_queue(queue),
            Err(SchedulerError::WaitQueueNotEmpty)
        );
        assert_eq!(
            scheduler.create_thread(),
            Err(SchedulerError::ThreadCapacityFull)
        );
        assert_eq!(scheduler.wake_one(queue), Ok(Some(thread)));
        assert_eq!(scheduler.state(thread), Ok(ThreadState::Ready));
        assert_eq!(scheduler.dispatch(), Ok(Some(thread)));
        assert_eq!(scheduler.exit_current(), Ok(None));
        scheduler.reap(thread).unwrap();
        assert_eq!(scheduler.destroy_wait_queue(queue), Ok(()));
    }

    #[test]
    fn full_queue_rejects_sleep_without_blocking_the_running_thread() {
        let mut scheduler = Scheduler::<2, 1, 1>::new();
        let queue = scheduler.create_wait_queue().unwrap();
        let first = scheduler.create_thread().unwrap();
        let second = scheduler.create_thread().unwrap();

        scheduler.dispatch().unwrap();
        scheduler.sleep_current(queue).unwrap();
        let current_before = scheduler.current();
        assert_eq!(
            scheduler.sleep_current(queue),
            Err(SchedulerError::WaiterCapacityFull)
        );
        assert_eq!(scheduler.current(), current_before);
        assert_eq!(scheduler.state(second), Ok(ThreadState::Running));
        assert_eq!(scheduler.state(first), Ok(ThreadState::Blocked(queue)));
    }

    #[test]
    fn stale_thread_and_queue_handles_are_rejected_after_reuse() {
        let mut scheduler = Scheduler::<1, 1, 1>::new();
        let old_thread = scheduler.create_thread().unwrap();
        scheduler.dispatch().unwrap();
        scheduler.exit_current().unwrap();
        scheduler.reap(old_thread).unwrap();
        let new_thread = scheduler.create_thread().unwrap();
        assert_ne!(old_thread, new_thread);
        assert_eq!(
            scheduler.state(old_thread),
            Err(SchedulerError::InvalidThread)
        );

        let old_queue = scheduler.create_wait_queue().unwrap();
        scheduler.destroy_wait_queue(old_queue).unwrap();
        let new_queue = scheduler.create_wait_queue().unwrap();
        assert_ne!(old_queue, new_queue);
        assert_eq!(
            scheduler.wake_one(old_queue),
            Err(SchedulerError::InvalidWaitQueue)
        );
    }

    #[test]
    fn zero_capacities_are_valid_and_report_exhaustion() {
        let mut scheduler = Scheduler::<0, 0, 0>::new();
        assert_eq!(scheduler.dispatch(), Ok(None));
        assert_eq!(
            scheduler.create_thread(),
            Err(SchedulerError::ThreadCapacityFull)
        );
        assert_eq!(
            scheduler.create_wait_queue(),
            Err(SchedulerError::WaitQueueCapacityFull)
        );
    }
}
