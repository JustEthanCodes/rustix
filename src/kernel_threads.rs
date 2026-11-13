//! Fixed-capacity single-vCPU kernel-thread runtime and scheduling smoke tests.
//!
//! Thread stacks are allocator-owned 4 KiB mappings with one unmapped lower
//! guard page. Scheduler state is mutated only with local interrupts disabled.
//! The PIT handler may preempt a running thread by suspending its own call stack
//! on that thread's kernel stack and switching to another saved context.

use crate::kprintln;
use core::arch::asm;
#[cfg(feature = "probe-kernel-threads")]
use core::hint::spin_loop;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use rustix_kernel::frame::{Frame, FrameAllocator};

use rustix_kernel::paging::{
    validate_mapping_range, CachePolicy, CandidatePageTableMemory, CandidatePageTables,
    EffectiveMemoryType, MtrrState, PagePermissions, PageWalkOutcome, PatLayout, PAGE_SIZE,
};
use rustix_kernel::scheduler::{
    initialize_thread_context_stack, Scheduler, SchedulerError, ThreadId, ThreadState, WaitQueueId,
};
use rustix_kernel::time::AtomicTickCounter;

const MAX_THREADS: usize = 2;
const THREAD_STACK_PAGES: usize = 4;
const THREAD_STACK_STRIDE: u64 = (THREAD_STACK_PAGES as u64 + 1) * PAGE_SIZE;
const THREAD_STACK_VIRTUAL_BASE: u64 = 0xffff_c400_0000_0000;
const CONTEXT_COUNT: usize = MAX_THREADS + 1;
const QUEUE_COUNT: usize = MAX_THREADS + 1;
const _: [(); QUEUE_COUNT] = [(); MAX_THREADS + 1];

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct FxSaveArea([u8; 512]);

impl FxSaveArea {
    const INITIAL: Self = {
        let mut bytes = [0; 512];
        bytes[0] = 0x7f;
        bytes[1] = 0x03;
        bytes[24] = 0x80;
        bytes[25] = 0x1f;
        Self(bytes)
    };
}

const _: [(); 512] = [(); core::mem::size_of::<FxSaveArea>()];
const _: [(); 16] = [(); core::mem::align_of::<FxSaveArea>()];

static THREAD_TEST_TRACE: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_RUNTIME: AtomicPtr<KernelThreadRuntime> = AtomicPtr::new(core::ptr::null_mut());
static mut BOOTSTRAP_FX_STATE: FxSaveArea = FxSaveArea::INITIAL;
#[export_name = "rustix_active_fpu_state_pointer"]
static mut ACTIVE_FX_STATE_POINTER: *mut FxSaveArea = core::ptr::null_mut();

/// Initialize the IRQ assembly's FXSAVE destination before any IRQ route is armed.
pub(crate) fn initialize_fpu_context() {
    // SAFETY: Bootstrap runs with IF clear and this pointer is published before
    // the timer or device IRQ routes can be unmasked.
    unsafe {
        ACTIVE_FX_STATE_POINTER = core::ptr::addr_of_mut!(BOOTSTRAP_FX_STATE);
    }
}

#[cfg(feature = "probe-kernel-threads")]
static PREEMPTION_A_STARTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "probe-kernel-threads")]
static PREEMPTION_B_STARTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "probe-kernel-threads")]
static PREEMPTION_TEST_FAILED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "probe-kernel-threads")]
static PREEMPTION_FPU_FAILED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "probe-kernel-threads")]
const PREEMPTION_TEST_TICK_BUDGET: u64 = 8;
#[cfg(feature = "probe-kernel-threads")]
const PREEMPTION_PATTERN_A: [u8; 16] = [0xa1; 16];
#[cfg(feature = "probe-kernel-threads")]
const PREEMPTION_PATTERN_B: [u8; 16] = [0xb2; 16];

type ThreadEntry = extern "C" fn(*mut (), usize);

struct KernelThreadRuntime {
    policy: Scheduler<MAX_THREADS, QUEUE_COUNT, MAX_THREADS>,
    saved_rsp: [usize; CONTEXT_COUNT],
    fx_state: [FxSaveArea; CONTEXT_COUNT],
    thread_ids: [Option<ThreadId>; MAX_THREADS],
    stack_virtual_starts: [Option<u64>; MAX_THREADS],
    entries: [Option<ThreadEntry>; MAX_THREADS],
    arguments: [usize; MAX_THREADS],
    deadlines: [Option<u64>; MAX_THREADS],
    event_queue: WaitQueueId,
    timer_queues: [WaitQueueId; MAX_THREADS],
    current_context: usize,
    input_events_enabled: bool,
    ticks: &'static AtomicTickCounter,
}

impl KernelThreadRuntime {
    fn new(ticks: &'static AtomicTickCounter) -> Result<Self, SchedulerError> {
        let mut policy = Scheduler::new();
        let event_queue = policy.create_wait_queue()?;
        let mut timer_queues = [event_queue; MAX_THREADS];
        for queue in &mut timer_queues {
            *queue = policy.create_wait_queue()?;
        }
        Ok(Self {
            policy,
            saved_rsp: [0; CONTEXT_COUNT],
            fx_state: [FxSaveArea::INITIAL; CONTEXT_COUNT],
            thread_ids: [None; MAX_THREADS],
            stack_virtual_starts: [None; MAX_THREADS],
            entries: [None; MAX_THREADS],
            arguments: [0; MAX_THREADS],
            deadlines: [None; MAX_THREADS],
            event_queue,
            timer_queues,
            current_context: 0,
            input_events_enabled: false,
            ticks,
        })
    }

    fn all_threads_exited(&self) -> bool {
        self.thread_ids
            .iter()
            .flatten()
            .all(|thread| self.policy.state(*thread) == Ok(ThreadState::Exited))
    }

    fn wake_expired(&mut self) {
        let now = self.ticks.ticks();
        for slot in 0..MAX_THREADS {
            if self.deadlines[slot].is_some_and(|deadline| now >= deadline) {
                self.deadlines[slot] = None;
                if self.policy.wake_one(self.timer_queues[slot]).is_err() {
                    THREAD_TEST_TRACE.store(99, Ordering::Release);
                }
            }
        }
    }

    fn wake_ready_events(&mut self) -> bool {
        self.wake_expired();
        let input_event = self.input_events_enabled
            && rustix_kernel::input::INPUT_EVENT_PENDING.swap(false, Ordering::AcqRel);
        if input_event && self.policy.wake_all(self.event_queue).is_err() {
            THREAD_TEST_TRACE.store(99, Ordering::Release);
        }
        input_event
    }

    unsafe fn run_from_raw(runtime_pointer: *mut Self) {
        let initial_flags = disable_interrupts();
        if ACTIVE_RUNTIME
            .compare_exchange(
                core::ptr::null_mut(),
                runtime_pointer,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            halt_on_stack_cleanup_failure();
        }
        let first = {
            // SAFETY: The caller supplies the live, exclusively owned runtime;
            // the temporary reference ends before the context switch.
            let runtime = unsafe { &mut *runtime_pointer };
            match runtime.policy.dispatch() {
                Ok(Some(thread)) => {
                    let context = thread.slot_index() + 1;
                    runtime.current_context = context;
                    Some((context, runtime.saved_rsp[context]))
                }
                Ok(None) => None,
                Err(_) => {
                    THREAD_TEST_TRACE.store(99, Ordering::Release);
                    None
                }
            }
        };
        if let Some((new_context, new_rsp)) = first {
            // SAFETY: Context zero is the active bootstrap stack; the selected
            // synthetic frame and both aligned FXSAVE areas remain live.
            unsafe {
                rustix_arch_context_switch(
                    core::ptr::addr_of_mut!((*runtime_pointer).saved_rsp[0]),
                    new_rsp as *mut usize,
                    core::ptr::addr_of_mut!((*runtime_pointer).fx_state[0]),
                    core::ptr::addr_of_mut!((*runtime_pointer).fx_state[new_context]),
                );
            }
        }
        restore_interrupts(initial_flags);

        loop {
            let flags = disable_interrupts();
            let (new_context, new_rsp, finished) = {
                // SAFETY: No other thread runs while IF is clear. All mutable
                // scheduler borrows end before any subsequent context switch.
                let runtime = unsafe { &mut *runtime_pointer };
                runtime.wake_ready_events();
                if runtime.all_threads_exited() {
                    (None, None, true)
                } else {
                    match runtime.policy.dispatch() {
                        Ok(Some(thread)) => {
                            let context = thread.slot_index() + 1;
                            runtime.current_context = context;
                            (Some(context), Some(runtime.saved_rsp[context]), false)
                        }
                        Ok(None) => (None, None, false),
                        Err(_) => {
                            THREAD_TEST_TRACE.store(99, Ordering::Release);
                            (None, None, true)
                        }
                    }
                }
            };
            if finished {
                ACTIVE_RUNTIME.store(core::ptr::null_mut(), Ordering::Release);
                unsafe { save_bootstrap_fx_state() };
                restore_interrupts(flags);
                return;
            }
            if let (Some(new_context), Some(new_rsp)) = (new_context, new_rsp) {
                // SAFETY: The bootstrap context is currently active and the
                // selected stack and FXSAVE area remain owned by this runtime.
                unsafe {
                    rustix_arch_context_switch(
                        core::ptr::addr_of_mut!((*runtime_pointer).saved_rsp[0]),
                        new_rsp as *mut usize,
                        core::ptr::addr_of_mut!((*runtime_pointer).fx_state[0]),
                        core::ptr::addr_of_mut!((*runtime_pointer).fx_state[new_context]),
                    );
                }
                restore_interrupts(flags);
            } else {
                // `sti; hlt` is atomic with respect to the interrupt shadow, so
                // a PIT wakeup cannot be lost between checking deadlines and halt.
                // SAFETY: The verified PIT handler is installed and the only
                // unmasked device route; it performs no allocation or scheduling.
                unsafe { asm!("sti; hlt") };
            }
        }
    }
}

/// Run a single long-lived cooperative worker on an owned guarded stack.
pub fn run_shell<M: CandidatePageTableMemory>(
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: *mut FrameAllocator,
    cpu_info: &crate::arch::x86_64::cpu::CpuInfo,
    ticks: &'static AtomicTickCounter,
    entry: extern "C" fn(*mut (), usize),
    argument: usize,
) -> ! {
    let mut runtime =
        KernelThreadRuntime::new(ticks).unwrap_or_else(|_| halt_on_stack_cleanup_failure());
    runtime.input_events_enabled = true;
    let runtime_pointer = core::ptr::addr_of_mut!(runtime);
    let flags = disable_interrupts();
    // SAFETY: The caller supplies the live allocator retained by BootInfo. This
    // exclusive borrow is limited to stack setup and ends before context switches.
    let spawned = unsafe {
        spawn_thread(
            &mut runtime,
            candidate,
            &mut *allocator,
            cpu_info,
            runtime_pointer,
            entry,
            argument,
        )
    };
    if spawned.is_err() {
        restore_interrupts(flags);
        halt_on_stack_cleanup_failure();
    }
    restore_interrupts(flags);
    // SAFETY: The caller keeps the active root, allocator, CPU snapshot, thread
    // context, and callback argument alive for this non-returning kernel runtime.
    unsafe { KernelThreadRuntime::run_from_raw(runtime_pointer) };
    let flags = disable_interrupts();
    // SAFETY: No worker is running after `run_from_raw` returns, so the raw
    // allocator pointer is exclusively available for final stack cleanup.
    let allocator = unsafe { &mut *allocator };
    reap_exited_stacks(&mut runtime, candidate, allocator);
    restore_interrupts(flags);
    halt_on_stack_cleanup_failure()
}

/// Block the current cooperative thread until an input IRQ publishes an event.
pub(crate) fn wait_for_input(runtime_pointer: *mut ()) {
    // SAFETY: Only a normal cooperative thread calls this; IRQ handlers merely
    // publish the atomic event and never touch scheduler policy state.
    if !unsafe { block_current(runtime_pointer.cast(), None) } {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
    }
}

/// Exercise real switching, stack guards, event wakeup, timed sleep, and timer preemption.
/// The caller must provide the current active root, keep this single-vCPU kernel
/// path alive for the call, and have already enabled the verified PIT route.
#[cfg(feature = "probe-kernel-threads")]
pub fn smoke<M: CandidatePageTableMemory>(
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: &mut FrameAllocator,
    cpu_info: &crate::arch::x86_64::cpu::CpuInfo,
    ticks: &'static AtomicTickCounter,
) -> Result<(), &'static str> {
    THREAD_TEST_TRACE.store(0, Ordering::Release);
    if !irq_spin_lock_preserves_interrupt_state() {
        return Err("IRQ-save spin lock failed to mask or restore IF");
    }
    kprintln!("IRQ-save lock path passed: prior IF state preserved");

    let mut runtime = KernelThreadRuntime::new(ticks).map_err(|_| "scheduler setup failed")?;
    let runtime_pointer = core::ptr::addr_of_mut!(runtime);

    let flags = disable_interrupts();
    let first = spawn_thread(
        &mut runtime,
        candidate,
        allocator,
        cpu_info,
        runtime_pointer,
        waiter_thread,
        0,
    );
    let second = if first.is_ok() {
        spawn_thread(
            &mut runtime,
            candidate,
            allocator,
            cpu_info,
            runtime_pointer,
            signaler_thread,
            0,
        )
    } else {
        Err("waiter thread stack setup failed")
    };
    restore_interrupts(flags);

    if first.is_err() || second.is_err() {
        cancel_unstarted_threads(&mut runtime);
        let flags = disable_interrupts();
        reap_exited_stacks(&mut runtime, candidate, allocator);
        restore_interrupts(flags);
        return Err(first
            .err()
            .or(second.err())
            .unwrap_or("thread setup failed"));
    }

    // Every stack slot was checked page by page during setup: the lower guard is
    // absent, and all four stack leaves are supervisor RW/NX with the selected WB type.
    kprintln!("kernel thread stacks verified: mapped RW/NX with absent lower guards");
    // SAFETY: The runtime remains on the bootstrap stack and is passed by raw
    // pointer; no mutable reference is retained across the context switches.
    unsafe { KernelThreadRuntime::run_from_raw(runtime_pointer) };

    let passed = THREAD_TEST_TRACE.load(Ordering::Acquire) == 5
        && ticks.ticks() >= 2
        && runtime.all_threads_exited();
    let flags = disable_interrupts();
    reap_exited_stacks(&mut runtime, candidate, allocator);
    restore_interrupts(flags);
    if !passed {
        return Err("cooperative yield/wakeup/timed-sleep sequence failed");
    }
    kprintln!("cooperative thread path passed: yield, event wakeup, timed sleep, stack guards");
    timer_preemption_smoke(candidate, allocator, cpu_info, ticks)
}

#[cfg(feature = "probe-kernel-threads")]
fn irq_spin_lock_preserves_interrupt_state() -> bool {
    use rustix_kernel::sync::IrqSpinLock;

    fn interrupts_enabled() -> bool {
        let flags: u64;
        // SAFETY: Reading RFLAGS is non-mutating in the CPL 0 QEMU probe.
        unsafe { asm!("pushfq", "pop {}", out(reg) flags) };
        flags & (1 << 9) != 0
    }

    let lock = IrqSpinLock::new(());
    let initially_enabled = interrupts_enabled();
    let masked_while_held = {
        let _guard = lock.lock();
        !interrupts_enabled()
    };
    let restored_after_enabled = interrupts_enabled() == initially_enabled;

    let flags = disable_interrupts();
    let masked_while_already_disabled = {
        let _guard = lock.lock();
        !interrupts_enabled()
    };
    let remained_disabled_after_drop = !interrupts_enabled();
    restore_interrupts(flags);

    initially_enabled
        && masked_while_held
        && restored_after_enabled
        && masked_while_already_disabled
        && remained_disabled_after_drop
}

#[cfg(feature = "probe-kernel-threads")]
fn timer_preemption_smoke<M: CandidatePageTableMemory>(
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: &mut FrameAllocator,
    cpu_info: &crate::arch::x86_64::cpu::CpuInfo,
    ticks: &'static AtomicTickCounter,
) -> Result<(), &'static str> {
    PREEMPTION_A_STARTED.store(0, Ordering::Release);
    PREEMPTION_B_STARTED.store(0, Ordering::Release);
    PREEMPTION_TEST_FAILED.store(0, Ordering::Release);
    PREEMPTION_FPU_FAILED.store(0, Ordering::Release);

    let mut runtime =
        KernelThreadRuntime::new(ticks).map_err(|_| "preemption scheduler setup failed")?;
    let runtime_pointer = core::ptr::addr_of_mut!(runtime);
    let ticks_pointer = ticks as *const AtomicTickCounter as usize;

    let flags = disable_interrupts();
    let first = spawn_thread(
        &mut runtime,
        candidate,
        allocator,
        cpu_info,
        runtime_pointer,
        non_yielding_preemption_worker_a,
        ticks_pointer,
    );
    let second = if first.is_ok() {
        spawn_thread(
            &mut runtime,
            candidate,
            allocator,
            cpu_info,
            runtime_pointer,
            non_yielding_preemption_worker_b,
            ticks_pointer,
        )
    } else {
        Err("first preemption worker stack setup failed")
    };
    restore_interrupts(flags);

    if first.is_err() || second.is_err() {
        cancel_unstarted_threads(&mut runtime);
        let flags = disable_interrupts();
        reap_exited_stacks(&mut runtime, candidate, allocator);
        restore_interrupts(flags);
        return Err(first
            .err()
            .or(second.err())
            .unwrap_or("preemption worker setup failed"));
    }

    // Both workers busy-wait without yielding. Worker B can start only after a
    // PIT interrupt preempts worker A. Worker A also checks that its live XMM0
    // value survives the interrupt handler and another thread's execution.
    unsafe { KernelThreadRuntime::run_from_raw(runtime_pointer) };
    let passed = PREEMPTION_A_STARTED.load(Ordering::Acquire) == 1
        && PREEMPTION_B_STARTED.load(Ordering::Acquire) == 1
        && PREEMPTION_TEST_FAILED.load(Ordering::Acquire) == 0
        && PREEMPTION_FPU_FAILED.load(Ordering::Acquire) == 0
        && runtime.all_threads_exited();
    let flags = disable_interrupts();
    reap_exited_stacks(&mut runtime, candidate, allocator);
    restore_interrupts(flags);
    if !passed {
        return Err("timer did not preempt a non-yielding thread within the tick budget");
    }
    kprintln!("timer preemption path passed: non-yielding workers and FPU state survived");
    Ok(())
}

#[cfg(feature = "probe-kernel-threads")]
extern "C" fn non_yielding_preemption_worker_a(_runtime: *mut (), ticks_pointer: usize) {
    PREEMPTION_A_STARTED.store(1, Ordering::Release);
    let ticks = unsafe { &*(ticks_pointer as *const AtomicTickCounter) };
    let deadline = ticks.ticks().saturating_add(PREEMPTION_TEST_TICK_BUDGET);
    unsafe {
        asm!(
            "movdqu xmm0, xmmword ptr [{pattern}]",
            pattern = in(reg) PREEMPTION_PATTERN_A.as_ptr(),
            out("xmm0") _,
            options(readonly, nostack, preserves_flags),
        );
    }
    while PREEMPTION_B_STARTED.load(Ordering::Acquire) == 0 {
        if ticks.ticks() >= deadline {
            PREEMPTION_TEST_FAILED.store(1, Ordering::Release);
            break;
        }
        spin_loop();
    }
    let mut saved_state = core::mem::MaybeUninit::<FxSaveArea>::uninit();
    // SAFETY: `FxSaveArea` is 16-byte aligned and exactly 512 bytes; FXSAVE
    // writes the complete legacy x87/SSE state image before it is inspected.
    unsafe {
        asm!(
            "fxsave64 [{state}]",
            state = in(reg) saved_state.as_mut_ptr(),
            options(nostack),
        );
    }
    // SAFETY: The preceding FXSAVE initialized every byte of the state image.
    let saved_state = unsafe { saved_state.assume_init() };
    if saved_state.0[160..176] != PREEMPTION_PATTERN_A {
        PREEMPTION_FPU_FAILED.store(1, Ordering::Release);
    }
}

#[cfg(feature = "probe-kernel-threads")]
extern "C" fn non_yielding_preemption_worker_b(_runtime: *mut (), _ticks_pointer: usize) {
    unsafe {
        asm!(
            "movdqu xmm0, xmmword ptr [{pattern}]",
            pattern = in(reg) PREEMPTION_PATTERN_B.as_ptr(),
            out("xmm0") _,
            options(readonly, nostack, preserves_flags),
        );
    }
    PREEMPTION_B_STARTED.store(1, Ordering::Release);
}

fn spawn_thread<M: CandidatePageTableMemory>(
    runtime: &mut KernelThreadRuntime,
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: &mut FrameAllocator,
    cpu_info: &crate::arch::x86_64::cpu::CpuInfo,
    runtime_pointer: *mut KernelThreadRuntime,
    entry: ThreadEntry,
    argument: usize,
) -> Result<ThreadId, &'static str> {
    let slot = runtime
        .thread_ids
        .iter()
        .position(Option::is_none)
        .ok_or("thread capacity exhausted")?;
    let region_start = THREAD_STACK_VIRTUAL_BASE
        .checked_add(
            (slot as u64)
                .checked_mul(THREAD_STACK_STRIDE)
                .ok_or("stack VA overflow")?,
        )
        .ok_or("stack VA overflow")?;
    let stack_start = region_start
        .checked_add(PAGE_SIZE)
        .ok_or("stack VA overflow")?;

    for page in 0..=THREAD_STACK_PAGES {
        let address = region_start + page as u64 * PAGE_SIZE;
        if !matches!(
            candidate.walk(address),
            Ok(PageWalkOutcome::NotPresent { .. })
        ) {
            return Err("thread guard or stack VA is already mapped");
        }
    }

    let physical_width = cpu_info
        .physical_address_bits
        .ok_or("physical width unavailable")?;
    let pat = PatLayout::from_msr_value(cpu_info.pat_msr_value.ok_or("PAT unavailable")?)
        .map_err(|_| "PAT state invalid")?;
    let mtrrs = match &cpu_info.mtrr {
        MtrrState::Captured(registers) => registers
            .validated_layout(physical_width)
            .map_err(|_| "MTRR state invalid")?,
        _ => return Err("MTRR state unavailable"),
    };
    let permissions = PagePermissions {
        writable: true,
        executable: false,
        user_accessible: false,
    };
    let mut mapped_pages = 0usize;
    for page in 0..THREAD_STACK_PAGES {
        let virtual_address = stack_start + page as u64 * PAGE_SIZE;
        let frame = allocator.allocate().ok_or_else(|| {
            rollback_stack(candidate, allocator, stack_start, mapped_pages);
            "physical frames exhausted for thread stack"
        })?;
        let mapping = match validate_mapping_range(
            virtual_address,
            frame.address(),
            PAGE_SIZE,
            permissions,
            Some(physical_width),
            cpu_info.active_linear_address_bits,
        ) {
            Ok(mapping) => mapping,
            Err(_) => {
                deallocate_or_halt(allocator, frame);
                rollback_stack(candidate, allocator, stack_start, mapped_pages);
                return Err("thread stack mapping rejected");
            }
        };
        let attributes = match mapping.select_cache_attributes(
            CachePolicy::WriteBack,
            pat,
            &mtrrs,
            cpu_info.normal_caching,
        ) {
            Ok(attributes) if attributes.effective_type() == EffectiveMemoryType::WriteBack => {
                attributes
            }
            _ => {
                deallocate_or_halt(allocator, frame);
                rollback_stack(candidate, allocator, stack_start, mapped_pages);
                return Err("thread stack has no uniform write-back policy");
            }
        };
        // SAFETY: The active root is current on this single CPU; IF is clear
        // throughout stack setup, and each mapping uses an allocator-owned frame.
        if let Err(failure) =
            unsafe { candidate.map_owned_page_active(allocator, frame, mapping, attributes) }
        {
            deallocate_or_halt(allocator, failure.frame);
            rollback_stack(candidate, allocator, stack_start, mapped_pages);
            return Err("thread stack mapping failed");
        }
        match candidate.walk(virtual_address) {
            Ok(PageWalkOutcome::Mapped(translation))
                if translation.permissions == permissions
                    && translation.pat_index == attributes.pat_index() => {}
            _ => {
                rollback_stack(candidate, allocator, stack_start, mapped_pages + 1);
                return Err("thread stack page-table verification failed");
            }
        }
        mapped_pages += 1;
    }

    let stack_top = stack_start + THREAD_STACK_PAGES as u64 * PAGE_SIZE;
    let frame_word_count = 16;
    let frame_words = unsafe {
        core::slice::from_raw_parts_mut(
            (stack_top as *mut usize).sub(frame_word_count),
            frame_word_count,
        )
    };
    let registers = [0, slot, runtime_pointer as usize, 0, 0, 0];
    let saved_rsp = initialize_thread_context_stack(
        frame_words,
        registers,
        kernel_thread_trampoline as *const () as usize,
    );
    let Some(saved_rsp) = saved_rsp else {
        rollback_stack(candidate, allocator, stack_start, mapped_pages);
        return Err("thread initial context frame did not fit");
    };
    let thread = match runtime.policy.create_thread() {
        Ok(thread) if thread.slot_index() == slot => thread,
        Ok(_) => {
            rollback_stack(candidate, allocator, stack_start, mapped_pages);
            return Err("scheduler slot and stack slot diverged");
        }
        Err(_) => {
            rollback_stack(candidate, allocator, stack_start, mapped_pages);
            return Err("scheduler thread capacity exhausted");
        }
    };
    runtime.thread_ids[slot] = Some(thread);
    runtime.stack_virtual_starts[slot] = Some(stack_start);
    runtime.entries[slot] = Some(entry);
    runtime.arguments[slot] = argument;
    runtime.saved_rsp[slot + 1] = saved_rsp;
    Ok(thread)
}

fn rollback_stack<M: CandidatePageTableMemory>(
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: &mut FrameAllocator,
    stack_start: u64,
    mapped_pages: usize,
) {
    for page in (0..mapped_pages).rev() {
        let virtual_address = stack_start + page as u64 * PAGE_SIZE;
        // SAFETY: Stack setup keeps IF clear and this candidate is the active
        // root; the frame is not returned until `invlpg` completes.
        let frame = unsafe { candidate.unmap_owned_page_active(virtual_address) }
            .unwrap_or_else(|_| halt_on_stack_cleanup_failure());
        deallocate_or_halt(allocator, frame);
    }
}

fn reap_exited_stacks<M: CandidatePageTableMemory>(
    runtime: &mut KernelThreadRuntime,
    candidate: &mut CandidatePageTables<'_, M>,
    allocator: &mut FrameAllocator,
) {
    for slot in 0..MAX_THREADS {
        let Some(thread) = runtime.thread_ids[slot] else {
            continue;
        };
        if runtime.policy.state(thread) != Ok(ThreadState::Exited) {
            continue;
        }
        let stack_start =
            runtime.stack_virtual_starts[slot].unwrap_or_else(|| halt_on_stack_cleanup_failure());
        rollback_stack(candidate, allocator, stack_start, THREAD_STACK_PAGES);
        runtime
            .policy
            .reap(thread)
            .unwrap_or_else(|_| halt_on_stack_cleanup_failure());
        runtime.thread_ids[slot] = None;
        runtime.stack_virtual_starts[slot] = None;
        runtime.entries[slot] = None;
        runtime.arguments[slot] = 0;
        runtime.deadlines[slot] = None;
    }
}

#[cfg(feature = "probe-kernel-threads")]
fn cancel_unstarted_threads(runtime: &mut KernelThreadRuntime) {
    loop {
        match runtime.policy.dispatch() {
            Ok(Some(_)) => {
                if runtime.policy.exit_current().is_err() {
                    halt_on_stack_cleanup_failure();
                }
            }
            Ok(None) => return,
            Err(_) => halt_on_stack_cleanup_failure(),
        }
    }
}

fn deallocate_or_halt(allocator: &mut FrameAllocator, frame: Frame) {
    if let Err(failure) = allocator.deallocate(frame) {
        kprintln!("thread stack frame release failed: {:?}", failure.error);
        halt_on_stack_cleanup_failure();
    }
}

fn halt_on_stack_cleanup_failure() -> ! {
    loop {
        // SAFETY: Losing stack-frame ownership is fatal; stop without touching
        // any potentially inconsistent scheduler or allocator state.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

extern "C" fn kernel_thread_trampoline() -> ! {
    let runtime_pointer: *mut KernelThreadRuntime;
    let slot: usize;
    // SAFETY: The initial stack frame restores the runtime pointer in R13 and
    // the generation-checked policy slot index in R14 before this entry.
    unsafe {
        asm!("mov {}, r13", out(reg) runtime_pointer, options(nomem, nostack, preserves_flags));
        asm!("mov {}, r14", out(reg) slot, options(nomem, nostack, preserves_flags));
    }
    let (entry, argument) = {
        // SAFETY: The runtime is live on the retained bootstrap stack and the
        // selected slot was initialized before its context became dispatchable.
        let runtime = unsafe { &*runtime_pointer };
        let entry = runtime.entries[slot].unwrap_or_else(|| halt_on_stack_cleanup_failure());
        (entry, runtime.arguments[slot])
    };
    // New cooperative contexts start with IF clear. Enable the already-verified
    // timer route only after their descriptor and runtime state are available.
    // SAFETY: The scheduler installs no thread until the caller has configured
    // the timer and registered its bounded non-scheduling handler.
    unsafe { asm!("sti") };
    entry(runtime_pointer.cast(), argument);
    // SAFETY: This thread's entry returned normally; mark it exited and switch
    // away before its stack can be reclaimed by the bootstrap context.
    unsafe { exit_current(runtime_pointer) }
}

#[cfg(feature = "probe-kernel-threads")]
extern "C" fn waiter_thread(runtime: *mut (), _argument: usize) {
    THREAD_TEST_TRACE.store(1, Ordering::Release);
    if !wait_for_event(runtime) || THREAD_TEST_TRACE.load(Ordering::Acquire) != 2 {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
        return;
    }
    THREAD_TEST_TRACE.store(3, Ordering::Release);
    if !sleep_for_ticks(runtime, 2) || THREAD_TEST_TRACE.load(Ordering::Acquire) != 4 {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
        return;
    }
    THREAD_TEST_TRACE.store(5, Ordering::Release);
}

#[cfg(feature = "probe-kernel-threads")]
extern "C" fn signaler_thread(runtime: *mut (), _argument: usize) {
    if THREAD_TEST_TRACE.load(Ordering::Acquire) != 1 {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
        return;
    }
    THREAD_TEST_TRACE.store(2, Ordering::Release);
    if !wake_event(runtime) {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
        return;
    }
    yield_current(runtime);
    if THREAD_TEST_TRACE.load(Ordering::Acquire) != 3 {
        THREAD_TEST_TRACE.store(99, Ordering::Release);
        return;
    }
    THREAD_TEST_TRACE.store(4, Ordering::Release);
    while THREAD_TEST_TRACE.load(Ordering::Acquire) != 5 {
        yield_current(runtime);
    }
}

#[cfg(feature = "probe-kernel-threads")]
fn wait_for_event(runtime_pointer: *mut ()) -> bool {
    // SAFETY: This is an ordinary cooperative thread, never an IRQ handler.
    unsafe { block_current(runtime_pointer.cast(), None) }
}

#[cfg(feature = "probe-kernel-threads")]
fn sleep_for_ticks(runtime_pointer: *mut (), delay: u64) -> bool {
    if delay == 0 {
        return true;
    }
    // SAFETY: The runtime pointer is restored from this thread's initial context;
    // the runtime remains alive until every thread has exited and been reaped.
    unsafe { block_current(runtime_pointer.cast(), Some(delay)) }
}

#[cfg(feature = "probe-kernel-threads")]
fn wake_event(runtime_pointer: *mut ()) -> bool {
    let flags = disable_interrupts();
    // SAFETY: IF is clear and only the current cooperative thread mutates policy.
    let result = unsafe {
        let runtime = &mut *runtime_pointer.cast::<KernelThreadRuntime>();
        runtime.policy.wake_one(runtime.event_queue).is_ok()
    };
    restore_interrupts(flags);
    result
}

#[cfg(feature = "probe-kernel-threads")]
fn yield_current(runtime_pointer: *mut ()) {
    let flags = disable_interrupts();
    let switch = unsafe {
        let runtime = &mut *runtime_pointer.cast::<KernelThreadRuntime>();
        runtime.wake_ready_events();
        let Some(current) = runtime.policy.current() else {
            restore_interrupts(flags);
            return;
        };
        let old_context = runtime.current_context;
        let next = match runtime.policy.yield_current() {
            Ok(next) => next,
            Err(_) => {
                THREAD_TEST_TRACE.store(99, Ordering::Release);
                restore_interrupts(flags);
                return;
            }
        };
        let next_context = next.slot_index() + 1;
        runtime.current_context = next_context;
        if current == next {
            None
        } else {
            Some((
                core::ptr::addr_of_mut!(runtime.saved_rsp[old_context]),
                runtime.saved_rsp[next_context],
                core::ptr::addr_of_mut!(runtime.fx_state[old_context]),
                core::ptr::addr_of_mut!(runtime.fx_state[next_context]),
            ))
        }
    };
    if let Some((old_rsp, new_rsp, old_fx_state, new_fx_state)) = switch {
        // SAFETY: The selected contexts are same-CPU kernel stacks, and the
        // temporary scheduler borrows end before switching their saved FPU state.
        unsafe {
            rustix_arch_context_switch(old_rsp, new_rsp as *mut usize, old_fx_state, new_fx_state)
        };
    }
    restore_interrupts(flags);
}

unsafe fn block_current(runtime_pointer: *mut KernelThreadRuntime, delay: Option<u64>) -> bool {
    let flags = disable_interrupts();
    let switch = {
        // SAFETY: Called from one cooperative thread with IF clear; the state
        // references are scoped entirely before the context switch.
        let runtime = unsafe { &mut *runtime_pointer };
        let input_event = runtime.wake_ready_events();
        if delay.is_none() && runtime.input_events_enabled && input_event {
            restore_interrupts(flags);
            return true;
        }
        let Some(current) = runtime.policy.current() else {
            restore_interrupts(flags);
            return false;
        };
        let slot = current.slot_index();
        let queue = if let Some(delay) = delay {
            let deadline = runtime.ticks.ticks().saturating_add(delay);
            runtime.deadlines[slot] = Some(deadline);
            runtime.timer_queues[slot]
        } else {
            runtime.event_queue
        };
        let next = match runtime.policy.sleep_current(queue) {
            Ok(next) => next,
            Err(_) => {
                runtime.deadlines[slot] = None;
                restore_interrupts(flags);
                return false;
            }
        };
        let next_context = next.map_or(0, |thread| thread.slot_index() + 1);
        let old_context = runtime.current_context;
        runtime.current_context = next_context;
        Some((
            core::ptr::addr_of_mut!(runtime.saved_rsp[old_context]),
            runtime.saved_rsp[next_context],
            core::ptr::addr_of_mut!(runtime.fx_state[old_context]),
            core::ptr::addr_of_mut!(runtime.fx_state[next_context]),
        ))
    };
    if let Some((old_rsp, new_rsp, old_fx_state, new_fx_state)) = switch {
        // SAFETY: The current thread is blocked and cannot run until a later
        // wake; both stack and FXSAVE areas remain live in the runtime.
        unsafe {
            rustix_arch_context_switch(old_rsp, new_rsp as *mut usize, old_fx_state, new_fx_state)
        };
    }
    restore_interrupts(flags);
    true
}

unsafe fn exit_current(runtime_pointer: *mut KernelThreadRuntime) -> ! {
    let flags = disable_interrupts();
    let (old_rsp, new_rsp, old_fx_state, new_fx_state) = {
        // SAFETY: This is the current thread's normal return path, with IF clear.
        let runtime = unsafe { &mut *runtime_pointer };
        runtime.wake_ready_events();
        let old_context = runtime.current_context;
        match runtime.policy.exit_current() {
            Ok(next) => {
                let next_context = next.map_or(0, |thread| thread.slot_index() + 1);
                runtime.current_context = next_context;
                (
                    core::ptr::addr_of_mut!(runtime.saved_rsp[old_context]),
                    runtime.saved_rsp[next_context],
                    core::ptr::addr_of_mut!(runtime.fx_state[old_context]),
                    core::ptr::addr_of_mut!(runtime.fx_state[next_context]),
                )
            }
            Err(_) => halt_on_stack_cleanup_failure(),
        }
    };
    // SAFETY: The exited context is never dispatched again; the target is a
    // different ready thread or the retained bootstrap stack.
    unsafe {
        rustix_arch_context_switch(old_rsp, new_rsp as *mut usize, old_fx_state, new_fx_state)
    };
    restore_interrupts(flags);
    halt_on_stack_cleanup_failure()
}

fn disable_interrupts() -> u64 {
    let flags: u64;
    // SAFETY: Bootstrap and cooperative threads execute at CPL 0; RFLAGS is
    // saved before CLI and the stack operation is balanced.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    flags
}

fn restore_interrupts(flags: u64) {
    if flags & (1 << 9) != 0 {
        // SAFETY: The caller only restores the prior IF state after its critical
        // section and after the selected stack/context is fully established.
        unsafe { asm!("sti") };
    }
}

unsafe fn rustix_arch_context_switch(
    old_rsp: *mut usize,
    new_rsp: *mut usize,
    old_fx_state: *mut FxSaveArea,
    new_fx_state: *mut FxSaveArea,
) {
    // SAFETY: The runtime maintains valid saved stack frames and aligned state
    // areas. Callers hold IF clear; publish the new area before it can receive IRQs.
    unsafe { publish_fx_state(new_fx_state) };
    // SAFETY: The context switch saves the current x87/SSE state and restores the
    // target context's initialized/saved FXSAVE image.
    unsafe {
        crate::arch::x86_64::context::context_switch(
            old_rsp,
            new_rsp,
            old_fx_state.cast(),
            new_fx_state.cast(),
        )
    };
}

unsafe fn rustix_arch_context_switch_from_irq(
    old_rsp: *mut usize,
    new_rsp: *mut usize,
    new_fx_state: *mut FxSaveArea,
) {
    // SAFETY: The IRQ stub already saved the interrupted task's FPU state before
    // entering Rust. Update the return-path target before switching away.
    unsafe { publish_fx_state(new_fx_state) };
    // SAFETY: This is called only from the configured timer IRQ handler with IF
    // clear; the target area's state is initialized and 16-byte aligned.
    unsafe {
        crate::arch::x86_64::context::context_switch_from_irq(old_rsp, new_rsp, new_fx_state.cast())
    };
}

unsafe fn publish_fx_state(state: *mut FxSaveArea) {
    // SAFETY: The single-vCPU runtime calls this only with IF clear; IRQ assembly
    // reads the pointer only while executing on that same CPU.
    unsafe { ACTIVE_FX_STATE_POINTER = state };
}

unsafe fn save_bootstrap_fx_state() {
    let state = core::ptr::addr_of_mut!(BOOTSTRAP_FX_STATE);
    // SAFETY: FXSAVE is enabled during boot, `state` is 16-byte aligned, and the
    // caller has IF clear while the last kernel thread returns to the bootstrap.
    unsafe { asm!("fxsave64 [{}]", in(reg) state, options(nostack)) };
    // SAFETY: Interrupts remain disabled until the saved bootstrap area is active.
    unsafe { publish_fx_state(state) };
}

/// Advance scheduler deadlines/events and preempt the current thread if another
/// context is ready. Called only after the timer IRQ has sent APIC EOI.
pub(crate) fn timer_interrupt() {
    let runtime_pointer = ACTIVE_RUNTIME.load(Ordering::Acquire);
    if runtime_pointer.is_null() {
        return;
    }

    // The interrupt gate has cleared IF. Every ordinary scheduler mutation also
    // disables IF before borrowing this runtime, so the single CPU cannot observe
    // a partially updated scheduler state here.
    let switch = unsafe {
        let runtime = &mut *runtime_pointer;
        runtime.wake_ready_events();
        let Some(current) = runtime.policy.current() else {
            return;
        };
        let old_context = runtime.current_context;
        if old_context != current.slot_index() + 1 {
            halt_on_stack_cleanup_failure();
        }
        let next = runtime
            .policy
            .preempt_current()
            .unwrap_or_else(|_| halt_on_stack_cleanup_failure());
        let next_context = next.slot_index() + 1;
        runtime.current_context = next_context;
        if next == current {
            None
        } else {
            Some((
                core::ptr::addr_of_mut!(runtime.saved_rsp[old_context]),
                runtime.saved_rsp[next_context],
                core::ptr::addr_of_mut!(runtime.fx_state[next_context]),
            ))
        }
    };
    if let Some((old_rsp, new_rsp, new_fx_state)) = switch {
        // SAFETY: The interrupted context's FXSAVE image was written by the IRQ
        // stub before Rust ran. This suspends the handler stack and restores the
        // selected context; the interrupted thread later resumes through IRETQ.
        unsafe {
            rustix_arch_context_switch_from_irq(old_rsp, new_rsp as *mut usize, new_fx_state)
        };
    }
}
