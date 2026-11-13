//! Interrupt-safe spin locks for shared kernel state.
//!
//! Lock acquisition saves and disables local maskable interrupts before
//! spinning. Dropping the guard releases the lock before restoring the caller's
//! previous interrupt state, so nested critical sections do not enable IRQs
//! early. This provides local IRQ reentrancy protection and atomic exclusion;
//! it does not by itself make scheduler or device state safe for SMP.

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A spin lock that masks local interrupts for the full guard lifetime.
pub struct IrqSpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: Access to `value` is exclusive while the atomic lock is held. The
// protected value must be transferable between CPUs, as required by spin locks.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

impl<T> IrqSpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock with local maskable interrupts disabled.
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let interrupt_flags = save_and_disable_interrupts();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        IrqSpinLockGuard {
            lock: self,
            interrupt_flags,
            _not_send: PhantomData,
        }
    }
}

/// Exclusive access to the value protected by an [`IrqSpinLock`].
pub struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    interrupt_flags: u64,
    _not_send: PhantomData<*mut ()>,
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The guard holds the lock for its full lifetime.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The guard holds the lock for its full lifetime and cannot be
        // sent to another CPU.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        restore_interrupts(self.interrupt_flags);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn save_and_disable_interrupts() -> u64 {
    let flags: u64;
    // SAFETY: Kernel callers execute at CPL 0; the stack operation is balanced.
    // The asm's memory effects also keep protected accesses inside the guard.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    flags
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn save_and_disable_interrupts() -> u64 {
    // Host tests exercise lock exclusion; privileged IF manipulation is only
    // available in the freestanding x86_64 kernel.
    0
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn restore_interrupts(flags: u64) {
    if flags & (1 << 9) != 0 {
        // SAFETY: The guard released its lock before restoring the prior IF state.
        unsafe { core::arch::asm!("sti", options(nostack)) };
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn restore_interrupts(_flags: u64) {}

#[cfg(test)]
mod tests {
    use super::IrqSpinLock;
    use core::assert_eq;

    #[test]
    fn guard_provides_exclusive_mutable_access_and_releases_lock() {
        let lock = IrqSpinLock::new(1usize);
        {
            let mut value = lock.lock();
            *value += 2;
            assert_eq!(*value, 3);
        }
        assert_eq!(*lock.lock(), 3);
    }

    #[test]
    fn nested_guards_preserve_lock_contents() {
        let outer = IrqSpinLock::new(4usize);
        let inner = IrqSpinLock::new(7usize);
        let mut outer_guard = outer.lock();
        let mut inner_guard = inner.lock();
        *outer_guard += *inner_guard;
        *inner_guard += 1;
        assert_eq!(*outer_guard, 11);
        assert_eq!(*inner_guard, 8);
    }
}
