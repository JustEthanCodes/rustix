//! Fixed-capacity process identity and parent/child exit-state policy.
//!
//! This module does not own address spaces or block in the scheduler. Callers
//! must pair each process ID with its root and retry `try_wait` after a child
//! state change; a `Running` result means a syscall caller still has to block.

pub const MAX_PROCESSES: usize = 4;

/// ID zero belongs to the kernel supervisor and is never assigned to userspace.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub const KERNEL_PROCESS_ID: ProcessId = ProcessId(0);

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
    ProcessIdExhausted,
}

#[derive(Clone, Copy)]
struct ProcessRecord {
    pid: ProcessId,
    parent: ProcessId,
    state: ProcessState,
}

/// Bounded, allocation-free process lifecycle records for the first user slice.
///
/// Exited records remain waitable zombies until their parent calls `try_wait`.
/// If a parent exits first, its children are reparented to the kernel supervisor
/// so their exit records remain reapable. Process roots and descriptor tables are
/// owned by a future runtime layer, not by this policy table.
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
        self.insert(KERNEL_PROCESS_ID)
    }

    /// Register a child of a currently running process.
    pub fn spawn(&mut self, parent: ProcessId) -> Result<ProcessId, ProcessTableError> {
        let parent_record = self
            .record(parent)
            .ok_or(ProcessTableError::InvalidParent)?;
        if parent_record.state != ProcessState::Running {
            return Err(ProcessTableError::ParentExited);
        }
        self.insert(parent)
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

    fn insert(&mut self, parent: ProcessId) -> Result<ProcessId, ProcessTableError> {
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
        ProcessState, ProcessTable, ProcessTableError, WaitResult, KERNEL_PROCESS_ID, MAX_PROCESSES,
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
}
