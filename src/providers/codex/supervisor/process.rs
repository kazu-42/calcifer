//! Guardian-owned process-group supervision for the staged Codex supervisor.
//!
//! This module deliberately keeps direct [`Child`] handles. Reported process
//! identifiers are containment metadata only; they are never wait authority.

use std::fmt;
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{ChildDisposition, ChildRole, StopAction, UnixSignal};

const READINESS_SENTINEL: u8 = b'R';
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SPAWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_CHILD_AUTHORITY: AtomicU64 = AtomicU64::new(1);

/// Process-local identity that cannot be reconstructed from a reported PID or
/// process-group number. It binds one-shot signal proofs to one direct child
/// handle even after the operating system reuses numeric process identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildAuthority(u64);

impl ChildAuthority {
    fn next() -> Self {
        match NEXT_CHILD_AUTHORITY.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        }) {
            Ok(authority) => Self(authority),
            Err(_) => std::process::abort(),
        }
    }
}

/// Bounded process identity published only for containment attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ContainmentMetadata {
    role: ChildRole,
    pid: i32,
    pgid: i32,
}

impl ContainmentMetadata {
    pub(super) const fn role(self) -> ChildRole {
        self.role
    }

    pub(super) const fn pid(self) -> i32 {
        self.pid
    }

    pub(super) const fn pgid(self) -> i32 {
        self.pgid
    }
}

/// Proof that every guardian-owned direct child was exactly reaped.
#[must_use = "child reaping proof must be published or deliberately discarded"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReapedChildren {
    tui: ChildDisposition,
    app_server: ChildDisposition,
}

/// The result of a bounded shutdown that exactly reaped every started child.
#[must_use = "shutdown outcome must be mapped to a terminal lifecycle event"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShutdownOutcome {
    Clean(ReapedChildren),
    Failed {
        children: ReapedChildren,
        error: ProcessError,
    },
}

impl ShutdownOutcome {
    pub(super) const fn children(self) -> ReapedChildren {
        match self {
            Self::Clean(children) | Self::Failed { children, .. } => children,
        }
    }

    pub(super) const fn failure(self) -> Option<ProcessError> {
        match self {
            Self::Clean(_) => None,
            Self::Failed { error, .. } => Some(error),
        }
    }
}

/// Non-reaping liveness observed through the guardian's direct wait authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildLiveness {
    Running,
    Exited,
}

/// A terminal signal that starts shutdown instead of returning to `Active`.
///
/// Keeping this narrower than [`UnixSignal`] prevents the checked shutdown
/// entrypoint from being armed by an interactive `INT` or `QUIT` forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalShutdownSignal {
    Hup,
    Term,
}

/// An interactive terminal signal that never begins checked shutdown.
///
/// The protocol carries all four forwarded signals in one wire enum, but the
/// direct-child authority boundary accepts only this narrower type. `HUP` and
/// `TERM` must use [`TerminalShutdownSignal`] and return a shutdown proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InteractiveTerminalSignal {
    Int,
    Quit,
}

impl InteractiveTerminalSignal {
    /// Narrows the wire-level allow-list after the guardian has already split
    /// shutdown signals from interactive signals.
    pub(super) const fn from_unix_signal(signal: UnixSignal) -> Option<Self> {
        match signal {
            UnixSignal::Int => Some(Self::Int),
            UnixSignal::Quit => Some(Self::Quit),
            UnixSignal::Hup | UnixSignal::Term => None,
        }
    }
}

/// Proof that shutdown forwarding completed for this exact TUI process group.
///
/// The private fields make the capability constructible only after a
/// successful direct-child signal operation in this module (including a
/// disappeared group whose direct child is confirmed exited). The checked
/// shutdown entrypoint consumes it and verifies the bounded process identity
/// before suppressing its normal TUI `TERM` start.
#[must_use = "forwarded TUI shutdown proof must be consumed by checked shutdown"]
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ForwardedTuiSignal {
    signal: TerminalShutdownSignal,
    containment: ContainmentMetadata,
    authority: ChildAuthority,
}

impl ForwardedTuiSignal {
    pub(super) const fn signal(&self) -> TerminalShutdownSignal {
        self.signal
    }

    fn matches(&self, child: &ManagedGroupChild) -> bool {
        self.containment == child.containment()
            && self.authority == child.authority
            && child.role == ChildRole::Tui
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Stopped,
    Continued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TuiShutdownMode {
    StartWithTerm,
    SignalAlreadyForwarded(TerminalShutdownSignal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionIdentityObservation {
    Pending,
    Exact,
}

impl ReapedChildren {
    pub(super) const fn tui(self) -> ChildDisposition {
        self.tui
    }

    pub(super) const fn app_server(self) -> ChildDisposition {
        self.app_server
    }
}

/// A fixed, redacted supervisor process failure.
///
/// It contains no command, path, provider output, readiness byte, or raw I/O
/// error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessError {
    Spawn {
        role: ChildRole,
    },
    ProcessGroupReadback {
        role: ChildRole,
    },
    ProcessGroupMismatch {
        role: ChildRole,
    },
    SessionReadback {
        role: ChildRole,
    },
    SessionMismatch {
        role: ChildRole,
    },
    SessionStartupTimeout {
        role: ChildRole,
    },
    SpawnCleanupTimeout {
        role: ChildRole,
    },
    SpawnContainmentUnconfirmed {
        role: ChildRole,
    },
    ReadinessUnavailable {
        role: ChildRole,
    },
    ParentLivenessUnavailable {
        role: ChildRole,
    },
    ReadinessTimeout {
        role: ChildRole,
    },
    ReadinessIo {
        role: ChildRole,
    },
    InvalidReadiness {
        role: ChildRole,
    },
    EarlyExit {
        role: ChildRole,
        disposition: ChildDisposition,
    },
    Signal {
        role: ChildRole,
        action: StopAction,
    },
    ForwardedSignalMismatch {
        role: ChildRole,
    },
    SuspendTimeout {
        role: ChildRole,
    },
    ResumeTimeout {
        role: ChildRole,
    },
    Wait {
        role: ChildRole,
    },
    WaitTimeout {
        role: ChildRole,
    },
    RoleMismatch {
        expected: ChildRole,
        actual: ChildRole,
    },
    RetryAfterResolution,
    Deadline,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Spawn { .. } => "supervised child spawn failed",
            Self::ProcessGroupReadback { .. } => "supervised child process-group readback failed",
            Self::ProcessGroupMismatch { .. } => {
                "supervised child process-group identity mismatched"
            }
            Self::SessionReadback { .. } => "supervised child session readback failed",
            Self::SessionMismatch { .. } => "supervised child session identity mismatched",
            Self::SessionStartupTimeout { .. } => {
                "supervised child did not claim its session before the deadline"
            }
            Self::SpawnCleanupTimeout { .. } => {
                "supervised child spawn cleanup exceeded its deadline"
            }
            Self::SpawnContainmentUnconfirmed { .. } => {
                "supervised child spawn containment remained unconfirmed"
            }
            Self::ReadinessUnavailable { .. } => "supervised child has no readiness channel",
            Self::ParentLivenessUnavailable { .. } => {
                "supervised child has no parent-liveness channel"
            }
            Self::ReadinessTimeout { .. } => "supervised child readiness exceeded its deadline",
            Self::ReadinessIo { .. } => "supervised child readiness channel failed",
            Self::InvalidReadiness { .. } => "supervised child readiness was invalid",
            Self::EarlyExit { .. } => "supervised child exited before readiness",
            Self::Signal { .. } => "supervised child process-group signal failed",
            Self::ForwardedSignalMismatch { .. } => {
                "forwarded shutdown signal did not match the supervised TUI"
            }
            Self::SuspendTimeout { .. } => "supervised child suspend exceeded its deadline",
            Self::ResumeTimeout { .. } => "supervised child resume exceeded its deadline",
            Self::Wait { .. } => "supervised child wait failed",
            Self::WaitTimeout { .. } => "supervised child wait exceeded its deadline",
            Self::RoleMismatch { .. } => "supervised child role mismatched its shutdown slot",
            Self::RetryAfterResolution => "supervised child shutdown was already resolved",
            Self::Deadline => "supervised child deadline was invalid",
        })
    }
}

impl std::error::Error for ProcessError {}

/// Redacted state of a failed spawn attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnFailureState {
    NotStarted,
    ReapedUnannounced,
    LiveUnannouncedChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnCleanupKind {
    NotStarted,
    ReapedUnannounced(ChildDisposition),
}

/// Local cleanup proof for a child whose spawn contract failed.
///
/// A reaped-unannounced child cannot be projected into the lifecycle protocol:
/// the coordinator never received `ChildStarted`. Its disposition stays
/// private to this module so this capability cannot be converted into
/// `CHILDREN_REAPED`. The higher-level guardian must withhold its terminal
/// frame and retain its leases even after this local cleanup succeeds.
#[must_use = "failed-spawn reaping proof must be consumed"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpawnCleanupProof {
    error: ProcessError,
    kind: SpawnCleanupKind,
}

impl SpawnCleanupProof {
    pub(super) const fn error(self) -> ProcessError {
        self.error
    }

    pub(super) const fn started_unannounced(self) -> bool {
        matches!(self.kind, SpawnCleanupKind::ReapedUnannounced(_))
    }
}

struct FailedSpawnChild {
    child: Child,
    expected_group: Option<rustix::process::Pid>,
    containment_swept: bool,
    drop_deadline: Option<Instant>,
    #[cfg(test)]
    force_group_sweep_failure: bool,
}

/// A spawn failure that preserves the direct child handle until exact reap.
///
/// A `LiveChild` state must be retained with the guardian lease or retried; a
/// timeout classification is not a substitute for the direct wait authority.
#[must_use = "a failed spawn can still own a live direct child"]
pub(super) struct SpawnFailure {
    error: ProcessError,
    child: Option<FailedSpawnChild>,
    disposition: Option<ChildDisposition>,
    started: bool,
}

impl SpawnFailure {
    fn not_started(error: ProcessError) -> Self {
        Self {
            error,
            child: None,
            disposition: None,
            started: false,
        }
    }

    fn started(
        error: ProcessError,
        child: Child,
        expected_group: Option<rustix::process::Pid>,
    ) -> Self {
        Self {
            error,
            child: Some(FailedSpawnChild {
                child,
                expected_group,
                containment_swept: false,
                drop_deadline: None,
                #[cfg(test)]
                force_group_sweep_failure: false,
            }),
            disposition: None,
            started: true,
        }
    }

    pub(super) const fn error(&self) -> ProcessError {
        self.error
    }

    pub(super) const fn state(&self) -> SpawnFailureState {
        if !self.started {
            return SpawnFailureState::NotStarted;
        }
        match (self.disposition, self.child.is_some()) {
            (Some(_), false) => SpawnFailureState::ReapedUnannounced,
            (Some(_), true) | (None, true) | (None, false) => {
                SpawnFailureState::LiveUnannouncedChild
            }
        }
    }

    /// Retries direct-child cleanup without losing the handle on timeout.
    pub(super) fn cleanup(mut self, deadline: Instant) -> Result<SpawnCleanupProof, Self> {
        if !self.started {
            return Ok(SpawnCleanupProof {
                error: self.error,
                kind: SpawnCleanupKind::NotStarted,
            });
        }
        if self.child.is_none() {
            if let Some(disposition) = self.disposition {
                return Ok(SpawnCleanupProof {
                    error: self.error,
                    kind: SpawnCleanupKind::ReapedUnannounced(disposition),
                });
            }
        }
        let Some(mut failed_child) = self.child.take() else {
            return Err(self);
        };
        failed_child.drop_deadline = None;

        // A consumed direct wait can no longer pin the process-group leader's
        // numeric identity. Never signal retained PGID metadata from such an
        // impossible state; only fail closed.
        if self.disposition.is_some() {
            self.child = Some(failed_child);
            return Err(self);
        }

        if !failed_child.containment_swept {
            failed_child.containment_swept = sweep_failed_spawn_group(&failed_child);
        }
        if !failed_child.containment_swept {
            // Best-effort stop the leader, but deliberately do not wait. The
            // unreaped direct child pins its PID/PGID against reuse, retaining
            // safe group-signal authority for a later explicit retry.
            let _ = failed_child.child.kill();
            failed_child.drop_deadline = Some(deadline);
            self.error = ProcessError::SpawnContainmentUnconfirmed {
                role: process_error_role(self.error),
            };
            self.child = Some(failed_child);
            return Err(self);
        }

        let _ = failed_child.child.kill();
        loop {
            match failed_child.child.try_wait() {
                Ok(Some(status)) => {
                    let disposition = project_disposition(status, StopAction::Kill);
                    return Ok(SpawnCleanupProof {
                        error: self.error,
                        kind: SpawnCleanupKind::ReapedUnannounced(disposition),
                    });
                }
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) | Err(_) => {
                    failed_child.drop_deadline = Some(deadline);
                    self.child = Some(failed_child);
                    return Err(self);
                }
            }
        }
    }

    /// Parks while retaining a post-spawn direct wait handle.
    ///
    /// The caller must keep A+B lease authority in the calling stack frame.
    pub(super) fn park(&mut self) -> ! {
        loop {
            thread::park();
        }
    }
}

impl fmt::Debug for SpawnFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpawnFailure")
            .field("error", &self.error)
            .field("state", &self.state())
            .finish()
    }
}

impl fmt::Display for SpawnFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SpawnFailure {}

impl Drop for SpawnFailure {
    fn drop(&mut self) {
        let Some(failed_child) = self.child.as_mut() else {
            return;
        };
        if self.disposition.is_some() {
            unreaped_drop_is_fatal();
        }
        if !failed_child.containment_swept {
            failed_child.containment_swept = sweep_failed_spawn_group(failed_child);
        }
        let deadline = match failed_child.drop_deadline {
            Some(deadline) => deadline,
            None => {
                let Some(deadline) = Instant::now().checked_add(DROP_CLEANUP_TIMEOUT) else {
                    unreaped_drop_is_fatal();
                };
                deadline
            }
        };

        if self.disposition.is_none() {
            let _ = failed_child.child.kill();
            loop {
                match failed_child.child.try_wait() {
                    Ok(Some(status)) => {
                        self.disposition = Some(project_disposition(status, StopAction::Kill));
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                    Ok(None) | Err(_) => unreaped_drop_is_fatal(),
                }
            }
        }

        if failed_child.containment_swept {
            return;
        }
        unreaped_drop_is_fatal();
    }
}

fn sweep_failed_spawn_group(failed_child: &FailedSpawnChild) -> bool {
    #[cfg(test)]
    if failed_child.force_group_sweep_failure {
        return false;
    }
    let Some(expected_group) = failed_child.expected_group else {
        return false;
    };
    // This helper is called only while the direct child remains unreaped, so
    // its leader PID cannot be reused. A missing group is therefore positive
    // absence proof, while every other signal error preserves uncertainty.
    match rustix::process::kill_process_group(expected_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => true,
        #[cfg(target_os = "macos")]
        Err(rustix::io::Errno::PERM) => failed_spawn_leader_exit_is_observed(failed_child),
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn failed_spawn_leader_exit_is_observed(failed_child: &FailedSpawnChild) -> bool {
    let pid = rustix::process::Pid::from_child(&failed_child.child);
    rustix::process::waitid(
        rustix::process::WaitId::Pid(pid),
        rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT,
    )
    .is_ok_and(|status| {
        status.is_some_and(|status| status.exited() || status.killed() || status.dumped())
    })
}

/// A guardian-owned direct child whose leader starts a distinct process group.
pub(super) struct ManagedGroupChild {
    role: ChildRole,
    authority: ChildAuthority,
    child: Child,
    readiness_stdout: Option<ChildStdout>,
    pid: rustix::process::Pid,
    pgid: rustix::process::Pid,
    observed_exit: bool,
    containment_swept: bool,
    stop_action: StopAction,
    disposition: Option<ChildDisposition>,
    drop_deadline: Option<Instant>,
}

impl ManagedGroupChild {
    pub(super) fn spawn(
        role: ChildRole,
        command: Command,
        readiness_stdout: bool,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_inner(role, command, readiness_stdout, false)
    }

    /// Spawns a synthetic child whose stdin closes if its guardian dies.
    ///
    /// The guardian retains the pipe writer through its exact [`Child`] handle.
    /// The fixed fixture child blocks on the read end after readiness, so an
    /// abrupt guardian exit makes it terminate without turning a reported PID
    /// into delayed signal authority. Production provider children must use a
    /// provider-specific liveness contract instead of assuming stdin is free.
    pub(super) fn spawn_with_parent_liveness_pipe(
        role: ChildRole,
        command: Command,
        readiness_stdout: bool,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_inner(role, command, readiness_stdout, true)
    }

    /// Spawns a reviewed launcher that claims a new session after `exec`.
    ///
    /// The caller must have already attached PTY slave descriptors to the
    /// command. Unlike [`Self::spawn`], this function deliberately does not
    /// call `process_group(0)`: a process-group leader cannot subsequently
    /// call `setsid(2)`. The child is not published until the guardian reads
    /// back both `PGID == PID` and `SID == PID` through its direct-child
    /// identity. A failure before that proof is cleaned through the exact
    /// [`Child`] handle and never signals an unconfirmed numeric group.
    pub(super) fn spawn_session_leader(
        role: ChildRole,
        mut command: Command,
        deadline: Instant,
    ) -> Result<Self, SpawnFailure> {
        let child = command
            .spawn()
            .map_err(|_| SpawnFailure::not_started(ProcessError::Spawn { role }))?;
        Self::publish_session_leader(role, child, deadline)
    }

    /// Spawns the reviewed session launcher with one child-only readiness fd.
    ///
    /// The descriptor stays close-on-exec in the guardian. The audited support
    /// crate gives only this exec a dynamically numbered duplicate and exports
    /// that number through its fixed environment key. Publication still waits
    /// for the exact `PID == PGID == SID` proof, and every failure retains or
    /// exactly reaps the direct child handle just like [`Self::spawn_session_leader`].
    pub(super) fn spawn_session_leader_with_inherited_fd(
        role: ChildRole,
        command: Command,
        inherited_fd: BorrowedFd<'_>,
        deadline: Instant,
    ) -> Result<Self, SpawnFailure> {
        let child = match calcifer_unix_child_fd::spawn_with_inherited_readiness_fd(
            command,
            inherited_fd,
        ) {
            Ok(child) => child,
            Err(error) => match error.into_started_child() {
                Some(child) => {
                    return Err(cleanup_unconfirmed_session(
                        child.into_child(),
                        ProcessError::Spawn { role },
                    ));
                }
                None => return Err(SpawnFailure::not_started(ProcessError::Spawn { role })),
            },
        };
        Self::publish_session_leader(role, child, deadline)
    }

    fn publish_session_leader(
        role: ChildRole,
        child: Child,
        deadline: Instant,
    ) -> Result<Self, SpawnFailure> {
        Self::publish_session_leader_with_probe(role, child, deadline, |pid| {
            observe_session_identity(pid, role)
        })
    }

    fn publish_session_leader_with_probe<F>(
        role: ChildRole,
        mut child: Child,
        deadline: Instant,
        mut probe: F,
    ) -> Result<Self, SpawnFailure>
    where
        F: FnMut(rustix::process::Pid) -> Result<SessionIdentityObservation, ProcessError>,
    {
        let pid = rustix::process::Pid::from_child(&child);

        loop {
            match probe(pid) {
                Ok(SessionIdentityObservation::Exact) => {
                    return Ok(Self {
                        role,
                        authority: ChildAuthority::next(),
                        child,
                        readiness_stdout: None,
                        pid,
                        pgid: pid,
                        observed_exit: false,
                        containment_swept: false,
                        stop_action: StopAction::None,
                        disposition: None,
                        drop_deadline: None,
                    });
                }
                Ok(SessionIdentityObservation::Pending) => {}
                Err(error) => return Err(cleanup_unconfirmed_session(child, error)),
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(SpawnFailure {
                        error: ProcessError::SessionMismatch { role },
                        child: None,
                        disposition: Some(project_disposition(status, StopAction::None)),
                        started: true,
                    });
                }
                Err(_) => {
                    return Err(cleanup_unconfirmed_session(
                        child,
                        ProcessError::Wait { role },
                    ));
                }
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) => {
                    return Err(cleanup_unconfirmed_session(
                        child,
                        ProcessError::SessionStartupTimeout { role },
                    ));
                }
            }
        }
    }

    fn spawn_inner(
        role: ChildRole,
        mut command: Command,
        readiness_stdout: bool,
        parent_liveness_pipe: bool,
    ) -> Result<Self, SpawnFailure> {
        command
            .process_group(0)
            .stdin(if parent_liveness_pipe {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::null())
            .stdout(if readiness_stdout {
                Stdio::piped()
            } else {
                Stdio::null()
            });

        let mut child = command
            .spawn()
            .map_err(|_| SpawnFailure::not_started(ProcessError::Spawn { role }))?;
        let pid = rustix::process::Pid::from_child(&child);
        let pgid = match rustix::process::getpgid(Some(pid)) {
            Ok(pgid) => pgid,
            Err(_) => {
                return Err(cleanup_failed_spawn(
                    child,
                    pid,
                    ProcessError::ProcessGroupReadback { role },
                ));
            }
        };
        if pgid != pid {
            return Err(cleanup_failed_spawn(
                child,
                pid,
                ProcessError::ProcessGroupMismatch { role },
            ));
        }

        if parent_liveness_pipe && child.stdin.is_none() {
            return Err(cleanup_failed_spawn(
                child,
                pid,
                ProcessError::ParentLivenessUnavailable { role },
            ));
        }

        let readiness_stdout = if readiness_stdout {
            match child.stdout.take() {
                Some(stdout) => Some(stdout),
                None => {
                    return Err(cleanup_failed_spawn(
                        child,
                        pid,
                        ProcessError::ReadinessUnavailable { role },
                    ));
                }
            }
        } else {
            None
        };

        Ok(Self {
            role,
            authority: ChildAuthority::next(),
            child,
            readiness_stdout,
            pid,
            pgid,
            observed_exit: false,
            containment_swept: false,
            stop_action: StopAction::None,
            disposition: None,
            drop_deadline: None,
        })
    }

    pub(super) const fn containment(&self) -> ContainmentMetadata {
        ContainmentMetadata {
            role: self.role,
            pid: self.pid.as_raw_pid(),
            pgid: self.pgid.as_raw_pid(),
        }
    }

    pub(super) fn await_ready(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        if let Some(disposition) = self.disposition {
            return Err(ProcessError::EarlyExit {
                role: self.role,
                disposition,
            });
        }
        if self.readiness_stdout.is_none() {
            return Err(ProcessError::ReadinessUnavailable { role: self.role });
        }

        let mut saw_sentinel = false;
        'readiness: loop {
            if self.observe_exit_for_readiness(deadline)? {
                let disposition = self.contain_and_reap_observed_exit(deadline)?;
                return Err(ProcessError::EarlyExit {
                    role: self.role,
                    disposition,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ProcessError::ReadinessTimeout { role: self.role });
            }

            let timeout = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
            let timeout =
                rustix::event::Timespec::try_from(timeout).map_err(|_| ProcessError::Deadline)?;
            let readiness = self
                .readiness_stdout
                .as_ref()
                .ok_or(ProcessError::ReadinessUnavailable { role: self.role })?;
            let mut descriptors = [rustix::event::PollFd::new(
                readiness,
                rustix::event::PollFlags::IN,
            )];
            let ready_count = match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Err(rustix::io::Errno::INTR) => continue 'readiness,
                Ok(count) => count,
                Err(_) => return Err(ProcessError::ReadinessIo { role: self.role }),
            };
            if ready_count == 0 {
                continue;
            }

            let events = descriptors[0].revents();
            if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL) {
                self.readiness_stdout.take();
                return Err(ProcessError::ReadinessIo { role: self.role });
            }
            if !events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP) {
                continue;
            }

            let mut bytes = [0_u8; 2];
            let byte_count = {
                let readiness = self
                    .readiness_stdout
                    .as_mut()
                    .ok_or(ProcessError::ReadinessUnavailable { role: self.role })?;
                loop {
                    match readiness.read(&mut bytes) {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                            if Instant::now() >= deadline {
                                return Err(ProcessError::ReadinessTimeout { role: self.role });
                            }
                        }
                        Err(_) => {
                            self.readiness_stdout.take();
                            return Err(ProcessError::ReadinessIo { role: self.role });
                        }
                        Ok(count) => break count,
                    }
                }
            };

            if byte_count == 0 {
                self.readiness_stdout.take();
                if self.observe_exit_for_readiness(deadline)? {
                    let disposition = self.contain_and_reap_observed_exit(deadline)?;
                    return Err(ProcessError::EarlyExit {
                        role: self.role,
                        disposition,
                    });
                }
                return if saw_sentinel {
                    Ok(())
                } else {
                    Err(ProcessError::InvalidReadiness { role: self.role })
                };
            }
            if !saw_sentinel && byte_count == 1 && bytes[0] == READINESS_SENTINEL {
                saw_sentinel = true;
                continue;
            }
            self.readiness_stdout.take();
            return Err(ProcessError::InvalidReadiness { role: self.role });
        }
    }

    /// Polls liveness without consuming the guardian's exact wait authority.
    pub(super) fn poll_liveness(
        &mut self,
        deadline: Instant,
    ) -> Result<ChildLiveness, ProcessError> {
        if self.observe_exit_without_reaping(deadline)? {
            Ok(ChildLiveness::Exited)
        } else {
            Ok(ChildLiveness::Running)
        }
    }

    /// Forwards one typed interactive signal through the guardian's still-live
    /// direct-child authority.
    pub(super) fn forward_interactive_terminal_signal(
        &mut self,
        signal: InteractiveTerminalSignal,
        deadline: Instant,
    ) -> Result<ChildLiveness, ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        let signal = match signal {
            InteractiveTerminalSignal::Int => rustix::process::Signal::INT,
            InteractiveTerminalSignal::Quit => rustix::process::Signal::QUIT,
        };
        self.signal_group(signal, StopAction::None, deadline)?;
        self.poll_liveness(deadline)
    }

    /// Forwards one `HUP` or `TERM` and returns identity-bound shutdown proof.
    ///
    /// Successful forwarding deliberately leaves [`Self::stop_action`] as
    /// [`StopAction::None`]. If the TUI exits from this original signal, exact
    /// wait projection therefore preserves that disposition. A later forced
    /// containment sweep changes the action to [`StopAction::Kill`] only when
    /// the direct child is still live.
    pub(super) fn forward_terminal_shutdown_signal(
        &mut self,
        signal: TerminalShutdownSignal,
        deadline: Instant,
    ) -> Result<ForwardedTuiSignal, ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        let forwarded_signal = signal;
        let unix_signal = match signal {
            TerminalShutdownSignal::Hup => rustix::process::Signal::HUP,
            TerminalShutdownSignal::Term => rustix::process::Signal::TERM,
        };
        self.signal_group(unix_signal, StopAction::None, deadline)?;
        Ok(ForwardedTuiSignal {
            signal: forwarded_signal,
            containment: self.containment(),
            authority: self.authority,
        })
    }

    /// Publishes a terminal resize only after the PTY size itself was updated.
    pub(super) fn notify_terminal_resize(
        &mut self,
        deadline: Instant,
    ) -> Result<ChildLiveness, ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        self.signal_group(rustix::process::Signal::WINCH, StopAction::None, deadline)?;
        self.poll_liveness(deadline)
    }

    /// Stops the complete TUI process group and observes the direct child in a
    /// stopped state without consuming exact exit wait authority.
    ///
    /// `SIGTSTP` preserves normal job-control semantics, but a descendant may
    /// ignore it even after the direct leader reports `STOPPED`. Therefore an
    /// uncatchable group-wide `SIGSTOP` sweep is mandatory before success.
    pub(super) fn suspend(
        &mut self,
        graceful_deadline: Instant,
        forced_deadline: Instant,
    ) -> Result<(), ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        if forced_deadline < graceful_deadline {
            return Err(ProcessError::Deadline);
        }
        self.signal_group(
            rustix::process::Signal::TSTP,
            StopAction::None,
            graceful_deadline,
        )?;
        let _leader_observed_after_tstp =
            self.wait_for_job_state(JobState::Stopped, graceful_deadline)?;
        self.signal_group(
            rustix::process::Signal::STOP,
            StopAction::None,
            forced_deadline,
        )?;
        if self.wait_for_job_state(JobState::Stopped, forced_deadline)? {
            Ok(())
        } else {
            Err(ProcessError::SuspendTimeout { role: self.role })
        }
    }

    /// Continues a previously stopped TUI and observes the direct child before
    /// the input gate can be reopened.
    pub(super) fn resume(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        self.signal_group(rustix::process::Signal::CONT, StopAction::None, deadline)?;
        if self.wait_for_job_state(JobState::Continued, deadline)? {
            Ok(())
        } else {
            Err(ProcessError::ResumeTimeout { role: self.role })
        }
    }

    fn wait_for_job_state(
        &mut self,
        expected: JobState,
        deadline: Instant,
    ) -> Result<bool, ProcessError> {
        loop {
            let options = match expected {
                JobState::Stopped => {
                    rustix::process::WaitIdOptions::STOPPED | rustix::process::WaitIdOptions::EXITED
                }
                JobState::Continued => {
                    rustix::process::WaitIdOptions::CONTINUED
                        | rustix::process::WaitIdOptions::EXITED
                }
            } | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT;
            match rustix::process::waitid(rustix::process::WaitId::Pid(self.pid), options) {
                Ok(Some(status)) if status.stopped() && expected == JobState::Stopped => {
                    return Ok(true);
                }
                Ok(Some(status)) if status.continued() && expected == JobState::Continued => {
                    return Ok(true);
                }
                Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
                    self.observed_exit = true;
                    return Err(ProcessError::EarlyExit {
                        role: self.role,
                        disposition: observed_waitid_disposition(status),
                    });
                }
                Ok(Some(_)) | Ok(None) if Instant::now() < deadline => {
                    sleep_until_next_poll(deadline);
                }
                Ok(Some(_)) | Ok(None) => return Ok(false),
                Err(rustix::io::Errno::INTR) if Instant::now() < deadline => {}
                Err(rustix::io::Errno::INTR) => return Ok(false),
                Err(_) => return Err(ProcessError::Wait { role: self.role }),
            }
        }
    }

    fn observe_exit_for_readiness(&mut self, deadline: Instant) -> Result<bool, ProcessError> {
        match self.observe_exit_without_reaping(deadline) {
            Err(ProcessError::WaitTimeout { .. }) => {
                Err(ProcessError::ReadinessTimeout { role: self.role })
            }
            result => result,
        }
    }

    fn observe_exit_without_reaping(&mut self, deadline: Instant) -> Result<bool, ProcessError> {
        if self.disposition.is_some() || self.observed_exit {
            return Ok(true);
        }
        let mut attempted = false;
        loop {
            if attempted && Instant::now() >= deadline {
                return Err(ProcessError::WaitTimeout { role: self.role });
            }
            attempted = true;
            match rustix::process::waitid(
                rustix::process::WaitId::Pid(self.pid),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ) {
                Ok(status) => {
                    // Darwin may surface a pending stopped/continued child
                    // status even when this non-consuming query requests
                    // `EXITED` only. Job-control state is still live process
                    // authority, so classify only terminal wait states as an
                    // observed exit.
                    self.observed_exit = status.is_some_and(|status| {
                        status.exited() || status.killed() || status.dumped()
                    });
                    return Ok(self.observed_exit);
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return Err(ProcessError::Wait { role: self.role }),
            }
        }
    }

    fn signal_group(
        &mut self,
        signal: rustix::process::Signal,
        action: StopAction,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        match rustix::process::kill_process_group(self.pgid, signal) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::SRCH) if self.observe_exit_without_reaping(deadline)? => Ok(()),
            #[cfg(target_os = "macos")]
            Err(rustix::io::Errno::PERM) if self.observe_exit_without_reaping(deadline)? => Ok(()),
            Err(_) => Err(ProcessError::Signal {
                role: self.role,
                action,
            }),
        }
    }

    fn contain_and_reap_observed_exit(
        &mut self,
        deadline: Instant,
    ) -> Result<ChildDisposition, ProcessError> {
        self.signal_group(rustix::process::Signal::KILL, StopAction::Kill, deadline)?;
        self.containment_swept = true;
        loop {
            if self.try_reap_after_containment()? {
                return self
                    .disposition
                    .ok_or(ProcessError::Wait { role: self.role });
            }
            if Instant::now() >= deadline {
                return Err(ProcessError::WaitTimeout { role: self.role });
            }
            sleep_until_next_poll(deadline);
        }
    }

    fn try_reap_after_containment(&mut self) -> Result<bool, ProcessError> {
        if self.disposition.is_some() {
            return Ok(true);
        }
        if !self.containment_swept {
            return Ok(false);
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.disposition = Some(project_disposition(status, self.stop_action));
                self.observed_exit = true;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(_) => Err(ProcessError::Wait { role: self.role }),
        }
    }

    fn begin_termination(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        let observation = self.observe_exit_without_reaping(deadline);
        match observation {
            Ok(false) | Err(_) => self.stop_action = StopAction::Term,
            Ok(true) => {}
        }
        let signal = self.signal_group(rustix::process::Signal::TERM, StopAction::Term, deadline);
        observation.and(signal)
    }

    fn sweep_with_kill(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        let observation = self.observe_exit_without_reaping(deadline);
        match observation {
            Ok(false) | Err(_) => self.stop_action = StopAction::Kill,
            Ok(true) => {}
        }
        let signal = self.signal_group(rustix::process::Signal::KILL, StopAction::Kill, deadline);
        if signal.is_ok() {
            self.containment_swept = true;
        }
        observation.and(signal)
    }

    fn role_matches(&self, expected: ChildRole) -> Result<(), ProcessError> {
        if self.role == expected {
            Ok(())
        } else {
            Err(ProcessError::RoleMismatch {
                expected,
                actual: self.role,
            })
        }
    }
}

impl Drop for ManagedGroupChild {
    fn drop(&mut self) {
        if self.disposition.is_some() {
            return;
        }

        let deadline = match self.drop_deadline {
            Some(deadline) => deadline,
            None => {
                let Some(deadline) = Instant::now().checked_add(DROP_CLEANUP_TIMEOUT) else {
                    unreaped_drop_is_fatal();
                };
                deadline
            }
        };
        let observed = self
            .observe_exit_without_reaping(deadline)
            .is_ok_and(|observed| observed);
        if !observed {
            self.stop_action = StopAction::Kill;
        }
        if !self.containment_swept
            && self
                .signal_group(rustix::process::Signal::KILL, StopAction::Kill, deadline)
                .is_ok()
        {
            self.containment_swept = true;
        }
        // Even after a failed group sweep, kill and reap the direct child as a
        // best-effort leak prevention step. Exact leader reap alone is not a
        // containment proof, though: descendants may still retain the process
        // group and inherited resources, so Drop must fail closed below rather
        // than release authority as if cleanup had completed.
        let _ = self.child.kill();

        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.disposition = Some(project_disposition(status, self.stop_action));
                    self.observed_exit = true;
                    if self.containment_swept {
                        return;
                    }
                    unreaped_drop_is_fatal();
                }
                Err(_) => unreaped_drop_is_fatal(),
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) => unreaped_drop_is_fatal(),
            }
        }
    }
}

fn observe_session_identity(
    pid: rustix::process::Pid,
    role: ChildRole,
) -> Result<SessionIdentityObservation, ProcessError> {
    // These syscalls cannot be sampled atomically. A launcher may execute
    // `setsid(2)` between them, so only the positive PID == PGID == SID tuple
    // is publishable. Every other live/transient tuple remains pending until
    // the direct-child wait authority or the caller's deadline resolves it.
    classify_session_identity(
        pid,
        rustix::process::getpgid(Some(pid)),
        rustix::process::getsid(Some(pid)),
        role,
    )
}

fn classify_session_identity(
    pid: rustix::process::Pid,
    process_group: Result<rustix::process::Pid, rustix::io::Errno>,
    session: Result<rustix::process::Pid, rustix::io::Errno>,
    role: ChildRole,
) -> Result<SessionIdentityObservation, ProcessError> {
    let process_group = match process_group {
        Ok(process_group) => process_group,
        Err(rustix::io::Errno::SRCH) => return Ok(SessionIdentityObservation::Pending),
        Err(_) => return Err(ProcessError::ProcessGroupReadback { role }),
    };
    let session = match session {
        Ok(session) => session,
        Err(rustix::io::Errno::SRCH) => return Ok(SessionIdentityObservation::Pending),
        Err(_) => return Err(ProcessError::SessionReadback { role }),
    };

    if process_group == pid && session == pid {
        Ok(SessionIdentityObservation::Exact)
    } else {
        Ok(SessionIdentityObservation::Pending)
    }
}

/// A failed shutdown that still owns every unreaped direct child handle.
#[must_use = "unreaped children must remain owned while the guardian lease is retained"]
pub(super) struct UnreapedChildren {
    error: ProcessError,
    tui: Option<ManagedGroupChild>,
    app_server: Option<ManagedGroupChild>,
    tui_shutdown_mode: TuiShutdownMode,
    resolved: bool,
}

impl UnreapedChildren {
    pub(super) const fn error(&self) -> ProcessError {
        self.error
    }

    /// Starts a new explicit bounded attempt while preserving the first error.
    pub(super) fn retry(
        &mut self,
        grace: Duration,
        forced: Duration,
    ) -> Result<ShutdownOutcome, ProcessError> {
        if self.resolved {
            return Err(ProcessError::RetryAfterResolution);
        }
        match shutdown_pair_inner(
            self.tui.take(),
            self.app_server.take(),
            grace,
            forced,
            self.tui_shutdown_mode,
            Some(self.error),
        ) {
            Ok(outcome) => {
                self.resolved = true;
                Ok(outcome)
            }
            Err(mut unreaped) => {
                self.error = unreaped.error;
                self.tui = unreaped.tui.take();
                self.app_server = unreaped.app_server.take();
                Err(self.error)
            }
        }
    }

    /// Parks while retaining both direct wait handles in this stack frame.
    ///
    /// The caller must keep the guardian/coordinator lease authority in the
    /// calling stack frame before entering this non-returning recovery state.
    pub(super) fn park(&mut self) -> ! {
        loop {
            thread::park();
        }
    }
}

impl fmt::Debug for UnreapedChildren {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnreapedChildren")
            .field("error", &self.error)
            .field("tui_owned", &self.tui.is_some())
            .field("app_server_owned", &self.app_server.is_some())
            .field("tui_shutdown_mode", &self.tui_shutdown_mode)
            .field("resolved", &self.resolved)
            .finish()
    }
}

impl fmt::Display for UnreapedChildren {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for UnreapedChildren {}

/// Stops TUI before App Server and returns proof only after exact direct waits.
pub(super) fn shutdown_pair(
    tui: Option<ManagedGroupChild>,
    app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    shutdown_pair_inner(
        tui,
        app_server,
        grace,
        forced,
        TuiShutdownMode::StartWithTerm,
        None,
    )
}

/// Shuts down after an identity-checked TUI `HUP` or `TERM` was forwarded.
///
/// Unlike [`shutdown_pair`], this entrypoint never starts another `TERM` on
/// the proven TUI. It still starts the App Server with `TERM`, observes both
/// direct children until both exit or the grace deadline, performs a
/// process-group `KILL` containment sweep, and requires exact waits before
/// returning proof. If a deadline expires, [`UnreapedChildren::retry`]
/// retains this mode.
pub(super) fn shutdown_pair_after_forwarded_tui_signal(
    tui: ManagedGroupChild,
    app_server: Option<ManagedGroupChild>,
    forwarded: ForwardedTuiSignal,
    grace: Duration,
    forced: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    let (mode, first_error) = if forwarded.matches(&tui) {
        (
            TuiShutdownMode::SignalAlreadyForwarded(forwarded.signal()),
            None,
        )
    } else {
        (
            TuiShutdownMode::StartWithTerm,
            Some(ProcessError::ForwardedSignalMismatch {
                role: ChildRole::Tui,
            }),
        )
    };
    shutdown_pair_inner(Some(tui), app_server, grace, forced, mode, first_error)
}

fn shutdown_pair_inner(
    mut tui: Option<ManagedGroupChild>,
    mut app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
    tui_shutdown_mode: TuiShutdownMode,
    mut first_error: Option<ProcessError>,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    clear_drop_deadline(&mut tui);
    clear_drop_deadline(&mut app_server);

    let started_at = Instant::now();
    let Some(grace_deadline) = started_at.checked_add(grace) else {
        return Err(unreaped_children(
            tui,
            app_server,
            ProcessError::Deadline,
            None,
            tui_shutdown_mode,
        ));
    };
    let Some(hard_deadline) = grace_deadline.checked_add(forced) else {
        return Err(unreaped_children(
            tui,
            app_server,
            ProcessError::Deadline,
            None,
            tui_shutdown_mode,
        ));
    };

    validate_child_role(&tui, ChildRole::Tui, &mut first_error);
    validate_child_role(&app_server, ChildRole::AppServer, &mut first_error);
    if matches!(tui_shutdown_mode, TuiShutdownMode::StartWithTerm) {
        begin_child_termination(&mut tui, grace_deadline, &mut first_error);
    }
    begin_child_termination(&mut app_server, grace_deadline, &mut first_error);

    loop {
        observe_child(&mut tui, grace_deadline, &mut first_error);
        observe_child(&mut app_server, grace_deadline, &mut first_error);
        if children_observed(&tui, &app_server) || Instant::now() >= grace_deadline {
            break;
        }
        sleep_until_next_poll(grace_deadline);
    }

    sweep_child_with_kill(&mut tui, hard_deadline, &mut first_error);
    sweep_child_with_kill(&mut app_server, hard_deadline, &mut first_error);

    loop {
        reap_child(&mut tui, &mut first_error);
        reap_child(&mut app_server, &mut first_error);
        if children_reaped(&tui, &app_server) {
            break;
        }
        if Instant::now() >= hard_deadline {
            if let Some(child) = first_unreaped_child(&tui, &app_server) {
                record_first_error(
                    &mut first_error,
                    ProcessError::WaitTimeout { role: child.role },
                );
            }
            break;
        }
        sleep_until_next_poll(hard_deadline);
    }

    if !children_reaped(&tui, &app_server) {
        let error = first_error.unwrap_or_else(|| ProcessError::WaitTimeout {
            role: first_unreaped_child(&tui, &app_server)
                .map_or(ChildRole::AppServer, |child| child.role),
        });
        return Err(unreaped_children(
            tui,
            app_server,
            error,
            Some(hard_deadline),
            tui_shutdown_mode,
        ));
    }

    let tui_disposition = match reaped_disposition(&tui, ChildRole::Tui) {
        Ok(disposition) => disposition,
        Err(error) => {
            return Err(unreaped_children(
                tui,
                app_server,
                error,
                None,
                tui_shutdown_mode,
            ));
        }
    };
    let app_server_disposition = match reaped_disposition(&app_server, ChildRole::AppServer) {
        Ok(disposition) => disposition,
        Err(error) => {
            return Err(unreaped_children(
                tui,
                app_server,
                error,
                None,
                tui_shutdown_mode,
            ));
        }
    };
    let children = ReapedChildren {
        tui: tui_disposition,
        app_server: app_server_disposition,
    };
    match first_error {
        Some(error) => Ok(ShutdownOutcome::Failed { children, error }),
        None => Ok(ShutdownOutcome::Clean(children)),
    }
}

fn clear_drop_deadline(child: &mut Option<ManagedGroupChild>) {
    if let Some(child) = child.as_mut() {
        child.drop_deadline = None;
    }
}

fn validate_child_role(
    child: &Option<ManagedGroupChild>,
    role: ChildRole,
    first_error: &mut Option<ProcessError>,
) {
    if let Some(child) = child.as_ref() {
        if let Err(error) = child.role_matches(role) {
            record_first_error(first_error, error);
        }
    }
}

fn begin_child_termination(
    child: &mut Option<ManagedGroupChild>,
    deadline: Instant,
    first_error: &mut Option<ProcessError>,
) {
    if let Some(child) = child.as_mut() {
        if let Err(error) = child.begin_termination(deadline) {
            record_first_error(first_error, error);
        }
    }
}

fn sweep_child_with_kill(
    child: &mut Option<ManagedGroupChild>,
    deadline: Instant,
    first_error: &mut Option<ProcessError>,
) {
    if let Some(child) = child.as_mut() {
        if let Err(error) = child.sweep_with_kill(deadline) {
            record_first_error(first_error, error);
        }
    }
}

fn observe_child(
    child: &mut Option<ManagedGroupChild>,
    deadline: Instant,
    first_error: &mut Option<ProcessError>,
) {
    if let Some(child) = child.as_mut() {
        if let Err(error) = child.observe_exit_without_reaping(deadline) {
            record_first_error(first_error, error);
        }
    }
}

fn reap_child(child: &mut Option<ManagedGroupChild>, first_error: &mut Option<ProcessError>) {
    if let Some(child) = child.as_mut() {
        if let Err(error) = child.try_reap_after_containment() {
            record_first_error(first_error, error);
        }
    }
}

fn unreaped_children(
    mut tui: Option<ManagedGroupChild>,
    mut app_server: Option<ManagedGroupChild>,
    error: ProcessError,
    drop_deadline: Option<Instant>,
    tui_shutdown_mode: TuiShutdownMode,
) -> Box<UnreapedChildren> {
    if let Some(child) = tui.as_mut() {
        child.drop_deadline = drop_deadline;
    }
    if let Some(child) = app_server.as_mut() {
        child.drop_deadline = drop_deadline;
    }
    Box::new(UnreapedChildren {
        error,
        tui,
        app_server,
        tui_shutdown_mode,
        resolved: false,
    })
}

fn children_observed(
    tui: &Option<ManagedGroupChild>,
    app_server: &Option<ManagedGroupChild>,
) -> bool {
    child_observed(tui) && child_observed(app_server)
}

fn child_observed(child: &Option<ManagedGroupChild>) -> bool {
    child
        .as_ref()
        .is_none_or(|child| child.observed_exit || child.disposition.is_some())
}

fn children_reaped(
    tui: &Option<ManagedGroupChild>,
    app_server: &Option<ManagedGroupChild>,
) -> bool {
    child_reaped(tui) && child_reaped(app_server)
}

fn child_reaped(child: &Option<ManagedGroupChild>) -> bool {
    child
        .as_ref()
        .is_none_or(|child| child.disposition.is_some())
}

fn first_unreaped_child<'a>(
    tui: &'a Option<ManagedGroupChild>,
    app_server: &'a Option<ManagedGroupChild>,
) -> Option<&'a ManagedGroupChild> {
    tui.as_ref()
        .filter(|child| child.disposition.is_none())
        .or_else(|| {
            app_server
                .as_ref()
                .filter(|child| child.disposition.is_none())
        })
}

fn reaped_disposition(
    child: &Option<ManagedGroupChild>,
    role: ChildRole,
) -> Result<ChildDisposition, ProcessError> {
    match child {
        None => Ok(ChildDisposition::NotStarted),
        Some(child) => child.disposition.ok_or(ProcessError::WaitTimeout { role }),
    }
}

fn record_first_error(first_error: &mut Option<ProcessError>, error: ProcessError) {
    if first_error.is_none() {
        *first_error = Some(error);
    }
}

fn cleanup_failed_spawn(
    child: Child,
    expected_group: rustix::process::Pid,
    original_error: ProcessError,
) -> SpawnFailure {
    let failure = SpawnFailure::started(original_error, child, Some(expected_group));
    let Some(deadline) = Instant::now().checked_add(SPAWN_CLEANUP_TIMEOUT) else {
        return failure;
    };
    match failure.cleanup(deadline) {
        Ok(reaped) => {
            let disposition = match reaped.kind {
                SpawnCleanupKind::NotStarted => ChildDisposition::NotStarted,
                SpawnCleanupKind::ReapedUnannounced(disposition) => disposition,
            };
            SpawnFailure {
                error: reaped.error,
                child: None,
                disposition: Some(disposition),
                started: true,
            }
        }
        Err(mut failure) => {
            if !matches!(
                failure.error,
                ProcessError::SpawnContainmentUnconfirmed { .. }
            ) {
                failure.error = ProcessError::SpawnCleanupTimeout {
                    role: process_error_role(original_error),
                };
            }
            failure
        }
    }
}

fn cleanup_unconfirmed_session(child: Child, original_error: ProcessError) -> SpawnFailure {
    let failure = SpawnFailure::started(original_error, child, None);
    let Some(deadline) = Instant::now().checked_add(SPAWN_CLEANUP_TIMEOUT) else {
        return failure;
    };
    match failure.cleanup(deadline) {
        Ok(reaped) => {
            let disposition = match reaped.kind {
                SpawnCleanupKind::NotStarted => ChildDisposition::NotStarted,
                SpawnCleanupKind::ReapedUnannounced(disposition) => disposition,
            };
            SpawnFailure {
                error: reaped.error,
                child: None,
                disposition: Some(disposition),
                started: true,
            }
        }
        Err(mut failure) => {
            if !matches!(
                failure.error,
                ProcessError::SpawnContainmentUnconfirmed { .. }
            ) {
                failure.error = ProcessError::SpawnCleanupTimeout {
                    role: process_error_role(original_error),
                };
            }
            failure
        }
    }
}

const fn process_error_role(error: ProcessError) -> ChildRole {
    match error {
        ProcessError::Spawn { role }
        | ProcessError::ProcessGroupReadback { role }
        | ProcessError::ProcessGroupMismatch { role }
        | ProcessError::SessionReadback { role }
        | ProcessError::SessionMismatch { role }
        | ProcessError::SessionStartupTimeout { role }
        | ProcessError::SpawnCleanupTimeout { role }
        | ProcessError::SpawnContainmentUnconfirmed { role }
        | ProcessError::ReadinessUnavailable { role }
        | ProcessError::ParentLivenessUnavailable { role }
        | ProcessError::ReadinessTimeout { role }
        | ProcessError::ReadinessIo { role }
        | ProcessError::InvalidReadiness { role }
        | ProcessError::EarlyExit { role, .. }
        | ProcessError::Signal { role, .. }
        | ProcessError::ForwardedSignalMismatch { role }
        | ProcessError::SuspendTimeout { role }
        | ProcessError::ResumeTimeout { role }
        | ProcessError::Wait { role }
        | ProcessError::WaitTimeout { role } => role,
        ProcessError::RoleMismatch { actual, .. } => actual,
        ProcessError::RetryAfterResolution | ProcessError::Deadline => ChildRole::AppServer,
    }
}

fn project_disposition(status: ExitStatus, stop_action: StopAction) -> ChildDisposition {
    if let Some(code) = status.code() {
        return ChildDisposition::Exited {
            code: bounded_exit_code(code),
            stop_action,
        };
    }
    ChildDisposition::Signaled {
        signal: bounded_signal(status.signal()),
        core_dumped: status.core_dumped(),
        stop_action,
    }
}

fn observed_waitid_disposition(status: rustix::process::WaitIdStatus) -> ChildDisposition {
    if status.exited() {
        return ChildDisposition::Exited {
            code: bounded_exit_code(status.exit_status().unwrap_or_default()),
            stop_action: StopAction::None,
        };
    }
    ChildDisposition::Signaled {
        signal: bounded_signal(status.terminating_signal()),
        core_dumped: status.dumped(),
        stop_action: StopAction::None,
    }
}

fn bounded_exit_code(code: i32) -> u8 {
    match u8::try_from(code) {
        Ok(code) => code,
        Err(_) if code < 0 => 0,
        Err(_) => u8::MAX,
    }
}

fn bounded_signal(signal: Option<i32>) -> u8 {
    match signal.and_then(|signal| u8::try_from(signal).ok()) {
        Some(signal @ 1..=127) => signal,
        Some(0) | Some(128..=u8::MAX) | None => 127,
    }
}

fn sleep_until_next_poll(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if !remaining.is_zero() {
        thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

/// A Drop fallback cannot return while it still owns an unreaped direct child:
/// doing so would detach the only wait authority and permit a zombie or live
/// descendant to outlive the guardian's lease. Structured shutdown returns the
/// handle for retry; Drop has no such return channel and therefore fails closed.
fn unreaped_drop_is_fatal() -> ! {
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_DEADLINE: Duration = Duration::from_secs(3);
    const SESSION_HELPER_ENV: &str = "CALCIFER_PROCESS_SESSION_HELPER";
    const SESSION_INHERITED_FD_HELPER_ENV: &str = "CALCIFER_PROCESS_SESSION_INHERITED_FD_HELPER";
    const SIGNAL_COUNTING_HELPER_ENV: &str = "CALCIFER_PROCESS_SIGNAL_COUNTING_HELPER";
    const SIGNAL_LOG_ENV: &str = "CALCIFER_PROCESS_SIGNAL_LOG";
    const UNREAPED_DROP_ABORT_HELPER_ENV: &str = "CALCIFER_PROCESS_UNREAPED_DROP_ABORT_HELPER";
    static SIGNAL_LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn externally_kill_and_reap(pid: rustix::process::Pid) -> Result<(), Box<dyn Error>> {
        rustix::process::kill_process(pid, rustix::process::Signal::KILL)?;
        loop {
            match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()) {
                Ok(Some((reaped, _))) if reaped == pid => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Ok(Some(_)) | Ok(None) | Err(_) => {
                    return Err("external direct-child reap failed".into());
                }
            }
        }
    }

    #[test]
    fn unreaped_drop_abort_child_helper() -> Result<(), Box<dyn Error>> {
        let Some(case) = std::env::var_os(UNREAPED_DROP_ABORT_HELPER_ENV) else {
            return Ok(());
        };
        match case.to_str() {
            Some("spawn-failure") => {
                let child = sleep_command("5").spawn()?;
                let pid = rustix::process::Pid::from_child(&child);
                externally_kill_and_reap(pid)?;

                // Deliberately retain a std Child after another safe waitpid
                // authority consumed the kernel wait state. Drop must hit
                // ECHILD and abort instead of treating it as exact reap proof.
                let failure = SpawnFailure::started(
                    ProcessError::Spawn {
                        role: ChildRole::Tui,
                    },
                    child,
                    None,
                );
                drop(failure);
            }
            Some("spawn-failure-no-group") => {
                let child = sleep_command("5").spawn()?;
                let failure = SpawnFailure::started(
                    ProcessError::Spawn {
                        role: ChildRole::Tui,
                    },
                    child,
                    None,
                );
                drop(failure);
            }
            Some("spawn-failure-group-drift") => {
                let child = sleep_command("5").spawn()?;
                let expected_group = rustix::process::Pid::from_child(&child);
                let mut failure = SpawnFailure::started(
                    ProcessError::Spawn {
                        role: ChildRole::Tui,
                    },
                    child,
                    Some(expected_group),
                );
                failure
                    .child
                    .as_mut()
                    .ok_or("spawn failure lost its direct child")?
                    .force_group_sweep_failure = true;
                drop(failure);
            }
            Some("managed-child") => {
                let mut child =
                    ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
                // Avoid re-signalling an externally reaped numeric group in
                // this deterministic Drop test; the production safety net
                // already considers a completed containment sweep sufficient.
                child.containment_swept = true;
                externally_kill_and_reap(child.pid)?;
                drop(child);
            }
            Some("managed-child-group-drift") => {
                let mut child =
                    ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
                child.pgid = rustix::process::Pid::from_raw(i32::MAX)
                    .ok_or("the drifted process-group identity was invalid")?;
                assert!(matches!(
                    child.signal_group(
                        rustix::process::Signal::KILL,
                        StopAction::Kill,
                        Instant::now() + TEST_DEADLINE,
                    ),
                    Err(ProcessError::Signal {
                        role: ChildRole::Tui,
                        action: StopAction::Kill,
                    })
                ));
                drop(child);
            }
            _ => return Err("unknown unreaped Drop helper case".into()),
        }
        Err("Drop detached an externally reaped direct-child authority".into())
    }

    #[test]
    fn direct_child_drop_fallbacks_abort_instead_of_detaching_wait_authority()
    -> Result<(), Box<dyn Error>> {
        for case in [
            "spawn-failure",
            "spawn-failure-no-group",
            "spawn-failure-group-drift",
            "managed-child",
            "managed-child-group-drift",
        ] {
            let status = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "providers::codex::supervisor::process::tests::unreaped_drop_abort_child_helper",
                    "--nocapture",
                ])
                .env(UNREAPED_DROP_ABORT_HELPER_ENV, case)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            assert_eq!(
                status.signal(),
                Some(rustix::process::Signal::ABORT.as_raw()),
                "{case} Drop did not abort"
            );
        }
        Ok(())
    }

    #[test]
    fn spawn_cleanup_retains_an_unreaped_leader_when_group_sweep_is_unconfirmed()
    -> Result<(), Box<dyn Error>> {
        let child = sleep_command("5").spawn()?;
        let expected_group = rustix::process::Pid::from_child(&child);
        let mut failure = SpawnFailure::started(
            ProcessError::Spawn {
                role: ChildRole::Tui,
            },
            child,
            Some(expected_group),
        );
        failure
            .child
            .as_mut()
            .ok_or("spawn failure lost its direct child")?
            .force_group_sweep_failure = true;

        let mut failure = failure
            .cleanup(Instant::now() + TEST_DEADLINE)
            .err()
            .ok_or("an unconfirmed group sweep must not return cleanup proof")?;
        assert_eq!(failure.state(), SpawnFailureState::LiveUnannouncedChild);
        assert_eq!(
            failure.error(),
            ProcessError::SpawnContainmentUnconfirmed {
                role: ChildRole::Tui,
            }
        );
        let retained = failure
            .child
            .as_ref()
            .ok_or("unreaped child authority and group metadata were discarded")?;
        assert_eq!(retained.expected_group, Some(expected_group));
        assert!(failure.disposition.is_none());
        assert!(!retained.containment_swept);
        assert!(!matches!(
            rustix::process::waitid(
                rustix::process::WaitId::Pid(expected_group),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ),
            Err(rustix::io::Errno::CHILD)
        ));

        // Remove only the deterministic injected fault. The still-unreaped
        // child pins the expected group, so a real retry can safely resolve
        // containment and consume the exact wait authority.
        failure
            .child
            .as_mut()
            .ok_or("spawn failure lost retained retry authority")?
            .force_group_sweep_failure = false;
        let proof = failure.cleanup(Instant::now() + TEST_DEADLINE).map_err(
            |failure| -> Box<dyn Error> { format!("cleanup remained live: {failure}").into() },
        )?;
        assert!(proof.started_unannounced());
        Ok(())
    }

    struct SignalLog(PathBuf);

    impl SignalLog {
        fn new(label: &str) -> Result<Self, Box<dyn Error>> {
            let sequence = SIGNAL_LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "calcifer-process-signal-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn contents(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            match fs::read(&self.0) {
                Ok(bytes) => Ok(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(error) => Err(error.into()),
            }
        }
    }

    impl Drop for SignalLog {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn sleep_command(seconds: &str) -> Command {
        let mut command = Command::new("/bin/sleep");
        command.arg(seconds);
        command
    }

    fn shell_command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    fn signal_counting_command(log: &SignalLog) -> Result<Command, Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::process::tests::signal_counting_child_helper",
                "--nocapture",
            ])
            .env(SIGNAL_COUNTING_HELPER_ENV, "1")
            .env(SIGNAL_LOG_ENV, log.path());
        Ok(command)
    }

    fn wait_for_signal_log(log: &SignalLog, expected: &[u8]) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + TEST_DEADLINE;
        loop {
            let contents = log.contents()?;
            if contents == expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "signal log did not reach {expected:?}; observed {contents:?}"
                )
                .into());
            }
            sleep_until_next_poll(deadline);
        }
    }

    #[test]
    fn signal_counting_child_helper() -> Result<(), Box<dyn Error>> {
        if std::env::var_os(SIGNAL_COUNTING_HELPER_ENV).is_none() {
            return Ok(());
        }
        let path = std::env::var_os(SIGNAL_LOG_ENV).ok_or("missing signal log path")?;
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::signal::SIGHUP,
            signal_hook::consts::signal::SIGTERM,
        ])?;
        fs::write(&path, b"R")?;
        loop {
            for signal in signals.pending() {
                let marker = match signal {
                    signal_hook::consts::signal::SIGHUP => b'H',
                    signal_hook::consts::signal::SIGTERM => b'T',
                    _ => return Err("unexpected registered signal".into()),
                };
                OpenOptions::new()
                    .append(true)
                    .open(&path)?
                    .write_all(&[marker])?;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn assert_no_wait_authority(pid: i32) -> Result<(), Box<dyn Error>> {
        let pid = rustix::process::Pid::from_raw(pid).ok_or("pid must be positive")?;
        match rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        ) {
            Err(rustix::io::Errno::CHILD) => Ok(()),
            Ok(Some(_)) => Err("child remained waitable after exact reap".into()),
            Ok(None) => Err("child remained live after exact reap".into()),
            Err(error) => Err(std::io::Error::from(error).into()),
        }
    }

    #[test]
    fn session_child_helper() -> Result<(), Box<dyn Error>> {
        if std::env::var_os(SESSION_HELPER_ENV).is_none() {
            return Ok(());
        }
        let inherited = if std::env::var_os(SESSION_INHERITED_FD_HELPER_ENV).is_some() {
            Some(calcifer_unix_child_fd::take_inherited_readiness_fd()?)
        } else {
            None
        };
        let session = rustix::process::setsid()?;
        let process = rustix::process::getpid();
        if session != process
            || rustix::process::getpgrp() != process
            || rustix::process::getsid(Some(process))? != process
        {
            return Err("session helper did not become its own session leader".into());
        }
        if let Some(inherited) = inherited {
            let mut readiness = UnixStream::from(inherited);
            readiness.write_all(&[READINESS_SENTINEL])?;
            readiness.shutdown(std::net::Shutdown::Write)?;
        }
        std::thread::sleep(Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn session_launcher_is_published_only_after_pid_pgid_sid_match() -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::process::tests::session_child_helper",
                "--nocapture",
            ])
            .env(SESSION_HELPER_ENV, "1");
        let child = ManagedGroupChild::spawn_session_leader(
            ChildRole::Tui,
            command,
            Instant::now() + TEST_DEADLINE,
        )?;
        let identity = child.containment();
        let pid = rustix::process::Pid::from_raw(identity.pid()).ok_or("invalid child PID")?;
        assert_eq!(identity.pid(), identity.pgid());
        assert_eq!(rustix::process::getsid(Some(pid))?, pid);

        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        assert_no_wait_authority(identity.pid())
    }

    #[test]
    fn a_mixed_session_identity_snapshot_is_pending_instead_of_mismatched() {
        let pid = rustix::process::getpid();
        let prior_group = rustix::process::getppid().unwrap_or(pid);

        assert_eq!(
            classify_session_identity(pid, Ok(prior_group), Ok(pid), ChildRole::Tui),
            Ok(SessionIdentityObservation::Pending)
        );
    }

    #[test]
    fn session_publication_retries_a_pending_observation() -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::process::tests::session_child_helper",
                "--nocapture",
            ])
            .env(SESSION_HELPER_ENV, "1");
        let child = command.spawn()?;
        let mut observations = 0_usize;

        let child = ManagedGroupChild::publish_session_leader_with_probe(
            ChildRole::Tui,
            child,
            Instant::now() + TEST_DEADLINE,
            |pid| {
                observations += 1;
                if observations == 1 {
                    Ok(SessionIdentityObservation::Pending)
                } else {
                    observe_session_identity(pid, ChildRole::Tui)
                }
            },
        )?;

        assert!(observations >= 2);
        let identity = child.containment();
        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        assert_no_wait_authority(identity.pid())
    }

    #[test]
    fn inherited_fd_session_launcher_publishes_only_after_pid_pgid_sid_match()
    -> Result<(), Box<dyn Error>> {
        let (mut readiness, inherited) = UnixStream::pair()?;
        readiness.set_read_timeout(Some(TEST_DEADLINE))?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::process::tests::session_child_helper",
                "--nocapture",
            ])
            .env(SESSION_HELPER_ENV, "1")
            .env(SESSION_INHERITED_FD_HELPER_ENV, "1");

        let child = ManagedGroupChild::spawn_session_leader_with_inherited_fd(
            ChildRole::Tui,
            command,
            inherited.as_fd(),
            Instant::now() + TEST_DEADLINE,
        )?;
        drop(inherited);

        let mut marker = [0_u8; 1];
        readiness.read_exact(&mut marker)?;
        assert_eq!(marker, [READINESS_SENTINEL]);
        let mut trailing = [0_u8; 1];
        assert_eq!(readiness.read(&mut trailing)?, 0);
        let identity = child.containment();
        let pid = rustix::process::Pid::from_raw(identity.pid()).ok_or("invalid child PID")?;
        assert_eq!(identity.pid(), identity.pgid());
        assert_eq!(rustix::process::getsid(Some(pid))?, pid);

        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        assert_no_wait_authority(identity.pid())
    }

    #[test]
    fn inherited_fd_session_failure_retains_unreaped_authority_without_a_safe_group()
    -> Result<(), Box<dyn Error>> {
        let (_observer, inherited) = UnixStream::pair()?;
        let mut failure = ManagedGroupChild::spawn_session_leader_with_inherited_fd(
            ChildRole::Tui,
            sleep_command("5"),
            inherited.as_fd(),
            Instant::now() + Duration::from_millis(30),
        )
        .err()
        .ok_or("a child that never calls setsid must not be published")?;
        assert_eq!(
            failure.error(),
            ProcessError::SpawnContainmentUnconfirmed {
                role: ChildRole::Tui
            }
        );
        assert_eq!(failure.state(), SpawnFailureState::LiveUnannouncedChild);
        let failed_child = failure
            .child
            .as_ref()
            .ok_or("unconfirmed session failure lost direct wait authority")?;
        assert_eq!(failed_child.expected_group, None);
        assert!(!failed_child.containment_swept);
        assert!(failure.disposition.is_none());
        let pid = rustix::process::Pid::from_child(&failed_child.child);
        assert!(!matches!(
            rustix::process::waitid(
                rustix::process::WaitId::Pid(pid),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ),
            Err(rustix::io::Errno::CHILD)
        ));

        // This synthetic child is known to have no descendants. Mark only the
        // test fixture as contained so its pinned direct wait can be consumed
        // without exercising the production Drop-abort path.
        failure
            .child
            .as_mut()
            .ok_or("unconfirmed session failure lost test cleanup authority")?
            .containment_swept = true;
        let proof = failure.cleanup(Instant::now() + TEST_DEADLINE).map_err(
            |failure| -> Box<dyn Error> { format!("cleanup remained live: {failure}").into() },
        )?;
        assert!(proof.started_unannounced());
        assert_no_wait_authority(pid.as_raw_pid())?;
        Ok(())
    }

    #[test]
    fn spawn_places_each_child_in_its_own_distinct_process_group() -> Result<(), Box<dyn Error>> {
        let tui = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
        let app = ManagedGroupChild::spawn(ChildRole::AppServer, sleep_command("5"), false)?;

        let tui_identity = tui.containment();
        let app_identity = app.containment();
        assert_eq!(tui_identity.role(), ChildRole::Tui);
        assert_eq!(tui_identity.pid(), tui_identity.pgid());
        assert_eq!(app_identity.pid(), app_identity.pgid());
        assert_ne!(tui_identity.pgid(), app_identity.pgid());
        assert_ne!(tui_identity.pgid(), rustix::process::getpgrp().as_raw_pid());

        let outcome = shutdown_pair(
            Some(tui),
            Some(app),
            Duration::from_millis(100),
            TEST_DEADLINE,
        )?;
        assert_eq!(outcome.failure(), None);
        let proof = outcome.children();
        assert!(matches!(
            proof.tui(),
            ChildDisposition::Signaled {
                stop_action: StopAction::Term,
                ..
            }
        ));
        assert!(matches!(
            proof.app_server(),
            ChildDisposition::Signaled {
                stop_action: StopAction::Term,
                ..
            }
        ));
        assert_no_wait_authority(tui_identity.pid())?;
        assert_no_wait_authority(app_identity.pid())?;
        Ok(())
    }

    #[test]
    fn await_ready_accepts_only_the_exact_one_byte_sentinel() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(
            ChildRole::Tui,
            shell_command("printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;

        child.await_ready(Instant::now() + TEST_DEADLINE)?;
        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        let proof = outcome.children();
        assert!(matches!(
            proof.tui(),
            ChildDisposition::Signaled {
                stop_action: StopAction::Term,
                ..
            }
        ));
        assert_eq!(proof.app_server(), ChildDisposition::NotStarted);
        Ok(())
    }

    #[test]
    fn await_ready_rejects_extra_bytes_without_retaining_them() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(
            ChildRole::Tui,
            shell_command("printf RX; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;

        let error = child
            .await_ready(Instant::now() + TEST_DEADLINE)
            .err()
            .ok_or("readiness must fail")?;
        assert_eq!(
            error,
            ProcessError::InvalidReadiness {
                role: ChildRole::Tui
            }
        );
        assert!(!format!("{error:?}").contains("RX"));
        assert!(!error.to_string().contains("RX"));

        let _proof = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_rejects_a_delayed_second_byte() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(
            ChildRole::Tui,
            shell_command(
                "printf R; /bin/sleep 0.05; printf X; exec >/dev/null; exec /bin/sleep 5",
            ),
            true,
        )?;

        let error = child
            .await_ready(Instant::now() + TEST_DEADLINE)
            .err()
            .ok_or("delayed extra readiness data must fail")?;
        assert_eq!(
            error,
            ProcessError::InvalidReadiness {
                role: ChildRole::Tui
            }
        );
        assert!(!format!("{error:?}").contains('X'));

        let _outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_requires_the_writer_to_close_after_the_sentinel() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(
            ChildRole::Tui,
            shell_command("printf R; exec /bin/sleep 5"),
            true,
        )?;

        let error = child
            .await_ready(Instant::now() + Duration::from_millis(30))
            .err()
            .ok_or("an open readiness writer must time out")?;
        assert_eq!(
            error,
            ProcessError::ReadinessTimeout {
                role: ChildRole::Tui
            }
        );

        let _outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_distinguishes_early_exit_from_timeout() -> Result<(), Box<dyn Error>> {
        // Keep the readiness pipe open in a same-group descendant so pipe EOF
        // cannot race the direct child's waitid-visible exit. The guardian must
        // still report the leader's clean early exit and sweep the descendant.
        let command = shell_command("/bin/sleep 1 & exec /bin/sleep 0.2");
        let mut child = ManagedGroupChild::spawn(ChildRole::Tui, command, true)?;

        let error = child
            .await_ready(Instant::now() + TEST_DEADLINE)
            .err()
            .ok_or("readiness must fail")?;
        assert!(matches!(
            error,
            ProcessError::EarlyExit {
                role: ChildRole::Tui,
                disposition: ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::None,
                },
            }
        ));

        let outcome = shutdown_pair(Some(child), None, Duration::ZERO, TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        let proof = outcome.children();
        assert!(matches!(
            proof.tui(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::None,
            }
        ));
        Ok(())
    }

    #[test]
    fn await_ready_reports_a_live_silent_child_as_timeout() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), true)?;

        let error = child
            .await_ready(Instant::now() + Duration::from_millis(30))
            .err()
            .ok_or("readiness must time out")?;
        assert_eq!(
            error,
            ProcessError::ReadinessTimeout {
                role: ChildRole::Tui
            }
        );

        let _proof = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn shutdown_escalates_a_term_ignoring_child_to_kill() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(
            ChildRole::Tui,
            shell_command("trap '' TERM; printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;
        child.await_ready(Instant::now() + TEST_DEADLINE)?;

        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(30), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        let proof = outcome.children();
        assert!(matches!(
            proof.tui(),
            ChildDisposition::Signaled {
                signal: 9,
                stop_action: StopAction::Kill,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn forwarded_hup_or_term_shutdown_does_not_term_signal_the_tui_again()
    -> Result<(), Box<dyn Error>> {
        for (label, signal, expected_log) in [
            ("hup", TerminalShutdownSignal::Hup, b"RH".as_slice()),
            ("term", TerminalShutdownSignal::Term, b"RT".as_slice()),
        ] {
            let log = SignalLog::new(label)?;
            let mut tui =
                ManagedGroupChild::spawn(ChildRole::Tui, signal_counting_command(&log)?, false)?;
            wait_for_signal_log(&log, b"R")?;
            let app = ManagedGroupChild::spawn(ChildRole::AppServer, sleep_command("5"), false)?;

            let forwarded =
                tui.forward_terminal_shutdown_signal(signal, Instant::now() + TEST_DEADLINE)?;
            wait_for_signal_log(&log, expected_log)?;
            let outcome = shutdown_pair_after_forwarded_tui_signal(
                tui,
                Some(app),
                forwarded,
                Duration::from_millis(100),
                TEST_DEADLINE,
            )?;

            assert_eq!(log.contents()?, expected_log);
            assert!(matches!(
                outcome.children().tui(),
                ChildDisposition::Signaled {
                    signal: 9,
                    stop_action: StopAction::Kill,
                    ..
                }
            ));
            assert!(matches!(
                outcome.children().app_server(),
                ChildDisposition::Signaled {
                    signal: 15,
                    stop_action: StopAction::Term,
                    ..
                }
            ));
        }
        Ok(())
    }

    #[test]
    fn forwarded_hup_or_term_disposition_survives_exact_reap() -> Result<(), Box<dyn Error>> {
        for (signal, expected_signal) in [
            (TerminalShutdownSignal::Hup, 1),
            (TerminalShutdownSignal::Term, 15),
        ] {
            let mut tui = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
            let forwarded =
                tui.forward_terminal_shutdown_signal(signal, Instant::now() + TEST_DEADLINE)?;
            let deadline = Instant::now() + TEST_DEADLINE;
            while tui.poll_liveness(deadline)? != ChildLiveness::Exited {
                sleep_until_next_poll(deadline);
            }

            let outcome = shutdown_pair_after_forwarded_tui_signal(
                tui,
                None,
                forwarded,
                Duration::from_millis(100),
                TEST_DEADLINE,
            )?;
            assert_eq!(outcome.failure(), None);
            assert_eq!(
                outcome.children().tui(),
                ChildDisposition::Signaled {
                    signal: expected_signal,
                    core_dumped: false,
                    stop_action: StopAction::None,
                }
            );
        }
        Ok(())
    }

    #[test]
    fn forwarded_tui_shutdown_mode_and_wait_ownership_survive_retry() -> Result<(), Box<dyn Error>>
    {
        let log = SignalLog::new("retry-term")?;
        let mut tui =
            ManagedGroupChild::spawn(ChildRole::Tui, signal_counting_command(&log)?, false)?;
        wait_for_signal_log(&log, b"R")?;
        let tui_pid = tui.containment().pid();
        let app = ManagedGroupChild::spawn(ChildRole::AppServer, sleep_command("5"), false)?;
        let app_pid = app.containment().pid();
        let forwarded = tui.forward_terminal_shutdown_signal(
            TerminalShutdownSignal::Term,
            Instant::now() + TEST_DEADLINE,
        )?;
        wait_for_signal_log(&log, b"RT")?;

        let mut unreaped = shutdown_pair_after_forwarded_tui_signal(
            tui,
            Some(app),
            forwarded,
            Duration::MAX,
            Duration::ZERO,
        )
        .err()
        .ok_or("overflowing deadline must retain both child handles")?;
        assert_eq!(unreaped.error(), ProcessError::Deadline);
        assert!(format!("{unreaped:?}").contains("tui_owned: true"));
        assert!(format!("{unreaped:?}").contains("app_server_owned: true"));

        let outcome = unreaped.retry(Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(log.contents()?, b"RT");
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 9,
                stop_action: StopAction::Kill,
                ..
            }
        ));
        assert!(matches!(
            outcome.children().app_server(),
            ChildDisposition::Signaled {
                signal: 15,
                stop_action: StopAction::Term,
                ..
            }
        ));
        assert_no_wait_authority(tui_pid)?;
        assert_no_wait_authority(app_pid)?;
        assert_eq!(
            unreaped.retry(Duration::ZERO, Duration::ZERO),
            Err(ProcessError::RetryAfterResolution)
        );
        Ok(())
    }

    #[test]
    fn forwarded_shutdown_proof_requires_process_local_child_authority()
    -> Result<(), Box<dyn Error>> {
        let first = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
        let second = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;

        // Reproduce the strongest numeric spoof available inside this module:
        // metadata matches the target exactly, but the unforgeable generation
        // remains bound to a different direct Child handle.
        let mismatched = ForwardedTuiSignal {
            signal: TerminalShutdownSignal::Term,
            containment: second.containment(),
            authority: first.authority,
        };
        let outcome = shutdown_pair_after_forwarded_tui_signal(
            second,
            None,
            mismatched,
            Duration::from_millis(100),
            TEST_DEADLINE,
        )?;
        assert!(matches!(
            outcome,
            ShutdownOutcome::Failed {
                error: ProcessError::ForwardedSignalMismatch {
                    role: ChildRole::Tui
                },
                ..
            }
        ));

        let cleanup = shutdown_pair(Some(first), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(cleanup.failure(), None);
        Ok(())
    }

    #[test]
    fn terminal_control_authority_rejects_an_app_server_child() -> Result<(), Box<dyn Error>> {
        let mut app = ManagedGroupChild::spawn(ChildRole::AppServer, sleep_command("5"), false)?;
        let deadline = Instant::now() + TEST_DEADLINE;

        assert_eq!(
            app.notify_terminal_resize(deadline),
            Err(ProcessError::RoleMismatch {
                expected: ChildRole::Tui,
                actual: ChildRole::AppServer,
            })
        );
        assert_eq!(
            app.forward_interactive_terminal_signal(InteractiveTerminalSignal::Int, deadline),
            Err(ProcessError::RoleMismatch {
                expected: ChildRole::Tui,
                actual: ChildRole::AppServer,
            })
        );
        assert_eq!(
            app.suspend(deadline, deadline),
            Err(ProcessError::RoleMismatch {
                expected: ChildRole::Tui,
                actual: ChildRole::AppServer,
            })
        );
        assert_eq!(
            app.resume(deadline),
            Err(ProcessError::RoleMismatch {
                expected: ChildRole::Tui,
                actual: ChildRole::AppServer,
            })
        );

        let outcome = shutdown_pair(None, Some(app), Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn interactive_signal_narrowing_rejects_shutdown_signals() {
        assert_eq!(
            InteractiveTerminalSignal::from_unix_signal(UnixSignal::Int),
            Some(InteractiveTerminalSignal::Int)
        );
        assert_eq!(
            InteractiveTerminalSignal::from_unix_signal(UnixSignal::Quit),
            Some(InteractiveTerminalSignal::Quit)
        );
        assert_eq!(
            InteractiveTerminalSignal::from_unix_signal(UnixSignal::Hup),
            None
        );
        assert_eq!(
            InteractiveTerminalSignal::from_unix_signal(UnixSignal::Term),
            None
        );
    }

    #[test]
    fn dropping_a_live_child_best_effort_kills_and_reaps_its_leader() -> Result<(), Box<dyn Error>>
    {
        let child = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
        let pid = child.containment().pid();

        drop(child);

        assert_no_wait_authority(pid)
    }

    #[test]
    fn liveness_poll_observes_exit_without_consuming_exact_wait_authority()
    -> Result<(), Box<dyn Error>> {
        // An instant exit can legitimately race the mandatory PGID readback during
        // spawn; this fixture instead exits just after containment is published.
        let command = sleep_command("0.2");
        let mut child = ManagedGroupChild::spawn(ChildRole::Tui, command, false)?;
        let deadline = Instant::now() + TEST_DEADLINE;

        loop {
            if child.poll_liveness(deadline)? == ChildLiveness::Exited {
                break;
            }
            if Instant::now() >= deadline {
                return Err("child did not exit before the liveness deadline".into());
            }
            sleep_until_next_poll(deadline);
        }

        let outcome = shutdown_pair(Some(child), None, Duration::ZERO, TEST_DEADLINE)?;
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::None,
            }
        ));
        Ok(())
    }

    #[test]
    fn liveness_poll_keeps_stopped_tui_classified_as_running() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;
        let started_at = Instant::now();
        child.suspend(
            started_at + Duration::from_millis(100),
            started_at + TEST_DEADLINE,
        )?;

        assert_eq!(
            child.poll_liveness(Instant::now() + TEST_DEADLINE)?,
            ChildLiveness::Running
        );

        child.resume(Instant::now() + TEST_DEADLINE)?;
        let outcome = shutdown_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn exact_reap_proof_survives_an_earlier_shutdown_failure() -> Result<(), Box<dyn Error>> {
        let wrong_role = ManagedGroupChild::spawn(ChildRole::AppServer, sleep_command("5"), false)?;

        let outcome = shutdown_pair(
            Some(wrong_role),
            None,
            Duration::from_millis(100),
            TEST_DEADLINE,
        )?;

        assert!(matches!(
            outcome,
            ShutdownOutcome::Failed {
                error: ProcessError::RoleMismatch {
                    expected: ChildRole::Tui,
                    actual: ChildRole::AppServer,
                },
                ..
            }
        ));
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled { .. }
        ));
        Ok(())
    }

    #[test]
    fn invalid_shutdown_deadline_returns_the_live_direct_handle_for_retry()
    -> Result<(), Box<dyn Error>> {
        let child = ManagedGroupChild::spawn(ChildRole::Tui, sleep_command("5"), false)?;

        let mut unreaped = shutdown_pair(Some(child), None, Duration::MAX, Duration::ZERO)
            .err()
            .ok_or("overflowing deadline must fail")?;
        assert_eq!(unreaped.error(), ProcessError::Deadline);

        let outcome = unreaped.retry(Duration::from_millis(100), TEST_DEADLINE)?;
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled { .. }
        ));
        assert_eq!(
            unreaped.retry(Duration::ZERO, Duration::ZERO),
            Err(ProcessError::RetryAfterResolution)
        );
        Ok(())
    }

    #[test]
    fn pre_spawn_failure_is_redacted_and_requires_no_wait_authority() -> Result<(), Box<dyn Error>>
    {
        let command = Command::new("/calcifer-private-sentinel/does-not-exist");

        let failure = ManagedGroupChild::spawn(ChildRole::Tui, command, false)
            .err()
            .ok_or("missing executable must fail")?;
        assert_eq!(failure.state(), SpawnFailureState::NotStarted);
        assert_eq!(
            failure.error(),
            ProcessError::Spawn {
                role: ChildRole::Tui
            }
        );
        assert!(!format!("{failure:?}").contains("private-sentinel"));

        let proof = failure.cleanup(Instant::now() + TEST_DEADLINE).map_err(
            |failure| -> Box<dyn Error> { format!("cleanup remained live: {failure}").into() },
        )?;
        assert_eq!(
            proof.error(),
            ProcessError::Spawn {
                role: ChildRole::Tui
            }
        );
        assert!(!proof.started_unannounced());
        Ok(())
    }
}
