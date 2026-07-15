//! Guardian-owned process-group supervision for the staged Codex supervisor.
//!
//! This module deliberately keeps direct [`Child`] handles. Reported process
//! identifiers are containment metadata only; they are never wait authority.

use std::fmt;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{ChildDisposition, ChildRole, StopAction};

const READINESS_SENTINEL: u8 = b'R';
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SPAWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

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
    SpawnCleanupTimeout {
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
            Self::SpawnCleanupTimeout { .. } => {
                "supervised child spawn cleanup exceeded its deadline"
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
    expected_group: rustix::process::Pid,
    drop_deadline: Option<Instant>,
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

    fn started(error: ProcessError, child: Child, expected_group: rustix::process::Pid) -> Self {
        Self {
            error,
            child: Some(FailedSpawnChild {
                child,
                expected_group,
                drop_deadline: None,
            }),
            disposition: None,
            started: true,
        }
    }

    pub(super) const fn error(&self) -> ProcessError {
        self.error
    }

    pub(super) const fn state(&self) -> SpawnFailureState {
        match (self.started, self.disposition, self.child.is_some()) {
            (false, _, _) => SpawnFailureState::NotStarted,
            (true, Some(_), false) => SpawnFailureState::ReapedUnannounced,
            (true, None, true) => SpawnFailureState::LiveUnannouncedChild,
            (true, None, false) | (true, Some(_), true) => SpawnFailureState::LiveUnannouncedChild,
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
        if let Some(disposition) = self.disposition {
            return Ok(SpawnCleanupProof {
                error: self.error,
                kind: SpawnCleanupKind::ReapedUnannounced(disposition),
            });
        }
        let Some(mut failed_child) = self.child.take() else {
            return Err(self);
        };
        failed_child.drop_deadline = None;

        let _ = rustix::process::kill_process_group(
            failed_child.expected_group,
            rustix::process::Signal::KILL,
        );
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
        let _ = rustix::process::kill_process_group(
            failed_child.expected_group,
            rustix::process::Signal::KILL,
        );
        let _ = failed_child.child.kill();
        let deadline = match failed_child.drop_deadline {
            Some(deadline) => deadline,
            None => {
                let Some(deadline) = Instant::now().checked_add(DROP_CLEANUP_TIMEOUT) else {
                    return;
                };
                deadline
            }
        };
        loop {
            match failed_child.child.try_wait() {
                Ok(Some(status)) => {
                    self.disposition = Some(project_disposition(status, StopAction::Kill));
                    return;
                }
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) | Err(_) => return,
            }
        }
    }
}

/// A guardian-owned direct child whose leader starts a distinct process group.
pub(super) struct ManagedGroupChild {
    role: ChildRole,
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
                    self.observed_exit = status.is_some();
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
                    return;
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
        if self
            .signal_group(rustix::process::Signal::KILL, StopAction::Kill, deadline)
            .is_ok()
        {
            self.containment_swept = true;
        }
        let _ = self.child.kill();

        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.disposition = Some(project_disposition(status, self.stop_action));
                    self.observed_exit = true;
                    return;
                }
                Err(_) => return,
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) => return,
            }
        }
    }
}

/// A failed shutdown that still owns every unreaped direct child handle.
#[must_use = "unreaped children must remain owned while the guardian lease is retained"]
pub(super) struct UnreapedChildren {
    error: ProcessError,
    tui: Option<ManagedGroupChild>,
    app_server: Option<ManagedGroupChild>,
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
    shutdown_pair_inner(tui, app_server, grace, forced, None)
}

fn shutdown_pair_inner(
    mut tui: Option<ManagedGroupChild>,
    mut app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
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
        ));
    };
    let Some(hard_deadline) = grace_deadline.checked_add(forced) else {
        return Err(unreaped_children(
            tui,
            app_server,
            ProcessError::Deadline,
            None,
        ));
    };

    validate_child_role(&tui, ChildRole::Tui, &mut first_error);
    validate_child_role(&app_server, ChildRole::AppServer, &mut first_error);
    begin_child_termination(&mut tui, grace_deadline, &mut first_error);
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
        ));
    }

    let tui_disposition = match reaped_disposition(&tui, ChildRole::Tui) {
        Ok(disposition) => disposition,
        Err(error) => return Err(unreaped_children(tui, app_server, error, None)),
    };
    let app_server_disposition = match reaped_disposition(&app_server, ChildRole::AppServer) {
        Ok(disposition) => disposition,
        Err(error) => return Err(unreaped_children(tui, app_server, error, None)),
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
    let failure = SpawnFailure::started(original_error, child, expected_group);
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
            failure.error = ProcessError::SpawnCleanupTimeout {
                role: process_error_role(original_error),
            };
            failure
        }
    }
}

const fn process_error_role(error: ProcessError) -> ChildRole {
    match error {
        ProcessError::Spawn { role }
        | ProcessError::ProcessGroupReadback { role }
        | ProcessError::ProcessGroupMismatch { role }
        | ProcessError::SpawnCleanupTimeout { role }
        | ProcessError::ReadinessUnavailable { role }
        | ProcessError::ParentLivenessUnavailable { role }
        | ProcessError::ReadinessTimeout { role }
        | ProcessError::ReadinessIo { role }
        | ProcessError::InvalidReadiness { role }
        | ProcessError::EarlyExit { role, .. }
        | ProcessError::Signal { role, .. }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;

    const TEST_DEADLINE: Duration = Duration::from_secs(3);

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
        let command = Command::new("/usr/bin/true");
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
        let command = Command::new("/usr/bin/true");
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
