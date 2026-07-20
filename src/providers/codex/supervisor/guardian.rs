//! Concrete guardian lifecycle driver for one same-profile Codex generation.
//!
//! Only the protocol harness is generic over its wire. Production ownership is
//! deliberately concrete: B enters as [`GuardianSessionAuthority`] and can
//! thereafter exist only inside the provider/startup/session linear owners.

use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::os::fd::AsFd;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::os::unix::fs::OpenOptionsExt;

use crate::profiles::{Profile, Registry};

use super::channel::{ChannelError, LifecycleEndpoint, bootstrap_guardian_from_stdin};
#[cfg(test)]
use super::entry::RecoveryCheckpoint;
use super::entry::{CompletionError, GuardianCompletion, RecoveryRequestPoll};
#[cfg(test)]
use super::packaged_smoke::write_private_atomic_new;
use super::process::ContainmentMetadata;
use super::protocol::{
    CleanupStatus, CoordinatorCommand, FailureCode, GuardianCommandReceiver, GuardianEvent,
    GuardianExitDisposition, Phase, ProtocolError, SessionTerminationCause, UnixSignal,
    WorkerJoinStatus,
};
use super::provider::{
    GuardianSessionAuthority, ProviderLaunchAuthorization, accept_provider_launch_authorization,
};
use super::session::{
    ActiveSupervisedSession, AwaitingReadySupervisedSession, DrainingSupervisedSession,
    ProductionSessionComponents, ProviderReleaseProof, ReadySupervisedSession,
    ResumedAwaitingGateSupervisedSession, SessionComponent, SessionLifecycleProjection,
    SessionLivenessFailure, SessionOperationError, SessionShutdownBounds, SessionShutdownFailure,
    SessionShutdownRecoveryStage, SessionShutdownReport, SessionState, SessionTerminalFailure,
    SuspendedSupervisedSession, TerminalPumpFailure, TerminalPumpProgress,
    admit_same_profile_guardian_session,
};
#[cfg(test)]
use super::session::{
    SessionShutdownTestTrigger, SessionStartupError, packaged_session_startup_failure_marker,
};
use super::startup::{
    AwaitingCoordinatorRestore, PostRestoreStartupCleanup, ProductionStartupBounds,
    StartupCleanupFailure, StartupCleanupReport, StartupLifecycleReportError,
    StartupLifecycleReporter, StartupQuiesceFailure, StartupShutdownBounds, SupervisedStartupError,
    SupervisedStartupFailure, start_supervised_session,
};
#[cfg(test)]
use super::startup::{
    PackagedRuntimeFailureStage, PackagedStartupQuiescePhase,
    start_supervised_session_with_test_compatibility,
};
use super::terminal::{RecoveryTty, TerminalEndpoint, TerminalError, TerminalSnapshot};

#[cfg(test)]
pub(super) const PACKAGED_APP_NOT_STARTED_MARKER: &str = "app.not-started-v1";
#[cfg(test)]
pub(super) const PACKAGED_TUI_NOT_STARTED_MARKER: &str = "tui.not-started-v1";
#[cfg(test)]
pub(super) const PACKAGED_STARTUP_FAILURE_MARKERS: &[&str] = &[
    "startup-failure.terminal",
    "startup-failure.compatibility",
    "startup-failure.runtime-create",
    "startup-failure.runtime-layout",
    "startup-failure.runtime",
    "startup-failure.app-plan",
    "startup-failure.app-launch",
    "startup-failure.app-socket",
    "startup-failure.monitor-connect",
    "startup-failure.monitor-start",
    "startup-failure.relay-plan",
    "startup-failure.relay-start",
    "startup-failure.tui-plan",
    "startup-failure.tui-pty",
    "startup-failure.tui-launch",
    "startup-failure.tui-readiness",
    "startup-failure.lifecycle",
    "startup-failure.session-readiness",
    "startup-failure.deadline",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardianLifecycleError {
    Deadline,
    Lost,
    Protocol,
}

fn classify_protocol_error(error: ProtocolError) -> GuardianLifecycleError {
    match error {
        ProtocolError::Timeout => GuardianLifecycleError::Deadline,
        ProtocolError::UnexpectedEof
        | ProtocolError::TruncatedHeader
        | ProtocolError::TruncatedBody
        | ProtocolError::Io => GuardianLifecycleError::Lost,
        _ => GuardianLifecycleError::Protocol,
    }
}

/// Transcript-validating owner for the guardian half of one lifecycle wire.
struct GuardianLifecycle<R> {
    commands: GuardianCommandReceiver<R>,
    completion: GuardianCompletion,
    failure_announced: bool,
    bounds: GuardianBounds,
    #[cfg(test)]
    before_completion_publication: Option<PackagedBeforeCompletionPublication>,
    #[cfg(test)]
    observe_completion_publication_failure: Option<PackagedCompletionPublicationFailureObserver>,
    #[cfg(test)]
    recovery_checkpoint: Option<RecoveryCheckpoint>,
    #[cfg(test)]
    packaged_checkpoint_report_root: Option<PathBuf>,
}

#[cfg(test)]
type PackagedBeforeCompletionPublication = fn() -> Result<(), CompletionError>;
#[cfg(test)]
type PackagedCompletionPublicationFailureObserver = fn(CompletionError);

#[cfg(test)]
const fn packaged_guardian_checkpoint_boundary_failure_marker(
    error: CompletionError,
) -> &'static str {
    match error {
        CompletionError::Create => "recovery.guardian-checkpoint.publish-failed.create",
        CompletionError::Descriptor => "recovery.guardian-checkpoint.publish-failed.descriptor",
        CompletionError::Inherited => "recovery.guardian-checkpoint.publish-failed.inherited",
        CompletionError::Io => "recovery.guardian-checkpoint.publish-failed.io",
        CompletionError::MissingFrame => {
            "recovery.guardian-checkpoint.publish-failed.missing-frame"
        }
        CompletionError::InvalidFrame => {
            "recovery.guardian-checkpoint.publish-failed.invalid-frame"
        }
        CompletionError::TrailingData => {
            "recovery.guardian-checkpoint.publish-failed.trailing-data"
        }
        CompletionError::RecoveryDeadline => "recovery.guardian-checkpoint.publish-failed.deadline",
        CompletionError::RecoveryPeerExited => {
            "recovery.guardian-checkpoint.publish-failed.peer-exited"
        }
        CompletionError::RecoveryReplay => "recovery.guardian-checkpoint.publish-failed.replay",
        CompletionError::RecoveryTooLate => "recovery.guardian-checkpoint.publish-failed.too-late",
    }
}

#[cfg(test)]
const fn packaged_guardian_checkpoint_request_failure_marker(
    error: CompletionError,
) -> &'static str {
    match error {
        CompletionError::Create => "recovery.guardian-checkpoint.request-failed.create",
        CompletionError::Descriptor => "recovery.guardian-checkpoint.request-failed.descriptor",
        CompletionError::Inherited => "recovery.guardian-checkpoint.request-failed.inherited",
        CompletionError::Io => "recovery.guardian-checkpoint.request-failed.io",
        CompletionError::MissingFrame => {
            "recovery.guardian-checkpoint.request-failed.missing-frame"
        }
        CompletionError::InvalidFrame => {
            "recovery.guardian-checkpoint.request-failed.invalid-frame"
        }
        CompletionError::TrailingData => {
            "recovery.guardian-checkpoint.request-failed.trailing-data"
        }
        CompletionError::RecoveryDeadline => "recovery.guardian-checkpoint.request-failed.deadline",
        CompletionError::RecoveryPeerExited => {
            "recovery.guardian-checkpoint.request-failed.peer-exited"
        }
        CompletionError::RecoveryReplay => "recovery.guardian-checkpoint.request-failed.replay",
        CompletionError::RecoveryTooLate => "recovery.guardian-checkpoint.request-failed.too-late",
    }
}

impl<R: Read> GuardianLifecycle<R> {
    fn new(wire: R, completion: GuardianCompletion, bounds: GuardianBounds) -> Self {
        Self {
            commands: GuardianCommandReceiver::new_terminal(wire),
            completion,
            failure_announced: false,
            bounds,
            #[cfg(test)]
            before_completion_publication: None,
            #[cfg(test)]
            observe_completion_publication_failure: None,
            #[cfg(test)]
            recovery_checkpoint: None,
            #[cfg(test)]
            packaged_checkpoint_report_root: None,
        }
    }

    #[cfg(test)]
    fn install_completion_publication_test_seam(
        &mut self,
        before: PackagedBeforeCompletionPublication,
        observe_failure: PackagedCompletionPublicationFailureObserver,
    ) {
        self.before_completion_publication = Some(before);
        self.observe_completion_publication_failure = Some(observe_failure);
    }

    #[cfg(test)]
    fn install_recovery_checkpoint(&mut self, checkpoint: Option<RecoveryCheckpoint>) {
        self.recovery_checkpoint = checkpoint;
    }

    #[cfg(test)]
    fn install_packaged_checkpoint_report_root(&mut self, report_root: Option<&Path>) {
        self.packaged_checkpoint_report_root = report_root.map(Path::to_path_buf);
    }

    #[cfg(test)]
    fn record_packaged_checkpoint_marker(&self, marker: &'static str) {
        if let Some(report_root) = &self.packaged_checkpoint_report_root {
            let _ = write_private_atomic_new(&report_root.join(marker), b"classified\n");
        }
    }

    #[cfg(test)]
    fn record_packaged_recovery_terminal_observation(&self, observation: RecoveryRequestPoll) {
        let marker = match observation {
            RecoveryRequestPoll::Verified => "recovery.guardian-checkpoint.request-verified",
            RecoveryRequestPoll::OwnerLost => "recovery.guardian-checkpoint.owner-lost",
            RecoveryRequestPoll::ProtocolRejectedOwnerLost => {
                "recovery.guardian-checkpoint.protocol-rejected-owner-lost"
            }
            RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected => return,
        };
        self.record_packaged_checkpoint_marker(marker);
    }

    #[cfg(test)]
    fn recovery_checkpoint_is_selected(&self, checkpoint: RecoveryCheckpoint) -> bool {
        self.recovery_checkpoint == Some(checkpoint)
    }

    /// Emits a test-only observation, then waits for the existing generation-
    /// bound request. The observation itself authorizes no state transition.
    #[cfg(test)]
    fn checkpoint_and_wait_for_recovery(
        &mut self,
        checkpoint: RecoveryCheckpoint,
        deadline: Instant,
    ) -> Result<TestRecoveryCheckpointOutcome, GuardianLifecycleError> {
        if !self.recovery_checkpoint_is_selected(checkpoint) {
            return Ok(TestRecoveryCheckpointOutcome::NotSelected);
        }
        self.recovery_checkpoint.take();
        self.record_packaged_checkpoint_marker("recovery.guardian-checkpoint.publish-attempt");
        if let Err(error) = self
            .completion
            .publish_test_checkpoint(checkpoint, deadline)
        {
            self.record_packaged_checkpoint_marker(
                packaged_guardian_checkpoint_boundary_failure_marker(error),
            );
            return self.finish_test_checkpoint_observation(
                checkpoint,
                TestRecoveryCheckpointOutcome::BoundaryFailed,
            );
        }
        self.record_packaged_checkpoint_marker("recovery.guardian-checkpoint.published");
        loop {
            match self.completion.poll_recovery_request(deadline) {
                Ok(RecoveryRequestPoll::Verified) => {
                    self.record_packaged_recovery_terminal_observation(
                        RecoveryRequestPoll::Verified,
                    );
                    return self.finish_test_checkpoint_observation(
                        checkpoint,
                        TestRecoveryCheckpointOutcome::RecoveryRequested,
                    );
                }
                Ok(RecoveryRequestPoll::OwnerLost) => {
                    self.record_packaged_recovery_terminal_observation(
                        RecoveryRequestPoll::OwnerLost,
                    );
                    return self.finish_test_checkpoint_observation(
                        checkpoint,
                        TestRecoveryCheckpointOutcome::RecoveryRequested,
                    );
                }
                Ok(RecoveryRequestPoll::ProtocolRejectedOwnerLost) => {
                    self.record_packaged_recovery_terminal_observation(
                        RecoveryRequestPoll::ProtocolRejectedOwnerLost,
                    );
                    return self.finish_test_checkpoint_observation(
                        checkpoint,
                        TestRecoveryCheckpointOutcome::RecoveryRequested,
                    );
                }
                Ok(RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected)
                    if Instant::now() < deadline => {}
                Ok(RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected) => {
                    self.record_packaged_checkpoint_marker(
                        "recovery.guardian-checkpoint.request-deadline",
                    );
                    return self.finish_test_checkpoint_observation(
                        checkpoint,
                        TestRecoveryCheckpointOutcome::BoundaryFailed,
                    );
                }
                Err(error) => {
                    self.record_packaged_checkpoint_marker(
                        packaged_guardian_checkpoint_request_failure_marker(error),
                    );
                    return self.finish_test_checkpoint_observation(
                        checkpoint,
                        TestRecoveryCheckpointOutcome::BoundaryFailed,
                    );
                }
            }
        }
    }

    #[cfg(test)]
    fn finish_test_checkpoint_observation(
        &mut self,
        checkpoint: RecoveryCheckpoint,
        outcome: TestRecoveryCheckpointOutcome,
    ) -> Result<TestRecoveryCheckpointOutcome, GuardianLifecycleError> {
        if checkpoint_arms_recovery_command_race(checkpoint) {
            self.commands_mut()
                .arm_recovery_command_race()
                .map_err(classify_protocol_error)?;
        }
        Ok(outcome)
    }

    /// Retained owners publish the observation before returning their typed
    /// authority; `RetainedGuardianGeneration::await_recovery` remains the
    /// only consumer of the real request.
    #[cfg(test)]
    fn publish_retained_checkpoint_if_selected(
        &mut self,
        checkpoint: RecoveryCheckpoint,
        deadline: Instant,
    ) -> Result<bool, CompletionError> {
        if !self.recovery_checkpoint_is_selected(checkpoint) {
            return Ok(false);
        }
        self.recovery_checkpoint.take();
        self.record_packaged_checkpoint_marker("recovery.guardian-checkpoint.publish-attempt");
        if let Err(error) = self
            .completion
            .publish_test_checkpoint(checkpoint, deadline)
        {
            self.record_packaged_checkpoint_marker(
                packaged_guardian_checkpoint_boundary_failure_marker(error),
            );
            return Err(error);
        }
        self.record_packaged_checkpoint_marker("recovery.guardian-checkpoint.published");
        Ok(true)
    }

    fn receive(&mut self, deadline: Instant) -> Result<CoordinatorCommand, GuardianLifecycleError> {
        self.commands
            .receive(deadline)
            .map_err(classify_protocol_error)
    }

    fn commands_mut(&mut self) -> &mut GuardianCommandReceiver<R> {
        &mut self.commands
    }

    fn publish_anchor_completion(self, proof: ProviderReleaseProof) -> Result<(), CompletionError> {
        let Self {
            commands,
            completion,
            failure_announced: _,
            bounds: _,
            #[cfg(test)]
            before_completion_publication,
            #[cfg(test)]
            observe_completion_publication_failure,
            #[cfg(test)]
                recovery_checkpoint: _,
            #[cfg(test)]
                packaged_checkpoint_report_root: _,
        } = self;
        drop(commands);
        #[cfg(test)]
        if let Some(before) = before_completion_publication {
            before()?;
        }
        let result = completion.publish_after_provider_release(proof);
        #[cfg(test)]
        if let (Err(error), Some(observe_failure)) =
            (result, observe_completion_publication_failure)
        {
            observe_failure(error);
        }
        result
    }

    fn publish_retained_unrecoverable(self) -> Result<(), CompletionError> {
        let Self {
            commands,
            completion,
            failure_announced: _,
            bounds: _,
            #[cfg(test)]
                before_completion_publication: _,
            #[cfg(test)]
                observe_completion_publication_failure: _,
            #[cfg(test)]
                recovery_checkpoint: _,
            #[cfg(test)]
                packaged_checkpoint_report_root: _,
        } = self;
        drop(commands);
        completion.publish_retained_unrecoverable()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestRecoveryCheckpointOutcome {
    NotSelected,
    RecoveryRequested,
    BoundaryFailed,
}

#[cfg(test)]
const fn checkpoint_arms_recovery_command_race(checkpoint: RecoveryCheckpoint) -> bool {
    matches!(
        checkpoint,
        RecoveryCheckpoint::Ready | RecoveryCheckpoint::Active | RecoveryCheckpoint::Suspended
    )
}

impl<R: Read + Write> GuardianLifecycle<R> {
    fn emit(
        &mut self,
        event: GuardianEvent,
        deadline: Instant,
    ) -> Result<(), GuardianLifecycleError> {
        self.commands
            .record_and_send(event, deadline)
            .map_err(classify_protocol_error)?;
        self.failure_announced |= matches!(event, GuardianEvent::Failed { .. });
        Ok(())
    }

    fn emit_failure(
        &mut self,
        phase: Phase,
        code: FailureCode,
        deadline: Instant,
    ) -> Result<(), GuardianLifecycleError> {
        self.emit(GuardianEvent::Failed { phase, code }, deadline)
    }

    fn take_exit_disposition(&mut self) -> Result<GuardianExitDisposition, GuardianLifecycleError> {
        self.commands
            .take_verified_exit_disposition()
            .map(|proof| proof.into_disposition())
            .map_err(classify_protocol_error)
    }
}

impl<R: AsFd> GuardianLifecycle<R> {
    fn readable_before(&self, deadline: Instant) -> Result<bool, GuardianLifecycleError> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let timeout =
                rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
                    .map_err(|_| GuardianLifecycleError::Deadline)?;
            let mut descriptors = [rustix::event::PollFd::new(
                &self.commands,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    let events = descriptors[0].revents();
                    if events
                        .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
                    {
                        return Err(GuardianLifecycleError::Lost);
                    }
                    return Ok(events
                        .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP));
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return Err(GuardianLifecycleError::Lost),
            }
        }
    }

    fn poll_recovery_request(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryRequestPoll, CompletionError> {
        self.completion.poll_recovery_request(deadline)
    }
}

struct LifecycleStartupReporter<'a, R> {
    lifecycle: &'a mut GuardianLifecycle<R>,
    last_error: Option<GuardianLifecycleError>,
    #[cfg(test)]
    checkpoint_shutdown_requested: bool,
    #[cfg(test)]
    packaged_child_report_root: Option<&'a Path>,
}

impl<'a, R> LifecycleStartupReporter<'a, R> {
    fn new(lifecycle: &'a mut GuardianLifecycle<R>) -> Self {
        Self {
            lifecycle,
            last_error: None,
            #[cfg(test)]
            checkpoint_shutdown_requested: false,
            #[cfg(test)]
            packaged_child_report_root: None,
        }
    }

    #[cfg(test)]
    fn set_packaged_child_report_root(&mut self, report_root: Option<&'a Path>) {
        self.packaged_child_report_root = report_root;
    }
}

impl<R: Read + Write + AsFd> StartupLifecycleReporter for LifecycleStartupReporter<'_, R> {
    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.lifecycle.commands.as_fd())?;
        self.lifecycle
            .completion
            .append_forbidden_descriptor(forbidden)
    }

    fn child_started(
        &mut self,
        child: ContainmentMetadata,
        deadline: Instant,
    ) -> Result<(), StartupLifecycleReportError> {
        if let Err(error) = self.lifecycle.emit(
            GuardianEvent::ChildStarted {
                role: child.role(),
                pid: child.pid(),
                pgid: child.pgid(),
            },
            deadline,
        ) {
            self.last_error = Some(error);
            return Err(StartupLifecycleReportError);
        }
        #[cfg(test)]
        if let Some(report_root) = self.packaged_child_report_root {
            let name = match child.role() {
                super::protocol::ChildRole::AppServer => "app.child",
                super::protocol::ChildRole::Tui => "tui.child",
            };
            let marker = write_private_atomic_new(
                &report_root.join(name),
                format!("{} {}\n", child.pid(), child.pgid()).as_bytes(),
            );
            if marker.is_err() {
                self.last_error = Some(GuardianLifecycleError::Protocol);
                return Err(StartupLifecycleReportError);
            }
        }
        #[cfg(test)]
        if child.role() == super::protocol::ChildRole::Tui {
            match self
                .lifecycle
                .checkpoint_and_wait_for_recovery(RecoveryCheckpoint::StartupQueued, deadline)
            {
                Ok(TestRecoveryCheckpointOutcome::NotSelected) => {}
                Ok(TestRecoveryCheckpointOutcome::RecoveryRequested) => {
                    self.checkpoint_shutdown_requested = true;
                    return Err(StartupLifecycleReportError);
                }
                Ok(TestRecoveryCheckpointOutcome::BoundaryFailed) => {
                    // A completion-boundary failure is not lifecycle loss.
                    // Abort startup into ordinary typed cleanup so only an
                    // actual lifecycle failure can authorize fallback restore.
                    self.checkpoint_shutdown_requested = true;
                    return Err(StartupLifecycleReportError);
                }
                Err(error) => {
                    self.last_error = Some(error);
                    return Err(StartupLifecycleReportError);
                }
            }
        }
        Ok(())
    }
}

/// Relative limits for one production guardian. A session may run forever;
/// every individual startup, pump, protocol, restore, and cleanup edge is
/// bounded by a freshly-derived absolute deadline.
#[derive(Clone, Copy)]
pub(super) struct GuardianBounds {
    pub(super) phase_timeout: Duration,
    pub(super) poll_interval: Duration,
    pub(super) startup_timeout: Duration,
    pub(super) compatibility_timeout: Duration,
    pub(super) relay_start_timeout: Duration,
    pub(super) containment_timeout: Duration,
    pub(super) tui_grace: Duration,
    pub(super) tui_forced: Duration,
    pub(super) relay_shutdown_timeout: Duration,
    pub(super) monitor_shutdown_timeout: Duration,
    pub(super) app_grace: Duration,
    pub(super) app_forced: Duration,
    pub(super) app_cleanup_timeout: Duration,
    pub(super) build_cleanup_timeout: Duration,
}

impl GuardianBounds {
    fn validate(self) -> Result<Self, GuardianSetupError> {
        let nonzero = [
            self.phase_timeout,
            self.poll_interval,
            self.startup_timeout,
            self.compatibility_timeout,
            self.relay_start_timeout,
            self.containment_timeout,
            self.relay_shutdown_timeout,
            self.monitor_shutdown_timeout,
            self.app_cleanup_timeout,
            self.build_cleanup_timeout,
        ]
        .into_iter()
        .all(|duration| !duration.is_zero());
        if !nonzero || self.poll_interval > self.phase_timeout {
            return Err(GuardianSetupError::Deadline);
        }
        Ok(self)
    }

    fn deadline_after(self, duration: Duration) -> Result<Instant, GuardianSetupError> {
        Instant::now()
            .checked_add(duration)
            .ok_or(GuardianSetupError::Deadline)
    }

    fn phase_deadline(self) -> Result<Instant, GuardianSetupError> {
        self.deadline_after(self.phase_timeout)
    }

    fn turn_deadline(self) -> Result<Instant, GuardianSetupError> {
        self.deadline_after(self.poll_interval)
    }

    fn startup(self) -> Result<ProductionStartupBounds, GuardianSetupError> {
        Ok(ProductionStartupBounds {
            deadline: self.deadline_after(self.startup_timeout)?,
            compatibility_timeout: self.compatibility_timeout,
            relay_timeout: self.relay_start_timeout,
        })
    }

    fn session_shutdown(self) -> Result<SessionShutdownBounds, GuardianSetupError> {
        Ok(SessionShutdownBounds {
            tui_grace: self.tui_grace,
            tui_forced: self.tui_forced,
            relay_timeout: self.relay_shutdown_timeout,
            monitor_timeout: self.monitor_shutdown_timeout,
            app_grace: self.app_grace,
            app_forced: self.app_forced,
            app_cleanup_timeout: self.app_cleanup_timeout,
            build_cleanup_timeout: self.build_cleanup_timeout,
        })
    }

    fn startup_shutdown(self) -> Result<StartupShutdownBounds, GuardianSetupError> {
        Ok(StartupShutdownBounds {
            containment_timeout: self.containment_timeout,
            session: self.session_shutdown()?,
        })
    }
}

pub(super) struct ProductionGuardianConfig<'a> {
    pub(super) registry: &'a Registry,
    pub(super) profile: &'a Profile,
    pub(super) working_directory: &'a Path,
    pub(super) thread_id: &'a str,
    pub(super) codex_executable: &'a Path,
    pub(super) runtime_parent: &'a Path,
    pub(super) expected_foreground_process_group: i32,
    pub(super) bounds: GuardianBounds,
    pub(super) completion: GuardianCompletion,
}

#[derive(Clone, Copy)]
struct GuardianExecutionConfig<'a> {
    codex_executable: &'a Path,
    runtime_parent: &'a Path,
    bounds: GuardianBounds,
    #[cfg(test)]
    packaged_child_report_root: Option<&'a Path>,
    #[cfg(test)]
    fixture_compatibility_stage_parent: Option<&'a Path>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardianSetupError {
    Deadline,
    Lifecycle,
    Terminal,
    Admission,
    Protocol,
}

impl fmt::Display for GuardianSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the production guardian could not be assembled")
    }
}

impl std::error::Error for GuardianSetupError {}

fn map_channel_error(_error: ChannelError) -> GuardianSetupError {
    GuardianSetupError::Lifecycle
}

fn map_terminal_error(_error: TerminalError) -> GuardianSetupError {
    GuardianSetupError::Terminal
}

/// Post-arm owner. The concrete launch authority contains the sole B lease;
/// no generic owner can enter this state.
struct ArmedProductionGuardian<'a> {
    config: GuardianExecutionConfig<'a>,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    authorization: ProviderLaunchAuthorization,
    terminal: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
}

/// Closed bootstrap variation surface. Production fixes every optional seam
/// to `None`. The packaged proof may select only the post-admission loopback
/// rewrite, fixed reporter root, deterministic recovery checkpoint, and
/// private fixture compatibility stage. Lifecycle, terminal, recovery
/// authority, admission, protocol, and launch-authority construction always
/// remain in the one core below.
#[derive(Clone, Copy)]
struct GuardianBootstrapSeams<'a> {
    _lifetime: PhantomData<&'a ()>,
    #[cfg(test)]
    after_admission: Option<PackagedAfterAdmission>,
    #[cfg(test)]
    fixed_report_root: Option<&'a Path>,
    #[cfg(test)]
    recovery_checkpoint: Option<RecoveryCheckpoint>,
    #[cfg(test)]
    fixture_compatibility_stage_parent: Option<&'a Path>,
}

#[cfg(test)]
type PackagedAfterAdmission = fn(&Path) -> Result<(), GuardianSetupError>;

impl GuardianBootstrapSeams<'_> {
    const fn production() -> Self {
        Self {
            _lifetime: PhantomData,
            #[cfg(test)]
            after_admission: None,
            #[cfg(test)]
            fixed_report_root: None,
            #[cfg(test)]
            recovery_checkpoint: None,
            #[cfg(test)]
            fixture_compatibility_stage_parent: None,
        }
    }
}

#[cfg(test)]
pub(super) struct PackagedGuardianSeams<'a> {
    pub(super) after_admission: fn(&Path) -> Result<(), GuardianSetupError>,
    pub(super) fixed_report_root: &'a Path,
    pub(super) recovery_checkpoint: Option<RecoveryCheckpoint>,
    pub(super) fixture_compatibility_stage_parent: Option<&'a Path>,
}

#[cfg(test)]
impl<'a> From<PackagedGuardianSeams<'a>> for GuardianBootstrapSeams<'a> {
    fn from(seams: PackagedGuardianSeams<'a>) -> Self {
        Self {
            _lifetime: PhantomData,
            after_admission: Some(seams.after_admission),
            fixed_report_root: Some(seams.fixed_report_root),
            recovery_checkpoint: seams.recovery_checkpoint,
            fixture_compatibility_stage_parent: seams.fixture_compatibility_stage_parent,
        }
    }
}

fn bootstrap_guardian_core<'a>(
    config: ProductionGuardianConfig<'a>,
    _seams: GuardianBootstrapSeams<'a>,
) -> Result<ArmedProductionGuardian<'a>, GuardianSetupError> {
    let ProductionGuardianConfig {
        registry,
        profile,
        working_directory,
        thread_id,
        codex_executable,
        runtime_parent,
        expected_foreground_process_group,
        bounds,
        completion,
    } = config;
    let bounds = bounds.validate()?;
    let endpoint = bootstrap_guardian_from_stdin().map_err(map_channel_error)?;
    endpoint
        .set_read_timeout(Some(bounds.phase_timeout))
        .and_then(|()| endpoint.set_write_timeout(Some(bounds.phase_timeout)))
        .map_err(map_channel_error)?;
    let terminal =
        TerminalEndpoint::bootstrap_from_inherited_stdout().map_err(map_terminal_error)?;
    let recovery = RecoveryTty::bootstrap_from_inherited_stderr().map_err(map_terminal_error)?;
    let snapshot =
        TerminalSnapshot::capture_for_recovery(&recovery, expected_foreground_process_group)
            .map_err(map_terminal_error)?;
    let mut lifecycle = GuardianLifecycle::new(endpoint, completion, bounds);
    #[cfg(test)]
    lifecycle.install_recovery_checkpoint(_seams.recovery_checkpoint);
    #[cfg(test)]
    lifecycle.install_packaged_checkpoint_report_root(_seams.fixed_report_root);

    #[cfg(test)]
    let selected_home = if _seams.after_admission.is_some() {
        Some(
            registry
                .profile_home(profile)
                .map_err(|_| GuardianSetupError::Admission)?,
        )
    } else {
        None
    };
    let guardian_session: GuardianSessionAuthority =
        admit_same_profile_guardian_session(registry, profile, working_directory, thread_id)
            .map_err(|_| GuardianSetupError::Admission)?;
    #[cfg(test)]
    if let Some(after_admission) = _seams.after_admission {
        let selected_home = selected_home.ok_or(GuardianSetupError::Admission)?;
        after_admission(&selected_home)?;
    }

    lifecycle
        .emit(GuardianEvent::LeaseCommitted, bounds.phase_deadline()?)
        .map_err(|_| GuardianSetupError::Protocol)?;
    if lifecycle
        .receive(bounds.phase_deadline()?)
        .map_err(|_| GuardianSetupError::Protocol)?
        != CoordinatorCommand::Start
    {
        return Err(GuardianSetupError::Protocol);
    }
    lifecycle
        .emit(
            GuardianEvent::TerminalArmed {
                snapshot: snapshot.semantic_fingerprint(),
            },
            bounds.phase_deadline()?,
        )
        .map_err(|_| GuardianSetupError::Protocol)?;
    let authorization = accept_provider_launch_authorization(
        guardian_session,
        lifecycle.commands_mut(),
        bounds.phase_deadline()?,
    )
    .map_err(|_| GuardianSetupError::Protocol)?;

    Ok(ArmedProductionGuardian {
        config: GuardianExecutionConfig {
            codex_executable,
            runtime_parent,
            bounds,
            #[cfg(test)]
            packaged_child_report_root: _seams.fixed_report_root,
            #[cfg(test)]
            fixture_compatibility_stage_parent: _seams.fixture_compatibility_stage_parent,
        },
        lifecycle,
        authorization,
        terminal,
        recovery,
        snapshot,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GuardianRetentionReason {
    Deadline,
    ProtocolInvalid,
    RestoreUnconfirmed,
    CleanupUnconfirmed,
    UnreportableChild,
}

const fn retention_reason_allows_recovery(reason: GuardianRetentionReason) -> bool {
    match reason {
        GuardianRetentionReason::Deadline | GuardianRetentionReason::CleanupUnconfirmed => true,
        GuardianRetentionReason::ProtocolInvalid
        | GuardianRetentionReason::RestoreUnconfirmed
        | GuardianRetentionReason::UnreportableChild => false,
    }
}

/// One retained generation may authorize exactly one bounded recovery retry.
/// The consumed state is persisted into every generation returned by that
/// retry, so a second `await_recovery` cannot poll the endpoint or retry an
/// exact owner again.
#[derive(Debug, Eq, PartialEq)]
enum RetainedRecoveryBudget {
    Available,
    Consumed,
}

/// Move-only proof that the current retained generation consumed its sole
/// retry budget before touching the recovery endpoint.
#[must_use = "a consumed recovery retry must be carried through the retained-owner attempt"]
struct ConsumedRecoveryRetry {
    _private: (),
}

impl RetainedRecoveryBudget {
    const fn available() -> Self {
        Self::Available
    }

    fn begin_retry(&mut self) -> Option<ConsumedRecoveryRetry> {
        match self {
            Self::Available => {
                *self = Self::Consumed;
                Some(ConsumedRecoveryRetry { _private: () })
            }
            Self::Consumed => None,
        }
    }

    const fn after_retry(_attempt: ConsumedRecoveryRetry) -> Self {
        Self::Consumed
    }
}

enum RetainedGuardianOwner {
    PostArm(Box<RetainedPostArm>),
    StartupQuiesce(StartupQuiesceFailure),
    StartupRestore(AwaitingCoordinatorRestore),
    StartupCleanup(StartupCleanupFailure),
    SessionShutdown(Box<SessionShutdownFailure>),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackagedGuardianOwnerKind {
    PostArm,
    StartupQuiesce,
    StartupRestore,
    StartupCleanup,
    SessionShutdown,
}

#[cfg(test)]
const fn packaged_retention_reason_marker(reason: GuardianRetentionReason) -> &'static str {
    match reason {
        GuardianRetentionReason::Deadline => "guardian-retained.reason.deadline",
        GuardianRetentionReason::ProtocolInvalid => "guardian-retained.reason.protocol-invalid",
        GuardianRetentionReason::RestoreUnconfirmed => {
            "guardian-retained.reason.restore-unconfirmed"
        }
        GuardianRetentionReason::CleanupUnconfirmed => {
            "guardian-retained.reason.cleanup-unconfirmed"
        }
        GuardianRetentionReason::UnreportableChild => "guardian-retained.reason.unreportable-child",
    }
}

#[cfg(test)]
const fn packaged_retention_owner_marker(kind: PackagedGuardianOwnerKind) -> &'static str {
    match kind {
        PackagedGuardianOwnerKind::PostArm => "guardian-retained.owner.post-arm",
        PackagedGuardianOwnerKind::StartupQuiesce => "guardian-retained.owner.startup-quiesce",
        PackagedGuardianOwnerKind::StartupRestore => "guardian-retained.owner.startup-restore",
        PackagedGuardianOwnerKind::StartupCleanup => "guardian-retained.owner.startup-cleanup",
        PackagedGuardianOwnerKind::SessionShutdown => "guardian-retained.owner.session-shutdown",
    }
}

#[cfg(test)]
const fn packaged_startup_quiesce_detail_markers(
    phase: PackagedStartupQuiescePhase,
    state: Option<&'static str>,
    error: Option<&'static str>,
) -> [Option<&'static str>; 4] {
    [Some(phase.marker()), state, error, None]
}

struct RetainedPostArm {
    authorization: ProviderLaunchAuthorization,
    terminal: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
}

impl RetainedGuardianOwner {
    #[cfg(test)]
    const fn packaged_kind(&self) -> PackagedGuardianOwnerKind {
        match self {
            Self::PostArm(_) => PackagedGuardianOwnerKind::PostArm,
            Self::StartupQuiesce(_) => PackagedGuardianOwnerKind::StartupQuiesce,
            Self::StartupRestore(_) => PackagedGuardianOwnerKind::StartupRestore,
            Self::StartupCleanup(_) => PackagedGuardianOwnerKind::StartupCleanup,
            Self::SessionShutdown(_) => PackagedGuardianOwnerKind::SessionShutdown,
        }
    }

    /// Touches every concrete linear owner before it is deliberately parked.
    /// This is not diagnostic projection: it documents the exact authority
    /// that pins B, provider children, terminal recovery, and completion.
    fn pin_authority(&self) {
        match self {
            Self::PostArm(owner) => {
                let owner = owner.as_ref();
                let _ = (
                    &owner.authorization,
                    &owner.terminal,
                    &owner.recovery,
                    &owner.snapshot,
                );
            }
            Self::StartupQuiesce(owner) => {
                let _ = owner;
            }
            Self::StartupRestore(owner) => {
                let _ = owner;
            }
            Self::StartupCleanup(owner) => {
                let _ = owner;
            }
            Self::SessionShutdown(owner) => {
                let _ = owner.as_ref();
            }
        }
    }
}

/// Fail-closed production owner. Every variant contains B indirectly through
/// a concrete startup/session authority; Drop intentionally leaks it.
#[must_use = "retained guardian authority must be parked"]
pub(super) struct RetainedGuardianGeneration {
    lifecycle: Option<GuardianLifecycle<LifecycleEndpoint>>,
    owner: Option<RetainedGuardianOwner>,
    reason: GuardianRetentionReason,
    recovery_budget: RetainedRecoveryBudget,
}

impl RetainedGuardianGeneration {
    /// Projects the retained state to closed package-test marker names. The
    /// detailed session fields are themselves fixed enums; no provider output,
    /// terminal bytes, identity, path, or descriptor value is exposed.
    #[cfg(test)]
    pub(super) fn packaged_marker_names(&self) -> [Option<&'static str>; 7] {
        let owner_marker = self
            .owner
            .as_ref()
            .map_or("guardian-retained.owner.missing", |owner| {
                packaged_retention_owner_marker(owner.packaged_kind())
            });
        let detail_markers = match self.owner.as_ref() {
            Some(RetainedGuardianOwner::StartupQuiesce(failure)) => {
                let phase = failure.packaged_phase();
                let (state, error) = match phase {
                    PackagedStartupQuiescePhase::Tui => failure.packaged_tui_retention_markers(),
                    PackagedStartupQuiescePhase::AppStop => {
                        failure.packaged_app_retention_markers()
                    }
                    _ => (None, None),
                };
                packaged_startup_quiesce_detail_markers(phase, state, error)
            }
            Some(RetainedGuardianOwner::SessionShutdown(failure)) => {
                failure.packaged_marker_names().map(Some)
            }
            _ => [None, None, None, None],
        };
        [
            Some("guardian-retained"),
            Some(packaged_retention_reason_marker(self.reason)),
            Some(owner_marker),
            detail_markers[0],
            detail_markers[1],
            detail_markers[2],
            detail_markers[3],
        ]
    }

    /// Waits on the exact anonymous owner endpoint and performs at most one
    /// fresh bounded retry of the retained linear owner. A malformed request
    /// never authorizes recovery; its eventual peer EOF is independently an
    /// owner-loss trigger. Any transport ambiguity or a second retention keeps
    /// the exact authority parked rather than reconstructing it from markers.
    pub(super) fn await_recovery(mut self: Box<Self>) -> GuardianRunOutcome {
        let recoverable = self
            .owner
            .as_ref()
            .is_some_and(|owner| retained_owner_allows_recovery(self.reason, owner));
        if !retained_generation_can_attempt_recovery(&self.recovery_budget, recoverable) {
            self.publish_retained_unrecoverable_and_park();
        }
        let recovery_attempt = match self.recovery_budget.begin_retry() {
            Some(attempt) => attempt,
            None => self.publish_retained_unrecoverable_and_park(),
        };
        self.await_recovery_with_attempt(recovery_attempt)
    }

    /// The endpoint polling implementation requires the move-only proof
    /// minted by the Available-to-Consumed transition. A retained generation
    /// that already consumed its budget cannot call this method.
    fn await_recovery_with_attempt(
        mut self: Box<Self>,
        recovery_attempt: ConsumedRecoveryRetry,
    ) -> GuardianRunOutcome {
        loop {
            let deadline = match self
                .lifecycle
                .as_ref()
                .and_then(|lifecycle| lifecycle.bounds.turn_deadline().ok())
            {
                Some(deadline) => deadline,
                None => self.publish_retained_unrecoverable_and_park(),
            };
            let observation = match self
                .lifecycle
                .as_mut()
                .unwrap_or_else(|| std::process::abort())
                .poll_recovery_request(deadline)
            {
                Ok(observation) => observation,
                Err(_) => self.publish_retained_unrecoverable_and_park(),
            };
            #[cfg(test)]
            self.lifecycle
                .as_ref()
                .unwrap_or_else(|| std::process::abort())
                .record_packaged_recovery_terminal_observation(observation);
            match observation {
                RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected => continue,
                RecoveryRequestPoll::Verified
                | RecoveryRequestPoll::OwnerLost
                | RecoveryRequestPoll::ProtocolRejectedOwnerLost => break,
            }
        }

        let lifecycle = self
            .lifecycle
            .take()
            .unwrap_or_else(|| std::process::abort());
        let bounds = lifecycle.bounds;
        let owner = self.owner.take().unwrap_or_else(|| std::process::abort());
        drop(self);
        retry_retained_owner(bounds, lifecycle, owner, recovery_attempt)
    }

    /// Publishes a terminal retained outcome at most once by consuming the
    /// lifecycle and completion endpoint, then pins only the exact typed
    /// provider/terminal owner. Publication and write-half shutdown failures
    /// do not weaken the fail-closed park boundary. The owned value remains a
    /// live local in the non-returning park loop, so the typed authority stays
    /// reachable instead of being intentionally forgotten.
    fn publish_retained_unrecoverable_and_park(mut self: Box<Self>) -> ! {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.publish_retained_unrecoverable();
        }
        if let Some(owner) = self.owner.take() {
            park_retained_owner(owner);
        }
        loop {
            std::thread::park();
        }
    }

    pub(super) fn park(self: Box<Self>) -> ! {
        self.publish_retained_unrecoverable_and_park()
    }
}

/// Keeps the exact retained provider/terminal owner structurally reachable
/// for the guardian's remaining lifetime. `park` may wake spuriously, so each
/// turn touches the owner before blocking again.
fn park_retained_owner(owner: RetainedGuardianOwner) -> ! {
    owner.pin_authority();
    loop {
        std::hint::black_box(&owner);
        std::thread::park();
    }
}

const fn retained_generation_can_attempt_recovery(
    budget: &RetainedRecoveryBudget,
    owner_allows_recovery: bool,
) -> bool {
    matches!(budget, RetainedRecoveryBudget::Available) && owner_allows_recovery
}

fn retained_owner_allows_recovery(
    reason: GuardianRetentionReason,
    owner: &RetainedGuardianOwner,
) -> bool {
    if !retention_reason_allows_recovery(reason) {
        return false;
    }
    match owner {
        RetainedGuardianOwner::PostArm(_) => false,
        RetainedGuardianOwner::StartupRestore(_) => reason == GuardianRetentionReason::Deadline,
        RetainedGuardianOwner::SessionShutdown(failure)
            if failure.recovery_stage() == SessionShutdownRecoveryStage::RestorePending =>
        {
            reason == GuardianRetentionReason::Deadline
        }
        RetainedGuardianOwner::StartupQuiesce(_)
        | RetainedGuardianOwner::StartupCleanup(_)
        | RetainedGuardianOwner::SessionShutdown(_) => true,
    }
}

impl Drop for RetainedGuardianGeneration {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle.take() {
            std::mem::forget(lifecycle);
        }
        if let Some(owner) = self.owner.take() {
            owner.pin_authority();
            std::mem::forget(owner);
        }
    }
}

impl fmt::Debug for RetainedGuardianGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.lifecycle, &self.owner, &self.recovery_budget);
        formatter
            .debug_struct("RetainedGuardianGeneration")
            .field("reason", &self.reason)
            .field("retains_concrete_b_authority", &true)
            .finish()
    }
}

pub(super) enum GuardianRunOutcome {
    Terminal(GuardianExitDisposition),
    Retained(Box<RetainedGuardianGeneration>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleCondition {
    Healthy,
    Lost,
    Invalid,
}

impl LifecycleCondition {
    const fn from_error(error: GuardianLifecycleError) -> Self {
        match error {
            GuardianLifecycleError::Lost => Self::Lost,
            GuardianLifecycleError::Deadline | GuardianLifecycleError::Protocol => Self::Invalid,
        }
    }
}

const fn restore_wait_retention_reason(error: GuardianLifecycleError) -> GuardianRetentionReason {
    match error {
        GuardianLifecycleError::Deadline => GuardianRetentionReason::Deadline,
        GuardianLifecycleError::Protocol => GuardianRetentionReason::ProtocolInvalid,
        GuardianLifecycleError::Lost => GuardianRetentionReason::RestoreUnconfirmed,
    }
}

/// The budget argument is mandatory at the sole retained-generation
/// constructor. Initial shutdown paths pass `Available`; recovery paths must
/// thread the `Consumed` state through every recursive restore/cleanup edge.
fn retained(
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    owner: RetainedGuardianOwner,
    reason: GuardianRetentionReason,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    #[cfg(test)]
    let mut lifecycle = lifecycle;
    #[cfg(test)]
    if let Some(checkpoint) = retained_owner_recovery_checkpoint(&owner) {
        // Publication is observation-only. If the test peer has disappeared,
        // the exact typed owner must still enter fail-closed retention.
        let deadline = lifecycle
            .bounds
            .phase_deadline()
            .unwrap_or_else(|_| Instant::now());
        let _ = lifecycle.publish_retained_checkpoint_if_selected(checkpoint, deadline);
    }
    GuardianRunOutcome::Retained(Box::new(RetainedGuardianGeneration {
        lifecycle: Some(lifecycle),
        owner: Some(owner),
        reason,
        recovery_budget,
    }))
}

#[cfg(test)]
fn retained_owner_recovery_checkpoint(owner: &RetainedGuardianOwner) -> Option<RecoveryCheckpoint> {
    let RetainedGuardianOwner::SessionShutdown(failure) = owner else {
        return None;
    };
    Some(retained_session_recovery_checkpoint(
        failure.recovery_stage(),
    ))
}

#[cfg(test)]
const fn retained_session_recovery_checkpoint(
    stage: SessionShutdownRecoveryStage,
) -> RecoveryCheckpoint {
    match stage {
        SessionShutdownRecoveryStage::Quiescing => RecoveryCheckpoint::RetainedQuiescing,
        SessionShutdownRecoveryStage::RestorePending => RecoveryCheckpoint::RetainedRestorePending,
        SessionShutdownRecoveryStage::CleanupPending => RecoveryCheckpoint::RetainedCleanupPending,
    }
}

fn retry_retained_owner(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    owner: RetainedGuardianOwner,
    recovery_attempt: ConsumedRecoveryRetry,
) -> GuardianRunOutcome {
    let outcome = retry_retained_owner_with_budget(
        bounds,
        lifecycle,
        owner,
        RetainedRecoveryBudget::after_retry(recovery_attempt),
    );
    match outcome {
        GuardianRunOutcome::Retained(retained) => {
            retained.publish_retained_unrecoverable_and_park()
        }
        GuardianRunOutcome::Terminal(disposition) => GuardianRunOutcome::Terminal(disposition),
    }
}

fn retry_retained_owner_with_budget(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    owner: RetainedGuardianOwner,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    match owner {
        RetainedGuardianOwner::PostArm(owner) => retained(
            lifecycle,
            RetainedGuardianOwner::PostArm(owner),
            GuardianRetentionReason::UnreportableChild,
            recovery_budget,
        ),
        RetainedGuardianOwner::StartupQuiesce(failure) => {
            let retry_bounds = match bounds.startup_shutdown() {
                Ok(bounds) => bounds,
                Err(_) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupQuiesce(failure),
                        GuardianRetentionReason::Deadline,
                        recovery_budget,
                    );
                }
            };
            match failure.retry(retry_bounds) {
                Ok(awaiting) => finish_startup_restore(
                    bounds,
                    lifecycle,
                    awaiting,
                    LifecycleCondition::Healthy,
                    recovery_budget,
                ),
                Err(failure) => retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupQuiesce(failure),
                    GuardianRetentionReason::CleanupUnconfirmed,
                    recovery_budget,
                ),
            }
        }
        RetainedGuardianOwner::StartupRestore(awaiting) => finish_startup_restore(
            bounds,
            lifecycle,
            awaiting,
            LifecycleCondition::Healthy,
            recovery_budget,
        ),
        RetainedGuardianOwner::StartupCleanup(failure) => {
            let retry_bounds = match bounds.startup_shutdown() {
                Ok(bounds) => bounds,
                Err(_) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupCleanup(failure),
                        GuardianRetentionReason::Deadline,
                        recovery_budget,
                    );
                }
            };
            match failure.retry(retry_bounds) {
                Ok(report) => finalize_startup_report(bounds, lifecycle, report),
                Err(failure) => {
                    let reason = if failure.terminal_reportable() {
                        GuardianRetentionReason::CleanupUnconfirmed
                    } else {
                        GuardianRetentionReason::UnreportableChild
                    };
                    retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupCleanup(failure),
                        reason,
                        recovery_budget,
                    )
                }
            }
        }
        RetainedGuardianOwner::SessionShutdown(failure) => match failure.recovery_stage() {
            SessionShutdownRecoveryStage::Quiescing
            | SessionShutdownRecoveryStage::RestorePending => finish_session_restore(
                bounds,
                lifecycle,
                failure,
                LifecycleCondition::Healthy,
                recovery_budget,
            ),
            SessionShutdownRecoveryStage::CleanupPending => finish_session_cleanup(
                bounds,
                lifecycle,
                failure,
                LifecycleCondition::Healthy,
                recovery_budget,
            ),
        },
    }
}

/// Runs the inherited production guardian role. Pre-arm setup failures own no
/// started provider child and may return directly. Every post-arm failure is
/// routed through a concrete cleanup or retained-B owner.
pub(super) fn run_production_guardian(config: ProductionGuardianConfig<'_>) -> GuardianRunOutcome {
    run_guardian_after_bootstrap(config, GuardianBootstrapSeams::production())
}

fn run_guardian_after_bootstrap<'a>(
    config: ProductionGuardianConfig<'a>,
    seams: GuardianBootstrapSeams<'a>,
) -> GuardianRunOutcome {
    match bootstrap_guardian_core(config, seams) {
        Ok(guardian) => guardian.run(),
        Err(_) => GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure),
    }
}

#[cfg(test)]
pub(super) fn run_production_guardian_with_test_seams<'a>(
    config: ProductionGuardianConfig<'a>,
    seams: PackagedGuardianSeams<'a>,
) -> GuardianRunOutcome {
    run_guardian_after_bootstrap(config, seams.into())
}

impl ArmedProductionGuardian<'_> {
    fn run(self) -> GuardianRunOutcome {
        let Self {
            config,
            mut lifecycle,
            authorization,
            terminal,
            recovery,
            snapshot,
        } = self;
        let startup_bounds = match config.bounds.startup() {
            Ok(bounds) => bounds,
            Err(_) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::PostArm(Box::new(RetainedPostArm {
                        authorization,
                        terminal,
                        recovery,
                        snapshot,
                    })),
                    GuardianRetentionReason::Deadline,
                    RetainedRecoveryBudget::available(),
                );
            }
        };
        let initial_size = snapshot.size();
        let (started, reporter_error, checkpoint_shutdown_requested) = {
            let mut reporter = LifecycleStartupReporter::new(&mut lifecycle);
            #[cfg(test)]
            reporter.set_packaged_child_report_root(config.packaged_child_report_root);
            #[cfg(test)]
            let started = match config.fixture_compatibility_stage_parent {
                Some(stage_parent) => start_supervised_session_with_test_compatibility(
                    authorization,
                    config.codex_executable,
                    stage_parent,
                    config.runtime_parent,
                    terminal,
                    recovery,
                    snapshot,
                    initial_size,
                    startup_bounds,
                    &mut reporter,
                ),
                None => start_supervised_session(
                    authorization,
                    config.codex_executable,
                    config.runtime_parent,
                    terminal,
                    recovery,
                    snapshot,
                    initial_size,
                    startup_bounds,
                    &mut reporter,
                ),
            };
            #[cfg(not(test))]
            let started = start_supervised_session(
                authorization,
                config.codex_executable,
                config.runtime_parent,
                terminal,
                recovery,
                snapshot,
                initial_size,
                startup_bounds,
                &mut reporter,
            );
            let checkpoint_shutdown_requested = {
                #[cfg(test)]
                {
                    reporter.checkpoint_shutdown_requested
                }
                #[cfg(not(test))]
                {
                    false
                }
            };
            (started, reporter.last_error, checkpoint_shutdown_requested)
        };

        #[cfg(test)]
        if checkpoint_shutdown_requested {
            return match started {
                Ok(session) => shutdown_after_recovery_request(config.bounds, lifecycle, session),
                Err(failure) => finish_startup_failure(
                    config.bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                ),
            };
        }

        #[cfg(not(test))]
        let _ = checkpoint_shutdown_requested;

        match started {
            Ok(session) => drive_awaiting_ready(config.bounds, lifecycle, session, reporter_error),
            Err(failure) => {
                #[cfg(test)]
                record_packaged_startup_failure(config.packaged_child_report_root, &failure);
                let condition = reporter_error.map_or(LifecycleCondition::Healthy, |error| {
                    LifecycleCondition::from_error(error)
                });
                finish_startup_failure(config.bounds, lifecycle, failure, condition)
            }
        }
    }
}

#[cfg(test)]
fn record_packaged_startup_failure(report_root: Option<&Path>, failure: &SupervisedStartupFailure) {
    let Some(report_root) = report_root else {
        return;
    };
    if let SupervisedStartupError::SessionReadiness(error) = failure.error() {
        record_packaged_session_readiness_failure(report_root, error);
        return;
    }
    let marker = match failure.packaged_runtime_failure_stage() {
        Some(PackagedRuntimeFailureStage::Create) => "startup-failure.runtime-create",
        Some(PackagedRuntimeFailureStage::Layout) => "startup-failure.runtime-layout",
        None => match failure.error() {
            SupervisedStartupError::Terminal => "startup-failure.terminal",
            SupervisedStartupError::Compatibility => "startup-failure.compatibility",
            SupervisedStartupError::Runtime => "startup-failure.runtime",
            SupervisedStartupError::AppPlan => "startup-failure.app-plan",
            SupervisedStartupError::AppLaunch => "startup-failure.app-launch",
            SupervisedStartupError::AppSocket => "startup-failure.app-socket",
            SupervisedStartupError::MonitorConnect => "startup-failure.monitor-connect",
            SupervisedStartupError::MonitorStart => "startup-failure.monitor-start",
            SupervisedStartupError::RelayPlan => "startup-failure.relay-plan",
            SupervisedStartupError::RelayStart => "startup-failure.relay-start",
            SupervisedStartupError::TuiPlan => "startup-failure.tui-plan",
            SupervisedStartupError::TuiPty => "startup-failure.tui-pty",
            SupervisedStartupError::TuiLaunch => "startup-failure.tui-launch",
            SupervisedStartupError::TuiReadiness => "startup-failure.tui-readiness",
            SupervisedStartupError::Lifecycle => "startup-failure.lifecycle",
            SupervisedStartupError::SessionReadiness(_) => unreachable!(
                "session-readiness failures are recorded through the fixed subtype boundary"
            ),
            SupervisedStartupError::Deadline => "startup-failure.deadline",
        },
    };
    write_packaged_startup_failure_marker(report_root, marker);
    if let Some(marker) = failure.packaged_compatibility_failure_marker() {
        write_packaged_startup_failure_marker(report_root, marker);
    }
    if failure.packaged_compatibility_failed_before_child_start() {
        write_packaged_startup_failure_marker(report_root, PACKAGED_APP_NOT_STARTED_MARKER);
        write_packaged_startup_failure_marker(report_root, PACKAGED_TUI_NOT_STARTED_MARKER);
    }
    if let Some(classification) = failure.packaged_tui_launch_failure_classification() {
        write_packaged_startup_failure_marker(report_root, classification.state_marker());
        write_packaged_startup_failure_marker(report_root, classification.subtype_marker());
    }
    if let Some(marker) = failure.packaged_app_socket_failure_marker() {
        write_packaged_startup_failure_marker(report_root, marker);
    }
}

#[cfg(test)]
fn record_packaged_session_readiness_failure(report_root: &Path, error: SessionStartupError) {
    write_packaged_startup_failure_marker(report_root, "startup-failure.session-readiness");
    write_packaged_startup_failure_marker(
        report_root,
        packaged_session_startup_failure_marker(error),
    );
}

#[cfg(test)]
pub(super) fn write_packaged_startup_failure_marker(report_root: &Path, marker: &'static str) {
    let _ = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(report_root.join(marker))
        .and_then(|mut file| {
            file.write_all(b"classified\n")?;
            file.sync_all()
        });
}

const LIFECYCLE_SESSION_ERROR: SessionOperationError =
    SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelEof);
const RECOVERY_SESSION_ERROR: SessionOperationError = SessionOperationError::RecoveryRequested;

fn checked_turn_deadline(bounds: GuardianBounds) -> Result<Instant, GuardianLifecycleError> {
    bounds
        .turn_deadline()
        .map_err(|_| GuardianLifecycleError::Deadline)
}

enum GuardianControlTurn {
    Idle,
    Command(CoordinatorCommand),
    Recovery,
}

fn receive_bounded_command(
    bounds: GuardianBounds,
    lifecycle: &mut GuardianLifecycle<LifecycleEndpoint>,
) -> Result<GuardianControlTurn, GuardianLifecycleError> {
    match lifecycle
        .poll_recovery_request(checked_turn_deadline(bounds)?)
        .map_err(|_| GuardianLifecycleError::Protocol)?
    {
        RecoveryRequestPoll::Verified
        | RecoveryRequestPoll::OwnerLost
        | RecoveryRequestPoll::ProtocolRejectedOwnerLost => {
            lifecycle
                .commands_mut()
                .arm_recovery_command_race()
                .map_err(classify_protocol_error)?;
            return Ok(GuardianControlTurn::Recovery);
        }
        RecoveryRequestPoll::Pending | RecoveryRequestPoll::ProtocolRejected => {}
    }
    let readable_deadline = checked_turn_deadline(bounds)?;
    if !lifecycle.readable_before(readable_deadline)? {
        return Ok(GuardianControlTurn::Idle);
    }
    lifecycle
        .receive(checked_turn_deadline(bounds)?)
        .map(GuardianControlTurn::Command)
}

type ProductionSession<State> = SessionState<ProductionSessionComponents, State>;
type ProductionLivenessFailure<State> = SessionLivenessFailure<ProductionSession<State>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TurnLivenessObservation {
    Healthy,
    DirectTuiExit,
    RelayTransport,
}

/// A direct TUI can become wait-visible just before its PTY reaches EOF. Keep
/// that exact session owner and let the terminal pump decide the terminal edge;
/// all other component failures remain immediately fatal. The caller bounds
/// the drain so a descendant holding the slave PTY cannot pin B forever.
fn check_turn_liveness<State>(
    session: ProductionSession<State>,
    deadline: Instant,
) -> Result<
    (ProductionSession<State>, TurnLivenessObservation),
    Box<ProductionLivenessFailure<State>>,
> {
    match session.check_liveness(deadline) {
        Ok(session) => Ok((session, TurnLivenessObservation::Healthy)),
        Err(failure) if failure.is_direct_tui_exit() => Ok((
            (*failure).into_session(),
            TurnLivenessObservation::DirectTuiExit,
        )),
        Err(failure) => match failure.into_relay_transport_session() {
            Ok(session) => Ok((session, TurnLivenessObservation::RelayTransport)),
            Err(failure) => Err(failure),
        },
    }
}

fn tui_exit_drain_deadline(now: Instant, bounds: GuardianBounds) -> Option<Instant> {
    now.checked_add(bounds.tui_grace)
}

fn shutdown_after_lifecycle_error<State>(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    session: SessionState<ProductionSessionComponents, State>,
    error: GuardianLifecycleError,
) -> GuardianRunOutcome {
    begin_session_shutdown(
        bounds,
        lifecycle,
        session,
        SessionShutdownTrigger::Failure(LIFECYCLE_SESSION_ERROR),
        LifecycleCondition::from_error(error),
    )
}

fn shutdown_after_liveness_failure<State>(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    failure: Box<ProductionLivenessFailure<State>>,
) -> GuardianRunOutcome {
    let error = failure.error();
    begin_session_shutdown(
        bounds,
        lifecycle,
        (*failure).into_session(),
        SessionShutdownTrigger::Failure(error),
        LifecycleCondition::Healthy,
    )
}

fn terminal_exit_observation_error(
    observation: TurnLivenessObservation,
) -> Option<SessionOperationError> {
    match observation {
        TurnLivenessObservation::Healthy => None,
        TurnLivenessObservation::DirectTuiExit => {
            Some(SessionOperationError::Component(SessionComponent::Tui))
        }
        TurnLivenessObservation::RelayTransport => Some(SessionOperationError::Component(
            SessionComponent::ReadinessRelay,
        )),
    }
}

fn drive_terminal_exit_drain(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut session: DrainingSupervisedSession,
    drain_deadline: Instant,
    unresolved_error: SessionOperationError,
) -> GuardianRunOutcome {
    loop {
        let now = Instant::now();
        if now >= drain_deadline {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Failure(unresolved_error),
                LifecycleCondition::Healthy,
            );
        }
        let turn_deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline.min(drain_deadline),
            Err(error) => {
                return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
            }
        };
        let progress;
        (session, progress) = match session.pump_terminal_output_once(turn_deadline) {
            Ok(result) => result,
            Err(failure) => {
                return finish_terminal_failure(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                );
            }
        };
        if progress == TerminalPumpProgress::TuiOutputClosed {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Cause(SessionTerminationCause::NaturalTuiEof),
                LifecycleCondition::Healthy,
            );
        }
        thread::sleep(
            bounds
                .poll_interval
                .min(drain_deadline.saturating_duration_since(Instant::now())),
        );
    }
}

fn begin_terminal_exit_drain(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    session: ActiveSupervisedSession,
    observation: TurnLivenessObservation,
) -> GuardianRunOutcome {
    let unresolved_error = terminal_exit_observation_error(observation)
        .unwrap_or(SessionOperationError::Component(SessionComponent::Tui));
    let Some(drain_deadline) = tui_exit_drain_deadline(Instant::now(), bounds) else {
        return begin_session_shutdown(
            bounds,
            lifecycle,
            session,
            SessionShutdownTrigger::Failure(unresolved_error),
            LifecycleCondition::Healthy,
        );
    };
    match session.begin_terminal_exit_drain() {
        Ok(session) => {
            drive_terminal_exit_drain(bounds, lifecycle, session, drain_deadline, unresolved_error)
        }
        Err(failure) => {
            finish_terminal_failure(bounds, lifecycle, failure, LifecycleCondition::Healthy)
        }
    }
}

fn shutdown_after_recovery_request<State>(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    session: SessionState<ProductionSessionComponents, State>,
) -> GuardianRunOutcome {
    begin_session_shutdown(
        bounds,
        lifecycle,
        session,
        recovery_shutdown_trigger(),
        LifecycleCondition::Healthy,
    )
}

fn drive_awaiting_ready(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    session: AwaitingReadySupervisedSession,
    reporter_error: Option<GuardianLifecycleError>,
) -> GuardianRunOutcome {
    if let Some(error) = reporter_error {
        return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
    }
    let deadline = match checked_turn_deadline(bounds) {
        Ok(deadline) => deadline,
        Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
    };
    let ready = match session.check_before_ready(deadline) {
        Ok(ready) => ready,
        Err(failure) => {
            return shutdown_after_liveness_failure(bounds, lifecycle, failure);
        }
    };
    if let Err(error) = lifecycle.emit(
        GuardianEvent::Ready,
        bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
    ) {
        return shutdown_after_lifecycle_error(bounds, lifecycle, ready, error);
    }
    #[cfg(test)]
    match lifecycle.checkpoint_and_wait_for_recovery(
        RecoveryCheckpoint::Ready,
        bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
    ) {
        Ok(TestRecoveryCheckpointOutcome::NotSelected) => {}
        Ok(TestRecoveryCheckpointOutcome::RecoveryRequested) => {
            return shutdown_after_recovery_request(bounds, lifecycle, ready);
        }
        Ok(TestRecoveryCheckpointOutcome::BoundaryFailed) => {
            return shutdown_after_recovery_request(bounds, lifecycle, ready);
        }
        Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, ready, error),
    }
    drive_ready_for_initial_gate(bounds, lifecycle, ready)
}

fn drive_ready_for_initial_gate(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut session: ReadySupervisedSession,
) -> GuardianRunOutcome {
    loop {
        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        session = match session.check_liveness(deadline) {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        let progress;
        (session, progress) = match session.pump_terminal_output_once(deadline) {
            Ok(result) => result,
            Err(failure) => {
                return finish_terminal_failure(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                );
            }
        };
        if progress == TerminalPumpProgress::TuiOutputClosed {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Failure(SessionOperationError::Component(
                    SessionComponent::Tui,
                )),
                LifecycleCondition::Healthy,
            );
        }
        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        session = match session.check_liveness(deadline) {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };

        let command = match receive_bounded_command(bounds, &mut lifecycle) {
            Ok(GuardianControlTurn::Command(command)) => command,
            Ok(GuardianControlTurn::Idle) => continue,
            Ok(GuardianControlTurn::Recovery) => {
                return shutdown_after_recovery_request(bounds, lifecycle, session);
            }
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        match command {
            CoordinatorCommand::OpenInputGate => {
                let proof = match lifecycle
                    .commands_mut()
                    .take_verified_initial_open_gate_command()
                {
                    Ok(proof) => proof,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(
                            bounds,
                            lifecycle,
                            session,
                            classify_protocol_error(error),
                        );
                    }
                };
                let deadline = match checked_turn_deadline(bounds) {
                    Ok(deadline) => deadline,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
                    }
                };
                let active = match session.open_initial_ingress(proof, deadline) {
                    Ok(active) => active,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::InputGateOpened,
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, active, error);
                }
                return drive_active(bounds, lifecycle, active);
            }
            CoordinatorCommand::Stop => {
                return begin_session_shutdown(
                    bounds,
                    lifecycle,
                    session,
                    coordinator_stop_trigger(),
                    LifecycleCondition::Healthy,
                );
            }
            _ => {
                return shutdown_after_lifecycle_error(
                    bounds,
                    lifecycle,
                    session,
                    GuardianLifecycleError::Protocol,
                );
            }
        }
    }
}

fn drive_active(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut session: ActiveSupervisedSession,
) -> GuardianRunOutcome {
    #[cfg(test)]
    match lifecycle.checkpoint_and_wait_for_recovery(
        RecoveryCheckpoint::Active,
        bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
    ) {
        Ok(TestRecoveryCheckpointOutcome::NotSelected) => {}
        Ok(TestRecoveryCheckpointOutcome::RecoveryRequested) => {
            return shutdown_after_recovery_request(bounds, lifecycle, session);
        }
        Ok(TestRecoveryCheckpointOutcome::BoundaryFailed) => {
            return shutdown_after_recovery_request(bounds, lifecycle, session);
        }
        Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
    }
    loop {
        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        let liveness;
        (session, liveness) = match check_turn_liveness(session, deadline) {
            Ok(result) => result,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        if liveness != TurnLivenessObservation::Healthy {
            return begin_terminal_exit_drain(bounds, lifecycle, session, liveness);
        }

        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        let progress;
        (session, progress) = match session.pump_terminal_once(deadline) {
            Ok(result) => result,
            Err(failure) => {
                return finish_terminal_failure(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                );
            }
        };
        if progress == TerminalPumpProgress::TuiOutputClosed {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Cause(SessionTerminationCause::NaturalTuiEof),
                LifecycleCondition::Healthy,
            );
        }

        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        let post_pump_liveness;
        (session, post_pump_liveness) = match check_turn_liveness(session, deadline) {
            Ok(result) => result,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        if post_pump_liveness != TurnLivenessObservation::Healthy {
            return begin_terminal_exit_drain(bounds, lifecycle, session, post_pump_liveness);
        }

        let command = match receive_bounded_command(bounds, &mut lifecycle) {
            Ok(GuardianControlTurn::Command(command)) => command,
            Ok(GuardianControlTurn::Idle) => continue,
            Ok(GuardianControlTurn::Recovery) => {
                return shutdown_after_recovery_request(bounds, lifecycle, session);
            }
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        match command {
            CoordinatorCommand::Stop => {
                return begin_session_shutdown(
                    bounds,
                    lifecycle,
                    session,
                    coordinator_stop_trigger(),
                    LifecycleCondition::Healthy,
                );
            }
            CoordinatorCommand::Signal { signal } => {
                session = match session.forward_terminal_signal(
                    signal,
                    checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
                ) {
                    Ok(session) => session,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::SignalForwarded { signal },
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
                }
                let cause = match signal {
                    UnixSignal::Hup => Some(SessionTerminationCause::ForwardedHup),
                    UnixSignal::Term => Some(SessionTerminationCause::ForwardedTerm),
                    UnixSignal::Int | UnixSignal::Quit => None,
                };
                if let Some(cause) = cause {
                    return begin_session_shutdown(
                        bounds,
                        lifecycle,
                        session,
                        SessionShutdownTrigger::Cause(cause),
                        LifecycleCondition::Healthy,
                    );
                }
            }
            CoordinatorCommand::Resize { rows, cols } => {
                let proof = match lifecycle.commands_mut().take_verified_resize_command() {
                    Ok(proof) => proof,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(
                            bounds,
                            lifecycle,
                            session,
                            classify_protocol_error(error),
                        );
                    }
                };
                session = match session.resize_terminal(
                    proof,
                    checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
                ) {
                    Ok(session) => session,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::ResizeApplied { rows, cols },
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
                }
            }
            CoordinatorCommand::Suspend => {
                let proof = match lifecycle.commands_mut().take_verified_suspend_command() {
                    Ok(proof) => proof,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(
                            bounds,
                            lifecycle,
                            session,
                            classify_protocol_error(error),
                        );
                    }
                };
                let graceful = Instant::now().checked_add(bounds.tui_grace);
                let forced = graceful.and_then(|deadline| deadline.checked_add(bounds.tui_forced));
                let (Some(graceful), Some(forced)) = (graceful, forced) else {
                    return begin_session_shutdown(
                        bounds,
                        lifecycle,
                        session,
                        SessionShutdownTrigger::Failure(SessionOperationError::Deadline),
                        LifecycleCondition::Healthy,
                    );
                };
                let suspended = match session.suspend_terminal(proof, graceful, forced) {
                    Ok(suspended) => suspended,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::Suspended,
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, suspended, error);
                }
                return drive_suspended(bounds, lifecycle, suspended);
            }
            _ => {
                return shutdown_after_lifecycle_error(
                    bounds,
                    lifecycle,
                    session,
                    GuardianLifecycleError::Protocol,
                );
            }
        }
    }
}

fn drive_suspended(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut session: SuspendedSupervisedSession,
) -> GuardianRunOutcome {
    #[cfg(test)]
    match lifecycle.checkpoint_and_wait_for_recovery(
        RecoveryCheckpoint::Suspended,
        bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
    ) {
        Ok(TestRecoveryCheckpointOutcome::NotSelected) => {}
        Ok(TestRecoveryCheckpointOutcome::RecoveryRequested) => {
            return shutdown_after_recovery_request(bounds, lifecycle, session);
        }
        Ok(TestRecoveryCheckpointOutcome::BoundaryFailed) => {
            return shutdown_after_recovery_request(bounds, lifecycle, session);
        }
        Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
    }
    loop {
        let deadline = match checked_turn_deadline(bounds) {
            Ok(deadline) => deadline,
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        session = match session.check_liveness(deadline) {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        let progress;
        (session, progress) = match session.pump_terminal_output_once(
            checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
        ) {
            Ok(result) => result,
            Err(failure) => {
                return finish_terminal_failure(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                );
            }
        };
        if progress == TerminalPumpProgress::TuiOutputClosed {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Failure(SessionOperationError::Component(
                    SessionComponent::Tui,
                )),
                LifecycleCondition::Healthy,
            );
        }
        session = match session
            .check_liveness(checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()))
        {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };

        let command = match receive_bounded_command(bounds, &mut lifecycle) {
            Ok(GuardianControlTurn::Command(command)) => command,
            Ok(GuardianControlTurn::Idle) => continue,
            Ok(GuardianControlTurn::Recovery) => {
                return shutdown_after_recovery_request(bounds, lifecycle, session);
            }
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        match command {
            CoordinatorCommand::Stop => {
                return begin_session_shutdown(
                    bounds,
                    lifecycle,
                    session,
                    coordinator_stop_trigger(),
                    LifecycleCondition::Healthy,
                );
            }
            CoordinatorCommand::Signal { signal } => {
                session = match session.forward_terminal_signal(
                    signal,
                    checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
                ) {
                    Ok(session) => session,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::SignalForwarded { signal },
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, session, error);
                }
                let cause = match signal {
                    UnixSignal::Hup => Some(SessionTerminationCause::ForwardedHup),
                    UnixSignal::Term => Some(SessionTerminationCause::ForwardedTerm),
                    UnixSignal::Int | UnixSignal::Quit => None,
                };
                if let Some(cause) = cause {
                    return begin_session_shutdown(
                        bounds,
                        lifecycle,
                        session,
                        SessionShutdownTrigger::Cause(cause),
                        LifecycleCondition::Healthy,
                    );
                }
            }
            CoordinatorCommand::Resume { rows, cols } => {
                let proof = match lifecycle.commands_mut().take_verified_resume_command() {
                    Ok(proof) => proof,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(
                            bounds,
                            lifecycle,
                            session,
                            classify_protocol_error(error),
                        );
                    }
                };
                let resumed = match session.resume_terminal(
                    proof,
                    checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
                ) {
                    Ok(resumed) => resumed,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::Resumed { rows, cols },
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, resumed, error);
                }
                return drive_resumed_gate(bounds, lifecycle, resumed);
            }
            _ => {
                return shutdown_after_lifecycle_error(
                    bounds,
                    lifecycle,
                    session,
                    GuardianLifecycleError::Protocol,
                );
            }
        }
    }
}

fn drive_resumed_gate(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut session: ResumedAwaitingGateSupervisedSession,
) -> GuardianRunOutcome {
    loop {
        session = match session
            .check_liveness(checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()))
        {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        let progress;
        (session, progress) = match session.pump_terminal_output_once(
            checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
        ) {
            Ok(result) => result,
            Err(failure) => {
                return finish_terminal_failure(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Healthy,
                );
            }
        };
        if progress == TerminalPumpProgress::TuiOutputClosed {
            return begin_session_shutdown(
                bounds,
                lifecycle,
                session,
                SessionShutdownTrigger::Failure(SessionOperationError::Component(
                    SessionComponent::Tui,
                )),
                LifecycleCondition::Healthy,
            );
        }
        session = match session
            .check_liveness(checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()))
        {
            Ok(session) => session,
            Err(failure) => return shutdown_after_liveness_failure(bounds, lifecycle, failure),
        };
        let command = match receive_bounded_command(bounds, &mut lifecycle) {
            Ok(GuardianControlTurn::Command(command)) => command,
            Ok(GuardianControlTurn::Idle) => continue,
            Ok(GuardianControlTurn::Recovery) => {
                return shutdown_after_recovery_request(bounds, lifecycle, session);
            }
            Err(error) => return shutdown_after_lifecycle_error(bounds, lifecycle, session, error),
        };
        match command {
            CoordinatorCommand::OpenInputGate => {
                let proof = match lifecycle
                    .commands_mut()
                    .take_verified_resume_open_gate_command()
                {
                    Ok(proof) => proof,
                    Err(error) => {
                        return shutdown_after_lifecycle_error(
                            bounds,
                            lifecycle,
                            session,
                            classify_protocol_error(error),
                        );
                    }
                };
                let active = match session.open_resumed_ingress(
                    proof,
                    checked_turn_deadline(bounds).unwrap_or_else(|_| Instant::now()),
                ) {
                    Ok(active) => active,
                    Err(failure) => {
                        return finish_terminal_failure(
                            bounds,
                            lifecycle,
                            failure,
                            LifecycleCondition::Healthy,
                        );
                    }
                };
                if let Err(error) = lifecycle.emit(
                    GuardianEvent::InputGateOpened,
                    bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
                ) {
                    return shutdown_after_lifecycle_error(bounds, lifecycle, active, error);
                }
                return drive_active(bounds, lifecycle, active);
            }
            CoordinatorCommand::Stop => {
                return begin_session_shutdown(
                    bounds,
                    lifecycle,
                    session,
                    coordinator_stop_trigger(),
                    LifecycleCondition::Healthy,
                );
            }
            _ => {
                return shutdown_after_lifecycle_error(
                    bounds,
                    lifecycle,
                    session,
                    GuardianLifecycleError::Protocol,
                );
            }
        }
    }
}

fn startup_failure_event(error: SupervisedStartupError) -> (Phase, FailureCode) {
    use SupervisedStartupError as Error;
    match error {
        Error::Terminal => (Phase::Terminal, FailureCode::Terminal),
        Error::Compatibility | Error::AppPlan | Error::RelayPlan | Error::TuiPlan => {
            (Phase::Runtime, FailureCode::Internal)
        }
        Error::Runtime => (Phase::Runtime, FailureCode::Internal),
        Error::AppLaunch | Error::AppSocket => (Phase::AppServer, FailureCode::Spawn),
        Error::MonitorConnect | Error::MonitorStart => (Phase::Worker, FailureCode::Worker),
        Error::RelayStart => (Phase::Readiness, FailureCode::Internal),
        Error::TuiPty | Error::TuiLaunch => (Phase::Tui, FailureCode::Spawn),
        Error::TuiReadiness => (Phase::Readiness, FailureCode::EarlyExit),
        Error::Lifecycle => (Phase::Protocol, FailureCode::InvalidControl),
        Error::SessionReadiness(_) => (Phase::Readiness, FailureCode::EarlyExit),
        Error::Deadline => (Phase::Readiness, FailureCode::Timeout),
    }
}

fn finish_startup_failure(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    failure: SupervisedStartupFailure,
    mut condition: LifecycleCondition,
) -> GuardianRunOutcome {
    let recovery_budget = RetainedRecoveryBudget::available();
    if condition == LifecycleCondition::Healthy {
        let (phase, code) = startup_failure_event(failure.error());
        if let Err(error) = lifecycle.emit_failure(
            phase,
            code,
            bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
        ) {
            condition = LifecycleCondition::from_error(error);
        }
    }

    let shutdown_bounds = match bounds.startup_shutdown() {
        Ok(bounds) => bounds,
        Err(_) => {
            return match failure.quiesce(overflow_startup_shutdown_bounds()) {
                Ok(awaiting) => retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupRestore(awaiting),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                ),
                Err(failure) => retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupQuiesce(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                ),
            };
        }
    };
    let awaiting = match failure.quiesce(shutdown_bounds) {
        Ok(awaiting) => awaiting,
        Err(failure) => {
            let retry_bounds = match bounds.startup_shutdown() {
                Ok(bounds) => bounds,
                Err(_) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupQuiesce(failure),
                        GuardianRetentionReason::Deadline,
                        recovery_budget,
                    );
                }
            };
            match failure.retry(retry_bounds) {
                Ok(awaiting) => awaiting,
                Err(failure) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupQuiesce(failure),
                        GuardianRetentionReason::CleanupUnconfirmed,
                        recovery_budget,
                    );
                }
            }
        }
    };
    finish_startup_restore(bounds, lifecycle, awaiting, condition, recovery_budget)
}

// Used only to convert an impossible post-arm Instant overflow into a linear
// retained owner without dropping B. Every deadline is already expired.
fn overflow_startup_shutdown_bounds() -> StartupShutdownBounds {
    StartupShutdownBounds {
        containment_timeout: Duration::MAX,
        session: SessionShutdownBounds {
            tui_grace: Duration::MAX,
            tui_forced: Duration::MAX,
            relay_timeout: Duration::MAX,
            monitor_timeout: Duration::MAX,
            app_grace: Duration::MAX,
            app_forced: Duration::MAX,
            app_cleanup_timeout: Duration::MAX,
            build_cleanup_timeout: Duration::MAX,
        },
    }
}

fn finish_startup_restore(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    awaiting: AwaitingCoordinatorRestore,
    condition: LifecycleCondition,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    if condition == LifecycleCondition::Invalid {
        return retained(
            lifecycle,
            RetainedGuardianOwner::StartupRestore(awaiting),
            GuardianRetentionReason::ProtocolInvalid,
            recovery_budget,
        );
    }

    let post_restore = if condition == LifecycleCondition::Lost {
        match awaiting.restore_after_lifecycle_loss() {
            Ok(post_restore) => post_restore,
            Err(awaiting) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupRestore(*awaiting),
                    GuardianRetentionReason::RestoreUnconfirmed,
                    recovery_budget,
                );
            }
        }
    } else {
        if let Err(error) = lifecycle.emit(
            GuardianEvent::TerminalQuiesced,
            bounds.phase_deadline().unwrap_or_else(|_| Instant::now()),
        ) {
            return match LifecycleCondition::from_error(error) {
                LifecycleCondition::Lost => finish_startup_restore(
                    bounds,
                    lifecycle,
                    awaiting,
                    LifecycleCondition::Lost,
                    recovery_budget,
                ),
                LifecycleCondition::Healthy | LifecycleCondition::Invalid => retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupRestore(awaiting),
                    GuardianRetentionReason::ProtocolInvalid,
                    recovery_budget,
                ),
            };
        }
        let proof = loop {
            let deadline = match bounds.phase_deadline() {
                Ok(deadline) => deadline,
                Err(_) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupRestore(awaiting),
                        GuardianRetentionReason::Deadline,
                        recovery_budget,
                    );
                }
            };
            match lifecycle.receive(deadline) {
                Ok(CoordinatorCommand::TerminalRestored) => {
                    match lifecycle
                        .commands_mut()
                        .take_verified_terminal_restored_command()
                    {
                        Ok(proof) => break proof,
                        Err(_) => {
                            return retained(
                                lifecycle,
                                RetainedGuardianOwner::StartupRestore(awaiting),
                                GuardianRetentionReason::ProtocolInvalid,
                                recovery_budget,
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(GuardianLifecycleError::Lost) => {
                    return finish_startup_restore(
                        bounds,
                        lifecycle,
                        awaiting,
                        LifecycleCondition::Lost,
                        recovery_budget,
                    );
                }
                Err(
                    error @ (GuardianLifecycleError::Deadline | GuardianLifecycleError::Protocol),
                ) => {
                    return retained(
                        lifecycle,
                        RetainedGuardianOwner::StartupRestore(awaiting),
                        restore_wait_retention_reason(error),
                        recovery_budget,
                    );
                }
            }
        };
        match awaiting.acknowledge_terminal_restored(proof) {
            Ok(post_restore) => post_restore,
            Err((awaiting, _proof)) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupRestore(awaiting),
                    GuardianRetentionReason::RestoreUnconfirmed,
                    recovery_budget,
                );
            }
        }
    };

    finish_startup_cleanup(bounds, lifecycle, post_restore, condition, recovery_budget)
}

fn finish_startup_cleanup(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    cleanup: PostRestoreStartupCleanup,
    condition: LifecycleCondition,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    let cleanup_bounds = match bounds.startup_shutdown() {
        Ok(bounds) => bounds,
        Err(_) => {
            return match cleanup.finish(overflow_startup_shutdown_bounds()) {
                Ok(report) => {
                    finalize_fallback_completion(lifecycle, report.into_lifecycle_projection())
                }
                Err(failure) => retained(
                    lifecycle,
                    RetainedGuardianOwner::StartupCleanup(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                ),
            };
        }
    };
    match cleanup.finish(cleanup_bounds) {
        Ok(report) if condition == LifecycleCondition::Healthy => {
            finalize_startup_report(bounds, lifecycle, report)
        }
        Ok(report) => finalize_fallback_completion(lifecycle, report.into_lifecycle_projection()),
        Err(failure) => {
            let reason = if failure.terminal_reportable() {
                GuardianRetentionReason::CleanupUnconfirmed
            } else {
                GuardianRetentionReason::UnreportableChild
            };
            retained(
                lifecycle,
                RetainedGuardianOwner::StartupCleanup(failure),
                reason,
                recovery_budget,
            )
        }
    }
}

fn finalize_startup_report(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    report: StartupCleanupReport,
) -> GuardianRunOutcome {
    finalize_projection(bounds, lifecycle, report.into_lifecycle_projection())
}

fn finalize_projection(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    projection: SessionLifecycleProjection,
) -> GuardianRunOutcome {
    let deadline = bounds.phase_deadline().unwrap_or_else(|_| Instant::now());
    if lifecycle
        .emit(GuardianEvent::TerminalRecoveryDisarmed, deadline)
        .is_err()
    {
        return GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure);
    }
    if projection.worker() != WorkerJoinStatus::JoinedClean
        && !lifecycle.failure_announced
        && lifecycle
            .emit_failure(Phase::Worker, FailureCode::Worker, deadline)
            .is_err()
    {
        return GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure);
    }
    let event = GuardianEvent::ChildrenReaped {
        app: projection.app(),
        tui: projection.tui(),
        worker: projection.worker(),
        cleanup: CleanupStatus::Complete,
        session: projection.session(),
        guardian_exit: projection.guardian_exit(),
    };
    if lifecycle.emit(event, deadline).is_err() {
        return GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure);
    }
    let disposition = match lifecycle.take_exit_disposition() {
        Ok(disposition) => disposition,
        Err(_) => return GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure),
    };
    let proof = projection.into_provider_release();
    if lifecycle.publish_anchor_completion(proof).is_err() {
        return GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure);
    }
    GuardianRunOutcome::Terminal(disposition)
}

/// Coordinator loss forbids a successful shell disposition, but a complete
/// fallback restore/disarm/cleanup still releases the persistent anchor.
fn finalize_fallback_completion(
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    projection: SessionLifecycleProjection,
) -> GuardianRunOutcome {
    let proof = projection.into_provider_release();
    let _ = lifecycle.publish_anchor_completion(proof);
    GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure)
}

#[derive(Clone, Copy)]
enum SessionShutdownTrigger {
    Cause(SessionTerminationCause),
    Failure(SessionOperationError),
}

const fn recovery_shutdown_trigger() -> SessionShutdownTrigger {
    SessionShutdownTrigger::Failure(RECOVERY_SESSION_ERROR)
}

const fn coordinator_stop_trigger() -> SessionShutdownTrigger {
    SessionShutdownTrigger::Cause(SessionTerminationCause::CoordinatorStop)
}

fn operation_failure_event(error: SessionOperationError) -> (Phase, FailureCode) {
    match error {
        SessionOperationError::RecoveryRequested => (Phase::Protocol, FailureCode::Internal),
        SessionOperationError::Deadline => (Phase::Pump, FailureCode::Timeout),
        SessionOperationError::Monitor(_) | SessionOperationError::Component(_) => {
            (Phase::Readiness, FailureCode::EarlyExit)
        }
        SessionOperationError::TerminalPump(_) => (Phase::Pump, FailureCode::Pump),
    }
}

fn begin_session_shutdown<State>(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    session: SessionState<ProductionSessionComponents, State>,
    trigger: SessionShutdownTrigger,
    mut condition: LifecycleCondition,
) -> GuardianRunOutcome {
    let recovery_budget = RetainedRecoveryBudget::available();
    if let SessionShutdownTrigger::Failure(error) = trigger {
        if condition == LifecycleCondition::Healthy {
            let (phase, code) = operation_failure_event(error);
            let deadline = bounds.phase_deadline().unwrap_or_else(|_| Instant::now());
            if let Err(error) = lifecycle.emit_failure(phase, code, deadline) {
                condition = LifecycleCondition::from_error(error);
            }
        }
    }

    #[cfg(test)]
    if lifecycle.recovery_checkpoint_is_selected(RecoveryCheckpoint::RetainedQuiescing) {
        let trigger = match trigger {
            SessionShutdownTrigger::Cause(cause) => SessionShutdownTestTrigger::Cause(cause),
            SessionShutdownTrigger::Failure(error) => SessionShutdownTestTrigger::Failure(error),
        };
        let failure = session.retain_before_shutdown_for_test(trigger);
        return retained(
            lifecycle,
            RetainedGuardianOwner::SessionShutdown(failure),
            GuardianRetentionReason::Deadline,
            recovery_budget,
        );
    }

    let shutdown_bounds = match bounds.session_shutdown() {
        Ok(bounds) => bounds,
        Err(_) => {
            // Preserve the exact state by driving with already-expired bounds;
            // an unexpected completion has no remaining armed recovery owner.
            let result = match trigger {
                SessionShutdownTrigger::Cause(cause) => {
                    session.shutdown_with_cause(cause, overflow_startup_shutdown_bounds().session)
                }
                SessionShutdownTrigger::Failure(error) => session
                    .shutdown_after_failure(error, overflow_startup_shutdown_bounds().session),
            };
            return match result {
                Ok(_report) => {
                    GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure)
                }
                Err(failure) => retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                ),
            };
        }
    };
    let shutdown = match trigger {
        SessionShutdownTrigger::Cause(cause) => session.shutdown_with_cause(cause, shutdown_bounds),
        SessionShutdownTrigger::Failure(error) => {
            session.shutdown_after_failure(error, shutdown_bounds)
        }
    };
    match shutdown {
        Ok(_report) => {
            // An armed generation cannot complete before the coordinator
            // restoration proof or the explicit lifecycle-loss fallback.
            std::process::abort()
        }
        Err(failure) => {
            finish_session_restore(bounds, lifecycle, failure, condition, recovery_budget)
        }
    }
}

fn finish_terminal_failure(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    failure: Box<SessionTerminalFailure>,
    mut condition: LifecycleCondition,
) -> GuardianRunOutcome {
    let recovery_budget = RetainedRecoveryBudget::available();
    if condition == LifecycleCondition::Healthy {
        let (phase, code) = operation_failure_event(failure.error());
        let deadline = bounds.phase_deadline().unwrap_or_else(|_| Instant::now());
        if let Err(error) = lifecycle.emit_failure(phase, code, deadline) {
            condition = LifecycleCondition::from_error(error);
        }
    }
    let shutdown_bounds = match bounds.session_shutdown() {
        Ok(bounds) => bounds,
        Err(_) => overflow_startup_shutdown_bounds().session,
    };
    match failure.shutdown(shutdown_bounds) {
        Ok(_report) => std::process::abort(),
        Err(failure) => {
            finish_session_restore(bounds, lifecycle, failure, condition, recovery_budget)
        }
    }
}

fn finish_session_restore(
    bounds: GuardianBounds,
    mut lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    mut failure: Box<SessionShutdownFailure>,
    condition: LifecycleCondition,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    if !failure.awaiting_terminal_restore() {
        let retry_bounds = match bounds.session_shutdown() {
            Ok(bounds) => bounds,
            Err(_) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                );
            }
        };
        failure = match failure.retry(retry_bounds) {
            Ok(_report) => std::process::abort(),
            Err(failure) => failure,
        };
        if !failure.awaiting_terminal_restore() {
            return retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::CleanupUnconfirmed,
                recovery_budget,
            );
        }
    }

    #[cfg(test)]
    if lifecycle.recovery_checkpoint_is_selected(RecoveryCheckpoint::RetainedRestorePending) {
        return retained(
            lifecycle,
            RetainedGuardianOwner::SessionShutdown(failure),
            GuardianRetentionReason::Deadline,
            recovery_budget,
        );
    }

    if condition == LifecycleCondition::Invalid {
        return retained(
            lifecycle,
            RetainedGuardianOwner::SessionShutdown(failure),
            GuardianRetentionReason::ProtocolInvalid,
            recovery_budget,
        );
    }

    if condition == LifecycleCondition::Lost {
        if failure.restore_after_lifecycle_loss().is_err() {
            return retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::RestoreUnconfirmed,
                recovery_budget,
            );
        }
        return finish_session_cleanup(bounds, lifecycle, failure, condition, recovery_budget);
    }

    let deadline = match bounds.phase_deadline() {
        Ok(deadline) => deadline,
        Err(_) => {
            return retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::Deadline,
                recovery_budget,
            );
        }
    };
    if let Err(error) = lifecycle.emit(GuardianEvent::TerminalQuiesced, deadline) {
        return match LifecycleCondition::from_error(error) {
            LifecycleCondition::Lost => finish_session_restore(
                bounds,
                lifecycle,
                failure,
                LifecycleCondition::Lost,
                recovery_budget,
            ),
            LifecycleCondition::Healthy | LifecycleCondition::Invalid => retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::ProtocolInvalid,
                recovery_budget,
            ),
        };
    }

    let proof = loop {
        let deadline = match bounds.phase_deadline() {
            Ok(deadline) => deadline,
            Err(_) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                );
            }
        };
        match lifecycle.receive(deadline) {
            Ok(CoordinatorCommand::TerminalRestored) => {
                match lifecycle
                    .commands_mut()
                    .take_verified_terminal_restored_command()
                {
                    Ok(proof) => break proof,
                    Err(_) => {
                        return retained(
                            lifecycle,
                            RetainedGuardianOwner::SessionShutdown(failure),
                            GuardianRetentionReason::ProtocolInvalid,
                            recovery_budget,
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(GuardianLifecycleError::Lost) => {
                return finish_session_restore(
                    bounds,
                    lifecycle,
                    failure,
                    LifecycleCondition::Lost,
                    recovery_budget,
                );
            }
            Err(error @ (GuardianLifecycleError::Deadline | GuardianLifecycleError::Protocol)) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    restore_wait_retention_reason(error),
                    recovery_budget,
                );
            }
        }
    };
    failure = match failure.acknowledge_terminal_restored(proof) {
        Ok(failure) => failure,
        Err((failure, _proof)) => {
            return retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::RestoreUnconfirmed,
                recovery_budget,
            );
        }
    };
    #[cfg(test)]
    if lifecycle.recovery_checkpoint_is_selected(RecoveryCheckpoint::RetainedCleanupPending) {
        let cleanup_bounds = match bounds.session_shutdown() {
            Ok(bounds) => bounds,
            Err(_) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    GuardianRetentionReason::Deadline,
                    recovery_budget,
                );
            }
        };
        failure = match failure.advance_acknowledged_terminal_restore_for_test(cleanup_bounds) {
            Ok(failure) => failure,
            Err(failure) => {
                return retained(
                    lifecycle,
                    RetainedGuardianOwner::SessionShutdown(failure),
                    GuardianRetentionReason::ProtocolInvalid,
                    recovery_budget,
                );
            }
        };
        return retained(
            lifecycle,
            RetainedGuardianOwner::SessionShutdown(failure),
            GuardianRetentionReason::Deadline,
            recovery_budget,
        );
    }
    finish_session_cleanup(bounds, lifecycle, failure, condition, recovery_budget)
}

fn finish_session_cleanup(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    failure: Box<SessionShutdownFailure>,
    condition: LifecycleCondition,
    recovery_budget: RetainedRecoveryBudget,
) -> GuardianRunOutcome {
    let cleanup_bounds = match bounds.session_shutdown() {
        Ok(bounds) => bounds,
        Err(_) => {
            return retained(
                lifecycle,
                RetainedGuardianOwner::SessionShutdown(failure),
                GuardianRetentionReason::Deadline,
                recovery_budget,
            );
        }
    };
    match failure.retry(cleanup_bounds) {
        Ok(report) if condition == LifecycleCondition::Healthy => {
            finalize_session_report(bounds, lifecycle, report)
        }
        Ok(report) => finalize_fallback_completion(lifecycle, report.into_lifecycle_projection()),
        Err(failure) => retained(
            lifecycle,
            RetainedGuardianOwner::SessionShutdown(failure),
            GuardianRetentionReason::CleanupUnconfirmed,
            recovery_budget,
        ),
    }
}

fn finalize_session_report(
    bounds: GuardianBounds,
    lifecycle: GuardianLifecycle<LifecycleEndpoint>,
    report: SessionShutdownReport,
) -> GuardianRunOutcome {
    finalize_projection(bounds, lifecycle, report.into_lifecycle_projection())
}

impl GuardianRunOutcome {
    pub(super) fn apply(self) -> ExitCode {
        match self {
            Self::Terminal(disposition) => apply_terminal_disposition(disposition),
            Self::Retained(retained) => match retained.await_recovery() {
                Self::Terminal(disposition) => apply_terminal_disposition(disposition),
                Self::Retained(retained) => retained.park(),
            },
        }
    }
}

fn apply_terminal_disposition(disposition: GuardianExitDisposition) -> ExitCode {
    match disposition {
        GuardianExitDisposition::Code(code) => ExitCode::from(code),
        GuardianExitDisposition::InternalFailure => ExitCode::from(1),
        GuardianExitDisposition::Signal(signal) => {
            let _ = signal_hook::low_level::emulate_default_handler(i32::from(signal));
            // A successfully emulated terminating default action must not
            // return. If it does (or emulation failed), fail closed instead
            // of inventing a shell exit convention.
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GuardianBounds, GuardianControlTurn, GuardianLifecycle, GuardianLifecycleError,
        GuardianRetentionReason, GuardianRunOutcome, GuardianSetupError, PackagedGuardianOwnerKind,
        RetainedRecoveryBudget, SessionShutdownTrigger, TestRecoveryCheckpointOutcome,
        checkpoint_arms_recovery_command_race, coordinator_stop_trigger, finalize_projection,
        packaged_guardian_checkpoint_boundary_failure_marker,
        packaged_guardian_checkpoint_request_failure_marker, packaged_retention_owner_marker,
        packaged_retention_reason_marker, packaged_startup_quiesce_detail_markers,
        receive_bounded_command, record_packaged_session_readiness_failure,
        recovery_shutdown_trigger, restore_wait_retention_reason,
        retained_generation_can_attempt_recovery, retained_session_recovery_checkpoint,
        retention_reason_allows_recovery, tui_exit_drain_deadline,
    };
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::super::channel::{LifecycleEndpoint, LifecyclePair};
    use super::super::entry::{
        AnchorCompletion, CompletionError, CompletionPair, RecoveryCheckpoint,
    };
    use super::super::protocol::SessionTerminationCause;
    use super::super::protocol::{
        ChildRole, CoordinatorCommand, FailureCode, GuardianEvent, GuardianExitDisposition, Phase,
        TerminalSnapshotFingerprint, UnixSignal, WorkerJoinStatus, send_coordinator_command,
    };
    use super::super::session::{
        PACKAGED_SESSION_STARTUP_FAILURE_MARKERS, SessionLifecycleProjection,
        SessionOperationError, SessionShutdownRecoveryStage, SessionStartupError,
        TerminalPumpFailure,
    };
    use super::super::startup::{
        PackagedStartupQuiescePhase, provider_never_started_for_completion_test,
    };
    use crate::providers::codex::monitor::SessionMonitorError;

    type QueuedCheckpointLifecycle = (
        AnchorCompletion,
        LifecycleEndpoint,
        GuardianLifecycle<LifecycleEndpoint>,
        CoordinatorCommand,
    );

    struct StartupFailureReportRoot(PathBuf);

    impl StartupFailureReportRoot {
        fn new() -> std::io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "calcifer-session-startup-failure-test-{}",
                uuid::Uuid::new_v4()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for StartupFailureReportRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn packaged_session_readiness_failure_writes_generic_and_one_fixed_subtype()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = StartupFailureReportRoot::new()?;
        let errors = [
            SessionStartupError::Monitor(SessionMonitorError::InvalidArgument),
            SessionStartupError::Monitor(SessionMonitorError::Handshake),
            SessionStartupError::Monitor(SessionMonitorError::Protocol),
            SessionStartupError::Monitor(SessionMonitorError::Authentication),
            SessionStartupError::Monitor(SessionMonitorError::Provider),
            SessionStartupError::Monitor(SessionMonitorError::Unsupported),
            SessionStartupError::Monitor(SessionMonitorError::Timeout),
            SessionStartupError::Monitor(SessionMonitorError::Transport),
            SessionStartupError::Monitor(SessionMonitorError::Worker),
            SessionStartupError::Monitor(SessionMonitorError::AppServer),
            SessionStartupError::ReadinessRelay,
            SessionStartupError::Tui,
            SessionStartupError::TerminalPump(TerminalPumpFailure::Deadline),
            SessionStartupError::TerminalPump(TerminalPumpFailure::InvalidState),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TuiOutputEof),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelEof),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TuiRead),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TuiWrite),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelRead),
            SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelWrite),
            SessionStartupError::TerminalPump(TerminalPumpFailure::Signal),
            SessionStartupError::TerminalPump(TerminalPumpFailure::Resize),
            SessionStartupError::TerminalPump(TerminalPumpFailure::Suspend),
            SessionStartupError::TerminalPump(TerminalPumpFailure::Resume),
            SessionStartupError::Deadline,
        ];

        for (index, (error, subtype)) in errors
            .into_iter()
            .zip(PACKAGED_SESSION_STARTUP_FAILURE_MARKERS.iter().copied())
            .enumerate()
        {
            let report = scratch.path().join(index.to_string());
            fs::DirBuilder::new().mode(0o700).create(&report)?;
            record_packaged_session_readiness_failure(&report, error);

            let mut names = fs::read_dir(&report)?
                .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
                .collect::<Result<Vec<_>, _>>()?;
            names.sort_unstable();
            let mut expected = vec!["startup-failure.session-readiness", subtype];
            expected.sort_unstable();
            assert_eq!(names, expected);

            for marker in expected {
                let path = report.join(marker);
                assert_eq!(fs::read(&path)?, b"classified\n");
                assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            }
        }
        Ok(())
    }

    #[test]
    fn packaged_retention_diagnostics_are_closed_fixed_markers() {
        assert_eq!(
            [
                GuardianRetentionReason::Deadline,
                GuardianRetentionReason::ProtocolInvalid,
                GuardianRetentionReason::RestoreUnconfirmed,
                GuardianRetentionReason::CleanupUnconfirmed,
                GuardianRetentionReason::UnreportableChild,
            ]
            .map(packaged_retention_reason_marker),
            [
                "guardian-retained.reason.deadline",
                "guardian-retained.reason.protocol-invalid",
                "guardian-retained.reason.restore-unconfirmed",
                "guardian-retained.reason.cleanup-unconfirmed",
                "guardian-retained.reason.unreportable-child",
            ]
        );
        assert_eq!(
            [
                PackagedGuardianOwnerKind::PostArm,
                PackagedGuardianOwnerKind::StartupQuiesce,
                PackagedGuardianOwnerKind::StartupRestore,
                PackagedGuardianOwnerKind::StartupCleanup,
                PackagedGuardianOwnerKind::SessionShutdown,
            ]
            .map(packaged_retention_owner_marker),
            [
                "guardian-retained.owner.post-arm",
                "guardian-retained.owner.startup-quiesce",
                "guardian-retained.owner.startup-restore",
                "guardian-retained.owner.startup-cleanup",
                "guardian-retained.owner.session-shutdown",
            ]
        );
    }

    #[test]
    fn packaged_startup_quiesce_phase_occupies_only_one_closed_detail_slot() {
        for phase in [
            PackagedStartupQuiescePhase::Tui,
            PackagedStartupQuiescePhase::Relay,
            PackagedStartupQuiescePhase::Monitor,
            PackagedStartupQuiescePhase::AppStop,
            PackagedStartupQuiescePhase::TerminalQuiesce,
            PackagedStartupQuiescePhase::AwaitingCoordinatorRestore,
            PackagedStartupQuiescePhase::RecoveryDisarm,
            PackagedStartupQuiescePhase::RuntimeCleanup,
            PackagedStartupQuiescePhase::BuildCleanup,
            PackagedStartupQuiescePhase::Complete,
            PackagedStartupQuiescePhase::SessionQuiescing,
            PackagedStartupQuiescePhase::SessionRestorePending,
            PackagedStartupQuiescePhase::SessionCleanupPending,
        ] {
            assert_eq!(
                packaged_startup_quiesce_detail_markers(phase, None, None),
                [Some(phase.marker()), None, None, None]
            );
        }
        assert_eq!(
            packaged_startup_quiesce_detail_markers(
                PackagedStartupQuiescePhase::Tui,
                Some("guardian-retained.startup-quiesce.tui.state.shutdown-failure"),
                Some("guardian-retained.startup-quiesce.tui.error.signal"),
            ),
            [
                Some("guardian-retained.startup-quiesce.phase.tui"),
                Some("guardian-retained.startup-quiesce.tui.state.shutdown-failure"),
                Some("guardian-retained.startup-quiesce.tui.error.signal"),
                None,
            ]
        );
    }

    #[test]
    fn packaged_checkpoint_diagnostics_are_closed_fixed_and_unique() {
        use std::collections::BTreeSet;

        let errors = [
            CompletionError::Create,
            CompletionError::Descriptor,
            CompletionError::Inherited,
            CompletionError::Io,
            CompletionError::MissingFrame,
            CompletionError::InvalidFrame,
            CompletionError::TrailingData,
            CompletionError::RecoveryDeadline,
            CompletionError::RecoveryPeerExited,
            CompletionError::RecoveryReplay,
            CompletionError::RecoveryTooLate,
        ];
        let markers: Vec<_> = errors
            .map(packaged_guardian_checkpoint_boundary_failure_marker)
            .into_iter()
            .chain(errors.map(packaged_guardian_checkpoint_request_failure_marker))
            .chain([
                "recovery.guardian-checkpoint.publish-attempt",
                "recovery.guardian-checkpoint.published",
                "recovery.guardian-checkpoint.request-verified",
                "recovery.guardian-checkpoint.owner-lost",
                "recovery.guardian-checkpoint.protocol-rejected-owner-lost",
                "recovery.guardian-checkpoint.request-deadline",
            ])
            .collect();
        let unique: BTreeSet<_> = markers.iter().copied().collect();
        assert_eq!(unique.len(), markers.len());
        assert!(markers.iter().all(|marker| {
            marker.is_ascii()
                && marker.starts_with("recovery.guardian-checkpoint.")
                && !marker.contains('/')
                && !marker.contains(' ')
        }));
    }

    #[test]
    fn selected_checkpoint_requires_real_recovery_and_is_consumed_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let bounds = recovery_race_bounds();
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let (_coordinator, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let mut lifecycle = GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
        lifecycle.install_recovery_checkpoint(Some(RecoveryCheckpoint::StartupQueued));

        let guardian = thread::spawn(move || {
            let not_selected = lifecycle.checkpoint_and_wait_for_recovery(
                RecoveryCheckpoint::Active,
                Instant::now() + Duration::from_secs(1),
            );
            let selected = lifecycle.checkpoint_and_wait_for_recovery(
                RecoveryCheckpoint::StartupQueued,
                Instant::now() + Duration::from_secs(1),
            );
            let consumed = lifecycle.checkpoint_and_wait_for_recovery(
                RecoveryCheckpoint::StartupQueued,
                Instant::now() + Duration::from_secs(1),
            );
            (not_selected, selected, consumed)
        });

        anchor.await_test_checkpoint(
            RecoveryCheckpoint::StartupQueued,
            Instant::now() + Duration::from_secs(1),
        )?;
        anchor.request_recovery(Instant::now() + Duration::from_secs(1))?;
        let (not_selected, selected, consumed) = guardian
            .join()
            .map_err(|_| "checkpoint guardian thread panicked")?;
        assert_eq!(not_selected, Ok(TestRecoveryCheckpointOutcome::NotSelected));
        assert_eq!(
            selected,
            Ok(TestRecoveryCheckpointOutcome::RecoveryRequested)
        );
        assert_eq!(consumed, Ok(TestRecoveryCheckpointOutcome::NotSelected));
        Ok(())
    }

    #[test]
    fn checkpoint_boundary_failure_is_not_relabelled_as_lifecycle_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let bounds = recovery_race_bounds();
        let (anchor, transit) = CompletionPair::new()?.split();
        drop(anchor);
        let (_coordinator, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let mut lifecycle = GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
        lifecycle.install_recovery_checkpoint(Some(RecoveryCheckpoint::StartupQueued));

        assert_eq!(
            lifecycle.checkpoint_and_wait_for_recovery(
                RecoveryCheckpoint::StartupQueued,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TestRecoveryCheckpointOutcome::BoundaryFailed)
        );
        Ok(())
    }

    #[test]
    fn active_and_suspended_boundary_failure_still_arm_one_queued_command_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        for checkpoint in [RecoveryCheckpoint::Active, RecoveryCheckpoint::Suspended] {
            let (anchor, mut coordinator_wire, mut lifecycle, queued) =
                checkpoint_lifecycle_with_queued_command(checkpoint)?;
            drop(anchor);
            assert_eq!(
                lifecycle.checkpoint_and_wait_for_recovery(
                    checkpoint,
                    Instant::now() + Duration::from_secs(1),
                ),
                Ok(TestRecoveryCheckpointOutcome::BoundaryFailed)
            );
            finish_queued_checkpoint_recovery(&mut coordinator_wire, &mut lifecycle, queued)?;
        }
        Ok(())
    }

    #[test]
    fn ready_active_and_suspended_checkpoint_recovery_arm_one_queued_command_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            [
                RecoveryCheckpoint::StartupQueued,
                RecoveryCheckpoint::Ready,
                RecoveryCheckpoint::Active,
                RecoveryCheckpoint::Suspended,
                RecoveryCheckpoint::RetainedQuiescing,
                RecoveryCheckpoint::RetainedRestorePending,
                RecoveryCheckpoint::RetainedCleanupPending,
            ]
            .map(checkpoint_arms_recovery_command_race),
            [false, true, true, true, false, false, false]
        );

        for checkpoint in [
            RecoveryCheckpoint::Ready,
            RecoveryCheckpoint::Active,
            RecoveryCheckpoint::Suspended,
        ] {
            let bounds = recovery_race_bounds();
            let (mut anchor, transit) = CompletionPair::new()?.split();
            let (mut coordinator_wire, guardian_wire) = LifecyclePair::new()?.split_for_test();
            let mut lifecycle =
                GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
            let deadline = || Instant::now() + Duration::from_secs(1);

            lifecycle
                .commands_mut()
                .record_event(GuardianEvent::LeaseCommitted)?;
            send_coordinator_command(&mut coordinator_wire, CoordinatorCommand::Start, deadline())?;
            assert_eq!(
                test_lifecycle(lifecycle.receive(deadline()))?,
                CoordinatorCommand::Start
            );
            lifecycle
                .commands_mut()
                .record_event(GuardianEvent::TerminalArmed {
                    snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
                })?;
            send_coordinator_command(
                &mut coordinator_wire,
                CoordinatorCommand::TerminalArmAccepted,
                deadline(),
            )?;
            assert_eq!(
                test_lifecycle(lifecycle.receive(deadline()))?,
                CoordinatorCommand::TerminalArmAccepted
            );
            for event in [
                GuardianEvent::ChildStarted {
                    role: ChildRole::AppServer,
                    pid: 101,
                    pgid: 101,
                },
                GuardianEvent::ChildStarted {
                    role: ChildRole::Tui,
                    pid: 202,
                    pgid: 202,
                },
                GuardianEvent::Ready,
            ] {
                lifecycle.commands_mut().record_event(event)?;
            }

            let queued = match checkpoint {
                RecoveryCheckpoint::Ready => CoordinatorCommand::OpenInputGate,
                RecoveryCheckpoint::Active | RecoveryCheckpoint::Suspended => {
                    send_coordinator_command(
                        &mut coordinator_wire,
                        CoordinatorCommand::OpenInputGate,
                        deadline(),
                    )?;
                    assert_eq!(
                        test_lifecycle(lifecycle.receive(deadline()))?,
                        CoordinatorCommand::OpenInputGate
                    );
                    let _gate = lifecycle
                        .commands_mut()
                        .take_verified_initial_open_gate_command()?;
                    lifecycle
                        .commands_mut()
                        .record_event(GuardianEvent::InputGateOpened)?;
                    if checkpoint == RecoveryCheckpoint::Active {
                        CoordinatorCommand::Signal {
                            signal: UnixSignal::Hup,
                        }
                    } else {
                        send_coordinator_command(
                            &mut coordinator_wire,
                            CoordinatorCommand::Suspend,
                            deadline(),
                        )?;
                        assert_eq!(
                            test_lifecycle(lifecycle.receive(deadline()))?,
                            CoordinatorCommand::Suspend
                        );
                        let _suspend = lifecycle.commands_mut().take_verified_suspend_command()?;
                        lifecycle
                            .commands_mut()
                            .record_event(GuardianEvent::Suspended)?;
                        CoordinatorCommand::Resume {
                            rows: 43,
                            cols: 125,
                        }
                    }
                }
                _ => unreachable!("the table contains only live session checkpoints"),
            };
            send_coordinator_command(&mut coordinator_wire, queued, deadline())?;
            lifecycle.install_recovery_checkpoint(Some(checkpoint));

            let guardian = thread::spawn(move || {
                let result = lifecycle.checkpoint_and_wait_for_recovery(
                    checkpoint,
                    Instant::now() + Duration::from_secs(1),
                );
                (result, lifecycle)
            });
            anchor.await_test_checkpoint(checkpoint, deadline())?;
            anchor.request_recovery(deadline())?;
            let (result, mut lifecycle) = guardian
                .join()
                .map_err(|_| "queued checkpoint guardian thread panicked")?;
            assert_eq!(
                result,
                Ok(TestRecoveryCheckpointOutcome::RecoveryRequested),
                "checkpoint {checkpoint:?}"
            );

            test_lifecycle(lifecycle.emit_failure(
                Phase::Protocol,
                FailureCode::Internal,
                deadline(),
            ))?;
            test_lifecycle(lifecycle.emit(GuardianEvent::TerminalQuiesced, deadline()))?;
            assert_eq!(
                test_lifecycle(lifecycle.receive(deadline()))?,
                queued,
                "checkpoint {checkpoint:?}"
            );
            send_coordinator_command(
                &mut coordinator_wire,
                CoordinatorCommand::TerminalRestored,
                deadline(),
            )?;
            assert_eq!(
                test_lifecycle(lifecycle.receive(deadline()))?,
                CoordinatorCommand::TerminalRestored
            );
            let _restored = lifecycle
                .commands_mut()
                .take_verified_terminal_restored_command()?;
        }
        Ok(())
    }

    #[test]
    fn retained_session_stages_map_to_closed_checkpoint_values() {
        assert_eq!(
            [
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::RestorePending,
                SessionShutdownRecoveryStage::CleanupPending,
            ]
            .map(retained_session_recovery_checkpoint),
            [
                RecoveryCheckpoint::RetainedQuiescing,
                RecoveryCheckpoint::RetainedRestorePending,
                RecoveryCheckpoint::RetainedCleanupPending,
            ]
        );
    }

    #[test]
    fn retained_recovery_retries_only_monotonic_deadline_or_cleanup_states() {
        assert_eq!(
            [
                GuardianRetentionReason::Deadline,
                GuardianRetentionReason::ProtocolInvalid,
                GuardianRetentionReason::RestoreUnconfirmed,
                GuardianRetentionReason::CleanupUnconfirmed,
                GuardianRetentionReason::UnreportableChild,
            ]
            .map(retention_reason_allows_recovery),
            [true, false, false, true, false]
        );
    }

    #[test]
    fn retained_recovery_budget_is_consumed_exactly_once_and_stays_consumed_after_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut initial = RetainedRecoveryBudget::available();
        let attempt = initial
            .begin_retry()
            .ok_or("the initial retained generation had no recovery retry budget")?;
        assert_eq!(initial, RetainedRecoveryBudget::Consumed);
        assert!(initial.begin_retry().is_none());
        assert!(!retained_generation_can_attempt_recovery(&initial, true));

        let mut retained_again = RetainedRecoveryBudget::after_retry(attempt);
        assert_eq!(retained_again, RetainedRecoveryBudget::Consumed);
        assert!(retained_again.begin_retry().is_none());
        assert!(!retained_generation_can_attempt_recovery(
            &retained_again,
            true
        ));
        Ok(())
    }

    #[test]
    fn retained_terminal_boundary_publishes_for_nonrecoverable_or_consumed_generations() {
        assert!(retained_generation_can_attempt_recovery(
            &RetainedRecoveryBudget::Available,
            true
        ));
        assert!(!retained_generation_can_attempt_recovery(
            &RetainedRecoveryBudget::Available,
            false
        ));
        assert!(!retained_generation_can_attempt_recovery(
            &RetainedRecoveryBudget::Consumed,
            true
        ));
    }

    #[test]
    fn retained_lifecycle_publication_consumes_epipe_without_a_success_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (anchor, transit) = CompletionPair::new()?.split();
        drop(anchor);
        let (_coordinator, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let lifecycle = GuardianLifecycle::new(
            guardian_wire,
            transit.into_guardian(),
            recovery_race_bounds(),
        );

        assert_eq!(
            lifecycle.publish_retained_unrecoverable(),
            Err(CompletionError::Io)
        );
        Ok(())
    }

    static COMPLETION_PUBLICATION_SEAM_EVENTS: std::sync::Mutex<Vec<&'static str>> =
        std::sync::Mutex::new(Vec::new());

    fn acknowledge_completion_publication_barrier() -> Result<(), CompletionError> {
        COMPLETION_PUBLICATION_SEAM_EVENTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push("before");
        Ok(())
    }

    fn observe_completion_publication_failure(error: CompletionError) {
        assert_eq!(error, CompletionError::Io);
        COMPLETION_PUBLICATION_SEAM_EVENTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push("io");
    }

    #[test]
    fn normal_completion_receiver_loss_after_cleanup_returns_internal_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        COMPLETION_PUBLICATION_SEAM_EVENTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let bounds = recovery_race_bounds();
        let (anchor, transit) = CompletionPair::new()?.split();
        let (mut coordinator_wire, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let mut lifecycle = GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
        let deadline = || Instant::now() + Duration::from_secs(1);

        test_lifecycle(lifecycle.emit(GuardianEvent::LeaseCommitted, deadline()))?;
        send_coordinator_command(&mut coordinator_wire, CoordinatorCommand::Start, deadline())?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::Start
        );
        test_lifecycle(lifecycle.emit(
            GuardianEvent::TerminalArmed {
                snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
            },
            deadline(),
        ))?;
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::TerminalArmAccepted,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalArmAccepted
        );
        test_lifecycle(lifecycle.emit_failure(
            Phase::Readiness,
            FailureCode::EarlyExit,
            deadline(),
        ))?;
        test_lifecycle(lifecycle.emit(GuardianEvent::TerminalQuiesced, deadline()))?;
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::TerminalRestored,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalRestored
        );
        let _restored = lifecycle
            .commands_mut()
            .take_verified_terminal_restored_command()?;
        lifecycle.install_completion_publication_test_seam(
            acknowledge_completion_publication_barrier,
            observe_completion_publication_failure,
        );

        drop(anchor);
        let projection = SessionLifecycleProjection::failed_before_provider_start(
            provider_never_started_for_completion_test(),
            None,
            WorkerJoinStatus::NotStarted,
        );
        assert!(matches!(
            finalize_projection(bounds, lifecycle, projection),
            GuardianRunOutcome::Terminal(GuardianExitDisposition::InternalFailure)
        ));
        assert_eq!(
            *COMPLETION_PUBLICATION_SEAM_EVENTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ["before", "io"]
        );
        Ok(())
    }

    #[test]
    fn startup_and_session_restore_waits_keep_timeout_recoverable_but_protocol_invalid() {
        let timeout = restore_wait_retention_reason(GuardianLifecycleError::Deadline);
        let malformed = restore_wait_retention_reason(GuardianLifecycleError::Protocol);
        assert_eq!(timeout, GuardianRetentionReason::Deadline);
        assert!(retention_reason_allows_recovery(timeout));
        assert_eq!(malformed, GuardianRetentionReason::ProtocolInvalid);
        assert!(!retention_reason_allows_recovery(malformed));
    }

    #[test]
    fn shutdown_bounds_preserve_relative_phase_budgets() -> Result<(), GuardianSetupError> {
        let mut bounds = recovery_race_bounds();
        bounds.containment_timeout = Duration::from_millis(11);
        bounds.relay_shutdown_timeout = Duration::from_millis(22);
        bounds.monitor_shutdown_timeout = Duration::from_millis(33);
        bounds.app_cleanup_timeout = Duration::from_millis(44);
        bounds.build_cleanup_timeout = Duration::from_millis(55);

        let shutdown = bounds.session_shutdown()?;
        assert_eq!(shutdown.relay_timeout, Duration::from_millis(22));
        assert_eq!(shutdown.monitor_timeout, Duration::from_millis(33));
        assert_eq!(shutdown.app_cleanup_timeout, Duration::from_millis(44));
        assert_eq!(shutdown.build_cleanup_timeout, Duration::from_millis(55));

        let startup = bounds.startup_shutdown()?;
        assert_eq!(startup.containment_timeout, Duration::from_millis(11));
        assert_eq!(startup.session.relay_timeout, Duration::from_millis(22));
        Ok(())
    }

    fn recovery_race_bounds() -> GuardianBounds {
        GuardianBounds {
            phase_timeout: Duration::from_secs(1),
            poll_interval: Duration::from_millis(20),
            startup_timeout: Duration::from_secs(1),
            compatibility_timeout: Duration::from_secs(1),
            relay_start_timeout: Duration::from_secs(1),
            containment_timeout: Duration::from_secs(1),
            tui_grace: Duration::from_millis(20),
            tui_forced: Duration::from_millis(20),
            relay_shutdown_timeout: Duration::from_secs(1),
            monitor_shutdown_timeout: Duration::from_secs(1),
            app_grace: Duration::from_millis(20),
            app_forced: Duration::from_millis(20),
            app_cleanup_timeout: Duration::from_secs(1),
            build_cleanup_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn tui_exit_drain_uses_tui_grace_not_the_startup_phase_timeout() {
        let now = Instant::now();
        let mut bounds = recovery_race_bounds();
        bounds.phase_timeout = Duration::from_secs(600);
        bounds.tui_grace = Duration::from_millis(20);

        let armed = tui_exit_drain_deadline(now, bounds);
        assert_eq!(armed, now.checked_add(bounds.tui_grace));
    }

    fn checkpoint_lifecycle_with_queued_command(
        checkpoint: RecoveryCheckpoint,
    ) -> Result<QueuedCheckpointLifecycle, Box<dyn std::error::Error>> {
        let bounds = recovery_race_bounds();
        let (anchor, transit) = CompletionPair::new()?.split();
        let (mut coordinator_wire, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let mut lifecycle = GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
        let deadline = || Instant::now() + Duration::from_secs(1);

        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::LeaseCommitted)?;
        send_coordinator_command(&mut coordinator_wire, CoordinatorCommand::Start, deadline())?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::Start
        );
        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::TerminalArmed {
                snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
            })?;
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::TerminalArmAccepted,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalArmAccepted
        );
        for event in [
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: 101,
                pgid: 101,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: 202,
                pgid: 202,
            },
            GuardianEvent::Ready,
        ] {
            lifecycle.commands_mut().record_event(event)?;
        }
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::OpenInputGate,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::OpenInputGate
        );
        let _gate = lifecycle
            .commands_mut()
            .take_verified_initial_open_gate_command()?;
        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::InputGateOpened)?;

        let queued = if checkpoint == RecoveryCheckpoint::Active {
            CoordinatorCommand::Signal {
                signal: UnixSignal::Hup,
            }
        } else {
            send_coordinator_command(
                &mut coordinator_wire,
                CoordinatorCommand::Suspend,
                deadline(),
            )?;
            assert_eq!(
                test_lifecycle(lifecycle.receive(deadline()))?,
                CoordinatorCommand::Suspend
            );
            let _suspend = lifecycle.commands_mut().take_verified_suspend_command()?;
            lifecycle
                .commands_mut()
                .record_event(GuardianEvent::Suspended)?;
            CoordinatorCommand::Resume {
                rows: 43,
                cols: 125,
            }
        };
        send_coordinator_command(&mut coordinator_wire, queued, deadline())?;
        lifecycle.install_recovery_checkpoint(Some(checkpoint));
        Ok((anchor, coordinator_wire, lifecycle, queued))
    }

    fn finish_queued_checkpoint_recovery(
        coordinator_wire: &mut LifecycleEndpoint,
        lifecycle: &mut GuardianLifecycle<LifecycleEndpoint>,
        queued: CoordinatorCommand,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = || Instant::now() + Duration::from_secs(1);
        test_lifecycle(lifecycle.emit_failure(Phase::Protocol, FailureCode::Internal, deadline()))?;
        test_lifecycle(lifecycle.emit(GuardianEvent::TerminalQuiesced, deadline()))?;
        assert_eq!(test_lifecycle(lifecycle.receive(deadline()))?, queued);
        send_coordinator_command(
            coordinator_wire,
            CoordinatorCommand::TerminalRestored,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalRestored
        );
        let _restored = lifecycle
            .commands_mut()
            .take_verified_terminal_restored_command()?;
        Ok(())
    }

    fn test_lifecycle<T>(
        result: Result<T, GuardianLifecycleError>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        result.map_err(|error| format!("guardian lifecycle fixture failed: {error:?}").into())
    }

    #[test]
    fn bounded_control_turn_arms_recovery_before_returning_with_a_queued_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let bounds = recovery_race_bounds();
        let (mut anchor, transit) = CompletionPair::new()?.split();
        let (mut coordinator_wire, guardian_wire) = LifecyclePair::new()?.split_for_test();
        let mut lifecycle = GuardianLifecycle::new(guardian_wire, transit.into_guardian(), bounds);
        let deadline = || Instant::now() + Duration::from_secs(1);

        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::LeaseCommitted)?;
        send_coordinator_command(&mut coordinator_wire, CoordinatorCommand::Start, deadline())?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::Start
        );
        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::TerminalArmed {
                snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
            })?;
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::TerminalArmAccepted,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalArmAccepted
        );
        for event in [
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: 101,
                pgid: 101,
            },
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: 202,
                pgid: 202,
            },
            GuardianEvent::Ready,
        ] {
            lifecycle.commands_mut().record_event(event)?;
        }
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::OpenInputGate,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::OpenInputGate
        );
        let _gate = lifecycle
            .commands_mut()
            .take_verified_initial_open_gate_command()?;
        lifecycle
            .commands_mut()
            .record_event(GuardianEvent::InputGateOpened)?;

        let queued = CoordinatorCommand::Signal {
            signal: UnixSignal::Hup,
        };
        send_coordinator_command(&mut coordinator_wire, queued, deadline())?;
        anchor.request_recovery(deadline())?;
        assert!(matches!(
            test_lifecycle(receive_bounded_command(bounds, &mut lifecycle))?,
            GuardianControlTurn::Recovery
        ));

        test_lifecycle(lifecycle.emit_failure(Phase::Protocol, FailureCode::Internal, deadline()))?;
        test_lifecycle(lifecycle.emit(GuardianEvent::TerminalQuiesced, deadline()))?;
        assert_eq!(test_lifecycle(lifecycle.receive(deadline()))?, queued);
        send_coordinator_command(
            &mut coordinator_wire,
            CoordinatorCommand::TerminalRestored,
            deadline(),
        )?;
        assert_eq!(
            test_lifecycle(lifecycle.receive(deadline()))?,
            CoordinatorCommand::TerminalRestored
        );
        let _restored = lifecycle
            .commands_mut()
            .take_verified_terminal_restored_command()?;
        Ok(())
    }

    #[test]
    fn out_of_band_recovery_is_not_relabelled_as_a_coordinator_stop() {
        assert!(matches!(
            recovery_shutdown_trigger(),
            SessionShutdownTrigger::Failure(SessionOperationError::RecoveryRequested)
        ));
        assert!(matches!(
            coordinator_stop_trigger(),
            SessionShutdownTrigger::Cause(SessionTerminationCause::CoordinatorStop)
        ));
    }

    #[test]
    fn production_and_package_have_one_guardian_bootstrap_constructor() {
        let source = include_str!("guardian.rs");
        assert_eq!(
            source
                .matches(&["fn bootstrap_guardian", "_core"].concat())
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(&["ArmedProduction", "Guardian {"].concat())
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(&["admit_same_profile_guardian", "_session("].concat())
                .count(),
            1
        );
        assert_eq!(
            source
                .matches(&["bootstrap_guardian_from_", "stdin()"].concat())
                .count(),
            1
        );
        assert!(!source.contains(&["run_packaged_guardian_", "harness"].concat()));
    }
}
