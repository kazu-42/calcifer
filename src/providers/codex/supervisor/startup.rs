//! Production startup orchestration for one supervised Codex session.
//!
//! Startup crosses several fallible ownership boundaries after the outer
//! terminal has been armed. Every edge is therefore represented by one
//! private linear owner. A caller can observe only a redacted error class and
//! drive the two-stage resolver: process quiescence first, coordinator-owned
//! terminal restoration second, and namespace/build cleanup only after the
//! guardian consumes the protocol-minted restoration proof.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::providers::codex::monitor::{
    SessionMonitor, SessionMonitorShutdownOwner, SessionMonitorStartFailure,
};

#[cfg(test)]
use super::super::handoff_compat::CodexHandoffError;
#[cfg(test)]
use super::launcher::PackagedRemoteTuiLaunchFailureClassification;
use super::launcher::{
    PendingRemoteTui, ReadyRemoteTui, RemoteTuiLaunchFailure, RemoteTuiReadinessContainmentFailure,
    RemoteTuiReadinessFailure, RemoteTuiShutdownFailure,
};
#[cfg(test)]
use super::process::{AppGracefulDrainFailureStage, ProcessError};
use super::process::{ContainmentMetadata, PinnedAppGracefulDrain, ShutdownOutcome};
use super::protocol::{VerifiedTerminalRestoredCommand, WorkerJoinStatus};
#[cfg(test)]
use super::provider::verify_authorized_test_compatibility;
use super::provider::{
    AppServerAdoptionContainmentComplete, AppServerAdoptionContainmentFailure, AppServerChild,
    AppServerLaunchContainmentComplete, AppServerLaunchReservationFailure, AppServerSession,
    AppServerSocketAdoptionFailure, AppServerStopFailure, AppServerTeardownFailure,
    AuthorizedCompatibilityFailure, AuthorizedCompatibilityResolution, ConnectedMonitorSession,
    ExactRelaySession, ExactRelayShutdownFailure, ExactRelayStartFailure, PinnedSessionBuild,
    ProviderCleanupFailure, ProviderLaunchAuthorization, StoppedAppServer,
    VerifiedAppDescriptorIsolation, verify_authorized_compatibility,
};
#[cfg(test)]
use super::provider::{AppServerTopologyError, ProviderLaunchError};
#[cfg(test)]
use super::runtime::AppSocketError;
use super::runtime::{
    AppSocketReservation, AppSocketReservationFailure, PrivateRuntime, RuntimeCleanupFailure,
    RuntimeCreateFailure,
};
#[cfg(test)]
use super::session::SessionShutdownRecoveryStage;
use super::session::{
    AwaitingReadySupervisedSession, SessionLifecycleProjection, SessionShutdownBounds,
    SessionShutdownFailure, SessionShutdownReport, SessionStartupError, SessionStartupFailure,
    TerminalGenerationOwner, assemble_started_session,
};
use super::terminal::{
    PtyOwner, RecoveryDisarmOutcome, RecoveryDisarmProof, RecoveryDisarmUnconfirmed, RecoveryTty,
    RestoredTerminalProof, TerminalEndpoint, TerminalError, TerminalShutdown, TerminalSize,
    TerminalSnapshot,
};

/// Move-only evidence that startup never crossed an App Server spawn edge.
///
/// The private field keeps this constructible only inside the startup state
/// machine, where the final clean authority variant distinguishes pre-spawn
/// runtime/reservation cleanup from every started or unannounced App path.
#[must_use = "never-started provider evidence must authorize lifecycle completion"]
pub(super) struct ProviderNeverStarted {
    _private: (),
}

/// Startup-only deadlines. Shutdown retries always receive a fresh
/// [`StartupShutdownBounds`] value instead of reusing these instants.
#[derive(Clone, Copy)]
pub(super) struct ProductionStartupBounds {
    pub(super) deadline: Instant,
    pub(super) compatibility_timeout: Duration,
    pub(super) relay_timeout: Duration,
}

impl ProductionStartupBounds {
    /// Clamps a stage-local relative timeout to the one absolute startup
    /// deadline. This is the only place startup may translate that deadline
    /// into a relative duration, preventing a late stage from receiving its
    /// original full budget after earlier stages consumed most of the window.
    fn remaining_timeout(self, requested: Duration) -> Duration {
        self.remaining_timeout_at(requested, Instant::now())
    }

    fn remaining_timeout_at(self, requested: Duration, now: Instant) -> Duration {
        requested.min(self.deadline.saturating_duration_since(now))
    }

    /// Mints one fixed relay-readiness deadline only when the complete
    /// configured window fits inside the global startup envelope.
    fn full_relay_deadline_at(self, now: Instant) -> Option<Instant> {
        if self.relay_timeout.is_zero() {
            return None;
        }
        let relay_deadline = now.checked_add(self.relay_timeout)?;
        (relay_deadline <= self.deadline).then_some(relay_deadline)
    }
}

enum RelayTuiStartBoundaryFailure<Relay, RelayError, TuiError> {
    Deadline,
    Relay(RelayError),
    Tui { relay: Relay, error: TuiError },
}

/// Crosses the only boundary that may start the relay and TUI. The closures
/// make the no-attempt deadline edge deterministic to test while retaining
/// the exact started relay owner if the subsequent TUI launch fails.
fn cross_relay_tui_start_boundary_at<Relay, PendingTui, RelayError, TuiError>(
    bounds: ProductionStartupBounds,
    now: Instant,
    spawn_relay: impl FnOnce(Instant) -> Result<Relay, RelayError>,
    launch_tui: impl FnOnce() -> Result<PendingTui, TuiError>,
) -> Result<(Relay, PendingTui), RelayTuiStartBoundaryFailure<Relay, RelayError, TuiError>> {
    let relay_deadline = bounds
        .full_relay_deadline_at(now)
        .ok_or(RelayTuiStartBoundaryFailure::Deadline)?;
    let relay = spawn_relay(relay_deadline).map_err(RelayTuiStartBoundaryFailure::Relay)?;
    match launch_tui() {
        Ok(tui) => Ok((relay, tui)),
        Err(error) => Err(RelayTuiStartBoundaryFailure::Tui { relay, error }),
    }
}

/// Redacted stage classification. Exact provider errors remain sealed in the
/// private owner that can retry or clean them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisedStartupError {
    Terminal,
    Compatibility,
    Runtime,
    AppPlan,
    AppLaunch,
    AppSocket,
    MonitorConnect,
    MonitorStart,
    RelayPlan,
    RelayStart,
    TuiPlan,
    TuiPty,
    TuiLaunch,
    TuiReadiness,
    Lifecycle,
    SessionReadiness(SessionStartupError),
    Deadline,
}

impl fmt::Display for SupervisedStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Terminal => "the supervised terminal startup failed",
            Self::Compatibility => "the Codex compatibility proof failed",
            Self::Runtime => "the private supervisor runtime failed",
            Self::AppPlan => "the App Server launch plan failed",
            Self::AppLaunch => "the App Server launch failed",
            Self::AppSocket => "the App Server socket topology failed",
            Self::MonitorConnect => "the App Server monitor connection failed",
            Self::MonitorStart => "the usage monitor failed to start",
            Self::RelayPlan => "the exact-resume relay plan failed",
            Self::RelayStart => "the exact-resume relay failed to start",
            Self::TuiPlan => "the remote TUI launch plan failed",
            Self::TuiPty => "the remote TUI PTY setup failed",
            Self::TuiLaunch => "the remote TUI launch failed",
            Self::TuiReadiness => "the remote TUI readiness proof failed",
            Self::Lifecycle => "the guardian lifecycle report failed",
            Self::SessionReadiness(_) => "the supervised session readiness gate failed",
            Self::Deadline => "the supervised startup deadline elapsed",
        })
    }
}

impl std::error::Error for SupervisedStartupError {}

/// Minimal guardian-driver callback. It receives only bounded direct-child
/// observations and has no signal, process-handle, or lifecycle endpoint
/// ownership. The driver remains responsible for mapping this to the exact
/// protocol event sequence.
pub(super) trait StartupLifecycleReporter {
    /// Appends the guardian lifecycle wire to a source-pinned child denyset.
    /// Implementations must not expose its raw descriptor or identity.
    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError>;

    fn child_started(
        &mut self,
        child: ContainmentMetadata,
        deadline: Instant,
    ) -> Result<(), StartupLifecycleReportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StartupLifecycleReportError;

fn report_child_started_or_retain<Owner>(
    owner: Owner,
    child: ContainmentMetadata,
    reporter: &mut impl StartupLifecycleReporter,
    deadline: Instant,
) -> Result<Owner, Owner> {
    match reporter.child_started(child, deadline) {
        Ok(()) => Ok(owner),
        Err(_) => Err(owner),
    }
}

enum StartupBuildAuthority {
    Authorized(ProviderLaunchAuthorization),
    CompatibilityFailure(Box<AuthorizedCompatibilityFailure>),
    CompatibilityResolved(AuthorizedCompatibilityResolution),
    Live(Box<PinnedSessionBuild>),
    CleanupFailure(Box<ProviderCleanupFailure>),
    Clean,
}

enum StartupAppAuthority {
    None,
    RuntimeCreateFailure(Box<RuntimeCreateFailure>),
    Runtime(Box<PrivateRuntime>),
    RuntimeCleanupFailure(Box<RuntimeCleanupFailure>),
    Reservation(Box<AppSocketReservation>),
    ReservationFailure(Box<AppSocketReservationFailure>),
    LaunchFailure(Box<AppServerLaunchReservationFailure>),
    LaunchContained(Box<AppServerLaunchContainmentComplete>),
    AdoptionFailure(Box<AppServerSocketAdoptionFailure>),
    AdoptionContainmentFailure(Box<AppServerAdoptionContainmentFailure>),
    AdoptionContained(Box<AppServerAdoptionContainmentComplete>),
    Session(Box<AppServerSession>),
    Connected(Box<ConnectedMonitorSession>),
    InMonitor,
    StopFailure(Box<AppServerStopFailure>),
    Stopped(Box<StoppedAppServer>),
    CleanupFailure(Box<AppServerTeardownFailure>),
    Clean(StartupProviderRelease),
}

enum StartupProviderRelease {
    NeverStarted(ProviderNeverStarted),
    GracefullyDrained(PinnedAppGracefulDrain),
}

fn provider_never_started() -> StartupProviderRelease {
    StartupProviderRelease::NeverStarted(ProviderNeverStarted { _private: () })
}

/// Supplies the real move-only pre-spawn evidence to completion-boundary
/// tests. This deliberately returns startup evidence instead of fabricating a
/// generic release token, so tests cross the same lifecycle projector as
/// production startup cleanup.
#[cfg(test)]
pub(super) fn provider_never_started_for_completion_test() -> ProviderNeverStarted {
    ProviderNeverStarted { _private: () }
}

enum StartupMonitorAuthority {
    None,
    Live(Box<SessionMonitor>),
}

enum StartupRelayAuthority {
    None,
    StartFailure(Box<ExactRelayStartFailure>),
    Live(Box<ExactRelaySession>),
    ShutdownFailure(Box<ExactRelayShutdownFailure>),
}

enum StartupTuiAuthority {
    None,
    LaunchFailure(Box<RemoteTuiLaunchFailure>),
    ReadinessFailure(Box<RemoteTuiReadinessFailure>),
    ReadinessContainmentFailure(Box<RemoteTuiReadinessContainmentFailure>),
    Live(Box<ReadyRemoteTui>),
    ShutdownFailure(Box<RemoteTuiShutdownFailure>),
    Clean(Option<ShutdownOutcome>),
}

enum StartupRecoveryAuthority {
    Armed(RecoveryTty),
    CoordinatorRestored {
        recovery: RecoveryTty,
        _proof: VerifiedTerminalRestoredCommand,
    },
    FallbackRestored {
        recovery: RecoveryTty,
        _proof: RestoredTerminalProof,
    },
    DisarmUnconfirmed(RecoveryDisarmUnconfirmed),
    Disarmed(RecoveryDisarmProof),
}

struct StartupTerminalAuthority {
    endpoint: Option<TerminalEndpoint>,
    recovery: Option<StartupRecoveryAuthority>,
    snapshot: TerminalSnapshot,
}

impl StartupTerminalAuthority {
    fn new(endpoint: TerminalEndpoint, recovery: RecoveryTty, snapshot: TerminalSnapshot) -> Self {
        Self {
            endpoint: Some(endpoint),
            recovery: Some(StartupRecoveryAuthority::Armed(recovery)),
            snapshot,
        }
    }

    fn validate(&self) -> Result<(), TerminalError> {
        let endpoint = self.endpoint.as_ref().ok_or(TerminalError::ChannelCreate)?;
        endpoint.verify_invariants()?;
        let Some(StartupRecoveryAuthority::Armed(recovery)) = self.recovery.as_ref() else {
            return Err(TerminalError::RecoveryAuthorityMismatch);
        };
        recovery.verify_invariants()?;
        if recovery.descriptor_identity() != self.snapshot.descriptor_identity() {
            return Err(TerminalError::TerminalIdentityMismatch);
        }
        Ok(())
    }

    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        let endpoint = self.endpoint.as_ref().ok_or(
            calcifer_unix_child_fd::CrossProcessDescriptorIdentityError::ObservationFailed,
        )?;
        let Some(StartupRecoveryAuthority::Armed(recovery)) = self.recovery.as_ref() else {
            return Err(
                calcifer_unix_child_fd::CrossProcessDescriptorIdentityError::ObservationFailed,
            );
        };
        endpoint.append_forbidden_descriptor(forbidden)?;
        recovery.append_forbidden_descriptor(forbidden)
    }

    /// Consumes the terminal cleanup authority only after recovery has been
    /// explicitly disarmed. The proof cannot disappear through the partial
    /// startup report's former `..` destructure.
    fn authorize_post_restore_release(self) {
        let Self {
            endpoint,
            recovery,
            snapshot,
        } = self;
        if endpoint.is_some() {
            std::process::abort();
        }
        match recovery {
            Some(StartupRecoveryAuthority::Disarmed(proof)) => drop(proof),
            Some(
                StartupRecoveryAuthority::Armed(_)
                | StartupRecoveryAuthority::CoordinatorRestored { .. }
                | StartupRecoveryAuthority::FallbackRestored { .. }
                | StartupRecoveryAuthority::DisarmUnconfirmed(_),
            )
            | None => std::process::abort(),
        }
        let _snapshot = snapshot;
    }

    fn into_generation(
        mut self,
        tui: ReadyRemoteTui,
    ) -> Result<TerminalGenerationOwner, Box<(Self, ReadyRemoteTui, TerminalError)>> {
        let Some(endpoint) = self.endpoint.take() else {
            return Err(Box::new((self, tui, TerminalError::ChannelCreate)));
        };
        let Some(StartupRecoveryAuthority::Armed(recovery)) = self.recovery.take() else {
            self.endpoint = Some(endpoint);
            return Err(Box::new((
                self,
                tui,
                TerminalError::RecoveryAuthorityMismatch,
            )));
        };
        let snapshot = self.snapshot;
        match TerminalGenerationOwner::new(tui, endpoint, recovery, snapshot) {
            Ok(owner) => Ok(owner),
            Err(failure) => {
                let error = failure.error();
                let (tui, endpoint, recovery, snapshot) = failure.into_parts();
                Err(Box::new((
                    Self::new(endpoint, recovery, snapshot),
                    tui,
                    error,
                )))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupShutdownPhase {
    Tui,
    Relay,
    Monitor,
    AppStop,
    TerminalQuiesce,
    AwaitingCoordinatorRestore,
    RecoveryDisarm,
    RuntimeCleanup,
    BuildCleanup,
    Complete,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PackagedStartupQuiescePhase {
    Tui,
    Relay,
    Monitor,
    AppStop,
    TerminalQuiesce,
    AwaitingCoordinatorRestore,
    RecoveryDisarm,
    RuntimeCleanup,
    BuildCleanup,
    Complete,
    SessionQuiescing,
    SessionRestorePending,
    SessionCleanupPending,
}

#[cfg(test)]
impl PackagedStartupQuiescePhase {
    const fn from_session_stage(stage: SessionShutdownRecoveryStage) -> Self {
        match stage {
            SessionShutdownRecoveryStage::Quiescing => Self::SessionQuiescing,
            SessionShutdownRecoveryStage::RestorePending => Self::SessionRestorePending,
            SessionShutdownRecoveryStage::CleanupPending => Self::SessionCleanupPending,
        }
    }

    pub(super) const fn marker(self) -> &'static str {
        match self {
            Self::Tui => "guardian-retained.startup-quiesce.phase.tui",
            Self::Relay => "guardian-retained.startup-quiesce.phase.relay",
            Self::Monitor => "guardian-retained.startup-quiesce.phase.monitor",
            Self::AppStop => "guardian-retained.startup-quiesce.phase.app-stop",
            Self::TerminalQuiesce => "guardian-retained.startup-quiesce.phase.terminal-quiesce",
            Self::AwaitingCoordinatorRestore => {
                "guardian-retained.startup-quiesce.phase.awaiting-coordinator-restore"
            }
            Self::RecoveryDisarm => "guardian-retained.startup-quiesce.phase.recovery-disarm",
            Self::RuntimeCleanup => "guardian-retained.startup-quiesce.phase.runtime-cleanup",
            Self::BuildCleanup => "guardian-retained.startup-quiesce.phase.build-cleanup",
            Self::Complete => "guardian-retained.startup-quiesce.phase.complete",
            Self::SessionQuiescing => "guardian-retained.startup-quiesce.phase.session-quiescing",
            Self::SessionRestorePending => {
                "guardian-retained.startup-quiesce.phase.session-restore-pending"
            }
            Self::SessionCleanupPending => {
                "guardian-retained.startup-quiesce.phase.session-cleanup-pending"
            }
        }
    }
}

#[cfg(test)]
const fn packaged_startup_tui_process_error_marker(error: ProcessError) -> &'static str {
    match error {
        ProcessError::Spawn { .. } => "guardian-retained.startup-quiesce.tui.error.spawn",
        ProcessError::ProcessGroupReadback { .. } => {
            "guardian-retained.startup-quiesce.tui.error.process-group-readback"
        }
        ProcessError::ProcessGroupMismatch { .. } => {
            "guardian-retained.startup-quiesce.tui.error.process-group-mismatch"
        }
        ProcessError::SessionReadback { .. } => {
            "guardian-retained.startup-quiesce.tui.error.session-readback"
        }
        ProcessError::SessionMismatch { .. } => {
            "guardian-retained.startup-quiesce.tui.error.session-mismatch"
        }
        ProcessError::SessionStartupTimeout { .. } => {
            "guardian-retained.startup-quiesce.tui.error.session-startup-timeout"
        }
        ProcessError::SpawnCleanupTimeout { .. } => {
            "guardian-retained.startup-quiesce.tui.error.spawn-cleanup-timeout"
        }
        ProcessError::SpawnContainmentUnconfirmed { .. } => {
            "guardian-retained.startup-quiesce.tui.error.spawn-containment-unconfirmed"
        }
        ProcessError::ReadinessUnavailable { .. } => {
            "guardian-retained.startup-quiesce.tui.error.readiness-unavailable"
        }
        ProcessError::ParentLivenessUnavailable { .. } => {
            "guardian-retained.startup-quiesce.tui.error.parent-liveness-unavailable"
        }
        ProcessError::ReadinessTimeout { .. } => {
            "guardian-retained.startup-quiesce.tui.error.readiness-timeout"
        }
        ProcessError::ReadinessIo { .. } => {
            "guardian-retained.startup-quiesce.tui.error.readiness-io"
        }
        ProcessError::InvalidReadiness { .. } => {
            "guardian-retained.startup-quiesce.tui.error.invalid-readiness"
        }
        ProcessError::EarlyExit { .. } => "guardian-retained.startup-quiesce.tui.error.early-exit",
        ProcessError::Signal { .. } => "guardian-retained.startup-quiesce.tui.error.signal",
        ProcessError::ForwardedSignalMismatch { .. } => {
            "guardian-retained.startup-quiesce.tui.error.forwarded-signal-mismatch"
        }
        ProcessError::SuspendTimeout { .. } => {
            "guardian-retained.startup-quiesce.tui.error.suspend-timeout"
        }
        ProcessError::Wait { .. } => "guardian-retained.startup-quiesce.tui.error.wait",
        ProcessError::WaitTimeout { .. } => {
            "guardian-retained.startup-quiesce.tui.error.wait-timeout"
        }
        ProcessError::TuiOutputDrain { .. } => {
            "guardian-retained.startup-quiesce.tui.error.tui-output-drain"
        }
        ProcessError::AppGracefulDrainUnconfirmed { .. } => {
            "guardian-retained.startup-quiesce.tui.error.app-graceful-drain-unconfirmed"
        }
        ProcessError::RoleMismatch { .. } => {
            "guardian-retained.startup-quiesce.tui.error.role-mismatch"
        }
        ProcessError::RetryAfterResolution => {
            "guardian-retained.startup-quiesce.tui.error.retry-after-resolution"
        }
        ProcessError::Deadline => "guardian-retained.startup-quiesce.tui.error.deadline",
    }
}

#[cfg(test)]
const fn packaged_startup_app_process_error_marker(error: ProcessError) -> &'static str {
    match error {
        ProcessError::Spawn { .. } => "guardian-retained.startup-quiesce.app.error.spawn",
        ProcessError::ProcessGroupReadback { .. } => {
            "guardian-retained.startup-quiesce.app.error.process-group-readback"
        }
        ProcessError::ProcessGroupMismatch { .. } => {
            "guardian-retained.startup-quiesce.app.error.process-group-mismatch"
        }
        ProcessError::SessionReadback { .. } => {
            "guardian-retained.startup-quiesce.app.error.session-readback"
        }
        ProcessError::SessionMismatch { .. } => {
            "guardian-retained.startup-quiesce.app.error.session-mismatch"
        }
        ProcessError::SessionStartupTimeout { .. } => {
            "guardian-retained.startup-quiesce.app.error.session-startup-timeout"
        }
        ProcessError::SpawnCleanupTimeout { .. } => {
            "guardian-retained.startup-quiesce.app.error.spawn-cleanup-timeout"
        }
        ProcessError::SpawnContainmentUnconfirmed { .. } => {
            "guardian-retained.startup-quiesce.app.error.spawn-containment-unconfirmed"
        }
        ProcessError::ReadinessUnavailable { .. } => {
            "guardian-retained.startup-quiesce.app.error.readiness-unavailable"
        }
        ProcessError::ParentLivenessUnavailable { .. } => {
            "guardian-retained.startup-quiesce.app.error.parent-liveness-unavailable"
        }
        ProcessError::ReadinessTimeout { .. } => {
            "guardian-retained.startup-quiesce.app.error.readiness-timeout"
        }
        ProcessError::ReadinessIo { .. } => {
            "guardian-retained.startup-quiesce.app.error.readiness-io"
        }
        ProcessError::InvalidReadiness { .. } => {
            "guardian-retained.startup-quiesce.app.error.invalid-readiness"
        }
        ProcessError::EarlyExit { .. } => "guardian-retained.startup-quiesce.app.error.early-exit",
        ProcessError::Signal { .. } => "guardian-retained.startup-quiesce.app.error.signal",
        ProcessError::ForwardedSignalMismatch { .. } => {
            "guardian-retained.startup-quiesce.app.error.forwarded-signal-mismatch"
        }
        ProcessError::SuspendTimeout { .. } => {
            "guardian-retained.startup-quiesce.app.error.suspend-timeout"
        }
        ProcessError::Wait { .. } => "guardian-retained.startup-quiesce.app.error.wait",
        ProcessError::WaitTimeout { .. } => {
            "guardian-retained.startup-quiesce.app.error.wait-timeout"
        }
        ProcessError::TuiOutputDrain { .. } => {
            "guardian-retained.startup-quiesce.app.error.tui-output-drain"
        }
        ProcessError::AppGracefulDrainUnconfirmed { stage, .. } => match stage {
            AppGracefulDrainFailureStage::PriorInvalid => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.prior-invalid"
            }
            AppGracefulDrainFailureStage::ExitedBeforeTerm => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.exited-before-term"
            }
            AppGracefulDrainFailureStage::StopTimeout => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.stop-timeout"
            }
            AppGracefulDrainFailureStage::ExitedWhileStopping => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.exited-while-stopping"
            }
            AppGracefulDrainFailureStage::InvalidDisposition => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.invalid-disposition"
            }
            AppGracefulDrainFailureStage::KillForbidden => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.kill-forbidden"
            }
            AppGracefulDrainFailureStage::WrongRetryPath => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.wrong-retry-path"
            }
            AppGracefulDrainFailureStage::MissingProof => {
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.missing-proof"
            }
        },
        ProcessError::RoleMismatch { .. } => {
            "guardian-retained.startup-quiesce.app.error.role-mismatch"
        }
        ProcessError::RetryAfterResolution => {
            "guardian-retained.startup-quiesce.app.error.retry-after-resolution"
        }
        ProcessError::Deadline => "guardian-retained.startup-quiesce.app.error.deadline",
    }
}

#[cfg(test)]
pub(super) const PACKAGED_COMPATIBILITY_FAILURE_MARKERS: &[&str] = &[
    "startup-failure.compatibility.subtype.unsupported",
    "startup-failure.compatibility.subtype.protocol",
    "startup-failure.compatibility.subtype.timeout",
    "startup-failure.compatibility.subtype.transport",
    "startup-failure.compatibility.subtype.spawn",
];

#[cfg(test)]
const fn packaged_compatibility_failure_marker(error: CodexHandoffError) -> &'static str {
    match error {
        CodexHandoffError::Unsupported => "startup-failure.compatibility.subtype.unsupported",
        CodexHandoffError::Protocol => "startup-failure.compatibility.subtype.protocol",
        CodexHandoffError::Timeout => "startup-failure.compatibility.subtype.timeout",
        CodexHandoffError::Transport => "startup-failure.compatibility.subtype.transport",
        CodexHandoffError::Spawn => "startup-failure.compatibility.subtype.spawn",
    }
}

#[cfg(test)]
pub(super) const PACKAGED_APP_SOCKET_FAILURE_MARKERS: &[&str] = &[
    "startup-failure.app-socket.subtype.cross-session-socket",
    "startup-failure.app-socket.subtype.descriptor-isolation.invalid-argument",
    "startup-failure.app-socket.subtype.descriptor-isolation.process-limit",
    "startup-failure.app-socket.subtype.descriptor-isolation.member-limit",
    "startup-failure.app-socket.subtype.descriptor-isolation.descriptor-limit",
    "startup-failure.app-socket.subtype.descriptor-isolation.forbidden-identity-limit",
    "startup-failure.app-socket.subtype.descriptor-isolation.deadline",
    "startup-failure.app-socket.subtype.descriptor-isolation.permission-denied",
    "startup-failure.app-socket.subtype.descriptor-isolation.process-user-mismatch",
    "startup-failure.app-socket.subtype.descriptor-isolation.process-changed",
    "startup-failure.app-socket.subtype.descriptor-isolation.descriptor-changed",
    "startup-failure.app-socket.subtype.descriptor-isolation.forbidden-descriptor",
    "startup-failure.app-socket.subtype.descriptor-isolation.unsupported-descriptor",
    "startup-failure.app-socket.subtype.descriptor-isolation.observation-failed",
    "startup-failure.app-socket.subtype.provider.invalid-argument",
    "startup-failure.app-socket.subtype.provider.authority-consumed",
    "startup-failure.app-socket.subtype.provider.session-in-use",
    "startup-failure.app-socket.subtype.provider.executable-changed",
    "startup-failure.app-socket.subtype.provider.session-changed",
    "startup-failure.app-socket.subtype.provider.storage",
    "startup-failure.app-socket.subtype.provider.timeout",
    "startup-failure.app-socket.subtype.socket.unsafe-runtime",
    "startup-failure.app-socket.subtype.socket.path-too-long",
    "startup-failure.app-socket.subtype.socket.collision",
    "startup-failure.app-socket.subtype.socket.unknown-entry",
    "startup-failure.app-socket.subtype.socket.socket-not-ready",
    "startup-failure.app-socket.subtype.socket.unsafe-node",
    #[cfg(target_os = "linux")]
    "startup-failure.app-socket.subtype.socket.identity-lease-unavailable",
    "startup-failure.app-socket.subtype.socket.identity-mismatch",
    "startup-failure.app-socket.subtype.socket.socket-still-present",
    "startup-failure.app-socket.subtype.socket.adoption-timeout",
    "startup-failure.app-socket.subtype.socket.timeout",
    "startup-failure.app-socket.subtype.socket.cleanup",
    "startup-failure.app-socket.subtype.process.spawn",
    "startup-failure.app-socket.subtype.process.process-group-readback",
    "startup-failure.app-socket.subtype.process.process-group-mismatch",
    "startup-failure.app-socket.subtype.process.session-readback",
    "startup-failure.app-socket.subtype.process.session-mismatch",
    "startup-failure.app-socket.subtype.process.session-startup-timeout",
    "startup-failure.app-socket.subtype.process.spawn-cleanup-timeout",
    "startup-failure.app-socket.subtype.process.spawn-containment-unconfirmed",
    "startup-failure.app-socket.subtype.process.readiness-unavailable",
    "startup-failure.app-socket.subtype.process.parent-liveness-unavailable",
    "startup-failure.app-socket.subtype.process.readiness-timeout",
    "startup-failure.app-socket.subtype.process.readiness-io",
    "startup-failure.app-socket.subtype.process.invalid-readiness",
    "startup-failure.app-socket.subtype.process.early-exit",
    "startup-failure.app-socket.subtype.process.signal",
    "startup-failure.app-socket.subtype.process.forwarded-signal-mismatch",
    "startup-failure.app-socket.subtype.process.suspend-timeout",
    "startup-failure.app-socket.subtype.process.wait",
    "startup-failure.app-socket.subtype.process.wait-timeout",
    "startup-failure.app-socket.subtype.process.tui-output-drain",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.prior-invalid",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.exited-before-term",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.stop-timeout",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.exited-while-stopping",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.invalid-disposition",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.kill-forbidden",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.wrong-retry-path",
    "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.missing-proof",
    "startup-failure.app-socket.subtype.process.role-mismatch",
    "startup-failure.app-socket.subtype.process.retry-after-resolution",
    "startup-failure.app-socket.subtype.process.deadline",
];

#[cfg(test)]
const fn packaged_app_socket_failure_marker(error: AppServerTopologyError) -> &'static str {
    match error {
        AppServerTopologyError::CrossSessionSocket => {
            "startup-failure.app-socket.subtype.cross-session-socket"
        }
        AppServerTopologyError::DescriptorIsolation(error) => {
            packaged_app_socket_descriptor_error_marker(error)
        }
        AppServerTopologyError::Provider(error) => packaged_app_socket_provider_error_marker(error),
        AppServerTopologyError::Socket(error) => packaged_app_socket_error_marker(error),
        AppServerTopologyError::Process(error) => packaged_app_socket_process_error_marker(error),
    }
}

#[cfg(test)]
const fn packaged_app_socket_descriptor_error_marker(
    error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
) -> &'static str {
    use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

    match error {
        ProcessGroupDescriptorScanError::InvalidArgument => {
            "startup-failure.app-socket.subtype.descriptor-isolation.invalid-argument"
        }
        ProcessGroupDescriptorScanError::ProcessLimit => {
            "startup-failure.app-socket.subtype.descriptor-isolation.process-limit"
        }
        ProcessGroupDescriptorScanError::MemberLimit => {
            "startup-failure.app-socket.subtype.descriptor-isolation.member-limit"
        }
        ProcessGroupDescriptorScanError::DescriptorLimit => {
            "startup-failure.app-socket.subtype.descriptor-isolation.descriptor-limit"
        }
        ProcessGroupDescriptorScanError::ForbiddenIdentityLimit => {
            "startup-failure.app-socket.subtype.descriptor-isolation.forbidden-identity-limit"
        }
        ProcessGroupDescriptorScanError::Deadline => {
            "startup-failure.app-socket.subtype.descriptor-isolation.deadline"
        }
        ProcessGroupDescriptorScanError::PermissionDenied => {
            "startup-failure.app-socket.subtype.descriptor-isolation.permission-denied"
        }
        ProcessGroupDescriptorScanError::ProcessUserMismatch => {
            "startup-failure.app-socket.subtype.descriptor-isolation.process-user-mismatch"
        }
        ProcessGroupDescriptorScanError::ProcessChanged => {
            "startup-failure.app-socket.subtype.descriptor-isolation.process-changed"
        }
        ProcessGroupDescriptorScanError::DescriptorChanged => {
            "startup-failure.app-socket.subtype.descriptor-isolation.descriptor-changed"
        }
        ProcessGroupDescriptorScanError::ForbiddenDescriptor => {
            "startup-failure.app-socket.subtype.descriptor-isolation.forbidden-descriptor"
        }
        ProcessGroupDescriptorScanError::UnsupportedDescriptor => {
            "startup-failure.app-socket.subtype.descriptor-isolation.unsupported-descriptor"
        }
        ProcessGroupDescriptorScanError::ObservationFailed => {
            "startup-failure.app-socket.subtype.descriptor-isolation.observation-failed"
        }
    }
}

#[cfg(test)]
const fn packaged_app_socket_provider_error_marker(error: ProviderLaunchError) -> &'static str {
    match error {
        ProviderLaunchError::InvalidArgument => {
            "startup-failure.app-socket.subtype.provider.invalid-argument"
        }
        ProviderLaunchError::AuthorityConsumed => {
            "startup-failure.app-socket.subtype.provider.authority-consumed"
        }
        ProviderLaunchError::SessionInUse => {
            "startup-failure.app-socket.subtype.provider.session-in-use"
        }
        ProviderLaunchError::ExecutableChanged => {
            "startup-failure.app-socket.subtype.provider.executable-changed"
        }
        ProviderLaunchError::SessionChanged => {
            "startup-failure.app-socket.subtype.provider.session-changed"
        }
        ProviderLaunchError::Storage => "startup-failure.app-socket.subtype.provider.storage",
        ProviderLaunchError::Timeout => "startup-failure.app-socket.subtype.provider.timeout",
    }
}

#[cfg(test)]
const fn packaged_app_socket_error_marker(error: AppSocketError) -> &'static str {
    match error {
        AppSocketError::UnsafeRuntime => "startup-failure.app-socket.subtype.socket.unsafe-runtime",
        AppSocketError::PathTooLong => "startup-failure.app-socket.subtype.socket.path-too-long",
        AppSocketError::Collision => "startup-failure.app-socket.subtype.socket.collision",
        AppSocketError::UnknownEntry => "startup-failure.app-socket.subtype.socket.unknown-entry",
        AppSocketError::SocketNotReady => {
            "startup-failure.app-socket.subtype.socket.socket-not-ready"
        }
        AppSocketError::UnsafeNode => "startup-failure.app-socket.subtype.socket.unsafe-node",
        #[cfg(target_os = "linux")]
        AppSocketError::IdentityLeaseUnavailable => {
            "startup-failure.app-socket.subtype.socket.identity-lease-unavailable"
        }
        AppSocketError::IdentityMismatch => {
            "startup-failure.app-socket.subtype.socket.identity-mismatch"
        }
        AppSocketError::SocketStillPresent => {
            "startup-failure.app-socket.subtype.socket.socket-still-present"
        }
        AppSocketError::AdoptionTimeout => {
            "startup-failure.app-socket.subtype.socket.adoption-timeout"
        }
        AppSocketError::Timeout => "startup-failure.app-socket.subtype.socket.timeout",
        AppSocketError::Cleanup => "startup-failure.app-socket.subtype.socket.cleanup",
    }
}

#[cfg(test)]
const fn packaged_app_socket_process_error_marker(error: ProcessError) -> &'static str {
    match error {
        ProcessError::Spawn { .. } => "startup-failure.app-socket.subtype.process.spawn",
        ProcessError::ProcessGroupReadback { .. } => {
            "startup-failure.app-socket.subtype.process.process-group-readback"
        }
        ProcessError::ProcessGroupMismatch { .. } => {
            "startup-failure.app-socket.subtype.process.process-group-mismatch"
        }
        ProcessError::SessionReadback { .. } => {
            "startup-failure.app-socket.subtype.process.session-readback"
        }
        ProcessError::SessionMismatch { .. } => {
            "startup-failure.app-socket.subtype.process.session-mismatch"
        }
        ProcessError::SessionStartupTimeout { .. } => {
            "startup-failure.app-socket.subtype.process.session-startup-timeout"
        }
        ProcessError::SpawnCleanupTimeout { .. } => {
            "startup-failure.app-socket.subtype.process.spawn-cleanup-timeout"
        }
        ProcessError::SpawnContainmentUnconfirmed { .. } => {
            "startup-failure.app-socket.subtype.process.spawn-containment-unconfirmed"
        }
        ProcessError::ReadinessUnavailable { .. } => {
            "startup-failure.app-socket.subtype.process.readiness-unavailable"
        }
        ProcessError::ParentLivenessUnavailable { .. } => {
            "startup-failure.app-socket.subtype.process.parent-liveness-unavailable"
        }
        ProcessError::ReadinessTimeout { .. } => {
            "startup-failure.app-socket.subtype.process.readiness-timeout"
        }
        ProcessError::ReadinessIo { .. } => {
            "startup-failure.app-socket.subtype.process.readiness-io"
        }
        ProcessError::InvalidReadiness { .. } => {
            "startup-failure.app-socket.subtype.process.invalid-readiness"
        }
        ProcessError::EarlyExit { .. } => "startup-failure.app-socket.subtype.process.early-exit",
        ProcessError::Signal { .. } => "startup-failure.app-socket.subtype.process.signal",
        ProcessError::ForwardedSignalMismatch { .. } => {
            "startup-failure.app-socket.subtype.process.forwarded-signal-mismatch"
        }
        ProcessError::SuspendTimeout { .. } => {
            "startup-failure.app-socket.subtype.process.suspend-timeout"
        }
        ProcessError::Wait { .. } => "startup-failure.app-socket.subtype.process.wait",
        ProcessError::WaitTimeout { .. } => {
            "startup-failure.app-socket.subtype.process.wait-timeout"
        }
        ProcessError::TuiOutputDrain { .. } => {
            "startup-failure.app-socket.subtype.process.tui-output-drain"
        }
        ProcessError::AppGracefulDrainUnconfirmed { stage, .. } => match stage {
            AppGracefulDrainFailureStage::PriorInvalid => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.prior-invalid"
            }
            AppGracefulDrainFailureStage::ExitedBeforeTerm => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.exited-before-term"
            }
            AppGracefulDrainFailureStage::StopTimeout => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.stop-timeout"
            }
            AppGracefulDrainFailureStage::ExitedWhileStopping => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.exited-while-stopping"
            }
            AppGracefulDrainFailureStage::InvalidDisposition => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.invalid-disposition"
            }
            AppGracefulDrainFailureStage::KillForbidden => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.kill-forbidden"
            }
            AppGracefulDrainFailureStage::WrongRetryPath => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.wrong-retry-path"
            }
            AppGracefulDrainFailureStage::MissingProof => {
                "startup-failure.app-socket.subtype.process.app-graceful-drain-unconfirmed.missing-proof"
            }
        },
        ProcessError::RoleMismatch { .. } => {
            "startup-failure.app-socket.subtype.process.role-mismatch"
        }
        ProcessError::RetryAfterResolution => {
            "startup-failure.app-socket.subtype.process.retry-after-resolution"
        }
        ProcessError::Deadline => "startup-failure.app-socket.subtype.process.deadline",
    }
}

#[cfg(test)]
impl StartupTuiAuthority {
    fn packaged_retention_markers(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Self::None => (
                Some("guardian-retained.startup-quiesce.tui.state.none"),
                None,
            ),
            Self::LaunchFailure(_) => (
                Some("guardian-retained.startup-quiesce.tui.state.launch-failure"),
                None,
            ),
            Self::ReadinessFailure(_) => (
                Some("guardian-retained.startup-quiesce.tui.state.readiness-failure"),
                None,
            ),
            Self::ReadinessContainmentFailure(failure) => (
                Some("guardian-retained.startup-quiesce.tui.state.readiness-containment-failure"),
                Some(packaged_startup_tui_process_error_marker(
                    failure.packaged_shutdown_error(),
                )),
            ),
            Self::Live(_) => (
                Some("guardian-retained.startup-quiesce.tui.state.live"),
                None,
            ),
            Self::ShutdownFailure(failure) => (
                Some("guardian-retained.startup-quiesce.tui.state.shutdown-failure"),
                Some(packaged_startup_tui_process_error_marker(failure.error())),
            ),
            Self::Clean(_) => (
                Some("guardian-retained.startup-quiesce.tui.state.clean"),
                None,
            ),
        }
    }
}

#[cfg(test)]
impl StartupAppAuthority {
    fn packaged_retention_markers(&self) -> (Option<&'static str>, Option<&'static str>) {
        let state = match self {
            Self::None => "guardian-retained.startup-quiesce.app.state.none",
            Self::RuntimeCreateFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.runtime-create-failure"
            }
            Self::Runtime(_) => "guardian-retained.startup-quiesce.app.state.runtime",
            Self::RuntimeCleanupFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.runtime-cleanup-failure"
            }
            Self::Reservation(_) => "guardian-retained.startup-quiesce.app.state.reservation",
            Self::ReservationFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.reservation-failure"
            }
            Self::LaunchFailure(_) => "guardian-retained.startup-quiesce.app.state.launch-failure",
            Self::LaunchContained(_) => {
                "guardian-retained.startup-quiesce.app.state.launch-contained"
            }
            Self::AdoptionFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.adoption-failure"
            }
            Self::AdoptionContainmentFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.adoption-containment-failure"
            }
            Self::AdoptionContained(_) => {
                "guardian-retained.startup-quiesce.app.state.adoption-contained"
            }
            Self::Session(_) => "guardian-retained.startup-quiesce.app.state.session",
            Self::Connected(_) => "guardian-retained.startup-quiesce.app.state.connected",
            Self::InMonitor => "guardian-retained.startup-quiesce.app.state.in-monitor",
            Self::StopFailure(_) => "guardian-retained.startup-quiesce.app.state.stop-failure",
            Self::Stopped(_) => "guardian-retained.startup-quiesce.app.state.stopped",
            Self::CleanupFailure(_) => {
                "guardian-retained.startup-quiesce.app.state.cleanup-failure"
            }
            Self::Clean(_) => "guardian-retained.startup-quiesce.app.state.clean",
        };
        let error = match self {
            Self::StopFailure(failure) => {
                Some(packaged_startup_app_process_error_marker(failure.error()))
            }
            _ => None,
        };
        (Some(state), error)
    }
}

impl StartupShutdownPhase {
    const fn next(self) -> Self {
        match self {
            Self::Tui => Self::Relay,
            Self::Relay => Self::Monitor,
            Self::Monitor => Self::AppStop,
            Self::AppStop => Self::TerminalQuiesce,
            Self::TerminalQuiesce => Self::AwaitingCoordinatorRestore,
            Self::AwaitingCoordinatorRestore => Self::RecoveryDisarm,
            Self::RecoveryDisarm => Self::RuntimeCleanup,
            Self::RuntimeCleanup => Self::BuildCleanup,
            Self::BuildCleanup | Self::Complete => Self::Complete,
        }
    }

    #[cfg(test)]
    const fn packaged_quiesce_phase(self) -> PackagedStartupQuiescePhase {
        match self {
            Self::Tui => PackagedStartupQuiescePhase::Tui,
            Self::Relay => PackagedStartupQuiescePhase::Relay,
            Self::Monitor => PackagedStartupQuiescePhase::Monitor,
            Self::AppStop => PackagedStartupQuiescePhase::AppStop,
            Self::TerminalQuiesce => PackagedStartupQuiescePhase::TerminalQuiesce,
            Self::AwaitingCoordinatorRestore => {
                PackagedStartupQuiescePhase::AwaitingCoordinatorRestore
            }
            Self::RecoveryDisarm => PackagedStartupQuiescePhase::RecoveryDisarm,
            Self::RuntimeCleanup => PackagedStartupQuiescePhase::RuntimeCleanup,
            Self::BuildCleanup => PackagedStartupQuiescePhase::BuildCleanup,
            Self::Complete => PackagedStartupQuiescePhase::Complete,
        }
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) struct StartupCleanupErrors(u16);

#[derive(Clone, Copy)]
enum StartupCleanupError {
    Tui = 1 << 0,
    Relay = 1 << 1,
    Monitor = 1 << 2,
    App = 1 << 3,
    TerminalQuiesce = 1 << 4,
    TerminalRestore = 1 << 5,
    RecoveryDisarm = 1 << 6,
    Runtime = 1 << 7,
    Build = 1 << 8,
    MissingAuthority = 1 << 9,
}

impl StartupCleanupErrors {
    fn record(&mut self, error: StartupCleanupError) {
        self.0 |= error as u16;
    }

    pub(super) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

struct PartialStartupOwner {
    build: StartupBuildAuthority,
    app: StartupAppAuthority,
    monitor: StartupMonitorAuthority,
    relay: StartupRelayAuthority,
    tui: StartupTuiAuthority,
    terminal: StartupTerminalAuthority,
    phase: StartupShutdownPhase,
    error: SupervisedStartupError,
    cleanup_errors: StartupCleanupErrors,
    worker_join_status: WorkerJoinStatus,
    terminal_reportable: bool,
}

enum StartupFailureOwner {
    Partial(Box<PartialStartupOwner>),
    Session(Box<SessionStartupFailure>),
}

/// Failure from any pre-active startup edge. No component owner is exposed to
/// callers; cleanup can only advance through the reviewed phase machine.
#[must_use = "startup failure retains terminal and provider cleanup authority"]
pub(super) struct SupervisedStartupFailure {
    owner: StartupFailureOwner,
    error: SupervisedStartupError,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PackagedRuntimeFailureStage {
    Create,
    Layout,
}

impl SupervisedStartupFailure {
    pub(super) const fn error(&self) -> SupervisedStartupError {
        self.error
    }

    #[cfg(test)]
    pub(super) fn packaged_runtime_failure_stage(&self) -> Option<PackagedRuntimeFailureStage> {
        if self.error != SupervisedStartupError::Runtime {
            return None;
        }
        match &self.owner {
            StartupFailureOwner::Partial(owner) => match &owner.app {
                StartupAppAuthority::RuntimeCreateFailure(_) => {
                    Some(PackagedRuntimeFailureStage::Create)
                }
                StartupAppAuthority::Runtime(_) => Some(PackagedRuntimeFailureStage::Layout),
                _ => None,
            },
            StartupFailureOwner::Session(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_tui_launch_failure_classification(
        &self,
    ) -> Option<PackagedRemoteTuiLaunchFailureClassification> {
        if self.error != SupervisedStartupError::TuiLaunch {
            return None;
        }
        match &self.owner {
            StartupFailureOwner::Partial(owner) => match &owner.tui {
                StartupTuiAuthority::LaunchFailure(failure) => {
                    Some(failure.packaged_classification())
                }
                _ => None,
            },
            StartupFailureOwner::Session(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_app_socket_failure_marker(&self) -> Option<&'static str> {
        if self.error != SupervisedStartupError::AppSocket {
            return None;
        }
        match &self.owner {
            StartupFailureOwner::Partial(owner) => match &owner.app {
                StartupAppAuthority::AdoptionFailure(failure) => {
                    Some(packaged_app_socket_failure_marker(failure.error()))
                }
                _ => None,
            },
            StartupFailureOwner::Session(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_compatibility_failure_marker(&self) -> Option<&'static str> {
        if self.error != SupervisedStartupError::Compatibility {
            return None;
        }
        match &self.owner {
            StartupFailureOwner::Partial(owner) => match &owner.build {
                StartupBuildAuthority::CompatibilityFailure(failure) => {
                    Some(packaged_compatibility_failure_marker(failure.error()))
                }
                _ => None,
            },
            StartupFailureOwner::Session(_) => None,
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_compatibility_failed_before_child_start(&self) -> bool {
        if self.error != SupervisedStartupError::Compatibility {
            return false;
        }
        match &self.owner {
            StartupFailureOwner::Partial(owner) => matches!(
                (
                    &owner.build,
                    &owner.app,
                    &owner.monitor,
                    &owner.relay,
                    &owner.tui,
                ),
                (
                    StartupBuildAuthority::CompatibilityFailure(_),
                    StartupAppAuthority::None,
                    StartupMonitorAuthority::None,
                    StartupRelayAuthority::None,
                    StartupTuiAuthority::None,
                )
            ),
            StartupFailureOwner::Session(_) => false,
        }
    }
}

impl fmt::Debug for SupervisedStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.owner {
            StartupFailureOwner::Partial(_) => "partial",
            StartupFailureOwner::Session(_) => "assembled",
        };
        formatter
            .debug_struct("SupervisedStartupFailure")
            .field("error", &self.error)
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

fn partial_failure(
    build: StartupBuildAuthority,
    app: StartupAppAuthority,
    monitor: StartupMonitorAuthority,
    relay: StartupRelayAuthority,
    tui: StartupTuiAuthority,
    terminal: StartupTerminalAuthority,
    error: SupervisedStartupError,
) -> SupervisedStartupFailure {
    SupervisedStartupFailure {
        owner: StartupFailureOwner::Partial(Box::new(PartialStartupOwner {
            build,
            app,
            monitor,
            relay,
            tui,
            terminal,
            phase: StartupShutdownPhase::Tui,
            error,
            cleanup_errors: StartupCleanupErrors::default(),
            worker_join_status: WorkerJoinStatus::NotStarted,
            terminal_reportable: true,
        })),
        error,
    }
}

fn deadline_error(bounds: ProductionStartupBounds) -> Option<SupervisedStartupError> {
    (Instant::now() >= bounds.deadline).then_some(SupervisedStartupError::Deadline)
}

fn ensure_descriptor_stage_before(
    deadline: Instant,
) -> Result<(), calcifer_unix_child_fd::ProcessGroupDescriptorScanError> {
    if Instant::now() >= deadline {
        Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline)
    } else {
        Ok(())
    }
}

fn verify_app_descriptor_inventory<'source>(
    child: &mut AppServerChild,
    build: &'source PinnedSessionBuild,
    reservation: &'source AppSocketReservation,
    terminal: &'source StartupTerminalAuthority,
    lifecycle: &'source impl StartupLifecycleReporter,
    deadline: Instant,
) -> Result<VerifiedAppDescriptorIsolation, calcifer_unix_child_fd::ProcessGroupDescriptorScanError>
{
    let mut forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
    ensure_descriptor_stage_before(deadline)?;
    build
        .append_forbidden_descriptors(&mut forbidden)
        .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
    ensure_descriptor_stage_before(deadline)?;
    reservation
        .append_forbidden_descriptors(&mut forbidden)
        .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
    ensure_descriptor_stage_before(deadline)?;
    terminal
        .append_forbidden_descriptors(&mut forbidden)
        .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
    ensure_descriptor_stage_before(deadline)?;
    lifecycle
        .append_forbidden_descriptors(&mut forbidden)
        .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
    ensure_descriptor_stage_before(deadline)?;
    child.verify_descriptor_isolation(&forbidden, deadline)
}

#[allow(clippy::too_many_arguments)]
fn await_tui_with_descriptor_inventory<'source>(
    pending: PendingRemoteTui,
    build: &'source PinnedSessionBuild,
    monitor: &'source SessionMonitor,
    relay: &'source ExactRelaySession,
    terminal: &'source StartupTerminalAuthority,
    lifecycle: &'source impl StartupLifecycleReporter,
    deadline: Instant,
) -> Result<ReadyRemoteTui, Box<RemoteTuiReadinessFailure>> {
    let inventory = (|| {
        let mut forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        ensure_descriptor_stage_before(deadline)?;
        build
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
        ensure_descriptor_stage_before(deadline)?;
        monitor
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
        ensure_descriptor_stage_before(deadline)?;
        relay
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
        ensure_descriptor_stage_before(deadline)?;
        terminal
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
        ensure_descriptor_stage_before(deadline)?;
        lifecycle
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
        ensure_descriptor_stage_before(deadline)?;
        Ok::<_, calcifer_unix_child_fd::ProcessGroupDescriptorScanError>(forbidden)
    })();

    match inventory {
        Ok(forbidden) => pending.await_ready(&forbidden, deadline),
        Err(error) => Err(pending.retain_descriptor_isolation_failure(error)),
    }
}

/// Runs the complete post-terminal-arm production startup. Raw profile homes,
/// socket addresses, commands, and thread IDs cannot enter this function; all
/// such identity is sealed in `authorization`.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_supervised_session(
    authorization: ProviderLaunchAuthorization,
    codex_executable: &Path,
    runtime_parent: &Path,
    terminal_endpoint: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    initial_size: TerminalSize,
    bounds: ProductionStartupBounds,
    lifecycle: &mut impl StartupLifecycleReporter,
) -> Result<AwaitingReadySupervisedSession, SupervisedStartupFailure> {
    start_supervised_session_core(
        authorization,
        codex_executable,
        runtime_parent,
        terminal_endpoint,
        recovery,
        snapshot,
        initial_size,
        bounds,
        lifecycle,
        StartupCompatibility::Production {
            _lifetime: std::marker::PhantomData,
        },
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn start_supervised_session_with_test_compatibility(
    authorization: ProviderLaunchAuthorization,
    codex_executable: &Path,
    compatibility_stage_parent: &Path,
    runtime_parent: &Path,
    terminal_endpoint: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    initial_size: TerminalSize,
    bounds: ProductionStartupBounds,
    lifecycle: &mut impl StartupLifecycleReporter,
) -> Result<AwaitingReadySupervisedSession, SupervisedStartupFailure> {
    start_supervised_session_core(
        authorization,
        codex_executable,
        runtime_parent,
        terminal_endpoint,
        recovery,
        snapshot,
        initial_size,
        bounds,
        lifecycle,
        StartupCompatibility::Fixture {
            stage_parent: compatibility_stage_parent,
        },
    )
}

#[derive(Clone, Copy)]
enum StartupCompatibility<'a> {
    Production {
        _lifetime: std::marker::PhantomData<&'a Path>,
    },
    #[cfg(test)]
    Fixture { stage_parent: &'a Path },
}

#[allow(clippy::too_many_arguments)]
fn start_supervised_session_core(
    authorization: ProviderLaunchAuthorization,
    codex_executable: &Path,
    runtime_parent: &Path,
    terminal_endpoint: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    initial_size: TerminalSize,
    bounds: ProductionStartupBounds,
    lifecycle: &mut impl StartupLifecycleReporter,
    compatibility: StartupCompatibility<'_>,
) -> Result<AwaitingReadySupervisedSession, SupervisedStartupFailure> {
    let terminal = StartupTerminalAuthority::new(terminal_endpoint, recovery, snapshot);
    if terminal.validate().is_err() {
        return Err(partial_failure(
            StartupBuildAuthority::Authorized(authorization),
            StartupAppAuthority::None,
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::Terminal,
        ));
    }
    if let Some(error) = deadline_error(bounds) {
        return Err(partial_failure(
            StartupBuildAuthority::Authorized(authorization),
            StartupAppAuthority::None,
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            error,
        ));
    }

    let compatibility_timeout = bounds.remaining_timeout(bounds.compatibility_timeout);
    if compatibility_timeout.is_zero() {
        return Err(partial_failure(
            StartupBuildAuthority::Authorized(authorization),
            StartupAppAuthority::None,
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::Deadline,
        ));
    }
    let verified = match compatibility {
        StartupCompatibility::Production { .. } => {
            verify_authorized_compatibility(authorization, codex_executable, compatibility_timeout)
        }
        #[cfg(test)]
        StartupCompatibility::Fixture { stage_parent } => verify_authorized_test_compatibility(
            authorization,
            codex_executable,
            stage_parent,
            compatibility_timeout,
        ),
    };
    let build = match verified {
        Ok(build) => build,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::CompatibilityFailure(failure),
                StartupAppAuthority::None,
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::Compatibility,
            ));
        }
    };
    continue_supervised_session(
        Box::new(build),
        runtime_parent,
        terminal,
        initial_size,
        bounds,
        lifecycle,
    )
}

/// Private post-compatibility continuation. Its build argument can be minted
/// only by the production Codex compatibility capability or by a cfg(test)
/// sealed test capability; no command, path, profile, or thread string can
/// bypass guardian admission and construct it.
#[allow(clippy::too_many_arguments)]
fn continue_supervised_session(
    build: Box<PinnedSessionBuild>,
    runtime_parent: &Path,
    terminal: StartupTerminalAuthority,
    initial_size: TerminalSize,
    bounds: ProductionStartupBounds,
    lifecycle: &mut impl StartupLifecycleReporter,
) -> Result<AwaitingReadySupervisedSession, SupervisedStartupFailure> {
    if let Some(error) = deadline_error(bounds) {
        return Err(partial_failure(
            StartupBuildAuthority::Live(build),
            StartupAppAuthority::None,
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            error,
        ));
    }

    let runtime = match PrivateRuntime::create(runtime_parent) {
        Ok(runtime) => runtime,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::RuntimeCreateFailure(Box::new(failure)),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::Runtime,
            ));
        }
    };
    let layout = match runtime.reserve_supervised_layout() {
        Ok(layout) => layout,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::Runtime(Box::new(failure.into_runtime())),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::Runtime,
            ));
        }
    };
    let (reservation, route) = layout.into_parts();
    let app_command = match build.app_server_command_for_reservation(&reservation, bounds.deadline)
    {
        Ok(command) => command,
        Err(_) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::Reservation(Box::new(reservation)),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::AppPlan,
            ));
        }
    };
    let (mut app_child, reservation) =
        match app_command.launch_with_reservation(reservation, bounds.deadline) {
            Ok(started) => started,
            Err(failure) => {
                return Err(partial_failure(
                    StartupBuildAuthority::Live(build),
                    StartupAppAuthority::LaunchFailure(failure),
                    StartupMonitorAuthority::None,
                    StartupRelayAuthority::None,
                    StartupTuiAuthority::None,
                    terminal,
                    SupervisedStartupError::AppLaunch,
                ));
            }
        };
    let descriptor_isolation = match verify_app_descriptor_inventory(
        &mut app_child,
        &build,
        &reservation,
        &terminal,
        lifecycle,
        bounds.deadline,
    ) {
        Ok(proof) => proof,
        Err(error) => {
            let failure = app_child.retain_descriptor_isolation_failure(reservation, error);
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::AdoptionFailure(failure),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::AppSocket,
            ));
        }
    };
    let app_containment = app_child.containment();
    let (app_child, reservation) = match report_child_started_or_retain(
        (app_child, reservation),
        app_containment,
        lifecycle,
        bounds.deadline,
    ) {
        Ok(owner) => owner,
        Err((app_child, reservation)) => {
            let app =
                match app_child.adopt_socket(reservation, descriptor_isolation, bounds.deadline) {
                    Ok(app) => StartupAppAuthority::Session(Box::new(app)),
                    Err(failure) => StartupAppAuthority::AdoptionFailure(failure),
                };
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                app,
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::Lifecycle,
            ));
        }
    };
    let app = match app_child.adopt_socket(reservation, descriptor_isolation, bounds.deadline) {
        Ok(app) => app,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::AdoptionFailure(failure),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::AppSocket,
            ));
        }
    };
    let connected = match app.connect_monitor(bounds.deadline) {
        Ok(connected) => connected,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::Session(Box::new(failure.into_session())),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::MonitorConnect,
            ));
        }
    };
    let monitor = match SessionMonitor::spawn(connected) {
        Ok(monitor) => monitor,
        Err(failure) => {
            let failure: Box<SessionMonitorStartFailure> = failure;
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::Connected(Box::new(failure.into_session())),
                StartupMonitorAuthority::None,
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::MonitorStart,
            ));
        }
    };
    let monitor = Box::new(monitor);

    let pty = match PtyOwner::open(initial_size) {
        Ok(pty) => pty,
        Err(_) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::TuiPty,
            ));
        }
    };
    let relay_plan = match build.exact_relay_plan(route, bounds.deadline) {
        Ok(plan) => plan,
        Err(_) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::RelayPlan,
            ));
        }
    };
    let tui_command = match relay_plan.remote_tui_command(bounds.deadline) {
        Ok(command) => command,
        Err(_) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::TuiPlan,
            ));
        }
    };
    let tui_command = match tui_command.into_launch_command(bounds.deadline) {
        Ok(command) => command,
        Err(_) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::TuiPlan,
            ));
        }
    };
    // Complete every potentially expensive executable and launcher check
    // before arming the relay's absolute readiness deadline. The prepared
    // typestate crosses only the short PTY/spawn boundary below.
    let prepared_tui = match tui_command.prepare(bounds.deadline) {
        Ok(prepared) => prepared,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::LaunchFailure(failure),
                terminal,
                SupervisedStartupError::TuiLaunch,
            ));
        }
    };
    let (relay, pending_tui) = match cross_relay_tui_start_boundary_at(
        bounds,
        Instant::now(),
        |relay_deadline| relay_plan.spawn_until(relay_deadline, bounds.deadline),
        || prepared_tui.launch(pty, bounds.deadline),
    ) {
        Ok(started) => started,
        Err(RelayTuiStartBoundaryFailure::Deadline) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::None,
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::Deadline,
            ));
        }
        Err(RelayTuiStartBoundaryFailure::Relay(failure)) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::StartFailure(failure),
                StartupTuiAuthority::None,
                terminal,
                SupervisedStartupError::RelayStart,
            ));
        }
        Err(RelayTuiStartBoundaryFailure::Tui { relay, error }) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::Live(Box::new(relay)),
                StartupTuiAuthority::LaunchFailure(error),
                terminal,
                SupervisedStartupError::TuiLaunch,
            ));
        }
    };
    let relay = Box::new(relay);
    let tui_containment = pending_tui.containment();
    let pending_tui = match report_child_started_or_retain(
        pending_tui,
        tui_containment,
        lifecycle,
        bounds.deadline,
    ) {
        Ok(pending) => pending,
        Err(pending) => {
            let tui = match await_tui_with_descriptor_inventory(
                pending,
                &build,
                &monitor,
                &relay,
                &terminal,
                lifecycle,
                bounds.deadline,
            ) {
                Ok(tui) => StartupTuiAuthority::Live(Box::new(tui)),
                Err(failure) => StartupTuiAuthority::ReadinessFailure(failure),
            };
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::Live(relay),
                tui,
                terminal,
                SupervisedStartupError::Lifecycle,
            ));
        }
    };
    let tui = match await_tui_with_descriptor_inventory(
        pending_tui,
        &build,
        &monitor,
        &relay,
        &terminal,
        lifecycle,
        bounds.deadline,
    ) {
        Ok(tui) => tui,
        Err(failure) => {
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::Live(relay),
                StartupTuiAuthority::ReadinessFailure(failure),
                terminal,
                SupervisedStartupError::TuiReadiness,
            ));
        }
    };
    let terminal = match terminal.into_generation(tui) {
        Ok(terminal) => terminal,
        Err(failure) => {
            let (terminal, tui, _) = *failure;
            return Err(partial_failure(
                StartupBuildAuthority::Live(build),
                StartupAppAuthority::InMonitor,
                StartupMonitorAuthority::Live(monitor),
                StartupRelayAuthority::Live(relay),
                StartupTuiAuthority::Live(Box::new(tui)),
                terminal,
                SupervisedStartupError::Terminal,
            ));
        }
    };

    match assemble_started_session(*build, *monitor, *relay, terminal, bounds.deadline) {
        Ok(session) => Ok(session),
        Err(failure) => {
            let error = SupervisedStartupError::SessionReadiness(failure.error());
            Err(SupervisedStartupFailure {
                owner: StartupFailureOwner::Session(failure),
                error,
            })
        }
    }
}

/// Relative bounds for one startup-abort retry. `containment_timeout` applies
/// to owners created before the normal live-session shutdown aggregate
/// existed; each sequential phase derives a fresh absolute deadline only when
/// it reaches that edge. The remaining values retain the same meanings as
/// session shutdown.
#[derive(Clone, Copy)]
pub(super) struct StartupShutdownBounds {
    pub(super) containment_timeout: Duration,
    pub(super) session: SessionShutdownBounds,
}

impl StartupShutdownBounds {
    fn containment_deadline(self) -> Instant {
        self.containment_deadline_at(Instant::now())
    }

    fn containment_deadline_at(self, now: Instant) -> Instant {
        now.checked_add(self.containment_timeout).unwrap_or(now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupStep {
    Advanced,
    Retained,
}

trait StartupPhaseBackend {
    fn phase(&self) -> StartupShutdownPhase;
    fn set_phase(&mut self, phase: StartupShutdownPhase);
    fn step(&mut self, phase: StartupShutdownPhase, bounds: StartupShutdownBounds) -> StartupStep;
}

fn drive_startup_phases(
    backend: &mut impl StartupPhaseBackend,
    stop_before: StartupShutdownPhase,
    bounds: StartupShutdownBounds,
) -> StartupStep {
    while backend.phase() != stop_before {
        let phase = backend.phase();
        if phase == StartupShutdownPhase::Complete {
            return StartupStep::Retained;
        }
        match backend.step(phase, bounds) {
            StartupStep::Advanced => backend.set_phase(phase.next()),
            StartupStep::Retained => return StartupStep::Retained,
        }
    }
    StartupStep::Advanced
}

impl PartialStartupOwner {
    fn run_to_restore(
        mut self: Box<Self>,
        bounds: StartupShutdownBounds,
    ) -> Result<Box<Self>, Box<Self>> {
        if drive_startup_phases(
            self.as_mut(),
            StartupShutdownPhase::AwaitingCoordinatorRestore,
            bounds,
        ) == StartupStep::Retained
        {
            return Err(self);
        }
        Ok(self)
    }

    fn run_after_restore(
        mut self: Box<Self>,
        bounds: StartupShutdownBounds,
    ) -> Result<StartupCleanupReport, Box<Self>> {
        if drive_startup_phases(self.as_mut(), StartupShutdownPhase::Complete, bounds)
            == StartupStep::Retained
        {
            return Err(self);
        }
        if !matches!(self.app, StartupAppAuthority::Clean(_))
            || !matches!(self.tui, StartupTuiAuthority::Clean(_))
        {
            return Err(self);
        }
        let Self {
            build,
            app,
            monitor,
            relay,
            tui,
            terminal,
            phase,
            error,
            cleanup_errors,
            worker_join_status,
            terminal_reportable,
        } = *self;
        if !matches!(build, StartupBuildAuthority::Clean)
            || !matches!(monitor, StartupMonitorAuthority::None)
            || !matches!(relay, StartupRelayAuthority::None)
            || phase != StartupShutdownPhase::Complete
        {
            std::process::abort();
        }
        terminal.authorize_post_restore_release();
        let StartupAppAuthority::Clean(provider_release) = app else {
            std::process::abort();
        };
        let StartupTuiAuthority::Clean(tui_outcome) = tui else {
            std::process::abort();
        };
        Ok(StartupCleanupReport {
            startup_error: error,
            details: StartupCleanupDetails::Partial(PartialStartupCleanupDetails {
                cleanup_errors,
                provider_release,
                tui_outcome,
                worker_join_status,
                terminal_reportable,
            }),
        })
    }

    fn quiesce_tui(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        let authority = std::mem::replace(&mut self.tui, StartupTuiAuthority::None);
        match authority {
            StartupTuiAuthority::None => {
                self.tui = StartupTuiAuthority::Clean(None);
                StartupStep::Advanced
            }
            StartupTuiAuthority::LaunchFailure(failure) => {
                match failure.resolve(bounds.containment_deadline()) {
                    Ok(resolution) => {
                        self.terminal_reportable &= resolution.terminal_reportable();
                        drop(resolution);
                        self.tui = StartupTuiAuthority::Clean(None);
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Tui);
                        self.tui = StartupTuiAuthority::LaunchFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupTuiAuthority::ReadinessFailure(failure) => {
                match failure.contain(bounds.session.tui_grace, bounds.session.tui_forced) {
                    Ok(resolution) => {
                        self.tui = StartupTuiAuthority::Clean(Some(resolution.outcome()));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Tui);
                        self.tui = StartupTuiAuthority::ReadinessContainmentFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupTuiAuthority::ReadinessContainmentFailure(failure) => {
                match failure.retry(bounds.session.tui_grace, bounds.session.tui_forced) {
                    Ok(resolution) => {
                        self.tui = StartupTuiAuthority::Clean(Some(resolution.outcome()));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Tui);
                        self.tui = StartupTuiAuthority::ReadinessContainmentFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupTuiAuthority::Live(tui) => {
                match (*tui).shutdown(bounds.session.tui_grace, bounds.session.tui_forced) {
                    Ok(outcome) => {
                        self.tui = StartupTuiAuthority::Clean(Some(outcome));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Tui);
                        self.tui = StartupTuiAuthority::ShutdownFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupTuiAuthority::ShutdownFailure(failure) => {
                match failure.retry(bounds.session.tui_grace, bounds.session.tui_forced) {
                    Ok(outcome) => {
                        self.tui = StartupTuiAuthority::Clean(Some(outcome));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Tui);
                        self.tui = StartupTuiAuthority::ShutdownFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            clean @ StartupTuiAuthority::Clean(_) => {
                self.tui = clean;
                StartupStep::Advanced
            }
        }
    }

    fn quiesce_relay(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        let authority = std::mem::replace(&mut self.relay, StartupRelayAuthority::None);
        match authority {
            StartupRelayAuthority::None => StartupStep::Advanced,
            StartupRelayAuthority::StartFailure(failure) => {
                match failure.resolve_for_startup_abort() {
                    Ok(resolution) => {
                        let _ = resolution.release();
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Relay);
                        self.relay = StartupRelayAuthority::StartFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupRelayAuthority::Live(relay) => {
                match (*relay).shutdown(bounds.session.relay_deadline()) {
                    Ok(complete) => {
                        complete.release();
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Relay);
                        match failure.try_resolve_without_retry() {
                            Ok(resolution) => {
                                let _prior_error = resolution.release();
                                StartupStep::Advanced
                            }
                            Err(failure) => {
                                self.relay = StartupRelayAuthority::ShutdownFailure(failure);
                                StartupStep::Retained
                            }
                        }
                    }
                }
            }
            StartupRelayAuthority::ShutdownFailure(failure) => {
                match failure.resolve(bounds.session.relay_deadline()) {
                    Ok(resolution) => {
                        let _ = resolution.release();
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Relay);
                        self.relay = StartupRelayAuthority::ShutdownFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
        }
    }

    fn quiesce_monitor(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        let authority = std::mem::replace(&mut self.monitor, StartupMonitorAuthority::None);
        match authority {
            StartupMonitorAuthority::None => {
                if matches!(self.app, StartupAppAuthority::InMonitor) {
                    self.cleanup_errors
                        .record(StartupCleanupError::MissingAuthority);
                    StartupStep::Retained
                } else {
                    StartupStep::Advanced
                }
            }
            StartupMonitorAuthority::Live(monitor) => {
                match (*monitor).shutdown(bounds.session.monitor_deadline()) {
                    Ok(complete) => {
                        self.worker_join_status = WorkerJoinStatus::JoinedClean;
                        match complete.into_session() {
                            Some(session) => {
                                self.app = StartupAppAuthority::Connected(Box::new(session));
                                StartupStep::Advanced
                            }
                            None => {
                                self.cleanup_errors
                                    .record(StartupCleanupError::MissingAuthority);
                                self.app = StartupAppAuthority::None;
                                StartupStep::Retained
                            }
                        }
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Monitor);
                        match failure.into_owner() {
                            SessionMonitorShutdownOwner::PendingJoin(monitor) => {
                                self.monitor = StartupMonitorAuthority::Live(monitor);
                                StartupStep::Retained
                            }
                            SessionMonitorShutdownOwner::JoinedFailed(session) => {
                                self.worker_join_status = WorkerJoinStatus::JoinedFailed;
                                match *session {
                                    Some(session) => {
                                        self.app =
                                            StartupAppAuthority::Connected(Box::new(session));
                                        StartupStep::Advanced
                                    }
                                    None => {
                                        self.cleanup_errors
                                            .record(StartupCleanupError::MissingAuthority);
                                        self.app = StartupAppAuthority::None;
                                        StartupStep::Retained
                                    }
                                }
                            }
                            SessionMonitorShutdownOwner::JoinedPanicked(session) => {
                                self.worker_join_status = WorkerJoinStatus::JoinedPanicked;
                                match *session {
                                    Some(session) => {
                                        self.app =
                                            StartupAppAuthority::Connected(Box::new(session));
                                        StartupStep::Advanced
                                    }
                                    None => {
                                        self.cleanup_errors
                                            .record(StartupCleanupError::MissingAuthority);
                                        self.app = StartupAppAuthority::None;
                                        StartupStep::Retained
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn stop_app(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        if !self.resolve_compatibility(bounds.containment_deadline()) {
            return StartupStep::Retained;
        }
        let authority = std::mem::replace(&mut self.app, StartupAppAuthority::None);
        match authority {
            authority @ (StartupAppAuthority::None
            | StartupAppAuthority::RuntimeCreateFailure(_)
            | StartupAppAuthority::Runtime(_)
            | StartupAppAuthority::RuntimeCleanupFailure(_)
            | StartupAppAuthority::Reservation(_)
            | StartupAppAuthority::ReservationFailure(_)
            | StartupAppAuthority::LaunchContained(_)
            | StartupAppAuthority::AdoptionContained(_)
            | StartupAppAuthority::Stopped(_)
            | StartupAppAuthority::CleanupFailure(_)
            | StartupAppAuthority::Clean(_)) => {
                self.app = authority;
                StartupStep::Advanced
            }
            StartupAppAuthority::LaunchFailure(failure) => {
                match failure.contain_child(bounds.containment_deadline()) {
                    Ok(contained) => {
                        self.app = StartupAppAuthority::LaunchContained(Box::new(contained));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::LaunchFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::AdoptionFailure(failure) => {
                match (*failure).contain_child(bounds.session.app_grace, bounds.session.app_forced)
                {
                    Ok(contained) => {
                        self.app = StartupAppAuthority::AdoptionContained(Box::new(contained));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::AdoptionContainmentFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::AdoptionContainmentFailure(failure) => {
                match (*failure).retry(bounds.session.app_grace, bounds.session.app_forced) {
                    Ok(contained) => {
                        self.app = StartupAppAuthority::AdoptionContained(Box::new(contained));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::AdoptionContainmentFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::Session(session) => {
                match (*session).stop(bounds.session.app_grace, bounds.session.app_forced) {
                    Ok(stopped) => {
                        self.app = StartupAppAuthority::Stopped(Box::new(stopped));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::StopFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::Connected(session) => {
                match (*session)
                    .stop_app_server(bounds.session.app_grace, bounds.session.app_forced)
                {
                    Ok(stopped) => {
                        self.app = StartupAppAuthority::Stopped(Box::new(stopped));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::StopFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::StopFailure(failure) => {
                match failure.retry(bounds.session.app_grace, bounds.session.app_forced) {
                    Ok(stopped) => {
                        self.app = StartupAppAuthority::Stopped(Box::new(stopped));
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::App);
                        self.app = StartupAppAuthority::StopFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::InMonitor => {
                self.app = StartupAppAuthority::InMonitor;
                self.cleanup_errors
                    .record(StartupCleanupError::MissingAuthority);
                StartupStep::Retained
            }
        }
    }

    fn resolve_compatibility(&mut self, deadline: Instant) -> bool {
        let authority = std::mem::replace(&mut self.build, StartupBuildAuthority::Clean);
        match authority {
            StartupBuildAuthority::CompatibilityFailure(failure) => match failure.resolve(deadline)
            {
                Ok(resolution) => {
                    self.build = StartupBuildAuthority::CompatibilityResolved(resolution);
                    true
                }
                Err(failure) => {
                    self.cleanup_errors.record(StartupCleanupError::Build);
                    self.build = StartupBuildAuthority::CompatibilityFailure(failure);
                    false
                }
            },
            authority => {
                self.build = authority;
                true
            }
        }
    }

    fn quiesce_terminal(&mut self) -> StartupStep {
        let Some(endpoint) = self.terminal.endpoint.take() else {
            return StartupStep::Advanced;
        };
        match endpoint.shutdown(TerminalShutdown::Both) {
            Ok(()) => {
                drop(endpoint);
                StartupStep::Advanced
            }
            Err(_) => {
                self.cleanup_errors
                    .record(StartupCleanupError::TerminalQuiesce);
                self.terminal.endpoint = Some(endpoint);
                StartupStep::Retained
            }
        }
    }

    fn disarm_recovery(&mut self) -> StartupStep {
        let Some(authority) = self.terminal.recovery.take() else {
            self.cleanup_errors
                .record(StartupCleanupError::MissingAuthority);
            return StartupStep::Retained;
        };
        match authority {
            StartupRecoveryAuthority::CoordinatorRestored { recovery, _proof } => {
                match recovery.disarm() {
                    Ok(RecoveryDisarmOutcome::Disarmed(proof)) => {
                        self.terminal.recovery = Some(StartupRecoveryAuthority::Disarmed(proof));
                        StartupStep::Advanced
                    }
                    Ok(RecoveryDisarmOutcome::Unconfirmed(evidence)) => {
                        self.cleanup_errors
                            .record(StartupCleanupError::RecoveryDisarm);
                        self.terminal.recovery =
                            Some(StartupRecoveryAuthority::DisarmUnconfirmed(evidence));
                        StartupStep::Retained
                    }
                    Err(failure) => {
                        self.cleanup_errors
                            .record(StartupCleanupError::RecoveryDisarm);
                        self.terminal.recovery =
                            Some(StartupRecoveryAuthority::CoordinatorRestored {
                                recovery: failure.into_recovery(),
                                _proof,
                            });
                        StartupStep::Retained
                    }
                }
            }
            StartupRecoveryAuthority::FallbackRestored { recovery, _proof } => {
                match recovery.disarm() {
                    Ok(RecoveryDisarmOutcome::Disarmed(proof)) => {
                        self.terminal.recovery = Some(StartupRecoveryAuthority::Disarmed(proof));
                        StartupStep::Advanced
                    }
                    Ok(RecoveryDisarmOutcome::Unconfirmed(evidence)) => {
                        self.cleanup_errors
                            .record(StartupCleanupError::RecoveryDisarm);
                        self.terminal.recovery =
                            Some(StartupRecoveryAuthority::DisarmUnconfirmed(evidence));
                        StartupStep::Retained
                    }
                    Err(failure) => {
                        self.cleanup_errors
                            .record(StartupCleanupError::RecoveryDisarm);
                        self.terminal.recovery = Some(StartupRecoveryAuthority::FallbackRestored {
                            recovery: failure.into_recovery(),
                            _proof,
                        });
                        StartupStep::Retained
                    }
                }
            }
            StartupRecoveryAuthority::DisarmUnconfirmed(evidence) => match evidence.retry_once() {
                RecoveryDisarmOutcome::Disarmed(proof) => {
                    self.terminal.recovery = Some(StartupRecoveryAuthority::Disarmed(proof));
                    StartupStep::Advanced
                }
                RecoveryDisarmOutcome::Unconfirmed(evidence) => {
                    self.cleanup_errors
                        .record(StartupCleanupError::RecoveryDisarm);
                    self.terminal.recovery =
                        Some(StartupRecoveryAuthority::DisarmUnconfirmed(evidence));
                    StartupStep::Retained
                }
            },
            disarmed @ StartupRecoveryAuthority::Disarmed(_) => {
                self.terminal.recovery = Some(disarmed);
                StartupStep::Advanced
            }
            armed @ StartupRecoveryAuthority::Armed(_) => {
                self.terminal.recovery = Some(armed);
                self.cleanup_errors
                    .record(StartupCleanupError::TerminalRestore);
                StartupStep::Retained
            }
        }
    }

    fn cleanup_runtime(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        let authority = std::mem::replace(&mut self.app, StartupAppAuthority::None);
        match authority {
            StartupAppAuthority::None => {
                self.app = StartupAppAuthority::Clean(provider_never_started());
                StartupStep::Advanced
            }
            StartupAppAuthority::RuntimeCreateFailure(failure) => {
                if !failure.has_created_path() {
                    self.app = StartupAppAuthority::Clean(provider_never_started());
                    return StartupStep::Advanced;
                }
                match (*failure).cleanup_created() {
                    Ok(_) => {
                        self.app = StartupAppAuthority::Clean(provider_never_started());
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::RuntimeCreateFailure(Box::new(failure));
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::Runtime(runtime) => match (*runtime).cleanup() {
                Ok(_) => {
                    self.app = StartupAppAuthority::Clean(provider_never_started());
                    StartupStep::Advanced
                }
                Err(failure) => {
                    self.cleanup_errors.record(StartupCleanupError::Runtime);
                    self.app = StartupAppAuthority::RuntimeCleanupFailure(Box::new(failure));
                    StartupStep::Retained
                }
            },
            StartupAppAuthority::RuntimeCleanupFailure(failure) => {
                match failure.into_runtime().cleanup() {
                    Ok(_) => {
                        self.app = StartupAppAuthority::Clean(provider_never_started());
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::RuntimeCleanupFailure(Box::new(failure));
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::Reservation(reservation) => self.cleanup_reservation(*reservation),
            StartupAppAuthority::ReservationFailure(failure) => {
                self.cleanup_reservation(failure.into_reservation())
            }
            StartupAppAuthority::LaunchFailure(failure) => {
                match failure.contain_child(bounds.containment_deadline()) {
                    Ok(contained) => self.cleanup_launch_contained(contained, bounds),
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::LaunchFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::LaunchContained(contained) => {
                self.cleanup_launch_contained(*contained, bounds)
            }
            StartupAppAuthority::AdoptionContained(contained) => {
                match (*contained).cleanup_socket(bounds.session.app_cleanup_deadline()) {
                    Ok(complete) => {
                        self.app = StartupAppAuthority::Clean(
                            StartupProviderRelease::GracefullyDrained(complete.into_drain()),
                        );
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::CleanupFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::Stopped(stopped) => {
                match (*stopped).cleanup_socket_runtime(bounds.session.app_cleanup_deadline()) {
                    Ok(complete) => {
                        self.app = StartupAppAuthority::Clean(
                            StartupProviderRelease::GracefullyDrained(complete.into_drain()),
                        );
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::CleanupFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupAppAuthority::CleanupFailure(failure) => {
                match failure.retry(bounds.session.app_cleanup_deadline()) {
                    Ok(complete) => {
                        self.app = StartupAppAuthority::Clean(
                            StartupProviderRelease::GracefullyDrained(complete.into_drain()),
                        );
                        StartupStep::Advanced
                    }
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Runtime);
                        self.app = StartupAppAuthority::CleanupFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            clean @ StartupAppAuthority::Clean(_) => {
                self.app = clean;
                StartupStep::Advanced
            }
            authority @ (StartupAppAuthority::AdoptionFailure(_)
            | StartupAppAuthority::AdoptionContainmentFailure(_)
            | StartupAppAuthority::Session(_)
            | StartupAppAuthority::Connected(_)
            | StartupAppAuthority::InMonitor
            | StartupAppAuthority::StopFailure(_)) => {
                self.app = authority;
                self.cleanup_errors
                    .record(StartupCleanupError::MissingAuthority);
                StartupStep::Retained
            }
        }
    }

    fn cleanup_reservation(&mut self, reservation: AppSocketReservation) -> StartupStep {
        match reservation.release_if_absent() {
            Ok(runtime) => match runtime.cleanup() {
                Ok(_) => {
                    self.app = StartupAppAuthority::Clean(provider_never_started());
                    StartupStep::Advanced
                }
                Err(failure) => {
                    self.cleanup_errors.record(StartupCleanupError::Runtime);
                    self.app = StartupAppAuthority::RuntimeCleanupFailure(Box::new(failure));
                    StartupStep::Retained
                }
            },
            Err(failure) => {
                self.cleanup_errors.record(StartupCleanupError::Runtime);
                self.app = StartupAppAuthority::ReservationFailure(Box::new(failure));
                StartupStep::Retained
            }
        }
    }

    fn cleanup_launch_contained(
        &mut self,
        contained: AppServerLaunchContainmentComplete,
        bounds: StartupShutdownBounds,
    ) -> StartupStep {
        match contained.cleanup_runtime(bounds.session.app_cleanup_deadline()) {
            Ok(resolution) => {
                self.terminal_reportable &= resolution.terminal_reportable();
                let _ = resolution.release();
                self.app = StartupAppAuthority::Clean(provider_never_started());
                StartupStep::Advanced
            }
            Err(failure) => {
                self.cleanup_errors.record(StartupCleanupError::Runtime);
                self.app = StartupAppAuthority::LaunchFailure(failure);
                StartupStep::Retained
            }
        }
    }

    fn cleanup_build(&mut self, bounds: StartupShutdownBounds) -> StartupStep {
        // A child that existed but could not be announced has no legal
        // `ChildrenReaped` representation. Keep the build-owned guardian
        // lease forever rather than letting a superficially clean local reap
        // manufacture terminal authority.
        if !self.terminal_reportable {
            self.cleanup_errors
                .record(StartupCleanupError::MissingAuthority);
            return StartupStep::Retained;
        }
        let authority = std::mem::replace(&mut self.build, StartupBuildAuthority::Clean);
        match authority {
            StartupBuildAuthority::Authorized(authorization) => {
                drop(authorization);
                StartupStep::Advanced
            }
            StartupBuildAuthority::CompatibilityResolved(resolution) => {
                let _ = resolution.release();
                StartupStep::Advanced
            }
            StartupBuildAuthority::Live(build) => {
                match (*build).cleanup(bounds.session.build_cleanup_deadline()) {
                    Ok(_) => StartupStep::Advanced,
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Build);
                        self.build = StartupBuildAuthority::CleanupFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupBuildAuthority::CleanupFailure(failure) => {
                match failure
                    .into_build()
                    .cleanup(bounds.session.build_cleanup_deadline())
                {
                    Ok(_) => StartupStep::Advanced,
                    Err(failure) => {
                        self.cleanup_errors.record(StartupCleanupError::Build);
                        self.build = StartupBuildAuthority::CleanupFailure(failure);
                        StartupStep::Retained
                    }
                }
            }
            StartupBuildAuthority::Clean => StartupStep::Advanced,
            failure @ StartupBuildAuthority::CompatibilityFailure(_) => {
                self.build = failure;
                self.cleanup_errors.record(StartupCleanupError::Build);
                StartupStep::Retained
            }
        }
    }
}

impl StartupPhaseBackend for PartialStartupOwner {
    fn phase(&self) -> StartupShutdownPhase {
        self.phase
    }

    fn set_phase(&mut self, phase: StartupShutdownPhase) {
        self.phase = phase;
    }

    fn step(&mut self, phase: StartupShutdownPhase, bounds: StartupShutdownBounds) -> StartupStep {
        match phase {
            StartupShutdownPhase::Tui => self.quiesce_tui(bounds),
            StartupShutdownPhase::Relay => self.quiesce_relay(bounds),
            StartupShutdownPhase::Monitor => self.quiesce_monitor(bounds),
            StartupShutdownPhase::AppStop => self.stop_app(bounds),
            StartupShutdownPhase::TerminalQuiesce => self.quiesce_terminal(),
            StartupShutdownPhase::AwaitingCoordinatorRestore => StartupStep::Retained,
            StartupShutdownPhase::RecoveryDisarm => self.disarm_recovery(),
            StartupShutdownPhase::RuntimeCleanup => self.cleanup_runtime(bounds),
            StartupShutdownPhase::BuildCleanup => self.cleanup_build(bounds),
            StartupShutdownPhase::Complete => StartupStep::Advanced,
        }
    }
}

enum StartupQuiesceOwner {
    Partial(Box<PartialStartupOwner>),
    Session(Box<SessionShutdownFailure>),
}

/// Retry owner for a timeout before all provider processes and terminal bytes
/// have become quiescent. The current phase is deliberately private.
#[must_use = "quiescence timeout retains the exact current phase owner"]
pub(super) struct StartupQuiesceFailure {
    owner: StartupQuiesceOwner,
    error: SupervisedStartupError,
}

impl StartupQuiesceFailure {
    #[cfg(test)]
    pub(super) fn packaged_phase(&self) -> PackagedStartupQuiescePhase {
        match &self.owner {
            StartupQuiesceOwner::Partial(owner) => owner.phase.packaged_quiesce_phase(),
            StartupQuiesceOwner::Session(failure) => {
                PackagedStartupQuiescePhase::from_session_stage(failure.recovery_stage())
            }
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_tui_retention_markers(
        &self,
    ) -> (Option<&'static str>, Option<&'static str>) {
        match &self.owner {
            StartupQuiesceOwner::Partial(owner) if owner.phase == StartupShutdownPhase::Tui => {
                owner.tui.packaged_retention_markers()
            }
            StartupQuiesceOwner::Partial(_) | StartupQuiesceOwner::Session(_) => (None, None),
        }
    }

    #[cfg(test)]
    pub(super) fn packaged_app_retention_markers(
        &self,
    ) -> (Option<&'static str>, Option<&'static str>) {
        match &self.owner {
            StartupQuiesceOwner::Partial(owner) if owner.phase == StartupShutdownPhase::AppStop => {
                owner.app.packaged_retention_markers()
            }
            StartupQuiesceOwner::Partial(_) | StartupQuiesceOwner::Session(_) => (None, None),
        }
    }

    pub(super) fn retry(
        self,
        bounds: StartupShutdownBounds,
    ) -> Result<AwaitingCoordinatorRestore, Self> {
        let Self { owner, error } = self;
        quiesce_owner(owner, error, bounds)
    }
}

impl fmt::Debug for StartupQuiesceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupQuiesceFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl SupervisedStartupFailure {
    /// Stops/reaps TUI, relay, monitor, and App authority in order, then
    /// closes the guardian terminal-byte endpoint. It intentionally stops at
    /// the coordinator-owned restoration barrier.
    pub(super) fn quiesce(
        self,
        bounds: StartupShutdownBounds,
    ) -> Result<AwaitingCoordinatorRestore, StartupQuiesceFailure> {
        let Self { owner, error } = self;
        let owner = match owner {
            StartupFailureOwner::Partial(owner) => StartupQuiesceOwner::Partial(owner),
            StartupFailureOwner::Session(failure) => match failure.shutdown(bounds.session) {
                Ok(_report) => {
                    unreachable!(
                        "an armed startup terminal cannot finish without restoration proof"
                    )
                }
                Err(failure) => StartupQuiesceOwner::Session(failure),
            },
        };
        quiesce_owner(owner, error, bounds)
    }
}

fn quiesce_owner(
    owner: StartupQuiesceOwner,
    error: SupervisedStartupError,
    bounds: StartupShutdownBounds,
) -> Result<AwaitingCoordinatorRestore, StartupQuiesceFailure> {
    match owner {
        StartupQuiesceOwner::Partial(owner) => match owner.run_to_restore(bounds) {
            Ok(owner) => Ok(AwaitingCoordinatorRestore {
                owner: AwaitingRestoreOwner::Partial(owner),
                error,
            }),
            Err(owner) => Err(StartupQuiesceFailure {
                owner: StartupQuiesceOwner::Partial(owner),
                error,
            }),
        },
        StartupQuiesceOwner::Session(failure) => match failure.retry(bounds.session) {
            Ok(_report) => {
                unreachable!("an armed startup terminal cannot finish without restoration proof")
            }
            Err(failure) if failure.awaiting_terminal_restore() => Ok(AwaitingCoordinatorRestore {
                owner: AwaitingRestoreOwner::Session(failure),
                error,
            }),
            Err(failure) => Err(StartupQuiesceFailure {
                owner: StartupQuiesceOwner::Session(failure),
                error,
            }),
        },
    }
}

enum AwaitingRestoreOwner {
    Partial(Box<PartialStartupOwner>),
    Session(Box<SessionShutdownFailure>),
}

/// All provider processes are contained and terminal bytes are quiescent, but
/// recovery remains armed. Normal cleanup cannot advance without the exact
/// guardian command proof minted after the coordinator restored its tty.
#[must_use = "terminal restoration must be acknowledged or handled as lifecycle loss"]
pub(super) struct AwaitingCoordinatorRestore {
    owner: AwaitingRestoreOwner,
    error: SupervisedStartupError,
}

impl AwaitingCoordinatorRestore {
    pub(super) fn acknowledge_terminal_restored(
        self,
        proof: VerifiedTerminalRestoredCommand,
    ) -> Result<PostRestoreStartupCleanup, (Self, VerifiedTerminalRestoredCommand)> {
        let Self { owner, error } = self;
        match owner {
            AwaitingRestoreOwner::Partial(mut owner) => {
                if owner.phase != StartupShutdownPhase::AwaitingCoordinatorRestore
                    || owner.terminal.endpoint.is_some()
                {
                    return Err((
                        Self {
                            owner: AwaitingRestoreOwner::Partial(owner),
                            error,
                        },
                        proof,
                    ));
                }
                let Some(authority) = owner.terminal.recovery.take() else {
                    return Err((
                        Self {
                            owner: AwaitingRestoreOwner::Partial(owner),
                            error,
                        },
                        proof,
                    ));
                };
                match authority {
                    StartupRecoveryAuthority::Armed(recovery) => {
                        owner.terminal.recovery =
                            Some(StartupRecoveryAuthority::CoordinatorRestored {
                                recovery,
                                _proof: proof,
                            });
                        owner.phase = owner.phase.next();
                        Ok(PostRestoreStartupCleanup {
                            owner: PostRestoreOwner::Partial(owner),
                            error,
                        })
                    }
                    authority => {
                        owner.terminal.recovery = Some(authority);
                        Err((
                            Self {
                                owner: AwaitingRestoreOwner::Partial(owner),
                                error,
                            },
                            proof,
                        ))
                    }
                }
            }
            AwaitingRestoreOwner::Session(failure) => {
                match failure.acknowledge_terminal_restored(proof) {
                    Ok(failure) => Ok(PostRestoreStartupCleanup {
                        owner: PostRestoreOwner::Session(failure),
                        error,
                    }),
                    Err((failure, proof)) => Err((
                        Self {
                            owner: AwaitingRestoreOwner::Session(failure),
                            error,
                        },
                        proof,
                    )),
                }
            }
        }
    }

    /// Guardian fallback is available only after lifecycle loss. It performs
    /// the same exact snapshot readback under a thread-local SIGTTOU block,
    /// then enters the post-restore cleanup phase without fabricating a
    /// coordinator command proof.
    pub(super) fn restore_after_lifecycle_loss(
        self,
    ) -> Result<PostRestoreStartupCleanup, Box<Self>> {
        let Self { owner, error } = self;
        match owner {
            AwaitingRestoreOwner::Partial(mut owner) => {
                let Some(authority) = owner.terminal.recovery.take() else {
                    return Err(Box::new(Self {
                        owner: AwaitingRestoreOwner::Partial(owner),
                        error,
                    }));
                };
                match authority {
                    StartupRecoveryAuthority::Armed(recovery) => {
                        match recovery.restore_with_sigttou_block(&owner.terminal.snapshot) {
                            Ok(proof) => {
                                owner.terminal.recovery =
                                    Some(StartupRecoveryAuthority::FallbackRestored {
                                        recovery,
                                        _proof: proof,
                                    });
                                owner.phase = owner.phase.next();
                                Ok(PostRestoreStartupCleanup {
                                    owner: PostRestoreOwner::Partial(owner),
                                    error,
                                })
                            }
                            Err(_) => {
                                owner
                                    .cleanup_errors
                                    .record(StartupCleanupError::TerminalRestore);
                                owner.terminal.recovery =
                                    Some(StartupRecoveryAuthority::Armed(recovery));
                                Err(Box::new(Self {
                                    owner: AwaitingRestoreOwner::Partial(owner),
                                    error,
                                }))
                            }
                        }
                    }
                    authority => {
                        owner.terminal.recovery = Some(authority);
                        Err(Box::new(Self {
                            owner: AwaitingRestoreOwner::Partial(owner),
                            error,
                        }))
                    }
                }
            }
            AwaitingRestoreOwner::Session(mut failure) => {
                if failure.restore_after_lifecycle_loss().is_ok() {
                    Ok(PostRestoreStartupCleanup {
                        owner: PostRestoreOwner::Session(failure),
                        error,
                    })
                } else {
                    Err(Box::new(Self {
                        owner: AwaitingRestoreOwner::Session(failure),
                        error,
                    }))
                }
            }
        }
    }
}

impl fmt::Debug for AwaitingCoordinatorRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwaitingCoordinatorRestore")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

enum PostRestoreOwner {
    Partial(Box<PartialStartupOwner>),
    Session(Box<SessionShutdownFailure>),
}

/// Terminal restoration is proven, but recovery and filesystem/build
/// authority remain. Only this state can perform namespace mutation.
#[must_use = "post-restore cleanup must disarm recovery and clean all retained owners"]
pub(super) struct PostRestoreStartupCleanup {
    owner: PostRestoreOwner,
    error: SupervisedStartupError,
}

impl PostRestoreStartupCleanup {
    pub(super) fn finish(
        self,
        bounds: StartupShutdownBounds,
    ) -> Result<StartupCleanupReport, StartupCleanupFailure> {
        finish_post_restore(self.owner, self.error, bounds)
    }
}

enum StartupCleanupFailureOwner {
    Partial(Box<PartialStartupOwner>),
    Session(Box<SessionShutdownFailure>),
}

/// Retry owner for recovery disarm, namespace cleanup, or pinned-build cleanup.
#[must_use = "cleanup timeout retains the exact current owner"]
pub(super) struct StartupCleanupFailure {
    owner: StartupCleanupFailureOwner,
    error: SupervisedStartupError,
}

impl StartupCleanupFailure {
    pub(super) fn terminal_reportable(&self) -> bool {
        match &self.owner {
            StartupCleanupFailureOwner::Partial(owner) => owner.terminal_reportable,
            StartupCleanupFailureOwner::Session(failure) => {
                if failure.awaiting_terminal_restore() {
                    std::process::abort();
                }
                true
            }
        }
    }

    /// Retries the exact post-restore phase without reconstructing any child,
    /// runtime, recovery, or provider authority from identifiers. The current
    /// guardian's bounded recovery loop consumes this seam without weakening
    /// the retained-owner invariant.
    pub(super) fn retry(self, bounds: StartupShutdownBounds) -> Result<StartupCleanupReport, Self> {
        let Self { owner, error } = self;
        let owner = match owner {
            StartupCleanupFailureOwner::Partial(owner) => PostRestoreOwner::Partial(owner),
            StartupCleanupFailureOwner::Session(failure) => PostRestoreOwner::Session(failure),
        };
        finish_post_restore(owner, error, bounds)
    }
}

impl fmt::Debug for StartupCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match &self.owner {
            StartupCleanupFailureOwner::Partial(owner) => Some(owner.phase),
            StartupCleanupFailureOwner::Session(failure) => {
                let _ = failure.awaiting_terminal_restore();
                None
            }
        };
        formatter
            .debug_struct("StartupCleanupFailure")
            .field("error", &self.error)
            .field("partial_phase", &phase)
            .finish_non_exhaustive()
    }
}

fn finish_post_restore(
    owner: PostRestoreOwner,
    error: SupervisedStartupError,
    bounds: StartupShutdownBounds,
) -> Result<StartupCleanupReport, StartupCleanupFailure> {
    match owner {
        PostRestoreOwner::Partial(owner) => {
            owner
                .run_after_restore(bounds)
                .map_err(|owner| StartupCleanupFailure {
                    owner: StartupCleanupFailureOwner::Partial(owner),
                    error,
                })
        }
        PostRestoreOwner::Session(failure) => failure.retry(bounds.session).map_or_else(
            |failure| {
                Err(StartupCleanupFailure {
                    owner: StartupCleanupFailureOwner::Session(failure),
                    error,
                })
            },
            |report| {
                Ok(StartupCleanupReport {
                    startup_error: error,
                    details: StartupCleanupDetails::Session(report),
                })
            },
        ),
    }
}

struct PartialStartupCleanupDetails {
    cleanup_errors: StartupCleanupErrors,
    provider_release: StartupProviderRelease,
    tui_outcome: Option<ShutdownOutcome>,
    worker_join_status: WorkerJoinStatus,
    terminal_reportable: bool,
}

enum StartupCleanupDetails {
    Partial(PartialStartupCleanupDetails),
    Session(SessionShutdownReport),
}

/// Completed cleanup after a failed startup. `is_success` is deliberately
/// always false: clean rollback never upgrades a failed startup operation.
#[must_use = "startup cleanup report must be projected to lifecycle disposition"]
pub(super) struct StartupCleanupReport {
    startup_error: SupervisedStartupError,
    details: StartupCleanupDetails,
}

impl StartupCleanupReport {
    #[cfg(test)]
    pub(super) const fn startup_error(&self) -> SupervisedStartupError {
        self.startup_error
    }

    pub(super) fn cleanup_errors_empty(&self) -> bool {
        match &self.details {
            StartupCleanupDetails::Partial(details) => details.cleanup_errors.is_empty(),
            StartupCleanupDetails::Session(report) => report.cleanup_errors().is_empty(),
        }
    }

    pub(super) fn terminal_reportable(&self) -> bool {
        match &self.details {
            StartupCleanupDetails::Partial(details) => details.terminal_reportable,
            StartupCleanupDetails::Session(_) => true,
        }
    }

    pub(super) fn into_lifecycle_projection(self) -> SessionLifecycleProjection {
        if !self.terminal_reportable() {
            // The BuildCleanup phase retains this owner forever when an
            // unannounced child prevents a legal terminal transcript. A
            // non-reportable completed report is therefore an internal
            // invariant violation, never permission to publish without proof.
            std::process::abort();
        }
        match self.details {
            StartupCleanupDetails::Partial(details) => match details.provider_release {
                StartupProviderRelease::NeverStarted(never_started) => {
                    SessionLifecycleProjection::failed_before_provider_start(
                        never_started,
                        details.tui_outcome,
                        details.worker_join_status,
                    )
                }
                StartupProviderRelease::GracefullyDrained(drain) => {
                    SessionLifecycleProjection::failed_after_app_drain(
                        drain,
                        details.tui_outcome,
                        details.worker_join_status,
                    )
                }
            },
            StartupCleanupDetails::Session(report) => report.into_failed_lifecycle_projection(),
        }
    }

    #[cfg(test)]
    pub(super) const fn is_success(&self) -> bool {
        false
    }
}

impl fmt::Debug for StartupCleanupReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupCleanupReport")
            .field("startup_error", &self.startup_error)
            .field("cleanup_errors_empty", &self.cleanup_errors_empty())
            .field("success", &false)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::{Cursor, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::providers::codex::handoff_compat::TestCompatibilityCapability;
    use crate::providers::codex::remote::ReadinessProxy;

    use super::super::protocol::{
        ChildRole, CoordinatorCommand, FailureCode, GuardianCommandReceiver, GuardianEvent, Phase,
        TerminalSnapshotFingerprint, send_coordinator_command,
    };
    use super::super::provider::{GuardianSessionAuthority, accept_provider_launch_authorization};
    use super::super::terminal::startup_failure_terminal_for_test;
    use super::*;

    const THREAD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const TEST_APP_READINESS_BOUND: Duration = Duration::from_secs(5);
    const TEST_APP_GROUP_READINESS_BOUND: Duration = Duration::from_secs(5);
    const TEST_APP_CONTAINMENT_BOUND: Duration = Duration::from_secs(5);
    const TEST_APP_DESCRIPTOR_SCAN_BOUND: Duration = Duration::from_secs(10);
    const TEST_COOPERATIVE_APP_HELPER_ENV: &str = "CALCIFER_STARTUP_COOPERATIVE_APP_HELPER";
    const TEST_COOPERATIVE_APP_READY_ENV: &str = "CALCIFER_STARTUP_COOPERATIVE_APP_READY";
    const TEST_COOPERATIVE_APP_HELPER_TEST: &str =
        "providers::codex::supervisor::startup::tests::cooperative_app_child_helper";
    const TEST_GUARDIAN_DESCRIPTOR_HELPER_ENV: &str = "CALCIFER_STARTUP_GUARDIAN_DESCRIPTOR_HELPER";
    const TEST_GUARDIAN_DESCRIPTOR_HELPER_TEST: &str = "providers::codex::supervisor::startup::tests::guardian_half_rejects_an_inherited_b_descriptor_in_the_app_group";
    const TEST_RETAINED_APP_HELPER_ENV: &str = "CALCIFER_STARTUP_RETAINED_APP_HELPER";
    const TEST_RETAINED_APP_HELPER_TEST: &str = "providers::codex::supervisor::startup::tests::real_app_early_exit_permanently_retains_provider_authority_before_restore";

    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = PathBuf::from(format!(
                "/tmp/cfs-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(fs::canonicalize(path)?))
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn private_directory(&self, name: &str) -> Result<PathBuf, std::io::Error> {
            let path = self.0.join(name);
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(path)
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_executable(path: &Path, body: &[u8]) -> Result<(), std::io::Error> {
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    fn cooperative_app_body(ready_marker: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let helper = fs::canonicalize(std::env::current_exe()?)?;
        let helper = shell_quote_test_value(
            helper
                .to_str()
                .ok_or("cooperative App helper path is not UTF-8")?,
        )?;
        let ready_marker = ready_marker
            .to_str()
            .ok_or("test App readiness marker is not UTF-8")?;
        let quoted_marker = shell_quote_test_value(ready_marker)?;
        let helper_test = shell_quote_test_value(TEST_COOPERATIVE_APP_HELPER_TEST)?;
        Ok(format!(
            "#!/bin/sh\n{TEST_COOPERATIVE_APP_HELPER_ENV}=1 {TEST_COOPERATIVE_APP_READY_ENV}={quoted_marker} exec {helper} --exact {helper_test} --nocapture --test-threads=1\n"
        )
        .into_bytes())
    }

    fn shell_quote_test_value(value: &str) -> Result<String, Box<dyn std::error::Error>> {
        if value.contains(['\n', '\r', '\0']) {
            return Err("test helper shell value contained a control byte".into());
        }
        Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
    }

    fn run_isolated_test(test: &str, environment: &str) -> Result<(), Box<dyn std::error::Error>> {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(environment, "1")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("isolated test {test} exited with {status:?}").into())
        }
    }

    #[test]
    fn cooperative_app_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TEST_COOPERATIVE_APP_HELPER_ENV).is_none() {
            return Ok(());
        }
        let ready = std::env::var_os(TEST_COOPERATIVE_APP_READY_ENV)
            .ok_or("cooperative App helper ready path is missing")?;
        let mut signals =
            signal_hook::iterator::Signals::new([signal_hook::consts::signal::SIGTERM])?;
        fs::write(ready, b"ready")?;
        for signal in signals.forever() {
            if signal == signal_hook::consts::signal::SIGTERM {
                return Ok(());
            }
        }
        Err("cooperative App signal iterator ended".into())
    }

    fn wait_for_test_app_ready(
        ready_marker: &Path,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while !ready_marker.exists() {
            if Instant::now() >= deadline {
                return Err("test App did not install its TERM handler before the deadline".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn wait_for_test_process_and_group_absent(
        process: rustix::process::Pid,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let process_absent = match rustix::process::getpgid(Some(process)) {
                Err(rustix::io::Errno::SRCH) => true,
                Ok(_) | Err(rustix::io::Errno::INTR) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            let group_absent = match rustix::process::test_kill_process_group(process) {
                Err(rustix::io::Errno::SRCH) => true,
                Ok(()) | Err(rustix::io::Errno::INTR) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            if process_absent && group_absent {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("test App process or process group remained live after cleanup".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn contain_test_app_adoption_failure(
        failure: Box<AppServerSocketAdoptionFailure>,
    ) -> Result<AppServerAdoptionContainmentComplete, Box<dyn std::error::Error>> {
        let failure = match (*failure)
            .contain_child(TEST_APP_CONTAINMENT_BOUND, TEST_APP_CONTAINMENT_BOUND)
        {
            Ok(contained) => return Ok(contained),
            Err(failure) => failure,
        };
        match failure.retry(TEST_APP_CONTAINMENT_BOUND, TEST_APP_CONTAINMENT_BOUND) {
            Ok(contained) => Ok(contained),
            Err(failure) => Err(retain_test_debug_failure(
                "App descriptor-failure containment failed",
                failure,
            )),
        }
    }

    fn retry_shutdown_bounds() -> StartupShutdownBounds {
        StartupShutdownBounds {
            containment_timeout: Duration::from_secs(5),
            session: SessionShutdownBounds {
                tui_grace: Duration::from_secs(2),
                tui_forced: Duration::from_secs(2),
                relay_timeout: Duration::from_secs(5),
                monitor_timeout: Duration::from_secs(5),
                app_grace: Duration::from_secs(2),
                app_forced: Duration::from_secs(2),
                app_cleanup_timeout: Duration::from_secs(5),
                build_cleanup_timeout: Duration::from_secs(5),
            },
        }
    }

    fn retain_test_debug_failure<Owner: fmt::Debug>(
        context: &str,
        owner: Owner,
    ) -> Box<dyn std::error::Error> {
        // The diagnostic is deliberately projected before parking the exact
        // linear owner. Returning a formatted error through `?` must never run
        // an authority-bearing Drop implementation after bounded recovery is
        // exhausted.
        let diagnostic = format!("{context}: {owner:?}");
        std::mem::forget(owner);
        diagnostic.into()
    }

    fn quiesce_test_startup_failure(
        failure: SupervisedStartupFailure,
        context: &str,
    ) -> Result<AwaitingCoordinatorRestore, Box<dyn std::error::Error>> {
        let failure = match failure.quiesce(shutdown_bounds()) {
            Ok(awaiting) => return Ok(awaiting),
            Err(failure) => failure,
        };
        match failure.retry(retry_shutdown_bounds()) {
            Ok(awaiting) => Ok(awaiting),
            Err(failure) => Err(retain_test_debug_failure(context, failure)),
        }
    }

    fn acknowledge_test_terminal_restored(
        awaiting: AwaitingCoordinatorRestore,
        context: &str,
    ) -> Result<PostRestoreStartupCleanup, Box<dyn std::error::Error>> {
        let proof = match verified_terminal_restored_command() {
            Ok(proof) => proof,
            Err(error) => {
                let diagnostic = format!("{context}: could not mint restore proof: {error}");
                std::mem::forget(awaiting);
                return Err(diagnostic.into());
            }
        };
        match awaiting.acknowledge_terminal_restored(proof) {
            Ok(cleanup) => Ok(cleanup),
            Err((owner, proof)) => {
                let diagnostic = format!("{context}: {owner:?}");
                std::mem::forget((owner, proof));
                Err(diagnostic.into())
            }
        }
    }

    fn finish_test_startup_cleanup(
        cleanup: PostRestoreStartupCleanup,
        context: &str,
    ) -> Result<StartupCleanupReport, Box<dyn std::error::Error>> {
        let failure = match cleanup.finish(shutdown_bounds()) {
            Ok(report) => return Ok(report),
            Err(failure) => failure,
        };
        match failure.retry(retry_shutdown_bounds()) {
            Ok(report) => Ok(report),
            Err(failure) => Err(retain_test_debug_failure(context, failure)),
        }
    }

    fn cleanup_test_app_socket(
        contained: AppServerAdoptionContainmentComplete,
        context: &str,
    ) -> Result<PinnedAppGracefulDrain, Box<dyn std::error::Error>> {
        let failure = match contained.cleanup_socket(Instant::now() + Duration::from_secs(1)) {
            Ok(teardown) => return Ok(teardown.into_drain()),
            Err(failure) => failure,
        };
        match (*failure).retry(Instant::now() + Duration::from_secs(5)) {
            Ok(teardown) => Ok(teardown.into_drain()),
            Err(failure) => Err(retain_test_debug_failure(context, failure)),
        }
    }

    fn cleanup_test_build(
        build: PinnedSessionBuild,
        context: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let failure = match build.cleanup(Instant::now() + Duration::from_secs(1)) {
            Ok(_) => return Ok(()),
            Err(failure) => failure,
        };
        match (*failure)
            .into_build()
            .cleanup(Instant::now() + Duration::from_secs(5))
        {
            Ok(_) => Ok(()),
            Err(failure) => Err(retain_test_debug_failure(context, failure)),
        }
    }

    fn test_launch_authorization(
        codex_home: &Path,
        working_directory: &Path,
    ) -> Result<ProviderLaunchAuthorization, Box<dyn std::error::Error>> {
        let session = GuardianSessionAuthority::for_test(codex_home, working_directory, THREAD_ID)?;
        accept_test_session(session)
    }

    fn accept_test_session(
        session: GuardianSessionAuthority,
    ) -> Result<ProviderLaunchAuthorization, Box<dyn std::error::Error>> {
        let mut wire = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        send_coordinator_command(&mut wire, CoordinatorCommand::Start, deadline)?;
        send_coordinator_command(&mut wire, CoordinatorCommand::TerminalArmAccepted, deadline)?;
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(wire));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(receiver.receive(deadline)?, CoordinatorCommand::Start);
        receiver.record_event(GuardianEvent::TerminalArmed {
            snapshot: TerminalSnapshotFingerprint::from_digest([0x5a; 32]),
        })?;
        Ok(accept_provider_launch_authorization(
            session,
            &mut receiver,
            deadline,
        )?)
    }

    fn verified_terminal_restored_command()
    -> Result<VerifiedTerminalRestoredCommand, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut wire = Vec::new();
        for command in [
            CoordinatorCommand::Start,
            CoordinatorCommand::TerminalArmAccepted,
            CoordinatorCommand::TerminalRestored,
        ] {
            send_coordinator_command(&mut wire, command, deadline)?;
        }
        let mut receiver = GuardianCommandReceiver::new_terminal(Cursor::new(wire));
        receiver.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(receiver.receive(deadline)?, CoordinatorCommand::Start);
        receiver.record_event(GuardianEvent::TerminalArmed {
            snapshot: TerminalSnapshotFingerprint::from_digest([0x6b; 32]),
        })?;
        assert_eq!(
            receiver.receive(deadline)?,
            CoordinatorCommand::TerminalArmAccepted
        );
        receiver.record_event(GuardianEvent::Failed {
            phase: Phase::Runtime,
            code: FailureCode::Internal,
        })?;
        receiver.record_event(GuardianEvent::TerminalQuiesced)?;
        assert_eq!(
            receiver.receive(deadline)?,
            CoordinatorCommand::TerminalRestored
        );
        Ok(receiver.take_verified_terminal_restored_command()?)
    }

    fn pinned_build(
        sandbox: &Sandbox,
        body: &[u8],
    ) -> Result<PinnedSessionBuild, Box<dyn std::error::Error>> {
        let home = sandbox.private_directory("home")?;
        let workspace = sandbox.private_directory("workspace")?;
        let stage_parent = sandbox.private_directory("stage")?;
        let installed = sandbox.path().join("codex");
        test_executable(&installed, body)?;
        Ok(PinnedSessionBuild::from_test_capability(
            test_launch_authorization(&home, &workspace)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?)
    }

    fn pinned_build_with_guardian_descriptor(
        sandbox: &Sandbox,
        body: &[u8],
        guardian_descriptor: fs::File,
    ) -> Result<PinnedSessionBuild, Box<dyn std::error::Error>> {
        let home = sandbox.private_directory("home")?;
        let workspace = sandbox.private_directory("workspace")?;
        let stage_parent = sandbox.private_directory("stage")?;
        let installed = sandbox.path().join("codex");
        test_executable(&installed, body)?;
        let session = GuardianSessionAuthority::for_test_with_guardian_descriptor(
            &home,
            &workspace,
            THREAD_ID,
            guardian_descriptor,
        )?;
        Ok(PinnedSessionBuild::from_test_capability(
            accept_test_session(session)?,
            TestCompatibilityCapability::capture(&installed)?,
            &stage_parent,
        )?)
    }

    fn shutdown_bounds() -> StartupShutdownBounds {
        StartupShutdownBounds {
            containment_timeout: Duration::from_secs(1),
            session: SessionShutdownBounds {
                tui_grace: Duration::from_millis(10),
                tui_forced: Duration::from_millis(10),
                relay_timeout: Duration::from_secs(1),
                monitor_timeout: Duration::from_secs(1),
                app_grace: Duration::from_millis(10),
                app_forced: Duration::from_millis(10),
                app_cleanup_timeout: Duration::from_secs(1),
                build_cleanup_timeout: Duration::from_secs(1),
            },
        }
    }

    #[test]
    fn startup_abort_phases_each_derive_a_fresh_deadline() {
        let bounds = shutdown_bounds();
        let first_phase_started = Instant::now();
        let later_phase_started = first_phase_started + Duration::from_secs(30);

        assert_eq!(
            bounds.containment_deadline_at(first_phase_started),
            first_phase_started + bounds.containment_timeout
        );
        assert_eq!(
            bounds.containment_deadline_at(later_phase_started),
            later_phase_started + bounds.containment_timeout
        );
        assert!(
            bounds.containment_deadline_at(later_phase_started)
                > bounds.containment_deadline_at(first_phase_started),
            "each startup-abort phase must arm containment when that phase begins"
        );
    }

    #[test]
    fn compatibility_timeout_is_clamped_to_the_single_absolute_startup_deadline() {
        let now = Instant::now();
        let bounds = ProductionStartupBounds {
            deadline: now + Duration::from_millis(40),
            compatibility_timeout: Duration::from_secs(30),
            relay_timeout: Duration::from_secs(10),
        };

        assert_eq!(
            bounds.remaining_timeout_at(bounds.compatibility_timeout, now),
            Duration::from_millis(40)
        );
        assert_eq!(
            bounds.remaining_timeout_at(Duration::from_millis(5), now),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn relay_tui_start_boundary_rejects_truncated_windows_without_any_attempt() {
        use std::cell::Cell;

        let now = Instant::now();
        let relay_timeout = Duration::from_millis(10);
        let greater = ProductionStartupBounds {
            deadline: now + Duration::from_millis(11),
            compatibility_timeout: Duration::from_secs(30),
            relay_timeout,
        };
        let equal = ProductionStartupBounds {
            deadline: now + relay_timeout,
            ..greater
        };
        let less = ProductionStartupBounds {
            deadline: now + Duration::from_millis(9),
            ..greater
        };
        let expired = ProductionStartupBounds {
            deadline: now - Duration::from_millis(1),
            ..greater
        };

        for bounds in [less, expired] {
            let relay_attempts = Cell::new(0);
            let tui_attempts = Cell::new(0);
            let result = cross_relay_tui_start_boundary_at(
                bounds,
                now,
                |_| {
                    relay_attempts.set(relay_attempts.get() + 1);
                    Ok::<_, &str>(7_u8)
                },
                || {
                    tui_attempts.set(tui_attempts.get() + 1);
                    Ok::<_, &str>(11_u8)
                },
            );
            assert!(matches!(
                result,
                Err(RelayTuiStartBoundaryFailure::Deadline)
            ));
            assert_eq!(relay_attempts.get(), 0);
            assert_eq!(tui_attempts.get(), 0);
        }

        for bounds in [equal, greater] {
            let relay_attempts = Cell::new(0);
            let tui_attempts = Cell::new(0);
            let observed_deadline = Cell::new(None);
            let result = cross_relay_tui_start_boundary_at(
                bounds,
                now,
                |deadline| {
                    observed_deadline.set(Some(deadline));
                    relay_attempts.set(relay_attempts.get() + 1);
                    Ok::<_, &str>(7_u8)
                },
                || {
                    tui_attempts.set(tui_attempts.get() + 1);
                    Ok::<_, &str>(11_u8)
                },
            );
            assert_eq!(result.ok(), Some((7, 11)));
            assert_eq!(observed_deadline.get(), Some(now + relay_timeout));
            assert_eq!(relay_attempts.get(), 1);
            assert_eq!(tui_attempts.get(), 1);
        }
    }

    #[test]
    fn relay_tui_start_boundary_preserves_attempt_order_and_started_owner() {
        use std::cell::Cell;

        let now = Instant::now();
        let bounds = ProductionStartupBounds {
            deadline: now + Duration::from_secs(2),
            compatibility_timeout: Duration::from_secs(1),
            relay_timeout: Duration::from_secs(1),
        };
        let tui_attempts = Cell::new(0);
        let relay_failure = cross_relay_tui_start_boundary_at(
            bounds,
            now,
            |_| Err::<u8, _>("relay-failure"),
            || {
                tui_attempts.set(tui_attempts.get() + 1);
                Ok::<_, &str>(11_u8)
            },
        );
        assert!(matches!(
            relay_failure,
            Err(RelayTuiStartBoundaryFailure::Relay("relay-failure"))
        ));
        assert_eq!(tui_attempts.get(), 0);

        let tui_failure = cross_relay_tui_start_boundary_at(
            bounds,
            now,
            |_| Ok::<_, &str>(7_u8),
            || Err::<u8, _>("tui-failure"),
        );
        assert!(matches!(
            tui_failure,
            Err(RelayTuiStartBoundaryFailure::Tui {
                relay: 7,
                error: "tui-failure"
            })
        ));
    }

    #[test]
    fn guardian_half_rejects_an_inherited_b_descriptor_in_the_app_group()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TEST_GUARDIAN_DESCRIPTOR_HELPER_ENV).is_none() {
            return run_isolated_test(
                TEST_GUARDIAN_DESCRIPTOR_HELPER_TEST,
                TEST_GUARDIAN_DESCRIPTOR_HELPER_ENV,
            );
        }

        let sandbox = Sandbox::new()?;
        let descendant_marker = sandbox.path().join("app-descendant.pid");
        // The delay deliberately exceeds the historical one-second readiness
        // barrier. Install the TERM trap before either sleep so a readiness
        // regression can still resolve the typed App owner without relying on
        // KILL or an authority-bearing Drop implementation.
        let script = format!(
            "#!/bin/sh\ndescendant=\ntrap 'if [ -n \"$descendant\" ]; then kill \"$descendant\" 2>/dev/null || :; wait \"$descendant\" 2>/dev/null || :; fi; exit 0' TERM\n/bin/sleep 1.25\n/bin/sleep 30 &\ndescendant=$!\nprintf '%s\\n' \"$descendant\" > \"{}\"\nwait \"$descendant\"\n",
            descendant_marker.display()
        );

        // This descriptor stands in for the guardian-only B lease. Production
        // B is close-on-exec; this fixed negative test intentionally clears
        // that bit before the real provider spawn so both the shell leader and
        // its `sleep` descendant inherit the same source-pinned identity.
        let guardian_path = sandbox.path().join("guardian-b");
        fs::write(&guardian_path, b"guardian-only")?;
        let guardian_descriptor = fs::File::open(&guardian_path)?;
        let descriptor_flags = rustix::io::fcntl_getfd(&guardian_descriptor)?;
        rustix::io::fcntl_setfd(
            &guardian_descriptor,
            descriptor_flags & !rustix::io::FdFlags::CLOEXEC,
        )?;
        let build = pinned_build_with_guardian_descriptor(
            &sandbox,
            script.as_bytes(),
            guardian_descriptor,
        )?;

        let runtime_parent = sandbox.private_directory("runtime")?;
        let runtime = PrivateRuntime::create(&runtime_parent)?;
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        drop(route);
        // Complete every fallible PTY setup step before the fail-closed App
        // owner exists. Otherwise a fixture error would unwind through
        // `ManagedGroupChild::drop` and abort instead of reporting the error.
        let (endpoint, terminal_peer, recovery, snapshot, _, _terminal_master_keepalive) =
            startup_failure_terminal_for_test()?;
        let terminal = StartupTerminalAuthority::new(endpoint, recovery, snapshot);
        terminal.validate()?;
        let command = build.app_server_command_for_reservation(
            &reservation,
            Instant::now() + Duration::from_secs(1),
        )?;
        let (mut child, reservation) = command
            .launch_with_reservation(reservation, Instant::now() + Duration::from_secs(1))?;
        let containment = child.containment();
        let app_pid = rustix::process::Pid::from_raw(containment.pid())
            .ok_or("invalid descriptor-negative App PID")?;

        let descendant_deadline = Instant::now() + TEST_APP_GROUP_READINESS_BOUND;
        let group_readiness_failure = loop {
            let descendant_pid = fs::read_to_string(&descendant_marker)
                .ok()
                .and_then(|raw| raw.trim().parse::<i32>().ok())
                .and_then(rustix::process::Pid::from_raw);
            let expected_group = rustix::process::Pid::from_raw(containment.pgid());
            if let (Some(pid), Some(group)) = (descendant_pid, expected_group) {
                if rustix::process::getpgid(Some(pid)).is_ok_and(|actual| actual == group) {
                    break None;
                }
            }
            if Instant::now() >= descendant_deadline {
                break Some(
                    "the test App descendant did not become ready in its exact process group",
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        };

        let reporter = FakeReporter {
            events: Vec::new(),
            fail_on: None,
        };
        let observed = verify_app_descriptor_inventory(
            &mut child,
            &build,
            &reservation,
            &terminal,
            &reporter,
            Instant::now() + TEST_APP_DESCRIPTOR_SCAN_BOUND,
        )
        .err();

        // Resolve the exact child/socket/runtime owners even if the assertion
        // below regresses, so a failed test cannot leave a provider group
        // running. The synthetic class is cleanup-only and is never asserted.
        let cleanup_error = observed
            .unwrap_or(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged);
        let failure = child.retain_descriptor_isolation_failure(reservation, cleanup_error);
        let contained = contain_test_app_adoption_failure(failure)?;
        let _drain = cleanup_test_app_socket(contained, "App descriptor-failure cleanup failed")?;
        drop((terminal, terminal_peer));
        cleanup_test_build(build, "provider build cleanup failed")?;
        wait_for_test_process_and_group_absent(
            app_pid,
            Instant::now() + TEST_APP_CONTAINMENT_BOUND,
        )?;

        // A readiness miss is a fixture failure, not a descriptor-isolation
        // observation. Return it only after the exact child/socket/build
        // owners above have completed their typed cleanup sequence.
        if let Some(error) = group_readiness_failure {
            return Err(error.into());
        }
        assert_eq!(
            observed,
            Some(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor)
        );
        Ok(())
    }

    #[test]
    fn real_runtime_and_pinned_build_wait_for_restore_proof_before_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new()?;
        let build = pinned_build(&sandbox, b"#!/bin/sh\nexit 0\n")?;
        let staged_executable = build.executable_path_for_test().to_path_buf();
        let staged_runtime = build.runtime_path_for_test().to_path_buf();
        let runtime_parent = sandbox.private_directory("runtime")?;
        let runtime = PrivateRuntime::create(&runtime_parent)?;
        let runtime_path = runtime.path().to_path_buf();
        let (
            endpoint,
            terminal_peer,
            recovery,
            snapshot,
            recovery_identity,
            _terminal_master_keepalive,
        ) = startup_failure_terminal_for_test()?;
        let terminal = StartupTerminalAuthority::new(endpoint, recovery, snapshot);
        terminal.validate()?;

        let failure = partial_failure(
            StartupBuildAuthority::Live(Box::new(build)),
            StartupAppAuthority::Runtime(Box::new(runtime)),
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::Runtime,
        );
        let awaiting = quiesce_test_startup_failure(failure, "real owner quiescence failed")?;
        drop(terminal_peer);

        assert!(runtime_path.exists());
        assert!(staged_executable.exists());
        assert!(staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            1
        );

        let cleanup = acknowledge_test_terminal_restored(awaiting, "restore proof was rejected")?;
        let report = finish_test_startup_cleanup(cleanup, "post-restore cleanup failed")?;

        assert!(!runtime_path.exists());
        assert!(!staged_executable.exists());
        assert!(!staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            0
        );
        assert!(report.cleanup_errors_empty());
        assert_eq!(report.startup_error(), SupervisedStartupError::Runtime);
        assert!(!report.is_success());
        Ok(())
    }

    #[test]
    fn real_app_lifecycle_report_failure_retains_child_until_ordered_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new()?;
        let ready_marker = sandbox.path().join("app-ready");
        let body = cooperative_app_body(&ready_marker)?;
        let build = pinned_build(&sandbox, &body)?;
        let staged_runtime = build.runtime_path_for_test().to_path_buf();
        let runtime_parent = sandbox.private_directory("runtime")?;
        let runtime = PrivateRuntime::create(&runtime_parent)?;
        let runtime_path = runtime.path().to_path_buf();
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        drop(route);
        // Prepare and validate recovery authority before creating the
        // fail-closed child owner; no fallible fixture setup may unwind across
        // a live App.
        let (
            endpoint,
            terminal_peer,
            recovery,
            snapshot,
            recovery_identity,
            _terminal_master_keepalive,
        ) = startup_failure_terminal_for_test()?;
        let terminal = StartupTerminalAuthority::new(endpoint, recovery, snapshot);
        terminal.validate()?;
        let command = build.app_server_command_for_reservation(
            &reservation,
            Instant::now() + Duration::from_secs(1),
        )?;
        let (mut child, reservation) = command
            .launch_with_reservation(reservation, Instant::now() + Duration::from_secs(1))?;
        if let Err(readiness_error) =
            wait_for_test_app_ready(&ready_marker, Instant::now() + TEST_APP_READINESS_BOUND)
        {
            let failure = child.retain_descriptor_isolation_failure(
                reservation,
                calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
            );
            let contained = contain_test_app_adoption_failure(failure)?;
            let _drain =
                cleanup_test_app_socket(contained, "lifecycle App readiness cleanup failed")?;
            drop((terminal, terminal_peer));
            cleanup_test_build(build, "lifecycle App build cleanup failed")?;
            return Err(readiness_error);
        }
        let containment = child.containment();
        let mut reporter = FakeReporter {
            events: Vec::new(),
            fail_on: Some(0),
        };
        let descriptor_isolation = match verify_app_descriptor_inventory(
            &mut child,
            &build,
            &reservation,
            &terminal,
            &reporter,
            Instant::now() + TEST_APP_DESCRIPTOR_SCAN_BOUND,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                let failure = child.retain_descriptor_isolation_failure(reservation, error);
                let contained = contain_test_app_adoption_failure(failure)?;
                let _drain =
                    cleanup_test_app_socket(contained, "lifecycle App scan cleanup failed")?;
                drop((terminal, terminal_peer));
                cleanup_test_build(build, "lifecycle App build cleanup failed")?;
                return Err(format!("lifecycle App descriptor scan failed: {error:?}").into());
            }
        };
        let (child, reservation) = match report_child_started_or_retain(
            (child, reservation),
            containment,
            &mut reporter,
            Instant::now() + Duration::from_secs(1),
        ) {
            Err(owner) => owner,
            Ok((child, reservation)) => {
                let failure = child.retain_descriptor_isolation_failure(
                    reservation,
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
                );
                let contained = contain_test_app_adoption_failure(failure)?;
                let _drain = cleanup_test_app_socket(
                    contained,
                    "unexpected lifecycle success cleanup failed",
                )?;
                drop((descriptor_isolation, terminal, terminal_peer));
                cleanup_test_build(build, "lifecycle App build cleanup failed")?;
                return Err("the fixed lifecycle fault unexpectedly reported App started".into());
            }
        };
        let app = match child.adopt_socket(
            reservation,
            descriptor_isolation,
            Instant::now() + Duration::from_millis(20),
        ) {
            Ok(session) => StartupAppAuthority::Session(Box::new(session)),
            Err(failure) => StartupAppAuthority::AdoptionFailure(failure),
        };
        let failure = partial_failure(
            StartupBuildAuthority::Live(Box::new(build)),
            app,
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::Lifecycle,
        );

        assert_eq!(reporter.events, [containment]);
        assert_eq!(containment.role(), ChildRole::AppServer);
        assert!(containment.pid() > 0);
        assert_eq!(containment.pid(), containment.pgid());
        let awaiting = quiesce_test_startup_failure(failure, "App containment failed")?;
        drop(terminal_peer);

        // The direct child is reaped before the barrier, but its exact socket,
        // runtime, pinned stage, and recovery authority remain owned until the
        // coordinator's restoration proof is consumed.
        assert!(runtime_path.exists());
        assert!(staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            1
        );

        let cleanup = acknowledge_test_terminal_restored(awaiting, "restore proof was rejected")?;
        let report = finish_test_startup_cleanup(cleanup, "App rollback cleanup failed")?;
        assert!(!runtime_path.exists());
        assert!(!staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            0
        );
        assert!(report.cleanup_errors_empty());
        assert_eq!(report.startup_error(), SupervisedStartupError::Lifecycle);
        assert!(!report.is_success());
        Ok(())
    }

    #[test]
    fn real_app_early_exit_permanently_retains_provider_authority_before_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(TEST_RETAINED_APP_HELPER_ENV).is_none() {
            return run_isolated_test(TEST_RETAINED_APP_HELPER_TEST, TEST_RETAINED_APP_HELPER_ENV);
        }

        let sandbox = Sandbox::new()?;
        let exit_gate = sandbox.path().join("app-exit.fifo");
        let exit_ready = sandbox.path().join("app-exit-ready");
        let fifo_status = Command::new("/usr/bin/mkfifo")
            .args(["-m", "600"])
            .arg(&exit_gate)
            .status()?;
        let fifo_metadata = fs::symlink_metadata(&exit_gate)?;
        if !fifo_status.success()
            || !fifo_metadata.file_type().is_fifo()
            || fifo_metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("test App exit FIFO was not created privately".into());
        }
        let quoted_exit_gate = shell_quote_test_value(
            exit_gate
                .to_str()
                .ok_or("test App exit FIFO path is not UTF-8")?,
        )?;
        let quoted_exit_ready = shell_quote_test_value(
            exit_ready
                .to_str()
                .ok_or("test App exit readiness path is not UTF-8")?,
        )?;
        let body = format!(
            "#!/bin/sh\nexec 3<> {quoted_exit_gate}\n: > {quoted_exit_ready}\nIFS= read -r _ <&3\nexit 17\n"
        );
        let build = pinned_build(&sandbox, body.as_bytes())?;
        let staged_runtime = build.runtime_path_for_test().to_path_buf();
        let runtime_parent = sandbox.private_directory("runtime")?;
        let runtime = PrivateRuntime::create(&runtime_parent)?;
        let runtime_path = runtime.path().to_path_buf();
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        drop(route);
        // Prepare and validate recovery authority before creating the
        // fail-closed child owner; no fallible fixture setup may unwind across
        // a live App.
        let (
            endpoint,
            terminal_peer,
            recovery,
            snapshot,
            recovery_identity,
            _terminal_master_keepalive,
        ) = startup_failure_terminal_for_test()?;
        let terminal = StartupTerminalAuthority::new(endpoint, recovery, snapshot);
        terminal.validate()?;
        let command = build.app_server_command_for_reservation(
            &reservation,
            Instant::now() + Duration::from_secs(1),
        )?;
        let (mut child, reservation) = command
            .launch_with_reservation(reservation, Instant::now() + Duration::from_secs(1))?;
        if let Err(readiness_error) =
            wait_for_test_app_ready(&exit_ready, Instant::now() + TEST_APP_READINESS_BOUND)
        {
            let failure = child.retain_descriptor_isolation_failure(
                reservation,
                calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
            );
            let contained = contain_test_app_adoption_failure(failure)?;
            let _drain = cleanup_test_app_socket(contained, "early App readiness cleanup failed")?;
            drop((terminal, terminal_peer));
            cleanup_test_build(build, "early App build cleanup failed")?;
            return Err(readiness_error);
        }
        let mut exit_writer = match rustix::fs::open(
            &exit_gate,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => fs::File::from(descriptor),
            Err(open_error) => {
                let failure = child.retain_descriptor_isolation_failure(
                    reservation,
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
                );
                let contained = contain_test_app_adoption_failure(failure)?;
                let _drain = cleanup_test_app_socket(contained, "early App writer cleanup failed")?;
                drop((terminal, terminal_peer));
                cleanup_test_build(build, "early App build cleanup failed")?;
                return Err(format!(
                    "early App exit writer failed: {:?}",
                    std::io::Error::from(open_error).kind()
                )
                .into());
            }
        };
        let containment = child.containment();
        let mut reporter = FakeReporter {
            events: Vec::new(),
            fail_on: None,
        };
        let descriptor_isolation = match verify_app_descriptor_inventory(
            &mut child,
            &build,
            &reservation,
            &terminal,
            &reporter,
            Instant::now() + TEST_APP_DESCRIPTOR_SCAN_BOUND,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                let failure = child.retain_descriptor_isolation_failure(reservation, error);
                let contained = contain_test_app_adoption_failure(failure)?;
                let _drain = cleanup_test_app_socket(contained, "early App scan cleanup failed")?;
                drop((terminal, terminal_peer));
                cleanup_test_build(build, "early App build cleanup failed")?;
                return Err(format!("early App descriptor scan failed: {error:?}").into());
            }
        };
        let (child, reservation) = match report_child_started_or_retain(
            (child, reservation),
            containment,
            &mut reporter,
            Instant::now() + Duration::from_secs(1),
        ) {
            Ok(owner) => owner,
            Err((child, reservation)) => {
                // This branch is impossible for the fixed successful fake.
                // Resolve every exact owner before reporting the regression;
                // unwinding through the live child would correctly abort.
                let failure = child.retain_descriptor_isolation_failure(
                    reservation,
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
                );
                let contained = contain_test_app_adoption_failure(failure)?;
                let _drain = cleanup_test_app_socket(contained, "early App report cleanup failed")?;
                drop((descriptor_isolation, terminal, terminal_peer));
                cleanup_test_build(build, "early App build cleanup failed")?;
                return Err("the successful lifecycle reporter lost App ownership".into());
            }
        };
        if let Err(write_error) = exit_writer.write_all(b"exit\n") {
            let failure = child.retain_descriptor_isolation_failure(
                reservation,
                calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
            );
            let contained = contain_test_app_adoption_failure(failure)?;
            let _drain = cleanup_test_app_socket(contained, "early App trigger cleanup failed")?;
            drop((descriptor_isolation, terminal, terminal_peer));
            cleanup_test_build(build, "early App build cleanup failed")?;
            return Err(format!("early App exit trigger failed: {:?}", write_error.kind()).into());
        }
        let adoption = child
            .adopt_socket(
                reservation,
                descriptor_isolation,
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .ok_or("an exited App child unexpectedly produced a live socket session")?;
        let packaged_adoption_marker = packaged_app_socket_failure_marker(adoption.error());
        let failure = partial_failure(
            StartupBuildAuthority::Live(Box::new(build)),
            StartupAppAuthority::AdoptionFailure(adoption),
            StartupMonitorAuthority::None,
            StartupRelayAuthority::None,
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::AppSocket,
        );

        assert_eq!(reporter.events, [containment]);
        assert_eq!(
            failure.packaged_app_socket_failure_marker(),
            Some(packaged_adoption_marker)
        );
        let retained = failure
            .quiesce(shutdown_bounds())
            .err()
            .ok_or("an App exit before Calcifer's TERM reached the restore barrier")?;
        drop(terminal_peer);

        let retained = retained
            .retry(shutdown_bounds())
            .err()
            .ok_or("retry incorrectly minted App graceful-drain authority")?;
        let StartupQuiesceOwner::Partial(owner) = &retained.owner else {
            return Err("early App exit changed into an assembled-session owner".into());
        };
        assert_eq!(owner.phase, StartupShutdownPhase::AppStop);
        assert!(matches!(
            owner.app,
            StartupAppAuthority::AdoptionContainmentFailure(_)
        ));
        assert!(runtime_path.exists());
        assert!(staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            1
        );

        // The direct child is already reaped, but detached work cannot be
        // disproved. Production parks this exact owner together with B;
        // forgetting it here models that non-returning state without letting
        // the test process abort through the fail-closed App Drop path.
        std::mem::forget(retained);
        Ok(())
    }

    #[test]
    fn real_relay_start_fault_retains_route_and_defers_runtime_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let sandbox = Sandbox::new()?;
        let build = pinned_build(&sandbox, b"#!/bin/sh\nexit 0\n")?;
        let staged_runtime = build.runtime_path_for_test().to_path_buf();
        let runtime_parent = sandbox.private_directory("runtime")?;
        let runtime = PrivateRuntime::create(&runtime_parent)?;
        let runtime_path = runtime.path().to_path_buf();
        let (reservation, route) = runtime.reserve_supervised_layout()?.into_parts();
        let relay_plan = build.exact_relay_plan(route, Instant::now() + Duration::from_secs(1))?;
        ReadinessProxy::fail_next_exact_start_after_bind_for_test();
        let relay_failure = relay_plan
            .spawn(
                Duration::from_secs(1),
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .ok_or("the fixed relay start fault unexpectedly became ready")?;
        let (
            endpoint,
            terminal_peer,
            recovery,
            snapshot,
            recovery_identity,
            _terminal_master_keepalive,
        ) = startup_failure_terminal_for_test()?;
        let terminal = StartupTerminalAuthority::new(endpoint, recovery, snapshot);
        terminal.validate()?;
        let failure = partial_failure(
            StartupBuildAuthority::Live(Box::new(build)),
            StartupAppAuthority::Reservation(Box::new(reservation)),
            StartupMonitorAuthority::None,
            StartupRelayAuthority::StartFailure(relay_failure),
            StartupTuiAuthority::None,
            terminal,
            SupervisedStartupError::RelayStart,
        );

        let awaiting = quiesce_test_startup_failure(failure, "relay fault resolution failed")?;
        drop(terminal_peer);
        assert!(runtime_path.exists());
        assert!(staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            1
        );

        let cleanup = acknowledge_test_terminal_restored(awaiting, "restore proof was rejected")?;
        let report = finish_test_startup_cleanup(cleanup, "relay rollback cleanup failed")?;
        assert!(!runtime_path.exists());
        assert!(!staged_runtime.exists());
        assert_eq!(
            calcifer_unix_child_fd::count_open_descriptors_with_identity(recovery_identity)?,
            0
        );
        assert!(report.cleanup_errors_empty());
        assert_eq!(report.startup_error(), SupervisedStartupError::RelayStart);
        assert!(!report.is_success());
        Ok(())
    }

    struct FakePhaseBackend {
        phase: StartupShutdownPhase,
        calls: Vec<StartupShutdownPhase>,
        retain_once: Option<StartupShutdownPhase>,
        owner_token: u64,
    }

    impl FakePhaseBackend {
        fn at(phase: StartupShutdownPhase) -> Self {
            Self {
                phase,
                calls: Vec::new(),
                retain_once: None,
                owner_token: 0xCA1C_1FE2,
            }
        }
    }

    impl StartupPhaseBackend for FakePhaseBackend {
        fn phase(&self) -> StartupShutdownPhase {
            self.phase
        }

        fn set_phase(&mut self, phase: StartupShutdownPhase) {
            self.phase = phase;
        }

        fn step(
            &mut self,
            phase: StartupShutdownPhase,
            _bounds: StartupShutdownBounds,
        ) -> StartupStep {
            self.calls.push(phase);
            if self.retain_once == Some(phase) {
                self.retain_once = None;
                StartupStep::Retained
            } else {
                StartupStep::Advanced
            }
        }
    }

    #[test]
    fn phase_driver_stops_before_restore_and_cannot_touch_namespace_or_build() {
        let mut backend = FakePhaseBackend::at(StartupShutdownPhase::Tui);
        assert_eq!(
            drive_startup_phases(
                &mut backend,
                StartupShutdownPhase::AwaitingCoordinatorRestore,
                shutdown_bounds(),
            ),
            StartupStep::Advanced
        );
        assert_eq!(
            backend.calls,
            [
                StartupShutdownPhase::Tui,
                StartupShutdownPhase::Relay,
                StartupShutdownPhase::Monitor,
                StartupShutdownPhase::AppStop,
                StartupShutdownPhase::TerminalQuiesce,
            ]
        );
        assert_eq!(
            backend.phase,
            StartupShutdownPhase::AwaitingCoordinatorRestore
        );
        assert!(
            !backend
                .calls
                .contains(&StartupShutdownPhase::RecoveryDisarm)
        );
        assert!(
            !backend
                .calls
                .contains(&StartupShutdownPhase::RuntimeCleanup)
        );
        assert!(!backend.calls.contains(&StartupShutdownPhase::BuildCleanup));

        // Advancing to RecoveryDisarm represents consumption of either the
        // protocol-minted coordinator proof or the explicit lifecycle-loss
        // fallback proof. Only then can mutation phases run.
        backend.set_phase(StartupShutdownPhase::RecoveryDisarm);
        assert_eq!(
            drive_startup_phases(
                &mut backend,
                StartupShutdownPhase::Complete,
                shutdown_bounds(),
            ),
            StartupStep::Advanced
        );
        assert_eq!(
            &backend.calls[5..],
            [
                StartupShutdownPhase::RecoveryDisarm,
                StartupShutdownPhase::RuntimeCleanup,
                StartupShutdownPhase::BuildCleanup,
            ]
        );
    }

    #[test]
    fn packaged_startup_quiesce_phase_markers_are_closed_and_fixed() {
        assert_eq!(
            [
                StartupShutdownPhase::Tui,
                StartupShutdownPhase::Relay,
                StartupShutdownPhase::Monitor,
                StartupShutdownPhase::AppStop,
                StartupShutdownPhase::TerminalQuiesce,
                StartupShutdownPhase::AwaitingCoordinatorRestore,
                StartupShutdownPhase::RecoveryDisarm,
                StartupShutdownPhase::RuntimeCleanup,
                StartupShutdownPhase::BuildCleanup,
                StartupShutdownPhase::Complete,
            ]
            .map(|phase| phase.packaged_quiesce_phase().marker()),
            [
                "guardian-retained.startup-quiesce.phase.tui",
                "guardian-retained.startup-quiesce.phase.relay",
                "guardian-retained.startup-quiesce.phase.monitor",
                "guardian-retained.startup-quiesce.phase.app-stop",
                "guardian-retained.startup-quiesce.phase.terminal-quiesce",
                "guardian-retained.startup-quiesce.phase.awaiting-coordinator-restore",
                "guardian-retained.startup-quiesce.phase.recovery-disarm",
                "guardian-retained.startup-quiesce.phase.runtime-cleanup",
                "guardian-retained.startup-quiesce.phase.build-cleanup",
                "guardian-retained.startup-quiesce.phase.complete",
            ]
        );
        assert_eq!(
            [
                PackagedStartupQuiescePhase::SessionQuiescing,
                PackagedStartupQuiescePhase::SessionRestorePending,
                PackagedStartupQuiescePhase::SessionCleanupPending,
            ]
            .map(PackagedStartupQuiescePhase::marker),
            [
                "guardian-retained.startup-quiesce.phase.session-quiescing",
                "guardian-retained.startup-quiesce.phase.session-restore-pending",
                "guardian-retained.startup-quiesce.phase.session-cleanup-pending",
            ]
        );
    }

    #[test]
    fn packaged_startup_process_error_markers_are_closed_and_fixed() {
        use super::super::process::ProcessError;
        use super::super::protocol::{ChildDisposition, StopAction};

        let tui = ChildRole::Tui;
        let cases = [
            (ProcessError::Spawn { role: tui }, "spawn"),
            (
                ProcessError::ProcessGroupReadback { role: tui },
                "process-group-readback",
            ),
            (
                ProcessError::ProcessGroupMismatch { role: tui },
                "process-group-mismatch",
            ),
            (
                ProcessError::SessionReadback { role: tui },
                "session-readback",
            ),
            (
                ProcessError::SessionMismatch { role: tui },
                "session-mismatch",
            ),
            (
                ProcessError::SessionStartupTimeout { role: tui },
                "session-startup-timeout",
            ),
            (
                ProcessError::SpawnCleanupTimeout { role: tui },
                "spawn-cleanup-timeout",
            ),
            (
                ProcessError::SpawnContainmentUnconfirmed { role: tui },
                "spawn-containment-unconfirmed",
            ),
            (
                ProcessError::ReadinessUnavailable { role: tui },
                "readiness-unavailable",
            ),
            (
                ProcessError::ParentLivenessUnavailable { role: tui },
                "parent-liveness-unavailable",
            ),
            (
                ProcessError::ReadinessTimeout { role: tui },
                "readiness-timeout",
            ),
            (ProcessError::ReadinessIo { role: tui }, "readiness-io"),
            (
                ProcessError::InvalidReadiness { role: tui },
                "invalid-readiness",
            ),
            (
                ProcessError::EarlyExit {
                    role: tui,
                    disposition: ChildDisposition::NotStarted,
                },
                "early-exit",
            ),
            (
                ProcessError::Signal {
                    role: tui,
                    action: StopAction::Kill,
                },
                "signal",
            ),
            (
                ProcessError::ForwardedSignalMismatch { role: tui },
                "forwarded-signal-mismatch",
            ),
            (
                ProcessError::SuspendTimeout { role: tui },
                "suspend-timeout",
            ),
            (ProcessError::Wait { role: tui }, "wait"),
            (ProcessError::WaitTimeout { role: tui }, "wait-timeout"),
            (
                ProcessError::TuiOutputDrain { role: tui },
                "tui-output-drain",
            ),
            (
                ProcessError::RoleMismatch {
                    expected: tui,
                    actual: ChildRole::AppServer,
                },
                "role-mismatch",
            ),
            (ProcessError::RetryAfterResolution, "retry-after-resolution"),
            (ProcessError::Deadline, "deadline"),
        ];

        for (error, suffix) in cases {
            assert_eq!(
                packaged_startup_tui_process_error_marker(error),
                format!("guardian-retained.startup-quiesce.tui.error.{suffix}")
            );
            assert_eq!(
                packaged_startup_app_process_error_marker(error),
                format!("guardian-retained.startup-quiesce.app.error.{suffix}")
            );
        }
        assert_eq!(
            packaged_startup_tui_process_error_marker(ProcessError::AppGracefulDrainUnconfirmed {
                role: tui,
                stage: AppGracefulDrainFailureStage::InvalidDisposition,
            }),
            "guardian-retained.startup-quiesce.tui.error.app-graceful-drain-unconfirmed"
        );
        assert_eq!(
            [
                AppGracefulDrainFailureStage::PriorInvalid,
                AppGracefulDrainFailureStage::ExitedBeforeTerm,
                AppGracefulDrainFailureStage::StopTimeout,
                AppGracefulDrainFailureStage::ExitedWhileStopping,
                AppGracefulDrainFailureStage::InvalidDisposition,
                AppGracefulDrainFailureStage::KillForbidden,
                AppGracefulDrainFailureStage::WrongRetryPath,
                AppGracefulDrainFailureStage::MissingProof,
            ]
            .map(|stage| {
                packaged_startup_app_process_error_marker(
                    ProcessError::AppGracefulDrainUnconfirmed { role: tui, stage },
                )
            }),
            [
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.prior-invalid",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.exited-before-term",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.stop-timeout",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.exited-while-stopping",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.invalid-disposition",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.kill-forbidden",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.wrong-retry-path",
                "guardian-retained.startup-quiesce.app.error.app-graceful-drain-unconfirmed.missing-proof",
            ]
        );
    }

    #[test]
    fn packaged_compatibility_failure_markers_are_closed_and_fixed() {
        let cases = [
            (
                CodexHandoffError::Unsupported,
                "startup-failure.compatibility.subtype.unsupported",
            ),
            (
                CodexHandoffError::Protocol,
                "startup-failure.compatibility.subtype.protocol",
            ),
            (
                CodexHandoffError::Timeout,
                "startup-failure.compatibility.subtype.timeout",
            ),
            (
                CodexHandoffError::Transport,
                "startup-failure.compatibility.subtype.transport",
            ),
            (
                CodexHandoffError::Spawn,
                "startup-failure.compatibility.subtype.spawn",
            ),
        ];
        let mapped = cases.map(|(error, expected)| {
            let marker = packaged_compatibility_failure_marker(error);
            assert_eq!(marker, expected);
            marker
        });

        assert_eq!(mapped.as_slice(), PACKAGED_COMPATIBILITY_FAILURE_MARKERS);
        let mut unique = mapped.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), mapped.len());
    }

    #[test]
    fn packaged_app_socket_failure_markers_are_closed_and_fixed() {
        use super::super::process::ProcessError;
        use super::super::protocol::{ChildDisposition, StopAction};
        use super::super::provider::{AppServerTopologyError, ProviderLaunchError};
        use super::super::runtime::AppSocketError;
        use calcifer_unix_child_fd::ProcessGroupDescriptorScanError;

        let mut mapped = Vec::new();
        let cross_session =
            packaged_app_socket_failure_marker(AppServerTopologyError::CrossSessionSocket);
        assert_eq!(
            cross_session,
            "startup-failure.app-socket.subtype.cross-session-socket"
        );
        mapped.push(cross_session);

        let descriptor_cases = [
            (
                ProcessGroupDescriptorScanError::InvalidArgument,
                "invalid-argument",
            ),
            (
                ProcessGroupDescriptorScanError::ProcessLimit,
                "process-limit",
            ),
            (ProcessGroupDescriptorScanError::MemberLimit, "member-limit"),
            (
                ProcessGroupDescriptorScanError::DescriptorLimit,
                "descriptor-limit",
            ),
            (
                ProcessGroupDescriptorScanError::ForbiddenIdentityLimit,
                "forbidden-identity-limit",
            ),
            (ProcessGroupDescriptorScanError::Deadline, "deadline"),
            (
                ProcessGroupDescriptorScanError::PermissionDenied,
                "permission-denied",
            ),
            (
                ProcessGroupDescriptorScanError::ProcessUserMismatch,
                "process-user-mismatch",
            ),
            (
                ProcessGroupDescriptorScanError::ProcessChanged,
                "process-changed",
            ),
            (
                ProcessGroupDescriptorScanError::DescriptorChanged,
                "descriptor-changed",
            ),
            (
                ProcessGroupDescriptorScanError::ForbiddenDescriptor,
                "forbidden-descriptor",
            ),
            (
                ProcessGroupDescriptorScanError::UnsupportedDescriptor,
                "unsupported-descriptor",
            ),
            (
                ProcessGroupDescriptorScanError::ObservationFailed,
                "observation-failed",
            ),
        ];
        for (error, suffix) in descriptor_cases {
            let marker = packaged_app_socket_failure_marker(
                AppServerTopologyError::DescriptorIsolation(error),
            );
            assert_eq!(
                marker,
                format!("startup-failure.app-socket.subtype.descriptor-isolation.{suffix}")
            );
            mapped.push(marker);
        }

        let provider_cases = [
            (ProviderLaunchError::InvalidArgument, "invalid-argument"),
            (ProviderLaunchError::AuthorityConsumed, "authority-consumed"),
            (ProviderLaunchError::SessionInUse, "session-in-use"),
            (ProviderLaunchError::ExecutableChanged, "executable-changed"),
            (ProviderLaunchError::SessionChanged, "session-changed"),
            (ProviderLaunchError::Storage, "storage"),
            (ProviderLaunchError::Timeout, "timeout"),
        ];
        for (error, suffix) in provider_cases {
            let marker =
                packaged_app_socket_failure_marker(AppServerTopologyError::Provider(error));
            assert_eq!(
                marker,
                format!("startup-failure.app-socket.subtype.provider.{suffix}")
            );
            mapped.push(marker);
        }

        let socket_cases = [
            (AppSocketError::UnsafeRuntime, "unsafe-runtime"),
            (AppSocketError::PathTooLong, "path-too-long"),
            (AppSocketError::Collision, "collision"),
            (AppSocketError::UnknownEntry, "unknown-entry"),
            (AppSocketError::SocketNotReady, "socket-not-ready"),
            (AppSocketError::UnsafeNode, "unsafe-node"),
            #[cfg(target_os = "linux")]
            (
                AppSocketError::IdentityLeaseUnavailable,
                "identity-lease-unavailable",
            ),
            (AppSocketError::IdentityMismatch, "identity-mismatch"),
            (AppSocketError::SocketStillPresent, "socket-still-present"),
            (AppSocketError::AdoptionTimeout, "adoption-timeout"),
            (AppSocketError::Timeout, "timeout"),
            (AppSocketError::Cleanup, "cleanup"),
        ];
        for (error, suffix) in socket_cases {
            let marker = packaged_app_socket_failure_marker(AppServerTopologyError::Socket(error));
            assert_eq!(
                marker,
                format!("startup-failure.app-socket.subtype.socket.{suffix}")
            );
            mapped.push(marker);
        }

        let role = ChildRole::AppServer;
        let process_cases = [
            ProcessError::Spawn { role },
            ProcessError::ProcessGroupReadback { role },
            ProcessError::ProcessGroupMismatch { role },
            ProcessError::SessionReadback { role },
            ProcessError::SessionMismatch { role },
            ProcessError::SessionStartupTimeout { role },
            ProcessError::SpawnCleanupTimeout { role },
            ProcessError::SpawnContainmentUnconfirmed { role },
            ProcessError::ReadinessUnavailable { role },
            ProcessError::ParentLivenessUnavailable { role },
            ProcessError::ReadinessTimeout { role },
            ProcessError::ReadinessIo { role },
            ProcessError::InvalidReadiness { role },
            ProcessError::EarlyExit {
                role,
                disposition: ChildDisposition::NotStarted,
            },
            ProcessError::Signal {
                role,
                action: StopAction::Kill,
            },
            ProcessError::ForwardedSignalMismatch { role },
            ProcessError::SuspendTimeout { role },
            ProcessError::Wait { role },
            ProcessError::WaitTimeout { role },
            ProcessError::TuiOutputDrain { role },
            ProcessError::RoleMismatch {
                expected: role,
                actual: ChildRole::Tui,
            },
            ProcessError::RetryAfterResolution,
            ProcessError::Deadline,
        ];
        mapped.extend(process_cases.map(|error| {
            packaged_app_socket_failure_marker(AppServerTopologyError::Process(error))
        }));
        mapped.extend(
            [
                AppGracefulDrainFailureStage::PriorInvalid,
                AppGracefulDrainFailureStage::ExitedBeforeTerm,
                AppGracefulDrainFailureStage::StopTimeout,
                AppGracefulDrainFailureStage::ExitedWhileStopping,
                AppGracefulDrainFailureStage::InvalidDisposition,
                AppGracefulDrainFailureStage::KillForbidden,
                AppGracefulDrainFailureStage::WrongRetryPath,
                AppGracefulDrainFailureStage::MissingProof,
            ]
            .map(|stage| {
                packaged_app_socket_failure_marker(AppServerTopologyError::Process(
                    ProcessError::AppGracefulDrainUnconfirmed { role, stage },
                ))
            }),
        );

        let mapped_count = mapped.len();
        mapped.sort_unstable();
        mapped.dedup();
        assert_eq!(
            mapped.len(),
            mapped_count,
            "two mapper branches emitted the same fixed marker"
        );

        let mut catalog = PACKAGED_APP_SOCKET_FAILURE_MARKERS.to_vec();
        let catalog_count = catalog.len();
        catalog.sort_unstable();
        catalog.dedup();
        assert_eq!(
            catalog.len(),
            catalog_count,
            "the closed failure catalog contained a duplicate"
        );
        assert_eq!(
            mapped, catalog,
            "the exhaustive mapper outputs and scanner catalog diverged"
        );
        assert!(catalog.iter().all(|marker| {
            marker.is_ascii()
                && marker.starts_with("startup-failure.app-socket.subtype.")
                && !marker.contains('/')
                && !marker.contains(' ')
        }));
    }

    #[test]
    fn retained_phase_retry_keeps_the_same_owner_and_retries_only_that_phase() {
        let mut backend = FakePhaseBackend::at(StartupShutdownPhase::Tui);
        backend.retain_once = Some(StartupShutdownPhase::Relay);
        let token = backend.owner_token;
        assert_eq!(
            drive_startup_phases(
                &mut backend,
                StartupShutdownPhase::AwaitingCoordinatorRestore,
                shutdown_bounds(),
            ),
            StartupStep::Retained
        );
        assert_eq!(backend.phase, StartupShutdownPhase::Relay);
        assert_eq!(backend.owner_token, token);
        assert_eq!(
            backend.calls,
            [StartupShutdownPhase::Tui, StartupShutdownPhase::Relay]
        );

        assert_eq!(
            drive_startup_phases(
                &mut backend,
                StartupShutdownPhase::AwaitingCoordinatorRestore,
                shutdown_bounds(),
            ),
            StartupStep::Advanced
        );
        assert_eq!(backend.owner_token, token);
        assert_eq!(
            backend.calls,
            [
                StartupShutdownPhase::Tui,
                StartupShutdownPhase::Relay,
                StartupShutdownPhase::Relay,
                StartupShutdownPhase::Monitor,
                StartupShutdownPhase::AppStop,
                StartupShutdownPhase::TerminalQuiesce,
            ]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeStartupEdge {
        Compatibility,
        Runtime,
        AppPlan,
        AppLaunch,
        AppLifecycleReport,
        AppEarlyExit,
        AppAdoption,
        MonitorConnect,
        MonitorStart,
        RelayPlan,
        RelayStart,
        TuiPlan,
        TuiLaunch,
        TuiReadiness,
        SessionReadiness,
        Deadline,
    }

    impl FakeStartupEdge {
        const fn first_owned_phase(self) -> StartupShutdownPhase {
            match self {
                Self::TuiLaunch | Self::TuiReadiness | Self::SessionReadiness => {
                    StartupShutdownPhase::Tui
                }
                Self::RelayStart => StartupShutdownPhase::Relay,
                Self::Compatibility
                | Self::AppLaunch
                | Self::AppLifecycleReport
                | Self::AppEarlyExit
                | Self::AppAdoption
                | Self::MonitorConnect
                | Self::MonitorStart => StartupShutdownPhase::AppStop,
                Self::RelayPlan | Self::TuiPlan => StartupShutdownPhase::Monitor,
                Self::Runtime | Self::AppPlan | Self::Deadline => {
                    StartupShutdownPhase::TerminalQuiesce
                }
            }
        }
    }

    #[test]
    fn startup_edge_matrix_assigns_every_partial_authority_to_its_cleanup_phase() {
        let cases = [
            (
                FakeStartupEdge::Compatibility,
                StartupShutdownPhase::AppStop,
            ),
            (
                FakeStartupEdge::Runtime,
                StartupShutdownPhase::TerminalQuiesce,
            ),
            (
                FakeStartupEdge::AppPlan,
                StartupShutdownPhase::TerminalQuiesce,
            ),
            (FakeStartupEdge::AppLaunch, StartupShutdownPhase::AppStop),
            (
                FakeStartupEdge::AppLifecycleReport,
                StartupShutdownPhase::AppStop,
            ),
            (FakeStartupEdge::AppEarlyExit, StartupShutdownPhase::AppStop),
            (FakeStartupEdge::AppAdoption, StartupShutdownPhase::AppStop),
            (
                FakeStartupEdge::MonitorConnect,
                StartupShutdownPhase::AppStop,
            ),
            (FakeStartupEdge::MonitorStart, StartupShutdownPhase::AppStop),
            (FakeStartupEdge::RelayPlan, StartupShutdownPhase::Monitor),
            (FakeStartupEdge::RelayStart, StartupShutdownPhase::Relay),
            (FakeStartupEdge::TuiPlan, StartupShutdownPhase::Monitor),
            (FakeStartupEdge::TuiLaunch, StartupShutdownPhase::Tui),
            (FakeStartupEdge::TuiReadiness, StartupShutdownPhase::Tui),
            (FakeStartupEdge::SessionReadiness, StartupShutdownPhase::Tui),
            (
                FakeStartupEdge::Deadline,
                StartupShutdownPhase::TerminalQuiesce,
            ),
        ];
        for (edge, expected) in cases {
            assert_eq!(edge.first_owned_phase(), expected, "edge {edge:?}");
        }
    }

    #[test]
    fn fixed_fault_harness_preserves_every_owner_across_the_restore_barrier() {
        let faults = [
            (FakeStartupEdge::Compatibility, 1_u64),
            (FakeStartupEdge::Runtime, 2),
            (FakeStartupEdge::AppLifecycleReport, 3),
            (FakeStartupEdge::AppEarlyExit, 4),
            (FakeStartupEdge::MonitorConnect, 5),
            (FakeStartupEdge::MonitorStart, 6),
            (FakeStartupEdge::RelayStart, 7),
            (FakeStartupEdge::TuiReadiness, 8),
            (FakeStartupEdge::Deadline, 9),
        ];

        for (fault, token) in faults {
            let mut backend = FakePhaseBackend::at(StartupShutdownPhase::Tui);
            backend.owner_token = token;
            assert_eq!(
                drive_startup_phases(
                    &mut backend,
                    StartupShutdownPhase::AwaitingCoordinatorRestore,
                    shutdown_bounds(),
                ),
                StartupStep::Advanced,
                "fault {fault:?}",
            );
            assert_eq!(backend.owner_token, token, "fault {fault:?}");
            assert_eq!(
                backend.phase,
                StartupShutdownPhase::AwaitingCoordinatorRestore,
                "fault {fault:?}",
            );
            assert!(
                !backend
                    .calls
                    .contains(&StartupShutdownPhase::RecoveryDisarm),
                "fault {fault:?}",
            );
            assert!(
                !backend
                    .calls
                    .contains(&StartupShutdownPhase::RuntimeCleanup),
                "fault {fault:?}",
            );
            assert!(
                !backend.calls.contains(&StartupShutdownPhase::BuildCleanup),
                "fault {fault:?}",
            );

            // This explicit transition represents consumption of the typed
            // restoration proof. The production owner exposes no such setter.
            backend.set_phase(StartupShutdownPhase::RecoveryDisarm);
            assert_eq!(
                drive_startup_phases(
                    &mut backend,
                    StartupShutdownPhase::Complete,
                    shutdown_bounds(),
                ),
                StartupStep::Advanced,
                "fault {fault:?}",
            );
            assert_eq!(backend.owner_token, token, "fault {fault:?}");
            assert_eq!(
                &backend.calls[5..],
                [
                    StartupShutdownPhase::RecoveryDisarm,
                    StartupShutdownPhase::RuntimeCleanup,
                    StartupShutdownPhase::BuildCleanup,
                ],
                "fault {fault:?}",
            );
        }
    }

    struct FakeReporter {
        events: Vec<ContainmentMetadata>,
        fail_on: Option<usize>,
    }

    impl StartupLifecycleReporter for FakeReporter {
        fn append_forbidden_descriptors<'source>(
            &'source self,
            _forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
        ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
            Ok(())
        }

        fn child_started(
            &mut self,
            child: ContainmentMetadata,
            _deadline: Instant,
        ) -> Result<(), StartupLifecycleReportError> {
            let index = self.events.len();
            self.events.push(child);
            if self.fail_on == Some(index) {
                Err(StartupLifecycleReportError)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug)]
    struct DropProbe(Rc<Cell<usize>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn lifecycle_reporter_observes_exact_app_then_tui_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = ContainmentMetadata::for_test(ChildRole::AppServer, 101, 101);
        let tui = ContainmentMetadata::for_test(ChildRole::Tui, 202, 202);
        let mut reporter = FakeReporter {
            events: Vec::new(),
            fail_on: None,
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        report_child_started_or_retain((), app, &mut reporter, deadline)
            .map_err(|_| "App ChildStarted")?;
        report_child_started_or_retain((), tui, &mut reporter, deadline)
            .map_err(|_| "TUI ChildStarted")?;
        assert_eq!(reporter.events, [app, tui]);
        assert_eq!(reporter.events[0].role(), ChildRole::AppServer);
        assert_eq!(reporter.events[1].role(), ChildRole::Tui);
        assert_eq!(reporter.events[0].pid(), reporter.events[0].pgid());
        assert_eq!(reporter.events[1].pid(), reporter.events[1].pgid());
        Ok(())
    }

    #[test]
    fn lifecycle_send_failure_returns_the_exact_undropped_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let dropped = Rc::new(Cell::new(0));
        let owner = DropProbe(Rc::clone(&dropped));
        let app = ContainmentMetadata::for_test(ChildRole::AppServer, 303, 303);
        let mut reporter = FakeReporter {
            events: Vec::new(),
            fail_on: Some(0),
        };
        let owner = report_child_started_or_retain(
            owner,
            app,
            &mut reporter,
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or("failed lifecycle send must return ownership")?;
        assert_eq!(dropped.get(), 0);
        assert_eq!(reporter.events, [app]);
        drop(owner);
        assert_eq!(dropped.get(), 1);
        Ok(())
    }

    #[test]
    fn cleanup_report_never_upgrades_a_failed_startup_to_success() {
        let clean = StartupCleanupReport {
            startup_error: SupervisedStartupError::RelayStart,
            details: StartupCleanupDetails::Partial(PartialStartupCleanupDetails {
                cleanup_errors: StartupCleanupErrors::default(),
                provider_release: provider_never_started(),
                tui_outcome: None,
                worker_join_status: WorkerJoinStatus::NotStarted,
                terminal_reportable: true,
            }),
        };
        assert!(clean.cleanup_errors_empty());
        assert!(!clean.is_success());

        let mut errors = StartupCleanupErrors::default();
        errors.record(StartupCleanupError::Runtime);
        let dirty = StartupCleanupReport {
            startup_error: SupervisedStartupError::Runtime,
            details: StartupCleanupDetails::Partial(PartialStartupCleanupDetails {
                cleanup_errors: errors,
                provider_release: provider_never_started(),
                tui_outcome: None,
                worker_join_status: WorkerJoinStatus::NotStarted,
                terminal_reportable: true,
            }),
        };
        assert!(!dirty.cleanup_errors_empty());
        assert!(!dirty.is_success());
    }
}
