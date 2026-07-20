//! Production coordinator for one supervised terminal generation.
//!
//! The coordinator owns lock A, the exact direct guardian child, the only
//! coordinator lifecycle endpoint, the outer-terminal state machine, and all
//! process signal latches. Guardian-reported PIDs are validated by the fixed
//! protocol but are never retained or used as signal/wait authority.

use std::fmt;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use crate::profiles::CoordinatorProfileLease;

use super::authority::{RetainedCoordinatorLease, RetentionReason};
use super::channel::LifecycleEndpoint;
use super::coordinator_terminal::{
    Active, CoordinatorPumpProgress, CoordinatorTerminal, CoordinatorTerminalError, GateReady,
    OutputOnly, Paused, Quiesced, RawAwaitAck, Restored, ResumeRaw, SuspendedRestored,
};
use super::protocol::{
    ChildDisposition, CleanupStatus, CoordinatorCommand, CoordinatorReceiver, FailureCode,
    GuardianEvent, GuardianExitDisposition, Phase, ProtocolError, SessionStatus,
    TerminalSnapshotFingerprint, UnixSignal, VerifiedOpenGateAck, VerifiedReady, WorkerJoinStatus,
};
use super::signals::{
    CoordinatorSignalAction, CoordinatorSignalInstallError, CoordinatorSignalLatches,
};
use super::terminal::{RestoredTerminalProof, TerminalSize};

/// Per-operation limits. A session may live indefinitely, but no lifecycle
/// read/write, pump fragment, control handshake, or exact child wait inherits
/// an unbounded deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorBounds {
    phase_timeout: Duration,
    poll_interval: Duration,
}

impl CoordinatorBounds {
    pub(super) fn new(
        phase_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, CoordinatorSetupError> {
        if phase_timeout.is_zero()
            || poll_interval.is_zero()
            || poll_interval > phase_timeout
            || Instant::now().checked_add(phase_timeout).is_none()
        {
            return Err(CoordinatorSetupError::Deadline);
        }
        Ok(Self {
            phase_timeout,
            poll_interval,
        })
    }

    fn phase_deadline(self) -> Result<Instant, CoordinatorDriveError> {
        Instant::now()
            .checked_add(self.phase_timeout)
            .ok_or(CoordinatorDriveError::Deadline)
    }

    fn turn_deadline(self, outer: Instant) -> Result<Instant, CoordinatorDriveError> {
        let local = Instant::now()
            .checked_add(self.poll_interval)
            .ok_or(CoordinatorDriveError::Deadline)?;
        Ok(local.min(outer))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorSetupError {
    Deadline,
    Lifecycle,
    Signals,
}

impl fmt::Display for CoordinatorSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the production coordinator could not be assembled")
    }
}

impl std::error::Error for CoordinatorSetupError {}

/// Setup failure retains every exact authority supplied by the caller.
#[must_use = "coordinator setup failure retains lock, child, channel, and terminal owners"]
pub(super) struct CoordinatorSetupFailure {
    authority: CoordinatorProfileLease,
    guardian: Child,
    lifecycle: LifecycleEndpoint,
    terminal: CoordinatorTerminal<OutputOnly>,
    error: CoordinatorSetupError,
}

impl fmt::Debug for CoordinatorSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.authority,
            &self.guardian,
            &self.lifecycle,
            &self.terminal,
        );
        formatter
            .debug_struct("CoordinatorSetupFailure")
            .field("error", &self.error)
            .field("retains_all_authority", &true)
            .finish()
    }
}

impl fmt::Display for CoordinatorSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for CoordinatorSetupFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorDriveError {
    Deadline,
    Lifecycle,
    Protocol,
    Snapshot,
    Terminal(CoordinatorTerminalError),
    Signal,
    Guardian,
    DescriptorIsolation(calcifer_unix_child_fd::ProcessGroupDescriptorScanError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorIsolationObservationStage {
    CoordinatorAuthority,
    Lifecycle,
    OuterTerminal,
    TargetProcessGroup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorIsolationObservationFailure {
    stage: DescriptorIsolationObservationStage,
    error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    retryable_target_change: bool,
}

impl DescriptorIsolationObservationFailure {
    const fn source(
        stage: DescriptorIsolationObservationStage,
        error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    ) -> Self {
        Self {
            stage,
            error,
            retryable_target_change: false,
        }
    }

    const fn target(error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError) -> Self {
        Self {
            stage: DescriptorIsolationObservationStage::TargetProcessGroup,
            error,
            retryable_target_change: matches!(
                error,
                calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged
                    | calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged
            ),
        }
    }
}

#[cfg(test)]
fn record_descriptor_isolation_observation_failure(failure: DescriptorIsolationObservationFailure) {
    let stage = failure.stage;
    let error = failure.error;
    eprintln!("descriptor-isolation-observation-failure:stage={stage:?}, error={error:?}");
}

fn final_descriptor_isolation_error(
    failure: DescriptorIsolationObservationFailure,
) -> CoordinatorDriveError {
    #[cfg(test)]
    record_descriptor_isolation_observation_failure(failure);
    CoordinatorDriveError::DescriptorIsolation(failure.error)
}

fn retry_descriptor_isolation_observation<T>(
    deadline: Instant,
    poll_interval: Duration,
    mut attempt: impl FnMut() -> (
        Result<T, DescriptorIsolationObservationFailure>,
        Result<(), CoordinatorDriveError>,
    ),
) -> Result<T, CoordinatorDriveError> {
    loop {
        if Instant::now() >= deadline {
            return Err(CoordinatorDriveError::DescriptorIsolation(
                calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline,
            ));
        }

        let (observation, guardian_liveness) = attempt();
        guardian_liveness?;
        match observation {
            Ok(proof) => return Ok(proof),
            Err(failure) if failure.retryable_target_change => {
                let now = Instant::now();
                if now >= deadline {
                    #[cfg(test)]
                    record_descriptor_isolation_observation_failure(failure);
                    return Err(CoordinatorDriveError::DescriptorIsolation(
                        calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline,
                    ));
                }
                thread::sleep(
                    poll_interval.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(failure) => return Err(final_descriptor_isolation_error(failure)),
        }
    }
}

impl CoordinatorDriveError {
    const fn retention_reason(self) -> RetentionReason {
        match self {
            Self::Lifecycle => RetentionReason::LifecycleLost,
            Self::Protocol | Self::Snapshot => RetentionReason::ProtocolInvalid,
            Self::Guardian => RetentionReason::GuardianExited,
            Self::Deadline => RetentionReason::ShutdownDeadline,
            Self::Terminal(_) | Self::Signal => RetentionReason::InvariantUnconfirmed,
            Self::DescriptorIsolation(_) => RetentionReason::InvariantUnconfirmed,
        }
    }
}

#[cfg(test)]
const fn packaged_coordinator_failure_marker(error: CoordinatorDriveError) -> &'static str {
    match error {
        CoordinatorDriveError::Deadline => "coordinator-retained.error.deadline",
        CoordinatorDriveError::Lifecycle => "coordinator-retained.error.lifecycle",
        CoordinatorDriveError::Protocol => "coordinator-retained.error.protocol",
        CoordinatorDriveError::Snapshot => "coordinator-retained.error.snapshot",
        CoordinatorDriveError::Terminal(error) => {
            packaged_coordinator_terminal_failure_marker(error)
        }
        CoordinatorDriveError::Signal => "coordinator-retained.error.signal",
        CoordinatorDriveError::Guardian => "coordinator-retained.error.guardian",
        CoordinatorDriveError::DescriptorIsolation(_) => {
            "coordinator-retained.error.descriptor-isolation"
        }
    }
}

#[cfg(test)]
const fn packaged_coordinator_terminal_failure_marker(
    error: CoordinatorTerminalError,
) -> &'static str {
    match error {
        CoordinatorTerminalError::Setup => "coordinator-retained.error.terminal.setup",
        CoordinatorTerminalError::Deadline => "coordinator-retained.error.terminal.deadline",
        CoordinatorTerminalError::OuterTerminalEof => {
            "coordinator-retained.error.terminal.outer-eof"
        }
        CoordinatorTerminalError::TerminalChannelRead => {
            "coordinator-retained.error.terminal.channel-read"
        }
        CoordinatorTerminalError::TerminalChannelWrite => {
            "coordinator-retained.error.terminal.channel-write"
        }
        CoordinatorTerminalError::OuterTerminalRead => {
            "coordinator-retained.error.terminal.outer-read"
        }
        CoordinatorTerminalError::OuterTerminalWrite => {
            "coordinator-retained.error.terminal.outer-write"
        }
        CoordinatorTerminalError::RawTransition => {
            "coordinator-retained.error.terminal.raw-transition"
        }
        CoordinatorTerminalError::Foreground => "coordinator-retained.error.terminal.foreground",
        CoordinatorTerminalError::WindowSize => "coordinator-retained.error.terminal.window-size",
        CoordinatorTerminalError::Restore => "coordinator-retained.error.terminal.restore",
        CoordinatorTerminalError::Shutdown => "coordinator-retained.error.terminal.shutdown",
    }
}

#[cfg(test)]
const fn packaged_coordinator_retention_reason_marker(reason: RetentionReason) -> &'static str {
    match reason {
        RetentionReason::LifecycleLost => "coordinator-retained.reason.lifecycle-lost",
        RetentionReason::ProtocolInvalid => "coordinator-retained.reason.protocol-invalid",
        RetentionReason::GuardianExited => "coordinator-retained.reason.guardian-exited",
        RetentionReason::ShutdownDeadline => "coordinator-retained.reason.shutdown-deadline",
        RetentionReason::ChildrenNotReaped => "coordinator-retained.reason.children-not-reaped",
        RetentionReason::WorkerNotJoined => "coordinator-retained.reason.worker-not-joined",
        RetentionReason::CleanupUnconfirmed => "coordinator-retained.reason.cleanup-unconfirmed",
        RetentionReason::InvariantUnconfirmed => {
            "coordinator-retained.reason.invariant-unconfirmed"
        }
    }
}

impl fmt::Display for CoordinatorDriveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Deadline => "the coordinator operation deadline elapsed",
            Self::Lifecycle => "the coordinator lifecycle channel failed",
            Self::Protocol => "the coordinator lifecycle transcript was invalid",
            Self::Snapshot => "the coordinator terminal snapshot mismatched",
            Self::Terminal(_) => "the coordinator terminal operation failed",
            Self::Signal => "the coordinator signal operation failed",
            Self::Guardian => "the guardian exited before terminal completion",
            Self::DescriptorIsolation(_) => {
                "a provider child retained a coordinator-only descriptor"
            }
        })
    }
}

impl std::error::Error for CoordinatorDriveError {}

fn classify_protocol_error(error: ProtocolError) -> CoordinatorDriveError {
    match error {
        ProtocolError::Timeout => CoordinatorDriveError::Deadline,
        ProtocolError::UnexpectedEof
        | ProtocolError::TruncatedHeader
        | ProtocolError::TruncatedBody
        | ProtocolError::Io => CoordinatorDriveError::Lifecycle,
        _ => CoordinatorDriveError::Protocol,
    }
}

/// Protocol-only owner used by both production and allocation-free scripted
/// tests. `ChildStarted` is intentionally consumed as observation-only data.
struct CoordinatorLifecycle<R> {
    receiver: CoordinatorReceiver<R>,
}

enum BootstrapOutcome {
    Ready(VerifiedReady),
    Failed,
}

enum GateOutcome {
    Open(VerifiedOpenGateAck),
    Failed,
}

impl<R: Read + Write> CoordinatorLifecycle<R> {
    fn new(wire: R) -> Self {
        Self {
            receiver: CoordinatorReceiver::new_terminal(wire),
        }
    }

    fn receive(&mut self, deadline: Instant) -> Result<GuardianEvent, CoordinatorDriveError> {
        self.receiver
            .receive(deadline)
            .map_err(classify_protocol_error)
    }

    fn command(
        &mut self,
        command: CoordinatorCommand,
        deadline: Instant,
    ) -> Result<(), CoordinatorDriveError> {
        self.receiver
            .record_and_send(command, deadline)
            .map_err(classify_protocol_error)
    }

    #[cfg(test)]
    fn bootstrap(
        &mut self,
        snapshot: TerminalSnapshotFingerprint,
        deadline: Instant,
    ) -> Result<BootstrapOutcome, CoordinatorDriveError> {
        if self.receive(deadline)? != GuardianEvent::LeaseCommitted {
            return Err(CoordinatorDriveError::Protocol);
        }
        self.command(CoordinatorCommand::Start, deadline)?;

        loop {
            match self.receive(deadline)? {
                GuardianEvent::TerminalArmed {
                    snapshot: guardian_snapshot,
                } if snapshot.matches(guardian_snapshot) => {
                    self.command(CoordinatorCommand::TerminalArmAccepted, deadline)?;
                }
                GuardianEvent::TerminalArmed { .. } => {
                    return Err(CoordinatorDriveError::Snapshot);
                }
                // Sequence, role and positive PID/PGID syntax are enforced by
                // CoordinatorReceiver. Numeric identities never escape this
                // match and can therefore never become signal authority.
                GuardianEvent::ChildStarted { .. } => {}
                GuardianEvent::Ready => {
                    let readiness = self
                        .receiver
                        .take_verified_ready()
                        .map_err(classify_protocol_error)?;
                    return Ok(BootstrapOutcome::Ready(readiness));
                }
                GuardianEvent::Failed { .. } => return Ok(BootstrapOutcome::Failed),
                _ => return Err(CoordinatorDriveError::Protocol),
            }
        }
    }

    #[cfg(test)]
    fn open_gate(&mut self, deadline: Instant) -> Result<GateOutcome, CoordinatorDriveError> {
        self.command(CoordinatorCommand::OpenInputGate, deadline)?;
        match self.receive(deadline)? {
            GuardianEvent::InputGateOpened => self
                .receiver
                .take_verified_open_gate_ack()
                .map(GateOutcome::Open)
                .map_err(classify_protocol_error),
            GuardianEvent::Failed { .. } => Ok(GateOutcome::Failed),
            _ => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn wire(&self) -> &R {
        self.receiver.wire()
    }

    fn verify_terminal_eof(&mut self, deadline: Instant) -> Result<(), CoordinatorDriveError> {
        self.receiver
            .verify_terminal_eof(deadline)
            .map_err(classify_protocol_error)
    }
}

impl<R: AsFd> CoordinatorLifecycle<R> {
    fn append_forbidden_descriptor<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.as_fd())
    }
}

impl<R: AsFd> AsFd for CoordinatorLifecycle<R> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.receiver.as_fd()
    }
}

enum CoordinatorTerminalOwner {
    OutputOnly(Box<CoordinatorTerminal<OutputOnly>>),
    GateReady(Box<CoordinatorTerminal<GateReady>>),
    RawAwaitAck(Box<CoordinatorTerminal<RawAwaitAck>>),
    Active(Box<CoordinatorTerminal<Active>>),
    Paused(Box<CoordinatorTerminal<Paused>>),
    SuspendedRestored(Box<CoordinatorTerminal<SuspendedRestored>>),
    ResumeRaw(Box<CoordinatorTerminal<ResumeRaw>>),
    Quiesced(Box<CoordinatorTerminal<Quiesced>>),
    Restored(Box<CoordinatorTerminal<Restored>>),
    Finished(RestoredTerminalProof),
}

impl fmt::Debug for CoordinatorTerminalOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::OutputOnly(_) => "output_only",
            Self::GateReady(_) => "gate_ready",
            Self::RawAwaitAck(_) => "raw_await_ack",
            Self::Active(_) => "active",
            Self::Paused(_) => "paused",
            Self::SuspendedRestored(_) => "suspended_restored",
            Self::ResumeRaw(_) => "resume_raw",
            Self::Quiesced(_) => "quiesced",
            Self::Restored(_) => "restored",
            Self::Finished(_) => "finished",
        };
        formatter
            .debug_tuple("CoordinatorTerminalOwner")
            .field(&name)
            .finish()
    }
}

impl CoordinatorTerminalOwner {
    fn append_forbidden_descriptors<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        match self {
            Self::OutputOnly(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::GateReady(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::RawAwaitAck(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::Active(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::Paused(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::SuspendedRestored(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::ResumeRaw(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::Quiesced(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::Restored(owner) => owner.append_forbidden_descriptors(forbidden),
            Self::Finished(_) => {
                Err(calcifer_unix_child_fd::CrossProcessDescriptorIdentityError::ObservationFailed)
            }
        }
    }

    fn snapshot_fingerprint(&self) -> Result<TerminalSnapshotFingerprint, CoordinatorDriveError> {
        match self {
            Self::OutputOnly(owner) => Ok(owner.snapshot_fingerprint()),
            _ => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn pump_output_once(
        self,
        deadline: Instant,
    ) -> Result<(Self, CoordinatorPumpProgress), (Self, CoordinatorTerminalError)> {
        macro_rules! pump {
            ($owner:expr, $variant:ident) => {
                match (*$owner).pump_output_once(deadline) {
                    Ok(turn) => {
                        let progress = turn.progress();
                        Ok((Self::$variant(Box::new(turn.into_owner())), progress))
                    }
                    Err(failure) => {
                        let error = failure.error();
                        Err((Self::$variant(Box::new(failure.into_owner())), error))
                    }
                }
            };
        }

        match self {
            Self::OutputOnly(owner) => pump!(owner, OutputOnly),
            Self::GateReady(owner) => pump!(owner, GateReady),
            Self::RawAwaitAck(owner) => pump!(owner, RawAwaitAck),
            Self::Active(owner) => pump!(owner, Active),
            Self::Paused(owner) => pump!(owner, Paused),
            Self::SuspendedRestored(owner) => pump!(owner, SuspendedRestored),
            Self::ResumeRaw(owner) => pump!(owner, ResumeRaw),
            Self::Quiesced(owner) => pump!(owner, Quiesced),
            owner @ (Self::Restored(_) | Self::Finished(_)) => {
                Ok((owner, CoordinatorPumpProgress::Idle))
            }
        }
    }

    fn pump_input_once(
        self,
        deadline: Instant,
    ) -> Result<(Self, CoordinatorPumpProgress), (Self, CoordinatorTerminalError)> {
        match self {
            Self::Active(owner) => match (*owner).pump_input_once(deadline) {
                Ok(turn) => {
                    let progress = turn.progress();
                    Ok((Self::Active(Box::new(turn.into_owner())), progress))
                }
                Err(failure) => {
                    let error = failure.error();
                    Err((Self::Active(Box::new(failure.into_owner())), error))
                }
            },
            owner => Ok((owner, CoordinatorPumpProgress::Idle)),
        }
    }

    fn current_size(&self) -> Result<TerminalSize, CoordinatorDriveError> {
        let result = match self {
            Self::Active(owner) => owner.current_size(),
            Self::SuspendedRestored(owner) => owner.current_size(),
            Self::ResumeRaw(owner) => owner.current_size(),
            _ => return Err(CoordinatorDriveError::Protocol),
        };
        result.map_err(CoordinatorDriveError::Terminal)
    }

    fn mark_ready(self, readiness: VerifiedReady) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::OutputOnly(owner) => {
                Ok(Self::GateReady(Box::new((*owner).mark_ready(readiness))))
            }
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn enter_initial_raw(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::GateReady(owner) => match (*owner).enter_raw() {
                Ok(owner) => Ok(Self::RawAwaitAck(Box::new(owner))),
                Err(failure) => {
                    let error = failure.error();
                    Err((
                        Self::GateReady(Box::new(failure.into_owner())),
                        CoordinatorDriveError::Terminal(error),
                    ))
                }
            },
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn open_after_ack(
        self,
        acknowledgement: VerifiedOpenGateAck,
    ) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::RawAwaitAck(owner) => Ok(Self::Active(Box::new(
                (*owner).open_after_ack(acknowledgement),
            ))),
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn pause(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::Active(owner) => Ok(Self::Paused(Box::new((*owner).pause_for_suspend()))),
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn restore_for_suspend(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::Paused(owner) => match (*owner).restore_for_suspend() {
                Ok(owner) => Ok(Self::SuspendedRestored(Box::new(owner))),
                Err(failure) => {
                    let error = failure.error();
                    Err((
                        Self::Paused(Box::new(failure.into_owner())),
                        CoordinatorDriveError::Terminal(error),
                    ))
                }
            },
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn enter_resume_raw(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::SuspendedRestored(owner) => match (*owner).enter_raw_after_continue() {
                Ok(owner) => Ok(Self::ResumeRaw(Box::new(owner))),
                Err(failure) => {
                    let error = failure.error();
                    Err((
                        Self::Quiesced(Box::new(failure.into_owner())),
                        CoordinatorDriveError::Terminal(error),
                    ))
                }
            },
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn mark_resumed(self, readiness: VerifiedReady) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::ResumeRaw(owner) => Ok(Self::RawAwaitAck(Box::new(
                (*owner).mark_resumed(readiness),
            ))),
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn quiesce(self) -> Self {
        match self {
            Self::OutputOnly(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            Self::GateReady(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            Self::RawAwaitAck(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            Self::Active(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            Self::Paused(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            Self::SuspendedRestored(owner) => {
                Self::Quiesced(Box::new((*owner).quiesce_after_suspend()))
            }
            Self::ResumeRaw(owner) => Self::Quiesced(Box::new((*owner).quiesce())),
            owner @ (Self::Quiesced(_) | Self::Restored(_) | Self::Finished(_)) => owner,
        }
    }

    fn restore(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::Quiesced(owner) => match (*owner).restore() {
                Ok(owner) => Ok(Self::Restored(Box::new(owner))),
                Err(failure) => {
                    let error = failure.error();
                    Err((
                        Self::Quiesced(Box::new(failure.into_owner())),
                        CoordinatorDriveError::Terminal(error),
                    ))
                }
            },
            owner @ (Self::Restored(_) | Self::Finished(_)) => Ok(owner),
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }

    fn finish(self) -> Result<Self, (Self, CoordinatorDriveError)> {
        match self {
            Self::Restored(owner) => match (*owner).finish() {
                Ok(proof) => Ok(Self::Finished(proof)),
                Err(failure) => {
                    let error = failure.error();
                    Err((
                        Self::Restored(Box::new(failure.into_owner())),
                        CoordinatorDriveError::Terminal(error),
                    ))
                }
            },
            owner @ Self::Finished(_) => Ok(owner),
            owner => Err((owner, CoordinatorDriveError::Protocol)),
        }
    }
}

/// Complete protocol terminal payload retained until exact guardian wait and
/// lifecycle EOF have both succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorTerminalReport {
    pub(super) app: ChildDisposition,
    pub(super) tui: ChildDisposition,
    pub(super) worker: WorkerJoinStatus,
    pub(super) cleanup: CleanupStatus,
    pub(super) session: SessionStatus,
    pub(super) guardian_exit: GuardianExitDisposition,
}

/// Successful terminal result. Dropping this value may release A because all
/// guardian cleanup, exact wait, terminal EOF, and restoration proofs exist.
#[must_use = "the terminal coordinator result still owns profile authority"]
pub(super) struct CoordinatorTerminalResult {
    authority: CoordinatorProfileLease,
    guardian_status: ExitStatus,
    report: CoordinatorTerminalReport,
}

impl CoordinatorTerminalResult {
    pub(super) const fn report(&self) -> CoordinatorTerminalReport {
        self.report
    }

    #[cfg(test)]
    pub(super) const fn guardian_status(&self) -> ExitStatus {
        self.guardian_status
    }

    pub(super) fn into_authority(self) -> CoordinatorProfileLease {
        self.authority
    }
}

impl fmt::Debug for CoordinatorTerminalResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.authority;
        formatter
            .debug_struct("CoordinatorTerminalResult")
            .field("guardian_status", &self.guardian_status)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

/// Fail-closed outcome. A is forgotten on Drop, while all other exact owners
/// remain available to a process-lifetime park loop or test-only inspection.
#[must_use = "retained coordinator authority must be parked or explicitly inspected"]
pub(super) struct RetainedCoordinatorGeneration {
    owners: RetainedLinearOwners<
        CoordinatorProfileLease,
        Child,
        CoordinatorLifecycle<LifecycleEndpoint>,
        CoordinatorTerminalOwner,
        CoordinatorSignalLatches,
    >,
    guardian_status: Option<ExitStatus>,
    guardian_poll_interval: Duration,
    reason: RetentionReason,
    failure: CoordinatorDriveError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedGuardianPoll {
    Pending,
    Reaped(ExitStatus),
    Uncertain,
}

/// Observes only the exact `Child` owner supplied by the retained generation.
/// A cached status is linear and idempotent; an uncertain wait can never be
/// flattened into a successful reap.
fn poll_retained_guardian(
    status: &mut Option<ExitStatus>,
    observe: impl FnOnce() -> std::io::Result<Option<ExitStatus>>,
) -> RetainedGuardianPoll {
    if let Some(status) = *status {
        return RetainedGuardianPoll::Reaped(status);
    }
    match observe() {
        Ok(Some(observed)) => {
            *status = Some(observed);
            RetainedGuardianPoll::Reaped(observed)
        }
        Ok(None) => RetainedGuardianPoll::Pending,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            RetainedGuardianPoll::Pending
        }
        Err(_) => RetainedGuardianPoll::Uncertain,
    }
}

fn pin_retained_value<T>(value: T) {
    std::mem::forget(value);
}

/// Generic all-fields leak boundary. Keeping the mechanism generic makes the
/// accidental-Drop invariant testable with probes instead of relying on a
/// live process/tty fixture merely to observe destructors.
struct RetainedLinearOwners<A, G, L, T, S> {
    authority: Option<A>,
    guardian: Option<G>,
    lifecycle: Option<L>,
    terminal: Option<T>,
    signals: Option<S>,
}

impl<A, G, L, T, S> RetainedLinearOwners<A, G, L, T, S> {
    fn new(authority: A, guardian: G, lifecycle: L, terminal: T, signals: S) -> Self {
        Self {
            authority: Some(authority),
            guardian: Some(guardian),
            lifecycle: Some(lifecycle),
            terminal: Some(terminal),
            signals: Some(signals),
        }
    }

    #[cfg(test)]
    fn take_for_test(mut self) -> (A, G, L, T, S) {
        let (Some(authority), Some(guardian), Some(lifecycle), Some(terminal), Some(signals)) = (
            self.authority.take(),
            self.guardian.take(),
            self.lifecycle.take(),
            self.terminal.take(),
            self.signals.take(),
        ) else {
            std::process::abort();
        };
        (authority, guardian, lifecycle, terminal, signals)
    }

    fn take_authority_for_retention(mut self) -> A {
        let Some(authority) = self.authority.take() else {
            std::process::abort();
        };
        if let Some(guardian) = self.guardian.take() {
            std::mem::forget(guardian);
        }
        if let Some(lifecycle) = self.lifecycle.take() {
            std::mem::forget(lifecycle);
        }
        if let Some(terminal) = self.terminal.take() {
            std::mem::forget(terminal);
        }
        if let Some(signals) = self.signals.take() {
            std::mem::forget(signals);
        }
        authority
    }
}

impl<A, G, L, T, S> Drop for RetainedLinearOwners<A, G, L, T, S> {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.take() {
            std::mem::forget(authority);
        }
        if let Some(guardian) = self.guardian.take() {
            std::mem::forget(guardian);
        }
        if let Some(lifecycle) = self.lifecycle.take() {
            std::mem::forget(lifecycle);
        }
        if let Some(terminal) = self.terminal.take() {
            std::mem::forget(terminal);
        }
        if let Some(signals) = self.signals.take() {
            std::mem::forget(signals);
        }
    }
}

impl RetainedCoordinatorGeneration {
    #[cfg(test)]
    pub(super) const fn reason(&self) -> RetentionReason {
        self.reason
    }

    #[cfg(test)]
    const fn failure_for_test(&self) -> CoordinatorDriveError {
        self.failure
    }

    #[cfg(test)]
    pub(super) const fn packaged_marker_names(&self) -> [&'static str; 2] {
        [
            packaged_coordinator_failure_marker(self.failure),
            packaged_coordinator_retention_reason_marker(self.reason),
        ]
    }

    pub(super) fn into_retained_lease(self) -> RetainedCoordinatorLease {
        let reason = self.reason;
        let authority = self.owners.take_authority_for_retention();
        RetainedCoordinatorLease::new(authority, reason)
    }

    pub(super) fn park(mut self) -> ! {
        loop {
            let guardian = self
                .owners
                .guardian
                .as_mut()
                .unwrap_or_else(|| std::process::abort());
            match poll_retained_guardian(&mut self.guardian_status, || guardian.try_wait()) {
                RetainedGuardianPoll::Reaped(_) => break,
                RetainedGuardianPoll::Pending => {
                    // Every kernel observation remains nonblocking and every
                    // retry interval remains bounded. The generation itself
                    // may live forever because retention is fail-closed.
                    thread::sleep(self.guardian_poll_interval);
                }
                RetainedGuardianPoll::Uncertain => self.park_with_all_owners(),
            }
        }
        // Exact guardian reap removes zombie residue but cannot repair the
        // shutdown lifecycle transcript. A therefore remains retained by the
        // existing process-lifetime lease park.
        self.into_retained_lease().park()
    }

    fn park_with_all_owners(self) -> ! {
        pin_retained_value(self);
        loop {
            thread::park();
        }
    }

    #[cfg(test)]
    fn release_for_test(self) -> CoordinatorProfileLease {
        let (authority, guardian, lifecycle, terminal, signals) = self.owners.take_for_test();
        drop((guardian, lifecycle, terminal, signals));
        authority
    }
}

impl fmt::Debug for RetainedCoordinatorGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.owners.authority,
            &self.owners.guardian,
            &self.guardian_status,
            &self.owners.lifecycle,
            &self.owners.terminal,
            &self.owners.signals,
        );
        formatter
            .debug_struct("RetainedCoordinatorGeneration")
            .field("reason", &self.reason)
            .field("failure", &self.failure)
            .field("retains_all_authority", &true)
            .finish()
    }
}

pub(super) enum CoordinatorRunOutcome {
    Terminal(CoordinatorTerminalResult),
    Retained(Box<RetainedCoordinatorGeneration>),
}

/// Exact production owner for one coordinator generation.
pub(super) struct ProductionCoordinator {
    authority: CoordinatorProfileLease,
    guardian: Child,
    guardian_status: Option<ExitStatus>,
    lifecycle: CoordinatorLifecycle<LifecycleEndpoint>,
    terminal: Option<CoordinatorTerminalOwner>,
    signals: CoordinatorSignalLatches,
    bounds: CoordinatorBounds,
    session_failed: bool,
}

enum ActiveOutcome {
    Quiesced,
    Failed,
}

enum ControlOutcome {
    Continue,
    Shutdown,
    Quiesced,
    Failed,
}

fn guardian_status_matches(status: ExitStatus, disposition: GuardianExitDisposition) -> bool {
    match disposition {
        GuardianExitDisposition::Code(code) => status.code() == Some(i32::from(code)),
        GuardianExitDisposition::Signal(signal) => status.signal() == Some(i32::from(signal)),
        GuardianExitDisposition::InternalFailure => status.code() == Some(1),
    }
}

impl ProductionCoordinator {
    pub(super) fn assemble(
        authority: CoordinatorProfileLease,
        guardian: Child,
        lifecycle: LifecycleEndpoint,
        terminal: CoordinatorTerminal<OutputOnly>,
        bounds: CoordinatorBounds,
    ) -> Result<Self, Box<CoordinatorSetupFailure>> {
        let lifecycle_ready = lifecycle
            .set_read_timeout(Some(bounds.phase_timeout))
            .and_then(|()| lifecycle.set_write_timeout(Some(bounds.phase_timeout)));
        if lifecycle_ready.is_err() {
            return Err(Box::new(CoordinatorSetupFailure {
                authority,
                guardian,
                lifecycle,
                terminal,
                error: CoordinatorSetupError::Lifecycle,
            }));
        }
        let signals = match CoordinatorSignalLatches::install() {
            Ok(signals) => signals,
            Err(CoordinatorSignalInstallError) => {
                return Err(Box::new(CoordinatorSetupFailure {
                    authority,
                    guardian,
                    lifecycle,
                    terminal,
                    error: CoordinatorSetupError::Signals,
                }));
            }
        };
        Ok(Self {
            authority,
            guardian,
            guardian_status: None,
            lifecycle: CoordinatorLifecycle::new(lifecycle),
            terminal: Some(CoordinatorTerminalOwner::OutputOnly(Box::new(terminal))),
            signals,
            bounds,
            session_failed: false,
        })
    }

    pub(super) fn run(mut self) -> CoordinatorRunOutcome {
        match self.drive() {
            Ok((guardian_status, report)) => {
                CoordinatorRunOutcome::Terminal(self.into_terminal_result(guardian_status, report))
            }
            Err(error) => CoordinatorRunOutcome::Retained(Box::new(self.retain(error))),
        }
    }

    fn drive(&mut self) -> Result<(ExitStatus, CoordinatorTerminalReport), CoordinatorDriveError> {
        match self.bootstrap()? {
            BootstrapOutcome::Ready(readiness) => {
                self.transition_terminal(|owner| owner.mark_ready(readiness))?;
                self.drain_output(self.bounds.phase_deadline()?)?;
                self.transition_terminal(CoordinatorTerminalOwner::enter_initial_raw)?;
                match self.open_gate_with_output()? {
                    GateOutcome::Open(acknowledgement) => {
                        self.transition_terminal(|owner| owner.open_after_ack(acknowledgement))?;
                    }
                    GateOutcome::Failed => {
                        self.session_failed = true;
                        self.signals.freeze_for_shutdown();
                        self.await_quiescence()?;
                        return self.finish_shutdown();
                    }
                }
            }
            BootstrapOutcome::Failed => {
                self.session_failed = true;
                self.signals.freeze_for_shutdown();
                self.await_quiescence()?;
                return self.finish_shutdown();
            }
        }

        match self.run_active()? {
            ActiveOutcome::Quiesced => {}
            ActiveOutcome::Failed => {
                self.session_failed = true;
                self.signals.freeze_for_shutdown();
                self.await_quiescence()?;
            }
        }
        self.finish_shutdown()
    }

    fn bootstrap(&mut self) -> Result<BootstrapOutcome, CoordinatorDriveError> {
        let deadline = self.bounds.phase_deadline()?;
        if self.receive_with_output(deadline)? != GuardianEvent::LeaseCommitted {
            return Err(CoordinatorDriveError::Protocol);
        }
        self.lifecycle
            .command(CoordinatorCommand::Start, self.bounds.phase_deadline()?)?;
        let snapshot = self
            .terminal
            .as_ref()
            .ok_or(CoordinatorDriveError::Protocol)?
            .snapshot_fingerprint()?;

        loop {
            match self.receive_with_output(self.bounds.phase_deadline()?)? {
                GuardianEvent::TerminalArmed {
                    snapshot: guardian_snapshot,
                } if snapshot.matches(guardian_snapshot) => {
                    self.lifecycle.command(
                        CoordinatorCommand::TerminalArmAccepted,
                        self.bounds.phase_deadline()?,
                    )?;
                }
                GuardianEvent::TerminalArmed { .. } => {
                    return Err(CoordinatorDriveError::Snapshot);
                }
                // The receiver validates exact role order and positive
                // PID/PGID syntax. The numeric identity is used synchronously
                // for one read-only scan and is never retained as signal or
                // wait authority.
                GuardianEvent::ChildStarted { pgid, .. } => {
                    self.verify_reported_child_descriptor_isolation(
                        pgid,
                        self.bounds.phase_deadline()?,
                    )?;
                }
                GuardianEvent::Ready => {
                    return self
                        .lifecycle
                        .receiver
                        .take_verified_ready()
                        .map(BootstrapOutcome::Ready)
                        .map_err(classify_protocol_error);
                }
                GuardianEvent::Failed { .. } => return Ok(BootstrapOutcome::Failed),
                _ => return Err(CoordinatorDriveError::Protocol),
            }
        }
    }

    fn verify_reported_child_descriptor_isolation(
        &mut self,
        process_group: i32,
        deadline: Instant,
    ) -> Result<(), CoordinatorDriveError> {
        let poll_interval = self.bounds.poll_interval;
        let proof = retry_descriptor_isolation_observation(deadline, poll_interval, || {
            let observation =
                self.observe_reported_child_descriptor_isolation(process_group, deadline);
            let guardian_liveness = self.ensure_guardian_live();
            (observation, guardian_liveness)
        })?;
        let _ = proof;
        Ok(())
    }

    fn observe_reported_child_descriptor_isolation(
        &self,
        process_group: i32,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        DescriptorIsolationObservationFailure,
    > {
        let mut forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        self.authority
            .append_forbidden_descriptor(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)
            .map_err(|error| {
                DescriptorIsolationObservationFailure::source(
                    DescriptorIsolationObservationStage::CoordinatorAuthority,
                    error,
                )
            })?;
        self.lifecycle
            .append_forbidden_descriptor(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)
            .map_err(|error| {
                DescriptorIsolationObservationFailure::source(
                    DescriptorIsolationObservationStage::Lifecycle,
                    error,
                )
            })?;
        self.terminal
            .as_ref()
            .ok_or_else(|| {
                DescriptorIsolationObservationFailure::source(
                    DescriptorIsolationObservationStage::OuterTerminal,
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
                )
            })?
            .append_forbidden_descriptors(&mut forbidden)
            .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)
            .map_err(|error| {
                DescriptorIsolationObservationFailure::source(
                    DescriptorIsolationObservationStage::OuterTerminal,
                    error,
                )
            })?;
        calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
            process_group,
            &forbidden,
            deadline,
        )
        .map_err(DescriptorIsolationObservationFailure::target)
    }

    fn run_active(&mut self) -> Result<ActiveOutcome, CoordinatorDriveError> {
        loop {
            let turn_deadline = self.bounds.phase_deadline()?;
            self.pump_output(self.bounds.turn_deadline(turn_deadline)?)?;
            self.pump_input(self.bounds.turn_deadline(turn_deadline)?)?;

            if let Some(action) = self.signals.next_active() {
                match self.handle_control(action)? {
                    ControlOutcome::Continue => {}
                    ControlOutcome::Shutdown => {
                        self.signals.freeze_for_shutdown();
                        self.await_quiescence()?;
                        return Ok(ActiveOutcome::Quiesced);
                    }
                    ControlOutcome::Quiesced => return Ok(ActiveOutcome::Quiesced),
                    ControlOutcome::Failed => return Ok(ActiveOutcome::Failed),
                }
            }

            let poll_deadline = self.bounds.turn_deadline(turn_deadline)?;
            if !self.lifecycle_readable(poll_deadline)? {
                self.ensure_guardian_live()?;
                continue;
            }
            match self.lifecycle.receive(self.bounds.phase_deadline()?)? {
                GuardianEvent::TerminalQuiesced => return Ok(ActiveOutcome::Quiesced),
                GuardianEvent::Failed { .. } => return Ok(ActiveOutcome::Failed),
                _ => return Err(CoordinatorDriveError::Protocol),
            }
        }
    }

    fn handle_control(
        &mut self,
        action: CoordinatorSignalAction,
    ) -> Result<ControlOutcome, CoordinatorDriveError> {
        match action {
            CoordinatorSignalAction::Forward(signal) => self.forward_signal(signal),
            CoordinatorSignalAction::Resize => self.resize(),
            CoordinatorSignalAction::Suspend => self.suspend_and_resume(),
            CoordinatorSignalAction::Continue => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn forward_signal(
        &mut self,
        signal: UnixSignal,
    ) -> Result<ControlOutcome, CoordinatorDriveError> {
        self.lifecycle.command(
            CoordinatorCommand::Signal { signal },
            self.bounds.phase_deadline()?,
        )?;
        match self.receive_with_output(self.bounds.phase_deadline()?)? {
            GuardianEvent::SignalForwarded { signal: forwarded } if forwarded == signal => {
                if matches!(signal, UnixSignal::Hup | UnixSignal::Term) {
                    Ok(ControlOutcome::Shutdown)
                } else {
                    Ok(ControlOutcome::Continue)
                }
            }
            GuardianEvent::TerminalQuiesced
                if matches!(signal, UnixSignal::Int | UnixSignal::Quit) =>
            {
                Ok(ControlOutcome::Quiesced)
            }
            GuardianEvent::Failed { .. } => Ok(ControlOutcome::Failed),
            _ => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn resize(&mut self) -> Result<ControlOutcome, CoordinatorDriveError> {
        let size = self.current_terminal_size()?;
        let command = CoordinatorCommand::Resize {
            rows: size.rows(),
            cols: size.columns(),
        };
        self.lifecycle
            .command(command, self.bounds.phase_deadline()?)?;
        match self.receive_with_output(self.bounds.phase_deadline()?)? {
            GuardianEvent::ResizeApplied { rows, cols }
                if rows == size.rows() && cols == size.columns() =>
            {
                Ok(ControlOutcome::Continue)
            }
            GuardianEvent::TerminalQuiesced => Ok(ControlOutcome::Quiesced),
            GuardianEvent::Failed { .. } => Ok(ControlOutcome::Failed),
            _ => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn suspend_and_resume(&mut self) -> Result<ControlOutcome, CoordinatorDriveError> {
        // Input storage disappears before the guardian sees Suspend.
        self.transition_terminal(CoordinatorTerminalOwner::pause)?;
        self.lifecycle
            .command(CoordinatorCommand::Suspend, self.bounds.phase_deadline()?)?;
        match self.receive_with_output(self.bounds.phase_deadline()?)? {
            GuardianEvent::Suspended => {}
            GuardianEvent::Failed { .. } => return Ok(ControlOutcome::Failed),
            _ => return Err(CoordinatorDriveError::Protocol),
        }
        self.transition_terminal(CoordinatorTerminalOwner::restore_for_suspend)?;

        // The signal owner masks CONT, clears the stale latch, performs the
        // uncatchable stop, and restores the exact prior mask as one boundary.
        self.signals
            .stop_after_suspended_ack()
            .map_err(|_| CoordinatorDriveError::Signal)?;

        let deadline = self.bounds.phase_deadline()?;
        loop {
            if Instant::now() >= deadline {
                return Err(CoordinatorDriveError::Deadline);
            }
            if let Some(action) = self.signals.next_suspended() {
                match action {
                    CoordinatorSignalAction::Continue => return self.resume_after_continue(),
                    CoordinatorSignalAction::Forward(signal) => {
                        match self.forward_signal(signal)? {
                            ControlOutcome::Continue => {}
                            outcome => return Ok(outcome),
                        }
                    }
                    CoordinatorSignalAction::Resize | CoordinatorSignalAction::Suspend => {
                        return Err(CoordinatorDriveError::Protocol);
                    }
                }
            }
            self.pump_output(self.bounds.turn_deadline(deadline)?)?;
            if self.lifecycle_readable(self.bounds.turn_deadline(deadline)?)? {
                return match self.lifecycle.receive(deadline)? {
                    GuardianEvent::Failed { .. } => Ok(ControlOutcome::Failed),
                    _ => Err(CoordinatorDriveError::Protocol),
                };
            }
            self.ensure_guardian_live()?;
        }
    }

    fn resume_after_continue(&mut self) -> Result<ControlOutcome, CoordinatorDriveError> {
        self.transition_terminal(CoordinatorTerminalOwner::enter_resume_raw)?;
        self.signals.prepare_resume_size_snapshot();
        let size = self.current_terminal_size()?;
        self.lifecycle.command(
            CoordinatorCommand::Resume {
                rows: size.rows(),
                cols: size.columns(),
            },
            self.bounds.phase_deadline()?,
        )?;
        match self.receive_with_output(self.bounds.phase_deadline()?)? {
            GuardianEvent::Resumed { rows, cols }
                if rows == size.rows() && cols == size.columns() =>
            {
                let readiness = self
                    .lifecycle
                    .receiver
                    .take_verified_ready()
                    .map_err(classify_protocol_error)?;
                self.transition_terminal(|owner| owner.mark_resumed(readiness))?;
            }
            GuardianEvent::Failed { .. } => return Ok(ControlOutcome::Failed),
            _ => return Err(CoordinatorDriveError::Protocol),
        }
        match self.open_gate_with_output()? {
            GateOutcome::Open(acknowledgement) => {
                self.transition_terminal(|owner| owner.open_after_ack(acknowledgement))?;
                Ok(ControlOutcome::Continue)
            }
            GateOutcome::Failed => Ok(ControlOutcome::Failed),
        }
    }

    fn await_quiescence(&mut self) -> Result<(), CoordinatorDriveError> {
        let deadline = self.bounds.phase_deadline()?;
        loop {
            if Instant::now() >= deadline {
                return Err(CoordinatorDriveError::Deadline);
            }
            self.pump_output(self.bounds.turn_deadline(deadline)?)?;
            if !self.lifecycle_readable(self.bounds.turn_deadline(deadline)?)? {
                self.ensure_guardian_live()?;
                continue;
            }
            match self.lifecycle.receive(deadline)? {
                GuardianEvent::TerminalQuiesced => return Ok(()),
                GuardianEvent::Failed { .. } if !self.session_failed => {
                    self.session_failed = true;
                    self.signals.freeze_for_shutdown();
                }
                _ => return Err(CoordinatorDriveError::Protocol),
            }
        }
    }

    fn finish_shutdown(
        &mut self,
    ) -> Result<(ExitStatus, CoordinatorTerminalReport), CoordinatorDriveError> {
        self.signals.freeze_for_shutdown();
        let owner = self
            .terminal
            .take()
            .ok_or(CoordinatorDriveError::Protocol)?;
        self.terminal = Some(owner.quiesce());
        self.drain_output(self.bounds.phase_deadline()?)?;
        self.transition_terminal(CoordinatorTerminalOwner::restore)?;
        self.transition_terminal(CoordinatorTerminalOwner::finish)?;

        self.lifecycle.command(
            CoordinatorCommand::TerminalRestored,
            self.bounds.phase_deadline()?,
        )?;
        if self.receive_without_terminal_pump(self.bounds.phase_deadline()?)?
            != GuardianEvent::TerminalRecoveryDisarmed
        {
            return Err(CoordinatorDriveError::Protocol);
        }

        let (report, verified_exit) = loop {
            match self.receive_without_terminal_pump(self.bounds.phase_deadline()?)? {
                GuardianEvent::Failed {
                    phase: Phase::Worker,
                    code: FailureCode::Worker,
                } if !self.session_failed => {
                    self.session_failed = true;
                }
                GuardianEvent::ChildrenReaped {
                    app,
                    tui,
                    worker,
                    cleanup,
                    session,
                    guardian_exit,
                } => {
                    let verified_exit = self
                        .lifecycle
                        .receiver
                        .take_verified_exit_disposition()
                        .map_err(classify_protocol_error)?
                        .into_disposition();
                    break (
                        CoordinatorTerminalReport {
                            app,
                            tui,
                            worker,
                            cleanup,
                            session,
                            guardian_exit,
                        },
                        verified_exit,
                    );
                }
                _ => return Err(CoordinatorDriveError::Protocol),
            }
        };

        let guardian_status = self.wait_guardian(self.bounds.phase_deadline()?)?;
        self.lifecycle
            .verify_terminal_eof(self.bounds.phase_deadline()?)?;

        if !guardian_status_matches(guardian_status, verified_exit)
            || report.guardian_exit != verified_exit
        {
            return Err(CoordinatorDriveError::Protocol);
        }
        Ok((guardian_status, report))
    }

    fn receive_with_output(
        &mut self,
        deadline: Instant,
    ) -> Result<GuardianEvent, CoordinatorDriveError> {
        loop {
            if Instant::now() >= deadline {
                return Err(CoordinatorDriveError::Deadline);
            }
            self.pump_output(self.bounds.turn_deadline(deadline)?)?;
            if self.lifecycle_readable(self.bounds.turn_deadline(deadline)?)? {
                return self.lifecycle.receive(deadline);
            }
            self.ensure_guardian_live()?;
        }
    }

    fn open_gate_with_output(&mut self) -> Result<GateOutcome, CoordinatorDriveError> {
        self.lifecycle.command(
            CoordinatorCommand::OpenInputGate,
            self.bounds.phase_deadline()?,
        )?;
        match self.receive_with_output(self.bounds.phase_deadline()?)? {
            GuardianEvent::InputGateOpened => self
                .lifecycle
                .receiver
                .take_verified_open_gate_ack()
                .map(GateOutcome::Open)
                .map_err(classify_protocol_error),
            GuardianEvent::Failed { .. } => Ok(GateOutcome::Failed),
            _ => Err(CoordinatorDriveError::Protocol),
        }
    }

    fn receive_without_terminal_pump(
        &mut self,
        deadline: Instant,
    ) -> Result<GuardianEvent, CoordinatorDriveError> {
        if Instant::now() >= deadline {
            return Err(CoordinatorDriveError::Deadline);
        }
        self.lifecycle.receive(deadline)
    }

    fn lifecycle_readable(&self, deadline: Instant) -> Result<bool, CoordinatorDriveError> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let timeout =
                rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
                    .map_err(|_| CoordinatorDriveError::Deadline)?;
            let mut descriptors = [rustix::event::PollFd::new(
                &self.lifecycle,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    let events = descriptors[0].revents();
                    if events
                        .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
                    {
                        return Err(CoordinatorDriveError::Lifecycle);
                    }
                    return Ok(events
                        .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP));
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return Err(CoordinatorDriveError::Lifecycle),
            }
        }
    }

    fn pump_output(&mut self, deadline: Instant) -> Result<(), CoordinatorDriveError> {
        let owner = self
            .terminal
            .take()
            .ok_or(CoordinatorDriveError::Protocol)?;
        match owner.pump_output_once(deadline) {
            Ok((owner, _)) => {
                self.terminal = Some(owner);
                Ok(())
            }
            Err((owner, error)) => {
                self.terminal = Some(owner);
                Err(CoordinatorDriveError::Terminal(error))
            }
        }
    }

    fn pump_input(&mut self, deadline: Instant) -> Result<(), CoordinatorDriveError> {
        let owner = self
            .terminal
            .take()
            .ok_or(CoordinatorDriveError::Protocol)?;
        match owner.pump_input_once(deadline) {
            Ok((owner, _)) => {
                self.terminal = Some(owner);
                Ok(())
            }
            Err((owner, error)) => {
                self.terminal = Some(owner);
                Err(CoordinatorDriveError::Terminal(error))
            }
        }
    }

    fn drain_output(&mut self, deadline: Instant) -> Result<(), CoordinatorDriveError> {
        loop {
            if Instant::now() >= deadline {
                return Err(CoordinatorDriveError::Deadline);
            }
            let owner = self
                .terminal
                .take()
                .ok_or(CoordinatorDriveError::Protocol)?;
            match owner.pump_output_once(self.bounds.turn_deadline(deadline)?) {
                Ok((owner, progress)) => {
                    self.terminal = Some(owner);
                    if matches!(
                        progress,
                        CoordinatorPumpProgress::Idle | CoordinatorPumpProgress::OutputClosed
                    ) {
                        return Ok(());
                    }
                }
                Err((owner, error)) => {
                    self.terminal = Some(owner);
                    return Err(CoordinatorDriveError::Terminal(error));
                }
            }
        }
    }

    fn current_terminal_size(&self) -> Result<TerminalSize, CoordinatorDriveError> {
        self.terminal
            .as_ref()
            .ok_or(CoordinatorDriveError::Protocol)?
            .current_size()
    }

    fn transition_terminal(
        &mut self,
        transition: impl FnOnce(
            CoordinatorTerminalOwner,
        ) -> Result<
            CoordinatorTerminalOwner,
            (CoordinatorTerminalOwner, CoordinatorDriveError),
        >,
    ) -> Result<(), CoordinatorDriveError> {
        let owner = self
            .terminal
            .take()
            .ok_or(CoordinatorDriveError::Protocol)?;
        match transition(owner) {
            Ok(owner) => {
                self.terminal = Some(owner);
                Ok(())
            }
            Err((owner, error)) => {
                self.terminal = Some(owner);
                Err(error)
            }
        }
    }

    fn wait_guardian(&mut self, deadline: Instant) -> Result<ExitStatus, CoordinatorDriveError> {
        if let Some(status) = self.guardian_status {
            return Ok(status);
        }
        loop {
            match self.guardian.try_wait() {
                Ok(Some(status)) => {
                    self.guardian_status = Some(status);
                    return Ok(status);
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(
                        self.bounds
                            .poll_interval
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Ok(None) => return Err(CoordinatorDriveError::Deadline),
                Err(_) => return Err(CoordinatorDriveError::Guardian),
            }
        }
    }

    fn ensure_guardian_live(&mut self) -> Result<(), CoordinatorDriveError> {
        if self.guardian_status.is_some() {
            return Err(CoordinatorDriveError::Guardian);
        }
        match self.guardian.try_wait() {
            Ok(Some(status)) => {
                self.guardian_status = Some(status);
                Err(CoordinatorDriveError::Guardian)
            }
            Ok(None) => Ok(()),
            Err(_) => Err(CoordinatorDriveError::Guardian),
        }
    }

    fn into_terminal_result(
        self,
        guardian_status: ExitStatus,
        report: CoordinatorTerminalReport,
    ) -> CoordinatorTerminalResult {
        let Self {
            authority,
            guardian,
            guardian_status: _,
            lifecycle,
            terminal,
            signals,
            bounds: _,
            session_failed: _,
        } = self;
        let restoration = match terminal {
            Some(CoordinatorTerminalOwner::Finished(restoration)) => restoration,
            _ => std::process::abort(),
        };
        drop((guardian, lifecycle, restoration, signals));
        CoordinatorTerminalResult {
            authority,
            guardian_status,
            report,
        }
    }

    fn retain(mut self, error: CoordinatorDriveError) -> RetainedCoordinatorGeneration {
        self.signals.freeze_for_shutdown();
        let Some(terminal) = self.terminal.take() else {
            // Every consuming transition reinserts its exact owner on error.
            // Reaching recovery without one is an impossible authority loss.
            std::process::abort();
        };
        let terminal = terminal.quiesce();
        // Input is physically absent before lifecycle loss can activate the
        // guardian's fallback restoration path.
        let lifecycle_shutdown = self.lifecycle.wire().shutdown();
        let mut reason = error.retention_reason();
        if lifecycle_shutdown.is_err() {
            reason = RetentionReason::InvariantUnconfirmed;
        }
        let terminal = match terminal.restore() {
            Ok(terminal) => terminal,
            Err((terminal, _)) => {
                reason = RetentionReason::InvariantUnconfirmed;
                terminal
            }
        };
        let terminal = match terminal.finish() {
            Ok(terminal) => terminal,
            Err((terminal, _)) => {
                reason = RetentionReason::InvariantUnconfirmed;
                terminal
            }
        };

        if self.guardian_status.is_none() {
            let deadline = self
                .bounds
                .phase_deadline()
                .unwrap_or_else(|_| Instant::now());
            while Instant::now() < deadline {
                match self.guardian.try_wait() {
                    Ok(Some(status)) => {
                        self.guardian_status = Some(status);
                        break;
                    }
                    Ok(None) => thread::sleep(
                        self.bounds
                            .poll_interval
                            .min(deadline.saturating_duration_since(Instant::now())),
                    ),
                    Err(_) => break,
                }
            }
        }

        RetainedCoordinatorGeneration {
            owners: RetainedLinearOwners::new(
                self.authority,
                self.guardian,
                self.lifecycle,
                terminal,
                self.signals,
            ),
            guardian_status: self.guardian_status,
            guardian_poll_interval: self.bounds.poll_interval,
            reason,
            failure: error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{ChildStdin, Command, Stdio};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver};

    use uuid::Uuid;

    use crate::profiles::Registry;

    use super::super::channel::LifecyclePair;
    use super::super::protocol::{
        ChildRole, GuardianCommandReceiver, SessionTerminationCause, StopAction,
        project_terminal_semantics, send_guardian_event,
    };
    use super::super::terminal::{
        PtyMaster, PtyOwner, TerminalBuffer, TerminalChannelPair, TerminalEndpoint, TerminalRead,
        TerminalShutdown, TerminalWrite, claim_controlling_terminal_from_stdin,
        termios_semantically_equal,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);
    const PRODUCTION_MATRIX_HELPER_ENV: &str = "CALCIFER_COORDINATOR_MATRIX_HELPER";
    const PRODUCTION_MATRIX_OUTPUT: &[u8] = b"calcifer-production-coordinator-output";

    #[test]
    fn packaged_retention_diagnostics_are_closed_fixed_and_payload_free() {
        assert_eq!(
            [
                CoordinatorDriveError::Deadline,
                CoordinatorDriveError::Lifecycle,
                CoordinatorDriveError::Protocol,
                CoordinatorDriveError::Snapshot,
                CoordinatorDriveError::Terminal(CoordinatorTerminalError::Restore),
                CoordinatorDriveError::Signal,
                CoordinatorDriveError::Guardian,
                CoordinatorDriveError::DescriptorIsolation(
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor,
                ),
            ]
            .map(packaged_coordinator_failure_marker),
            [
                "coordinator-retained.error.deadline",
                "coordinator-retained.error.lifecycle",
                "coordinator-retained.error.protocol",
                "coordinator-retained.error.snapshot",
                "coordinator-retained.error.terminal.restore",
                "coordinator-retained.error.signal",
                "coordinator-retained.error.guardian",
                "coordinator-retained.error.descriptor-isolation",
            ]
        );
        assert_eq!(
            [
                CoordinatorTerminalError::Setup,
                CoordinatorTerminalError::Deadline,
                CoordinatorTerminalError::OuterTerminalEof,
                CoordinatorTerminalError::TerminalChannelRead,
                CoordinatorTerminalError::TerminalChannelWrite,
                CoordinatorTerminalError::OuterTerminalRead,
                CoordinatorTerminalError::OuterTerminalWrite,
                CoordinatorTerminalError::RawTransition,
                CoordinatorTerminalError::Foreground,
                CoordinatorTerminalError::WindowSize,
                CoordinatorTerminalError::Restore,
                CoordinatorTerminalError::Shutdown,
            ]
            .map(|error| packaged_coordinator_failure_marker(
                CoordinatorDriveError::Terminal(error)
            )),
            [
                "coordinator-retained.error.terminal.setup",
                "coordinator-retained.error.terminal.deadline",
                "coordinator-retained.error.terminal.outer-eof",
                "coordinator-retained.error.terminal.channel-read",
                "coordinator-retained.error.terminal.channel-write",
                "coordinator-retained.error.terminal.outer-read",
                "coordinator-retained.error.terminal.outer-write",
                "coordinator-retained.error.terminal.raw-transition",
                "coordinator-retained.error.terminal.foreground",
                "coordinator-retained.error.terminal.window-size",
                "coordinator-retained.error.terminal.restore",
                "coordinator-retained.error.terminal.shutdown",
            ]
        );
        assert_eq!(
            [
                RetentionReason::LifecycleLost,
                RetentionReason::ProtocolInvalid,
                RetentionReason::GuardianExited,
                RetentionReason::ShutdownDeadline,
                RetentionReason::ChildrenNotReaped,
                RetentionReason::WorkerNotJoined,
                RetentionReason::CleanupUnconfirmed,
                RetentionReason::InvariantUnconfirmed,
            ]
            .map(packaged_coordinator_retention_reason_marker),
            [
                "coordinator-retained.reason.lifecycle-lost",
                "coordinator-retained.reason.protocol-invalid",
                "coordinator-retained.reason.guardian-exited",
                "coordinator-retained.reason.shutdown-deadline",
                "coordinator-retained.reason.children-not-reaped",
                "coordinator-retained.reason.worker-not-joined",
                "coordinator-retained.reason.cleanup-unconfirmed",
                "coordinator-retained.reason.invariant-unconfirmed",
            ]
        );

        let synthetic_secret = "synthetic-private-profile@example.invalid";
        for marker in [
            packaged_coordinator_failure_marker(CoordinatorDriveError::Protocol),
            packaged_coordinator_retention_reason_marker(RetentionReason::ProtocolInvalid),
        ] {
            assert!(!marker.contains(synthetic_secret));
            assert!(
                marker
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b'.')
            );
        }
    }

    #[test]
    fn descriptor_isolation_retries_transient_target_changes_with_exact_liveness_checks()
    -> Result<(), Box<dyn std::error::Error>> {
        for transient in [
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged,
        ] {
            let mut attempts = 0_usize;
            let mut liveness_checks = 0_usize;
            let proof = retry_descriptor_isolation_observation(
                Instant::now() + TEST_TIMEOUT,
                Duration::from_millis(1),
                || {
                    attempts += 1;
                    liveness_checks += 1;
                    let observation = if attempts == 1 {
                        Err(DescriptorIsolationObservationFailure::target(transient))
                    } else {
                        Ok(0x42_u8)
                    };
                    (observation, Ok(()))
                },
            )?;
            assert_eq!(proof, 0x42);
            assert_eq!(attempts, 2);
            assert_eq!(liveness_checks, attempts);
        }
        Ok(())
    }

    #[test]
    fn permanent_target_changes_exhaust_one_deadline_and_require_retention() {
        for transient in [
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged,
        ] {
            let mut attempts = 0_usize;
            let mut liveness_checks = 0_usize;
            let result = retry_descriptor_isolation_observation::<u8>(
                Instant::now() + Duration::from_millis(20),
                Duration::from_millis(1),
                || {
                    attempts += 1;
                    liveness_checks += 1;
                    (
                        Err(DescriptorIsolationObservationFailure::target(transient)),
                        Ok(()),
                    )
                },
            );
            let error = match result {
                Ok(_) => panic!("permanent descriptor churn minted a stable proof"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                CoordinatorDriveError::DescriptorIsolation(
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline
                )
            );
            assert_eq!(
                error.retention_reason(),
                RetentionReason::InvariantUnconfirmed
            );
            assert!(attempts > 1);
            assert_eq!(liveness_checks, attempts);
        }
    }

    #[test]
    fn descriptor_isolation_never_retries_source_changes_or_fatal_target_failures() {
        let source_change = DescriptorIsolationObservationFailure::source(
            DescriptorIsolationObservationStage::CoordinatorAuthority,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged,
        );
        let fatal_target_errors = [
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::InvalidArgument,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessLimit,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::MemberLimit,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorLimit,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenIdentityLimit,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::PermissionDenied,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessUserMismatch,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::UnsupportedDescriptor,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ObservationFailed,
        ];
        let failures = std::iter::once(source_change).chain(
            fatal_target_errors
                .into_iter()
                .map(DescriptorIsolationObservationFailure::target),
        );

        for failure in failures {
            let mut attempts = 0_usize;
            let result = retry_descriptor_isolation_observation::<u8>(
                Instant::now() + TEST_TIMEOUT,
                Duration::from_millis(1),
                || {
                    attempts += 1;
                    (Err(failure), Ok(()))
                },
            );
            let error = match result {
                Ok(_) => panic!("fatal descriptor observation minted a stable proof"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                CoordinatorDriveError::DescriptorIsolation(failure.error)
            );
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn descriptor_isolation_requires_exact_guardian_liveness_after_every_attempt() {
        let mut attempts = 0_usize;
        let result = retry_descriptor_isolation_observation::<u8>(
            Instant::now() + TEST_TIMEOUT,
            Duration::from_millis(1),
            || {
                attempts += 1;
                (
                    Err(DescriptorIsolationObservationFailure::target(
                        calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged,
                    )),
                    Err(CoordinatorDriveError::Guardian),
                )
            },
        );
        assert_eq!(result, Err(CoordinatorDriveError::Guardian));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn verified_guardian_exit_requires_exact_unix_disposition() {
        let exit_zero = ExitStatus::from_raw(0);
        let exit_twenty_three = ExitStatus::from_raw(23 << 8);
        let signal_hup = ExitStatus::from_raw(1);
        let signal_term = ExitStatus::from_raw(15);

        assert!(guardian_status_matches(
            exit_zero,
            GuardianExitDisposition::Code(0)
        ));
        assert!(guardian_status_matches(
            exit_twenty_three,
            GuardianExitDisposition::Code(23)
        ));
        assert!(guardian_status_matches(
            signal_hup,
            GuardianExitDisposition::Signal(1)
        ));
        assert!(guardian_status_matches(
            signal_term,
            GuardianExitDisposition::Signal(15)
        ));
        assert!(guardian_status_matches(
            ExitStatus::from_raw(1 << 8),
            GuardianExitDisposition::InternalFailure
        ));

        assert!(!guardian_status_matches(
            exit_zero,
            GuardianExitDisposition::Signal(1)
        ));
        assert!(!guardian_status_matches(
            signal_term,
            GuardianExitDisposition::Code(15)
        ));
        assert!(!guardian_status_matches(
            exit_twenty_three,
            GuardianExitDisposition::InternalFailure
        ));
    }

    #[test]
    fn production_entry_and_retention_are_coordinator_lease_only() {
        type Assemble = fn(
            CoordinatorProfileLease,
            Child,
            LifecycleEndpoint,
            CoordinatorTerminal<OutputOnly>,
            CoordinatorBounds,
        ) -> Result<ProductionCoordinator, Box<CoordinatorSetupFailure>>;
        let _assemble: Assemble = ProductionCoordinator::assemble;
        let _retain: fn(RetainedCoordinatorGeneration) -> RetainedCoordinatorLease =
            RetainedCoordinatorGeneration::into_retained_lease;
        let _terminal_authority: fn(CoordinatorTerminalResult) -> CoordinatorProfileLease =
            CoordinatorTerminalResult::into_authority;
    }

    struct ScriptedWire {
        read: Cursor<Vec<u8>>,
        writes: Rc<RefCell<Vec<u8>>>,
    }

    impl Read for ScriptedWire {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(bytes)
        }
    }

    impl Write for ScriptedWire {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bootstrap_enforces_arm_and_distinct_child_order_without_exporting_pid_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = TerminalSnapshotFingerprint::from_digest([0x42; 32]);
        let app = GuardianEvent::ChildStarted {
            role: ChildRole::AppServer,
            pid: 101,
            pgid: 101,
        };
        let tui = GuardianEvent::ChildStarted {
            role: ChildRole::Tui,
            pid: 202,
            pgid: 202,
        };
        let mut events = Vec::new();
        for event in [
            GuardianEvent::LeaseCommitted,
            GuardianEvent::TerminalArmed { snapshot },
            app,
            tui,
            GuardianEvent::Ready,
            GuardianEvent::InputGateOpened,
        ] {
            send_guardian_event(&mut events, event, Instant::now() + TEST_TIMEOUT)?;
        }
        let writes = Rc::new(RefCell::new(Vec::new()));
        let wire = ScriptedWire {
            read: Cursor::new(events),
            writes: Rc::clone(&writes),
        };
        let mut lifecycle = CoordinatorLifecycle::new(wire);
        let readiness = match lifecycle.bootstrap(snapshot, Instant::now() + TEST_TIMEOUT)? {
            BootstrapOutcome::Ready(readiness) => readiness,
            BootstrapOutcome::Failed => return Err("bootstrap unexpectedly failed".into()),
        };
        assert_eq!(format!("{readiness:?}"), "VerifiedReady(<redacted>)");
        let acknowledgement = match lifecycle.open_gate(Instant::now() + TEST_TIMEOUT)? {
            GateOutcome::Open(acknowledgement) => acknowledgement,
            GateOutcome::Failed => return Err("gate unexpectedly failed".into()),
        };
        assert_eq!(
            format!("{acknowledgement:?}"),
            "VerifiedOpenGateAck(<redacted>)"
        );

        let encoded = writes.borrow().clone();
        let mut guardian = GuardianCommandReceiver::new_terminal(Cursor::new(encoded));
        guardian.record_event(GuardianEvent::LeaseCommitted)?;
        assert_eq!(
            guardian.receive(Instant::now() + TEST_TIMEOUT)?,
            CoordinatorCommand::Start
        );
        guardian.record_event(GuardianEvent::TerminalArmed { snapshot })?;
        assert_eq!(
            guardian.receive(Instant::now() + TEST_TIMEOUT)?,
            CoordinatorCommand::TerminalArmAccepted
        );
        for event in [app, tui, GuardianEvent::Ready] {
            guardian.record_event(event)?;
        }
        assert_eq!(
            guardian.receive(Instant::now() + TEST_TIMEOUT)?,
            CoordinatorCommand::OpenInputGate
        );
        Ok(())
    }

    struct DropProbe(Arc<AtomicUsize>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn accidental_retained_generation_drop_leaks_every_linear_owner() {
        let drops = std::array::from_fn::<_, 5, _>(|_| Arc::new(AtomicUsize::new(0)));
        let owners = RetainedLinearOwners::new(
            DropProbe(Arc::clone(&drops[0])),
            DropProbe(Arc::clone(&drops[1])),
            DropProbe(Arc::clone(&drops[2])),
            DropProbe(Arc::clone(&drops[3])),
            DropProbe(Arc::clone(&drops[4])),
        );
        drop(owners);
        for observed in drops {
            assert_eq!(observed.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn test_only_retained_extractor_consumes_all_five_owners() {
        let drops = std::array::from_fn::<_, 5, _>(|_| Arc::new(AtomicUsize::new(0)));
        let owners = RetainedLinearOwners::new(
            DropProbe(Arc::clone(&drops[0])),
            DropProbe(Arc::clone(&drops[1])),
            DropProbe(Arc::clone(&drops[2])),
            DropProbe(Arc::clone(&drops[3])),
            DropProbe(Arc::clone(&drops[4])),
        );
        let extracted = owners.take_for_test();
        drop(extracted);
        for observed in drops {
            assert_eq!(observed.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn retained_guardian_poll_is_idempotent_after_exact_reap() {
        let expected = ExitStatus::from_raw(23 << 8);
        let mut status = Some(expected);
        let mut observations = 0_usize;

        let poll = poll_retained_guardian(&mut status, || {
            observations = observations.saturating_add(1);
            Err(std::io::Error::other(
                "an already-reaped exact child must not be observed again",
            ))
        });

        assert_eq!(poll, RetainedGuardianPoll::Reaped(expected));
        assert_eq!(status, Some(expected));
        assert_eq!(observations, 0);
    }

    #[test]
    fn retained_guardian_poll_reaps_only_the_exact_delayed_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut exact_child = Command::new("/bin/sh")
            .args(["-c", "if IFS= read -r _; then exit 23; else exit 99; fi"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut exact_trigger = exact_child
            .stdin
            .take()
            .ok_or("missing exact child trigger")?;
        let mut exact = MatrixTestChild::new(exact_child);
        let mut sibling_child = Command::new("/bin/sh")
            .args(["-c", "if IFS= read -r _; then exit 29; else exit 98; fi"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut sibling_trigger = sibling_child
            .stdin
            .take()
            .ok_or("missing sibling trigger")?;
        let mut sibling = MatrixTestChild::new(sibling_child);
        let mut status = None;

        let exact_child = exact.child.as_mut().ok_or("exact child was missing")?;
        assert_eq!(
            poll_retained_guardian(&mut status, || exact_child.try_wait()),
            RetainedGuardianPoll::Pending
        );
        exact_trigger.write_all(b"release\n")?;
        drop(exact_trigger);

        let deadline = Instant::now() + TEST_TIMEOUT;
        let exact_status = loop {
            let exact_child = exact.child.as_mut().ok_or("exact child was missing")?;
            match poll_retained_guardian(&mut status, || exact_child.try_wait()) {
                RetainedGuardianPoll::Reaped(status) => break status,
                RetainedGuardianPoll::Pending if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                RetainedGuardianPoll::Pending => {
                    return Err("exact retained guardian was not reaped".into());
                }
                RetainedGuardianPoll::Uncertain => {
                    return Err("exact retained guardian wait became uncertain".into());
                }
            }
        };
        assert_eq!(exact_status.code(), Some(23));
        assert_eq!(status, Some(exact_status));
        assert!(
            sibling
                .child
                .as_mut()
                .ok_or("sibling child was missing")?
                .try_wait()?
                .is_none()
        );

        sibling_trigger.write_all(b"release\n")?;
        drop(sibling_trigger);
        let sibling_status = sibling.wait_before(Instant::now() + TEST_TIMEOUT)?;
        assert_eq!(sibling_status.code(), Some(29));
        Ok(())
    }

    #[test]
    fn retained_guardian_wait_error_selects_an_all_owner_pin() {
        let mut status = None;
        let poll = poll_retained_guardian(&mut status, || {
            Err(std::io::Error::other("synthetic exact wait failure"))
        });
        assert_eq!(poll, RetainedGuardianPoll::Uncertain);
        assert_eq!(status, None);

        let drops = std::array::from_fn::<_, 5, _>(|_| Arc::new(AtomicUsize::new(0)));
        let owners = RetainedLinearOwners::new(
            DropProbe(Arc::clone(&drops[0])),
            DropProbe(Arc::clone(&drops[1])),
            DropProbe(Arc::clone(&drops[2])),
            DropProbe(Arc::clone(&drops[3])),
            DropProbe(Arc::clone(&drops[4])),
        );
        pin_retained_value(owners);
        for observed in drops {
            assert_eq!(observed.load(Ordering::SeqCst), 0);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProductionMatrixCase {
        Eof,
        DataThenEof,
        ExitTwentyThree,
        ForwardedHup,
        ForwardedTerm,
        SuspendResume,
        LifecycleLost,
        CoordinatorAuthorityLeak,
    }

    impl ProductionMatrixCase {
        const ALL: [Self; 7] = [
            Self::Eof,
            Self::DataThenEof,
            Self::ExitTwentyThree,
            Self::ForwardedHup,
            Self::ForwardedTerm,
            Self::SuspendResume,
            Self::LifecycleLost,
        ];

        const fn as_str(self) -> &'static str {
            match self {
                Self::Eof => "eof",
                Self::DataThenEof => "data-eof",
                Self::ExitTwentyThree => "exit-23",
                Self::ForwardedHup => "forward-hup",
                Self::ForwardedTerm => "forward-term",
                Self::SuspendResume => "suspend-resume",
                Self::LifecycleLost => "lifecycle-lost",
                Self::CoordinatorAuthorityLeak => "coordinator-authority-leak",
            }
        }

        fn from_str(value: &str) -> Option<Self> {
            Self::ALL
                .into_iter()
                .chain(std::iter::once(Self::CoordinatorAuthorityLeak))
                .find(|case| case.as_str() == value)
        }

        const fn termination_cause(self) -> SessionTerminationCause {
            match self {
                Self::ForwardedHup => SessionTerminationCause::ForwardedHup,
                Self::ForwardedTerm => SessionTerminationCause::ForwardedTerm,
                Self::Eof
                | Self::DataThenEof
                | Self::ExitTwentyThree
                | Self::SuspendResume
                | Self::LifecycleLost
                | Self::CoordinatorAuthorityLeak => SessionTerminationCause::NaturalTuiEof,
            }
        }

        const fn tui_disposition(self) -> ChildDisposition {
            match self {
                Self::ExitTwentyThree => ChildDisposition::Exited {
                    code: 23,
                    stop_action: StopAction::None,
                },
                Self::ForwardedHup => ChildDisposition::Signaled {
                    signal: 1,
                    core_dumped: false,
                    stop_action: StopAction::None,
                },
                Self::ForwardedTerm => ChildDisposition::Signaled {
                    signal: 15,
                    core_dumped: false,
                    stop_action: StopAction::None,
                },
                Self::Eof
                | Self::DataThenEof
                | Self::SuspendResume
                | Self::LifecycleLost
                | Self::CoordinatorAuthorityLeak => ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::None,
                },
            }
        }

        const fn child_script(self) -> &'static str {
            match self {
                Self::ExitTwentyThree => "if IFS= read -r _; then exit 23; else exit 99; fi",
                Self::ForwardedHup => "if IFS= read -r _; then kill -HUP \"$$\"; else exit 99; fi",
                Self::ForwardedTerm => {
                    "if IFS= read -r _; then kill -TERM \"$$\"; else exit 99; fi"
                }
                Self::Eof
                | Self::DataThenEof
                | Self::SuspendResume
                | Self::CoordinatorAuthorityLeak => {
                    "if IFS= read -r _; then exit 0; else exit 99; fi"
                }
                Self::LifecycleLost => "IFS= read -r _; exit 99",
            }
        }

        fn expected_guardian_exit(self) -> GuardianExitDisposition {
            project_terminal_semantics(
                ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::None,
                },
                self.tui_disposition(),
                WorkerJoinStatus::JoinedClean,
                self.termination_cause(),
            )
            .1
        }

        fn expected_session_status(self) -> SessionStatus {
            project_terminal_semantics(
                ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::None,
                },
                self.tui_disposition(),
                WorkerJoinStatus::JoinedClean,
                self.termination_cause(),
            )
            .0
        }
    }

    #[test]
    fn production_coordinator_real_outer_pty_matrix() -> Result<(), Box<dyn std::error::Error>> {
        for case in ProductionMatrixCase::ALL {
            if let Err(error) = run_matrix_parent(case) {
                return Err(format!("production matrix {case:?} failed: {error}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn production_coordinator_rejects_inherited_a_before_opening_input()
    -> Result<(), Box<dyn std::error::Error>> {
        run_matrix_parent(ProductionMatrixCase::CoordinatorAuthorityLeak)
    }

    #[test]
    fn production_coordinator_matrix_child_helper() {
        let Some(value) = std::env::var_os(PRODUCTION_MATRIX_HELPER_ENV) else {
            return;
        };
        let Some(case) = value.to_str().and_then(ProductionMatrixCase::from_str) else {
            eprintln!("matrix-helper-error:invalid-case");
            std::process::exit(91);
        };
        if let Err(error) = run_matrix_child(case) {
            eprintln!("matrix-helper-error:{error}");
            std::process::exit(91);
        }
    }

    fn run_matrix_parent(case: ProductionMatrixCase) -> Result<(), Box<dyn std::error::Error>> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "providers::codex::supervisor::coordinator::tests::production_coordinator_matrix_child_helper",
                "--nocapture",
            ])
            .env(PRODUCTION_MATRIX_HELPER_ENV, case.as_str());
        let owner = PtyOwner::open(TerminalSize::new(33, 107))?;
        let master = owner.configure_child(&mut command)?;
        let initial_termios = rustix::termios::tcgetattr(&master)?;
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let raw_pid = i32::try_from(child.id())?;
        let pid = rustix::process::Pid::from_raw(raw_pid).ok_or("invalid helper PID")?;
        let stderr = child.stderr.take().ok_or("missing matrix helper stderr")?;
        let mut child = MatrixTestChild::new(child);
        let (line_sender, line_receiver) = mpsc::channel();
        let (reader_done_sender, reader_done_receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if line_sender.send(line).is_err() {
                    break;
                }
            }
            let _ = reader_done_sender.send(());
        });
        master.enable_nonblocking()?;

        if case == ProductionMatrixCase::CoordinatorAuthorityLeak {
            expect_matrix_line(
                &line_receiver,
                "descriptor-isolation-observation-failure:stage=TargetProcessGroup, error=ForbiddenDescriptor",
            )?;
            expect_matrix_line(&line_receiver, "coordinator-a-leak-rejected")?;
            let (drain_sender, drain_receiver) = mpsc::channel();
            let drainer = std::thread::spawn(move || {
                let result = drain_matrix_master(master, Instant::now() + TEST_TIMEOUT);
                let _ = drain_sender.send(result);
            });
            let status = child.wait_before(Instant::now() + TEST_TIMEOUT)?;
            if !status.success() {
                return Err(format!("A-leak helper exited as {status}").into());
            }
            drain_receiver
                .recv_timeout(TEST_TIMEOUT)
                .map_err(|_| "A-leak PTY drainer timed out")??;
            drainer.join().map_err(|_| "A-leak PTY drainer panicked")?;
            reader_done_receiver
                .recv_timeout(TEST_TIMEOUT)
                .map_err(|_| "A-leak stderr reader did not observe EOF")?;
            reader.join().map_err(|_| "A-leak stderr reader panicked")?;
            return Ok(());
        }

        expect_matrix_line(&line_receiver, "coordinator-active")?;
        match case {
            ProductionMatrixCase::ForwardedHup => {
                rustix::process::kill_process(pid, rustix::process::Signal::HUP)?;
            }
            ProductionMatrixCase::ForwardedTerm => {
                rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
            }
            ProductionMatrixCase::SuspendResume => {
                rustix::process::kill_process(pid, rustix::process::Signal::TSTP)?;
                wait_for_matrix_stop(pid, Instant::now() + TEST_TIMEOUT)?;
                let stopped_termios = rustix::termios::tcgetattr(&master)?;
                if !termios_semantically_equal(&initial_termios, &stopped_termios) {
                    return Err("suspend did not restore the exact outer terminal".into());
                }
                let mut mutated = stopped_termios;
                if mutated
                    .local_modes
                    .contains(rustix::termios::LocalModes::ECHO)
                {
                    mutated
                        .local_modes
                        .remove(rustix::termios::LocalModes::ECHO);
                } else {
                    mutated
                        .local_modes
                        .insert(rustix::termios::LocalModes::ECHO);
                }
                rustix::termios::tcsetattr(
                    &master,
                    rustix::termios::OptionalActions::Now,
                    &mutated,
                )?;
                rustix::process::kill_process(pid, rustix::process::Signal::CONT)?;
            }
            ProductionMatrixCase::Eof
            | ProductionMatrixCase::DataThenEof
            | ProductionMatrixCase::ExitTwentyThree
            | ProductionMatrixCase::LifecycleLost
            | ProductionMatrixCase::CoordinatorAuthorityLeak => {}
        }

        if case == ProductionMatrixCase::DataThenEof {
            wait_for_matrix_output(
                &master,
                PRODUCTION_MATRIX_OUTPUT,
                Instant::now() + TEST_TIMEOUT,
            )?;
        }
        expect_matrix_line(&line_receiver, "coordinator-finished")?;
        if case == ProductionMatrixCase::SuspendResume {
            let final_termios = rustix::termios::tcgetattr(&master)?;
            if !termios_semantically_equal(&initial_termios, &final_termios) {
                return Err("post-resume shutdown did not restore the original termios".into());
            }
        }

        let (drain_sender, drain_receiver) = mpsc::channel();
        let drainer = std::thread::spawn(move || {
            let result = drain_matrix_master(master, Instant::now() + TEST_TIMEOUT);
            let _ = drain_sender.send(result);
        });
        let status = child.wait_before(Instant::now() + TEST_TIMEOUT)?;
        if !status.success() {
            return Err(format!("matrix helper {case:?} exited as {status}").into());
        }
        drain_receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "matrix PTY drainer timed out")??;
        drainer.join().map_err(|_| "matrix PTY drainer panicked")?;
        reader_done_receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "matrix stderr reader did not observe EOF")?;
        reader.join().map_err(|_| "matrix stderr reader panicked")?;
        Ok(())
    }

    fn run_matrix_child(case: ProductionMatrixCase) -> Result<(), Box<dyn std::error::Error>> {
        claim_controlling_terminal_from_stdin()?;
        let root = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-coordinator-matrix-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("matrix")?;
        let mut auth = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.home().join("auth.json"))?;
        auth.write_all(
            serde_json::to_string(&serde_json::json!({
                "auth_mode": "chatgpt",
                "tokens": { "account_id": Uuid::new_v4().to_string() }
            }))?
            .as_bytes(),
        )?;
        auth.sync_all()?;
        let profile = pending.commit(crate::providers::codex::CodexIdentityAdapter::for_test())?;
        let authority = registry.lock_profile_coordinator(&profile)?;

        let (coordinator_terminal, guardian_terminal) = TerminalChannelPair::new()?.split();
        let terminal = CoordinatorTerminal::capture(std::io::stdin(), coordinator_terminal)?;
        let snapshot = terminal.snapshot_fingerprint();
        let (coordinator_lifecycle, guardian_lifecycle) = LifecyclePair::new()?.split_for_test();
        let inherited_a = if case == ProductionMatrixCase::CoordinatorAuthorityLeak {
            let descriptor = rustix::io::fcntl_dupfd_cloexec(authority.lock_file()?, 3)?;
            let flags = rustix::io::fcntl_getfd(&descriptor)?;
            rustix::io::fcntl_setfd(&descriptor, flags & !rustix::io::FdFlags::CLOEXEC)?;
            Some(descriptor)
        } else {
            None
        };
        let app_group = spawn_matrix_scan_group(&root, "app")?;
        let app_group_pid = app_group.raw_pid;
        drop(inherited_a);
        let tui_group = spawn_matrix_scan_group(&root, "tui")?;
        let tui_group_pid = tui_group.raw_pid;
        let mut child = Command::new("/bin/sh")
            .args(["-c", case.child_script()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let trigger = child.stdin.take().ok_or("missing guardian child trigger")?;
        let peer = std::thread::spawn(move || {
            run_matrix_guardian_peer(
                case,
                snapshot,
                guardian_lifecycle,
                guardian_terminal,
                trigger,
                app_group,
                tui_group,
            )
        });
        let bounds = CoordinatorBounds::new(Duration::from_secs(2), Duration::from_millis(5))?;
        let coordinator = ProductionCoordinator::assemble(
            authority,
            child,
            coordinator_lifecycle,
            terminal,
            bounds,
        )
        .map_err(|_| "production coordinator assembly failed")?;
        let outcome = coordinator.run();
        let peer_result = peer.join().map_err(|_| "matrix guardian peer panicked")?;

        match (case, outcome) {
            (
                ProductionMatrixCase::CoordinatorAuthorityLeak,
                CoordinatorRunOutcome::Retained(retained),
            ) => {
                if retained.reason() != RetentionReason::InvariantUnconfirmed
                    || retained.failure_for_test()
                        != CoordinatorDriveError::DescriptorIsolation(
                            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor,
                        )
                {
                    let reason = retained.reason();
                    let failure = retained.failure_for_test();
                    drop(retained.release_for_test());
                    return Err(format!(
                        "A leak retained the wrong state: {reason:?}, failure={failure:?}"
                    )
                    .into());
                }
                let retained_a = retained.release_for_test();
                retained_a.lock_file()?;
                drop(retained_a);
                peer_result.map_err(|error| format!("A-leak guardian peer failed: {error}"))?;
                wait_for_matrix_group_gone(app_group_pid, Instant::now() + TEST_TIMEOUT)?;
                wait_for_matrix_group_gone(tui_group_pid, Instant::now() + TEST_TIMEOUT)?;
                std::fs::remove_dir_all(root)?;
                eprintln!("coordinator-a-leak-rejected");
                return Ok(());
            }
            (
                ProductionMatrixCase::CoordinatorAuthorityLeak,
                CoordinatorRunOutcome::Terminal(_),
            ) => {
                return Err("an inherited A descriptor opened terminal input authority".into());
            }
            (ProductionMatrixCase::LifecycleLost, CoordinatorRunOutcome::Retained(retained)) => {
                if !matches!(
                    retained.reason(),
                    RetentionReason::LifecycleLost | RetentionReason::InvariantUnconfirmed
                ) {
                    let reason = retained.reason();
                    drop(retained.release_for_test());
                    return Err(format!(
                        "lifecycle loss retained the wrong failure reason: {reason:?}"
                    )
                    .into());
                }
                drop(retained.release_for_test());
            }
            (ProductionMatrixCase::LifecycleLost, CoordinatorRunOutcome::Terminal(_)) => {
                return Err("lifecycle loss manufactured terminal authority".into());
            }
            (_, CoordinatorRunOutcome::Retained(retained)) => {
                let reason = retained.reason();
                let failure = retained.failure_for_test();
                drop(retained.release_for_test());
                return Err(format!(
                    "terminal matrix case retained authority: {reason:?}, failure={failure:?}"
                )
                .into());
            }
            (_, CoordinatorRunOutcome::Terminal(result)) => {
                let expected_exit = case.expected_guardian_exit();
                if !guardian_status_matches(result.guardian_status(), expected_exit) {
                    return Err("exact guardian wait disposition was flattened".into());
                }
                let report = result.report();
                if report.app
                    != (ChildDisposition::Exited {
                        code: 0,
                        stop_action: StopAction::None,
                    })
                    || report.tui != case.tui_disposition()
                    || report.worker != WorkerJoinStatus::JoinedClean
                    || report.cleanup != CleanupStatus::Complete
                    || report.session != case.expected_session_status()
                    || report.guardian_exit != expected_exit
                {
                    return Err("terminal matrix report lost exact lifecycle fields".into());
                }
                drop(result.into_authority());
            }
        }
        peer_result.map_err(|error| format!("matrix guardian peer failed: {error}"))?;
        std::fs::remove_dir_all(root)?;
        eprintln!("coordinator-finished");
        Ok(())
    }

    fn run_matrix_guardian_peer(
        case: ProductionMatrixCase,
        snapshot: TerminalSnapshotFingerprint,
        lifecycle: LifecycleEndpoint,
        terminal: TerminalEndpoint,
        mut trigger: ChildStdin,
        app_group: MatrixScanGroup,
        tui_group: MatrixScanGroup,
    ) -> Result<(), &'static str> {
        let mut receiver = GuardianCommandReceiver::new_terminal(lifecycle);
        matrix_event(&mut receiver, GuardianEvent::LeaseCommitted)?;
        matrix_command(&mut receiver, CoordinatorCommand::Start)?;
        matrix_event(&mut receiver, GuardianEvent::TerminalArmed { snapshot })?;
        matrix_command(&mut receiver, CoordinatorCommand::TerminalArmAccepted)?;
        matrix_event(
            &mut receiver,
            GuardianEvent::ChildStarted {
                role: ChildRole::AppServer,
                pid: app_group.raw_pid,
                pgid: app_group.raw_pid,
            },
        )?;
        if case == ProductionMatrixCase::CoordinatorAuthorityLeak {
            if receiver.receive(Instant::now() + TEST_TIMEOUT).is_ok() {
                return Err("A leak advanced the coordinator lifecycle");
            }
            trigger
                .write_all(b"stop\n")
                .map_err(|_| "A-leak guardian trigger failed")?;
            return Ok(());
        }
        matrix_event(
            &mut receiver,
            GuardianEvent::ChildStarted {
                role: ChildRole::Tui,
                pid: tui_group.raw_pid,
                pgid: tui_group.raw_pid,
            },
        )?;
        matrix_event(&mut receiver, GuardianEvent::Ready)?;
        matrix_command(&mut receiver, CoordinatorCommand::OpenInputGate)?;
        let _initial_gate = receiver
            .take_verified_initial_open_gate_command()
            .map_err(|_| "missing initial gate proof")?;
        matrix_event(&mut receiver, GuardianEvent::InputGateOpened)?;
        eprintln!("coordinator-active");

        match case {
            ProductionMatrixCase::ForwardedHup => {
                matrix_command(
                    &mut receiver,
                    CoordinatorCommand::Signal {
                        signal: UnixSignal::Hup,
                    },
                )?;
                matrix_event(
                    &mut receiver,
                    GuardianEvent::SignalForwarded {
                        signal: UnixSignal::Hup,
                    },
                )?;
            }
            ProductionMatrixCase::ForwardedTerm => {
                matrix_command(
                    &mut receiver,
                    CoordinatorCommand::Signal {
                        signal: UnixSignal::Term,
                    },
                )?;
                matrix_event(
                    &mut receiver,
                    GuardianEvent::SignalForwarded {
                        signal: UnixSignal::Term,
                    },
                )?;
            }
            ProductionMatrixCase::SuspendResume => {
                matrix_command(&mut receiver, CoordinatorCommand::Suspend)?;
                let _suspend = receiver
                    .take_verified_suspend_command()
                    .map_err(|_| "missing suspend proof")?;
                matrix_event(&mut receiver, GuardianEvent::Suspended)?;
                let resume = receiver
                    .receive(Instant::now() + TEST_TIMEOUT)
                    .map_err(|_| "missing resume command")?;
                let CoordinatorCommand::Resume { rows, cols } = resume else {
                    return Err("unexpected command after suspend");
                };
                let proof = receiver
                    .take_verified_resume_command()
                    .map_err(|_| "missing resume proof")?;
                if proof.rows() != rows || proof.cols() != cols {
                    return Err("resume proof geometry mismatch");
                }
                matrix_event(&mut receiver, GuardianEvent::Resumed { rows, cols })?;
                matrix_command(&mut receiver, CoordinatorCommand::OpenInputGate)?;
                let _resume_gate = receiver
                    .take_verified_resume_open_gate_command()
                    .map_err(|_| "missing resume gate proof")?;
                matrix_event(&mut receiver, GuardianEvent::InputGateOpened)?;
            }
            ProductionMatrixCase::Eof
            | ProductionMatrixCase::DataThenEof
            | ProductionMatrixCase::ExitTwentyThree
            | ProductionMatrixCase::LifecycleLost
            | ProductionMatrixCase::CoordinatorAuthorityLeak => {}
        }

        if case == ProductionMatrixCase::DataThenEof {
            write_matrix_terminal(&terminal, PRODUCTION_MATRIX_OUTPUT)?;
        }
        terminal
            .shutdown(TerminalShutdown::Write)
            .map_err(|_| "terminal peer half-close failed")?;
        if case == ProductionMatrixCase::LifecycleLost {
            // Close lifecycle while the direct guardian child is still
            // definitely alive. This makes channel loss, rather than a racing
            // wait-visible child, the retained root cause. The trigger stays
            // owned by this thread until after the coordinator has observed
            // EOF and entered bounded retention.
            drop(receiver);
            drop(terminal);
            std::thread::sleep(Duration::from_millis(150));
            return Ok(());
        }
        // Force the production loop to observe terminal-channel EOF before
        // lifecycle quiescence; EOF is sticky data-path state, never the
        // authority that replaces this later typed event.
        std::thread::sleep(Duration::from_millis(75));
        matrix_event(&mut receiver, GuardianEvent::TerminalQuiesced)?;
        matrix_command(&mut receiver, CoordinatorCommand::TerminalRestored)?;
        let _restored = receiver
            .take_verified_terminal_restored_command()
            .map_err(|_| "missing restored command proof")?;
        matrix_event(&mut receiver, GuardianEvent::TerminalRecoveryDisarmed)?;
        trigger
            .write_all(b"finish\n")
            .map_err(|_| "guardian child trigger failed")?;
        trigger
            .flush()
            .map_err(|_| "guardian child trigger flush failed")?;

        let app = ChildDisposition::Exited {
            code: 0,
            stop_action: StopAction::None,
        };
        let guardian_exit = case.expected_guardian_exit();
        matrix_event(
            &mut receiver,
            GuardianEvent::ChildrenReaped {
                app,
                tui: case.tui_disposition(),
                worker: WorkerJoinStatus::JoinedClean,
                cleanup: CleanupStatus::Complete,
                session: case.expected_session_status(),
                guardian_exit,
            },
        )?;
        let verified = receiver
            .take_verified_exit_disposition()
            .map_err(|_| "guardian exit proof was not minted")?
            .into_disposition();
        if verified != guardian_exit {
            return Err("guardian exit proof mismatch");
        }
        Ok(())
    }

    fn matrix_event(
        receiver: &mut GuardianCommandReceiver<LifecycleEndpoint>,
        event: GuardianEvent,
    ) -> Result<(), &'static str> {
        receiver
            .record_and_send(event, Instant::now() + TEST_TIMEOUT)
            .map_err(|_| "guardian lifecycle event failed")
    }

    fn matrix_command(
        receiver: &mut GuardianCommandReceiver<LifecycleEndpoint>,
        expected: CoordinatorCommand,
    ) -> Result<(), &'static str> {
        let context = match expected {
            CoordinatorCommand::Start => "START command failed",
            CoordinatorCommand::TerminalArmAccepted => "terminal-arm command failed",
            CoordinatorCommand::OpenInputGate => "open-gate command failed",
            CoordinatorCommand::Signal { .. } => "signal command failed",
            CoordinatorCommand::Resize { .. } => "resize command failed",
            CoordinatorCommand::Suspend => "suspend command failed",
            CoordinatorCommand::Resume { .. } => "resume command failed",
            CoordinatorCommand::TerminalRestored => "terminal-restored command failed",
            CoordinatorCommand::Stop => "stop command failed",
        };
        let actual = receiver
            .receive(Instant::now() + TEST_TIMEOUT)
            .map_err(|_| context)?;
        if actual == expected {
            Ok(())
        } else {
            Err("unexpected coordinator lifecycle command")
        }
    }

    fn write_matrix_terminal(
        endpoint: &TerminalEndpoint,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer
            .load(bytes)
            .map_err(|_| "terminal output buffer failed")?;
        let deadline = Instant::now() + TEST_TIMEOUT;
        while chunk.remaining() != 0 {
            if Instant::now() >= deadline {
                return Err("terminal output write timed out");
            }
            match endpoint
                .try_write(&mut chunk)
                .map_err(|_| "terminal output write failed")?
            {
                TerminalWrite::Complete => return Ok(()),
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        Ok(())
    }

    fn expect_matrix_line(
        receiver: &Receiver<Result<String, std::io::Error>>,
        expected: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let line = receiver
            .recv_timeout(TEST_TIMEOUT)
            .map_err(|_| "matrix helper control line timed out")??;
        if line == expected {
            Ok(())
        } else {
            Err(format!("expected matrix line {expected:?}, received {line:?}").into())
        }
    }

    fn wait_for_matrix_output(
        master: &PtyMaster,
        marker: &[u8],
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut matched = 0;
        let mut buffer = TerminalBuffer::new();
        loop {
            if Instant::now() >= deadline {
                return Err("matrix terminal output marker timed out".into());
            }
            match master.read_into(&mut buffer)? {
                TerminalRead::Data(chunk) => {
                    for byte in chunk.remaining_bytes_for_test() {
                        if *byte == marker[matched] {
                            matched += 1;
                            if matched == marker.len() {
                                return Ok(());
                            }
                        } else {
                            matched = usize::from(*byte == marker[0]);
                        }
                    }
                }
                TerminalRead::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
                TerminalRead::EndOfStream => {
                    return Err("matrix PTY closed before output marker".into());
                }
            }
        }
    }

    fn wait_for_matrix_stop(
        pid: rustix::process::Pid,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            match rustix::process::waitpid(
                Some(pid),
                rustix::process::WaitOptions::UNTRACED | rustix::process::WaitOptions::NOHANG,
            ) {
                Ok(Some((observed, status))) if observed == pid && status.stopped() => {
                    return Ok(());
                }
                Ok(Some((_, status))) if status.exited() || status.signaled() => {
                    return Err("matrix helper exited before the suspend stop".into());
                }
                Ok(Some(_)) | Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(rustix::io::Errno::INTR) => {}
                Ok(Some(_)) | Ok(None) => return Err("matrix helper did not stop".into()),
                Err(_) => return Err("matrix helper waitpid failed".into()),
            }
        }
    }

    fn drain_matrix_master(master: PtyMaster, deadline: Instant) -> Result<(), &'static str> {
        let mut buffer = TerminalBuffer::new();
        loop {
            if Instant::now() >= deadline {
                return Err("matrix outer PTY remained open");
            }
            match master.read_into(&mut buffer) {
                Ok(TerminalRead::EndOfStream) => return Ok(()),
                Ok(TerminalRead::Data(_) | TerminalRead::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return Err("matrix outer PTY drain failed"),
            }
        }
    }

    fn spawn_matrix_scan_group(
        root: &std::path::Path,
        role: &str,
    ) -> Result<MatrixScanGroup, Box<dyn std::error::Error>> {
        let marker = root.join(format!("{role}-group-ready"));
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "/bin/sleep 30 & child=$!; : > \"$CALCIFER_MATRIX_GROUP_READY\"; wait \"$child\"",
            ])
            .env("CALCIFER_MATRIX_GROUP_READY", &marker)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn()?;
        let raw_pid = i32::try_from(child.id())?;
        let group = MatrixScanGroup { child, raw_pid };
        let deadline = Instant::now() + TEST_TIMEOUT;
        let empty_forbidden = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        loop {
            let stable = marker.is_file()
                && calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                    raw_pid,
                    &empty_forbidden,
                    deadline,
                )
                .is_ok_and(|proof| proof.member_count() == 2);
            if stable {
                std::fs::remove_file(&marker)?;
                return Ok(group);
            }
            if Instant::now() >= deadline {
                return Err("matrix process group did not become ready".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    struct MatrixScanGroup {
        child: Child,
        raw_pid: i32,
    }

    fn wait_for_matrix_group_gone(
        raw_process_group: i32,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let process_group = rustix::process::Pid::from_raw(raw_process_group)
            .ok_or("invalid matrix process group")?;
        loop {
            match rustix::process::test_kill_process_group(process_group) {
                Err(rustix::io::Errno::SRCH) => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Ok(()) | Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(()) => return Err("matrix process group remained live".into()),
                Err(_) => return Err("matrix process group absence was inconclusive".into()),
            }
        }
    }

    impl Drop for MatrixScanGroup {
        fn drop(&mut self) {
            if let Some(group) = rustix::process::Pid::from_raw(self.raw_pid) {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = self.child.wait();
        }
    }

    struct MatrixTestChild {
        child: Option<Child>,
    }

    impl MatrixTestChild {
        fn new(child: Child) -> Self {
            Self { child: Some(child) }
        }

        fn wait_before(
            &mut self,
            deadline: Instant,
        ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
            let child = self.child.as_mut().ok_or("matrix helper already reaped")?;
            loop {
                if let Some(status) = child.try_wait()? {
                    self.child = None;
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    self.child = None;
                    return Err("matrix helper exceeded its deadline".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Drop for MatrixTestChild {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
            }
        }
    }
}
