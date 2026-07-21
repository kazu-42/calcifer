//! Linear composition for one feature-gated supervised Codex session.
//!
//! This module owns lifecycle ordering only. Provider identities, paths, and
//! thread metadata remain sealed in the capabilities that created the concrete
//! components; the session state machine never reconstructs them from strings.

use std::fmt;
use std::marker::PhantomData;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use super::launcher::RemoteTuiLauncherError;
use super::launcher::{ReadyRemoteTui, RemoteTuiShutdownFailure};
#[cfg(test)]
use super::packaged_smoke::write_private_atomic_new;
use super::process::{
    ForwardedTuiSignal, InteractiveTerminalSignal, PinnedAppGracefulDrain, ShutdownOutcome,
    TerminalShutdownSignal,
};
#[cfg(test)]
use super::protocol::StopAction;
use super::protocol::{
    ChildDisposition, GuardianExitDisposition, SessionStatus, SessionTerminationCause, UnixSignal,
    VerifiedInitialOpenGateCommand, VerifiedResizeCommand, VerifiedResumeCommand,
    VerifiedResumeOpenGateCommand, VerifiedSuspendCommand, VerifiedTerminalRestoredCommand,
    WorkerJoinStatus, project_terminal_semantics,
};
use super::provider::{
    AppServerStopFailure, AppServerTeardownFailure, ConnectedMonitorSession, ExactRelaySession,
    ExactRelayShutdownFailure, GuardianSessionAdmissionFailure, GuardianSessionAuthority,
    PinnedSessionBuild, ProviderCleanupFailure, ProviderLaunchError, StoppedAppServer,
    admit_guardian_session,
};
use super::startup::ProviderNeverStarted;
use super::terminal::{
    RecoveryDisarmOutcome, RecoveryDisarmProof, RecoveryDisarmUnconfirmed, RecoveryTty,
    RestoredTerminalProof, TerminalBuffer, TerminalEndpoint, TerminalError, TerminalRead,
    TerminalShutdown, TerminalSize, TerminalSnapshot, TerminalWrite,
};
use crate::profiles::{Profile, ProfileError, Registry};
use crate::providers::codex::CodexUsage;
use crate::providers::codex::monitor::{
    SessionMonitor, SessionMonitorError, SessionMonitorShutdownOwner, SessionUsageLimitSignal,
};
use crate::providers::codex::remote::{EffectiveThreadSettings, ReadinessProxyError};

const TERMINAL_PUMP_RETRY: Duration = Duration::from_millis(1);
const TERMINAL_DISCARD_MAX_FRAGMENTS: usize = 64;

#[cfg(test)]
const PACKAGED_INPUT_OBSERVATION_LIMIT: usize = 64 * 1024;

#[cfg(test)]
pub(super) const PACKAGED_TUI_OUTPUT_SENTINEL: &str = "calcifer package current response sentinel";

/// Constant-space matcher for the current package-only response proof. It
/// retains no terminal bytes: only the longest matching prefix and the sticky
/// result. Startup history uses a distinct sentinel and cannot satisfy it.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PackagedTuiOutputMatcher {
    matched_prefix: usize,
    seen: bool,
}

#[cfg(test)]
impl PackagedTuiOutputMatcher {
    pub(super) const fn new() -> Self {
        Self {
            matched_prefix: 0,
            seen: false,
        }
    }

    pub(super) fn observe(&mut self, bytes: &[u8]) {
        if self.seen {
            return;
        }
        for &byte in bytes {
            self.matched_prefix = advance_packaged_output_match(self.matched_prefix, byte);
            if self.matched_prefix == PACKAGED_TUI_OUTPUT_SENTINEL.len() {
                self.seen = true;
                return;
            }
        }
    }

    pub(super) const fn seen(self) -> bool {
        self.seen
    }
}

#[cfg(test)]
fn advance_packaged_output_match(matched_prefix: usize, byte: u8) -> usize {
    let pattern = PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes();
    let sequence_length = matched_prefix.saturating_add(1);
    let mut candidate = sequence_length.min(pattern.len());
    while candidate != 0 {
        let suffix_start = sequence_length - candidate;
        let mut offset = 0;
        let mut matches = true;
        while offset < candidate {
            let source_index = suffix_start + offset;
            let source = if source_index < matched_prefix {
                pattern[source_index]
            } else {
                byte
            };
            if pattern[offset] != source {
                matches = false;
                break;
            }
            offset += 1;
        }
        if matches {
            return candidate;
        }
        candidate -= 1;
    }
    0
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedTerminationCause {
    None,
    NaturalTuiEof,
    CoordinatorStop,
    ForwardedHup,
    ForwardedTerm,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedOperationError {
    None,
    RecoveryRequested,
    Deadline,
    MonitorInvalidArgument,
    MonitorHandshake,
    MonitorProtocol,
    MonitorAuthentication,
    MonitorProvider,
    MonitorUnsupported,
    MonitorTimeout,
    MonitorTransport,
    MonitorWorker,
    MonitorAppServer,
    ComponentMonitorApp,
    ComponentReadinessRelay,
    ComponentTui,
    PumpDeadline,
    PumpInvalidState,
    PumpTuiOutputEof,
    PumpTerminalChannelEof,
    PumpTuiRead,
    PumpTuiWrite,
    PumpTerminalChannelRead,
    PumpTerminalChannelWrite,
    PumpSignal,
    PumpResize,
    PumpSuspend,
    PumpResume,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedTuiDisposition {
    Unresolved,
    Forced,
    ExitZero,
    ExitNonzero,
    Signaled,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedWorkerJoin {
    NotStarted,
    JoinedClean,
    JoinedFailed,
    JoinedPanicked,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedSessionStatus {
    Completed,
    Failed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservedGuardianExit {
    Success,
    NonzeroCode,
    Signal,
    InternalFailure,
}

#[cfg(test)]
// Termination causes are causal observations, not failure classifications:
// natural EOF and the coordinated/signal shutdown causes can all project to a
// successful session. Concrete operation, disposition, cleanup, session, and
// guardian markers below remain the fail-closed package diagnostic surface.
pub(super) const PACKAGED_SESSION_TERMINAL_FAILURE_MARKERS: &[&str] = &[
    "session-terminal.operation.deadline",
    "session-terminal.operation.monitor-invalid-argument",
    "session-terminal.operation.monitor-handshake",
    "session-terminal.operation.monitor-protocol",
    "session-terminal.operation.monitor-authentication",
    "session-terminal.operation.monitor-provider",
    "session-terminal.operation.monitor-unsupported",
    "session-terminal.operation.monitor-timeout",
    "session-terminal.operation.monitor-transport",
    "session-terminal.operation.monitor-worker",
    "session-terminal.operation.monitor-app-server",
    "session-terminal.operation.component-monitor-app",
    "session-terminal.operation.component-readiness-relay",
    "session-terminal.operation.component-tui",
    "session-terminal.operation.pump-deadline",
    "session-terminal.operation.pump-invalid-state",
    "session-terminal.operation.pump-tui-output-eof",
    "session-terminal.operation.pump-terminal-channel-eof",
    "session-terminal.operation.pump-tui-read",
    "session-terminal.operation.pump-tui-write",
    "session-terminal.operation.pump-terminal-channel-read",
    "session-terminal.operation.pump-terminal-channel-write",
    "session-terminal.operation.pump-signal",
    "session-terminal.operation.pump-resize",
    "session-terminal.operation.pump-suspend",
    "session-terminal.operation.pump-resume",
    "session-terminal.tui.exit-nonzero",
    "session-terminal.tui.signaled",
    "session-terminal.tui.forced",
    "session-terminal.tui.unresolved",
    "session-terminal.worker.joined-failed",
    "session-terminal.worker.joined-panicked",
    "session-terminal.worker.not-started",
    "session-terminal.cleanup.failed",
    "session-terminal.guardian-exit.nonzero-code",
    "session-terminal.guardian-exit.signal",
    "session-terminal.guardian-exit.internal-failure",
    "session-terminal.session.failed",
];

/// Closed package-only catalog for the exact operation held by a retained
/// guardian before a terminal observation can be published.
#[cfg(test)]
pub(super) const PACKAGED_SESSION_RETAINED_OPERATION_MARKERS: &[&str] = &[
    "guardian-retained.session-operation.none",
    "guardian-retained.session-operation.recovery-requested",
    "guardian-retained.session-operation.deadline",
    "guardian-retained.session-operation.monitor-invalid-argument",
    "guardian-retained.session-operation.monitor-handshake",
    "guardian-retained.session-operation.monitor-protocol",
    "guardian-retained.session-operation.monitor-authentication",
    "guardian-retained.session-operation.monitor-provider",
    "guardian-retained.session-operation.monitor-unsupported",
    "guardian-retained.session-operation.monitor-timeout",
    "guardian-retained.session-operation.monitor-transport",
    "guardian-retained.session-operation.monitor-worker",
    "guardian-retained.session-operation.monitor-app-server",
    "guardian-retained.session-operation.component-monitor-app",
    "guardian-retained.session-operation.component-readiness-relay",
    "guardian-retained.session-operation.component-tui",
    "guardian-retained.session-operation.pump-deadline",
    "guardian-retained.session-operation.pump-invalid-state",
    "guardian-retained.session-operation.pump-tui-output-eof",
    "guardian-retained.session-operation.pump-terminal-channel-eof",
    "guardian-retained.session-operation.pump-tui-read",
    "guardian-retained.session-operation.pump-tui-write",
    "guardian-retained.session-operation.pump-terminal-channel-read",
    "guardian-retained.session-operation.pump-terminal-channel-write",
    "guardian-retained.session-operation.pump-signal",
    "guardian-retained.session-operation.pump-resize",
    "guardian-retained.session-operation.pump-suspend",
    "guardian-retained.session-operation.pump-resume",
];

#[cfg(test)]
const fn packaged_observed_termination_marker(
    cause: PackagedObservedTerminationCause,
) -> &'static str {
    match cause {
        PackagedObservedTerminationCause::None => "session-terminal.termination-cause.none",
        PackagedObservedTerminationCause::NaturalTuiEof => {
            "session-terminal.termination-cause.natural-tui-eof"
        }
        PackagedObservedTerminationCause::CoordinatorStop => {
            "session-terminal.termination-cause.coordinator-stop"
        }
        PackagedObservedTerminationCause::ForwardedHup => {
            "session-terminal.termination-cause.forwarded-hup"
        }
        PackagedObservedTerminationCause::ForwardedTerm => {
            "session-terminal.termination-cause.forwarded-term"
        }
    }
}

#[cfg(test)]
const fn packaged_observed_operation_marker(error: PackagedObservedOperationError) -> &'static str {
    match error {
        PackagedObservedOperationError::None => "session-terminal.operation.none",
        PackagedObservedOperationError::RecoveryRequested => {
            "session-terminal.operation.recovery-requested"
        }
        PackagedObservedOperationError::Deadline => "session-terminal.operation.deadline",
        PackagedObservedOperationError::MonitorInvalidArgument => {
            "session-terminal.operation.monitor-invalid-argument"
        }
        PackagedObservedOperationError::MonitorHandshake => {
            "session-terminal.operation.monitor-handshake"
        }
        PackagedObservedOperationError::MonitorProtocol => {
            "session-terminal.operation.monitor-protocol"
        }
        PackagedObservedOperationError::MonitorAuthentication => {
            "session-terminal.operation.monitor-authentication"
        }
        PackagedObservedOperationError::MonitorProvider => {
            "session-terminal.operation.monitor-provider"
        }
        PackagedObservedOperationError::MonitorUnsupported => {
            "session-terminal.operation.monitor-unsupported"
        }
        PackagedObservedOperationError::MonitorTimeout => {
            "session-terminal.operation.monitor-timeout"
        }
        PackagedObservedOperationError::MonitorTransport => {
            "session-terminal.operation.monitor-transport"
        }
        PackagedObservedOperationError::MonitorWorker => {
            "session-terminal.operation.monitor-worker"
        }
        PackagedObservedOperationError::MonitorAppServer => {
            "session-terminal.operation.monitor-app-server"
        }
        PackagedObservedOperationError::ComponentMonitorApp => {
            "session-terminal.operation.component-monitor-app"
        }
        PackagedObservedOperationError::ComponentReadinessRelay => {
            "session-terminal.operation.component-readiness-relay"
        }
        PackagedObservedOperationError::ComponentTui => "session-terminal.operation.component-tui",
        PackagedObservedOperationError::PumpDeadline => "session-terminal.operation.pump-deadline",
        PackagedObservedOperationError::PumpInvalidState => {
            "session-terminal.operation.pump-invalid-state"
        }
        PackagedObservedOperationError::PumpTuiOutputEof => {
            "session-terminal.operation.pump-tui-output-eof"
        }
        PackagedObservedOperationError::PumpTerminalChannelEof => {
            "session-terminal.operation.pump-terminal-channel-eof"
        }
        PackagedObservedOperationError::PumpTuiRead => "session-terminal.operation.pump-tui-read",
        PackagedObservedOperationError::PumpTuiWrite => "session-terminal.operation.pump-tui-write",
        PackagedObservedOperationError::PumpTerminalChannelRead => {
            "session-terminal.operation.pump-terminal-channel-read"
        }
        PackagedObservedOperationError::PumpTerminalChannelWrite => {
            "session-terminal.operation.pump-terminal-channel-write"
        }
        PackagedObservedOperationError::PumpSignal => "session-terminal.operation.pump-signal",
        PackagedObservedOperationError::PumpResize => "session-terminal.operation.pump-resize",
        PackagedObservedOperationError::PumpSuspend => "session-terminal.operation.pump-suspend",
        PackagedObservedOperationError::PumpResume => "session-terminal.operation.pump-resume",
    }
}

#[cfg(test)]
const fn packaged_observed_tui_marker(disposition: PackagedObservedTuiDisposition) -> &'static str {
    match disposition {
        PackagedObservedTuiDisposition::Unresolved => "session-terminal.tui.unresolved",
        PackagedObservedTuiDisposition::Forced => "session-terminal.tui.forced",
        PackagedObservedTuiDisposition::ExitZero => "session-terminal.tui.exit-0",
        PackagedObservedTuiDisposition::ExitNonzero => "session-terminal.tui.exit-nonzero",
        PackagedObservedTuiDisposition::Signaled => "session-terminal.tui.signaled",
    }
}

#[cfg(test)]
const fn packaged_observed_worker_marker(worker: PackagedObservedWorkerJoin) -> &'static str {
    match worker {
        PackagedObservedWorkerJoin::NotStarted => "session-terminal.worker.not-started",
        PackagedObservedWorkerJoin::JoinedClean => "session-terminal.worker.joined-clean",
        PackagedObservedWorkerJoin::JoinedFailed => "session-terminal.worker.joined-failed",
        PackagedObservedWorkerJoin::JoinedPanicked => "session-terminal.worker.joined-panicked",
    }
}

#[cfg(test)]
const fn packaged_observed_cleanup_marker(cleanup_clean: bool) -> &'static str {
    if cleanup_clean {
        "session-terminal.cleanup.clean"
    } else {
        "session-terminal.cleanup.failed"
    }
}

#[cfg(test)]
const fn packaged_observed_session_marker(status: PackagedObservedSessionStatus) -> &'static str {
    match status {
        PackagedObservedSessionStatus::Completed => "session-terminal.session.completed",
        PackagedObservedSessionStatus::Failed => "session-terminal.session.failed",
    }
}

#[cfg(test)]
const fn packaged_observed_guardian_exit_marker(
    disposition: PackagedObservedGuardianExit,
) -> &'static str {
    match disposition {
        PackagedObservedGuardianExit::Success => "session-terminal.guardian-exit.success",
        PackagedObservedGuardianExit::NonzeroCode => "session-terminal.guardian-exit.nonzero-code",
        PackagedObservedGuardianExit::Signal => "session-terminal.guardian-exit.signal",
        PackagedObservedGuardianExit::InternalFailure => {
            "session-terminal.guardian-exit.internal-failure"
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum PackagedObservationIntegrityFailure {
    MarkerWrite,
    OutputOrder,
    InitialSize,
    InputOrder,
    InputLengthOverflow,
    InputLimit,
    InputPersist,
    DuplicateShutdown,
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(super) struct PackagedSessionObservation {
    pub(super) initial_size: Option<(u16, u16)>,
    pub(super) resized_sizes: Vec<(u16, u16)>,
    pub(super) resumed_sizes: Vec<(u16, u16)>,
    pub(super) suspend_count: usize,
    pub(super) input: Vec<u8>,
    pub(super) output_sentinel_seen: bool,
    pub(super) shutdown_observed: bool,
    pub(super) termination_cause: Option<PackagedObservedTerminationCause>,
    pub(super) operation_error: Option<PackagedObservedOperationError>,
    pub(super) tui_disposition: Option<PackagedObservedTuiDisposition>,
    pub(super) worker_join: Option<PackagedObservedWorkerJoin>,
    pub(super) cleanup_clean: Option<bool>,
    pub(super) session_status: Option<PackagedObservedSessionStatus>,
    pub(super) guardian_exit: Option<PackagedObservedGuardianExit>,
    pub(super) integrity_failure: Option<PackagedObservationIntegrityFailure>,
    pub(super) observation_failed: bool,
}

#[cfg(test)]
struct ArmedPackagedSessionObservation {
    observation_root: PathBuf,
    live_input_path: PathBuf,
    output_matcher: PackagedTuiOutputMatcher,
    observation: PackagedSessionObservation,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPackagedOutputObservation {
    before: PackagedTuiOutputMatcher,
    after: PackagedTuiOutputMatcher,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingPackagedInputObservation {
    prior_length: usize,
    bytes: Vec<u8>,
}

#[cfg(test)]
static PACKAGED_SESSION_OBSERVATION: Mutex<Option<ArmedPackagedSessionObservation>> =
    Mutex::new(None);

#[cfg(test)]
fn fail_packaged_session_observation(
    armed: &mut ArmedPackagedSessionObservation,
    failure: PackagedObservationIntegrityFailure,
) {
    armed.observation.observation_failed = true;
    armed.observation.integrity_failure.get_or_insert(failure);
}

fn terminal_resize_requires_application(
    applied: Option<TerminalSize>,
    requested: TerminalSize,
) -> bool {
    applied != Some(requested)
}

#[cfg(test)]
pub(super) fn arm_packaged_session_observation(
    observation_root: PathBuf,
) -> Result<(), std::io::Error> {
    let live_input_path = observation_root.join("input.live");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&live_input_path)?;
    file.sync_all()?;
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_some() {
        return Err(std::io::Error::other(
            "the packaged session observer was already armed",
        ));
    }
    *guard = Some(ArmedPackagedSessionObservation {
        observation_root,
        live_input_path,
        output_matcher: PackagedTuiOutputMatcher::new(),
        observation: PackagedSessionObservation::default(),
    });
    Ok(())
}

#[cfg(test)]
fn write_packaged_observation_marker(
    armed: &mut ArmedPackagedSessionObservation,
    name: &str,
    payload: &[u8],
) {
    write_packaged_observation_marker_with_publisher(
        armed,
        name,
        payload,
        write_private_atomic_new,
    );
}

#[cfg(test)]
fn write_packaged_observation_marker_with_publisher<E>(
    armed: &mut ArmedPackagedSessionObservation,
    name: &str,
    payload: &[u8],
    publish: impl FnOnce(&Path, &[u8]) -> Result<(), E>,
) {
    // Observation markers are consumed concurrently by the package-smoke
    // coordinator. Publish the complete, durable payload atomically so the
    // reader can never mistake a newly-created empty or partial file for an
    // integrity failure.
    let marker = armed.observation_root.join(name);
    let result = publish(&marker, payload);
    if result.is_err() {
        fail_packaged_session_observation(armed, PackagedObservationIntegrityFailure::MarkerWrite);
    }
}

#[cfg(test)]
pub(super) fn take_packaged_session_observation() -> Option<PackagedSessionObservation> {
    PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .map(|armed| armed.observation)
}

#[cfg(test)]
fn prepare_packaged_output_observation(bytes: &[u8]) -> Option<PendingPackagedOutputObservation> {
    let guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let armed = guard.as_ref()?;
    let before = armed.output_matcher;
    let mut after = before;
    after.observe(bytes);
    Some(PendingPackagedOutputObservation { before, after })
}

#[cfg(test)]
fn commit_packaged_output_observation(pending: Option<PendingPackagedOutputObservation>) {
    let Some(pending) = pending else {
        return;
    };
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(armed) = guard.as_mut() else {
        return;
    };
    if armed.output_matcher != pending.before {
        fail_packaged_session_observation(armed, PackagedObservationIntegrityFailure::OutputOrder);
        return;
    }
    armed.output_matcher = pending.after;
    armed.observation.output_sentinel_seen = pending.after.seen();
}

#[cfg(test)]
fn packaged_output_sentinel_seen_for_test() -> bool {
    PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_some_and(|armed| armed.output_matcher.seen())
}

#[cfg(test)]
fn observe_packaged_initial_size(size: Result<TerminalSize, RemoteTuiLauncherError>) {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(armed) = guard.as_mut() else {
        return;
    };
    match size {
        Ok(size) => {
            armed.observation.initial_size = Some((size.rows(), size.columns()));
            write_packaged_observation_marker(
                armed,
                "initial-size.live",
                format!("{} {}\n", size.rows(), size.columns()).as_bytes(),
            );
        }
        Err(_) => fail_packaged_session_observation(
            armed,
            PackagedObservationIntegrityFailure::InitialSize,
        ),
    }
}

#[cfg(test)]
fn observe_packaged_resize(size: TerminalSize) {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(armed) = guard.as_mut() {
        armed
            .observation
            .resized_sizes
            .push((size.rows(), size.columns()));
        if armed.observation.resized_sizes.len() == 1 {
            write_packaged_observation_marker(
                armed,
                "resize.live",
                format!("{} {}\n", size.rows(), size.columns()).as_bytes(),
            );
        }
    }
}

#[cfg(test)]
fn observe_packaged_suspend() {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(armed) = guard.as_mut() {
        armed.observation.suspend_count = armed.observation.suspend_count.saturating_add(1);
        if armed.observation.suspend_count == 1 {
            write_packaged_observation_marker(armed, "suspend.live", b"suspended\n");
        }
    }
}

#[cfg(test)]
fn observe_packaged_resume(size: TerminalSize) {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(armed) = guard.as_mut() {
        armed
            .observation
            .resumed_sizes
            .push((size.rows(), size.columns()));
        if armed.observation.resumed_sizes.len() == 1 {
            write_packaged_observation_marker(
                armed,
                "resume.live",
                format!("{} {}\n", size.rows(), size.columns()).as_bytes(),
            );
        }
    }
}

#[cfg(test)]
fn observe_packaged_gate(name: &str) {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(armed) = guard.as_mut() {
        write_packaged_observation_marker(armed, name, b"open\n");
    }
}

#[cfg(test)]
fn prepare_packaged_input_observation(bytes: &[u8]) -> Option<PendingPackagedInputObservation> {
    let guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let armed = guard.as_ref()?;
    Some(PendingPackagedInputObservation {
        prior_length: armed.observation.input.len(),
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
fn commit_packaged_input_observation(pending: Option<PendingPackagedInputObservation>) {
    let Some(pending) = pending else {
        return;
    };
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(armed) = guard.as_mut() else {
        return;
    };
    if armed.observation.input.len() != pending.prior_length {
        fail_packaged_session_observation(armed, PackagedObservationIntegrityFailure::InputOrder);
        return;
    }
    let Some(next_length) = armed
        .observation
        .input
        .len()
        .checked_add(pending.bytes.len())
    else {
        fail_packaged_session_observation(
            armed,
            PackagedObservationIntegrityFailure::InputLengthOverflow,
        );
        return;
    };
    if next_length > PACKAGED_INPUT_OBSERVATION_LIMIT {
        fail_packaged_session_observation(armed, PackagedObservationIntegrityFailure::InputLimit);
        return;
    }
    armed.observation.input.extend_from_slice(&pending.bytes);
    let append = OpenOptions::new()
        .append(true)
        .mode(0o600)
        .open(&armed.live_input_path)
        .and_then(|mut file| {
            file.write_all(&pending.bytes)?;
            file.sync_data()
        });
    if append.is_err() {
        fail_packaged_session_observation(armed, PackagedObservationIntegrityFailure::InputPersist);
    }
}

#[cfg(test)]
fn observe_packaged_terminal_report(
    termination_cause: Option<SessionTerminationCause>,
    operation_error: Option<SessionOperationError>,
    tui_disposition: ChildDisposition,
    worker_join: WorkerJoinStatus,
    cleanup_clean: bool,
    session_status: SessionStatus,
    guardian_exit: GuardianExitDisposition,
) {
    let mut guard = PACKAGED_SESSION_OBSERVATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(armed) = guard.as_mut() else {
        return;
    };
    if armed.observation.shutdown_observed {
        fail_packaged_session_observation(
            armed,
            PackagedObservationIntegrityFailure::DuplicateShutdown,
        );
        return;
    }
    armed.observation.shutdown_observed = true;
    armed.observation.termination_cause = Some(match termination_cause {
        None => PackagedObservedTerminationCause::None,
        Some(SessionTerminationCause::NaturalTuiEof) => {
            PackagedObservedTerminationCause::NaturalTuiEof
        }
        Some(SessionTerminationCause::CoordinatorStop) => {
            PackagedObservedTerminationCause::CoordinatorStop
        }
        Some(SessionTerminationCause::ForwardedHup) => {
            PackagedObservedTerminationCause::ForwardedHup
        }
        Some(SessionTerminationCause::ForwardedTerm) => {
            PackagedObservedTerminationCause::ForwardedTerm
        }
    });
    armed.observation.operation_error = Some(match operation_error {
        None => PackagedObservedOperationError::None,
        Some(SessionOperationError::RecoveryRequested) => {
            PackagedObservedOperationError::RecoveryRequested
        }
        Some(SessionOperationError::Deadline) => PackagedObservedOperationError::Deadline,
        Some(SessionOperationError::Monitor(SessionMonitorError::InvalidArgument)) => {
            PackagedObservedOperationError::MonitorInvalidArgument
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Handshake)) => {
            PackagedObservedOperationError::MonitorHandshake
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Protocol)) => {
            PackagedObservedOperationError::MonitorProtocol
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Authentication)) => {
            PackagedObservedOperationError::MonitorAuthentication
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Provider)) => {
            PackagedObservedOperationError::MonitorProvider
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Unsupported)) => {
            PackagedObservedOperationError::MonitorUnsupported
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Timeout)) => {
            PackagedObservedOperationError::MonitorTimeout
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Transport)) => {
            PackagedObservedOperationError::MonitorTransport
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Worker)) => {
            PackagedObservedOperationError::MonitorWorker
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::AppServer)) => {
            PackagedObservedOperationError::MonitorAppServer
        }
        Some(SessionOperationError::Component(SessionComponent::MonitorAndApp)) => {
            PackagedObservedOperationError::ComponentMonitorApp
        }
        Some(SessionOperationError::Component(SessionComponent::ReadinessRelay)) => {
            PackagedObservedOperationError::ComponentReadinessRelay
        }
        Some(SessionOperationError::Component(SessionComponent::Tui)) => {
            PackagedObservedOperationError::ComponentTui
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Deadline)) => {
            PackagedObservedOperationError::PumpDeadline
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::InvalidState)) => {
            PackagedObservedOperationError::PumpInvalidState
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiOutputEof)) => {
            PackagedObservedOperationError::PumpTuiOutputEof
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelEof)) => {
            PackagedObservedOperationError::PumpTerminalChannelEof
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiRead)) => {
            PackagedObservedOperationError::PumpTuiRead
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiWrite)) => {
            PackagedObservedOperationError::PumpTuiWrite
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelRead)) => {
            PackagedObservedOperationError::PumpTerminalChannelRead
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelWrite)) => {
            PackagedObservedOperationError::PumpTerminalChannelWrite
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Signal)) => {
            PackagedObservedOperationError::PumpSignal
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Resize)) => {
            PackagedObservedOperationError::PumpResize
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Suspend)) => {
            PackagedObservedOperationError::PumpSuspend
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Resume)) => {
            PackagedObservedOperationError::PumpResume
        }
    });
    armed.observation.tui_disposition = Some(match tui_disposition {
        ChildDisposition::NotStarted => PackagedObservedTuiDisposition::Unresolved,
        ChildDisposition::Exited {
            stop_action: StopAction::Term | StopAction::Kill,
            ..
        }
        | ChildDisposition::Signaled {
            stop_action: StopAction::Term | StopAction::Kill,
            ..
        } => PackagedObservedTuiDisposition::Forced,
        ChildDisposition::Exited {
            code: 0,
            stop_action: StopAction::None,
        } => PackagedObservedTuiDisposition::ExitZero,
        ChildDisposition::Exited {
            stop_action: StopAction::None,
            ..
        } => PackagedObservedTuiDisposition::ExitNonzero,
        ChildDisposition::Signaled {
            stop_action: StopAction::None,
            ..
        } => PackagedObservedTuiDisposition::Signaled,
    });
    armed.observation.worker_join = Some(match worker_join {
        WorkerJoinStatus::NotStarted => PackagedObservedWorkerJoin::NotStarted,
        WorkerJoinStatus::JoinedClean => PackagedObservedWorkerJoin::JoinedClean,
        WorkerJoinStatus::JoinedFailed => PackagedObservedWorkerJoin::JoinedFailed,
        WorkerJoinStatus::JoinedPanicked => PackagedObservedWorkerJoin::JoinedPanicked,
    });
    armed.observation.cleanup_clean = Some(cleanup_clean);
    armed.observation.session_status = Some(match session_status {
        SessionStatus::Completed => PackagedObservedSessionStatus::Completed,
        SessionStatus::Failed => PackagedObservedSessionStatus::Failed,
    });
    armed.observation.guardian_exit = Some(match guardian_exit {
        GuardianExitDisposition::Code(0) => PackagedObservedGuardianExit::Success,
        GuardianExitDisposition::Code(_) => PackagedObservedGuardianExit::NonzeroCode,
        GuardianExitDisposition::Signal(_) => PackagedObservedGuardianExit::Signal,
        GuardianExitDisposition::InternalFailure => PackagedObservedGuardianExit::InternalFailure,
    });
    let markers = [
        armed
            .observation
            .termination_cause
            .map(packaged_observed_termination_marker),
        armed
            .observation
            .operation_error
            .map(packaged_observed_operation_marker),
        armed
            .observation
            .tui_disposition
            .map(packaged_observed_tui_marker),
        armed
            .observation
            .worker_join
            .map(packaged_observed_worker_marker),
        armed
            .observation
            .cleanup_clean
            .map(packaged_observed_cleanup_marker),
        armed
            .observation
            .session_status
            .map(packaged_observed_session_marker),
        armed
            .observation
            .guardian_exit
            .map(packaged_observed_guardian_exit_marker),
    ];
    for marker in markers.into_iter().flatten() {
        write_packaged_observation_marker(armed, marker, b"classified\n");
    }
}

/// The exact component whose fresh liveness observation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionComponent {
    MonitorAndApp,
    ReadinessRelay,
    Tui,
}

/// Fixed, redacted active-session failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionOperationError {
    RecoveryRequested,
    Deadline,
    Monitor(SessionMonitorError),
    Component(SessionComponent),
    TerminalPump(TerminalPumpFailure),
}

impl fmt::Display for SessionOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoveryRequested => {
                formatter.write_str("the generation owner requested supervised recovery")
            }
            Self::Deadline => formatter.write_str("the supervised session deadline elapsed"),
            Self::Monitor(error) => error.fmt(formatter),
            Self::Component(SessionComponent::MonitorAndApp) => {
                formatter.write_str("the supervised App Server or monitor is not live")
            }
            Self::Component(SessionComponent::ReadinessRelay) => {
                formatter.write_str("the supervised readiness relay is not live")
            }
            Self::Component(SessionComponent::Tui) => {
                formatter.write_str("the supervised TUI is not live")
            }
            Self::TerminalPump(_) => formatter.write_str("the supervised terminal pump failed"),
        }
    }
}

impl std::error::Error for SessionOperationError {}

/// Internal liveness evidence retained alongside the redacted operation
/// failure. Only a post-readiness relay transport EOF may be correlated with
/// a subsequently observed TUI exit; protocol, worker, and sequencing errors
/// remain immediately fatal even if the TUI exits at the same time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SessionLivenessError {
    operation: SessionOperationError,
    relay_transport: bool,
    tui_exited: bool,
}

impl SessionLivenessError {
    const fn operation(operation: SessionOperationError) -> Self {
        Self {
            operation,
            relay_transport: false,
            tui_exited: false,
        }
    }

    const fn relay(error: ReadinessProxyError) -> Self {
        Self {
            operation: SessionOperationError::Component(SessionComponent::ReadinessRelay),
            relay_transport: matches!(error, ReadinessProxyError::Transport),
            tui_exited: false,
        }
    }

    const fn tui(error: RemoteTuiLauncherError) -> Self {
        Self {
            operation: SessionOperationError::Component(SessionComponent::Tui),
            relay_transport: false,
            tui_exited: matches!(error, RemoteTuiLauncherError::NotLive),
        }
    }
}

/// A bounded, redacted failure from the guardian-side terminal-byte pump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalPumpFailure {
    Deadline,
    InvalidState,
    TuiOutputEof,
    TerminalChannelEof,
    TuiRead,
    TuiWrite,
    TerminalChannelRead,
    TerminalChannelWrite,
    Signal,
    Resize,
    Suspend,
    Resume,
}

/// Observable work from one synchronous, allocation-free pump turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalPumpProgress {
    Idle,
    Output,
    Input,
    Duplex,
    /// The TUI side of the PTY reached its natural terminal EOF. This is a
    /// shutdown trigger, not an I/O failure; exact wait disposition still
    /// decides whether the completed session succeeded.
    TuiOutputClosed,
}

#[cfg(test)]
static PACKAGED_FAIL_NEXT_TERMINAL_CHANNEL_WRITE: AtomicBool = AtomicBool::new(false);

/// Arms one process-local package fault at the production terminal-pump
/// write edge. The package Guardian runs in its own helper process, so this
/// cannot affect another generation or any production build.
#[cfg(test)]
pub(super) fn fail_next_packaged_terminal_channel_write() {
    PACKAGED_FAIL_NEXT_TERMINAL_CHANNEL_WRITE.store(true, Ordering::SeqCst);
}

struct OutputOnlyPump {
    output: TerminalBuffer,
}

struct DuplexPump {
    output: TerminalBuffer,
    input: TerminalBuffer,
}

struct SuspendedPump {
    output: TerminalBuffer,
    resumed: bool,
}

enum TerminalPumpAuthority {
    /// No input buffer or terminal-channel read transition exists in this
    /// variant. Pre-gate bytes therefore cannot reach the PTY by construction.
    OutputOnly(Box<OutputOnlyPump>),
    Duplex(Box<DuplexPump>),
    /// Suspend destroys the old input buffer/generation. Resume leaves this
    /// output-only until a fresh resume-gate proof creates a new buffer.
    Suspended(Box<SuspendedPump>),
    /// PTY EOF synchronously destroys the sole input-buffer generation. The
    /// lifecycle owner may now only quiesce and reap the TUI.
    OutputClosed,
    Quiesced,
    Failed(TerminalPumpFailure),
}

trait GuardianTuiPumpIo {
    fn read_output<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError>;

    fn try_write_input(
        &self,
        chunk: &mut super::terminal::TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError>;
}

trait GuardianTerminalInput {
    fn read_input<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError>;
}

impl GuardianTerminalInput for TerminalEndpoint {
    fn read_input<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        self.read_into(buffer)
    }
}

impl GuardianTuiPumpIo for ReadyRemoteTui {
    fn read_output<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        self.read_terminal_output(buffer)
    }

    fn try_write_input(
        &self,
        chunk: &mut super::terminal::TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError> {
        self.try_write_terminal_input(chunk)
    }
}

/// Production guardian terminal generation. It owns only the guardian's
/// terminal-byte endpoint and the official TUI PTY. The coordinator remains
/// the sole owner of the outer tty, raw-mode gate, and shell anchor.
#[must_use = "terminal generation authority must be restored and disarmed"]
pub(super) struct TerminalGenerationOwner {
    tui: Option<TuiAuthority>,
    applied_terminal_size: Option<TerminalSize>,
    forwarded_shutdown: Option<ForwardedTuiSignal>,
    termination_cause: Option<SessionTerminationCause>,
    terminal: TerminalEndpoint,
    pump: TerminalPumpAuthority,
    recovery: Option<TerminalRecoveryAuthority>,
    snapshot: TerminalSnapshot,
}

enum TuiAuthority {
    Live(ReadyRemoteTui),
    Retained(Box<RemoteTuiShutdownFailure>),
    Reaped(ShutdownOutcome),
}

enum TerminalRecoveryAuthority {
    Armed {
        recovery: RecoveryTty,
        restoration_required: bool,
    },
    CoordinatorRestored {
        recovery: RecoveryTty,
        _proof: VerifiedTerminalRestoredCommand,
    },
    FallbackRestored {
        recovery: RecoveryTty,
        _proof: RestoredTerminalProof,
    },
    DisarmUnconfirmed {
        evidence: RecoveryDisarmUnconfirmed,
    },
    Disarmed {
        proof: RecoveryDisarmProof,
    },
}

impl TerminalGenerationOwner {
    pub(super) fn new(
        tui: ReadyRemoteTui,
        terminal: TerminalEndpoint,
        recovery: RecoveryTty,
        snapshot: TerminalSnapshot,
    ) -> Result<Self, Box<TerminalGenerationStartFailure>> {
        #[cfg(test)]
        observe_packaged_initial_size(tui.terminal_size_for_packaged_test());
        let validation = terminal
            .verify_invariants()
            .and_then(|()| recovery.verify_invariants())
            .and_then(|()| {
                if recovery.descriptor_identity() == snapshot.descriptor_identity() {
                    Ok(())
                } else {
                    Err(TerminalError::TerminalIdentityMismatch)
                }
            })
            .and_then(|()| terminal.enable_nonblocking())
            .and_then(|()| tui.enable_terminal_io());
        if let Err(error) = validation {
            return Err(Box::new(TerminalGenerationStartFailure {
                tui,
                terminal,
                recovery,
                snapshot,
                error,
            }));
        }
        Ok(Self {
            tui: Some(TuiAuthority::Live(tui)),
            applied_terminal_size: None,
            forwarded_shutdown: None,
            termination_cause: None,
            terminal,
            pump: TerminalPumpAuthority::OutputOnly(Box::new(OutputOnlyPump {
                output: TerminalBuffer::new(),
            })),
            recovery: Some(TerminalRecoveryAuthority::Armed {
                recovery,
                // After TERMINAL_ARM_ACCEPTED the coordinator may die anywhere
                // around flush/raw/open-gate. The guardian cannot prove which
                // mutation occurred, so exact idempotent restoration remains
                // conservatively required for the whole generation.
                restoration_required: true,
            }),
            snapshot,
        })
    }

    /// Creates the first and only initial input reader after the guardian's
    /// sequence validator accepts `OpenInputGate` in the initial READY cycle.
    fn open_initial_ingress(
        &mut self,
        proof: VerifiedInitialOpenGateCommand,
        deadline: Instant,
    ) -> Result<(), TerminalPumpFailure> {
        let _ = proof;
        self.discard_pending_terminal_input(deadline)?;
        let authority = std::mem::replace(
            &mut self.pump,
            TerminalPumpAuthority::Failed(TerminalPumpFailure::InvalidState),
        );
        match authority {
            TerminalPumpAuthority::OutputOnly(pump) => {
                let OutputOnlyPump { output } = *pump;
                self.pump = TerminalPumpAuthority::Duplex(Box::new(DuplexPump {
                    output,
                    input: TerminalBuffer::new(),
                }));
                #[cfg(test)]
                observe_packaged_gate("initial-gate.live");
                Ok(())
            }
            authority => {
                self.pump = authority;
                Err(TerminalPumpFailure::InvalidState)
            }
        }
    }

    /// Recreates input with a fresh buffer only after CONT, a fresh component
    /// liveness check, and a protocol-valid post-resume gate command.
    fn open_resumed_ingress(
        &mut self,
        proof: VerifiedResumeOpenGateCommand,
        deadline: Instant,
    ) -> Result<(), TerminalPumpFailure> {
        let _ = proof;
        self.discard_pending_terminal_input(deadline)?;
        let authority = std::mem::replace(
            &mut self.pump,
            TerminalPumpAuthority::Failed(TerminalPumpFailure::InvalidState),
        );
        match authority {
            TerminalPumpAuthority::Suspended(pump) if pump.resumed => {
                let SuspendedPump { output, resumed: _ } = *pump;
                self.pump = TerminalPumpAuthority::Duplex(Box::new(DuplexPump {
                    output,
                    input: TerminalBuffer::new(),
                }));
                #[cfg(test)]
                observe_packaged_gate("resume-gate.live");
                Ok(())
            }
            authority => {
                self.pump = authority;
                Err(TerminalPumpFailure::InvalidState)
            }
        }
    }

    fn ensure_tui_live(&mut self, deadline: Instant) -> Result<(), RemoteTuiLauncherError> {
        match self.tui.as_mut() {
            Some(TuiAuthority::Live(tui)) => tui.ensure_live(deadline),
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                Err(RemoteTuiLauncherError::NotLive)
            }
        }
    }

    /// Runs at most one fixed-buffer fragment in each direction. A partial
    /// write is completed synchronously or converted to a bounded fatal pump
    /// error; no transcript fragment can outlive this call.
    fn pump_once(
        &mut self,
        deadline: Instant,
    ) -> Result<TerminalPumpProgress, TerminalPumpFailure> {
        let tui = match self.tui.as_ref() {
            Some(TuiAuthority::Live(tui)) => tui,
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                return Err(TerminalPumpFailure::InvalidState);
            }
        };
        let result = pump_guardian_terminal_once(tui, &self.terminal, &mut self.pump, deadline);
        apply_guardian_pump_result(&mut self.pump, &mut self.termination_cause, result)
    }

    /// Irreversibly destroys active coordinator-to-TUI ingress authority while
    /// retaining the PTY output buffer for a bounded natural-exit drain. This is the
    /// only safe transition after a direct TUI exit or relay transport EOF:
    /// no stale-liveness input can be forwarded, yet macOS may still drain the
    /// PTY master so a controlling-terminal leader can finish `ttywait()`.
    fn begin_output_drain(&mut self) -> Result<(), TerminalPumpFailure> {
        begin_terminal_output_drain(&mut self.pump)
    }

    fn suspend(
        &mut self,
        graceful_deadline: Instant,
        forced_deadline: Instant,
    ) -> Result<(), TerminalPumpFailure> {
        let authority = std::mem::replace(
            &mut self.pump,
            TerminalPumpAuthority::Failed(TerminalPumpFailure::InvalidState),
        );
        match authority {
            TerminalPumpAuthority::Duplex(pump) => {
                let DuplexPump { output, input: _ } = *pump;
                // Dropping the sole input buffer is the synchronous ingress
                // barrier. It is recreated only by a later resume proof.
                self.pump = TerminalPumpAuthority::Suspended(Box::new(SuspendedPump {
                    output,
                    resumed: false,
                }));
            }
            authority => {
                self.pump = authority;
                return Err(TerminalPumpFailure::InvalidState);
            }
        }
        if let Err(error) = self.discard_pending_terminal_input(forced_deadline) {
            self.pump = TerminalPumpAuthority::Failed(error);
            return Err(error);
        }
        let tui = match self.tui.as_mut() {
            Some(TuiAuthority::Live(tui)) => tui,
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                self.pump = TerminalPumpAuthority::Failed(TerminalPumpFailure::InvalidState);
                return Err(TerminalPumpFailure::InvalidState);
            }
        };
        if tui
            .suspend_terminal(graceful_deadline, forced_deadline)
            .is_err()
        {
            self.pump = TerminalPumpAuthority::Failed(TerminalPumpFailure::Suspend);
            return Err(TerminalPumpFailure::Suspend);
        }
        #[cfg(test)]
        observe_packaged_suspend();
        Ok(())
    }

    fn resume_tui(
        &mut self,
        size: TerminalSize,
        deadline: Instant,
    ) -> Result<(), TerminalPumpFailure> {
        match &self.pump {
            TerminalPumpAuthority::Suspended(pump) if !pump.resumed => {}
            TerminalPumpAuthority::Failed(error) => return Err(*error),
            _ => return Err(TerminalPumpFailure::InvalidState),
        }
        let tui = match self.tui.as_mut() {
            Some(TuiAuthority::Live(tui)) => tui,
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                return Err(TerminalPumpFailure::InvalidState);
            }
        };
        if tui.resize_terminal(size, deadline).is_err() {
            self.pump = TerminalPumpAuthority::Failed(TerminalPumpFailure::Resize);
            return Err(TerminalPumpFailure::Resize);
        }
        if tui.resume_terminal(deadline).is_err() {
            self.pump = TerminalPumpAuthority::Failed(TerminalPumpFailure::Resume);
            return Err(TerminalPumpFailure::Resume);
        }
        self.applied_terminal_size = Some(size);
        let TerminalPumpAuthority::Suspended(pump) = &mut self.pump else {
            return Err(TerminalPumpFailure::InvalidState);
        };
        pump.resumed = true;
        #[cfg(test)]
        observe_packaged_resume(size);
        Ok(())
    }

    fn resize(&mut self, size: TerminalSize, deadline: Instant) -> Result<(), TerminalPumpFailure> {
        if !matches!(self.pump, TerminalPumpAuthority::Duplex(_)) {
            return Err(TerminalPumpFailure::InvalidState);
        }
        if !terminal_resize_requires_application(self.applied_terminal_size, size) {
            return Ok(());
        }
        let result = match self.tui.as_mut() {
            Some(TuiAuthority::Live(tui)) => tui
                .resize_terminal(size, deadline)
                .map_err(|_| TerminalPumpFailure::Resize),
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                Err(TerminalPumpFailure::InvalidState)
            }
        };
        if result.is_ok() {
            self.applied_terminal_size = Some(size);
            #[cfg(test)]
            observe_packaged_resize(size);
        }
        result
    }

    fn forward_signal(
        &mut self,
        signal: UnixSignal,
        deadline: Instant,
    ) -> Result<(), TerminalPumpFailure> {
        let suspended = matches!(self.pump, TerminalPumpAuthority::Suspended(_));
        if !matches!(self.pump, TerminalPumpAuthority::Duplex(_)) && !suspended
            || self.forwarded_shutdown.is_some()
        {
            return Err(TerminalPumpFailure::InvalidState);
        }
        let tui = match self.tui.as_mut() {
            Some(TuiAuthority::Live(tui)) => tui,
            Some(TuiAuthority::Retained(_) | TuiAuthority::Reaped(_)) | None => {
                return Err(TerminalPumpFailure::InvalidState);
            }
        };
        match signal {
            UnixSignal::Int | UnixSignal::Quit => {
                let Some(signal) = InteractiveTerminalSignal::from_unix_signal(signal) else {
                    return Err(TerminalPumpFailure::InvalidState);
                };
                tui.forward_interactive_signal(signal, deadline)
                    .map_err(|_| TerminalPumpFailure::Signal)
            }
            UnixSignal::Hup | UnixSignal::Term => {
                let signal = match signal {
                    UnixSignal::Hup => TerminalShutdownSignal::Hup,
                    UnixSignal::Term => TerminalShutdownSignal::Term,
                    UnixSignal::Int | UnixSignal::Quit => {
                        return Err(TerminalPumpFailure::InvalidState);
                    }
                };
                let forwarded = tui
                    .forward_shutdown_signal(signal, deadline)
                    .map_err(|_| TerminalPumpFailure::Signal)?;
                if suspended {
                    tui.continue_after_forwarded_shutdown(&forwarded, deadline)
                        .map_err(|_| TerminalPumpFailure::Signal)?;
                }
                self.termination_cause = Some(match forwarded.signal() {
                    TerminalShutdownSignal::Hup => SessionTerminationCause::ForwardedHup,
                    TerminalShutdownSignal::Term => SessionTerminationCause::ForwardedTerm,
                });
                self.forwarded_shutdown = Some(forwarded);
                Ok(())
            }
        }
    }

    fn accept_termination_cause(
        &mut self,
        cause: SessionTerminationCause,
    ) -> Result<(), TerminalPumpFailure> {
        match (self.termination_cause, cause) {
            (None, SessionTerminationCause::CoordinatorStop) => {
                self.termination_cause = Some(cause);
                Ok(())
            }
            (Some(observed), supplied) if observed == supplied => Ok(()),
            _ => Err(TerminalPumpFailure::InvalidState),
        }
    }

    fn discard_pending_terminal_input(&self, deadline: Instant) -> Result<(), TerminalPumpFailure> {
        discard_terminal_input_before(&self.terminal, deadline)
    }

    fn quiesce(&mut self) -> ShutdownStep {
        self.pump = TerminalPumpAuthority::Quiesced;
        match self.terminal.shutdown(TerminalShutdown::Both) {
            Ok(()) => ShutdownStep::advanced(),
            Err(_) => ShutdownStep::retained(None, Some(SessionCleanupError::Quiesce)),
        }
    }

    fn shutdown_tui(&mut self, bounds: SessionShutdownBounds) -> ShutdownStep {
        let Some(authority) = self.tui.take() else {
            return ShutdownStep::retained(None, Some(SessionCleanupError::MissingAuthority));
        };
        match authority {
            TuiAuthority::Live(tui) => match self.forwarded_shutdown.take() {
                Some(forwarded) => match tui.shutdown_after_forwarded_signal(
                    forwarded,
                    bounds.tui_grace,
                    bounds.tui_forced,
                ) {
                    Ok(outcome) => {
                        self.tui = Some(TuiAuthority::Reaped(outcome));
                        ShutdownStep::advanced()
                    }
                    Err(failure) => {
                        self.tui = Some(TuiAuthority::Retained(failure));
                        ShutdownStep::retained(None, Some(SessionCleanupError::Tui))
                    }
                },
                None if self.termination_cause == Some(SessionTerminationCause::NaturalTuiEof) => {
                    match tui.shutdown_after_output_eof(bounds.tui_grace, bounds.tui_forced) {
                        Ok(outcome) => {
                            self.tui = Some(TuiAuthority::Reaped(outcome));
                            ShutdownStep::advanced()
                        }
                        Err(failure) => {
                            self.tui = Some(TuiAuthority::Retained(failure));
                            ShutdownStep::retained(None, Some(SessionCleanupError::Tui))
                        }
                    }
                }
                None => match tui.shutdown(bounds.tui_grace, bounds.tui_forced) {
                    Ok(outcome) => {
                        self.tui = Some(TuiAuthority::Reaped(outcome));
                        ShutdownStep::advanced()
                    }
                    Err(failure) => {
                        self.tui = Some(TuiAuthority::Retained(failure));
                        ShutdownStep::retained(None, Some(SessionCleanupError::Tui))
                    }
                },
            },
            TuiAuthority::Retained(failure) => {
                match failure.retry(bounds.tui_grace, bounds.tui_forced) {
                    Ok(outcome) => {
                        self.tui = Some(TuiAuthority::Reaped(outcome));
                        ShutdownStep::advanced()
                    }
                    Err(failure) => {
                        self.tui = Some(TuiAuthority::Retained(failure));
                        ShutdownStep::retained(None, Some(SessionCleanupError::Tui))
                    }
                }
            }
            authority @ TuiAuthority::Reaped(_) => {
                self.tui = Some(authority);
                ShutdownStep::advanced()
            }
        }
    }

    fn await_coordinator_restore(&mut self) -> ShutdownStep {
        if !matches!(self.pump, TerminalPumpAuthority::Quiesced)
            || !matches!(self.tui, Some(TuiAuthority::Reaped(_)))
        {
            return ShutdownStep::retained(None, Some(SessionCleanupError::TerminalRestore));
        }
        match self.recovery {
            Some(
                TerminalRecoveryAuthority::CoordinatorRestored { .. }
                | TerminalRecoveryAuthority::FallbackRestored { .. }
                | TerminalRecoveryAuthority::DisarmUnconfirmed { .. }
                | TerminalRecoveryAuthority::Disarmed { .. },
            ) => ShutdownStep::advanced(),
            // Waiting for the coordinator's protocol proof is a normal
            // lifecycle barrier, not a cleanup error.
            Some(TerminalRecoveryAuthority::Armed { .. }) => ShutdownStep::retained(None, None),
            None => ShutdownStep::retained(None, Some(SessionCleanupError::MissingAuthority)),
        }
    }

    fn acknowledge_coordinator_restore(
        &mut self,
        proof: VerifiedTerminalRestoredCommand,
    ) -> Result<(), VerifiedTerminalRestoredCommand> {
        let Some(authority) = self.recovery.take() else {
            return Err(proof);
        };
        match authority {
            TerminalRecoveryAuthority::Armed { recovery, .. }
                if matches!(self.pump, TerminalPumpAuthority::Quiesced)
                    && matches!(self.tui, Some(TuiAuthority::Reaped(_))) =>
            {
                self.recovery = Some(TerminalRecoveryAuthority::CoordinatorRestored {
                    recovery,
                    _proof: proof,
                });
                Ok(())
            }
            authority => {
                self.recovery = Some(authority);
                Err(proof)
            }
        }
    }

    fn restore_after_lifecycle_loss(&mut self) -> ShutdownStep {
        let Some(authority) = self.recovery.take() else {
            return ShutdownStep::retained(None, Some(SessionCleanupError::MissingAuthority));
        };
        match authority {
            TerminalRecoveryAuthority::Armed {
                recovery,
                restoration_required: true,
            } => match recovery.restore_with_sigttou_block(&self.snapshot) {
                Ok(proof) => {
                    self.recovery = Some(TerminalRecoveryAuthority::FallbackRestored {
                        recovery,
                        _proof: proof,
                    });
                    ShutdownStep::advanced()
                }
                Err(_) => {
                    self.recovery = Some(TerminalRecoveryAuthority::Armed {
                        recovery,
                        restoration_required: true,
                    });
                    ShutdownStep::retained(None, Some(SessionCleanupError::TerminalRestore))
                }
            },
            authority @ (TerminalRecoveryAuthority::CoordinatorRestored { .. }
            | TerminalRecoveryAuthority::FallbackRestored { .. }
            | TerminalRecoveryAuthority::DisarmUnconfirmed { .. }
            | TerminalRecoveryAuthority::Disarmed { .. }) => {
                self.recovery = Some(authority);
                ShutdownStep::advanced()
            }
            TerminalRecoveryAuthority::Armed {
                recovery,
                restoration_required: false,
            } => {
                self.recovery = Some(TerminalRecoveryAuthority::Armed {
                    recovery,
                    restoration_required: false,
                });
                ShutdownStep::retained(None, Some(SessionCleanupError::TerminalRestore))
            }
        }
    }

    fn disarm_recovery(&mut self) -> ShutdownStep {
        let Some(authority) = self.recovery.take() else {
            return ShutdownStep::retained(None, Some(SessionCleanupError::MissingAuthority));
        };
        match authority {
            TerminalRecoveryAuthority::CoordinatorRestored { recovery, _proof } => {
                match recovery.disarm() {
                    Ok(RecoveryDisarmOutcome::Disarmed(proof)) => {
                        self.recovery = Some(TerminalRecoveryAuthority::Disarmed { proof });
                        ShutdownStep::advanced()
                    }
                    Ok(RecoveryDisarmOutcome::Unconfirmed(evidence)) => {
                        self.recovery =
                            Some(TerminalRecoveryAuthority::DisarmUnconfirmed { evidence });
                        ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
                    }
                    Err(failure) => {
                        self.recovery = Some(TerminalRecoveryAuthority::CoordinatorRestored {
                            recovery: failure.into_recovery(),
                            _proof,
                        });
                        ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
                    }
                }
            }
            TerminalRecoveryAuthority::FallbackRestored { recovery, _proof } => {
                match recovery.disarm() {
                    Ok(RecoveryDisarmOutcome::Disarmed(proof)) => {
                        self.recovery = Some(TerminalRecoveryAuthority::Disarmed { proof });
                        ShutdownStep::advanced()
                    }
                    Ok(RecoveryDisarmOutcome::Unconfirmed(evidence)) => {
                        self.recovery =
                            Some(TerminalRecoveryAuthority::DisarmUnconfirmed { evidence });
                        ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
                    }
                    Err(failure) => {
                        self.recovery = Some(TerminalRecoveryAuthority::FallbackRestored {
                            recovery: failure.into_recovery(),
                            _proof,
                        });
                        ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
                    }
                }
            }
            TerminalRecoveryAuthority::DisarmUnconfirmed { evidence } => {
                match evidence.retry_once() {
                    RecoveryDisarmOutcome::Disarmed(proof) => {
                        self.recovery = Some(TerminalRecoveryAuthority::Disarmed { proof });
                        ShutdownStep::advanced()
                    }
                    RecoveryDisarmOutcome::Unconfirmed(evidence) => {
                        self.recovery =
                            Some(TerminalRecoveryAuthority::DisarmUnconfirmed { evidence });
                        ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
                    }
                }
            }
            authority @ TerminalRecoveryAuthority::Disarmed { .. } => {
                self.recovery = Some(authority);
                ShutdownStep::advanced()
            }
            authority => {
                self.recovery = Some(authority);
                ShutdownStep::retained(None, Some(SessionCleanupError::RecoveryDisarm))
            }
        }
    }

    /// Consumes the terminal-generation owner only after the ordered shutdown
    /// reached its final state. In particular, the recovery-disarm proof is
    /// bound and consumed here instead of becoming an unread field that could
    /// be dropped accidentally by a future report conversion.
    fn into_final_outcome(self) -> (Option<ShutdownOutcome>, Option<SessionTerminationCause>) {
        let Self {
            tui,
            applied_terminal_size: _,
            forwarded_shutdown,
            termination_cause,
            terminal,
            pump,
            recovery,
            snapshot,
        } = self;
        let tui_outcome = match tui {
            Some(TuiAuthority::Reaped(outcome)) => Some(outcome),
            Some(TuiAuthority::Live(_) | TuiAuthority::Retained(_)) | None => std::process::abort(),
        };
        match pump {
            TerminalPumpAuthority::Quiesced => {}
            TerminalPumpAuthority::OutputOnly(_)
            | TerminalPumpAuthority::Duplex(_)
            | TerminalPumpAuthority::Suspended(_)
            | TerminalPumpAuthority::OutputClosed
            | TerminalPumpAuthority::Failed(_) => std::process::abort(),
        }
        match recovery {
            Some(TerminalRecoveryAuthority::Disarmed { proof }) => drop(proof),
            Some(
                TerminalRecoveryAuthority::Armed { .. }
                | TerminalRecoveryAuthority::CoordinatorRestored { .. }
                | TerminalRecoveryAuthority::FallbackRestored { .. }
                | TerminalRecoveryAuthority::DisarmUnconfirmed { .. },
            )
            | None => std::process::abort(),
        }
        drop((forwarded_shutdown, terminal, snapshot));
        (tui_outcome, termination_cause)
    }
}

/// Pre-pump construction failure retaining every consumed terminal authority.
#[must_use = "terminal start failure retains TUI, channel, and recovery owners"]
pub(super) struct TerminalGenerationStartFailure {
    tui: ReadyRemoteTui,
    terminal: TerminalEndpoint,
    recovery: RecoveryTty,
    snapshot: TerminalSnapshot,
    error: TerminalError,
}

impl TerminalGenerationStartFailure {
    pub(super) const fn error(&self) -> TerminalError {
        self.error
    }

    pub(super) fn into_parts(
        self: Box<Self>,
    ) -> (
        ReadyRemoteTui,
        TerminalEndpoint,
        RecoveryTty,
        TerminalSnapshot,
    ) {
        let Self {
            tui,
            terminal,
            recovery,
            snapshot,
            error: _,
        } = *self;
        (tui, terminal, recovery, snapshot)
    }
}

impl fmt::Debug for TerminalGenerationStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.tui, &self.terminal, &self.recovery, &self.snapshot);
        formatter
            .debug_struct("TerminalGenerationStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

fn pump_guardian_terminal_once<Tui: GuardianTuiPumpIo>(
    tui: &Tui,
    terminal: &TerminalEndpoint,
    pump: &mut TerminalPumpAuthority,
    deadline: Instant,
) -> Result<TerminalPumpProgress, TerminalPumpFailure> {
    let output = match pump {
        TerminalPumpAuthority::OutputOnly(pump) => &mut pump.output,
        TerminalPumpAuthority::Duplex(pump) => &mut pump.output,
        TerminalPumpAuthority::Suspended(pump) => &mut pump.output,
        TerminalPumpAuthority::OutputClosed => {
            return Ok(TerminalPumpProgress::TuiOutputClosed);
        }
        TerminalPumpAuthority::Quiesced => return Ok(TerminalPumpProgress::Idle),
        TerminalPumpAuthority::Failed(error) => return Err(*error),
    };
    let output_progress = match tui
        .read_output(output)
        .map_err(|_| TerminalPumpFailure::TuiRead)?
    {
        TerminalRead::Data(mut chunk) => {
            #[cfg(test)]
            let pending_output =
                prepare_packaged_output_observation(chunk.remaining_bytes_for_test());
            write_fragment_before(deadline, &mut chunk, |chunk| {
                #[cfg(test)]
                if PACKAGED_FAIL_NEXT_TERMINAL_CHANNEL_WRITE.swap(false, Ordering::SeqCst) {
                    return Err(TerminalPumpFailure::TerminalChannelWrite);
                }
                terminal
                    .try_write(chunk)
                    .map_err(|_| TerminalPumpFailure::TerminalChannelWrite)
            })?;
            #[cfg(test)]
            commit_packaged_output_observation(pending_output);
            true
        }
        TerminalRead::WouldBlock => false,
        TerminalRead::EndOfStream => return Err(TerminalPumpFailure::TuiOutputEof),
    };

    let input_progress = match pump {
        TerminalPumpAuthority::Duplex(pump) => match terminal
            .read_into(&mut pump.input)
            .map_err(|_| TerminalPumpFailure::TerminalChannelRead)?
        {
            TerminalRead::Data(mut chunk) => {
                #[cfg(test)]
                let pending_input =
                    prepare_packaged_input_observation(chunk.remaining_bytes_for_test());
                write_fragment_before(deadline, &mut chunk, |chunk| {
                    tui.try_write_input(chunk)
                        .map_err(|_| TerminalPumpFailure::TuiWrite)
                })?;
                #[cfg(test)]
                commit_packaged_input_observation(pending_input);
                true
            }
            TerminalRead::WouldBlock => false,
            TerminalRead::EndOfStream => return Err(TerminalPumpFailure::TerminalChannelEof),
        },
        TerminalPumpAuthority::OutputOnly(_)
        | TerminalPumpAuthority::Suspended(_)
        | TerminalPumpAuthority::OutputClosed
        | TerminalPumpAuthority::Quiesced => false,
        TerminalPumpAuthority::Failed(error) => return Err(*error),
    };

    Ok(match (output_progress, input_progress) {
        (false, false) => TerminalPumpProgress::Idle,
        (true, false) => TerminalPumpProgress::Output,
        (false, true) => TerminalPumpProgress::Input,
        (true, true) => TerminalPumpProgress::Duplex,
    })
}

fn begin_terminal_output_drain(
    authority_slot: &mut TerminalPumpAuthority,
) -> Result<(), TerminalPumpFailure> {
    if !matches!(authority_slot, TerminalPumpAuthority::Duplex(_)) {
        return Err(TerminalPumpFailure::InvalidState);
    }
    let authority = std::mem::replace(
        authority_slot,
        TerminalPumpAuthority::Failed(TerminalPumpFailure::InvalidState),
    );
    match authority {
        TerminalPumpAuthority::Duplex(duplex) => {
            let DuplexPump { output, input: _ } = *duplex;
            *authority_slot =
                TerminalPumpAuthority::OutputOnly(Box::new(OutputOnlyPump { output }));
            Ok(())
        }
        authority => {
            *authority_slot = authority;
            Err(TerminalPumpFailure::InvalidState)
        }
    }
}

fn apply_guardian_pump_result(
    pump: &mut TerminalPumpAuthority,
    termination_cause: &mut Option<SessionTerminationCause>,
    result: Result<TerminalPumpProgress, TerminalPumpFailure>,
) -> Result<TerminalPumpProgress, TerminalPumpFailure> {
    match result {
        Ok(progress) => Ok(progress),
        Err(TerminalPumpFailure::TuiOutputEof) => {
            // PTY EOF is the TUI's normal completion edge. Destroy any live
            // input capability immediately, but retain exact child wait
            // authority so disposition can distinguish exit 0 from a crash,
            // unexpected signal, or forced containment.
            *pump = TerminalPumpAuthority::OutputClosed;
            *termination_cause = Some(SessionTerminationCause::NaturalTuiEof);
            Ok(TerminalPumpProgress::TuiOutputClosed)
        }
        Err(error) => {
            *pump = TerminalPumpAuthority::Failed(error);
            Err(error)
        }
    }
}

/// Discards terminal-channel input that was queued before a newly accepted
/// input-gate generation. The fixed fragment budget prevents an untrusted or
/// stale coordinator peer from extending this barrier indefinitely by
/// continuously flooding the socket.
fn discard_terminal_input_before<Terminal: GuardianTerminalInput>(
    terminal: &Terminal,
    deadline: Instant,
) -> Result<(), TerminalPumpFailure> {
    let mut discard = TerminalBuffer::new();
    for _ in 0..TERMINAL_DISCARD_MAX_FRAGMENTS {
        if Instant::now() >= deadline {
            return Err(TerminalPumpFailure::Deadline);
        }
        match terminal
            .read_input(&mut discard)
            .map_err(|_| TerminalPumpFailure::TerminalChannelRead)?
        {
            TerminalRead::Data(chunk) => drop(chunk),
            TerminalRead::WouldBlock => return Ok(()),
            TerminalRead::EndOfStream => return Err(TerminalPumpFailure::TerminalChannelEof),
        }
    }
    Err(TerminalPumpFailure::Deadline)
}

fn write_fragment_before(
    deadline: Instant,
    chunk: &mut super::terminal::TerminalChunk<'_>,
    mut write: impl FnMut(
        &mut super::terminal::TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalPumpFailure>,
) -> Result<(), TerminalPumpFailure> {
    while chunk.remaining() != 0 {
        if Instant::now() >= deadline {
            return Err(TerminalPumpFailure::Deadline);
        }
        match write(chunk)? {
            TerminalWrite::Complete => return Ok(()),
            TerminalWrite::Progress { .. } => {}
            TerminalWrite::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(TerminalPumpFailure::Deadline);
                }
                thread::sleep(TERMINAL_PUMP_RETRY.min(remaining));
            }
        }
    }
    Ok(())
}

impl fmt::Debug for TerminalGenerationOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.tui, &self.terminal, &self.recovery, &self.snapshot);
        formatter.write_str("TerminalGenerationOwner(<redacted>)")
    }
}

/// Minimal liveness surface shared by the concrete aggregate and deterministic
/// fault tests. It intentionally has no provider command or message method.
pub(super) trait LiveSessionComponents {
    fn ensure_monitor_and_app_live(
        &mut self,
        deadline: Instant,
    ) -> Result<(), SessionLivenessError>;

    fn ensure_relay_live(&mut self, deadline: Instant) -> Result<(), SessionLivenessError>;

    fn ensure_tui_live(&mut self, deadline: Instant) -> Result<(), SessionLivenessError>;
}

/// Runs one uncached observation in the normative App/monitor -> relay -> TUI
/// order. Every gate transition below calls this function independently.
fn check_all_live<C: LiveSessionComponents>(
    components: &mut C,
    deadline: Instant,
) -> Result<(), SessionLivenessError> {
    if Instant::now() >= deadline {
        return Err(SessionLivenessError::operation(
            SessionOperationError::Deadline,
        ));
    }
    components.ensure_monitor_and_app_live(deadline)?;
    if Instant::now() >= deadline {
        return Err(SessionLivenessError::operation(
            SessionOperationError::Deadline,
        ));
    }
    components.ensure_relay_live(deadline)?;
    if Instant::now() >= deadline {
        return Err(SessionLivenessError::operation(
            SessionOperationError::Deadline,
        ));
    }
    components.ensure_tui_live(deadline)
}

fn relay_shutdown_operation_error(
    termination_cause: Option<SessionTerminationCause>,
    error: Option<ReadinessProxyError>,
) -> Option<SessionOperationError> {
    match error {
        Some(ReadinessProxyError::Transport)
            if termination_cause == Some(SessionTerminationCause::NaturalTuiEof) =>
        {
            None
        }
        Some(_) => Some(SessionOperationError::Component(
            SessionComponent::ReadinessRelay,
        )),
        None => None,
    }
}

#[derive(Debug)]
pub(super) enum AwaitingReady {}
#[derive(Debug)]
pub(super) enum ReadyToOpenGate {}
#[derive(Debug)]
pub(super) enum ActiveIngress {}
#[derive(Debug)]
pub(super) enum DrainingTerminalExit {}
#[derive(Debug)]
pub(super) enum SuspendedIngress {}
#[derive(Debug)]
pub(super) enum ResumedAwaitingGate {}

/// One linear supervised session at a typed lifecycle checkpoint.
#[must_use = "a supervised session must be advanced or explicitly shut down"]
#[derive(Debug)]
pub(super) struct SessionState<Components, State> {
    components: Components,
    _state: PhantomData<State>,
}

impl<Components, State> SessionState<Components, State> {
    fn transition<Next>(self) -> SessionState<Components, Next> {
        SessionState {
            components: self.components,
            _state: PhantomData,
        }
    }
}

/// A failed checkpoint returns the exact prior state, so infrastructure loss
/// cannot drop child, worker, PTY, runtime, or lease authority.
#[must_use = "a liveness failure retains the complete supervised session"]
#[derive(Debug)]
pub(super) struct SessionLivenessFailure<Session> {
    session: Session,
    error: SessionLivenessError,
}

impl<Session> SessionLivenessFailure<Session> {
    pub(super) const fn error(&self) -> SessionOperationError {
        self.error.operation
    }

    pub(super) fn into_session(self) -> Session {
        self.session
    }

    pub(super) const fn is_direct_tui_exit(&self) -> bool {
        self.error.tui_exited
    }
}

impl<Components: LiveSessionComponents, State>
    SessionLivenessFailure<SessionState<Components, State>>
{
    /// Consumes only an exact post-readiness relay transport failure. The
    /// caller must immediately destroy ingress and drain PTY output; polling
    /// direct-child status here would deadlock Darwin's `ttywait()` ordering.
    pub(super) fn into_relay_transport_session(
        self: Box<Self>,
    ) -> Result<SessionState<Components, State>, Box<Self>> {
        if !self.error.relay_transport {
            return Err(self);
        }
        Ok(self.session)
    }
}

type AwaitingReadyLivenessFailure<Components> =
    Box<SessionLivenessFailure<SessionState<Components, AwaitingReady>>>;

impl<Components: LiveSessionComponents> SessionState<Components, AwaitingReady> {
    pub(super) fn check_before_ready(
        mut self,
        deadline: Instant,
    ) -> Result<SessionState<Components, ReadyToOpenGate>, AwaitingReadyLivenessFailure<Components>>
    {
        match check_all_live(&mut self.components, deadline) {
            Ok(()) => Ok(self.transition()),
            Err(error) => Err(Box::new(SessionLivenessFailure {
                session: self,
                error,
            })),
        }
    }
}

/// Same-profile guardian admission that mints B directly under the
/// coordinator's already-held A. This is the production path for Slice 3;
/// cross-profile handoff continues to use descriptor transfer and ACK.
pub(super) fn admit_same_profile_guardian_session(
    registry: &Registry,
    expected_profile: &Profile,
    working_directory: &Path,
    thread_id: &str,
) -> Result<GuardianSessionAuthority, Box<SameProfileAdmissionFailure>> {
    let guardian_lease = registry
        .lock_profile_guardian_current(expected_profile)
        .map_err(|error| Box::new(SameProfileAdmissionFailure::Profile(error)))?;
    admit_guardian_session(guardian_lease, registry, working_directory, thread_id)
        .map_err(|failure| Box::new(SameProfileAdmissionFailure::Provider(failure)))
}

/// Admission failure either owns no B or retains the exact provisional B in
/// the provider failure owner. Debug output remains fixed and redacted.
#[must_use = "provider admission failure can retain the guardian lease"]
pub(super) enum SameProfileAdmissionFailure {
    Profile(ProfileError),
    Provider(Box<GuardianSessionAdmissionFailure>),
}

impl SameProfileAdmissionFailure {
    pub(super) fn provider_error(&self) -> Option<ProviderLaunchError> {
        match self {
            Self::Profile(_) => None,
            Self::Provider(failure) => Some(failure.error()),
        }
    }
}

impl fmt::Debug for SameProfileAdmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SameProfileAdmissionFailure")
            .field(
                "kind",
                &match self {
                    Self::Profile(_) => "profile",
                    Self::Provider(_) => "provider",
                },
            )
            .field("provider_error", &self.provider_error())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SameProfileAdmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => error.fmt(formatter),
            Self::Provider(failure) => failure.fmt(formatter),
        }
    }
}

impl std::error::Error for SameProfileAdmissionFailure {}

/// The cleanup boundary whose exact authority could not yet be discharged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum SessionCleanupError {
    Quiesce = 1 << 0,
    Tui = 1 << 1,
    ReadinessRelay = 1 << 2,
    Monitor = 1 << 3,
    AppServer = 1 << 4,
    TerminalRestore = 1 << 5,
    RecoveryDisarm = 1 << 6,
    Runtime = 1 << 7,
    PinnedBuild = 1 << 8,
    MissingAuthority = 1 << 9,
}

/// Bounded set of every cleanup phase that failed at least once. Repeated
/// retries at the same phase coalesce, while failures at later phases remain
/// visible in the final proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct SessionCleanupErrors(u16);

impl SessionCleanupErrors {
    #[cfg(test)]
    pub(super) const fn contains(self, error: SessionCleanupError) -> bool {
        self.0 & error as u16 != 0
    }

    pub(super) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn insert(&mut self, error: Option<SessionCleanupError>) {
        if let Some(error) = error {
            self.0 |= error as u16;
        }
    }
}

/// Independent first-error slots. A later cleanup success never turns an
/// earlier infrastructure failure into a successful TUI disposition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SessionErrors {
    operation: Option<SessionOperationError>,
    cleanup: SessionCleanupErrors,
}

impl SessionErrors {
    fn record_operation(&mut self, error: Option<SessionOperationError>) {
        if self.operation.is_none() {
            self.operation = error;
        }
    }

    fn record_cleanup(&mut self, error: Option<SessionCleanupError>) {
        self.cleanup.insert(error);
    }
}

/// Relative shutdown bounds are supplied together so each sequential phase
/// arms its own absolute deadline when that phase actually begins. A retry
/// therefore receives the full configured budget for only its retained edge,
/// never an expired deadline inherited from earlier cleanup work.
#[derive(Clone, Copy)]
pub(super) struct SessionShutdownBounds {
    pub(super) tui_grace: Duration,
    pub(super) tui_forced: Duration,
    pub(super) relay_timeout: Duration,
    pub(super) monitor_timeout: Duration,
    pub(super) app_grace: Duration,
    pub(super) app_forced: Duration,
    pub(super) app_cleanup_timeout: Duration,
    pub(super) build_cleanup_timeout: Duration,
}

impl SessionShutdownBounds {
    fn deadline_at(now: Instant, timeout: Duration) -> Instant {
        // An unrepresentable deadline must already be expired. Returning the
        // phase start preserves the linear owner while forcing the bounded
        // operation down its existing fail-closed timeout path.
        now.checked_add(timeout).unwrap_or(now)
    }

    pub(super) fn relay_deadline(self) -> Instant {
        self.relay_deadline_at(Instant::now())
    }

    pub(super) fn monitor_deadline(self) -> Instant {
        self.monitor_deadline_at(Instant::now())
    }

    pub(super) fn app_cleanup_deadline(self) -> Instant {
        self.app_cleanup_deadline_at(Instant::now())
    }

    pub(super) fn build_cleanup_deadline(self) -> Instant {
        self.build_cleanup_deadline_at(Instant::now())
    }

    fn relay_deadline_at(self, now: Instant) -> Instant {
        Self::deadline_at(now, self.relay_timeout)
    }

    fn monitor_deadline_at(self, now: Instant) -> Instant {
        Self::deadline_at(now, self.monitor_timeout)
    }

    fn app_cleanup_deadline_at(self, now: Instant) -> Instant {
        Self::deadline_at(now, self.app_cleanup_timeout)
    }

    fn build_cleanup_deadline_at(self, now: Instant) -> Instant {
        Self::deadline_at(now, self.build_cleanup_timeout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownPhase {
    Quiesce,
    Tui,
    ReadinessRelay,
    Monitor,
    AppServerStop,
    TerminalRestore,
    RecoveryDisarm,
    RuntimeCleanup,
    PinnedBuild,
    Complete,
}

/// The only three legal retained-session recovery entry points. This closed
/// projection prevents a retry from skipping coordinator-owned terminal
/// restoration or re-entering it after recovery was already disarmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionShutdownRecoveryStage {
    Quiescing,
    RestorePending,
    CleanupPending,
}

/// Closed, payload-free selector for deterministic retained-session tests.
/// The cause path still executes the production termination-cause validator;
/// the failure path carries only an already-typed operation error.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionShutdownTestTrigger {
    Cause(SessionTerminationCause),
    Failure(SessionOperationError),
}

#[cfg(test)]
fn apply_session_shutdown_test_trigger(
    trigger: SessionShutdownTestTrigger,
    mut accept_cause: impl FnMut(SessionTerminationCause) -> Result<(), TerminalPumpFailure>,
) -> Option<SessionOperationError> {
    match trigger {
        SessionShutdownTestTrigger::Cause(cause) => accept_cause(cause)
            .err()
            .map(SessionOperationError::TerminalPump),
        SessionShutdownTestTrigger::Failure(error) => Some(error),
    }
}

const fn session_shutdown_recovery_stage(phase: ShutdownPhase) -> SessionShutdownRecoveryStage {
    match phase {
        ShutdownPhase::Quiesce
        | ShutdownPhase::Tui
        | ShutdownPhase::ReadinessRelay
        | ShutdownPhase::Monitor
        | ShutdownPhase::AppServerStop => SessionShutdownRecoveryStage::Quiescing,
        ShutdownPhase::TerminalRestore => SessionShutdownRecoveryStage::RestorePending,
        ShutdownPhase::RecoveryDisarm
        | ShutdownPhase::RuntimeCleanup
        | ShutdownPhase::PinnedBuild
        | ShutdownPhase::Complete => SessionShutdownRecoveryStage::CleanupPending,
    }
}

impl ShutdownPhase {
    const fn next(self) -> Self {
        match self {
            Self::Quiesce => Self::Tui,
            Self::Tui => Self::ReadinessRelay,
            Self::ReadinessRelay => Self::Monitor,
            Self::Monitor => Self::AppServerStop,
            Self::AppServerStop => Self::TerminalRestore,
            Self::TerminalRestore => Self::RecoveryDisarm,
            Self::RecoveryDisarm => Self::RuntimeCleanup,
            Self::RuntimeCleanup => Self::PinnedBuild,
            Self::PinnedBuild | Self::Complete => Self::Complete,
        }
    }
}

#[cfg(test)]
const fn packaged_session_shutdown_phase_marker(phase: ShutdownPhase) -> &'static str {
    match phase {
        ShutdownPhase::Quiesce => "guardian-retained.session-phase.quiesce",
        ShutdownPhase::Tui => "guardian-retained.session-phase.tui",
        ShutdownPhase::ReadinessRelay => "guardian-retained.session-phase.readiness-relay",
        ShutdownPhase::Monitor => "guardian-retained.session-phase.monitor",
        ShutdownPhase::AppServerStop => "guardian-retained.session-phase.app-server-stop",
        ShutdownPhase::TerminalRestore => "guardian-retained.session-phase.terminal-restore",
        ShutdownPhase::RecoveryDisarm => "guardian-retained.session-phase.recovery-disarm",
        ShutdownPhase::RuntimeCleanup => "guardian-retained.session-phase.runtime-cleanup",
        ShutdownPhase::PinnedBuild => "guardian-retained.session-phase.pinned-build",
        ShutdownPhase::Complete => "guardian-retained.session-phase.complete",
    }
}

#[cfg(test)]
const fn packaged_session_operation_marker(error: Option<SessionOperationError>) -> &'static str {
    match error {
        None => "guardian-retained.session-operation.none",
        Some(SessionOperationError::RecoveryRequested) => {
            "guardian-retained.session-operation.recovery-requested"
        }
        Some(SessionOperationError::Deadline) => "guardian-retained.session-operation.deadline",
        Some(SessionOperationError::Monitor(SessionMonitorError::InvalidArgument)) => {
            "guardian-retained.session-operation.monitor-invalid-argument"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Handshake)) => {
            "guardian-retained.session-operation.monitor-handshake"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Protocol)) => {
            "guardian-retained.session-operation.monitor-protocol"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Authentication)) => {
            "guardian-retained.session-operation.monitor-authentication"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Provider)) => {
            "guardian-retained.session-operation.monitor-provider"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Unsupported)) => {
            "guardian-retained.session-operation.monitor-unsupported"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Timeout)) => {
            "guardian-retained.session-operation.monitor-timeout"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Transport)) => {
            "guardian-retained.session-operation.monitor-transport"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::Worker)) => {
            "guardian-retained.session-operation.monitor-worker"
        }
        Some(SessionOperationError::Monitor(SessionMonitorError::AppServer)) => {
            "guardian-retained.session-operation.monitor-app-server"
        }
        Some(SessionOperationError::Component(SessionComponent::MonitorAndApp)) => {
            "guardian-retained.session-operation.component-monitor-app"
        }
        Some(SessionOperationError::Component(SessionComponent::ReadinessRelay)) => {
            "guardian-retained.session-operation.component-readiness-relay"
        }
        Some(SessionOperationError::Component(SessionComponent::Tui)) => {
            "guardian-retained.session-operation.component-tui"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Deadline)) => {
            "guardian-retained.session-operation.pump-deadline"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::InvalidState)) => {
            "guardian-retained.session-operation.pump-invalid-state"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiOutputEof)) => {
            "guardian-retained.session-operation.pump-tui-output-eof"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelEof)) => {
            "guardian-retained.session-operation.pump-terminal-channel-eof"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiRead)) => {
            "guardian-retained.session-operation.pump-tui-read"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TuiWrite)) => {
            "guardian-retained.session-operation.pump-tui-write"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelRead)) => {
            "guardian-retained.session-operation.pump-terminal-channel-read"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::TerminalChannelWrite)) => {
            "guardian-retained.session-operation.pump-terminal-channel-write"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Signal)) => {
            "guardian-retained.session-operation.pump-signal"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Resize)) => {
            "guardian-retained.session-operation.pump-resize"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Suspend)) => {
            "guardian-retained.session-operation.pump-suspend"
        }
        Some(SessionOperationError::TerminalPump(TerminalPumpFailure::Resume)) => {
            "guardian-retained.session-operation.pump-resume"
        }
    }
}

#[cfg(test)]
const fn packaged_session_termination_cause_marker(
    cause: Option<SessionTerminationCause>,
) -> &'static str {
    match cause {
        None => "guardian-retained.termination-cause.none",
        Some(SessionTerminationCause::NaturalTuiEof) => {
            "guardian-retained.termination-cause.natural-tui-eof"
        }
        Some(SessionTerminationCause::CoordinatorStop) => {
            "guardian-retained.termination-cause.coordinator-stop"
        }
        Some(SessionTerminationCause::ForwardedHup) => {
            "guardian-retained.termination-cause.forwarded-hup"
        }
        Some(SessionTerminationCause::ForwardedTerm) => {
            "guardian-retained.termination-cause.forwarded-term"
        }
    }
}

#[cfg(test)]
const fn packaged_session_tui_disposition_marker(
    disposition: Option<ChildDisposition>,
) -> &'static str {
    match disposition {
        None | Some(ChildDisposition::NotStarted) => "guardian-retained.tui-disposition.unresolved",
        Some(
            ChildDisposition::Exited {
                stop_action: StopAction::Term | StopAction::Kill,
                ..
            }
            | ChildDisposition::Signaled {
                stop_action: StopAction::Term | StopAction::Kill,
                ..
            },
        ) => "guardian-retained.tui-disposition.forced",
        Some(ChildDisposition::Exited {
            code: 0,
            stop_action: StopAction::None,
        }) => "guardian-retained.tui-disposition.exit-0",
        Some(ChildDisposition::Exited {
            stop_action: StopAction::None,
            ..
        }) => "guardian-retained.tui-disposition.exit-nonzero",
        Some(ChildDisposition::Signaled {
            stop_action: StopAction::None,
            ..
        }) => "guardian-retained.tui-disposition.signaled",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownProgress {
    Advanced,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ShutdownStep {
    progress: ShutdownProgress,
    operation_error: Option<SessionOperationError>,
    cleanup_error: Option<SessionCleanupError>,
}

impl ShutdownStep {
    const fn advanced() -> Self {
        Self {
            progress: ShutdownProgress::Advanced,
            operation_error: None,
            cleanup_error: None,
        }
    }

    const fn advanced_with(
        operation_error: Option<SessionOperationError>,
        cleanup_error: Option<SessionCleanupError>,
    ) -> Self {
        Self {
            progress: ShutdownProgress::Advanced,
            operation_error,
            cleanup_error,
        }
    }

    const fn retained(
        operation_error: Option<SessionOperationError>,
        cleanup_error: Option<SessionCleanupError>,
    ) -> Self {
        Self {
            progress: ShutdownProgress::Retained,
            operation_error,
            cleanup_error,
        }
    }
}

/// Backend contract for the ordered teardown engine.
///
/// `Retained` means the backend still owns the exact authority for the current
/// phase. An implementation must not return it after dropping a child handle,
/// join handle, socket identity, runtime, PTY, or staged-build owner.
trait OrderedShutdownBackend: Sized {
    type Complete;

    fn shutdown_step(
        &mut self,
        phase: ShutdownPhase,
        bounds: SessionShutdownBounds,
    ) -> ShutdownStep;

    fn finish(self, errors: SessionErrors) -> Self::Complete;
}

#[derive(Debug)]
struct OrderedShutdown<Backend> {
    backend: Backend,
    phase: ShutdownPhase,
    errors: SessionErrors,
}

impl<Backend: OrderedShutdownBackend> OrderedShutdown<Backend> {
    fn new(backend: Backend, operation_error: Option<SessionOperationError>) -> Self {
        Self {
            backend,
            phase: ShutdownPhase::Quiesce,
            errors: SessionErrors {
                operation: operation_error,
                cleanup: SessionCleanupErrors::default(),
            },
        }
    }

    fn run(
        mut self,
        bounds: SessionShutdownBounds,
    ) -> Result<Backend::Complete, RetainedShutdown<Backend>> {
        while self.phase != ShutdownPhase::Complete {
            let step = self.backend.shutdown_step(self.phase, bounds);
            self.errors.record_operation(step.operation_error);
            self.errors.record_cleanup(step.cleanup_error);
            match step.progress {
                ShutdownProgress::Advanced => self.phase = self.phase.next(),
                ShutdownProgress::Retained => return Err(RetainedShutdown { shutdown: self }),
            }
        }
        Ok(self.backend.finish(self.errors))
    }
}

/// Retryable shutdown authority. The exact phase is private so a caller cannot
/// skip TUI containment, worker joins, App cleanup, or build cleanup.
#[must_use = "timed-out shutdown retains exact component ownership"]
#[derive(Debug)]
struct RetainedShutdown<Backend> {
    shutdown: OrderedShutdown<Backend>,
}

impl<Backend: OrderedShutdownBackend> RetainedShutdown<Backend> {
    #[cfg(test)]
    fn before_first_step_for_test(
        backend: Backend,
        operation_error: Option<SessionOperationError>,
    ) -> Self {
        Self {
            shutdown: OrderedShutdown::new(backend, operation_error),
        }
    }

    /// Executes only the already-acknowledged TerminalRestore barrier. A
    /// caller cannot use this seam to enter or replay any other shutdown
    /// phase, and successful advancement stops before RecoveryDisarm.
    #[cfg(test)]
    fn advance_terminal_restore_one_step_for_test(
        mut self,
        bounds: SessionShutdownBounds,
    ) -> Result<Self, Self> {
        if self.shutdown.phase != ShutdownPhase::TerminalRestore {
            return Err(self);
        }
        let step = self
            .shutdown
            .backend
            .shutdown_step(ShutdownPhase::TerminalRestore, bounds);
        self.shutdown.errors.record_operation(step.operation_error);
        self.shutdown.errors.record_cleanup(step.cleanup_error);
        match step.progress {
            ShutdownProgress::Advanced => {
                self.shutdown.phase = ShutdownPhase::RecoveryDisarm;
                Ok(self)
            }
            ShutdownProgress::Retained => Err(self),
        }
    }

    #[cfg(test)]
    const fn operation_error(&self) -> Option<SessionOperationError> {
        self.shutdown.errors.operation
    }

    #[cfg(test)]
    const fn cleanup_errors(&self) -> SessionCleanupErrors {
        self.shutdown.errors.cleanup
    }

    fn retry(self, bounds: SessionShutdownBounds) -> Result<Backend::Complete, Self> {
        self.shutdown
            .run(bounds)
            .map_err(|failure| RetainedShutdown {
                shutdown: failure.shutdown,
            })
    }
}

enum RelayAuthority {
    Live(Box<ExactRelaySession>),
    Retained(Box<ExactRelayShutdownFailure>),
    Clean,
}

enum MonitorAuthority {
    Live(Box<SessionMonitor>),
    Clean,
}

enum AppAuthority {
    InMonitor,
    Connected(Box<ConnectedMonitorSession>),
    StopRetained(Box<AppServerStopFailure>),
    Stopped(Box<StoppedAppServer>),
    CleanupRetained(Box<AppServerTeardownFailure>),
    Clean(PinnedAppGracefulDrain),
    Missing,
}

enum BuildAuthority {
    Live(Box<PinnedSessionBuild>),
    CleanupRetained(Box<ProviderCleanupFailure>),
    Clean,
}

/// Concrete component aggregate for one exact pinned provider session.
///
/// App authority begins inside `SessionMonitor` and is recovered only after
/// its worker is joined. The relay owns no runtime; `AppAuthority` therefore
/// cannot advance from stopped child to socket/runtime cleanup until relay
/// shutdown, terminal restoration, and recovery disarm have completed.
pub(super) struct ProductionSessionComponents {
    build: BuildAuthority,
    monitor: MonitorAuthority,
    relay: RelayAuthority,
    terminal: TerminalGenerationOwner,
    app: AppAuthority,
    worker_join_status: WorkerJoinStatus,
    effective_settings: Option<EffectiveThreadSettings>,
}

impl LiveSessionComponents for ProductionSessionComponents {
    fn ensure_monitor_and_app_live(
        &mut self,
        _deadline: Instant,
    ) -> Result<(), SessionLivenessError> {
        match &mut self.monitor {
            MonitorAuthority::Live(monitor) => monitor.ensure_live().map_err(|error| {
                SessionLivenessError::operation(SessionOperationError::Monitor(error))
            }),
            MonitorAuthority::Clean => Err(SessionLivenessError::operation(
                SessionOperationError::Component(SessionComponent::MonitorAndApp),
            )),
        }
    }

    fn ensure_relay_live(&mut self, _deadline: Instant) -> Result<(), SessionLivenessError> {
        match &mut self.relay {
            RelayAuthority::Live(relay) => relay
                .ensure_connected()
                .map_err(SessionLivenessError::relay),
            RelayAuthority::Retained(_) | RelayAuthority::Clean => {
                Err(SessionLivenessError::operation(
                    SessionOperationError::Component(SessionComponent::ReadinessRelay),
                ))
            }
        }
    }

    fn ensure_tui_live(&mut self, deadline: Instant) -> Result<(), SessionLivenessError> {
        self.terminal
            .ensure_tui_live(deadline)
            .map_err(SessionLivenessError::tui)
    }
}

impl OrderedShutdownBackend for ProductionSessionComponents {
    type Complete = SessionShutdownReport;

    fn shutdown_step(
        &mut self,
        phase: ShutdownPhase,
        bounds: SessionShutdownBounds,
    ) -> ShutdownStep {
        match phase {
            ShutdownPhase::Quiesce => self.terminal.quiesce(),
            ShutdownPhase::Tui => self.terminal.shutdown_tui(bounds),
            ShutdownPhase::ReadinessRelay => self.shutdown_relay(bounds.relay_deadline()),
            ShutdownPhase::Monitor => self.shutdown_monitor(bounds.monitor_deadline()),
            ShutdownPhase::AppServerStop => {
                self.stop_app_server(bounds.app_grace, bounds.app_forced)
            }
            ShutdownPhase::TerminalRestore => self.terminal.await_coordinator_restore(),
            ShutdownPhase::RecoveryDisarm => self.terminal.disarm_recovery(),
            ShutdownPhase::RuntimeCleanup => {
                self.cleanup_app_runtime(bounds.app_cleanup_deadline())
            }
            ShutdownPhase::PinnedBuild => self.cleanup_build(bounds.build_cleanup_deadline()),
            ShutdownPhase::Complete => ShutdownStep::advanced(),
        }
    }

    fn finish(self, errors: SessionErrors) -> Self::Complete {
        let app_drain = match self.app {
            AppAuthority::Clean(drain) => drain,
            AppAuthority::InMonitor
            | AppAuthority::Connected(_)
            | AppAuthority::StopRetained(_)
            | AppAuthority::Stopped(_)
            | AppAuthority::CleanupRetained(_)
            | AppAuthority::Missing => std::process::abort(),
        };
        let (tui_outcome, termination_cause) = self.terminal.into_final_outcome();
        drop(self.effective_settings);
        SessionShutdownReport {
            tui_outcome,
            app_drain,
            worker_join_status: self.worker_join_status,
            termination_cause,
            operation_error: errors.operation,
            cleanup_errors: errors.cleanup,
        }
    }
}

impl ProductionSessionComponents {
    fn shutdown_relay(&mut self, deadline: Instant) -> ShutdownStep {
        let authority = std::mem::replace(&mut self.relay, RelayAuthority::Clean);
        match authority {
            RelayAuthority::Clean => ShutdownStep::advanced(),
            RelayAuthority::Live(relay) => match (*relay).shutdown(deadline) {
                Ok(complete) => {
                    complete.release();
                    ShutdownStep::advanced()
                }
                Err(failure) => {
                    let operation_error = relay_shutdown_operation_error(
                        self.terminal.termination_cause,
                        failure.operation_error(),
                    );
                    let cleanup_error = failure
                        .cleanup_error()
                        .map(|_| SessionCleanupError::ReadinessRelay);
                    match failure.try_resolve_without_retry() {
                        Ok(resolution) => {
                            let _prior_error = resolution.release();
                            ShutdownStep::advanced_with(operation_error, cleanup_error)
                        }
                        Err(failure) => {
                            self.relay = RelayAuthority::Retained(failure);
                            ShutdownStep::retained(operation_error, cleanup_error)
                        }
                    }
                }
            },
            RelayAuthority::Retained(failure) => match failure.resolve(deadline) {
                Ok(resolution) => {
                    let operation_error = relay_shutdown_operation_error(
                        self.terminal.termination_cause,
                        resolution.operation_error(),
                    );
                    let cleanup_error = resolution
                        .cleanup_error()
                        .map(|_| SessionCleanupError::ReadinessRelay);
                    let _prior_error = resolution.release();
                    ShutdownStep::advanced_with(operation_error, cleanup_error)
                }
                Err(failure) => {
                    let operation_error = failure.operation_error().map(|_| {
                        SessionOperationError::Component(SessionComponent::ReadinessRelay)
                    });
                    let cleanup_error = failure
                        .cleanup_error()
                        .map(|_| SessionCleanupError::ReadinessRelay);
                    self.relay = RelayAuthority::Retained(failure);
                    ShutdownStep::retained(operation_error, cleanup_error)
                }
            },
        }
    }

    fn shutdown_monitor(&mut self, deadline: Instant) -> ShutdownStep {
        let authority = std::mem::replace(&mut self.monitor, MonitorAuthority::Clean);
        match authority {
            MonitorAuthority::Clean => match self.app {
                AppAuthority::InMonitor => ShutdownStep::retained(
                    Some(SessionOperationError::Component(
                        SessionComponent::MonitorAndApp,
                    )),
                    Some(SessionCleanupError::MissingAuthority),
                ),
                _ => ShutdownStep::advanced(),
            },
            MonitorAuthority::Live(monitor) => match (*monitor).shutdown(deadline) {
                Ok(complete) => {
                    self.worker_join_status = WorkerJoinStatus::JoinedClean;
                    match complete.into_session() {
                        Some(session) => {
                            self.app = AppAuthority::Connected(Box::new(session));
                            ShutdownStep::advanced()
                        }
                        None => {
                            self.app = AppAuthority::Missing;
                            ShutdownStep::retained(
                                Some(SessionOperationError::Component(
                                    SessionComponent::MonitorAndApp,
                                )),
                                Some(SessionCleanupError::MissingAuthority),
                            )
                        }
                    }
                }
                Err(failure) => {
                    let operation_error = Some(SessionOperationError::Monitor(failure.error()));
                    match failure.into_owner() {
                        SessionMonitorShutdownOwner::PendingJoin(monitor) => {
                            self.monitor = MonitorAuthority::Live(monitor);
                            ShutdownStep::retained(
                                operation_error,
                                Some(SessionCleanupError::Monitor),
                            )
                        }
                        SessionMonitorShutdownOwner::JoinedFailed(session) => {
                            self.worker_join_status = WorkerJoinStatus::JoinedFailed;
                            match *session {
                                Some(session) => {
                                    self.app = AppAuthority::Connected(Box::new(session));
                                    ShutdownStep::advanced_with(operation_error, None)
                                }
                                None => {
                                    self.app = AppAuthority::Missing;
                                    ShutdownStep::retained(
                                        operation_error,
                                        Some(SessionCleanupError::MissingAuthority),
                                    )
                                }
                            }
                        }
                        SessionMonitorShutdownOwner::JoinedPanicked(session) => {
                            self.worker_join_status = WorkerJoinStatus::JoinedPanicked;
                            match *session {
                                Some(session) => {
                                    self.app = AppAuthority::Connected(Box::new(session));
                                    ShutdownStep::advanced_with(operation_error, None)
                                }
                                None => {
                                    self.app = AppAuthority::Missing;
                                    ShutdownStep::retained(
                                        operation_error,
                                        Some(SessionCleanupError::MissingAuthority),
                                    )
                                }
                            }
                        }
                    }
                }
            },
        }
    }

    fn stop_app_server(&mut self, graceful: Duration, forced: Duration) -> ShutdownStep {
        let authority = std::mem::replace(&mut self.app, AppAuthority::Missing);
        match authority {
            AppAuthority::Connected(session) => {
                match (*session).stop_app_server(graceful, forced) {
                    Ok(stopped) => {
                        self.app = AppAuthority::Stopped(Box::new(stopped));
                        ShutdownStep::advanced()
                    }
                    Err(failure) => {
                        self.app = AppAuthority::StopRetained(failure);
                        ShutdownStep::retained(None, Some(SessionCleanupError::AppServer))
                    }
                }
            }
            AppAuthority::StopRetained(failure) => match failure.retry(graceful, forced) {
                Ok(stopped) => {
                    self.app = AppAuthority::Stopped(Box::new(stopped));
                    ShutdownStep::advanced()
                }
                Err(failure) => {
                    self.app = AppAuthority::StopRetained(failure);
                    ShutdownStep::retained(None, Some(SessionCleanupError::AppServer))
                }
            },
            authority @ (AppAuthority::Stopped(_)
            | AppAuthority::CleanupRetained(_)
            | AppAuthority::Clean(_)) => {
                self.app = authority;
                ShutdownStep::advanced()
            }
            AppAuthority::InMonitor | AppAuthority::Missing => {
                self.app = AppAuthority::Missing;
                ShutdownStep::retained(
                    Some(SessionOperationError::Component(
                        SessionComponent::MonitorAndApp,
                    )),
                    Some(SessionCleanupError::MissingAuthority),
                )
            }
        }
    }

    fn cleanup_app_runtime(&mut self, deadline: Instant) -> ShutdownStep {
        let authority = std::mem::replace(&mut self.app, AppAuthority::Missing);
        match authority {
            AppAuthority::Stopped(stopped) => match (*stopped).cleanup_socket_runtime(deadline) {
                Ok(complete) => {
                    self.app = AppAuthority::Clean(complete.into_drain());
                    ShutdownStep::advanced()
                }
                Err(failure) => {
                    self.app = AppAuthority::CleanupRetained(failure);
                    ShutdownStep::retained(None, Some(SessionCleanupError::Runtime))
                }
            },
            AppAuthority::CleanupRetained(failure) => match failure.retry(deadline) {
                Ok(complete) => {
                    self.app = AppAuthority::Clean(complete.into_drain());
                    ShutdownStep::advanced()
                }
                Err(failure) => {
                    self.app = AppAuthority::CleanupRetained(failure);
                    ShutdownStep::retained(None, Some(SessionCleanupError::Runtime))
                }
            },
            authority @ AppAuthority::Clean(_) => {
                self.app = authority;
                ShutdownStep::advanced()
            }
            AppAuthority::InMonitor
            | AppAuthority::Connected(_)
            | AppAuthority::StopRetained(_)
            | AppAuthority::Missing => {
                self.app = AppAuthority::Missing;
                ShutdownStep::retained(None, Some(SessionCleanupError::MissingAuthority))
            }
        }
    }

    fn cleanup_build(&mut self, deadline: Instant) -> ShutdownStep {
        let authority = std::mem::replace(&mut self.build, BuildAuthority::Clean);
        let cleanup = match authority {
            BuildAuthority::Live(build) => (*build).cleanup(deadline),
            BuildAuthority::CleanupRetained(failure) => failure.into_build().cleanup(deadline),
            BuildAuthority::Clean => return ShutdownStep::advanced(),
        };
        match cleanup {
            Ok(_) => ShutdownStep::advanced(),
            Err(failure) => {
                self.build = BuildAuthority::CleanupRetained(failure);
                ShutdownStep::retained(None, Some(SessionCleanupError::PinnedBuild))
            }
        }
    }
}

/// Session state after monitor/TUI startup and relay semantic readiness, but
/// before the mandatory fresh `READY` checkpoint.
pub(super) type AwaitingReadySupervisedSession =
    SessionState<ProductionSessionComponents, AwaitingReady>;
pub(super) type ReadySupervisedSession = SessionState<ProductionSessionComponents, ReadyToOpenGate>;
pub(super) type ActiveSupervisedSession = SessionState<ProductionSessionComponents, ActiveIngress>;
pub(super) type DrainingSupervisedSession =
    SessionState<ProductionSessionComponents, DrainingTerminalExit>;
pub(super) type SuspendedSupervisedSession =
    SessionState<ProductionSessionComponents, SuspendedIngress>;
pub(super) type ResumedAwaitingGateSupervisedSession =
    SessionState<ProductionSessionComponents, ResumedAwaitingGate>;

/// Fatal terminal transition failure that retains every session authority but
/// deliberately exposes no transition back to an active typed state.
#[must_use = "a failed terminal generation still owns provider cleanup authority"]
pub(super) struct SessionTerminalFailure {
    components: ProductionSessionComponents,
    error: SessionOperationError,
}

impl SessionTerminalFailure {
    pub(super) const fn error(&self) -> SessionOperationError {
        self.error
    }

    pub(super) fn shutdown(
        self: Box<Self>,
        bounds: SessionShutdownBounds,
    ) -> Result<SessionShutdownReport, Box<SessionShutdownFailure>> {
        let Self { components, error } = *self;
        run_production_shutdown(components, Some(error), bounds)
    }
}

impl fmt::Debug for SessionTerminalFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.components;
        formatter
            .debug_struct("SessionTerminalFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SessionStartupError {
    Monitor(SessionMonitorError),
    ReadinessRelay(ReadinessProxyError),
    Tui,
    TerminalPump(TerminalPumpFailure),
    Deadline,
}

const fn readiness_relay_startup_error(error: ReadinessProxyError) -> SessionStartupError {
    SessionStartupError::ReadinessRelay(error)
}

fn project_relay_poll_result(
    result: Result<Option<EffectiveThreadSettings>, ReadinessProxyError>,
) -> Result<Option<EffectiveThreadSettings>, SessionStartupError> {
    result.map_err(readiness_relay_startup_error)
}

fn project_relay_connection_result(
    result: Result<(), ReadinessProxyError>,
) -> Result<(), SessionStartupError> {
    result.map_err(readiness_relay_startup_error)
}

/// Closed scanner catalog for package-only session-readiness diagnostics.
/// Every entry is a fixed ASCII filename; no provider, process, path, or
/// terminal payload can cross this boundary.
#[cfg(test)]
pub(super) const PACKAGED_SESSION_STARTUP_FAILURE_MARKERS: &[&str] = &[
    "startup-failure.session-readiness.subtype.monitor-invalid-argument",
    "startup-failure.session-readiness.subtype.monitor-handshake",
    "startup-failure.session-readiness.subtype.monitor-protocol",
    "startup-failure.session-readiness.subtype.monitor-authentication",
    "startup-failure.session-readiness.subtype.monitor-provider",
    "startup-failure.session-readiness.subtype.monitor-unsupported",
    "startup-failure.session-readiness.subtype.monitor-timeout",
    "startup-failure.session-readiness.subtype.monitor-transport",
    "startup-failure.session-readiness.subtype.monitor-worker",
    "startup-failure.session-readiness.subtype.monitor-app-server",
    "startup-failure.session-readiness.subtype.readiness-relay.invalid-argument",
    "startup-failure.session-readiness.subtype.readiness-relay.bind",
    "startup-failure.session-readiness.subtype.readiness-relay.accept",
    "startup-failure.session-readiness.subtype.readiness-relay.connect",
    "startup-failure.session-readiness.subtype.readiness-relay.handshake-too-large",
    "startup-failure.session-readiness.subtype.readiness-relay.invalid-handshake",
    "startup-failure.session-readiness.subtype.readiness-relay.frame-too-large",
    "startup-failure.session-readiness.subtype.readiness-relay.invalid-frame",
    "startup-failure.session-readiness.subtype.readiness-relay.invalid-message",
    "startup-failure.session-readiness.subtype.readiness-relay.unexpected-sequence",
    "startup-failure.session-readiness.subtype.readiness-relay.target-mismatch",
    "startup-failure.session-readiness.subtype.readiness-relay.timeout",
    "startup-failure.session-readiness.subtype.readiness-relay.transport",
    "startup-failure.session-readiness.subtype.readiness-relay.worker",
    "startup-failure.session-readiness.subtype.readiness-relay.cleanup",
    "startup-failure.session-readiness.subtype.tui",
    "startup-failure.session-readiness.subtype.terminal-pump.deadline",
    "startup-failure.session-readiness.subtype.terminal-pump.invalid-state",
    "startup-failure.session-readiness.subtype.terminal-pump.tui-output-eof",
    "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-eof",
    "startup-failure.session-readiness.subtype.terminal-pump.tui-read",
    "startup-failure.session-readiness.subtype.terminal-pump.tui-write",
    "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-read",
    "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write",
    "startup-failure.session-readiness.subtype.terminal-pump.signal",
    "startup-failure.session-readiness.subtype.terminal-pump.resize",
    "startup-failure.session-readiness.subtype.terminal-pump.suspend",
    "startup-failure.session-readiness.subtype.terminal-pump.resume",
    "startup-failure.session-readiness.subtype.deadline",
];

#[cfg(test)]
pub(super) const fn packaged_session_startup_failure_marker(
    error: SessionStartupError,
) -> &'static str {
    match error {
        SessionStartupError::Monitor(SessionMonitorError::InvalidArgument) => {
            "startup-failure.session-readiness.subtype.monitor-invalid-argument"
        }
        SessionStartupError::Monitor(SessionMonitorError::Handshake) => {
            "startup-failure.session-readiness.subtype.monitor-handshake"
        }
        SessionStartupError::Monitor(SessionMonitorError::Protocol) => {
            "startup-failure.session-readiness.subtype.monitor-protocol"
        }
        SessionStartupError::Monitor(SessionMonitorError::Authentication) => {
            "startup-failure.session-readiness.subtype.monitor-authentication"
        }
        SessionStartupError::Monitor(SessionMonitorError::Provider) => {
            "startup-failure.session-readiness.subtype.monitor-provider"
        }
        SessionStartupError::Monitor(SessionMonitorError::Unsupported) => {
            "startup-failure.session-readiness.subtype.monitor-unsupported"
        }
        SessionStartupError::Monitor(SessionMonitorError::Timeout) => {
            "startup-failure.session-readiness.subtype.monitor-timeout"
        }
        SessionStartupError::Monitor(SessionMonitorError::Transport) => {
            "startup-failure.session-readiness.subtype.monitor-transport"
        }
        SessionStartupError::Monitor(SessionMonitorError::Worker) => {
            "startup-failure.session-readiness.subtype.monitor-worker"
        }
        SessionStartupError::Monitor(SessionMonitorError::AppServer) => {
            "startup-failure.session-readiness.subtype.monitor-app-server"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidArgument) => {
            "startup-failure.session-readiness.subtype.readiness-relay.invalid-argument"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Bind) => {
            "startup-failure.session-readiness.subtype.readiness-relay.bind"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Accept) => {
            "startup-failure.session-readiness.subtype.readiness-relay.accept"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Connect) => {
            "startup-failure.session-readiness.subtype.readiness-relay.connect"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::HandshakeTooLarge) => {
            "startup-failure.session-readiness.subtype.readiness-relay.handshake-too-large"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidHandshake) => {
            "startup-failure.session-readiness.subtype.readiness-relay.invalid-handshake"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::FrameTooLarge) => {
            "startup-failure.session-readiness.subtype.readiness-relay.frame-too-large"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidFrame) => {
            "startup-failure.session-readiness.subtype.readiness-relay.invalid-frame"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidMessage) => {
            "startup-failure.session-readiness.subtype.readiness-relay.invalid-message"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::UnexpectedSequence) => {
            "startup-failure.session-readiness.subtype.readiness-relay.unexpected-sequence"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::TargetMismatch) => {
            "startup-failure.session-readiness.subtype.readiness-relay.target-mismatch"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Timeout) => {
            "startup-failure.session-readiness.subtype.readiness-relay.timeout"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Transport) => {
            "startup-failure.session-readiness.subtype.readiness-relay.transport"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Worker) => {
            "startup-failure.session-readiness.subtype.readiness-relay.worker"
        }
        SessionStartupError::ReadinessRelay(ReadinessProxyError::Cleanup) => {
            "startup-failure.session-readiness.subtype.readiness-relay.cleanup"
        }
        SessionStartupError::Tui => "startup-failure.session-readiness.subtype.tui",
        SessionStartupError::TerminalPump(TerminalPumpFailure::Deadline) => {
            "startup-failure.session-readiness.subtype.terminal-pump.deadline"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::InvalidState) => {
            "startup-failure.session-readiness.subtype.terminal-pump.invalid-state"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TuiOutputEof) => {
            "startup-failure.session-readiness.subtype.terminal-pump.tui-output-eof"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelEof) => {
            "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-eof"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TuiRead) => {
            "startup-failure.session-readiness.subtype.terminal-pump.tui-read"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TuiWrite) => {
            "startup-failure.session-readiness.subtype.terminal-pump.tui-write"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelRead) => {
            "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-read"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelWrite) => {
            "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::Signal) => {
            "startup-failure.session-readiness.subtype.terminal-pump.signal"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::Resize) => {
            "startup-failure.session-readiness.subtype.terminal-pump.resize"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::Suspend) => {
            "startup-failure.session-readiness.subtype.terminal-pump.suspend"
        }
        SessionStartupError::TerminalPump(TerminalPumpFailure::Resume) => {
            "startup-failure.session-readiness.subtype.terminal-pump.resume"
        }
        SessionStartupError::Deadline => "startup-failure.session-readiness.subtype.deadline",
    }
}

#[must_use = "startup failure retains every started component"]
pub(super) struct SessionStartupFailure {
    components: ProductionSessionComponents,
    error: SessionStartupError,
}

const fn session_startup_operation_error(error: SessionStartupError) -> SessionOperationError {
    match error {
        SessionStartupError::Monitor(error) => SessionOperationError::Monitor(error),
        SessionStartupError::ReadinessRelay(_) => {
            SessionOperationError::Component(SessionComponent::ReadinessRelay)
        }
        SessionStartupError::Tui => SessionOperationError::Component(SessionComponent::Tui),
        SessionStartupError::TerminalPump(error) => SessionOperationError::TerminalPump(error),
        SessionStartupError::Deadline => SessionOperationError::Deadline,
    }
}

impl SessionStartupFailure {
    pub(super) const fn error(&self) -> SessionStartupError {
        self.error
    }

    pub(super) fn shutdown(
        self,
        bounds: SessionShutdownBounds,
    ) -> Result<SessionShutdownReport, Box<SessionShutdownFailure>> {
        run_production_shutdown(
            self.components,
            Some(session_startup_operation_error(self.error)),
            bounds,
        )
    }
}

impl fmt::Debug for SessionStartupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.components;
        formatter
            .debug_struct("SessionStartupFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Composes already-started sealed owners and performs the two protocol
/// startup gates. The function accepts no raw profile/home/thread/cwd/socket.
pub(super) fn assemble_started_session(
    build: PinnedSessionBuild,
    mut monitor: SessionMonitor,
    mut relay: ExactRelaySession,
    mut terminal: TerminalGenerationOwner,
    deadline: Instant,
) -> Result<AwaitingReadySupervisedSession, Box<SessionStartupFailure>> {
    let mut monitor_ready = false;
    let effective_settings = loop {
        if Instant::now() >= deadline {
            return Err(startup_failure(
                build,
                monitor,
                relay,
                terminal,
                SessionStartupError::Deadline,
                None,
            ));
        }
        if let Err(error) = terminal.pump_once(deadline) {
            return Err(startup_failure(
                build,
                monitor,
                relay,
                terminal,
                SessionStartupError::TerminalPump(error),
                None,
            ));
        }
        match monitor.poll_ready() {
            Ok(Some(())) => monitor_ready = true,
            Ok(None) if !monitor_ready => {}
            Ok(None) => {}
            Err(error) => {
                return Err(startup_failure(
                    build,
                    monitor,
                    relay,
                    terminal,
                    SessionStartupError::Monitor(error),
                    None,
                ));
            }
        }
        let settings = match project_relay_poll_result(relay.poll_ready()) {
            Ok(settings) => settings,
            Err(error) => {
                return Err(startup_failure(
                    build, monitor, relay, terminal, error, None,
                ));
            }
        };
        if monitor_ready {
            if let Some(settings) = settings {
                break settings;
            }
        }
        thread::sleep(TERMINAL_PUMP_RETRY.min(deadline.saturating_duration_since(Instant::now())));
    };
    if let Err(error) = monitor.ensure_live() {
        return Err(startup_failure(
            build,
            monitor,
            relay,
            terminal,
            SessionStartupError::Monitor(error),
            Some(effective_settings),
        ));
    }
    if let Err(error) = project_relay_connection_result(relay.ensure_connected()) {
        return Err(startup_failure(
            build,
            monitor,
            relay,
            terminal,
            error,
            Some(effective_settings),
        ));
    }
    if terminal.ensure_tui_live(deadline).is_err() {
        return Err(startup_failure(
            build,
            monitor,
            relay,
            terminal,
            SessionStartupError::Tui,
            Some(effective_settings),
        ));
    }
    Ok(SessionState {
        components: ProductionSessionComponents {
            build: BuildAuthority::Live(Box::new(build)),
            monitor: MonitorAuthority::Live(Box::new(monitor)),
            relay: RelayAuthority::Live(Box::new(relay)),
            terminal,
            app: AppAuthority::InMonitor,
            worker_join_status: WorkerJoinStatus::NotStarted,
            effective_settings: Some(effective_settings),
        },
        _state: PhantomData,
    })
}

fn startup_failure(
    build: PinnedSessionBuild,
    monitor: SessionMonitor,
    relay: ExactRelaySession,
    terminal: TerminalGenerationOwner,
    error: SessionStartupError,
    effective_settings: Option<EffectiveThreadSettings>,
) -> Box<SessionStartupFailure> {
    Box::new(SessionStartupFailure {
        components: ProductionSessionComponents {
            build: BuildAuthority::Live(Box::new(build)),
            monitor: MonitorAuthority::Live(Box::new(monitor)),
            relay: RelayAuthority::Live(Box::new(relay)),
            terminal,
            app: AppAuthority::InMonitor,
            worker_join_status: WorkerJoinStatus::NotStarted,
            effective_settings,
        },
        error,
    })
}

#[must_use = "session disposition is valid only after every cleanup phase"]
pub(super) struct SessionShutdownReport {
    tui_outcome: Option<ShutdownOutcome>,
    app_drain: PinnedAppGracefulDrain,
    worker_join_status: WorkerJoinStatus,
    termination_cause: Option<SessionTerminationCause>,
    operation_error: Option<SessionOperationError>,
    cleanup_errors: SessionCleanupErrors,
}

/// Move-only release authorization consumed by the entry completion boundary.
///
/// This is intentionally opaque outside the lifecycle projector. A pinned App
/// graceful drain and a startup that provably never spawned App are the only
/// two ways to construct it.
#[must_use = "provider release proof must be consumed by guardian completion"]
pub(super) struct ProviderReleaseProof {
    evidence: ProviderReleaseEvidence,
}

enum ProviderReleaseEvidence {
    NeverStarted(ProviderNeverStarted),
    GracefullyDrained(PinnedAppGracefulDrain),
}

impl ProviderReleaseProof {
    /// Consumes the sole release capability at the completion boundary.
    ///
    /// Binding the concrete evidence here is intentional: completion is not
    /// authorized by dropping an opaque wrapper incidentally, but by
    /// exhausting one of the two closed proof cases.
    pub(super) fn authorize_release(self) {
        match self.evidence {
            ProviderReleaseEvidence::NeverStarted(never_started) => drop(never_started),
            ProviderReleaseEvidence::GracefullyDrained(drain) => drop(drain),
        }
    }
}

impl fmt::Debug for ProviderReleaseProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match &self.evidence {
            ProviderReleaseEvidence::NeverStarted(_) => "NeverStarted",
            ProviderReleaseEvidence::GracefullyDrained(_) => "GracefullyDrained",
        };
        formatter
            .debug_tuple("ProviderReleaseProof")
            .field(&label)
            .finish()
    }
}

/// Fixed lifecycle fields plus the sole provider-release authorization.
///
/// Keeping projection here gives startup cleanup and the production guardian
/// one disposition policy. Neither caller may infer success from cleanup
/// syscall success alone or copy the capability into a second completion.
#[must_use = "lifecycle projection must be consumed by guardian completion"]
pub(super) struct SessionLifecycleProjection {
    app: ChildDisposition,
    tui: ChildDisposition,
    worker: WorkerJoinStatus,
    session: SessionStatus,
    guardian_exit: GuardianExitDisposition,
    provider_release: ProviderReleaseProof,
}

impl SessionLifecycleProjection {
    pub(super) fn failed_before_provider_start(
        never_started: ProviderNeverStarted,
        tui_outcome: Option<ShutdownOutcome>,
        worker: WorkerJoinStatus,
    ) -> Self {
        Self {
            app: ChildDisposition::NotStarted,
            tui: tui_outcome.map_or(ChildDisposition::NotStarted, |outcome| {
                outcome.children().tui()
            }),
            worker,
            session: SessionStatus::Failed,
            guardian_exit: GuardianExitDisposition::InternalFailure,
            provider_release: ProviderReleaseProof {
                evidence: ProviderReleaseEvidence::NeverStarted(never_started),
            },
        }
    }

    pub(super) fn failed_after_app_drain(
        drain: PinnedAppGracefulDrain,
        tui_outcome: Option<ShutdownOutcome>,
        worker: WorkerJoinStatus,
    ) -> Self {
        let app = drain.outcome().children().app_server();
        Self {
            app,
            tui: tui_outcome.map_or(ChildDisposition::NotStarted, |outcome| {
                outcome.children().tui()
            }),
            worker,
            session: SessionStatus::Failed,
            guardian_exit: GuardianExitDisposition::InternalFailure,
            provider_release: ProviderReleaseProof {
                evidence: ProviderReleaseEvidence::GracefullyDrained(drain),
            },
        }
    }

    pub(super) const fn app(&self) -> ChildDisposition {
        self.app
    }

    pub(super) const fn tui(&self) -> ChildDisposition {
        self.tui
    }

    pub(super) const fn worker(&self) -> WorkerJoinStatus {
        self.worker
    }

    pub(super) const fn session(&self) -> SessionStatus {
        self.session
    }

    pub(super) const fn guardian_exit(&self) -> GuardianExitDisposition {
        self.guardian_exit
    }

    pub(super) fn into_provider_release(self) -> ProviderReleaseProof {
        self.provider_release
    }
}

impl SessionShutdownReport {
    pub(super) const fn cleanup_errors(&self) -> SessionCleanupErrors {
        self.cleanup_errors
    }

    pub(super) fn into_lifecycle_projection(self) -> SessionLifecycleProjection {
        project_session_lifecycle(
            self.app_drain,
            self.tui_outcome,
            self.worker_join_status,
            self.termination_cause,
            self.operation_error,
            self.cleanup_errors,
        )
    }

    /// Consumes a fully cleaned assembled session on a startup-failure path.
    /// The App release evidence remains identical, while the already-failed
    /// startup operation cannot be upgraded to a completed session.
    pub(super) fn into_failed_lifecycle_projection(self) -> SessionLifecycleProjection {
        #[cfg(test)]
        observe_packaged_terminal_report(
            self.termination_cause,
            self.operation_error,
            self.tui_outcome
                .map_or(ChildDisposition::NotStarted, |outcome| {
                    outcome.children().tui()
                }),
            self.worker_join_status,
            self.cleanup_errors.is_empty(),
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );
        SessionLifecycleProjection::failed_after_app_drain(
            self.app_drain,
            self.tui_outcome,
            self.worker_join_status,
        )
    }
}

fn project_session_lifecycle(
    app_drain: PinnedAppGracefulDrain,
    tui_outcome: Option<ShutdownOutcome>,
    worker: WorkerJoinStatus,
    termination_cause: Option<SessionTerminationCause>,
    operation_error: Option<SessionOperationError>,
    cleanup_errors: SessionCleanupErrors,
) -> SessionLifecycleProjection {
    let fields = project_session_lifecycle_fields(
        Some(*app_drain.outcome()),
        tui_outcome,
        worker,
        termination_cause,
        operation_error,
        cleanup_errors,
    );
    #[cfg(test)]
    observe_packaged_terminal_report(
        termination_cause,
        operation_error,
        fields.tui,
        fields.worker,
        cleanup_errors.is_empty(),
        fields.session,
        fields.guardian_exit,
    );
    SessionLifecycleProjection {
        app: fields.app,
        tui: fields.tui,
        worker: fields.worker,
        session: fields.session,
        guardian_exit: fields.guardian_exit,
        provider_release: ProviderReleaseProof {
            evidence: ProviderReleaseEvidence::GracefullyDrained(app_drain),
        },
    }
}

#[derive(Clone, Copy)]
struct SessionLifecycleFields {
    app: ChildDisposition,
    tui: ChildDisposition,
    worker: WorkerJoinStatus,
    session: SessionStatus,
    guardian_exit: GuardianExitDisposition,
}

fn project_session_lifecycle_fields(
    app_outcome: Option<ShutdownOutcome>,
    tui_outcome: Option<ShutdownOutcome>,
    worker: WorkerJoinStatus,
    termination_cause: Option<SessionTerminationCause>,
    operation_error: Option<SessionOperationError>,
    cleanup_errors: SessionCleanupErrors,
) -> SessionLifecycleFields {
    let app = app_outcome.map_or(ChildDisposition::NotStarted, |outcome| {
        outcome.children().app_server()
    });
    let tui = tui_outcome.map_or(ChildDisposition::NotStarted, |outcome| {
        outcome.children().tui()
    });
    let session = project_session_status(SessionStatusEvidence {
        app,
        tui,
        worker,
        termination_cause,
        operation_clean: operation_error.is_none(),
        cleanup_clean: cleanup_errors.is_empty(),
        app_shutdown_clean: app_outcome.is_some_and(|outcome| outcome.failure().is_none()),
        tui_shutdown_clean: tui_outcome.is_some_and(|outcome| outcome.failure().is_none()),
    });
    let guardian_exit = project_guardian_exit(SessionStatusEvidence {
        app,
        tui,
        worker,
        termination_cause,
        operation_clean: operation_error.is_none(),
        cleanup_clean: cleanup_errors.is_empty(),
        app_shutdown_clean: app_outcome.is_some_and(|outcome| outcome.failure().is_none()),
        tui_shutdown_clean: tui_outcome.is_some_and(|outcome| outcome.failure().is_none()),
    });
    SessionLifecycleFields {
        app,
        tui,
        worker,
        session,
        guardian_exit,
    }
}

#[derive(Clone, Copy)]
struct SessionStatusEvidence {
    app: ChildDisposition,
    tui: ChildDisposition,
    worker: WorkerJoinStatus,
    termination_cause: Option<SessionTerminationCause>,
    operation_clean: bool,
    cleanup_clean: bool,
    app_shutdown_clean: bool,
    tui_shutdown_clean: bool,
}

fn project_session_status(evidence: SessionStatusEvidence) -> SessionStatus {
    project_session_semantics(evidence).0
}

fn project_guardian_exit(evidence: SessionStatusEvidence) -> GuardianExitDisposition {
    project_session_semantics(evidence).1
}

fn project_session_semantics(
    evidence: SessionStatusEvidence,
) -> (SessionStatus, GuardianExitDisposition) {
    if !evidence.operation_clean
        || !evidence.cleanup_clean
        || !evidence.app_shutdown_clean
        || !evidence.tui_shutdown_clean
    {
        return (
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );
    }
    let Some(cause) = evidence.termination_cause else {
        return (
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );
    };
    project_terminal_semantics(evidence.app, evidence.tui, evidence.worker, cause)
}

#[must_use = "shutdown failure retains the exact current phase owner"]
pub(super) struct SessionShutdownFailure {
    retained: RetainedShutdown<ProductionSessionComponents>,
}

impl SessionShutdownFailure {
    pub(super) const fn recovery_stage(&self) -> SessionShutdownRecoveryStage {
        session_shutdown_recovery_stage(self.retained.shutdown.phase)
    }

    pub(super) fn awaiting_terminal_restore(&self) -> bool {
        self.retained.shutdown.phase == ShutdownPhase::TerminalRestore
    }

    /// Installs the one-shot coordinator restoration proof while retaining the
    /// exact shutdown phase. The subsequent `retry` performs disarm and later
    /// cleanup in the original order.
    pub(super) fn acknowledge_terminal_restored(
        mut self: Box<Self>,
        proof: VerifiedTerminalRestoredCommand,
    ) -> Result<Box<Self>, (Box<Self>, VerifiedTerminalRestoredCommand)> {
        if self.retained.shutdown.phase != ShutdownPhase::TerminalRestore {
            return Err((self, proof));
        }
        match self
            .retained
            .shutdown
            .backend
            .terminal
            .acknowledge_coordinator_restore(proof)
        {
            Ok(()) => Ok(self),
            Err(proof) => Err((self, proof)),
        }
    }

    /// Uses guardian fallback restoration only after lifecycle loss. Normal
    /// shutdown must instead consume `VerifiedTerminalRestoredCommand`.
    pub(super) fn restore_after_lifecycle_loss(&mut self) -> Result<(), SessionCleanupError> {
        if self.retained.shutdown.phase != ShutdownPhase::TerminalRestore {
            return Err(SessionCleanupError::TerminalRestore);
        }
        let step = self
            .retained
            .shutdown
            .backend
            .terminal
            .restore_after_lifecycle_loss();
        self.retained
            .shutdown
            .errors
            .record_cleanup(step.cleanup_error);
        match step.progress {
            ShutdownProgress::Advanced => Ok(()),
            ShutdownProgress::Retained => Err(step
                .cleanup_error
                .unwrap_or(SessionCleanupError::TerminalRestore)),
        }
    }

    pub(super) fn retry(
        self: Box<Self>,
        bounds: SessionShutdownBounds,
    ) -> Result<SessionShutdownReport, Box<Self>> {
        match self.retained.retry(bounds) {
            Ok(report) => Ok(report),
            Err(retained) => Err(Box::new(Self { retained })),
        }
    }

    /// Deterministically exposes CleanupPending to guardian recovery tests
    /// without executing RecoveryDisarm or any later cleanup phase.
    #[cfg(test)]
    pub(super) fn advance_acknowledged_terminal_restore_for_test(
        self: Box<Self>,
        bounds: SessionShutdownBounds,
    ) -> Result<Box<Self>, Box<Self>> {
        if self.retained.shutdown.phase != ShutdownPhase::TerminalRestore {
            return Err(self);
        }
        let Self { retained } = *self;
        match retained.advance_terminal_restore_one_step_for_test(bounds) {
            Ok(retained) => Ok(Box::new(Self { retained })),
            Err(retained) => Err(Box::new(Self { retained })),
        }
    }

    /// Returns only closed, payload-free package-test marker names. No process,
    /// terminal, provider, path, or descriptor value crosses this projection.
    #[cfg(test)]
    pub(super) const fn packaged_marker_names(&self) -> [&'static str; 4] {
        let terminal = &self.retained.shutdown.backend.terminal;
        let tui_disposition = match &terminal.tui {
            Some(TuiAuthority::Reaped(outcome)) => Some(outcome.children().tui()),
            Some(TuiAuthority::Live(_) | TuiAuthority::Retained(_)) | None => None,
        };
        [
            packaged_session_shutdown_phase_marker(self.retained.shutdown.phase),
            packaged_session_operation_marker(self.retained.shutdown.errors.operation),
            packaged_session_termination_cause_marker(terminal.termination_cause),
            packaged_session_tui_disposition_marker(tui_disposition),
        ]
    }
}

fn run_production_shutdown(
    components: ProductionSessionComponents,
    operation_error: Option<SessionOperationError>,
    bounds: SessionShutdownBounds,
) -> Result<SessionShutdownReport, Box<SessionShutdownFailure>> {
    OrderedShutdown::new(components, operation_error)
        .run(bounds)
        .map_err(|retained| Box::new(SessionShutdownFailure { retained }))
}

fn terminal_transition_failure(
    components: ProductionSessionComponents,
    error: SessionOperationError,
) -> Box<SessionTerminalFailure> {
    Box::new(SessionTerminalFailure { components, error })
}

impl SessionState<ProductionSessionComponents, ReadyToOpenGate> {
    /// Performs the mandatory fresh App/monitor -> relay -> TUI observation
    /// after the guardian has accepted `OpenInputGate`, then consumes that
    /// one-shot proof to create the first terminal-channel input buffer.
    pub(super) fn open_initial_ingress(
        mut self,
        proof: VerifiedInitialOpenGateCommand,
        deadline: Instant,
    ) -> Result<ActiveSupervisedSession, Box<SessionTerminalFailure>> {
        if let Err(error) = check_all_live(&mut self.components, deadline) {
            return Err(terminal_transition_failure(
                self.components,
                error.operation,
            ));
        }
        if let Err(error) = self
            .components
            .terminal
            .open_initial_ingress(proof, deadline)
        {
            return Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            ));
        }
        Ok(self.transition())
    }
}

impl SessionState<ProductionSessionComponents, ActiveIngress> {
    /// Consumes the active input generation and returns a state that can only
    /// drain TUI output or shut down. A failed half-close retains every
    /// cleanup authority but cannot transition back to active ingress.
    pub(super) fn begin_terminal_exit_drain(
        mut self,
    ) -> Result<DrainingSupervisedSession, Box<SessionTerminalFailure>> {
        match self.components.terminal.begin_output_drain() {
            Ok(()) => Ok(self.transition()),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    /// One synchronous pump turn. Failure consumes the active typed state and
    /// returns only a cleanup-capable owner, preventing accidental reuse.
    pub(super) fn pump_terminal_once(
        mut self,
        deadline: Instant,
    ) -> Result<(Self, TerminalPumpProgress), Box<SessionTerminalFailure>> {
        match self.components.terminal.pump_once(deadline) {
            Ok(progress) => Ok((self, progress)),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    pub(super) fn resize_terminal(
        mut self,
        proof: VerifiedResizeCommand,
        deadline: Instant,
    ) -> Result<Self, Box<SessionTerminalFailure>> {
        let size = TerminalSize::new(proof.rows(), proof.cols());
        match self.components.terminal.resize(size, deadline) {
            Ok(()) => Ok(self),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    pub(super) fn forward_terminal_signal(
        mut self,
        signal: UnixSignal,
        deadline: Instant,
    ) -> Result<Self, Box<SessionTerminalFailure>> {
        match self.components.terminal.forward_signal(signal, deadline) {
            Ok(()) => Ok(self),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    /// Destroys the current input-buffer generation before signalling the TUI
    /// process group. No reader survives into the suspended typed state.
    pub(super) fn suspend_terminal(
        mut self,
        proof: VerifiedSuspendCommand,
        graceful_deadline: Instant,
        forced_deadline: Instant,
    ) -> Result<SuspendedSupervisedSession, Box<SessionTerminalFailure>> {
        let _ = proof;
        match self
            .components
            .terminal
            .suspend(graceful_deadline, forced_deadline)
        {
            Ok(()) => Ok(self.transition()),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }
}

impl SessionState<ProductionSessionComponents, SuspendedIngress> {
    /// Forwards signals while ingress remains physically absent. HUP/TERM
    /// also continue the stopped process group solely so the already-forwarded
    /// shutdown signal can take effect; this never recreates an input gate.
    pub(super) fn forward_terminal_signal(
        mut self,
        signal: UnixSignal,
        deadline: Instant,
    ) -> Result<Self, Box<SessionTerminalFailure>> {
        match self.components.terminal.forward_signal(signal, deadline) {
            Ok(()) => Ok(self),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    /// Applies the exact resume-command size and CONT while ingress remains
    /// absent. The caller must publish `Resumed` and obtain a fresh gate proof.
    pub(super) fn resume_terminal(
        mut self,
        proof: VerifiedResumeCommand,
        deadline: Instant,
    ) -> Result<ResumedAwaitingGateSupervisedSession, Box<SessionTerminalFailure>> {
        let size = TerminalSize::new(proof.rows(), proof.cols());
        match self.components.terminal.resume_tui(size, deadline) {
            Ok(()) => Ok(self.transition()),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }
}

impl SessionState<ProductionSessionComponents, ResumedAwaitingGate> {
    /// Rechecks all live components immediately after the new gate command and
    /// only then allocates the replacement input buffer.
    pub(super) fn open_resumed_ingress(
        mut self,
        proof: VerifiedResumeOpenGateCommand,
        deadline: Instant,
    ) -> Result<ActiveSupervisedSession, Box<SessionTerminalFailure>> {
        if let Err(error) = check_all_live(&mut self.components, deadline) {
            return Err(terminal_transition_failure(
                self.components,
                error.operation,
            ));
        }
        if let Err(error) = self
            .components
            .terminal
            .open_resumed_ingress(proof, deadline)
        {
            return Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            ));
        }
        Ok(self.transition())
    }
}

impl<State> SessionState<ProductionSessionComponents, State> {
    /// Retains the exact live session at Quiesce before any shutdown action.
    /// This seam is test-only and accepts neither descriptors nor process or
    /// provider identifiers.
    #[cfg(test)]
    pub(super) fn retain_before_shutdown_for_test(
        mut self,
        trigger: SessionShutdownTestTrigger,
    ) -> Box<SessionShutdownFailure> {
        let operation_error = apply_session_shutdown_test_trigger(trigger, |cause| {
            self.components.terminal.accept_termination_cause(cause)
        });
        Box::new(SessionShutdownFailure {
            retained: RetainedShutdown::before_first_step_for_test(
                self.components,
                operation_error,
            ),
        })
    }

    /// Performs a fresh ordered App/monitor -> relay -> TUI observation for
    /// one bounded guardian turn. The complete prior typed state is returned
    /// on failure so active input can never continue from stale liveness.
    pub(super) fn check_liveness(
        mut self,
        deadline: Instant,
    ) -> Result<Self, Box<SessionLivenessFailure<Self>>> {
        match check_all_live(&mut self.components, deadline) {
            Ok(()) => Ok(self),
            Err(error) => Err(Box::new(SessionLivenessFailure {
                session: self,
                error,
            })),
        }
    }

    /// Pumps TUI output before the initial gate (and while suspended) without
    /// creating any terminal-channel input reader.
    pub(super) fn pump_terminal_output_once(
        mut self,
        deadline: Instant,
    ) -> Result<(Self, TerminalPumpProgress), Box<SessionTerminalFailure>> {
        match self.components.terminal.pump_once(deadline) {
            Ok(progress) => Ok((self, progress)),
            Err(error) => Err(terminal_transition_failure(
                self.components,
                SessionOperationError::TerminalPump(error),
            )),
        }
    }

    /// Returns only the latest redacted observation from the already-live
    /// monitor. The coordinator status surface will consume this once its
    /// account-scoped query protocol is added; retaining this typed seam keeps
    /// usage observation separate from restart/profile-selection authority.
    #[expect(
        dead_code,
        reason = "staged production seam for the account usage/status protocol"
    )]
    pub(super) fn latest_usage(&self) -> Option<CodexUsage> {
        match &self.components.monitor {
            MonitorAuthority::Live(monitor) => monitor.latest_usage(),
            MonitorAuthority::Clean => None,
        }
    }

    /// Takes at most one already-observed limit transition. This does not
    /// restart a process or select an account; those policy decisions remain
    /// with the future coordinator failover loop.
    #[expect(
        dead_code,
        reason = "staged production seam for the coordinator limit/failover protocol"
    )]
    pub(super) fn take_usage_limit(
        &self,
    ) -> Result<Option<SessionUsageLimitSignal>, SessionMonitorError> {
        match &self.components.monitor {
            MonitorAuthority::Live(monitor) => monitor.take_usage_limit(),
            MonitorAuthority::Clean => Err(SessionMonitorError::Worker),
        }
    }

    /// Begins successful-wrapper shutdown only when the supplied typed cause
    /// matches terminal evidence already held by this exact session owner.
    /// A mismatch still performs complete cleanup but projects a failed
    /// lifecycle, so a caller cannot relabel a crash as a normal exit.
    pub(super) fn shutdown_with_cause(
        mut self,
        cause: SessionTerminationCause,
        bounds: SessionShutdownBounds,
    ) -> Result<SessionShutdownReport, Box<SessionShutdownFailure>> {
        let operation_error = self
            .components
            .terminal
            .accept_termination_cause(cause)
            .err()
            .map(SessionOperationError::TerminalPump);
        run_production_shutdown(self.components, operation_error, bounds)
    }

    pub(super) fn shutdown_after_failure(
        self,
        error: SessionOperationError,
        bounds: SessionShutdownBounds,
    ) -> Result<SessionShutdownReport, Box<SessionShutdownFailure>> {
        run_production_shutdown(self.components, Some(error), bounds)
    }
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{ChildDisposition, SessionTerminationCause};
    use super::{
        PACKAGED_SESSION_RETAINED_OPERATION_MARKERS, PACKAGED_SESSION_STARTUP_FAILURE_MARKERS,
        SessionComponent, SessionMonitorError, SessionOperationError, SessionShutdownRecoveryStage,
        SessionStartupError, ShutdownPhase, TerminalPumpFailure, packaged_session_operation_marker,
        packaged_session_shutdown_phase_marker, packaged_session_startup_failure_marker,
        packaged_session_termination_cause_marker, packaged_session_tui_disposition_marker,
        project_relay_connection_result, project_relay_poll_result, readiness_relay_startup_error,
        session_shutdown_recovery_stage, session_startup_operation_error,
    };
    use crate::providers::codex::remote::ReadinessProxyError;

    #[test]
    fn packaged_session_startup_failure_markers_are_closed_unique_and_fixed() {
        let cases = [
            (
                SessionStartupError::Monitor(SessionMonitorError::InvalidArgument),
                "startup-failure.session-readiness.subtype.monitor-invalid-argument",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Handshake),
                "startup-failure.session-readiness.subtype.monitor-handshake",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Protocol),
                "startup-failure.session-readiness.subtype.monitor-protocol",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Authentication),
                "startup-failure.session-readiness.subtype.monitor-authentication",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Provider),
                "startup-failure.session-readiness.subtype.monitor-provider",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Unsupported),
                "startup-failure.session-readiness.subtype.monitor-unsupported",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Timeout),
                "startup-failure.session-readiness.subtype.monitor-timeout",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Transport),
                "startup-failure.session-readiness.subtype.monitor-transport",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::Worker),
                "startup-failure.session-readiness.subtype.monitor-worker",
            ),
            (
                SessionStartupError::Monitor(SessionMonitorError::AppServer),
                "startup-failure.session-readiness.subtype.monitor-app-server",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidArgument),
                "startup-failure.session-readiness.subtype.readiness-relay.invalid-argument",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Bind),
                "startup-failure.session-readiness.subtype.readiness-relay.bind",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Accept),
                "startup-failure.session-readiness.subtype.readiness-relay.accept",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Connect),
                "startup-failure.session-readiness.subtype.readiness-relay.connect",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::HandshakeTooLarge),
                "startup-failure.session-readiness.subtype.readiness-relay.handshake-too-large",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidHandshake),
                "startup-failure.session-readiness.subtype.readiness-relay.invalid-handshake",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::FrameTooLarge),
                "startup-failure.session-readiness.subtype.readiness-relay.frame-too-large",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidFrame),
                "startup-failure.session-readiness.subtype.readiness-relay.invalid-frame",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::InvalidMessage),
                "startup-failure.session-readiness.subtype.readiness-relay.invalid-message",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::UnexpectedSequence),
                "startup-failure.session-readiness.subtype.readiness-relay.unexpected-sequence",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::TargetMismatch),
                "startup-failure.session-readiness.subtype.readiness-relay.target-mismatch",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Timeout),
                "startup-failure.session-readiness.subtype.readiness-relay.timeout",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Transport),
                "startup-failure.session-readiness.subtype.readiness-relay.transport",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Worker),
                "startup-failure.session-readiness.subtype.readiness-relay.worker",
            ),
            (
                SessionStartupError::ReadinessRelay(ReadinessProxyError::Cleanup),
                "startup-failure.session-readiness.subtype.readiness-relay.cleanup",
            ),
            (
                SessionStartupError::Tui,
                "startup-failure.session-readiness.subtype.tui",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::Deadline),
                "startup-failure.session-readiness.subtype.terminal-pump.deadline",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::InvalidState),
                "startup-failure.session-readiness.subtype.terminal-pump.invalid-state",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TuiOutputEof),
                "startup-failure.session-readiness.subtype.terminal-pump.tui-output-eof",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelEof),
                "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-eof",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TuiRead),
                "startup-failure.session-readiness.subtype.terminal-pump.tui-read",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TuiWrite),
                "startup-failure.session-readiness.subtype.terminal-pump.tui-write",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelRead),
                "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-read",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::TerminalChannelWrite),
                "startup-failure.session-readiness.subtype.terminal-pump.terminal-channel-write",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::Signal),
                "startup-failure.session-readiness.subtype.terminal-pump.signal",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::Resize),
                "startup-failure.session-readiness.subtype.terminal-pump.resize",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::Suspend),
                "startup-failure.session-readiness.subtype.terminal-pump.suspend",
            ),
            (
                SessionStartupError::TerminalPump(TerminalPumpFailure::Resume),
                "startup-failure.session-readiness.subtype.terminal-pump.resume",
            ),
            (
                SessionStartupError::Deadline,
                "startup-failure.session-readiness.subtype.deadline",
            ),
        ];

        let mapped = cases.map(|(error, expected)| {
            let marker = packaged_session_startup_failure_marker(error);
            assert_eq!(marker, expected);
            marker
        });
        assert_eq!(mapped.as_slice(), PACKAGED_SESSION_STARTUP_FAILURE_MARKERS);

        let mut unique = mapped.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), cases.len());
        assert!(
            PACKAGED_SESSION_STARTUP_FAILURE_MARKERS
                .iter()
                .all(|marker| {
                    marker.starts_with("startup-failure.session-readiness.subtype.")
                        && marker.is_ascii()
                        && marker
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-' | b'.'))
                })
        );
    }

    #[test]
    fn startup_monitor_failure_keeps_its_exact_shutdown_operation_subtype() {
        for error in [
            SessionMonitorError::InvalidArgument,
            SessionMonitorError::Handshake,
            SessionMonitorError::Protocol,
            SessionMonitorError::Authentication,
            SessionMonitorError::Provider,
            SessionMonitorError::Unsupported,
            SessionMonitorError::Timeout,
            SessionMonitorError::Transport,
            SessionMonitorError::Worker,
            SessionMonitorError::AppServer,
        ] {
            assert_eq!(
                session_startup_operation_error(SessionStartupError::Monitor(error)),
                SessionOperationError::Monitor(error)
            );
        }
    }

    #[test]
    fn startup_relay_failure_subtypes_keep_the_existing_shutdown_component() {
        for error in [
            ReadinessProxyError::InvalidArgument,
            ReadinessProxyError::Bind,
            ReadinessProxyError::Accept,
            ReadinessProxyError::Connect,
            ReadinessProxyError::HandshakeTooLarge,
            ReadinessProxyError::InvalidHandshake,
            ReadinessProxyError::FrameTooLarge,
            ReadinessProxyError::InvalidFrame,
            ReadinessProxyError::InvalidMessage,
            ReadinessProxyError::UnexpectedSequence,
            ReadinessProxyError::TargetMismatch,
            ReadinessProxyError::Timeout,
            ReadinessProxyError::Transport,
            ReadinessProxyError::Worker,
            ReadinessProxyError::Cleanup,
        ] {
            assert_eq!(
                readiness_relay_startup_error(error),
                SessionStartupError::ReadinessRelay(error)
            );
            assert_eq!(
                project_relay_poll_result(Err(error)),
                Err(SessionStartupError::ReadinessRelay(error))
            );
            assert_eq!(
                project_relay_connection_result(Err(error)),
                Err(SessionStartupError::ReadinessRelay(error))
            );
            assert_eq!(
                session_startup_operation_error(SessionStartupError::ReadinessRelay(error)),
                SessionOperationError::Component(SessionComponent::ReadinessRelay)
            );
        }
    }

    #[test]
    fn packaged_session_shutdown_diagnostics_are_exhaustive_fixed_markers() {
        assert_eq!(
            [
                ShutdownPhase::Quiesce,
                ShutdownPhase::Tui,
                ShutdownPhase::ReadinessRelay,
                ShutdownPhase::Monitor,
                ShutdownPhase::AppServerStop,
                ShutdownPhase::TerminalRestore,
                ShutdownPhase::RecoveryDisarm,
                ShutdownPhase::RuntimeCleanup,
                ShutdownPhase::PinnedBuild,
                ShutdownPhase::Complete,
            ]
            .map(session_shutdown_recovery_stage),
            [
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::Quiescing,
                SessionShutdownRecoveryStage::RestorePending,
                SessionShutdownRecoveryStage::CleanupPending,
                SessionShutdownRecoveryStage::CleanupPending,
                SessionShutdownRecoveryStage::CleanupPending,
                SessionShutdownRecoveryStage::CleanupPending,
            ]
        );
        assert_eq!(
            [
                ShutdownPhase::Quiesce,
                ShutdownPhase::Tui,
                ShutdownPhase::ReadinessRelay,
                ShutdownPhase::Monitor,
                ShutdownPhase::AppServerStop,
                ShutdownPhase::TerminalRestore,
                ShutdownPhase::RecoveryDisarm,
                ShutdownPhase::RuntimeCleanup,
                ShutdownPhase::PinnedBuild,
                ShutdownPhase::Complete,
            ]
            .map(packaged_session_shutdown_phase_marker),
            [
                "guardian-retained.session-phase.quiesce",
                "guardian-retained.session-phase.tui",
                "guardian-retained.session-phase.readiness-relay",
                "guardian-retained.session-phase.monitor",
                "guardian-retained.session-phase.app-server-stop",
                "guardian-retained.session-phase.terminal-restore",
                "guardian-retained.session-phase.recovery-disarm",
                "guardian-retained.session-phase.runtime-cleanup",
                "guardian-retained.session-phase.pinned-build",
                "guardian-retained.session-phase.complete",
            ]
        );

        let operations = [
            None,
            Some(SessionOperationError::RecoveryRequested),
            Some(SessionOperationError::Deadline),
            Some(SessionOperationError::Component(
                SessionComponent::MonitorAndApp,
            )),
            Some(SessionOperationError::Component(
                SessionComponent::ReadinessRelay,
            )),
            Some(SessionOperationError::Component(SessionComponent::Tui)),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Deadline,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::InvalidState,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiOutputEof,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelEof,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiRead,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiWrite,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelRead,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelWrite,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Signal,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Resize,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Suspend,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Resume,
            )),
        ];
        assert_eq!(
            operations.map(packaged_session_operation_marker),
            [
                "guardian-retained.session-operation.none",
                "guardian-retained.session-operation.recovery-requested",
                "guardian-retained.session-operation.deadline",
                "guardian-retained.session-operation.component-monitor-app",
                "guardian-retained.session-operation.component-readiness-relay",
                "guardian-retained.session-operation.component-tui",
                "guardian-retained.session-operation.pump-deadline",
                "guardian-retained.session-operation.pump-invalid-state",
                "guardian-retained.session-operation.pump-tui-output-eof",
                "guardian-retained.session-operation.pump-terminal-channel-eof",
                "guardian-retained.session-operation.pump-tui-read",
                "guardian-retained.session-operation.pump-tui-write",
                "guardian-retained.session-operation.pump-terminal-channel-read",
                "guardian-retained.session-operation.pump-terminal-channel-write",
                "guardian-retained.session-operation.pump-signal",
                "guardian-retained.session-operation.pump-resize",
                "guardian-retained.session-operation.pump-suspend",
                "guardian-retained.session-operation.pump-resume",
            ]
        );

        assert_eq!(
            [
                None,
                Some(SessionTerminationCause::NaturalTuiEof),
                Some(SessionTerminationCause::CoordinatorStop),
                Some(SessionTerminationCause::ForwardedHup),
                Some(SessionTerminationCause::ForwardedTerm),
            ]
            .map(packaged_session_termination_cause_marker),
            [
                "guardian-retained.termination-cause.none",
                "guardian-retained.termination-cause.natural-tui-eof",
                "guardian-retained.termination-cause.coordinator-stop",
                "guardian-retained.termination-cause.forwarded-hup",
                "guardian-retained.termination-cause.forwarded-term",
            ]
        );
        assert_eq!(
            [
                None,
                Some(ChildDisposition::NotStarted),
                Some(ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::None,
                }),
                Some(ChildDisposition::Exited {
                    code: 7,
                    stop_action: StopAction::None,
                }),
                Some(ChildDisposition::Signaled {
                    signal: 15,
                    core_dumped: false,
                    stop_action: StopAction::None,
                }),
                Some(ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::Term,
                }),
                Some(ChildDisposition::Signaled {
                    signal: 9,
                    core_dumped: false,
                    stop_action: StopAction::Kill,
                }),
            ]
            .map(packaged_session_tui_disposition_marker),
            [
                "guardian-retained.tui-disposition.unresolved",
                "guardian-retained.tui-disposition.unresolved",
                "guardian-retained.tui-disposition.exit-0",
                "guardian-retained.tui-disposition.exit-nonzero",
                "guardian-retained.tui-disposition.signaled",
                "guardian-retained.tui-disposition.forced",
                "guardian-retained.tui-disposition.forced",
            ]
        );
    }

    #[test]
    fn monitor_liveness_failures_keep_a_closed_payload_free_subtype() {
        assert_eq!(
            [
                SessionMonitorError::InvalidArgument,
                SessionMonitorError::Handshake,
                SessionMonitorError::Protocol,
                SessionMonitorError::Authentication,
                SessionMonitorError::Provider,
                SessionMonitorError::Unsupported,
                SessionMonitorError::Timeout,
                SessionMonitorError::Transport,
                SessionMonitorError::Worker,
                SessionMonitorError::AppServer,
            ]
            .map(|error| {
                packaged_session_operation_marker(Some(SessionOperationError::Monitor(error)))
            }),
            [
                "guardian-retained.session-operation.monitor-invalid-argument",
                "guardian-retained.session-operation.monitor-handshake",
                "guardian-retained.session-operation.monitor-protocol",
                "guardian-retained.session-operation.monitor-authentication",
                "guardian-retained.session-operation.monitor-provider",
                "guardian-retained.session-operation.monitor-unsupported",
                "guardian-retained.session-operation.monitor-timeout",
                "guardian-retained.session-operation.monitor-transport",
                "guardian-retained.session-operation.monitor-worker",
                "guardian-retained.session-operation.monitor-app-server",
            ]
        );
    }

    #[test]
    fn retained_operation_catalog_covers_every_closed_mapper_output() {
        let mut operations = vec![
            None,
            Some(SessionOperationError::RecoveryRequested),
            Some(SessionOperationError::Deadline),
        ];
        operations.extend(
            [
                SessionMonitorError::InvalidArgument,
                SessionMonitorError::Handshake,
                SessionMonitorError::Protocol,
                SessionMonitorError::Authentication,
                SessionMonitorError::Provider,
                SessionMonitorError::Unsupported,
                SessionMonitorError::Timeout,
                SessionMonitorError::Transport,
                SessionMonitorError::Worker,
                SessionMonitorError::AppServer,
            ]
            .map(|error| Some(SessionOperationError::Monitor(error))),
        );
        operations.extend([
            Some(SessionOperationError::Component(
                SessionComponent::MonitorAndApp,
            )),
            Some(SessionOperationError::Component(
                SessionComponent::ReadinessRelay,
            )),
            Some(SessionOperationError::Component(SessionComponent::Tui)),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Deadline,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::InvalidState,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiOutputEof,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelEof,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiRead,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TuiWrite,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelRead,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::TerminalChannelWrite,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Signal,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Resize,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Suspend,
            )),
            Some(SessionOperationError::TerminalPump(
                TerminalPumpFailure::Resume,
            )),
        ]);

        let mapped: Vec<_> = operations
            .into_iter()
            .map(packaged_session_operation_marker)
            .collect();
        assert_eq!(
            mapped.as_slice(),
            PACKAGED_SESSION_RETAINED_OPERATION_MARKERS
        );
    }

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::time::Duration;

    use uuid::Uuid;

    use super::super::protocol::StopAction;
    use super::*;

    fn exited(code: u8, stop_action: StopAction) -> ChildDisposition {
        ChildDisposition::Exited { code, stop_action }
    }

    fn signaled(signal: u8, stop_action: StopAction) -> ChildDisposition {
        ChildDisposition::Signaled {
            signal,
            core_dumped: false,
            stop_action,
        }
    }

    fn clean_status_evidence(
        tui: ChildDisposition,
        cause: SessionTerminationCause,
    ) -> SessionStatusEvidence {
        SessionStatusEvidence {
            app: signaled(15, StopAction::Term),
            tui,
            worker: WorkerJoinStatus::JoinedClean,
            termination_cause: Some(cause),
            operation_clean: true,
            cleanup_clean: true,
            app_shutdown_clean: true,
            tui_shutdown_clean: true,
        }
    }

    #[test]
    fn session_disposition_projection_is_cause_aware_and_fail_closed() {
        struct Case {
            name: &'static str,
            evidence: SessionStatusEvidence,
            session: SessionStatus,
            guardian_exit: GuardianExitDisposition,
        }

        let natural = SessionTerminationCause::NaturalTuiEof;
        let coordinator = SessionTerminationCause::CoordinatorStop;
        let forwarded_hup = SessionTerminationCause::ForwardedHup;
        let forwarded_term = SessionTerminationCause::ForwardedTerm;
        let mut worker_failed = clean_status_evidence(exited(0, StopAction::None), natural);
        worker_failed.worker = WorkerJoinStatus::JoinedFailed;
        let mut worker_panicked = clean_status_evidence(exited(0, StopAction::None), natural);
        worker_panicked.worker = WorkerJoinStatus::JoinedPanicked;
        let mut cleanup_failed = clean_status_evidence(exited(0, StopAction::None), natural);
        cleanup_failed.cleanup_clean = false;
        let mut app_killed = clean_status_evidence(exited(0, StopAction::None), natural);
        app_killed.app = signaled(9, StopAction::Kill);
        let mut tui_shutdown_failed = clean_status_evidence(exited(0, StopAction::None), natural);
        tui_shutdown_failed.tui_shutdown_clean = false;

        let cases = [
            Case {
                name: "natural exit zero",
                evidence: clean_status_evidence(exited(0, StopAction::None), natural),
                session: SessionStatus::Completed,
                guardian_exit: GuardianExitDisposition::Code(0),
            },
            Case {
                name: "natural nonzero is exact failed exit",
                evidence: clean_status_evidence(exited(17, StopAction::None), natural),
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::Code(17),
            },
            Case {
                name: "natural unexpected signal is exact failed signal",
                evidence: clean_status_evidence(signaled(11, StopAction::None), natural),
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::Signal(11),
            },
            Case {
                name: "coordinator stop accepts cleanup term",
                evidence: clean_status_evidence(signaled(15, StopAction::Term), coordinator),
                session: SessionStatus::Completed,
                guardian_exit: GuardianExitDisposition::Code(0),
            },
            Case {
                name: "forwarded hup preserves signal",
                evidence: clean_status_evidence(signaled(1, StopAction::None), forwarded_hup),
                session: SessionStatus::Completed,
                guardian_exit: GuardianExitDisposition::Signal(1),
            },
            Case {
                name: "forwarded term preserves signal",
                evidence: clean_status_evidence(signaled(15, StopAction::None), forwarded_term),
                session: SessionStatus::Completed,
                guardian_exit: GuardianExitDisposition::Signal(15),
            },
            Case {
                name: "signal requires matching forwarded cause",
                evidence: clean_status_evidence(signaled(1, StopAction::None), forwarded_term),
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::Signal(1),
            },
            Case {
                name: "forced tui kill is internal failure",
                evidence: clean_status_evidence(signaled(9, StopAction::Kill), coordinator),
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
            Case {
                name: "normal app cleanup term is accepted",
                evidence: clean_status_evidence(exited(0, StopAction::None), natural),
                session: SessionStatus::Completed,
                guardian_exit: GuardianExitDisposition::Code(0),
            },
            Case {
                name: "forced app kill fails",
                evidence: app_killed,
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
            Case {
                name: "worker join failure is internal",
                evidence: worker_failed,
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
            Case {
                name: "worker join panic is exact internal failure",
                evidence: worker_panicked,
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
            Case {
                name: "cleanup failure is internal",
                evidence: cleanup_failed,
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
            Case {
                name: "shutdown infrastructure failure is internal",
                evidence: tui_shutdown_failed,
                session: SessionStatus::Failed,
                guardian_exit: GuardianExitDisposition::InternalFailure,
            },
        ];

        for case in cases {
            assert_eq!(
                project_session_status(case.evidence),
                case.session,
                "{} session status",
                case.name
            );
            assert_eq!(
                project_guardian_exit(case.evidence),
                case.guardian_exit,
                "{} guardian exit",
                case.name
            );
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Observation {
        MonitorAndApp,
        Relay,
        Tui,
    }

    #[derive(Debug)]
    struct FakeComponents {
        observations: Vec<Observation>,
        fail: Option<SessionComponent>,
        also_fail_tui: bool,
    }

    impl FakeComponents {
        fn healthy() -> Self {
            Self {
                observations: Vec::new(),
                fail: None,
                also_fail_tui: false,
            }
        }

        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(1)
        }

        fn record(
            &mut self,
            observation: Observation,
            component: SessionComponent,
        ) -> Result<(), SessionLivenessError> {
            self.observations.push(observation);
            if self.fail == Some(component)
                || (component == SessionComponent::Tui && self.also_fail_tui)
            {
                if component == SessionComponent::ReadinessRelay {
                    Err(SessionLivenessError::relay(ReadinessProxyError::Transport))
                } else if component == SessionComponent::Tui {
                    Err(SessionLivenessError::tui(RemoteTuiLauncherError::NotLive))
                } else {
                    Err(SessionLivenessError::operation(
                        SessionOperationError::Component(component),
                    ))
                }
            } else {
                Ok(())
            }
        }
    }

    impl LiveSessionComponents for FakeComponents {
        fn ensure_monitor_and_app_live(
            &mut self,
            _deadline: Instant,
        ) -> Result<(), SessionLivenessError> {
            self.record(Observation::MonitorAndApp, SessionComponent::MonitorAndApp)
        }

        fn ensure_relay_live(&mut self, _deadline: Instant) -> Result<(), SessionLivenessError> {
            self.record(Observation::Relay, SessionComponent::ReadinessRelay)
        }

        fn ensure_tui_live(&mut self, _deadline: Instant) -> Result<(), SessionLivenessError> {
            self.record(Observation::Tui, SessionComponent::Tui)
        }
    }

    fn assembled(components: FakeComponents) -> SessionState<FakeComponents, AwaitingReady> {
        SessionState {
            components,
            _state: PhantomData,
        }
    }

    fn fake_checkpoint<State, Next>(
        mut session: SessionState<FakeComponents, State>,
    ) -> Result<
        SessionState<FakeComponents, Next>,
        SessionLivenessFailure<SessionState<FakeComponents, State>>,
    > {
        match check_all_live(&mut session.components, FakeComponents::deadline()) {
            Ok(()) => Ok(session.transition()),
            Err(error) => Err(SessionLivenessFailure { session, error }),
        }
    }

    #[derive(Clone, Copy)]
    enum FakeTuiOutput {
        Data(&'static [u8]),
        WouldBlock,
        EndOfStream,
        Error,
    }

    struct FakeGuardianTui {
        output: RefCell<VecDeque<FakeTuiOutput>>,
        expected_input: Option<&'static [u8]>,
        input_would_block_once: Cell<bool>,
        input_calls: Cell<usize>,
        matched_input: Cell<bool>,
    }

    impl FakeGuardianTui {
        fn with_output(output: impl IntoIterator<Item = FakeTuiOutput>) -> Self {
            Self {
                output: RefCell::new(output.into_iter().collect()),
                expected_input: None,
                input_would_block_once: Cell::new(false),
                input_calls: Cell::new(0),
                matched_input: Cell::new(false),
            }
        }

        fn expecting_input(expected: &'static [u8], would_block_once: bool) -> Self {
            Self {
                output: RefCell::new(VecDeque::from([FakeTuiOutput::WouldBlock])),
                expected_input: Some(expected),
                input_would_block_once: Cell::new(would_block_once),
                input_calls: Cell::new(0),
                matched_input: Cell::new(false),
            }
        }
    }

    impl GuardianTuiPumpIo for FakeGuardianTui {
        fn read_output<'buffer>(
            &self,
            buffer: &'buffer mut TerminalBuffer,
        ) -> Result<TerminalRead<'buffer>, TerminalError> {
            match self
                .output
                .borrow_mut()
                .pop_front()
                .unwrap_or(FakeTuiOutput::WouldBlock)
            {
                FakeTuiOutput::Data(bytes) => buffer.load(bytes).map(TerminalRead::Data),
                FakeTuiOutput::WouldBlock => Ok(TerminalRead::WouldBlock),
                FakeTuiOutput::EndOfStream => Ok(TerminalRead::EndOfStream),
                FakeTuiOutput::Error => Err(TerminalError::Read),
            }
        }

        fn try_write_input(
            &self,
            chunk: &mut super::super::terminal::TerminalChunk<'_>,
        ) -> Result<TerminalWrite, TerminalError> {
            self.input_calls.set(self.input_calls.get() + 1);
            if self.input_would_block_once.replace(false) {
                return Ok(TerminalWrite::WouldBlock);
            }
            if let Some(expected) = self.expected_input {
                if !chunk.matches(expected) {
                    return Err(TerminalError::Write);
                }
                self.matched_input.set(true);
            }
            chunk.consume_for_test()
        }
    }

    struct FloodedTerminalInput {
        reads: Cell<usize>,
    }

    impl GuardianTerminalInput for FloodedTerminalInput {
        fn read_input<'buffer>(
            &self,
            buffer: &'buffer mut TerminalBuffer,
        ) -> Result<TerminalRead<'buffer>, TerminalError> {
            self.reads.set(self.reads.get() + 1);
            buffer.load(b"stale").map(TerminalRead::Data)
        }
    }

    fn send_terminal(endpoint: &TerminalEndpoint, bytes: &[u8]) -> Result<(), TerminalError> {
        let mut buffer = TerminalBuffer::new();
        let mut chunk = buffer.load(bytes)?;
        for _ in 0..128 {
            match endpoint.try_write(&mut chunk)? {
                TerminalWrite::Complete => return Ok(()),
                TerminalWrite::Progress { .. } => {}
                TerminalWrite::WouldBlock => std::thread::yield_now(),
            }
        }
        Err(TerminalError::Write)
    }

    fn duplex_pump() -> TerminalPumpAuthority {
        TerminalPumpAuthority::Duplex(Box::new(DuplexPump {
            output: TerminalBuffer::new(),
            input: TerminalBuffer::new(),
        }))
    }

    #[test]
    fn packaged_tui_output_matcher_handles_fragment_boundaries_without_retaining_bytes() {
        let pattern = PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes();
        let split = pattern.len() / 2;
        let mut matcher = PackagedTuiOutputMatcher::new();

        matcher.observe(&pattern[..split]);
        assert!(!matcher.seen());
        matcher.observe(&pattern[split..]);
        assert!(matcher.seen());

        let mut nonmatch = PackagedTuiOutputMatcher::new();
        nonmatch.observe(b"running one test with unrelated terminal output");
        assert!(!nonmatch.seen());
    }

    #[test]
    fn packaged_terminal_observation_is_closed_and_one_shot()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = PackagedObservationTestScope::arm()?;
        observe_packaged_terminal_report(
            Some(SessionTerminationCause::NaturalTuiEof),
            Some(SessionOperationError::Component(
                SessionComponent::MonitorAndApp,
            )),
            ChildDisposition::Exited {
                code: 7,
                stop_action: StopAction::None,
            },
            WorkerJoinStatus::JoinedFailed,
            false,
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );
        observe_packaged_terminal_report(
            Some(SessionTerminationCause::CoordinatorStop),
            None,
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::None,
            },
            WorkerJoinStatus::JoinedClean,
            true,
            SessionStatus::Completed,
            GuardianExitDisposition::Code(0),
        );

        let observation =
            take_packaged_session_observation().ok_or("packaged observer disappeared")?;
        let value = serde_json::to_value(observation)?;
        assert_eq!(value["shutdown_observed"], true);
        assert_eq!(value["termination_cause"], "natural-tui-eof");
        assert_eq!(value["operation_error"], "component-monitor-app");
        assert_eq!(value["tui_disposition"], "exit-nonzero");
        assert_eq!(value["worker_join"], "joined-failed");
        assert_eq!(value["cleanup_clean"], false);
        assert_eq!(value["session_status"], "failed");
        assert_eq!(value["guardian_exit"], "internal-failure");
        assert_eq!(value["integrity_failure"], "duplicate-shutdown");
        assert_eq!(value["observation_failed"], true);
        for marker in [
            "session-terminal.termination-cause.natural-tui-eof",
            "session-terminal.operation.component-monitor-app",
            "session-terminal.tui.exit-nonzero",
            "session-terminal.worker.joined-failed",
            "session-terminal.cleanup.failed",
            "session-terminal.session.failed",
            "session-terminal.guardian-exit.internal-failure",
        ] {
            assert!(scope.root.join(marker).is_file(), "missing {marker}");
        }
        Ok(())
    }

    #[test]
    fn packaged_observation_integrity_preserves_the_first_closed_failure_subtype()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = PackagedObservationTestScope::arm()?;
        write_packaged_observation_marker(
            PACKAGED_SESSION_OBSERVATION
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .ok_or("packaged observer disappeared")?,
            "integrity-marker.live",
            b"first\n",
        );
        write_packaged_observation_marker(
            PACKAGED_SESSION_OBSERVATION
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .ok_or("packaged observer disappeared")?,
            "integrity-marker.live",
            b"duplicate\n",
        );
        observe_packaged_terminal_report(
            None,
            None,
            ChildDisposition::NotStarted,
            WorkerJoinStatus::NotStarted,
            false,
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );
        observe_packaged_terminal_report(
            None,
            None,
            ChildDisposition::NotStarted,
            WorkerJoinStatus::NotStarted,
            false,
            SessionStatus::Failed,
            GuardianExitDisposition::InternalFailure,
        );

        let observation =
            take_packaged_session_observation().ok_or("packaged observer disappeared")?;
        assert_eq!(
            observation.integrity_failure,
            Some(PackagedObservationIntegrityFailure::MarkerWrite)
        );
        let value = serde_json::to_value(observation)?;
        assert_eq!(value["integrity_failure"], "marker-write");
        assert_eq!(value["observation_failed"], true);
        assert!(scope.root.join("integrity-marker.live").is_file());
        Ok(())
    }

    #[test]
    fn packaged_observation_marker_routes_through_a_fail_closed_publisher()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = PackagedObservationTestScope::arm()?;
        let marker = scope.root.join("atomic-marker.live");
        let mut publisher_called = false;
        {
            let mut guard = PACKAGED_SESSION_OBSERVATION
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let armed = guard.as_mut().ok_or("packaged observer disappeared")?;
            write_packaged_observation_marker_with_publisher(
                armed,
                "atomic-marker.live",
                b"complete\n",
                |path, payload| {
                    publisher_called = true;
                    assert_eq!(path, marker.as_path());
                    assert_eq!(payload, b"complete\n");
                    Err(std::io::Error::other("injected publication failure"))
                },
            );
        }

        let observation =
            take_packaged_session_observation().ok_or("packaged observer disappeared")?;
        assert!(publisher_called);
        assert!(!marker.exists());
        assert_eq!(
            observation.integrity_failure,
            Some(PackagedObservationIntegrityFailure::MarkerWrite)
        );
        assert!(observation.observation_failed);
        Ok(())
    }

    #[test]
    fn repeated_resize_observation_preserves_semantics_without_corrupting_the_observer()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = PackagedObservationTestScope::arm()?;
        observe_packaged_resize(TerminalSize::new(41, 123));
        observe_packaged_resize(TerminalSize::new(43, 125));

        let observation =
            take_packaged_session_observation().ok_or("packaged observer disappeared")?;
        assert_eq!(observation.resized_sizes, [(41, 123), (43, 125)]);
        assert_eq!(observation.integrity_failure, None);
        assert!(!observation.observation_failed);
        assert_eq!(fs::read(scope.root.join("resize.live"))?, b"41 123\n");
        Ok(())
    }

    #[test]
    fn identical_terminal_resize_is_idempotent_after_apply_or_resume() {
        let initial = TerminalSize::new(37, 111);
        let resized = TerminalSize::new(41, 123);

        assert!(terminal_resize_requires_application(None, initial));
        assert!(terminal_resize_requires_application(Some(initial), resized));
        assert!(!terminal_resize_requires_application(
            Some(resized),
            resized
        ));
    }

    #[test]
    fn packaged_terminal_observation_preserves_monitor_failure_subtypes()
    -> Result<(), Box<dyn std::error::Error>> {
        for (error, serialized, marker) in [
            (
                SessionMonitorError::Authentication,
                "monitor-authentication",
                "session-terminal.operation.monitor-authentication",
            ),
            (
                SessionMonitorError::Provider,
                "monitor-provider",
                "session-terminal.operation.monitor-provider",
            ),
            (
                SessionMonitorError::Unsupported,
                "monitor-unsupported",
                "session-terminal.operation.monitor-unsupported",
            ),
        ] {
            let scope = PackagedObservationTestScope::arm()?;
            observe_packaged_terminal_report(
                None,
                Some(SessionOperationError::Monitor(error)),
                ChildDisposition::NotStarted,
                WorkerJoinStatus::NotStarted,
                false,
                SessionStatus::Failed,
                GuardianExitDisposition::InternalFailure,
            );

            let observation =
                take_packaged_session_observation().ok_or("packaged observer disappeared")?;
            let value = serde_json::to_value(observation)?;
            assert_eq!(value["operation_error"], serialized);
            assert!(scope.root.join(marker).is_file(), "missing {marker}");
            drop(scope);
        }
        Ok(())
    }

    #[test]
    fn packaged_terminal_observation_distinguishes_unobserved_from_domain_none()
    -> Result<(), Box<dyn std::error::Error>> {
        let _scope = PackagedObservationTestScope::arm()?;
        let observation =
            take_packaged_session_observation().ok_or("packaged observer disappeared")?;
        let value = serde_json::to_value(observation)?;
        assert_eq!(value["shutdown_observed"], false);
        assert_eq!(value["termination_cause"], serde_json::Value::Null);
        assert_eq!(value["operation_error"], serde_json::Value::Null);
        assert_eq!(value["tui_disposition"], serde_json::Value::Null);
        assert_eq!(value["worker_join"], serde_json::Value::Null);
        assert_eq!(value["cleanup_clean"], serde_json::Value::Null);
        assert_eq!(value["session_status"], serde_json::Value::Null);
        assert_eq!(value["guardian_exit"], serde_json::Value::Null);
        Ok(())
    }

    static PACKAGED_OBSERVATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct PackagedObservationTestScope {
        root: PathBuf,
        _test_lock: std::sync::MutexGuard<'static, ()>,
    }

    impl PackagedObservationTestScope {
        fn arm() -> Result<Self, Box<dyn std::error::Error>> {
            let test_lock = PACKAGED_OBSERVATION_TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let root = std::env::temp_dir().join(format!(
                "calcifer-packaged-output-observer-{}",
                Uuid::new_v4()
            ));
            fs::DirBuilder::new().mode(0o700).create(&root)?;
            arm_packaged_session_observation(root.clone())?;
            Ok(Self {
                root,
                _test_lock: test_lock,
            })
        }
    }

    impl Drop for PackagedObservationTestScope {
        fn drop(&mut self) {
            let _ = take_packaged_session_observation();
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn packaged_output_observer_commits_only_after_a_complete_forward()
    -> Result<(), Box<dyn std::error::Error>> {
        let _scope = PackagedObservationTestScope::arm()?;
        let (coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        let mut pump = TerminalPumpAuthority::OutputOnly(Box::new(OutputOnlyPump {
            output: TerminalBuffer::new(),
        }));

        let failed = FakeGuardianTui::with_output([FakeTuiOutput::Data(
            PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes(),
        )]);
        assert_eq!(
            pump_guardian_terminal_once(&failed, &guardian, &mut pump, Instant::now()),
            Err(TerminalPumpFailure::Deadline)
        );
        assert!(!packaged_output_sentinel_seen_for_test());

        let forwarded = FakeGuardianTui::with_output([FakeTuiOutput::Data(
            PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes(),
        )]);
        assert_eq!(
            pump_guardian_terminal_once(
                &forwarded,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Output)
        );
        assert!(packaged_output_sentinel_seen_for_test());

        let mut output = TerminalBuffer::new();
        assert!(matches!(
            coordinator.read_into(&mut output)?,
            TerminalRead::Data(chunk)
                if chunk.matches(PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes())
        ));

        let observation =
            take_packaged_session_observation().ok_or("packaged output observer disappeared")?;
        assert!(observation.output_sentinel_seen);
        let serialized = serde_json::to_value(&observation)?;
        assert_eq!(
            serialized
                .get("output_sentinel_seen")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(serialized.get("output").is_none());
        assert!(serialized.get("transcript").is_none());
        assert!(
            !serde_json::to_vec(&observation)?
                .windows(PACKAGED_TUI_OUTPUT_SENTINEL.len())
                .any(|window| window == PACKAGED_TUI_OUTPUT_SENTINEL.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn packaged_input_observer_commits_only_after_a_complete_forward()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = PackagedObservationTestScope::arm()?;
        let (coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        let tui = FakeGuardianTui::expecting_input(b"typed-input", false);
        let mut pump = duplex_pump();

        send_terminal(&coordinator, b"typed-input")?;
        assert_eq!(
            pump_guardian_terminal_once(&tui, &guardian, &mut pump, Instant::now()),
            Err(TerminalPumpFailure::Deadline)
        );
        assert_eq!(
            PACKAGED_SESSION_OBSERVATION
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|armed| armed.observation.input.as_slice()),
            Some([].as_slice())
        );
        assert_eq!(fs::read(scope.root.join("input.live"))?, b"");

        send_terminal(&coordinator, b"typed-input")?;
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Input)
        );
        let observation =
            take_packaged_session_observation().ok_or("packaged input observer disappeared")?;
        assert_eq!(observation.input, b"typed-input");
        assert_eq!(fs::read(scope.root.join("input.live"))?, b"typed-input");
        Ok(())
    }

    #[test]
    fn guardian_output_only_pump_discards_pre_gate_input_before_reader_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        send_terminal(&coordinator, b"pre-gate-sentinel")?;

        let tui = FakeGuardianTui::with_output([FakeTuiOutput::Data(b"tui-output")]);
        let mut pump = TerminalPumpAuthority::OutputOnly(Box::new(OutputOnlyPump {
            output: TerminalBuffer::new(),
        }));
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Output)
        );
        assert_eq!(tui.input_calls.get(), 0);

        let mut output = TerminalBuffer::new();
        assert!(matches!(
            coordinator.read_into(&mut output)?,
            TerminalRead::Data(chunk) if chunk.matches(b"tui-output")
        ));

        assert!(
            discard_terminal_input_before(&guardian, Instant::now() + Duration::from_secs(1))
                .is_ok(),
            "pre-gate terminal bytes must be drained before opening ingress"
        );
        let output = match pump {
            TerminalPumpAuthority::OutputOnly(pump) => pump.output,
            _ => panic!("output-only authority changed before the gate"),
        };
        pump = TerminalPumpAuthority::Duplex(Box::new(DuplexPump {
            output,
            input: TerminalBuffer::new(),
        }));
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Idle)
        );
        assert_eq!(tui.input_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn terminal_exit_drain_destroys_ingress_and_mints_natural_cause_only_on_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        send_terminal(&coordinator, b"must-not-reach-tui")?;

        let tui = FakeGuardianTui::with_output([
            FakeTuiOutput::Data(b"last-output"),
            FakeTuiOutput::EndOfStream,
        ]);
        let mut pump = duplex_pump();
        assert_eq!(begin_terminal_output_drain(&mut pump), Ok(()));
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Output)
        );
        assert_eq!(tui.input_calls.get(), 0);

        let eof = pump_guardian_terminal_once(
            &tui,
            &guardian,
            &mut pump,
            Instant::now() + Duration::from_secs(1),
        );
        let mut cause = None;
        assert_eq!(
            apply_guardian_pump_result(&mut pump, &mut cause, eof),
            Ok(TerminalPumpProgress::TuiOutputClosed)
        );
        assert_eq!(cause, Some(SessionTerminationCause::NaturalTuiEof));
        assert_eq!(tui.input_calls.get(), 0);

        let mut output = TerminalBuffer::new();
        assert!(matches!(
            coordinator.read_into(&mut output)?,
            TerminalRead::Data(chunk) if chunk.matches(b"last-output")
        ));
        let mut untouched_input = TerminalBuffer::new();
        assert!(matches!(
            guardian.read_into(&mut untouched_input)?,
            TerminalRead::Data(chunk) if chunk.matches(b"must-not-reach-tui")
        ));
        Ok(())
    }

    #[test]
    fn guardian_duplex_pump_retries_would_block_and_treats_channel_eof_as_fatal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        coordinator.enable_nonblocking()?;
        guardian.enable_nonblocking()?;
        send_terminal(&coordinator, b"typed-input")?;

        let tui = FakeGuardianTui::expecting_input(b"typed-input", true);
        let mut pump = duplex_pump();
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::Input)
        );
        assert_eq!(tui.input_calls.get(), 2);
        assert!(tui.matched_input.get());

        coordinator.shutdown(TerminalShutdown::Write)?;
        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(TerminalPumpFailure::TerminalChannelEof)
        );
        Ok(())
    }

    #[test]
    fn raw_guardian_pump_distinguishes_tui_eof_from_read_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        for (output, expected) in [
            (
                FakeTuiOutput::EndOfStream,
                TerminalPumpFailure::TuiOutputEof,
            ),
            (FakeTuiOutput::Error, TerminalPumpFailure::TuiRead),
        ] {
            let (_coordinator, guardian) =
                super::super::terminal::TerminalChannelPair::new()?.split();
            guardian.enable_nonblocking()?;
            let tui = FakeGuardianTui::with_output([output]);
            let mut pump = TerminalPumpAuthority::OutputOnly(Box::new(OutputOnlyPump {
                output: TerminalBuffer::new(),
            }));
            assert_eq!(
                pump_guardian_terminal_once(
                    &tui,
                    &guardian,
                    &mut pump,
                    Instant::now() + Duration::from_secs(1),
                ),
                Err(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn observed_tui_output_close_is_sticky_and_has_no_input_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_coordinator, guardian) = super::super::terminal::TerminalChannelPair::new()?.split();
        guardian.enable_nonblocking()?;
        let tui = FakeGuardianTui::with_output([FakeTuiOutput::Error]);
        let mut pump = TerminalPumpAuthority::OutputClosed;

        assert_eq!(
            pump_guardian_terminal_once(
                &tui,
                &guardian,
                &mut pump,
                Instant::now() + Duration::from_secs(1),
            ),
            Ok(TerminalPumpProgress::TuiOutputClosed)
        );
        assert_eq!(tui.input_calls.get(), 0);
        assert!(matches!(pump, TerminalPumpAuthority::OutputClosed));
        Ok(())
    }

    #[test]
    fn tui_output_eof_destroys_ingress_and_records_natural_shutdown_cause() {
        let mut pump = duplex_pump();
        let mut cause = None;

        assert_eq!(
            apply_guardian_pump_result(
                &mut pump,
                &mut cause,
                Err(TerminalPumpFailure::TuiOutputEof),
            ),
            Ok(TerminalPumpProgress::TuiOutputClosed)
        );
        assert!(matches!(pump, TerminalPumpAuthority::OutputClosed));
        assert_eq!(cause, Some(SessionTerminationCause::NaturalTuiEof));

        assert_eq!(
            apply_guardian_pump_result(
                &mut pump,
                &mut cause,
                Err(TerminalPumpFailure::TerminalChannelEof),
            ),
            Err(TerminalPumpFailure::TerminalChannelEof)
        );
        assert!(matches!(
            pump,
            TerminalPumpAuthority::Failed(TerminalPumpFailure::TerminalChannelEof)
        ));
    }

    #[test]
    fn stale_input_discard_is_bounded_by_deadline_and_fragment_budget() {
        let flooded = FloodedTerminalInput {
            reads: Cell::new(0),
        };
        assert_eq!(
            discard_terminal_input_before(&flooded, Instant::now() + Duration::from_secs(1)),
            Err(TerminalPumpFailure::Deadline)
        );
        assert_eq!(flooded.reads.get(), TERMINAL_DISCARD_MAX_FRAGMENTS);

        let unread = FloodedTerminalInput {
            reads: Cell::new(0),
        };
        assert_eq!(
            discard_terminal_input_before(&unread, Instant::now()),
            Err(TerminalPumpFailure::Deadline)
        );
        assert_eq!(unread.reads.get(), 0);
    }

    #[test]
    fn every_gate_checkpoint_rechecks_all_components_in_dependency_order() {
        let ready = match assembled(FakeComponents::healthy())
            .check_before_ready(FakeComponents::deadline())
        {
            Ok(ready) => ready,
            Err(_) => panic!("READY checkpoint must be healthy"),
        };
        let active: SessionState<_, ActiveIngress> = match fake_checkpoint(ready) {
            Ok(active) => active,
            Err(_) => panic!("OPEN_GATE checkpoint must be healthy"),
        };
        let suspended: SessionState<_, SuspendedIngress> = active.transition();
        let active: SessionState<_, ActiveIngress> = match fake_checkpoint(suspended) {
            Ok(active) => active,
            Err(_) => panic!("post-CONT checkpoint must be healthy"),
        };

        assert_eq!(
            active.components.observations,
            [
                Observation::MonitorAndApp,
                Observation::Relay,
                Observation::Tui,
                Observation::MonitorAndApp,
                Observation::Relay,
                Observation::Tui,
                Observation::MonitorAndApp,
                Observation::Relay,
                Observation::Tui,
            ]
        );
    }

    #[test]
    fn component_loss_returns_the_exact_prior_typed_owner() {
        let ready = match assembled(FakeComponents::healthy())
            .check_before_ready(FakeComponents::deadline())
        {
            Ok(ready) => ready,
            Err(_) => panic!("initial liveness must succeed"),
        };
        let mut ready = ready;
        ready.components.fail = Some(SessionComponent::ReadinessRelay);

        let failure = match fake_checkpoint::<_, ActiveIngress>(ready) {
            Err(failure) => failure,
            Ok(_) => panic!("relay loss must keep ingress closed"),
        };
        assert_eq!(
            failure.error(),
            SessionOperationError::Component(SessionComponent::ReadinessRelay)
        );
        let retained = failure.into_session();
        assert_eq!(
            retained.components.observations,
            [
                Observation::MonitorAndApp,
                Observation::Relay,
                Observation::Tui,
                Observation::MonitorAndApp,
                Observation::Relay,
            ]
        );
    }

    #[test]
    fn only_relay_transport_enters_bounded_tui_exit_correlation() {
        let relay_error = SessionOperationError::Component(SessionComponent::ReadinessRelay);
        let proxy_errors = [
            ReadinessProxyError::InvalidArgument,
            ReadinessProxyError::Bind,
            ReadinessProxyError::Accept,
            ReadinessProxyError::Connect,
            ReadinessProxyError::HandshakeTooLarge,
            ReadinessProxyError::InvalidHandshake,
            ReadinessProxyError::FrameTooLarge,
            ReadinessProxyError::InvalidFrame,
            ReadinessProxyError::InvalidMessage,
            ReadinessProxyError::UnexpectedSequence,
            ReadinessProxyError::TargetMismatch,
            ReadinessProxyError::Timeout,
            ReadinessProxyError::Transport,
            ReadinessProxyError::Worker,
            ReadinessProxyError::Cleanup,
        ];
        for error in proxy_errors {
            assert_eq!(
                SessionLivenessError::relay(error).relay_transport,
                error == ReadinessProxyError::Transport
            );
        }

        let failure = Box::new(SessionLivenessFailure {
            session: assembled(FakeComponents::healthy()),
            error: SessionLivenessError::relay(ReadinessProxyError::Transport),
        });
        let session = match failure.into_relay_transport_session() {
            Ok(session) => session,
            Err(failure) => {
                assert_eq!(failure.error(), relay_error);
                panic!("a transport EOF may enter only the caller's bounded drain");
            }
        };
        assert!(session.components.observations.is_empty());

        let result = Box::new(SessionLivenessFailure {
            session: assembled(FakeComponents::healthy()),
            error: SessionLivenessError::relay(ReadinessProxyError::Worker),
        })
        .into_relay_transport_session();
        let failure = match result {
            Err(failure) => failure,
            Ok(session) => {
                assert!(session.components.observations.is_empty());
                panic!("a non-transport relay failure must remain immediately fatal");
            }
        };
        assert_eq!(failure.error(), relay_error);
        assert!(failure.session.components.observations.is_empty());
    }

    #[test]
    fn only_tui_not_live_is_a_direct_exit_observation() {
        assert!(SessionLivenessError::tui(RemoteTuiLauncherError::NotLive).tui_exited);
        for error in [
            RemoteTuiLauncherError::InvalidCommand,
            RemoteTuiLauncherError::LauncherUnavailable,
            RemoteTuiLauncherError::Exec,
        ] {
            assert!(!SessionLivenessError::tui(error).tui_exited);
        }
    }

    #[test]
    fn natural_tui_eof_suppresses_only_its_correlated_relay_transport_error() {
        let relay_error = Some(SessionOperationError::Component(
            SessionComponent::ReadinessRelay,
        ));
        assert_eq!(
            relay_shutdown_operation_error(
                Some(SessionTerminationCause::NaturalTuiEof),
                Some(ReadinessProxyError::Transport),
            ),
            None
        );
        assert_eq!(
            relay_shutdown_operation_error(
                Some(SessionTerminationCause::CoordinatorStop),
                Some(ReadinessProxyError::Transport),
            ),
            relay_error
        );
        assert_eq!(
            relay_shutdown_operation_error(
                Some(SessionTerminationCause::NaturalTuiEof),
                Some(ReadinessProxyError::Timeout),
            ),
            relay_error
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn same_profile_admission_failure_retains_b_until_the_failure_owner_is_dropped()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "calcifer-session-direct-b-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let registry = Registry::at(root.clone());
        let pending = registry.begin_codex_registration("work")?;
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
        let coordinator = registry.lock_profile_coordinator(&profile)?;

        let cases = [
            (
                Path::new("relative-cwd"),
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            (root.as_path(), "not-a-thread-uuid"),
        ];
        for (working_directory, thread_id) in cases {
            let failure = match admit_same_profile_guardian_session(
                &registry,
                &profile,
                working_directory,
                thread_id,
            ) {
                Err(failure) => failure,
                Ok(_) => return Err("invalid provider spec minted guardian authority".into()),
            };
            assert!(matches!(
                failure.as_ref(),
                SameProfileAdmissionFailure::Provider(_)
            ));
            assert!(matches!(
                registry.lock_profile_provider(&profile),
                Err(ProfileError::Busy(_))
            ));

            drop(failure);
            drop(registry.lock_profile_provider(&profile)?);
        }

        drop(coordinator);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[derive(Debug)]
    struct FakeShutdown {
        calls: Vec<ShutdownPhase>,
        retain_once_at: Option<ShutdownPhase>,
        retained_marker: bool,
        later_cleanup_error: Option<ShutdownPhase>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct FakeShutdownComplete {
        calls: Vec<ShutdownPhase>,
        errors: SessionErrors,
        retained_marker: bool,
    }

    impl OrderedShutdownBackend for FakeShutdown {
        type Complete = FakeShutdownComplete;

        fn shutdown_step(
            &mut self,
            phase: ShutdownPhase,
            _bounds: SessionShutdownBounds,
        ) -> ShutdownStep {
            self.calls.push(phase);
            if self.retain_once_at == Some(phase) {
                self.retain_once_at = None;
                self.retained_marker = true;
                return ShutdownStep::retained(
                    Some(SessionOperationError::Component(
                        SessionComponent::ReadinessRelay,
                    )),
                    Some(SessionCleanupError::ReadinessRelay),
                );
            }
            if self.later_cleanup_error == Some(phase) {
                self.later_cleanup_error = None;
                return ShutdownStep::advanced_with(None, Some(SessionCleanupError::PinnedBuild));
            }
            ShutdownStep::advanced()
        }

        fn finish(self, errors: SessionErrors) -> Self::Complete {
            FakeShutdownComplete {
                calls: self.calls,
                errors,
                retained_marker: self.retained_marker,
            }
        }
    }

    fn shutdown_bounds() -> SessionShutdownBounds {
        SessionShutdownBounds {
            tui_grace: Duration::from_millis(10),
            tui_forced: Duration::from_millis(10),
            relay_timeout: Duration::from_secs(1),
            monitor_timeout: Duration::from_secs(1),
            app_grace: Duration::from_millis(10),
            app_forced: Duration::from_millis(10),
            app_cleanup_timeout: Duration::from_secs(1),
            build_cleanup_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn sequential_shutdown_phases_each_derive_a_fresh_deadline() {
        let bounds = shutdown_bounds();
        let first_phase_started = Instant::now();
        let later_phase_started = first_phase_started + Duration::from_secs(30);

        assert_eq!(
            bounds.relay_deadline_at(first_phase_started),
            first_phase_started + bounds.relay_timeout
        );
        assert_eq!(
            bounds.monitor_deadline_at(later_phase_started),
            later_phase_started + bounds.monitor_timeout
        );
        assert_eq!(
            bounds.app_cleanup_deadline_at(later_phase_started),
            later_phase_started + bounds.app_cleanup_timeout
        );
        assert_eq!(
            bounds.build_cleanup_deadline_at(later_phase_started),
            later_phase_started + bounds.build_cleanup_timeout
        );
        assert!(
            bounds.monitor_deadline_at(later_phase_started)
                > bounds.relay_deadline_at(first_phase_started),
            "a later phase must not inherit an absolute deadline armed before earlier work"
        );

        let overflow = SessionShutdownBounds {
            relay_timeout: Duration::MAX,
            monitor_timeout: Duration::MAX,
            app_cleanup_timeout: Duration::MAX,
            build_cleanup_timeout: Duration::MAX,
            ..bounds
        };
        assert_eq!(
            overflow.relay_deadline_at(later_phase_started),
            later_phase_started
        );
        assert_eq!(
            overflow.app_cleanup_deadline_at(later_phase_started),
            later_phase_started,
            "deadline overflow must fail closed with an already-expired phase deadline"
        );
    }

    #[test]
    fn retained_stage_test_helpers_stop_before_shutdown_and_after_terminal_restore() {
        let operation_error = SessionOperationError::Component(SessionComponent::MonitorAndApp);
        let quiescing = RetainedShutdown::before_first_step_for_test(
            FakeShutdown {
                calls: Vec::new(),
                retain_once_at: None,
                retained_marker: false,
                later_cleanup_error: None,
            },
            Some(operation_error),
        );
        assert_eq!(quiescing.shutdown.phase, ShutdownPhase::Quiesce);
        assert_eq!(quiescing.shutdown.errors.operation, Some(operation_error));
        assert!(quiescing.shutdown.errors.cleanup.is_empty());
        assert!(quiescing.shutdown.backend.calls.is_empty());
        assert_eq!(
            session_shutdown_recovery_stage(quiescing.shutdown.phase),
            SessionShutdownRecoveryStage::Quiescing
        );

        assert_eq!(
            session_shutdown_recovery_stage(ShutdownPhase::TerminalRestore),
            SessionShutdownRecoveryStage::RestorePending
        );
        let restore_pending = RetainedShutdown {
            shutdown: OrderedShutdown {
                backend: FakeShutdown {
                    calls: Vec::new(),
                    retain_once_at: None,
                    retained_marker: false,
                    later_cleanup_error: None,
                },
                phase: ShutdownPhase::TerminalRestore,
                errors: SessionErrors {
                    operation: Some(operation_error),
                    cleanup: SessionCleanupErrors::default(),
                },
            },
        };
        let cleanup_pending =
            match restore_pending.advance_terminal_restore_one_step_for_test(shutdown_bounds()) {
                Ok(retained) => retained,
                Err(_) => panic!("an acknowledged terminal restore must advance exactly once"),
            };
        assert_eq!(
            cleanup_pending.shutdown.phase,
            ShutdownPhase::RecoveryDisarm
        );
        assert_eq!(
            session_shutdown_recovery_stage(cleanup_pending.shutdown.phase),
            SessionShutdownRecoveryStage::CleanupPending
        );
        assert_eq!(
            cleanup_pending.shutdown.backend.calls,
            [ShutdownPhase::TerminalRestore]
        );
        assert_eq!(
            cleanup_pending.shutdown.errors.operation,
            Some(operation_error)
        );
        assert!(cleanup_pending.shutdown.errors.cleanup.is_empty());
    }

    #[test]
    fn retained_stage_test_trigger_routes_cause_through_acceptance_only() {
        let mut accepted = None;
        let operation_error = apply_session_shutdown_test_trigger(
            SessionShutdownTestTrigger::Cause(SessionTerminationCause::CoordinatorStop),
            |cause| {
                accepted = Some(cause);
                Ok(())
            },
        );
        assert_eq!(accepted, Some(SessionTerminationCause::CoordinatorStop));
        assert_eq!(operation_error, None);

        let failure = SessionOperationError::Component(SessionComponent::MonitorAndApp);
        let operation_error = apply_session_shutdown_test_trigger(
            SessionShutdownTestTrigger::Failure(failure),
            |_| panic!("a failure trigger must not synthesize a termination cause"),
        );
        assert_eq!(operation_error, Some(failure));
    }

    #[test]
    fn cleanup_pending_test_helper_rejects_non_restore_stage_without_running_a_step() {
        let quiescing = RetainedShutdown::before_first_step_for_test(
            FakeShutdown {
                calls: Vec::new(),
                retain_once_at: None,
                retained_marker: false,
                later_cleanup_error: None,
            },
            None,
        );
        let quiescing =
            match quiescing.advance_terminal_restore_one_step_for_test(shutdown_bounds()) {
                Err(retained) => retained,
                Ok(_) => panic!("only RestorePending may advance to CleanupPending"),
            };
        assert_eq!(quiescing.shutdown.phase, ShutdownPhase::Quiesce);
        assert!(quiescing.shutdown.backend.calls.is_empty());
    }

    #[test]
    fn shutdown_is_ordered_and_timeout_returns_the_same_phase_owner() {
        let backend = FakeShutdown {
            calls: Vec::new(),
            retain_once_at: Some(ShutdownPhase::ReadinessRelay),
            retained_marker: false,
            later_cleanup_error: None,
        };
        let failure = match OrderedShutdown::new(backend, None).run(shutdown_bounds()) {
            Err(failure) => failure,
            Ok(_) => panic!("relay timeout must retain shutdown authority"),
        };
        assert_eq!(
            failure.shutdown.backend.calls,
            [
                ShutdownPhase::Quiesce,
                ShutdownPhase::Tui,
                ShutdownPhase::ReadinessRelay,
            ]
        );
        assert!(failure.shutdown.backend.retained_marker);

        let complete = match failure.retry(shutdown_bounds()) {
            Ok(complete) => complete,
            Err(_) => panic!("the retained relay owner must be retryable"),
        };
        assert_eq!(
            complete.calls,
            [
                ShutdownPhase::Quiesce,
                ShutdownPhase::Tui,
                ShutdownPhase::ReadinessRelay,
                ShutdownPhase::ReadinessRelay,
                ShutdownPhase::Monitor,
                ShutdownPhase::AppServerStop,
                ShutdownPhase::TerminalRestore,
                ShutdownPhase::RecoveryDisarm,
                ShutdownPhase::RuntimeCleanup,
                ShutdownPhase::PinnedBuild,
            ]
        );
        assert!(complete.retained_marker);
    }

    #[test]
    fn operation_and_cleanup_errors_survive_successful_later_retries_independently() {
        let original = SessionOperationError::Component(SessionComponent::MonitorAndApp);
        let backend = FakeShutdown {
            calls: Vec::new(),
            retain_once_at: Some(ShutdownPhase::ReadinessRelay),
            retained_marker: false,
            later_cleanup_error: Some(ShutdownPhase::PinnedBuild),
        };
        let failure = match OrderedShutdown::new(backend, Some(original)).run(shutdown_bounds()) {
            Err(failure) => failure,
            Ok(_) => panic!("first relay cleanup attempt must be retained"),
        };
        assert_eq!(failure.operation_error(), Some(original));
        assert!(
            failure
                .cleanup_errors()
                .contains(SessionCleanupError::ReadinessRelay)
        );

        let complete = match failure.retry(shutdown_bounds()) {
            Ok(complete) => complete,
            Err(_) => panic!("later cleanup must complete"),
        };
        assert_eq!(complete.errors.operation, Some(original));
        assert!(
            complete
                .errors
                .cleanup
                .contains(SessionCleanupError::ReadinessRelay)
        );
        assert!(
            complete
                .errors
                .cleanup
                .contains(SessionCleanupError::PinnedBuild)
        );
    }
}
