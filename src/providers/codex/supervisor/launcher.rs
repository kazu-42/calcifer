//! Feature-gated exec launcher for the official Codex remote TUI.
//!
//! Codex itself does not create a session or claim a controlling terminal.
//! This reviewed, single-purpose launcher does exactly that before replacing
//! itself with the already-verified remote-TUI command. Its argv and command
//! schema are closed; it cannot run a prompt, shell, or caller-supplied CLI.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::process::{
    ChildLiveness, ContainmentMetadata, ForwardedTuiSignal, InheritedTuiReadiness,
    InteractiveTerminalSignal, ManagedGroupChild, ProcessError, ShutdownOutcome, SpawnCleanupProof,
    SpawnFailure, SpawnFailureState, TerminalShutdownSignal, TuiReadinessError,
    TuiReadinessReceiver, UnreapedChildren, VerifiedTuiReadiness,
    shutdown_tui_after_forwarded_signal_with_output_progress,
    shutdown_tui_after_output_eof_with_output_progress, shutdown_tui_child_with_output_progress,
    tui_readiness_pair,
};
use super::protocol::ChildRole;
use super::provider::{PinnedSessionBuild, ProviderLaunchError, SessionRuntimeGuard};
use super::terminal::{
    PtyMaster, PtyOwner, TerminalBuffer, TerminalChunk, TerminalError, TerminalRead, TerminalSize,
    TerminalWrite, claim_controlling_terminal_from_stdin, terminal_size,
    verify_controlling_terminal_from_stdin,
};

const LAUNCH_CONTRACT_ENV: &str = "CALCIFER_INTERNAL_TUI_LAUNCH_CONTRACT";
const TARGET_PROGRAM_ENV: &str = "CALCIFER_INTERNAL_TUI_TARGET_PROGRAM";
const TARGET_SOCKET_ENV: &str = "CALCIFER_INTERNAL_TUI_TARGET_SOCKET";
const TARGET_THREAD_ENV: &str = "CALCIFER_INTERNAL_TUI_TARGET_THREAD";
const LAUNCH_CONTRACT_V1: &str = "codex-remote-tui-v1";
const CLI_CREDENTIALS_OVERRIDE: &str = r#"cli_auth_credentials_store="file""#;
const MCP_CREDENTIALS_OVERRIDE: &str = r#"mcp_oauth_credentials_store="file""#;
const MAX_EXECUTABLE_BYTES: usize = 4_096;
const MAX_SOCKET_BYTES: usize = 110;
const FIXTURE_TARGET_ENV: &str = "CALCIFER_INTERNAL_TUI_FIXTURE_TARGET";
const FIXTURE_EXPECTED_READINESS_ENV: &str = "CALCIFER_INTERNAL_TUI_FIXTURE_EXPECTED_READINESS";
const FIXTURE_AMBIENT_ENV_CANARY: &str = "CALCIFER_INTERNAL_TUI_FIXTURE_AMBIENT_CANARY";
const FIXTURE_ENVIRONMENT_TARGET_ENV: &str = "CFX_FIXTURE_ENVIRONMENT_TARGET";
const FIXTURE_ENVIRONMENT_NONCE_ENV: &str = "CFX_FIXTURE_ENVIRONMENT_NONCE";
const FIXTURE_ENVIRONMENT_EXPECTED_ENV: &str = "CFX_FIXTURE_ENVIRONMENT_EXPECTED";
const FIXTURE_SAFE_AMBIENT_ENV: &str = "SAFE_AMBIENT_CONTEXT";
const FIXTURE_SOCKET: &str = "unix:///tmp/calcifer-launcher-fixture.sock";
const FIXTURE_THREAD: &str = "123e4567-e89b-42d3-a456-426614174000";
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(3);
const FIXTURE_POLL: Duration = Duration::from_millis(10);
const FIXTURE_VERIFIED_BYTE: u8 = b'V';
const TUI_SHUTDOWN_DRAIN_MAX_FRAGMENTS_PER_POLL: usize = 16;
#[cfg(test)]
const PACKAGED_TUI_LAUNCHER_ENV: &str = "CALCIFER_PACKAGE_TUI_LAUNCHER";

/// Fixed, non-sensitive launcher failure. Command paths, provider output,
/// environment values, readiness bytes, and terminal payloads are omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RemoteTuiLauncherError {
    InvalidCommand,
    LauncherUnavailable,
    Terminal(TerminalError),
    Readiness(TuiReadinessError),
    Provider(ProviderLaunchError),
    Process(ProcessError),
    DescriptorIsolation(calcifer_unix_child_fd::ProcessGroupDescriptorScanError),
    NotLive,
    Exec,
}

impl fmt::Display for RemoteTuiLauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "the remote TUI launch command was invalid",
            Self::LauncherUnavailable => "the internal TUI launcher was unavailable",
            Self::Terminal(_) => "the TUI launcher terminal setup failed",
            Self::Readiness(_) => "the TUI launcher readiness proof failed",
            Self::Provider(_) => "the verified TUI launch inputs changed",
            Self::Process(_) => "the TUI launcher process failed",
            Self::DescriptorIsolation(_) => "the TUI descriptor isolation proof failed",
            Self::NotLive => "the TUI is no longer live",
            Self::Exec => "the TUI launcher could not exec Codex",
        })
    }
}

impl std::error::Error for RemoteTuiLauncherError {}

impl From<TerminalError> for RemoteTuiLauncherError {
    fn from(error: TerminalError) -> Self {
        Self::Terminal(error)
    }
}

impl From<TuiReadinessError> for RemoteTuiLauncherError {
    fn from(error: TuiReadinessError) -> Self {
        Self::Readiness(error)
    }
}

impl From<ProviderLaunchError> for RemoteTuiLauncherError {
    fn from(error: ProviderLaunchError) -> Self {
        Self::Provider(error)
    }
}

impl From<ProcessError> for RemoteTuiLauncherError {
    fn from(error: ProcessError) -> Self {
        Self::Process(error)
    }
}

/// Provider-verified command plus the exact pinned session it borrows.
///
/// Only `provider.rs` can construct this after its final session/executable
/// revalidation. The raw [`Command`] never crosses into a public API.
#[must_use = "the verified remote TUI command must be launched or deliberately dropped"]
pub(super) struct RemoteTuiLaunchCommand<'build> {
    command: Command,
    build: &'build PinnedSessionBuild,
}

impl<'build> RemoteTuiLaunchCommand<'build> {
    pub(super) fn from_verified(command: Command, build: &'build PinnedSessionBuild) -> Self {
        Self { command, build }
    }

    /// Completes every potentially expensive provider and launcher check
    /// before the caller arms the relay's absolute readiness deadline.
    ///
    /// The returned typestate is independent of the borrowed build, but its
    /// runtime guard prevents the pinned stage from being cleaned while the
    /// prepared command is waiting to cross the process boundary.
    pub(super) fn prepare(
        self,
        deadline: Instant,
    ) -> Result<PreparedRemoteTuiLaunch<'build>, Box<RemoteTuiLaunchFailure>> {
        let runtime_guard = self.build.retain_runtime();
        if let Err(error) = self.build.revalidate_remote_tui_launch(deadline) {
            return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                error.into(),
                runtime_guard,
            )));
        }
        let launcher = match current_launcher_executable() {
            Ok(launcher) => launcher,
            Err(error) => {
                return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                    error,
                    runtime_guard,
                )));
            }
        };
        let launcher_identity = match LauncherExecutableIdentity::capture(&launcher) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                    error,
                    runtime_guard,
                )));
            }
        };
        let command = match prepare_launcher_command(&self.command, &launcher) {
            Ok(command) => command,
            Err(error) => {
                return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                    error,
                    runtime_guard,
                )));
            }
        };
        Ok(PreparedRemoteTuiLaunch {
            command,
            build: self.build,
            launcher_identity,
            runtime_guard,
        })
    }
}

impl fmt::Debug for RemoteTuiLaunchCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.command, self.build);
        formatter.write_str("RemoteTuiLaunchCommand(<redacted>)")
    }
}

/// A fully validated remote-TUI launch whose remaining work is limited to
/// fresh PTY/readiness setup and the direct-child spawn boundary.
///
/// This value intentionally has no borrow back into [`PinnedSessionBuild`].
/// Its runtime guard makes an attempted concurrent build cleanup fail closed.
#[must_use = "the prepared remote TUI launch must be spawned or deliberately dropped"]
pub(super) struct PreparedRemoteTuiLaunch<'build> {
    command: Command,
    build: &'build PinnedSessionBuild,
    launcher_identity: LauncherExecutableIdentity,
    runtime_guard: SessionRuntimeGuard,
}

impl PreparedRemoteTuiLaunch<'_> {
    /// Attaches a fresh PTY, gives only the launcher the one-shot readiness
    /// descriptor, and publishes no child until PID=PGID=SID is read back.
    /// No executable hashing or provider-input validation occurs here. The
    /// fixed relay deadline therefore spends its remaining window on process
    /// launch and readiness rather than storage throughput.
    pub(super) fn launch(
        self,
        pty: PtyOwner,
        deadline: Instant,
    ) -> Result<PendingRemoteTui, Box<RemoteTuiLaunchFailure>> {
        let Self {
            mut command,
            build,
            launcher_identity,
            runtime_guard,
        } = self;
        let (readiness, sender) = match tui_readiness_pair() {
            Ok(pair) => pair,
            Err(error) => {
                return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                    error.into(),
                    runtime_guard,
                )));
            }
        };
        let master = match pty.configure_child(&mut command) {
            Ok(master) => master,
            Err(error) => {
                return Err(Box::new(RemoteTuiLaunchFailure::before_spawn(
                    error.into(),
                    runtime_guard,
                )));
            }
        };
        if let Err(error) = build.revalidate_remote_tui_spawn_identity(deadline) {
            return Err(Box::new(RemoteTuiLaunchFailure {
                kind: RemoteTuiLaunchFailureKind::BeforeSpawn(error.into()),
                master: Some(master),
                runtime_guard,
            }));
        }
        if let Err(error) = launcher_identity.revalidate() {
            return Err(Box::new(RemoteTuiLaunchFailure {
                kind: RemoteTuiLaunchFailureKind::BeforeSpawn(error),
                master: Some(master),
                runtime_guard,
            }));
        }
        let child = match ManagedGroupChild::spawn_session_leader_with_inherited_fd(
            ChildRole::Tui,
            command,
            sender.as_fd(),
            deadline,
        ) {
            Ok(child) => child,
            Err(failure) => {
                return Err(Box::new(RemoteTuiLaunchFailure {
                    kind: RemoteTuiLaunchFailureKind::Spawn(failure),
                    master: Some(master),
                    runtime_guard,
                }));
            }
        };
        drop(sender);
        Ok(PendingRemoteTui {
            child,
            master,
            readiness,
            runtime_guard,
        })
    }
}

impl fmt::Debug for PreparedRemoteTuiLaunch<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.command,
            self.build,
            &self.launcher_identity,
            &self.runtime_guard,
        );
        formatter.write_str("PreparedRemoteTuiLaunch(<redacted>)")
    }
}

enum RemoteTuiLaunchFailureKind {
    BeforeSpawn(RemoteTuiLauncherError),
    Spawn(SpawnFailure),
}

/// Launch failure retaining both pinned-session lifetime and any direct child.
#[must_use = "a launcher spawn failure can retain direct-child wait authority"]
pub(super) struct RemoteTuiLaunchFailure {
    kind: RemoteTuiLaunchFailureKind,
    master: Option<PtyMaster>,
    runtime_guard: SessionRuntimeGuard,
}

impl RemoteTuiLaunchFailure {
    fn before_spawn(error: RemoteTuiLauncherError, runtime_guard: SessionRuntimeGuard) -> Self {
        Self {
            kind: RemoteTuiLaunchFailureKind::BeforeSpawn(error),
            master: None,
            runtime_guard,
        }
    }

    pub(super) fn error(&self) -> RemoteTuiLauncherError {
        match &self.kind {
            RemoteTuiLaunchFailureKind::BeforeSpawn(error) => *error,
            RemoteTuiLaunchFailureKind::Spawn(failure) => {
                RemoteTuiLauncherError::Process(failure.error())
            }
        }
    }

    /// Returns only fixed, redacted package-test marker names. The launch
    /// authority state is reported independently from the error subtype so a
    /// pre-spawn validation failure can never be confused with an
    /// unannounced child that still requires exact containment.
    #[cfg(test)]
    pub(super) fn packaged_classification(&self) -> PackagedRemoteTuiLaunchFailureClassification {
        let spawn_state = match &self.kind {
            RemoteTuiLaunchFailureKind::BeforeSpawn(_) => None,
            RemoteTuiLaunchFailureKind::Spawn(failure) => Some(failure.state()),
        };
        PackagedRemoteTuiLaunchFailureClassification {
            state_marker: packaged_launch_failure_state_marker(spawn_state),
            subtype_marker: packaged_tui_launch_error_marker(self.error()),
        }
    }

    /// Resolves an unannounced child exactly before releasing PTY and session
    /// authority. A timeout returns the same authority for retry.
    #[expect(
        clippy::boxed_local,
        reason = "the launch API deliberately returns a boxed linear failure owner"
    )]
    pub(super) fn resolve(
        self: Box<Self>,
        deadline: Instant,
    ) -> Result<RemoteTuiLaunchResolution, Box<Self>> {
        let Self {
            kind,
            master,
            runtime_guard,
        } = *self;
        match kind {
            RemoteTuiLaunchFailureKind::BeforeSpawn(_) => Ok(RemoteTuiLaunchResolution {
                cleanup: None,
                master,
                runtime_guard,
            }),
            RemoteTuiLaunchFailureKind::Spawn(failure) => match failure.cleanup(deadline) {
                Ok(cleanup) => Ok(RemoteTuiLaunchResolution {
                    cleanup: Some(cleanup),
                    master,
                    runtime_guard,
                }),
                Err(failure) => Err(Box::new(Self {
                    kind: RemoteTuiLaunchFailureKind::Spawn(failure),
                    master,
                    runtime_guard,
                })),
            },
        }
    }
}

/// Test-only, path-free diagnostic projection for the official-package E2E.
///
/// Both values come from closed enum matches below; neither can contain a
/// provider payload, command, path, PID, descriptor number, or OS error text.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PackagedRemoteTuiLaunchFailureClassification {
    state_marker: &'static str,
    subtype_marker: &'static str,
}

#[cfg(test)]
impl PackagedRemoteTuiLaunchFailureClassification {
    pub(super) const fn state_marker(self) -> &'static str {
        self.state_marker
    }

    pub(super) const fn subtype_marker(self) -> &'static str {
        self.subtype_marker
    }
}

#[cfg(test)]
const fn packaged_launch_failure_state_marker(
    spawn_state: Option<SpawnFailureState>,
) -> &'static str {
    match spawn_state {
        None => "startup-failure.tui-launch.state.before-spawn",
        Some(SpawnFailureState::NotStarted) => "startup-failure.tui-launch.state.spawn-not-started",
        Some(SpawnFailureState::ReapedUnannounced) => {
            "startup-failure.tui-launch.state.started-unannounced-reaped"
        }
        Some(SpawnFailureState::LiveUnannouncedChild) => {
            "startup-failure.tui-launch.state.started-unannounced-live"
        }
    }
}

#[cfg(test)]
const fn packaged_tui_launch_error_marker(error: RemoteTuiLauncherError) -> &'static str {
    match error {
        RemoteTuiLauncherError::InvalidCommand => {
            "startup-failure.tui-launch.subtype.invalid-command"
        }
        RemoteTuiLauncherError::LauncherUnavailable => {
            "startup-failure.tui-launch.subtype.launcher-unavailable"
        }
        RemoteTuiLauncherError::Terminal(_) => "startup-failure.tui-launch.subtype.terminal",
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Channel) => {
            "startup-failure.tui-launch.subtype.readiness-channel"
        }
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Descriptor) => {
            "startup-failure.tui-launch.subtype.readiness-descriptor"
        }
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Inherited) => {
            "startup-failure.tui-launch.subtype.readiness-inherited"
        }
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Invalid) => {
            "startup-failure.tui-launch.subtype.readiness-invalid"
        }
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Timeout) => {
            "startup-failure.tui-launch.subtype.readiness-timeout"
        }
        RemoteTuiLauncherError::Readiness(TuiReadinessError::Deadline) => {
            "startup-failure.tui-launch.subtype.readiness-deadline"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::InvalidArgument) => {
            "startup-failure.tui-launch.subtype.provider-invalid-argument"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::AuthorityConsumed) => {
            "startup-failure.tui-launch.subtype.provider-authority-consumed"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::SessionInUse) => {
            "startup-failure.tui-launch.subtype.provider-session-in-use"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::ExecutableChanged) => {
            "startup-failure.tui-launch.subtype.provider-executable-changed"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::SessionChanged) => {
            "startup-failure.tui-launch.subtype.provider-session-changed"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::Storage) => {
            "startup-failure.tui-launch.subtype.provider-storage"
        }
        RemoteTuiLauncherError::Provider(ProviderLaunchError::Timeout) => {
            "startup-failure.tui-launch.subtype.provider-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::Spawn { .. }) => {
            "startup-failure.tui-launch.subtype.process-spawn"
        }
        RemoteTuiLauncherError::Process(ProcessError::ProcessGroupReadback { .. }) => {
            "startup-failure.tui-launch.subtype.process-group-readback"
        }
        RemoteTuiLauncherError::Process(ProcessError::ProcessGroupMismatch { .. }) => {
            "startup-failure.tui-launch.subtype.process-group-mismatch"
        }
        RemoteTuiLauncherError::Process(ProcessError::SessionReadback { .. }) => {
            "startup-failure.tui-launch.subtype.process-session-readback"
        }
        RemoteTuiLauncherError::Process(ProcessError::SessionMismatch { .. }) => {
            "startup-failure.tui-launch.subtype.process-session-mismatch"
        }
        RemoteTuiLauncherError::Process(ProcessError::SessionStartupTimeout { .. }) => {
            "startup-failure.tui-launch.subtype.process-session-startup-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::SpawnCleanupTimeout { .. }) => {
            "startup-failure.tui-launch.subtype.process-spawn-cleanup-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::SpawnContainmentUnconfirmed { .. }) => {
            "startup-failure.tui-launch.subtype.process-spawn-containment-unconfirmed"
        }
        RemoteTuiLauncherError::Process(ProcessError::ReadinessUnavailable { .. }) => {
            "startup-failure.tui-launch.subtype.process-readiness-unavailable"
        }
        RemoteTuiLauncherError::Process(ProcessError::ParentLivenessUnavailable { .. }) => {
            "startup-failure.tui-launch.subtype.process-parent-liveness-unavailable"
        }
        RemoteTuiLauncherError::Process(ProcessError::ReadinessTimeout { .. }) => {
            "startup-failure.tui-launch.subtype.process-readiness-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::ReadinessIo { .. }) => {
            "startup-failure.tui-launch.subtype.process-readiness-io"
        }
        RemoteTuiLauncherError::Process(ProcessError::InvalidReadiness { .. }) => {
            "startup-failure.tui-launch.subtype.process-invalid-readiness"
        }
        RemoteTuiLauncherError::Process(ProcessError::EarlyExit { .. }) => {
            "startup-failure.tui-launch.subtype.process-early-exit"
        }
        RemoteTuiLauncherError::Process(ProcessError::Signal { .. }) => {
            "startup-failure.tui-launch.subtype.process-signal"
        }
        RemoteTuiLauncherError::Process(ProcessError::ForwardedSignalMismatch { .. }) => {
            "startup-failure.tui-launch.subtype.process-forwarded-signal-mismatch"
        }
        RemoteTuiLauncherError::Process(ProcessError::SuspendTimeout { .. }) => {
            "startup-failure.tui-launch.subtype.process-suspend-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::Wait { .. }) => {
            "startup-failure.tui-launch.subtype.process-wait"
        }
        RemoteTuiLauncherError::Process(ProcessError::WaitTimeout { .. }) => {
            "startup-failure.tui-launch.subtype.process-wait-timeout"
        }
        RemoteTuiLauncherError::Process(ProcessError::TuiOutputDrain { .. }) => {
            "startup-failure.tui-launch.subtype.process-tui-output-drain"
        }
        RemoteTuiLauncherError::Process(ProcessError::AppGracefulDrainUnconfirmed { .. }) => {
            "startup-failure.tui-launch.subtype.process-app-graceful-drain-unconfirmed"
        }
        RemoteTuiLauncherError::Process(ProcessError::RoleMismatch { .. }) => {
            "startup-failure.tui-launch.subtype.process-role-mismatch"
        }
        RemoteTuiLauncherError::Process(ProcessError::RetryAfterResolution) => {
            "startup-failure.tui-launch.subtype.process-retry-after-resolution"
        }
        RemoteTuiLauncherError::Process(ProcessError::Deadline) => {
            "startup-failure.tui-launch.subtype.process-deadline"
        }
        RemoteTuiLauncherError::DescriptorIsolation(_) => {
            "startup-failure.tui-launch.subtype.descriptor-isolation"
        }
        RemoteTuiLauncherError::NotLive => "startup-failure.tui-launch.subtype.not-live",
        RemoteTuiLauncherError::Exec => "startup-failure.tui-launch.subtype.exec",
    }
}

impl fmt::Debug for RemoteTuiLaunchFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.master, &self.runtime_guard);
        formatter
            .debug_struct("RemoteTuiLaunchFailure")
            .field("error", &self.error())
            .field("retains_session", &true)
            .finish_non_exhaustive()
    }
}

pub(super) struct RemoteTuiLaunchResolution {
    cleanup: Option<SpawnCleanupProof>,
    master: Option<PtyMaster>,
    runtime_guard: SessionRuntimeGuard,
}

impl RemoteTuiLaunchResolution {
    /// An unannounced child cannot be represented by the terminal lifecycle
    /// frame, even after its exact direct wait has been consumed. The caller
    /// must retain the session lease instead of projecting it as `NotStarted`.
    pub(super) const fn terminal_reportable(&self) -> bool {
        !matches!(self.cleanup, Some(cleanup) if cleanup.started_unannounced())
    }

    #[cfg(test)]
    pub(super) const fn started_child_for_test(&self) -> bool {
        self.cleanup.is_some()
    }
}

impl fmt::Debug for RemoteTuiLaunchResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.cleanup, &self.master, &self.runtime_guard);
        formatter.write_str("RemoteTuiLaunchResolution(<redacted>)")
    }
}

/// Spawned launcher before token+exec-EOF readiness is proven.
#[must_use = "pending TUI readiness must be resolved before input can open"]
pub(super) struct PendingRemoteTui {
    child: ManagedGroupChild,
    master: PtyMaster,
    readiness: TuiReadinessReceiver,
    runtime_guard: SessionRuntimeGuard,
}

impl PendingRemoteTui {
    /// Read-only identity published from the still-owned direct child handle.
    /// It carries no numeric signal authority.
    pub(super) const fn containment(&self) -> ContainmentMetadata {
        self.child.containment()
    }

    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        self.child
            .observe_forbidden_descriptors_absent(forbidden, deadline)
    }

    pub(super) fn await_ready(
        mut self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<ReadyRemoteTui, Box<RemoteTuiReadinessFailure>> {
        let proof = match self.readiness.receive(deadline) {
            Ok(proof) => proof,
            Err(error) => {
                return Err(Box::new(RemoteTuiReadinessFailure {
                    pending: self,
                    error: error.into(),
                }));
            }
        };
        if let Err(error) = self.child.confirm_running_after_readiness(deadline) {
            return Err(Box::new(RemoteTuiReadinessFailure {
                pending: self,
                error: RemoteTuiLauncherError::Process(error),
            }));
        }
        let descriptor_scan = (|| {
            let master_forbidden = self
                .master
                .capture_forbidden_descriptor_set_before_tui()
                .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
            let combined = forbidden
                .combined_with(&master_forbidden)
                .map_err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::from)?;
            self.child
                .observe_forbidden_descriptors_absent_while_live(&combined, deadline)
        })();
        let descriptor_isolation = match descriptor_scan {
            Ok(proof) => VerifiedTuiDescriptorIsolation {
                containment: self.containment(),
                proof,
            },
            Err(error) => {
                return Err(Box::new(RemoteTuiReadinessFailure {
                    pending: self,
                    error: RemoteTuiLauncherError::DescriptorIsolation(error),
                }));
            }
        };
        if let Err(error) = self.child.confirm_running_after_readiness(deadline) {
            return Err(Box::new(RemoteTuiReadinessFailure {
                pending: self,
                error: RemoteTuiLauncherError::Process(error),
            }));
        }
        Ok(ReadyRemoteTui {
            child: self.child,
            master: self.master,
            readiness: proof,
            runtime_guard: self.runtime_guard,
            descriptor_isolation,
        })
    }

    /// Retains every pending TUI authority when assembling the external
    /// forbidden set fails before readiness observation can begin.
    pub(super) fn retain_descriptor_isolation_failure(
        self,
        error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    ) -> Box<RemoteTuiReadinessFailure> {
        Box::new(RemoteTuiReadinessFailure {
            pending: self,
            error: RemoteTuiLauncherError::DescriptorIsolation(error),
        })
    }
}

/// Move-only proof branded to the exact TUI process group that crossed both
/// the exec-readiness and descriptor-isolation barriers.
#[must_use = "TUI descriptor isolation must remain embedded in ReadyRemoteTui"]
struct VerifiedTuiDescriptorIsolation {
    containment: ContainmentMetadata,
    proof: calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
}

impl fmt::Debug for VerifiedTuiDescriptorIsolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.containment, self.proof);
        formatter.write_str("VerifiedTuiDescriptorIsolation(<redacted>)")
    }
}

/// Bounded, redacted shutdown-only progress on the guardian-owned PTY master.
///
/// Darwin can hold a controlling-terminal session leader in `P_WEXIT` until
/// final PTY output is consumed. Each call performs a fixed maximum number of
/// nonblocking reads; the process shutdown loop remains the sole owner of the
/// absolute grace and hard deadlines. Every returned chunk zeroes itself on
/// drop, and neither terminal bytes nor terminal errors escape this adapter.
struct TuiShutdownOutputDrain<'master> {
    master: &'master PtyMaster,
    buffer: TerminalBuffer,
    nonblocking_ready: bool,
    terminal_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TuiShutdownDrainObservation {
    Data,
    WouldBlock,
    EndOfStream,
}

fn run_bounded_tui_shutdown_drain(
    mut read: impl FnMut() -> Result<TuiShutdownDrainObservation, ()>,
) -> Result<bool, ()> {
    for _ in 0..TUI_SHUTDOWN_DRAIN_MAX_FRAGMENTS_PER_POLL {
        match read()? {
            TuiShutdownDrainObservation::Data => {}
            TuiShutdownDrainObservation::WouldBlock => return Ok(false),
            TuiShutdownDrainObservation::EndOfStream => return Ok(true),
        }
    }
    Ok(false)
}

impl<'master> TuiShutdownOutputDrain<'master> {
    fn new(master: &'master PtyMaster) -> Self {
        Self {
            master,
            buffer: TerminalBuffer::new(),
            nonblocking_ready: master.enable_nonblocking().is_ok(),
            terminal_closed: false,
        }
    }

    fn progress(&mut self) -> Result<(), ProcessError> {
        if !self.nonblocking_ready {
            return Err(ProcessError::TuiOutputDrain {
                role: ChildRole::Tui,
            });
        }
        if self.terminal_closed {
            return Ok(());
        }

        let closed =
            run_bounded_tui_shutdown_drain(|| match self.master.read_into(&mut self.buffer) {
                Ok(TerminalRead::Data(chunk)) => {
                    drop(chunk);
                    Ok(TuiShutdownDrainObservation::Data)
                }
                Ok(TerminalRead::WouldBlock) => Ok(TuiShutdownDrainObservation::WouldBlock),
                Ok(TerminalRead::EndOfStream) => Ok(TuiShutdownDrainObservation::EndOfStream),
                Err(_) => Err(()),
            })
            .map_err(|()| ProcessError::TuiOutputDrain {
                role: ChildRole::Tui,
            })?;
        self.terminal_closed = closed;
        Ok(())
    }
}

fn shutdown_tui_child_draining_output(
    child: ManagedGroupChild,
    master: &PtyMaster,
    graceful_deadline: Duration,
    forced_deadline: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    let mut drain = TuiShutdownOutputDrain::new(master);
    let mut progress = || drain.progress();
    shutdown_tui_child_with_output_progress(
        child,
        graceful_deadline,
        forced_deadline,
        &mut progress,
    )
}

fn shutdown_tui_after_forwarded_signal_draining_output(
    child: ManagedGroupChild,
    master: &PtyMaster,
    forwarded: ForwardedTuiSignal,
    graceful_deadline: Duration,
    forced_deadline: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    let mut drain = TuiShutdownOutputDrain::new(master);
    let mut progress = || drain.progress();
    shutdown_tui_after_forwarded_signal_with_output_progress(
        child,
        forwarded,
        graceful_deadline,
        forced_deadline,
        &mut progress,
    )
}

fn shutdown_tui_after_output_eof_draining_output(
    child: ManagedGroupChild,
    master: &PtyMaster,
    graceful_deadline: Duration,
    forced_deadline: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    let mut drain = TuiShutdownOutputDrain::new(master);
    let mut progress = || drain.progress();
    shutdown_tui_after_output_eof_with_output_progress(
        child,
        graceful_deadline,
        forced_deadline,
        &mut progress,
    )
}

fn retry_tui_shutdown_draining_output(
    unreaped: &mut UnreapedChildren,
    master: &PtyMaster,
    graceful_deadline: Duration,
    forced_deadline: Duration,
) -> Result<ShutdownOutcome, ProcessError> {
    let mut drain = TuiShutdownOutputDrain::new(master);
    let mut progress = || drain.progress();
    unreaped.retry_with_tui_output_progress(graceful_deadline, forced_deadline, &mut progress)
}

impl fmt::Debug for PendingRemoteTui {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.child,
            &self.master,
            &self.readiness,
            &self.runtime_guard,
        );
        formatter.write_str("PendingRemoteTui(<redacted>)")
    }
}

#[must_use = "readiness failure retains the supervised child and PTY"]
pub(super) struct RemoteTuiReadinessFailure {
    pending: PendingRemoteTui,
    error: RemoteTuiLauncherError,
}

impl RemoteTuiReadinessFailure {
    /// Starts bounded containment while keeping the session guard, PTY, and
    /// readiness channel attached to any unreaped direct-child authority.
    #[expect(
        clippy::boxed_local,
        reason = "the readiness API deliberately returns a boxed linear failure owner"
    )]
    pub(super) fn contain(
        self: Box<Self>,
        graceful_deadline: Duration,
        forced_deadline: Duration,
    ) -> Result<RemoteTuiReadinessResolution, Box<RemoteTuiReadinessContainmentFailure>> {
        let Self { pending, error } = *self;
        let PendingRemoteTui {
            child,
            master,
            readiness,
            runtime_guard,
        } = pending;
        match shutdown_tui_child_draining_output(child, &master, graceful_deadline, forced_deadline)
        {
            Ok(outcome) => {
                let _ = (master, readiness, runtime_guard);
                Ok(RemoteTuiReadinessResolution { error, outcome })
            }
            Err(unreaped) => Err(Box::new(RemoteTuiReadinessContainmentFailure {
                unreaped,
                master,
                readiness,
                runtime_guard,
                readiness_error: error,
            })),
        }
    }
}

impl fmt::Debug for RemoteTuiReadinessFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.pending;
        formatter
            .debug_struct("RemoteTuiReadinessFailure")
            .field("error", &self.error)
            .field("retains_child", &true)
            .finish_non_exhaustive()
    }
}

#[must_use = "unreaped readiness failure retains the TUI session guard"]
pub(super) struct RemoteTuiReadinessContainmentFailure {
    unreaped: Box<UnreapedChildren>,
    master: PtyMaster,
    readiness: TuiReadinessReceiver,
    runtime_guard: SessionRuntimeGuard,
    readiness_error: RemoteTuiLauncherError,
}

impl RemoteTuiReadinessContainmentFailure {
    #[cfg(test)]
    pub(super) fn packaged_shutdown_error(&self) -> ProcessError {
        self.unreaped.error()
    }

    /// Retries the same exact wait authority. Failure returns this owner with
    /// its Arc session guard intact; only a proven reap releases the guard.
    pub(super) fn retry(
        mut self: Box<Self>,
        graceful_deadline: Duration,
        forced_deadline: Duration,
    ) -> Result<RemoteTuiReadinessResolution, Box<Self>> {
        match retry_tui_shutdown_draining_output(
            &mut self.unreaped,
            &self.master,
            graceful_deadline,
            forced_deadline,
        ) {
            Ok(outcome) => {
                let Self {
                    unreaped,
                    master,
                    readiness,
                    runtime_guard,
                    readiness_error,
                } = *self;
                let _ = (unreaped, master, readiness, runtime_guard);
                Ok(RemoteTuiReadinessResolution {
                    error: readiness_error,
                    outcome,
                })
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for RemoteTuiReadinessContainmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.unreaped,
            &self.master,
            &self.readiness,
            &self.runtime_guard,
        );
        formatter
            .debug_struct("RemoteTuiReadinessContainmentFailure")
            .field("error", &self.readiness_error)
            .field("retains_session", &true)
            .finish_non_exhaustive()
    }
}

#[must_use = "the original readiness error must be projected after cleanup"]
pub(super) struct RemoteTuiReadinessResolution {
    error: RemoteTuiLauncherError,
    outcome: ShutdownOutcome,
}

impl RemoteTuiReadinessResolution {
    pub(super) const fn outcome(&self) -> ShutdownOutcome {
        self.outcome
    }
}

impl fmt::Debug for RemoteTuiReadinessResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteTuiReadinessResolution")
            .field("error", &self.error)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Live official TUI after controlling-terminal and exec-boundary readiness.
#[must_use = "the ready TUI must remain supervised and exactly reaped"]
pub(super) struct ReadyRemoteTui {
    child: ManagedGroupChild,
    master: PtyMaster,
    readiness: VerifiedTuiReadiness,
    runtime_guard: SessionRuntimeGuard,
    descriptor_isolation: VerifiedTuiDescriptorIsolation,
}

impl ReadyRemoteTui {
    #[cfg(test)]
    pub(super) const fn containment(&self) -> ContainmentMetadata {
        self.child.containment()
    }

    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        self.child
            .observe_forbidden_descriptors_absent(forbidden, deadline)
    }

    /// Enables nonblocking PTY I/O without exposing or splitting the sealed
    /// master descriptor from this exact ready child authority.
    pub(super) fn enable_terminal_io(&self) -> Result<(), TerminalError> {
        self.master.enable_nonblocking()
    }

    /// Reads one fixed-size PTY output fragment. Linux PTY `EIO` and portable
    /// zero-byte EOF remain normalized by [`PtyMaster::read_into`].
    pub(super) fn read_terminal_output<'buffer>(
        &self,
        buffer: &'buffer mut TerminalBuffer,
    ) -> Result<TerminalRead<'buffer>, TerminalError> {
        self.master.read_into(buffer)
    }

    /// Writes one fixed-size input fragment to the sealed PTY master.
    pub(super) fn try_write_terminal_input(
        &self,
        chunk: &mut TerminalChunk<'_>,
    ) -> Result<TerminalWrite, TerminalError> {
        self.master.try_write(chunk)
    }

    #[cfg(test)]
    pub(super) fn terminal_size_for_packaged_test(
        &self,
    ) -> Result<TerminalSize, RemoteTuiLauncherError> {
        self.master.size().map_err(Into::into)
    }

    /// Applies the PTY geometry before notifying the exact TUI process group.
    pub(super) fn resize_terminal(
        &mut self,
        size: TerminalSize,
        deadline: Instant,
    ) -> Result<(), RemoteTuiLauncherError> {
        self.master.set_size(size)?;
        match self.child.notify_terminal_resize(deadline)? {
            ChildLiveness::Running => Ok(()),
            ChildLiveness::Exited => Err(RemoteTuiLauncherError::NotLive),
        }
    }

    /// Suspends the complete exact TUI process group. The caller must close
    /// terminal ingress before invoking this method.
    pub(super) fn suspend_terminal(
        &mut self,
        graceful_deadline: Instant,
        forced_deadline: Instant,
    ) -> Result<(), RemoteTuiLauncherError> {
        self.child
            .suspend(graceful_deadline, forced_deadline)
            .map_err(Into::into)
    }

    /// Continues the exact stopped TUI while leaving ingress physically closed
    /// until a fresh protocol gate proof is consumed by session composition.
    pub(super) fn resume_terminal(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RemoteTuiLauncherError> {
        self.child.resume(deadline).map_err(Into::into)
    }

    /// Performs a fresh non-consuming exact-child liveness observation.
    ///
    /// Session composition uses this immediately before each lifecycle gate;
    /// cached exec/readiness evidence is never treated as current liveness.
    pub(super) fn ensure_live(&mut self, deadline: Instant) -> Result<(), RemoteTuiLauncherError> {
        match self.child.poll_liveness(deadline)? {
            ChildLiveness::Running => Ok(()),
            ChildLiveness::Exited => Err(RemoteTuiLauncherError::NotLive),
        }
    }

    pub(super) fn forward_interactive_signal(
        &mut self,
        signal: InteractiveTerminalSignal,
        deadline: Instant,
    ) -> Result<(), RemoteTuiLauncherError> {
        match self
            .child
            .forward_interactive_terminal_signal(signal, deadline)?
        {
            ChildLiveness::Running => Ok(()),
            ChildLiveness::Exited => Err(RemoteTuiLauncherError::NotLive),
        }
    }

    pub(super) fn forward_shutdown_signal(
        &mut self,
        signal: TerminalShutdownSignal,
        deadline: Instant,
    ) -> Result<ForwardedTuiSignal, RemoteTuiLauncherError> {
        self.child
            .forward_terminal_shutdown_signal(signal, deadline)
            .map_err(Into::into)
    }

    pub(super) fn continue_after_forwarded_shutdown(
        &mut self,
        forwarded: &ForwardedTuiSignal,
        deadline: Instant,
    ) -> Result<(), RemoteTuiLauncherError> {
        self.child
            .continue_after_forwarded_shutdown(forwarded, deadline)
            .map_err(Into::into)
    }

    pub(super) fn shutdown(
        self,
        graceful_deadline: std::time::Duration,
        forced_deadline: std::time::Duration,
    ) -> Result<ShutdownOutcome, Box<RemoteTuiShutdownFailure>> {
        let Self {
            child,
            master,
            readiness,
            runtime_guard,
            descriptor_isolation,
        } = self;
        match shutdown_tui_child_draining_output(child, &master, graceful_deadline, forced_deadline)
        {
            Ok(outcome) => {
                let _ = (master, readiness, runtime_guard, descriptor_isolation);
                Ok(outcome)
            }
            Err(unreaped) => Err(Box::new(RemoteTuiShutdownFailure {
                unreaped,
                master,
                readiness,
                runtime_guard,
            })),
        }
    }

    pub(super) fn shutdown_after_forwarded_signal(
        self,
        forwarded: ForwardedTuiSignal,
        graceful_deadline: Duration,
        forced_deadline: Duration,
    ) -> Result<ShutdownOutcome, Box<RemoteTuiShutdownFailure>> {
        let Self {
            child,
            master,
            readiness,
            runtime_guard,
            descriptor_isolation,
        } = self;
        match shutdown_tui_after_forwarded_signal_draining_output(
            child,
            &master,
            forwarded,
            graceful_deadline,
            forced_deadline,
        ) {
            Ok(outcome) => {
                let _ = (master, readiness, runtime_guard, descriptor_isolation);
                Ok(outcome)
            }
            Err(unreaped) => Err(Box::new(RemoteTuiShutdownFailure {
                unreaped,
                master,
                readiness,
                runtime_guard,
            })),
        }
    }

    /// Preserves a natural TUI disposition after the exact PTY master reached
    /// EOF. No `TERM` is sent to the TUI during the grace window.
    pub(super) fn shutdown_after_output_eof(
        self,
        graceful_deadline: Duration,
        forced_deadline: Duration,
    ) -> Result<ShutdownOutcome, Box<RemoteTuiShutdownFailure>> {
        let Self {
            child,
            master,
            readiness,
            runtime_guard,
            descriptor_isolation,
        } = self;
        match shutdown_tui_after_output_eof_draining_output(
            child,
            &master,
            graceful_deadline,
            forced_deadline,
        ) {
            Ok(outcome) => {
                let _ = (master, readiness, runtime_guard, descriptor_isolation);
                Ok(outcome)
            }
            Err(unreaped) => Err(Box::new(RemoteTuiShutdownFailure {
                unreaped,
                master,
                readiness,
                runtime_guard,
            })),
        }
    }
}

impl fmt::Debug for ReadyRemoteTui {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.child,
            &self.master,
            &self.readiness,
            &self.runtime_guard,
            &self.descriptor_isolation,
        );
        formatter.write_str("ReadyRemoteTui(<redacted>)")
    }
}

#[must_use = "unreaped ready TUI retains the session guard and PTY"]
pub(super) struct RemoteTuiShutdownFailure {
    unreaped: Box<UnreapedChildren>,
    master: PtyMaster,
    readiness: VerifiedTuiReadiness,
    runtime_guard: SessionRuntimeGuard,
}

impl RemoteTuiShutdownFailure {
    pub(super) fn error(&self) -> ProcessError {
        self.unreaped.error()
    }

    pub(super) fn retry(
        mut self: Box<Self>,
        graceful_deadline: Duration,
        forced_deadline: Duration,
    ) -> Result<ShutdownOutcome, Box<Self>> {
        match retry_tui_shutdown_draining_output(
            &mut self.unreaped,
            &self.master,
            graceful_deadline,
            forced_deadline,
        ) {
            Ok(outcome) => {
                let Self {
                    unreaped,
                    master,
                    readiness,
                    runtime_guard,
                } = *self;
                let _ = (unreaped, master, readiness, runtime_guard);
                Ok(outcome)
            }
            Err(_) => Err(self),
        }
    }
}

impl fmt::Debug for RemoteTuiShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.unreaped,
            &self.master,
            &self.readiness,
            &self.runtime_guard,
        );
        formatter
            .debug_struct("RemoteTuiShutdownFailure")
            .field("error", &self.error())
            .field("retains_session", &true)
            .finish_non_exhaustive()
    }
}

/// Exec-entry used only by the fixed internal launcher role.
pub(super) fn run_exec_launcher() -> Result<ExitCode, RemoteTuiLauncherError> {
    // This is deliberately the first capability acquisition. It reseals the
    // child-only descriptor before terminal mutation, allocation-heavy command
    // parsing, or any possibility of a descendant spawn.
    let readiness = InheritedTuiReadiness::take()?;
    let proof = claim_controlling_terminal_from_stdin()?;
    if !rustix::termios::isatty(std::io::stdin())
        || !rustix::termios::isatty(std::io::stdout())
        || !rustix::termios::isatty(std::io::stderr())
        || proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
    {
        return Err(RemoteTuiLauncherError::Terminal(
            TerminalError::ControllingTerminalMismatch,
        ));
    }
    let size = terminal_size(std::io::stdin())?;
    if size.rows() == 0 || size.columns() == 0 {
        return Err(RemoteTuiLauncherError::Terminal(
            TerminalError::WindowSizeMismatch,
        ));
    }

    let spec = ExecSpec::from_environment()?;
    let mut command = spec.into_target_command();
    scrub_launcher_environment(&mut command);
    readiness.publish_before_exec()?;
    let error = command.exec();
    let _ = error.kind();
    Err(RemoteTuiLauncherError::Exec)
}

struct ExecSpec {
    program: PathBuf,
    socket: String,
    thread: String,
}

impl ExecSpec {
    fn from_environment() -> Result<Self, RemoteTuiLauncherError> {
        if env::var(LAUNCH_CONTRACT_ENV).ok().as_deref() != Some(LAUNCH_CONTRACT_V1) {
            return Err(RemoteTuiLauncherError::InvalidCommand);
        }
        let program = env::var_os(TARGET_PROGRAM_ENV)
            .map(PathBuf::from)
            .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
        let socket =
            env::var(TARGET_SOCKET_ENV).map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
        let thread =
            env::var(TARGET_THREAD_ENV).map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
        validate_exec_fields(&program, &socket, &thread)?;
        Ok(Self {
            program,
            socket,
            thread,
        })
    }

    fn into_target_command(self) -> Command {
        let mut command = Command::new(self.program);
        command.args([
            "-c",
            CLI_CREDENTIALS_OVERRIDE,
            "-c",
            MCP_CREDENTIALS_OVERRIDE,
            "resume",
            "--no-alt-screen",
            "--remote",
            &self.socket,
            &self.thread,
        ]);
        command
    }
}

fn prepare_launcher_command(
    target: &Command,
    launcher: &Path,
) -> Result<Command, RemoteTuiLauncherError> {
    let spec = ExecSpec::from_command(target)?;
    let working_directory = target
        .get_current_dir()
        .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    if !working_directory.is_absolute() {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    for (name, value) in target.get_envs() {
        // A concrete value would let the target inject launcher authority.
        // An explicit removal is the opposite operation: retain it in the
        // projected command so inherited authority stays absent, then install
        // only Calcifer's sealed launch-contract values below.
        if value.is_some() && is_launcher_environment(name) {
            return Err(RemoteTuiLauncherError::InvalidCommand);
        }
    }

    let mut command = Command::new(launcher);
    command.env_clear().current_dir(working_directory);
    for (name, value) in target.get_envs() {
        match value {
            Some(value) => {
                command.env(name, value);
            }
            None => {
                command.env_remove(name);
            }
        }
    }
    #[cfg(test)]
    command.env_remove(PACKAGED_TUI_LAUNCHER_ENV);
    command
        .env(LAUNCH_CONTRACT_ENV, LAUNCH_CONTRACT_V1)
        .env(TARGET_PROGRAM_ENV, spec.program)
        .env(TARGET_SOCKET_ENV, spec.socket)
        .env(TARGET_THREAD_ENV, spec.thread);
    Ok(command)
}

impl ExecSpec {
    fn from_command(command: &Command) -> Result<Self, RemoteTuiLauncherError> {
        let arguments = command.get_args().collect::<Vec<_>>();
        if arguments.len() != 9
            || arguments[0] != OsStr::new("-c")
            || arguments[1] != OsStr::new(CLI_CREDENTIALS_OVERRIDE)
            || arguments[2] != OsStr::new("-c")
            || arguments[3] != OsStr::new(MCP_CREDENTIALS_OVERRIDE)
            || arguments[4] != OsStr::new("resume")
            || arguments[5] != OsStr::new("--no-alt-screen")
            || arguments[6] != OsStr::new("--remote")
        {
            return Err(RemoteTuiLauncherError::InvalidCommand);
        }
        let program = PathBuf::from(command.get_program());
        let socket = arguments[7]
            .to_str()
            .ok_or(RemoteTuiLauncherError::InvalidCommand)?
            .to_owned();
        let thread = arguments[8]
            .to_str()
            .ok_or(RemoteTuiLauncherError::InvalidCommand)?
            .to_owned();
        validate_exec_fields(&program, &socket, &thread)?;
        Ok(Self {
            program,
            socket,
            thread,
        })
    }
}

fn validate_exec_fields(
    program: &Path,
    socket: &str,
    thread: &str,
) -> Result<(), RemoteTuiLauncherError> {
    if !program.is_absolute()
        || program.as_os_str().as_bytes().is_empty()
        || program.as_os_str().as_bytes().len() > MAX_EXECUTABLE_BYTES
        || !socket.starts_with("unix:///")
        || socket.len() > MAX_SOCKET_BYTES
        || socket.chars().any(char::is_control)
        || uuid::Uuid::parse_str(thread).is_err()
    {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LauncherExecutableMetadata {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

/// Exact pathname identity for the reviewed internal launcher binary.
///
/// The identity is captured while the expensive target validation is still
/// outside the relay budget, then compared again immediately before spawn.
/// It contains no bytes or paths that can reach a package marker or error.
struct LauncherExecutableIdentity {
    path: PathBuf,
    metadata: LauncherExecutableMetadata,
}

impl LauncherExecutableIdentity {
    fn capture(path: &Path) -> Result<Self, RemoteTuiLauncherError> {
        if std::fs::canonicalize(path).map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?
            != path
        {
            return Err(RemoteTuiLauncherError::LauncherUnavailable);
        }
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
        let file = std::fs::File::from(descriptor);
        let opened = launcher_executable_metadata(
            &file
                .metadata()
                .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?,
        )?;
        let visible = launcher_executable_metadata(
            &std::fs::symlink_metadata(path)
                .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?,
        )?;
        if opened != visible {
            return Err(RemoteTuiLauncherError::LauncherUnavailable);
        }
        Ok(Self {
            path: path.to_path_buf(),
            metadata: opened,
        })
    }

    fn revalidate(&self) -> Result<(), RemoteTuiLauncherError> {
        let observed = Self::capture(&self.path)?;
        if observed.metadata == self.metadata {
            Ok(())
        } else {
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        }
    }
}

impl fmt::Debug for LauncherExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.path, self.metadata);
        formatter.write_str("LauncherExecutableIdentity(<redacted>)")
    }
}

fn launcher_executable_metadata(
    metadata: &std::fs::Metadata,
) -> Result<LauncherExecutableMetadata, RemoteTuiLauncherError> {
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() == 0
    {
        return Err(RemoteTuiLauncherError::LauncherUnavailable);
    }
    Ok(LauncherExecutableMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn current_launcher_executable() -> Result<PathBuf, RemoteTuiLauncherError> {
    #[cfg(test)]
    if env::var_os(PACKAGED_TUI_LAUNCHER_ENV).is_some() {
        return packaged_launcher_executable_from_environment().map(|(_, path)| path);
    }
    let executable = env::current_exe().map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    if !executable.is_absolute()
        || std::fs::canonicalize(&executable)
            .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?
            != executable
    {
        return Err(RemoteTuiLauncherError::LauncherUnavailable);
    }
    Ok(executable)
}

#[cfg(test)]
pub(super) fn packaged_launcher_executable_from_environment()
-> Result<(&'static str, PathBuf), RemoteTuiLauncherError> {
    let candidate = env::var_os(PACKAGED_TUI_LAUNCHER_ENV)
        .map(PathBuf::from)
        .ok_or(RemoteTuiLauncherError::LauncherUnavailable)?;
    validate_packaged_launcher_executable(&candidate)
        .map(|executable| (PACKAGED_TUI_LAUNCHER_ENV, executable))
}

#[cfg(test)]
fn validate_packaged_launcher_executable(
    candidate: &Path,
) -> Result<PathBuf, RemoteTuiLauncherError> {
    if !candidate.is_absolute()
        || candidate.as_os_str().as_bytes().is_empty()
        || candidate.as_os_str().as_bytes().len() > MAX_EXECUTABLE_BYTES
    {
        return Err(RemoteTuiLauncherError::LauncherUnavailable);
    }
    let initial = std::fs::symlink_metadata(candidate)
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let canonical = std::fs::canonicalize(candidate)
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let stable = std::fs::symlink_metadata(&canonical)
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let mode = stable.mode();
    if canonical != candidate
        || !initial.file_type().is_file()
        || !stable.file_type().is_file()
        || initial.dev() != stable.dev()
        || initial.ino() != stable.ino()
        || stable.uid() != rustix::process::geteuid().as_raw()
        || stable.nlink() != 1
        || stable.len() == 0
        || mode & 0o100 == 0
        || mode & 0o6022 != 0
    {
        return Err(RemoteTuiLauncherError::LauncherUnavailable);
    }
    Ok(canonical)
}

pub(super) fn internal_launcher_requested() -> bool {
    env::var(LAUNCH_CONTRACT_ENV).ok().as_deref() == Some(LAUNCH_CONTRACT_V1)
}

fn scrub_launcher_environment(command: &mut Command) {
    calcifer_unix_child_fd::scrub_readiness_fd_env(command);
    for name in [
        LAUNCH_CONTRACT_ENV,
        TARGET_PROGRAM_ENV,
        TARGET_SOCKET_ENV,
        TARGET_THREAD_ENV,
    ] {
        command.env_remove(name);
    }
    #[cfg(test)]
    command.env_remove(PACKAGED_TUI_LAUNCHER_ENV);
}

fn is_launcher_environment(name: &OsStr) -> bool {
    let production_private = [
        LAUNCH_CONTRACT_ENV,
        TARGET_PROGRAM_ENV,
        TARGET_SOCKET_ENV,
        TARGET_THREAD_ENV,
        calcifer_unix_child_fd::READINESS_FD_ENV,
    ]
    .into_iter()
    .any(|candidate| name == OsStr::new(candidate));
    #[cfg(test)]
    {
        production_private || name == OsStr::new(PACKAGED_TUI_LAUNCHER_ENV)
    }
    #[cfg(not(test))]
    production_private
}

pub(super) fn fixture_target_requested() -> bool {
    env::var_os(FIXTURE_TARGET_ENV).is_some()
        || env::var_os(FIXTURE_ENVIRONMENT_TARGET_ENV).is_some()
}

/// Closed real-exec harness used by `tests/supervisor.rs`. It accepts only
/// four fixed cases and never accepts a program, shell fragment, prompt, or
/// terminal payload from argv.
pub(super) fn run_fixture_harness(case: &str) -> Result<ExitCode, RemoteTuiLauncherError> {
    let case = match case {
        "success" => FixtureLaunchCase::Success,
        "exec-failure" => FixtureLaunchCase::ExecFailure,
        "early-exit" => FixtureLaunchCase::EarlyExit,
        "environment" => FixtureLaunchCase::Environment,
        _ => return Err(RemoteTuiLauncherError::InvalidCommand),
    };
    let deadline = fixture_deadline()?;
    if case == FixtureLaunchCase::Environment {
        return run_fixture_environment_harness(deadline);
    }
    let (mut readiness, sender) = tui_readiness_pair()?;
    let sender_identity = calcifer_unix_child_fd::descriptor_identity(sender.as_fd())
        .map_err(|_| RemoteTuiLauncherError::Readiness(TuiReadinessError::Descriptor))?;
    let launcher = current_launcher_executable()?;
    let target_program = match case {
        FixtureLaunchCase::Success | FixtureLaunchCase::EarlyExit => launcher.clone(),
        FixtureLaunchCase::ExecFailure => {
            PathBuf::from("/calcifer/internal-fixture/nonexistent-codex")
        }
        FixtureLaunchCase::Environment => return Err(RemoteTuiLauncherError::InvalidCommand),
    };
    let working_directory = env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let mut target = Command::new(target_program);
    target
        .env_clear()
        .args([
            "-c",
            CLI_CREDENTIALS_OVERRIDE,
            "-c",
            MCP_CREDENTIALS_OVERRIDE,
            "resume",
            "--no-alt-screen",
            "--remote",
            FIXTURE_SOCKET,
            FIXTURE_THREAD,
        ])
        .current_dir(&working_directory)
        .env("CODEX_HOME", &working_directory)
        .env(
            FIXTURE_TARGET_ENV,
            match case {
                FixtureLaunchCase::Success => "success",
                FixtureLaunchCase::EarlyExit => "early-exit",
                FixtureLaunchCase::ExecFailure => "exec-failure",
                FixtureLaunchCase::Environment => {
                    return Err(RemoteTuiLauncherError::InvalidCommand);
                }
            },
        )
        .env(
            FIXTURE_EXPECTED_READINESS_ENV,
            format!("{}:{}", sender_identity.device, sender_identity.inode),
        );

    let mut command = prepare_launcher_command(&target, &launcher)?;
    let pty = PtyOwner::open(TerminalSize::new(37, 111))?;
    let master = pty.configure_child(&mut command)?;
    let mut child = match ManagedGroupChild::spawn_fixture_session_leader_with_inherited_fd(
        ChildRole::Tui,
        command,
        sender.as_fd(),
        deadline,
    ) {
        Ok(child) => child,
        Err(failure)
            if matches!(
                case,
                FixtureLaunchCase::ExecFailure | FixtureLaunchCase::EarlyExit
            ) && failure.state() != SpawnFailureState::NotStarted =>
        {
            return match failure.cleanup(deadline) {
                Ok(_) => Ok(ExitCode::SUCCESS),
                Err(_) => Err(RemoteTuiLauncherError::Process(
                    ProcessError::SpawnCleanupTimeout {
                        role: ChildRole::Tui,
                    },
                )),
            };
        }
        Err(failure) => {
            let _ = failure.cleanup(deadline);
            return Err(RemoteTuiLauncherError::Process(ProcessError::Spawn {
                role: ChildRole::Tui,
            }));
        }
    };
    drop(sender);

    if matches!(
        case,
        FixtureLaunchCase::ExecFailure | FixtureLaunchCase::EarlyExit
    ) {
        thread::sleep(FIXTURE_POLL.saturating_mul(3));
        let _proof = readiness.receive(deadline)?;
        let observed = child.confirm_running_after_readiness(deadline);
        let outcome =
            shutdown_tui_child_draining_output(child, &master, Duration::ZERO, FIXTURE_TIMEOUT)
                .map_err(|failure| RemoteTuiLauncherError::Process(failure.error()))?;
        if matches!(observed, Err(ProcessError::EarlyExit { .. })) && outcome.failure().is_none() {
            return Ok(ExitCode::SUCCESS);
        }
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }

    let _proof = readiness.receive(deadline)?;
    child.confirm_running_after_readiness(deadline)?;
    await_fixture_target_verification(&master, deadline)?;
    let outcome = shutdown_tui_child_draining_output(
        child,
        &master,
        Duration::from_millis(100),
        FIXTURE_TIMEOUT,
    )
    .map_err(|failure| RemoteTuiLauncherError::Process(failure.error()))?;
    if outcome.failure().is_some() {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FixtureLaunchCase {
    Success,
    ExecFailure,
    EarlyExit,
    Environment,
}

fn run_fixture_environment_harness(deadline: Instant) -> Result<ExitCode, RemoteTuiLauncherError> {
    let launcher = current_launcher_executable()?;
    let working_directory = env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| RemoteTuiLauncherError::LauncherUnavailable)?;
    let encoded_nonce = encode_fixture_environment_bytes(&nonce);

    let mut app =
        fixture_managed_environment_command(&launcher, &working_directory, &encoded_nonce, false);
    let app_environment = fixture_environment_digest_from_command(&app, &nonce)?;
    let mut tui =
        fixture_managed_environment_command(&launcher, &working_directory, &encoded_nonce, true);
    let tui_environment = fixture_environment_digest_from_command(&tui, &nonce)?;
    if app_environment != tui_environment {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    app.env(FIXTURE_ENVIRONMENT_EXPECTED_ENV, &app_environment);
    tui.env(FIXTURE_ENVIRONMENT_EXPECTED_ENV, &tui_environment);

    let output = app
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| RemoteTuiLauncherError::Exec)?;
    if !output.status.success()
        || output.stdout != [FIXTURE_VERIFIED_BYTE]
        || !output.stderr.is_empty()
    {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }

    let (mut readiness, sender) = tui_readiness_pair()?;
    let mut command = prepare_launcher_command(&tui, &launcher)?;
    let pty = PtyOwner::open(TerminalSize::new(37, 111))?;
    let master = pty.configure_child(&mut command)?;
    let mut child = match ManagedGroupChild::spawn_fixture_session_leader_with_inherited_fd(
        ChildRole::Tui,
        command,
        sender.as_fd(),
        deadline,
    ) {
        Ok(child) => child,
        Err(failure) => {
            let _ = failure.cleanup(deadline);
            return Err(RemoteTuiLauncherError::Process(ProcessError::Spawn {
                role: ChildRole::Tui,
            }));
        }
    };
    drop(sender);

    let exercise = (|| {
        let _proof = readiness.receive(deadline)?;
        child.confirm_running_after_readiness(deadline)?;
        await_fixture_target_verification(&master, deadline)
    })();
    let outcome = shutdown_tui_child_draining_output(
        child,
        &master,
        Duration::from_millis(100),
        FIXTURE_TIMEOUT,
    )
    .map_err(|failure| RemoteTuiLauncherError::Process(failure.error()))?;
    if outcome.failure().is_some() {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    exercise?;
    Ok(ExitCode::SUCCESS)
}

fn fixture_managed_environment_command(
    program: &Path,
    working_directory: &Path,
    encoded_nonce: &str,
    tui: bool,
) -> Command {
    let mut command = crate::providers::codex::managed_command(program, working_directory);
    if tui {
        command.args([
            "resume",
            "--no-alt-screen",
            "--remote",
            FIXTURE_SOCKET,
            FIXTURE_THREAD,
        ]);
    } else {
        command.args(["app-server", "--listen", FIXTURE_SOCKET]);
    }
    command
        .current_dir(working_directory)
        .env(FIXTURE_ENVIRONMENT_TARGET_ENV, "v1")
        .env(FIXTURE_ENVIRONMENT_NONCE_ENV, encoded_nonce);
    command
}

fn fixture_environment_digest_from_command(
    command: &Command,
    nonce: &[u8; 32],
) -> Result<String, RemoteTuiLauncherError> {
    let environment = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    fixture_environment_digest(environment, nonce)
}

fn fixture_environment_digest(
    mut environment: Vec<(OsString, OsString)>,
    nonce: &[u8; 32],
) -> Result<String, RemoteTuiLauncherError> {
    environment.retain(|(name, _)| {
        name != OsStr::new(FIXTURE_ENVIRONMENT_NONCE_ENV)
            && name != OsStr::new(FIXTURE_ENVIRONMENT_EXPECTED_ENV)
    });
    environment.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    for (name, value) in environment {
        let name_length = u64::try_from(name.as_bytes().len())
            .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
        let value_length = u64::try_from(value.as_bytes().len())
            .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
        hasher.update(name_length.to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update(value_length.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Ok(encode_fixture_environment_bytes(&hasher.finalize()))
}

fn encode_fixture_environment_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Fixed fake official target reached only after the launcher has exec'd.
pub(super) fn run_fixture_target(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<ExitCode, RemoteTuiLauncherError> {
    if let Some(value) = env::var_os(FIXTURE_ENVIRONMENT_TARGET_ENV) {
        if value != OsStr::new("v1") {
            return Err(RemoteTuiLauncherError::InvalidCommand);
        }
        return run_fixture_environment_target();
    }
    let mut arguments = arguments.into_iter();
    let program = arguments
        .next()
        .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    let mut values = Vec::with_capacity(9);
    for _ in 0..9 {
        values.push(
            arguments
                .next()
                .ok_or(RemoteTuiLauncherError::InvalidCommand)?,
        );
    }
    if arguments.next().is_some() {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    let mut projected = Command::new(program);
    projected.args(&values);
    let spec = ExecSpec::from_command(&projected)?;
    if spec.socket != FIXTURE_SOCKET || spec.thread != FIXTURE_THREAD {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }

    let proof = verify_controlling_terminal_from_stdin()?;
    if !rustix::termios::isatty(std::io::stdin())
        || !rustix::termios::isatty(std::io::stdout())
        || !rustix::termios::isatty(std::io::stderr())
        || proof.process() != proof.process_group()
        || proof.process() != proof.session()
        || proof.process() != proof.foreground_process_group()
        || terminal_size(std::io::stdin())? != TerminalSize::new(37, 111)
        || [
            LAUNCH_CONTRACT_ENV,
            TARGET_PROGRAM_ENV,
            TARGET_SOCKET_ENV,
            TARGET_THREAD_ENV,
            calcifer_unix_child_fd::READINESS_FD_ENV,
            FIXTURE_AMBIENT_ENV_CANARY,
        ]
        .into_iter()
        .any(|name| env::var_os(name).is_some())
    {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    let expected = parse_fixture_descriptor_identity()?;
    if calcifer_unix_child_fd::count_open_descriptors_with_identity(expected)
        .map_err(|_| RemoteTuiLauncherError::Readiness(TuiReadinessError::Descriptor))?
        != 0
    {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }

    match env::var(FIXTURE_TARGET_ENV).ok().as_deref() {
        Some("early-exit") => Ok(ExitCode::from(23)),
        Some("success") => {
            std::io::stdout()
                .write_all(&[FIXTURE_VERIFIED_BYTE])
                .and_then(|()| std::io::stdout().flush())
                .map_err(|_| RemoteTuiLauncherError::Exec)?;
            loop {
                thread::park();
            }
        }
        _ => Err(RemoteTuiLauncherError::InvalidCommand),
    }
}

fn run_fixture_environment_target() -> Result<ExitCode, RemoteTuiLauncherError> {
    let nonce = decode_fixture_environment_nonce()?;
    let current_directory = env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    let has_expected_path = |name: &str, suffix: &str| {
        env::var_os(name).map(PathBuf::from) == Some(current_directory.join(suffix))
    };
    if std::fs::canonicalize(home).map_err(|_| RemoteTuiLauncherError::InvalidCommand)?
        != current_directory
        || env::var_os("PATH").as_deref() != Some(OsStr::new("/usr/bin:/bin"))
        || env::var_os("TERM").as_deref() != Some(OsStr::new("xterm-256color"))
        || env::var_os("LANG").as_deref() != Some(OsStr::new("C"))
        || env::var_os(FIXTURE_SAFE_AMBIENT_ENV).as_deref() != Some(OsStr::new("preserved"))
        || !has_expected_path("XDG_CONFIG_HOME", "xdg-config")
        || !has_expected_path("XDG_DATA_HOME", "xdg-data")
        || !has_expected_path("XDG_CACHE_HOME", "xdg-cache")
        || !has_expected_path("XDG_RUNTIME_DIR", "xdg-run")
        || env::vars_os().any(|(name, _)| {
            let normalized = name.to_string_lossy().to_ascii_uppercase();
            normalized.starts_with("CALCIFER_") || normalized.starts_with("OPENAI_")
        })
    {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    let expected = env::var_os(FIXTURE_ENVIRONMENT_EXPECTED_ENV)
        .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    let actual = fixture_environment_digest(env::vars_os().collect(), &nonce)?;
    if expected != OsStr::new(&actual) {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    std::io::stdout()
        .write_all(&[FIXTURE_VERIFIED_BYTE])
        .and_then(|()| std::io::stdout().flush())
        .map_err(|_| RemoteTuiLauncherError::Exec)?;
    if rustix::termios::isatty(std::io::stdin()) {
        loop {
            thread::park();
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn decode_fixture_environment_nonce() -> Result<[u8; 32], RemoteTuiLauncherError> {
    let encoded =
        env::var_os(FIXTURE_ENVIRONMENT_NONCE_ENV).ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    let encoded = encoded.as_bytes();
    if encoded.len() != 64 {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    let mut nonce = [0_u8; 32];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high = decode_fixture_environment_nibble(pair[0])?;
        let low = decode_fixture_environment_nibble(pair[1])?;
        nonce[index] = (high << 4) | low;
    }
    Ok(nonce)
}

fn decode_fixture_environment_nibble(value: u8) -> Result<u8, RemoteTuiLauncherError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(RemoteTuiLauncherError::InvalidCommand),
    }
}

fn parse_fixture_descriptor_identity()
-> Result<calcifer_unix_child_fd::DescriptorIdentity, RemoteTuiLauncherError> {
    let encoded = env::var(FIXTURE_EXPECTED_READINESS_ENV)
        .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
    if encoded.len() > 64 {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    let (device, inode) = encoded
        .split_once(':')
        .ok_or(RemoteTuiLauncherError::InvalidCommand)?;
    let device = device
        .parse::<u64>()
        .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
    let inode = inode
        .parse::<u64>()
        .map_err(|_| RemoteTuiLauncherError::InvalidCommand)?;
    if inode == 0 {
        return Err(RemoteTuiLauncherError::InvalidCommand);
    }
    Ok(calcifer_unix_child_fd::DescriptorIdentity { device, inode })
}

fn await_fixture_target_verification(
    master: &PtyMaster,
    deadline: Instant,
) -> Result<(), RemoteTuiLauncherError> {
    master.enable_nonblocking()?;
    let mut buffer = TerminalBuffer::new();
    loop {
        match master.read_into(&mut buffer)? {
            TerminalRead::Data(chunk) if chunk.matches(&[FIXTURE_VERIFIED_BYTE]) => return Ok(()),
            TerminalRead::Data(_) | TerminalRead::EndOfStream => {
                return Err(RemoteTuiLauncherError::InvalidCommand);
            }
            TerminalRead::WouldBlock if Instant::now() < deadline => thread::sleep(FIXTURE_POLL),
            TerminalRead::WouldBlock => {
                return Err(RemoteTuiLauncherError::Readiness(
                    TuiReadinessError::Timeout,
                ));
            }
        }
    }
}

fn fixture_deadline() -> Result<Instant, RemoteTuiLauncherError> {
    Instant::now()
        .checked_add(FIXTURE_TIMEOUT)
        .ok_or(RemoteTuiLauncherError::Readiness(
            TuiReadinessError::Deadline,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    const THREAD_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    static NEXT_PACKAGE_LAUNCHER_TEST: AtomicU64 = AtomicU64::new(0);

    struct PackageLauncherTestFile {
        root: PathBuf,
        executable: PathBuf,
    }

    impl PackageLauncherTestFile {
        fn create() -> Result<Self, Box<dyn std::error::Error>> {
            let sequence = NEXT_PACKAGE_LAUNCHER_TEST.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "calcifer-package-launcher-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let root = fs::canonicalize(root)?;
            let executable = root.join("calcifer-supervisor-fixture");
            fs::write(&executable, b"fixture")?;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
            Ok(Self { root, executable })
        }
    }

    impl Drop for PackageLauncherTestFile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn remote_command() -> Command {
        let mut command = Command::new("/private/calcifer/staged/codex");
        command
            .args([
                "-c",
                CLI_CREDENTIALS_OVERRIDE,
                "-c",
                MCP_CREDENTIALS_OVERRIDE,
                "resume",
                "--no-alt-screen",
                "--remote",
                "unix:///tmp/calcifer.sock",
                THREAD_ID,
            ])
            .current_dir("/tmp")
            .env("CODEX_HOME", "/private/calcifer/profile")
            .env_remove("OPENAI_API_KEY");
        command
    }

    fn assert_build_independent<T: 'static>() {}

    #[test]
    fn packaged_launch_failure_classification_is_fixed_and_separates_authority_state() {
        assert_eq!(
            packaged_launch_failure_state_marker(None),
            "startup-failure.tui-launch.state.before-spawn"
        );
        assert_eq!(
            packaged_launch_failure_state_marker(Some(SpawnFailureState::NotStarted)),
            "startup-failure.tui-launch.state.spawn-not-started"
        );
        assert_eq!(
            packaged_launch_failure_state_marker(Some(SpawnFailureState::ReapedUnannounced)),
            "startup-failure.tui-launch.state.started-unannounced-reaped"
        );
        assert_eq!(
            packaged_launch_failure_state_marker(Some(SpawnFailureState::LiveUnannouncedChild)),
            "startup-failure.tui-launch.state.started-unannounced-live"
        );
        assert_eq!(
            packaged_tui_launch_error_marker(RemoteTuiLauncherError::Provider(
                ProviderLaunchError::Timeout,
            )),
            "startup-failure.tui-launch.subtype.provider-timeout"
        );
        assert_eq!(
            packaged_tui_launch_error_marker(RemoteTuiLauncherError::Process(
                ProcessError::SessionStartupTimeout {
                    role: ChildRole::Tui,
                },
            )),
            "startup-failure.tui-launch.subtype.process-session-startup-timeout"
        );
        assert_eq!(
            packaged_tui_launch_error_marker(RemoteTuiLauncherError::Process(
                ProcessError::TuiOutputDrain {
                    role: ChildRole::Tui,
                },
            )),
            "startup-failure.tui-launch.subtype.process-tui-output-drain"
        );
    }

    #[test]
    fn shutdown_output_drain_is_strictly_bounded_per_process_poll() -> Result<(), ()> {
        let mut reads = 0_usize;

        let closed = run_bounded_tui_shutdown_drain(|| {
            reads += 1;
            Ok(TuiShutdownDrainObservation::Data)
        })?;

        assert!(!closed);
        assert_eq!(reads, TUI_SHUTDOWN_DRAIN_MAX_FRAGMENTS_PER_POLL);
        Ok(())
    }

    #[test]
    fn shutdown_output_drain_stops_on_idle_eof_or_error() -> Result<(), ()> {
        for (observation, expected_closed) in [
            (TuiShutdownDrainObservation::WouldBlock, false),
            (TuiShutdownDrainObservation::EndOfStream, true),
        ] {
            let mut reads = 0_usize;
            let closed = run_bounded_tui_shutdown_drain(|| {
                reads += 1;
                Ok(observation)
            })?;
            assert_eq!(reads, 1);
            assert_eq!(closed, expected_closed);
        }

        let mut reads = 0_usize;
        assert_eq!(
            run_bounded_tui_shutdown_drain(|| {
                reads += 1;
                Err(())
            }),
            Err(())
        );
        assert_eq!(reads, 1);
        Ok(())
    }

    #[test]
    fn every_post_spawn_authority_is_independent_of_the_borrowed_build() {
        assert_build_independent::<PendingRemoteTui>();
        assert_build_independent::<ReadyRemoteTui>();
        assert_build_independent::<RemoteTuiLaunchFailure>();
        assert_build_independent::<RemoteTuiLaunchResolution>();
        assert_build_independent::<RemoteTuiReadinessFailure>();
        assert_build_independent::<RemoteTuiReadinessContainmentFailure>();
        assert_build_independent::<RemoteTuiReadinessResolution>();
        assert_build_independent::<RemoteTuiShutdownFailure>();

        let _pending_observer: fn(&PendingRemoteTui) -> ContainmentMetadata =
            PendingRemoteTui::containment;
        let _ready_observer: fn(&ReadyRemoteTui) -> ContainmentMetadata =
            ReadyRemoteTui::containment;
        let _pending_descriptor_observer: fn(
            &PendingRemoteTui,
            &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
            Instant,
        ) -> Result<
            calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
        > = PendingRemoteTui::observe_forbidden_descriptors_absent;
        let _ready_descriptor_observer: fn(
            &ReadyRemoteTui,
            &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
            Instant,
        ) -> Result<
            calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
        > = ReadyRemoteTui::observe_forbidden_descriptors_absent;
    }

    #[test]
    fn launcher_wraps_only_the_closed_remote_tui_schema_and_preserves_context() {
        let target = remote_command();
        let launcher = prepare_launcher_command(&target, Path::new("/private/calcifer/bin"))
            .unwrap_or_else(|error| panic!("launcher preparation failed: {error}"));

        assert!(launcher.get_args().next().is_none());
        assert_eq!(launcher.get_current_dir(), Some(Path::new("/tmp")));
        assert!(launcher.get_envs().any(|(name, value)| {
            name == OsStr::new("CODEX_HOME")
                && value == Some(OsStr::new("/private/calcifer/profile"))
        }));
        // `env_clear` may elide a subsequent explicit removal from
        // `Command::get_envs`; the builder invariant is that the forbidden
        // key has no concrete value. The real-exec environment fixture also
        // verifies that an ambient value is absent in the launched process.
        assert!(
            !launcher
                .get_envs()
                .any(|(name, value)| { name == OsStr::new("OPENAI_API_KEY") && value.is_some() })
        );
        assert_eq!(
            launcher
                .get_envs()
                .find(|(name, _)| *name == OsStr::new(TARGET_THREAD_ENV))
                .and_then(|(_, value)| value),
            Some(OsStr::new(THREAD_ID))
        );
    }

    #[test]
    fn launcher_accepts_explicit_private_environment_removal_without_a_concrete_value() {
        let mut target = remote_command();
        target.env_remove(calcifer_unix_child_fd::READINESS_FD_ENV);

        let launcher = prepare_launcher_command(&target, Path::new("/private/calcifer/bin"))
            .unwrap_or_else(|error| panic!("safe environment removal was rejected: {error}"));

        assert!(!launcher.get_envs().any(|(name, value)| {
            name == OsStr::new(calcifer_unix_child_fd::READINESS_FD_ENV) && value.is_some()
        }));
    }

    #[test]
    fn packaged_launcher_path_is_canonical_owned_regular_single_link_and_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackageLauncherTestFile::create()?;
        assert_eq!(
            validate_packaged_launcher_executable(&fixture.executable)?,
            fixture.executable
        );

        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            validate_packaged_launcher_executable(&fixture.executable),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700))?;

        let hard_link = fixture.root.join("fixture-hard-link");
        fs::hard_link(&fixture.executable, &hard_link)?;
        assert_eq!(
            validate_packaged_launcher_executable(&fixture.executable),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );
        fs::remove_file(hard_link)?;

        for mode in [0o720, 0o4700, 0o2700] {
            fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(mode))?;
            assert_eq!(
                validate_packaged_launcher_executable(&fixture.executable),
                Err(RemoteTuiLauncherError::LauncherUnavailable)
            );
        }
        Ok(())
    }

    #[test]
    fn packaged_launcher_path_rejects_relative_symlink_directory_and_empty_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackageLauncherTestFile::create()?;
        assert_eq!(
            validate_packaged_launcher_executable(Path::new("calcifer-supervisor-fixture")),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );

        let link = fixture.root.join("fixture-link");
        symlink(&fixture.executable, &link)?;
        assert_eq!(
            validate_packaged_launcher_executable(&link),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );
        assert_eq!(
            validate_packaged_launcher_executable(&fixture.root),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );

        fs::write(&fixture.executable, b"")?;
        assert_eq!(
            validate_packaged_launcher_executable(&fixture.executable),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );
        Ok(())
    }

    #[test]
    fn launcher_identity_recheck_rejects_a_post_prepare_path_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = PackageLauncherTestFile::create()?;
        let identity = LauncherExecutableIdentity::capture(&fixture.executable)?;
        let original = fixture.root.join("fixture-original");
        fs::rename(&fixture.executable, &original)?;
        fs::write(&fixture.executable, b"replacement")?;
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700))?;

        assert_eq!(
            identity.revalidate(),
            Err(RemoteTuiLauncherError::LauncherUnavailable)
        );
        assert!(original.exists());
        assert!(fixture.executable.exists());
        Ok(())
    }

    #[test]
    fn packaged_launcher_override_is_private_authority_and_is_removed_before_exec() {
        let mut injected = remote_command();
        injected.env(PACKAGED_TUI_LAUNCHER_ENV, "/private/calcifer/injected");
        assert_eq!(
            prepare_launcher_command(&injected, Path::new("/private/calcifer/bin"))
                .err()
                .unwrap_or(RemoteTuiLauncherError::Exec),
            RemoteTuiLauncherError::InvalidCommand
        );

        let launcher =
            prepare_launcher_command(&remote_command(), Path::new("/private/calcifer/bin"))
                .unwrap_or_else(|error| panic!("launcher preparation failed: {error}"));
        assert!(!launcher.get_envs().any(|(name, value)| {
            name == OsStr::new(PACKAGED_TUI_LAUNCHER_ENV) && value.is_some()
        }));
    }

    #[test]
    fn launcher_rejects_shells_extra_arguments_and_private_environment_injection() {
        let mut shell = remote_command();
        shell.arg("--last");
        assert_eq!(
            prepare_launcher_command(&shell, Path::new("/private/calcifer/bin"))
                .err()
                .unwrap_or(RemoteTuiLauncherError::Exec),
            RemoteTuiLauncherError::InvalidCommand
        );

        let mut injected = remote_command();
        injected.env(TARGET_PROGRAM_ENV, "/bin/sh");
        assert_eq!(
            prepare_launcher_command(&injected, Path::new("/private/calcifer/bin"))
                .err()
                .unwrap_or(RemoteTuiLauncherError::Exec),
            RemoteTuiLauncherError::InvalidCommand
        );
    }

    #[test]
    fn launcher_environment_is_scrubbed_from_the_exec_command() {
        let mut command = Command::new("/private/calcifer/staged/codex");
        for name in [
            LAUNCH_CONTRACT_ENV,
            TARGET_PROGRAM_ENV,
            TARGET_SOCKET_ENV,
            TARGET_THREAD_ENV,
            calcifer_unix_child_fd::READINESS_FD_ENV,
        ] {
            command.env(name, OsStr::from_bytes(b"synthetic"));
        }
        scrub_launcher_environment(&mut command);
        assert!(command.get_envs().all(|(_, value)| value.is_none()));
    }
}
