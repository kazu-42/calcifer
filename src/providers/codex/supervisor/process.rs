//! Guardian-owned process-group supervision for the staged Codex supervisor.
//!
//! This module deliberately keeps direct [`Child`] handles. Reported process
//! identifiers are containment metadata only; they are never wait authority.

use std::fmt;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::protocol::{ChildDisposition, ChildRole, StopAction, UnixSignal};

const READINESS_SENTINEL: u8 = b'R';
const TUI_READINESS_TOKEN: u8 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
// A Linux attempt walks the process table and target fd tables twice. Give
// transient churn time to settle without consuming an entire startup budget.
const DESCRIPTOR_OBSERVATION_SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const SPAWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const DROP_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
static NEXT_CHILD_AUTHORITY: AtomicU64 = AtomicU64::new(1);

/// A fixed, redacted failure at the one-shot TUI launcher readiness boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TuiReadinessError {
    Channel,
    Descriptor,
    Inherited,
    Invalid,
    Timeout,
    Deadline,
}

impl fmt::Display for TuiReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Channel => "TUI readiness channel failed",
            Self::Descriptor => "TUI readiness descriptor was invalid",
            Self::Inherited => "TUI readiness capability was unavailable",
            Self::Invalid => "TUI readiness proof was invalid",
            Self::Timeout => "TUI readiness exceeded its deadline",
            Self::Deadline => "TUI readiness deadline was invalid",
        })
    }
}

impl std::error::Error for TuiReadinessError {}

/// Capability proving that the launcher emitted exactly one token and then
/// closed its write half. Its fields are private so later terminal typestates
/// cannot manufacture readiness from a byte or a child PID.
pub(super) struct VerifiedTuiReadiness {
    _private: (),
}

impl fmt::Debug for VerifiedTuiReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedTuiReadiness(<verified>)")
    }
}

/// Guardian-side half of the bounded launcher readiness protocol.
pub(super) struct TuiReadinessReceiver {
    stream: UnixStream,
    saw_token: bool,
}

/// Child-only descriptor authority. It exposes only `AsFd`, which lets the
/// audited inheritance crate duplicate it for one selected exec.
pub(super) struct TuiReadinessSender {
    stream: UnixStream,
}

impl AsFd for TuiReadinessSender {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

/// Creates a close-on-exec full-duplex readiness pair.
pub(super) fn tui_readiness_pair()
-> Result<(TuiReadinessReceiver, TuiReadinessSender), TuiReadinessError> {
    let (receiver, sender) = UnixStream::pair().map_err(|_| TuiReadinessError::Channel)?;
    for stream in [&receiver, &sender] {
        let flags = rustix::io::fcntl_getfd(stream).map_err(|_| TuiReadinessError::Descriptor)?;
        rustix::io::fcntl_setfd(stream, flags | rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| TuiReadinessError::Descriptor)?;
        if !rustix::io::fcntl_getfd(stream)
            .map_err(|_| TuiReadinessError::Descriptor)?
            .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(TuiReadinessError::Descriptor);
        }
    }
    receiver
        .set_nonblocking(true)
        .map_err(|_| TuiReadinessError::Channel)?;
    Ok((
        TuiReadinessReceiver {
            stream: receiver,
            saw_token: false,
        },
        TuiReadinessSender { stream: sender },
    ))
}

impl TuiReadinessReceiver {
    pub(super) fn descriptor_identity(
        &self,
    ) -> Result<calcifer_unix_child_fd::DescriptorIdentity, TuiReadinessError> {
        calcifer_unix_child_fd::descriptor_identity(self.stream.as_fd())
            .map_err(|_| TuiReadinessError::Descriptor)
    }

    /// Waits for exactly `token + EOF`, never extending the caller's absolute
    /// deadline after EINTR, partial input, or a token without peer closure.
    pub(super) fn receive(
        &mut self,
        deadline: Instant,
    ) -> Result<VerifiedTuiReadiness, TuiReadinessError> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(TuiReadinessError::Timeout);
            }
            let timeout =
                rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
                    .map_err(|_| TuiReadinessError::Deadline)?;
            let mut descriptors = [rustix::event::PollFd::new(
                &self.stream,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut descriptors, Some(&timeout)) {
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(TuiReadinessError::Channel),
                Ok(0) => return Err(TuiReadinessError::Timeout),
                Ok(_) => {}
            }
            let events = descriptors[0].revents();
            if events.intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL) {
                return Err(TuiReadinessError::Channel);
            }
            if events.intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP) {
                if let Some(proof) = self.try_receive()? {
                    return Ok(proof);
                }
            }
        }
    }

    /// Performs one bounded two-byte read for guardian loops that must also
    /// interleave child liveness and lifecycle-channel checks.
    pub(super) fn try_receive(
        &mut self,
    ) -> Result<Option<VerifiedTuiReadiness>, TuiReadinessError> {
        let mut bytes = [0_u8; 2];
        match self.stream.read(&mut bytes) {
            Ok(0) if self.saw_token => Ok(Some(VerifiedTuiReadiness { _private: () })),
            Ok(0) => Err(TuiReadinessError::Invalid),
            Ok(1) if !self.saw_token && bytes[0] == TUI_READINESS_TOKEN => {
                self.saw_token = true;
                Ok(None)
            }
            Ok(_) => Err(TuiReadinessError::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(TuiReadinessError::Channel),
        }
    }
}

/// Launcher-side one-shot publisher acquired before any terminal mutation.
pub(super) struct InheritedTuiReadiness {
    stream: UnixStream,
}

impl InheritedTuiReadiness {
    pub(super) fn take() -> Result<Self, TuiReadinessError> {
        let inherited = calcifer_unix_child_fd::take_inherited_readiness_fd()
            .map_err(|_| TuiReadinessError::Inherited)?;
        Ok(Self {
            stream: UnixStream::from(inherited),
        })
    }

    /// Emits the sole fixed token and shuts down the write half. Shutdown is
    /// required because the sealed bootstrap descriptor remains open until
    /// the immediately following exec closes it via `FD_CLOEXEC`.
    pub(super) fn publish(mut self) -> Result<(), TuiReadinessError> {
        self.stream
            .write_all(&[TUI_READINESS_TOKEN])
            .and_then(|()| self.stream.flush())
            .map_err(|_| TuiReadinessError::Channel)?;
        self.stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| TuiReadinessError::Channel)
    }

    /// Writes the token without closing the socket. The caller must exec
    /// immediately: EOF is then generated only when `FD_CLOEXEC` seals the
    /// bootstrap descriptor at that exec boundary (or when a failed launcher
    /// exits). This lets the guardian distinguish a silent pre-exec stall from
    /// an exec attempt without passing the readiness fd to Codex.
    pub(super) fn publish_before_exec(mut self) -> Result<(), TuiReadinessError> {
        self.stream
            .write_all(&[TUI_READINESS_TOKEN])
            .and_then(|()| self.stream.flush())
            .map_err(|_| TuiReadinessError::Channel)
    }

    #[cfg(test)]
    fn from_stream_for_test(stream: UnixStream) -> Self {
        Self { stream }
    }
}

/// Process-local identity that cannot be reconstructed from a reported PID or
/// process-group number. It binds one-shot signal proofs to one direct child
/// handle even after the operating system reuses numeric process identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ChildAuthority(u64);

impl ChildAuthority {
    fn next() -> Self {
        match NEXT_CHILD_AUTHORITY.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        }) {
            Ok(authority) => Self(authority),
            Err(_) => std::process::abort(),
        }
    }

    #[cfg(test)]
    pub(super) const fn for_test(value: u64) -> Self {
        Self(value)
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

    #[cfg(test)]
    pub(super) const fn for_test(role: ChildRole, pid: i32, pgid: i32) -> Self {
        Self { role, pid, pgid }
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

/// Move-only evidence that the pinned official App Server received the
/// guardian's one allowed shutdown signal and then exited successfully.
///
/// Codex shell tools may call `setsid(2)` and leave the App Server's process
/// group. This capability is therefore not a kernel-level descendant-absence
/// proof. It authorizes release only under the pinned upstream App Server's
/// graceful running-turn shutdown contract: the exact direct child must exit
/// with code zero after this owner delivers its first and only `SIGTERM`.
#[must_use = "the pinned App graceful-drain evidence must stay attached to provider teardown"]
pub(super) struct PinnedAppGracefulDrain {
    outcome: ShutdownOutcome,
    _proof: PinnedAppGracefullyDrained,
}

struct PinnedAppGracefullyDrained {
    authority: ChildAuthority,
}

struct ShutdownCompletion {
    outcome: ShutdownOutcome,
    app_gracefully_drained: Option<PinnedAppGracefullyDrained>,
}

impl PinnedAppGracefulDrain {
    pub(super) const fn outcome(&self) -> &ShutdownOutcome {
        &self.outcome
    }

    pub(super) const fn child_authority(&self) -> ChildAuthority {
        self._proof.authority
    }

    #[cfg(test)]
    pub(super) const fn for_child_authority_test(authority: ChildAuthority) -> Self {
        Self {
            outcome: ShutdownOutcome::Clean(ReapedChildren {
                tui: ChildDisposition::NotStarted,
                app_server: ChildDisposition::NotStarted,
            }),
            _proof: PinnedAppGracefullyDrained { authority },
        }
    }
}

impl fmt::Debug for PinnedAppGracefulDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedAppGracefulDrain")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
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
enum TuiShutdownMode {
    StartWithTerm,
    SignalAlreadyForwarded(TerminalShutdownSignal),
    OutputEofObserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppGracefulDrainState {
    NotApplicable,
    AwaitingInitialTerm,
    InitialTermSent,
    Drained,
    Invalid,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedAppShutdownFault {
    Stop,
    Term,
    Cont,
}

impl AppGracefulDrainState {
    const fn for_role(role: ChildRole) -> Self {
        match role {
            ChildRole::AppServer => Self::AwaitingInitialTerm,
            ChildRole::Tui => Self::NotApplicable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionIdentityObservation {
    Pending,
    Exact,
}

/// Whether a synthetic fixture may use Darwin's bounded zombie-only group
/// observation after `killpg` returns `EPERM`.
///
/// Every real provider child is permanently `ProductionStrict`: EPERM alone
/// never becomes containment proof there. The fixture-only variant is explicit so
/// a test accommodation cannot silently reach App Server or official TUI
/// cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupContainmentPolicy {
    ProductionStrict,
    #[cfg(any(test, feature = "internal-supervisor-fixture"))]
    SyntheticFixture,
}

impl GroupContainmentPolicy {
    #[cfg(target_os = "macos")]
    fn permits_macos_eperm(self, _process_group: rustix::process::Pid) -> bool {
        match self {
            Self::ProductionStrict => false,
            #[cfg(any(test, feature = "internal-supervisor-fixture"))]
            Self::SyntheticFixture => calcifer_unix_child_fd::macos_process_group_has_live_members(
                _process_group.as_raw_nonzero().get(),
            )
            .is_ok_and(|has_live_members| !has_live_members),
        }
    }
}

/// Returns an independent Darwin absence proof for a wait-visible direct
/// leader that still pins its PID/PGID against reuse.
///
/// This does not reinterpret `EPERM` as success. The exact non-consuming wait
/// and the bounded, stable zombie-only group snapshots must both succeed;
/// every ambiguous observation remains an unresolved containment failure.
#[cfg(target_os = "macos")]
fn macos_anchored_zombie_group_absent(
    direct_child: rustix::process::Pid,
    process_group: rustix::process::Pid,
) -> bool {
    if direct_child != process_group {
        return false;
    }
    let terminal = rustix::process::waitid(
        rustix::process::WaitId::Pid(direct_child),
        rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::NOWAIT,
    )
    .ok()
    .flatten()
    .is_some_and(|status| status.exited() || status.killed() || status.dumped());
    terminal
        && calcifer_unix_child_fd::macos_process_group_is_anchored_zombie_only(
            process_group.as_raw_nonzero().get(),
            direct_child.as_raw_nonzero().get(),
        )
        .unwrap_or(false)
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
pub(super) enum AppGracefulDrainFailureStage {
    PriorInvalid,
    ExitedBeforeTerm,
    StopTimeout,
    ExitedWhileStopping,
    InvalidDisposition,
    KillForbidden,
    WrongRetryPath,
    MissingProof,
}

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
    Wait {
        role: ChildRole,
    },
    WaitTimeout {
        role: ChildRole,
    },
    TuiOutputDrain {
        role: ChildRole,
    },
    AppGracefulDrainUnconfirmed {
        role: ChildRole,
        stage: AppGracefulDrainFailureStage,
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
            Self::Wait { .. } => "supervised child wait failed",
            Self::WaitTimeout { .. } => "supervised child wait exceeded its deadline",
            Self::TuiOutputDrain { .. } => "supervised TUI shutdown output drain failed",
            Self::AppGracefulDrainUnconfirmed { .. } => {
                "the pinned App Server graceful drain remained unconfirmed"
            }
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
    kind: SpawnCleanupKind,
}

impl SpawnCleanupProof {
    pub(super) const fn started_unannounced(self) -> bool {
        matches!(self.kind, SpawnCleanupKind::ReapedUnannounced(_))
    }
}

struct FailedSpawnChild {
    child: Child,
    expected_group: Option<rustix::process::Pid>,
    containment_swept: bool,
    drop_deadline: Option<Instant>,
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            dead_code,
            reason = "read only by Darwin EPERM containment classification"
        )
    )]
    containment_policy: GroupContainmentPolicy,
    #[cfg(test)]
    force_group_sweep_failure: bool,
    #[cfg(all(test, target_os = "macos"))]
    force_group_sweep_permission_denied: bool,
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

    #[cfg(all(test, target_os = "macos"))]
    fn started(
        error: ProcessError,
        child: Child,
        expected_group: Option<rustix::process::Pid>,
    ) -> Self {
        Self::started_with_policy(
            error,
            child,
            expected_group,
            GroupContainmentPolicy::ProductionStrict,
        )
    }

    #[cfg(test)]
    fn started_fixture(
        error: ProcessError,
        child: Child,
        expected_group: Option<rustix::process::Pid>,
    ) -> Self {
        Self::started_with_policy(
            error,
            child,
            expected_group,
            GroupContainmentPolicy::SyntheticFixture,
        )
    }

    #[cfg(test)]
    pub(super) fn live_unannounced_app_for_test(
        mut command: Command,
    ) -> Result<(Self, ContainmentMetadata), std::io::Error> {
        command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        let pid = rustix::process::Pid::from_child(&child);
        let pgid = match rustix::process::getpgid(Some(pid)) {
            Ok(pgid) if pgid == pid => pgid,
            Ok(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::other(
                    "test App did not enter its exact process group",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::from(error));
            }
        };
        Ok((
            Self::started_fixture(
                ProcessError::Spawn {
                    role: ChildRole::AppServer,
                },
                child,
                Some(pgid),
            ),
            ContainmentMetadata {
                role: ChildRole::AppServer,
                pid: pid.as_raw_pid(),
                pgid: pgid.as_raw_pid(),
            },
        ))
    }

    fn started_with_policy(
        error: ProcessError,
        child: Child,
        expected_group: Option<rustix::process::Pid>,
        containment_policy: GroupContainmentPolicy,
    ) -> Self {
        Self {
            error,
            child: Some(FailedSpawnChild {
                child,
                expected_group,
                containment_swept: false,
                drop_deadline: None,
                containment_policy,
                #[cfg(test)]
                force_group_sweep_failure: false,
                #[cfg(all(test, target_os = "macos"))]
                force_group_sweep_permission_denied: false,
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
                kind: SpawnCleanupKind::NotStarted,
            });
        }
        if self.child.is_none() {
            if let Some(disposition) = self.disposition {
                return Ok(SpawnCleanupProof {
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
    #[cfg(all(test, target_os = "macos"))]
    if failed_child.force_group_sweep_permission_denied {
        return failed_child
            .expected_group
            .is_some_and(|group| failed_child.containment_policy.permits_macos_eperm(group));
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
        Err(rustix::io::Errno::PERM)
            if macos_anchored_zombie_group_absent(
                rustix::process::Pid::from_child(&failed_child.child),
                expected_group,
            ) =>
        {
            true
        }
        #[cfg(target_os = "macos")]
        Err(rustix::io::Errno::PERM) => failed_child
            .containment_policy
            .permits_macos_eperm(expected_group),
        Err(_) => false,
    }
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
    app_graceful_drain: AppGracefulDrainState,
    drop_deadline: Option<Instant>,
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            dead_code,
            reason = "read only by Darwin EPERM containment classification"
        )
    )]
    containment_policy: GroupContainmentPolicy,
    #[cfg(test)]
    injected_app_shutdown_fault: Option<InjectedAppShutdownFault>,
}

impl ManagedGroupChild {
    pub(super) fn spawn(
        role: ChildRole,
        command: Command,
        readiness_stdout: bool,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_inner(
            role,
            command,
            readiness_stdout,
            false,
            GroupContainmentPolicy::ProductionStrict,
        )
    }

    /// Spawns a synthetic test child under the fixture-only Darwin policy.
    ///
    /// macOS may report `EPERM` while a process group contains only exited
    /// fixture members. Tests may use the bounded process-table scan to prove
    /// that synthetic absence, but real provider children must always use
    /// [`Self::spawn`] and retain `EPERM` as an unresolved containment error.
    #[cfg(test)]
    fn spawn_fixture(
        role: ChildRole,
        command: Command,
        readiness_stdout: bool,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_inner(
            role,
            command,
            readiness_stdout,
            false,
            GroupContainmentPolicy::SyntheticFixture,
        )
    }

    /// Spawns a synthetic child whose stdin closes if its guardian dies.
    ///
    /// The guardian retains the pipe writer through its exact [`Child`] handle.
    /// The fixed fixture child blocks on the read end after readiness, so an
    /// abrupt guardian exit makes it terminate without turning a reported PID
    /// into delayed signal authority. Production provider children must use a
    /// provider-specific liveness contract instead of assuming stdin is free.
    #[cfg(feature = "internal-supervisor-fixture")]
    pub(super) fn spawn_with_parent_liveness_pipe(
        role: ChildRole,
        command: Command,
        readiness_stdout: bool,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_inner(
            role,
            command,
            readiness_stdout,
            true,
            GroupContainmentPolicy::SyntheticFixture,
        )
    }

    #[cfg(test)]
    fn spawn_fixture_session_leader(
        role: ChildRole,
        mut command: Command,
        deadline: Instant,
    ) -> Result<Self, SpawnFailure> {
        let child = command
            .spawn()
            .map_err(|_| SpawnFailure::not_started(ProcessError::Spawn { role }))?;
        Self::publish_session_leader(
            role,
            child,
            deadline,
            GroupContainmentPolicy::SyntheticFixture,
        )
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
        Self::spawn_session_leader_with_inherited_fd_policy(
            role,
            command,
            inherited_fd,
            deadline,
            GroupContainmentPolicy::ProductionStrict,
        )
    }

    #[cfg(any(test, feature = "internal-supervisor-fixture"))]
    pub(super) fn spawn_fixture_session_leader_with_inherited_fd(
        role: ChildRole,
        command: Command,
        inherited_fd: BorrowedFd<'_>,
        deadline: Instant,
    ) -> Result<Self, SpawnFailure> {
        Self::spawn_session_leader_with_inherited_fd_policy(
            role,
            command,
            inherited_fd,
            deadline,
            GroupContainmentPolicy::SyntheticFixture,
        )
    }

    fn spawn_session_leader_with_inherited_fd_policy(
        role: ChildRole,
        command: Command,
        inherited_fd: BorrowedFd<'_>,
        deadline: Instant,
        containment_policy: GroupContainmentPolicy,
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
                        containment_policy,
                    ));
                }
                None => return Err(SpawnFailure::not_started(ProcessError::Spawn { role })),
            },
        };
        Self::publish_session_leader(role, child, deadline, containment_policy)
    }

    fn publish_session_leader(
        role: ChildRole,
        child: Child,
        deadline: Instant,
        containment_policy: GroupContainmentPolicy,
    ) -> Result<Self, SpawnFailure> {
        Self::publish_session_leader_with_probe(role, child, deadline, containment_policy, |pid| {
            observe_session_identity(pid, role)
        })
    }

    fn publish_session_leader_with_probe<F>(
        role: ChildRole,
        mut child: Child,
        deadline: Instant,
        containment_policy: GroupContainmentPolicy,
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
                        app_graceful_drain: AppGracefulDrainState::for_role(role),
                        drop_deadline: None,
                        containment_policy,
                        #[cfg(test)]
                        injected_app_shutdown_fault: None,
                    });
                }
                Ok(SessionIdentityObservation::Pending) => {}
                Err(error) => {
                    return Err(cleanup_unconfirmed_session(
                        child,
                        error,
                        containment_policy,
                    ));
                }
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
                        containment_policy,
                    ));
                }
                Ok(None) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(None) => {
                    return Err(cleanup_unconfirmed_session(
                        child,
                        ProcessError::SessionStartupTimeout { role },
                        containment_policy,
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
        containment_policy: GroupContainmentPolicy,
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
                    containment_policy,
                ));
            }
        };
        if pgid != pid {
            return Err(cleanup_failed_spawn(
                child,
                pid,
                ProcessError::ProcessGroupMismatch { role },
                containment_policy,
            ));
        }

        if parent_liveness_pipe && child.stdin.is_none() {
            return Err(cleanup_failed_spawn(
                child,
                pid,
                ProcessError::ParentLivenessUnavailable { role },
                containment_policy,
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
                        containment_policy,
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
            app_graceful_drain: AppGracefulDrainState::for_role(role),
            drop_deadline: None,
            containment_policy,
            #[cfg(test)]
            injected_app_shutdown_fault: None,
        })
    }

    pub(super) const fn containment(&self) -> ContainmentMetadata {
        ContainmentMetadata {
            role: self.role,
            pid: self.pid.as_raw_pid(),
            pgid: self.pgid.as_raw_pid(),
        }
    }

    pub(super) const fn child_authority(&self) -> ChildAuthority {
        self.authority
    }

    /// Takes a bounded, read-only snapshot of this exact process group.
    ///
    /// This observer carries no signal or wait authority. The returned proof
    /// is momentary and must be projected into a higher-level readiness or
    /// cleanup barrier by the owner that still retains this child.
    #[cfg(test)]
    pub(super) fn observe_forbidden_descriptors_absent(
        &self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        retry_descriptor_observation(deadline, |deadline| {
            calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                self.pgid.as_raw_pid(),
                forbidden,
                deadline,
            )
            .map_err(DescriptorObservationAttemptError::from_scan)
        })
    }

    /// Retries only transient process/fd snapshot races while the exact direct
    /// child handle remains live before and after every attempted scan.
    ///
    /// A successful return therefore represents the final stable double
    /// snapshot, not an earlier partial observation. Forbidden identities and
    /// every non-race failure remain immediately fatal.
    pub(super) fn observe_forbidden_descriptors_absent_while_live(
        &mut self,
        forbidden: &calcifer_unix_child_fd::CrossProcessDescriptorSet<'_>,
        deadline: Instant,
    ) -> Result<
        calcifer_unix_child_fd::ProcessGroupDescriptorIsolationProof,
        calcifer_unix_child_fd::ProcessGroupDescriptorScanError,
    > {
        let process_group = self.pgid.as_raw_pid();
        retry_descriptor_observation(deadline, |deadline| {
            self.confirm_running_after_readiness(deadline)
                .map_err(|_| DescriptorObservationAttemptError::terminal_process_changed())?;
            let observed =
                calcifer_unix_child_fd::verify_process_group_forbidden_descriptors_absent_before(
                    process_group,
                    forbidden,
                    deadline,
                );
            match observed {
                Ok(proof) => {
                    self.confirm_running_after_readiness(deadline)
                        .map_err(|_| {
                            DescriptorObservationAttemptError::terminal_process_changed()
                        })?;
                    Ok(proof)
                }
                Err(error @ (
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged
                    | calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged
                )) => {
                    self.confirm_running_after_readiness(deadline)
                        .map_err(|_| {
                            DescriptorObservationAttemptError::terminal_process_changed()
                        })?;
                    Err(DescriptorObservationAttemptError::from_scan(error))
                }
                Err(error) => Err(DescriptorObservationAttemptError::Terminal(error)),
            }
        })
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

    /// Rejects a direct child that has already become wait-visible at the
    /// token+EOF boundary. Launcher exec failures close their readiness fd as
    /// the launcher exits and therefore become typed early exits here.
    pub(super) fn confirm_running_after_readiness(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        if self.observe_exit_for_readiness(deadline)? {
            let disposition = self.contain_and_reap_observed_exit(deadline)?;
            Err(ProcessError::EarlyExit {
                role: self.role,
                disposition,
            })
        } else {
            Ok(())
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

    /// Continues a stopped TUI only to deliver an already-forwarded terminal
    /// shutdown signal. Unlike interactive resume, an exit caused by that
    /// signal is the expected result and is therefore not classified as an
    /// early-exit error. No input-gate authority is created here.
    pub(super) fn continue_after_forwarded_shutdown(
        &mut self,
        forwarded: &ForwardedTuiSignal,
        deadline: Instant,
    ) -> Result<(), ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        if !forwarded.matches(self) {
            return Err(ProcessError::ForwardedSignalMismatch {
                role: ChildRole::Tui,
            });
        }
        self.signal_group(rustix::process::Signal::CONT, StopAction::None, deadline)
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
        let leader_stopped_after_tstp = self.wait_for_stopped(graceful_deadline)?;
        self.signal_group(
            rustix::process::Signal::STOP,
            StopAction::None,
            forced_deadline,
        )?;
        // A graceful STOPPED notification is consumed before the mandatory
        // descendant sweep. Waiting for another leader notification in that
        // case would require an implementation-specific duplicate. When the
        // leader ignored SIGTSTP, however, the SIGSTOP notification is the
        // required proof that the forced fallback took effect.
        if leader_stopped_after_tstp || self.wait_for_stopped(forced_deadline)? {
            Ok(())
        } else {
            Err(ProcessError::SuspendTimeout { role: self.role })
        }
    }

    /// Continues a previously stopped TUI and rejects an already-exited direct
    /// child before the input gate can be reopened.
    ///
    /// A successful `SIGCONT` to the identity-pinned process group performs the
    /// continuation action even when the kernel coalesces its advisory
    /// `CLD_CONTINUED` wait notification. Requiring that edge notification can
    /// therefore turn a live resumed TUI into a false timeout. Exact exit wait
    /// authority remains unconsumed and the higher-level gate rechecks liveness
    /// immediately before ingress starts.
    pub(super) fn resume(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        self.role_matches(ChildRole::Tui)?;
        self.signal_group(rustix::process::Signal::CONT, StopAction::None, deadline)?;
        if self.observe_exit_without_reaping(Instant::now())? {
            let disposition = self.contain_and_reap_observed_exit(deadline)?;
            return Err(ProcessError::EarlyExit {
                role: self.role,
                disposition,
            });
        }
        Ok(())
    }

    fn wait_for_stopped(&mut self, deadline: Instant) -> Result<bool, ProcessError> {
        loop {
            let options = rustix::process::WaitIdOptions::STOPPED
                | rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT;
            match rustix::process::waitid(rustix::process::WaitId::Pid(self.pid), options) {
                Ok(Some(status)) if status.stopped() => {
                    // Consume only the nonterminal job-control notification.
                    // Exit authority remains with the exact `Child` handle.
                    let consumed = rustix::process::waitid(
                        rustix::process::WaitId::Pid(self.pid),
                        rustix::process::WaitIdOptions::STOPPED
                            | rustix::process::WaitIdOptions::NOHANG,
                    );
                    return match consumed {
                        Ok(Some(consumed)) if consumed.stopped() => Ok(true),
                        Ok(Some(_)) | Ok(None) => Err(ProcessError::Wait { role: self.role }),
                        Err(_) => Err(ProcessError::Wait { role: self.role }),
                    };
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
                Ok(Some(_)) | Ok(None) => {
                    return Ok(false);
                }
                Err(rustix::io::Errno::INTR) if Instant::now() < deadline => {}
                Err(rustix::io::Errno::INTR) => {
                    return Ok(false);
                }
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
            Err(rustix::io::Errno::PERM)
                if macos_anchored_zombie_group_absent(self.pid, self.pgid) =>
            {
                Ok(())
            }
            #[cfg(target_os = "macos")]
            Err(rustix::io::Errno::PERM)
                if self.containment_policy.permits_macos_eperm(self.pgid) =>
            {
                Ok(())
            }
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

    fn try_reap_app_server(&mut self) -> Result<bool, ProcessError> {
        if self.disposition.is_some() {
            return Ok(true);
        }
        if self.role != ChildRole::AppServer {
            return Err(ProcessError::RoleMismatch {
                expected: ChildRole::AppServer,
                actual: self.role,
            });
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let disposition = project_disposition(status, self.stop_action);
                self.disposition = Some(disposition);
                self.observed_exit = true;
                self.app_graceful_drain = if self.app_graceful_drain
                    == AppGracefulDrainState::InitialTermSent
                    && disposition
                        == (ChildDisposition::Exited {
                            code: 0,
                            stop_action: StopAction::Term,
                        }) {
                    AppGracefulDrainState::Drained
                } else {
                    AppGracefulDrainState::Invalid
                };
                if self.app_graceful_drain == AppGracefulDrainState::Drained {
                    Ok(true)
                } else {
                    Err(ProcessError::AppGracefulDrainUnconfirmed {
                        role: self.role,
                        stage: AppGracefulDrainFailureStage::InvalidDisposition,
                    })
                }
            }
            Ok(None) => Ok(false),
            Err(_) => {
                self.app_graceful_drain = AppGracefulDrainState::Invalid;
                Err(ProcessError::Wait { role: self.role })
            }
        }
    }

    fn begin_app_server_shutdown(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        match self.app_graceful_drain {
            AppGracefulDrainState::Drained | AppGracefulDrainState::InitialTermSent => {
                return Ok(());
            }
            AppGracefulDrainState::Invalid => {
                return Err(ProcessError::AppGracefulDrainUnconfirmed {
                    role: self.role,
                    stage: AppGracefulDrainFailureStage::PriorInvalid,
                });
            }
            AppGracefulDrainState::NotApplicable => {
                return Err(ProcessError::RoleMismatch {
                    expected: ChildRole::AppServer,
                    actual: self.role,
                });
            }
            AppGracefulDrainState::AwaitingInitialTerm => {}
        }

        // Invalid is written before either observation or signal. Any syscall
        // failure therefore permanently removes permission to retry TERM.
        self.app_graceful_drain = AppGracefulDrainState::Invalid;
        match self.observe_exit_without_reaping(deadline) {
            Ok(true) => {
                let _ = self.try_reap_app_server();
                return Err(ProcessError::AppGracefulDrainUnconfirmed {
                    role: self.role,
                    stage: AppGracefulDrainFailureStage::ExitedBeforeTerm,
                });
            }
            Ok(false) => {}
            Err(error) => return Err(error),
        }

        // Pin the exact unreaped leader in a stopped state before queuing the
        // shutdown signal. This closes the observation-to-signal race where a
        // group-wide `killpg` can succeed only because another same-group
        // member survived after the App leader exited. The direct Child wait
        // authority prevents numeric PID reuse until this protocol resolves.
        #[cfg(test)]
        if self.injected_app_shutdown_fault == Some(InjectedAppShutdownFault::Stop) {
            return Err(ProcessError::Signal {
                role: self.role,
                action: StopAction::None,
            });
        }
        rustix::process::kill_process(self.pid, rustix::process::Signal::STOP).map_err(|_| {
            ProcessError::Signal {
                role: self.role,
                action: StopAction::None,
            }
        })?;
        match self.wait_for_stopped(deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ProcessError::AppGracefulDrainUnconfirmed {
                    role: self.role,
                    stage: AppGracefulDrainFailureStage::StopTimeout,
                });
            }
            Err(ProcessError::EarlyExit { .. }) => {
                let _ = self.try_reap_app_server();
                return Err(ProcessError::AppGracefulDrainUnconfirmed {
                    role: self.role,
                    stage: AppGracefulDrainFailureStage::ExitedWhileStopping,
                });
            }
            Err(error) => return Err(error),
        }

        #[cfg(test)]
        if self.injected_app_shutdown_fault == Some(InjectedAppShutdownFault::Term) {
            return Err(ProcessError::Signal {
                role: self.role,
                action: StopAction::Term,
            });
        }
        self.stop_action = StopAction::Term;
        // Queue TERM on the exact stopped leader. No group member can make
        // this syscall look successful on behalf of a leader that raced to
        // exit, and no detached tool receives an independent shutdown signal.
        rustix::process::kill_process(self.pid, rustix::process::Signal::TERM).map_err(|_| {
            ProcessError::Signal {
                role: self.role,
                action: StopAction::Term,
            }
        })?;
        // Delivery occurs only after this exact continuation edge. A failure
        // leaves the state permanently invalid: retries may observe/reap but
        // may never issue another STOP, TERM, CONT, or KILL.
        #[cfg(test)]
        if self.injected_app_shutdown_fault == Some(InjectedAppShutdownFault::Cont) {
            return Err(ProcessError::Signal {
                role: self.role,
                action: StopAction::None,
            });
        }
        rustix::process::kill_process(self.pid, rustix::process::Signal::CONT).map_err(|_| {
            ProcessError::Signal {
                role: self.role,
                action: StopAction::None,
            }
        })?;
        self.app_graceful_drain = AppGracefulDrainState::InitialTermSent;
        Ok(())
    }

    fn begin_termination(&mut self, deadline: Instant) -> Result<(), ProcessError> {
        if self.role == ChildRole::AppServer {
            return self.begin_app_server_shutdown(deadline);
        }
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
        if self.role == ChildRole::AppServer {
            self.app_graceful_drain = AppGracefulDrainState::Invalid;
            return Err(ProcessError::AppGracefulDrainUnconfirmed {
                role: self.role,
                stage: AppGracefulDrainFailureStage::KillForbidden,
            });
        }
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

enum DescriptorObservationAttemptError {
    TransientProcessChanged,
    TransientDescriptorChanged,
    Terminal(calcifer_unix_child_fd::ProcessGroupDescriptorScanError),
}

impl DescriptorObservationAttemptError {
    fn from_scan(error: calcifer_unix_child_fd::ProcessGroupDescriptorScanError) -> Self {
        match error {
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged => {
                Self::TransientProcessChanged
            }
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::DescriptorChanged => {
                Self::TransientDescriptorChanged
            }
            error => Self::Terminal(error),
        }
    }

    fn terminal_process_changed() -> Self {
        Self::Terminal(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged)
    }
}

fn retry_descriptor_observation<T>(
    caller_deadline: Instant,
    mut observe: impl FnMut(Instant) -> Result<T, DescriptorObservationAttemptError>,
) -> Result<T, calcifer_unix_child_fd::ProcessGroupDescriptorScanError> {
    let deadline = descriptor_observation_deadline(Instant::now(), caller_deadline);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline);
        }
        match observe(deadline) {
            Ok(proof) => return Ok(proof),
            Err(
                DescriptorObservationAttemptError::TransientProcessChanged
                | DescriptorObservationAttemptError::TransientDescriptorChanged,
            ) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline);
                }
                thread::sleep(deadline.saturating_duration_since(now).min(POLL_INTERVAL));
            }
            Err(DescriptorObservationAttemptError::Terminal(error)) => return Err(error),
        }
    }
}

fn descriptor_observation_deadline(now: Instant, caller_deadline: Instant) -> Instant {
    match now.checked_add(DESCRIPTOR_OBSERVATION_SETTLE_TIMEOUT) {
        Some(settle_deadline) if settle_deadline < caller_deadline => settle_deadline,
        Some(_) | None => caller_deadline,
    }
}

impl Drop for ManagedGroupChild {
    fn drop(&mut self) {
        if self.role == ChildRole::AppServer {
            if self.app_graceful_drain == AppGracefulDrainState::Drained
                && self.disposition.is_some()
            {
                return;
            }
            // An ambiguous App owner may contain detached-session tools. Drop
            // has no authority to send a second shutdown edge or a forced
            // signal, and direct reap alone cannot satisfy the pinned App
            // graceful-drain contract.
            // Structured production recovery parks while retaining this owner;
            // accidental unwinding fails closed without signalling anything.
            unreaped_drop_is_fatal();
        }
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
    #[cfg(test)]
    pub(super) fn retry(
        &mut self,
        grace: Duration,
        forced: Duration,
    ) -> Result<ShutdownOutcome, ProcessError> {
        self.retry_inner(grace, forced, None)
    }

    pub(super) fn retry_with_tui_output_progress(
        &mut self,
        grace: Duration,
        forced: Duration,
        progress: &mut dyn FnMut() -> Result<(), ProcessError>,
    ) -> Result<ShutdownOutcome, ProcessError> {
        self.retry_inner(grace, forced, Some(progress))
    }

    fn retry_inner(
        &mut self,
        grace: Duration,
        forced: Duration,
        tui_output_progress: Option<&mut dyn FnMut() -> Result<(), ProcessError>>,
    ) -> Result<ShutdownOutcome, ProcessError> {
        if self.resolved {
            return Err(ProcessError::RetryAfterResolution);
        }
        if [self.tui.as_ref(), self.app_server.as_ref()]
            .into_iter()
            .flatten()
            .any(|child| child.role == ChildRole::AppServer)
        {
            return Err(ProcessError::AppGracefulDrainUnconfirmed {
                role: ChildRole::AppServer,
                stage: AppGracefulDrainFailureStage::WrongRetryPath,
            });
        }
        match shutdown_pair_inner_with_tui_output_progress(
            self.tui.take(),
            self.app_server.take(),
            grace,
            forced,
            self.tui_shutdown_mode,
            Some(self.error),
            tui_output_progress,
        ) {
            Ok(completion) => {
                self.resolved = true;
                Ok(completion.outcome)
            }
            Err(mut unreaped) => {
                self.error = unreaped.error;
                self.tui = unreaped.tui.take();
                self.app_server = unreaped.app_server.take();
                Err(self.error)
            }
        }
    }

    #[cfg(test)]
    fn retry_fixture(
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
            Ok(completion) => {
                self.resolved = true;
                Ok(completion.outcome)
            }
            Err(mut unreaped) => {
                self.error = unreaped.error;
                self.tui = unreaped.tui.take();
                self.app_server = unreaped.app_server.take();
                Err(self.error)
            }
        }
    }

    /// Retries only observation/reaping for an App shutdown that already used
    /// its one signal sequence. The stored App state makes a second STOP,
    /// TERM, CONT, or KILL structurally unreachable.
    pub(super) fn retry_app_server(
        &mut self,
        grace: Duration,
        forced: Duration,
    ) -> Result<PinnedAppGracefulDrain, ProcessError> {
        if self.resolved {
            return Err(ProcessError::RetryAfterResolution);
        }
        if self.tui.is_some()
            || self
                .app_server
                .as_ref()
                .is_none_or(|child| child.role != ChildRole::AppServer)
        {
            return Err(ProcessError::RoleMismatch {
                expected: ChildRole::AppServer,
                actual: self
                    .app_server
                    .as_ref()
                    .map_or(ChildRole::Tui, |child| child.role),
            });
        }
        match shutdown_pair_inner(
            None,
            self.app_server.take(),
            grace,
            forced,
            self.tui_shutdown_mode,
            Some(self.error),
        ) {
            Ok(completion) => {
                let Some(proof) = completion.app_gracefully_drained else {
                    std::process::abort();
                };
                self.resolved = true;
                Ok(PinnedAppGracefulDrain {
                    outcome: completion.outcome,
                    _proof: proof,
                })
            }
            Err(mut unreaped) => {
                self.error = unreaped.error;
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

/// Synthetic combined shutdown used only by the internal supervisor fixture.
/// Production App ownership must use [`shutdown_app_server_child`] so pinned
/// graceful-drain evidence cannot be erased into a bare outcome.
#[cfg(any(test, feature = "internal-supervisor-fixture"))]
pub(super) fn shutdown_fixture_pair(
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
    .map(|completion| completion.outcome)
}

/// Stops one TUI while allowing its sole PTY-master owner to make bounded
/// output-drain progress between wait observations.
///
/// On Darwin a controlling-terminal process can enter `P_WEXIT` and remain
/// invisible to `waitpid(2)` while `ttywait()` waits for the PTY master to
/// consume final output. The callback is deliberately synchronous and
/// non-owning: the launcher retains the exact PTY master and this process
/// module retains the exact child wait authority for the whole attempt.
pub(super) fn shutdown_tui_child_with_output_progress(
    tui: ManagedGroupChild,
    grace: Duration,
    forced: Duration,
    progress: &mut dyn FnMut() -> Result<(), ProcessError>,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    shutdown_pair_inner_with_tui_output_progress(
        Some(tui),
        None,
        grace,
        forced,
        TuiShutdownMode::StartWithTerm,
        None,
        Some(progress),
    )
    .map(|completion| completion.outcome)
}

/// Runs the official App Server's one-shot graceful-drain protocol.
///
/// Unlike the generic fixture-facing pair helper, this production boundary
/// returns move-only pinned-App graceful-drain evidence.
pub(super) fn shutdown_app_server_child(
    app_server: ManagedGroupChild,
    grace: Duration,
    forced: Duration,
) -> Result<PinnedAppGracefulDrain, Box<UnreapedChildren>> {
    if app_server.role != ChildRole::AppServer {
        let actual = app_server.role;
        return Err(unreaped_children(
            None,
            Some(app_server),
            ProcessError::RoleMismatch {
                expected: ChildRole::AppServer,
                actual,
            },
            None,
            TuiShutdownMode::StartWithTerm,
        ));
    }
    let completion = shutdown_pair_inner(
        None,
        Some(app_server),
        grace,
        forced,
        TuiShutdownMode::StartWithTerm,
        None,
    )?;
    let Some(proof) = completion.app_gracefully_drained else {
        // Returning without the capability would release provider/runtime
        // authority under an internal invariant violation.
        std::process::abort();
    };
    Ok(PinnedAppGracefulDrain {
        outcome: completion.outcome,
        _proof: proof,
    })
}

/// Shuts down after an identity-checked TUI `HUP` or `TERM` was forwarded.
///
/// Unlike [`shutdown_fixture_pair`], this entrypoint never starts another `TERM` on
/// the proven TUI. It still starts the App Server with `TERM`, observes both
/// direct children until both exit or the grace deadline, performs a
/// process-group `KILL` containment sweep, and requires exact waits before
/// returning proof. If a deadline expires, [`UnreapedChildren::retry`]
/// retains this mode.
#[cfg(any(test, feature = "internal-supervisor-fixture"))]
pub(super) fn shutdown_fixture_pair_after_forwarded_tui_signal(
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
        .map(|completion| completion.outcome)
}

pub(super) fn shutdown_tui_after_forwarded_signal_with_output_progress(
    tui: ManagedGroupChild,
    forwarded: ForwardedTuiSignal,
    grace: Duration,
    forced: Duration,
    progress: &mut dyn FnMut() -> Result<(), ProcessError>,
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
    shutdown_pair_inner_with_tui_output_progress(
        Some(tui),
        None,
        grace,
        forced,
        mode,
        first_error,
        Some(progress),
    )
    .map(|completion| completion.outcome)
}

/// Shuts down after the exact TUI PTY master observed EOF.
///
/// EOF is a natural-exit hint, not permission to overwrite the child's Unix
/// disposition with `TERM`. The TUI therefore gets the full grace window to
/// become wait-visible without a signal; only the hard containment phase may
/// use `KILL`. App Server cleanup still starts with `TERM` immediately.
#[cfg(test)]
pub(super) fn shutdown_fixture_pair_after_tui_output_eof(
    tui: ManagedGroupChild,
    app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    shutdown_pair_inner(
        Some(tui),
        app_server,
        grace,
        forced,
        TuiShutdownMode::OutputEofObserved,
        None,
    )
    .map(|completion| completion.outcome)
}

pub(super) fn shutdown_tui_after_output_eof_with_output_progress(
    tui: ManagedGroupChild,
    grace: Duration,
    forced: Duration,
    progress: &mut dyn FnMut() -> Result<(), ProcessError>,
) -> Result<ShutdownOutcome, Box<UnreapedChildren>> {
    shutdown_pair_inner_with_tui_output_progress(
        Some(tui),
        None,
        grace,
        forced,
        TuiShutdownMode::OutputEofObserved,
        None,
        Some(progress),
    )
    .map(|completion| completion.outcome)
}

fn shutdown_pair_inner(
    tui: Option<ManagedGroupChild>,
    app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
    tui_shutdown_mode: TuiShutdownMode,
    first_error: Option<ProcessError>,
) -> Result<ShutdownCompletion, Box<UnreapedChildren>> {
    shutdown_pair_inner_with_tui_output_progress(
        tui,
        app_server,
        grace,
        forced,
        tui_shutdown_mode,
        first_error,
        None,
    )
}

fn shutdown_pair_inner_with_tui_output_progress(
    mut tui: Option<ManagedGroupChild>,
    mut app_server: Option<ManagedGroupChild>,
    grace: Duration,
    forced: Duration,
    tui_shutdown_mode: TuiShutdownMode,
    mut first_error: Option<ProcessError>,
    mut tui_output_progress: Option<&mut dyn FnMut() -> Result<(), ProcessError>>,
) -> Result<ShutdownCompletion, Box<UnreapedChildren>> {
    clear_drop_deadline(&mut tui);
    clear_drop_deadline(&mut app_server);

    let started_at = Instant::now();
    let Some(grace_deadline) = started_at.checked_add(grace) else {
        invalidate_undrained_app_children(&mut tui, &mut app_server);
        return Err(unreaped_children(
            tui,
            app_server,
            ProcessError::Deadline,
            None,
            tui_shutdown_mode,
        ));
    };
    let Some(hard_deadline) = grace_deadline.checked_add(forced) else {
        invalidate_undrained_app_children(&mut tui, &mut app_server);
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
        run_tui_output_progress(&mut tui_output_progress, &mut first_error);
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
        run_tui_output_progress(&mut tui_output_progress, &mut first_error);
        reap_child(&mut tui, &mut first_error);
        reap_child(&mut app_server, &mut first_error);
        if children_reaped(&tui, &app_server) {
            break;
        }
        if Instant::now() >= hard_deadline {
            invalidate_undrained_app_children(&mut tui, &mut app_server);
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

    if !app_children_drained(&tui, &app_server) {
        let error = first_error.unwrap_or(ProcessError::AppGracefulDrainUnconfirmed {
            role: ChildRole::AppServer,
            stage: AppGracefulDrainFailureStage::MissingProof,
        });
        return Err(unreaped_children(
            tui,
            app_server,
            error,
            None,
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
    let app_gracefully_drained = app_server.as_ref().and_then(|child| {
        (child.role == ChildRole::AppServer
            && child.app_graceful_drain == AppGracefulDrainState::Drained)
            .then_some(PinnedAppGracefullyDrained {
                authority: child.authority,
            })
    });
    let outcome = match first_error {
        Some(error) => ShutdownOutcome::Failed { children, error },
        None => ShutdownOutcome::Clean(children),
    };
    Ok(ShutdownCompletion {
        outcome,
        app_gracefully_drained,
    })
}

fn run_tui_output_progress(
    progress: &mut Option<&mut dyn FnMut() -> Result<(), ProcessError>>,
    first_error: &mut Option<ProcessError>,
) {
    if let Some(progress) = progress.as_deref_mut() {
        if let Err(error) = progress() {
            record_first_error(first_error, error);
        }
    }
}

fn invalidate_undrained_app_children(
    tui: &mut Option<ManagedGroupChild>,
    app_server: &mut Option<ManagedGroupChild>,
) {
    for child in [tui.as_mut(), app_server.as_mut()].into_iter().flatten() {
        if child.role == ChildRole::AppServer
            && child.app_graceful_drain != AppGracefulDrainState::Drained
        {
            child.app_graceful_drain = AppGracefulDrainState::Invalid;
        }
    }
}

fn app_children_drained(
    tui: &Option<ManagedGroupChild>,
    app_server: &Option<ManagedGroupChild>,
) -> bool {
    [tui.as_ref(), app_server.as_ref()]
        .into_iter()
        .flatten()
        .filter(|child| child.role == ChildRole::AppServer)
        .all(|child| child.app_graceful_drain == AppGracefulDrainState::Drained)
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
        if child.role == ChildRole::AppServer {
            return;
        }
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
        let reaped = if child.role == ChildRole::AppServer {
            child.try_reap_app_server()
        } else {
            child.try_reap_after_containment()
        };
        if let Err(error) = reaped {
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
    containment_policy: GroupContainmentPolicy,
) -> SpawnFailure {
    let failure = SpawnFailure::started_with_policy(
        original_error,
        child,
        Some(expected_group),
        containment_policy,
    );
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
                error: original_error,
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

fn cleanup_unconfirmed_session(
    child: Child,
    original_error: ProcessError,
    containment_policy: GroupContainmentPolicy,
) -> SpawnFailure {
    let failure =
        SpawnFailure::started_with_policy(original_error, child, None, containment_policy);
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
                error: original_error,
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
        | ProcessError::Wait { role }
        | ProcessError::WaitTimeout { role }
        | ProcessError::TuiOutputDrain { role }
        | ProcessError::AppGracefulDrainUnconfirmed { role, .. } => role,
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
    const SIGNAL_TERM_BEHAVIOR_ENV: &str = "CALCIFER_PROCESS_SIGNAL_TERM_BEHAVIOR";
    const UNREAPED_DROP_ABORT_HELPER_ENV: &str = "CALCIFER_PROCESS_UNREAPED_DROP_ABORT_HELPER";
    const UNREAPED_DROP_APP_PID_ENV: &str = "CALCIFER_PROCESS_UNREAPED_DROP_APP_PID";
    static SIGNAL_LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn typed_tui_readiness_requires_one_token_followed_by_eof() -> Result<(), Box<dyn Error>> {
        let (mut receiver, sender) = tui_readiness_pair()?;
        InheritedTuiReadiness::from_stream_for_test(sender.stream).publish()?;

        let proof = receiver.receive(Instant::now() + TEST_DEADLINE)?;
        assert_eq!(format!("{proof:?}"), "VerifiedTuiReadiness(<verified>)");
        Ok(())
    }

    #[test]
    fn typed_tui_readiness_rejects_malformed_and_duplicate_tokens() -> Result<(), Box<dyn Error>> {
        for payload in [[0_u8, 0_u8].as_slice(), [TUI_READINESS_TOKEN; 2].as_slice()] {
            let (mut receiver, mut sender) = tui_readiness_pair()?;
            sender.stream.write_all(payload)?;
            sender.stream.shutdown(std::net::Shutdown::Write)?;

            assert_eq!(
                receiver
                    .receive(Instant::now() + TEST_DEADLINE)
                    .err()
                    .ok_or("invalid readiness must fail")?,
                TuiReadinessError::Invalid
            );
        }
        Ok(())
    }

    #[test]
    fn typed_tui_readiness_uses_the_callers_absolute_deadline() -> Result<(), Box<dyn Error>> {
        let (mut receiver, _sender) = tui_readiness_pair()?;
        let deadline = Instant::now() + Duration::from_millis(30);

        assert_eq!(
            receiver
                .receive(deadline)
                .err()
                .ok_or("open silent readiness channel must time out")?,
            TuiReadinessError::Timeout
        );
        assert!(Instant::now() >= deadline);
        Ok(())
    }

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
                let failure = SpawnFailure::started_fixture(
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
                let failure = SpawnFailure::started_fixture(
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
                let mut failure = SpawnFailure::started_fixture(
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
                    ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
                // Avoid re-signalling an externally reaped numeric group in
                // this deterministic Drop test; the production safety net
                // already considers a completed containment sweep sufficient.
                child.containment_swept = true;
                externally_kill_and_reap(child.pid)?;
                drop(child);
            }
            Some("managed-child-group-drift") => {
                let mut child =
                    ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
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
            Some("app-managed-child-no-signal") => {
                let signal_log =
                    std::env::var_os(SIGNAL_LOG_ENV).ok_or("missing App Drop signal log path")?;
                let pid_log = std::env::var_os(UNREAPED_DROP_APP_PID_ENV)
                    .ok_or("missing App Drop PID log path")?;
                let mut command = Command::new(std::env::current_exe()?);
                command
                    .args([
                        "--exact",
                        "providers::codex::supervisor::process::tests::signal_counting_child_helper",
                        "--nocapture",
                    ])
                    .env(SIGNAL_COUNTING_HELPER_ENV, "1")
                    .env(SIGNAL_LOG_ENV, &signal_log)
                    .env(SIGNAL_TERM_BEHAVIOR_ENV, "ignore");
                let child = ManagedGroupChild::spawn_fixture(ChildRole::AppServer, command, false)?;
                let ready_deadline = Instant::now() + TEST_DEADLINE;
                loop {
                    match fs::read(&signal_log) {
                        Ok(bytes) if bytes == b"R" => break,
                        Ok(_) | Err(_) if Instant::now() < ready_deadline => {
                            sleep_until_next_poll(ready_deadline);
                        }
                        Ok(bytes) => {
                            return Err(format!("unexpected App Drop signal log: {bytes:?}").into());
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                fs::write(pid_log, child.pid.as_raw_pid().to_string())?;
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
    fn ambiguous_app_drop_aborts_without_sending_a_signal() -> Result<(), Box<dyn Error>> {
        let signal_log = SignalLog::new("app-drop-no-signal")?;
        let pid_log = SignalLog::new("app-drop-pid")?;
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "providers::codex::supervisor::process::tests::unreaped_drop_abort_child_helper",
                "--nocapture",
            ])
            .env(
                UNREAPED_DROP_ABORT_HELPER_ENV,
                "app-managed-child-no-signal",
            )
            .env(SIGNAL_LOG_ENV, signal_log.path())
            .env(UNREAPED_DROP_APP_PID_ENV, pid_log.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::ABORT.as_raw()),
            "ambiguous App Drop did not abort"
        );
        assert_eq!(signal_log.contents()?, b"R");

        let raw_pid = String::from_utf8(pid_log.contents()?)?.parse::<i32>()?;
        let pid = rustix::process::Pid::from_raw(raw_pid).ok_or("invalid retained App PID")?;
        rustix::process::kill_process_group(pid, rustix::process::Signal::KILL)?;
        let gone_deadline = Instant::now() + TEST_DEADLINE;
        loop {
            match rustix::process::getpgid(Some(pid)) {
                Err(rustix::io::Errno::SRCH) => break,
                Ok(_) | Err(rustix::io::Errno::INTR) if Instant::now() < gone_deadline => {
                    sleep_until_next_poll(gone_deadline);
                }
                Ok(_) | Err(rustix::io::Errno::INTR) => {
                    return Err("orphaned App Drop fixture remained live".into());
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        Ok(())
    }

    #[test]
    fn spawn_cleanup_retains_an_unreaped_leader_when_group_sweep_is_unconfirmed()
    -> Result<(), Box<dyn Error>> {
        let child = sleep_command("5").spawn()?;
        let expected_group = rustix::process::Pid::from_child(&child);
        let mut failure = SpawnFailure::started_fixture(
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

    #[cfg(target_os = "macos")]
    #[test]
    fn production_strict_app_shutdown_uses_the_pinned_graceful_contract()
    -> Result<(), Box<dyn Error>> {
        let mut app_server =
            ManagedGroupChild::spawn(ChildRole::AppServer, cooperative_app_command(), true)?;
        app_server.await_ready(Instant::now() + TEST_DEADLINE)?;

        let outcome = shutdown_fixture_pair(
            None,
            Some(app_server),
            Duration::from_millis(100),
            TEST_DEADLINE,
        )?;

        assert_eq!(outcome.failure(), None);
        assert!(matches!(
            outcome.children().app_server(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::Term,
            }
        ));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_eperm_never_treats_an_exited_leader_as_descendant_containment()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::process::CommandExt as _;

        let marker = SignalLog::new("eperm-descendant")?;
        let mut command =
            shell_command("/bin/sleep 5 & printf '%s' \"$!\" > \"$DESCENDANT_PID_PATH\"; exit 0");
        command
            .process_group(0)
            .env("DESCENDANT_PID_PATH", marker.path());
        let child = command.spawn()?;
        let expected_group = rustix::process::Pid::from_child(&child);
        let deadline = Instant::now() + TEST_DEADLINE;
        let descendant = loop {
            if let Ok(value) = fs::read_to_string(marker.path()) {
                if let Ok(raw) = value.parse::<i32>() {
                    if let Some(pid) = rustix::process::Pid::from_raw(raw) {
                        break pid;
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err("descendant PID was not published".into());
            }
            sleep_until_next_poll(deadline);
        };
        loop {
            match rustix::process::waitid(
                rustix::process::WaitId::Pid(expected_group),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            ) {
                Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => break,
                Ok(_) if Instant::now() < deadline => sleep_until_next_poll(deadline),
                Ok(_) => return Err("group leader did not become wait-visible".into()),
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        assert_eq!(rustix::process::getpgid(Some(descendant))?, expected_group);

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
            .force_group_sweep_permission_denied = true;
        let mut failure = failure
            .cleanup(deadline)
            .err()
            .ok_or("EPERM must retain unconfirmed descendant containment")?;
        assert_eq!(
            failure.error(),
            ProcessError::SpawnContainmentUnconfirmed {
                role: ChildRole::Tui,
            }
        );
        assert_eq!(rustix::process::getpgid(Some(descendant))?, expected_group);

        failure
            .child
            .as_mut()
            .ok_or("spawn failure lost retry authority")?
            .force_group_sweep_permission_denied = false;
        let proof = failure.cleanup(Instant::now() + TEST_DEADLINE).map_err(
            |failure| -> Box<dyn Error> { format!("cleanup remained live: {failure}").into() },
        )?;
        assert!(proof.started_unannounced());
        let gone_deadline = Instant::now() + TEST_DEADLINE;
        loop {
            match rustix::process::getpgid(Some(descendant)) {
                Err(rustix::io::Errno::SRCH) => break,
                Ok(_) | Err(rustix::io::Errno::INTR) if Instant::now() < gone_deadline => {
                    sleep_until_next_poll(gone_deadline);
                }
                Ok(_) | Err(rustix::io::Errno::INTR) => {
                    return Err("contained descendant remained live".into());
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
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

    fn cooperative_app_command() -> Command {
        shell_command(
            "trap 'exit 0' TERM; printf R; exec >/dev/null; while :; do /bin/sleep 0.01; done",
        )
    }

    fn spawn_cooperative_app_fixture() -> Result<ManagedGroupChild, Box<dyn Error>> {
        let mut app = ManagedGroupChild::spawn_fixture(
            ChildRole::AppServer,
            cooperative_app_command(),
            true,
        )?;
        app.await_ready(Instant::now() + TEST_DEADLINE)?;
        Ok(app)
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

    fn app_server_signal_command(
        log: &SignalLog,
        term_behavior: &str,
    ) -> Result<Command, Box<dyn Error>> {
        let mut command = signal_counting_command(log)?;
        command.env(SIGNAL_TERM_BEHAVIOR_ENV, term_behavior);
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
            signal_hook::consts::signal::SIGTSTP,
        ])?;
        fs::write(&path, b"R")?;
        loop {
            for signal in signals.pending() {
                let marker = match signal {
                    signal_hook::consts::signal::SIGHUP => b'H',
                    signal_hook::consts::signal::SIGTERM => b'T',
                    signal_hook::consts::signal::SIGTSTP => b'S',
                    _ => return Err("unexpected registered signal".into()),
                };
                OpenOptions::new()
                    .append(true)
                    .open(&path)?
                    .write_all(&[marker])?;
                if signal == signal_hook::consts::signal::SIGTERM {
                    match std::env::var(SIGNAL_TERM_BEHAVIOR_ENV).as_deref() {
                        Ok("exit-0") => std::process::exit(0),
                        Ok("exit-23") => std::process::exit(23),
                        Ok("self-kill") => {
                            rustix::process::kill_process(
                                rustix::process::getpid(),
                                rustix::process::Signal::KILL,
                            )?;
                        }
                        Ok("ignore") | Err(_) => {}
                        Ok(_) => return Err("unknown TERM behavior".into()),
                    }
                }
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
        let child = ManagedGroupChild::spawn_fixture_session_leader(
            ChildRole::Tui,
            command,
            Instant::now() + TEST_DEADLINE,
        )?;
        let identity = child.containment();
        let pid = rustix::process::Pid::from_raw(identity.pid()).ok_or("invalid child PID")?;
        assert_eq!(identity.pid(), identity.pgid());
        assert_eq!(rustix::process::getsid(Some(pid))?, pid);

        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
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
            GroupContainmentPolicy::SyntheticFixture,
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
        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
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

        let child = ManagedGroupChild::spawn_fixture_session_leader_with_inherited_fd(
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

        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        assert_no_wait_authority(identity.pid())
    }

    #[test]
    fn inherited_fd_session_failure_retains_unreaped_authority_without_a_safe_group()
    -> Result<(), Box<dyn Error>> {
        let (_observer, inherited) = UnixStream::pair()?;
        let mut failure = ManagedGroupChild::spawn_fixture_session_leader_with_inherited_fd(
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
        let tui = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
        let app = spawn_cooperative_app_fixture()?;

        let tui_identity = tui.containment();
        let app_identity = app.containment();
        assert_eq!(tui_identity.role(), ChildRole::Tui);
        assert_eq!(tui_identity.pid(), tui_identity.pgid());
        assert_eq!(app_identity.pid(), app_identity.pgid());
        assert_ne!(tui_identity.pgid(), app_identity.pgid());
        assert_ne!(tui_identity.pgid(), rustix::process::getpgrp().as_raw_pid());

        let outcome = shutdown_fixture_pair(
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
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::Term,
            }
        ));
        assert_no_wait_authority(tui_identity.pid())?;
        assert_no_wait_authority(app_identity.pid())?;
        Ok(())
    }

    #[test]
    fn managed_child_observes_descriptor_isolation_across_its_descendant_group()
    -> Result<(), Box<dyn Error>> {
        let (forbidden, _peer) = UnixStream::pair()?;
        let mut identities = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        identities.capture(forbidden.as_fd())?;
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::AppServer,
            shell_command(
                "/bin/sleep 5 >/dev/null & child=$!; trap 'kill \"$child\" 2>/dev/null || :; wait \"$child\" 2>/dev/null || :; exit 0' TERM; printf R; exec >/dev/null; wait \"$child\"",
            ),
            true,
        )?;
        child.await_ready(Instant::now() + TEST_DEADLINE)?;

        let proof = child
            .observe_forbidden_descriptors_absent(&identities, Instant::now() + TEST_DEADLINE)?;
        assert_eq!(proof.member_count(), 2);
        assert!(proof.descriptor_count() >= 6);

        let outcome =
            shutdown_fixture_pair(None, Some(child), Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn live_descriptor_observation_does_not_retry_a_terminal_child_exit()
    -> Result<(), Box<dyn Error>> {
        let (forbidden, _peer) = UnixStream::pair()?;
        let mut identities = calcifer_unix_child_fd::CrossProcessDescriptorSet::new();
        identities.capture(forbidden.as_fd())?;
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;
        child.await_ready(Instant::now() + TEST_DEADLINE)?;
        rustix::process::kill_process(child.pid, rustix::process::Signal::TERM)?;
        let exit_deadline = Instant::now() + TEST_DEADLINE;
        while !child.observe_exit_without_reaping(exit_deadline)? {
            sleep_until_next_poll(exit_deadline);
        }

        let error = child
            .observe_forbidden_descriptors_absent_while_live(
                &identities,
                Instant::now() + Duration::from_millis(100),
            )
            .err()
            .ok_or("an exited direct child must fail descriptor observation")?;
        assert_eq!(
            error,
            calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ProcessChanged
        );

        let outcome = shutdown_fixture_pair(Some(child), None, Duration::ZERO, TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn descriptor_observation_retries_only_transient_races_until_the_deadline() {
        let deadline_origin = Instant::now();
        assert_eq!(
            descriptor_observation_deadline(
                deadline_origin,
                deadline_origin + Duration::from_secs(1),
            ),
            deadline_origin + Duration::from_secs(1)
        );
        assert_eq!(
            descriptor_observation_deadline(
                deadline_origin,
                deadline_origin + Duration::from_secs(60),
            ),
            deadline_origin + DESCRIPTOR_OBSERVATION_SETTLE_TIMEOUT
        );

        let mut attempts = 0_usize;
        let value = retry_descriptor_observation(
            Instant::now() + TEST_DEADLINE,
            |_| -> Result<u8, DescriptorObservationAttemptError> {
                attempts += 1;
                if attempts == 1 {
                    Err(DescriptorObservationAttemptError::TransientDescriptorChanged)
                } else {
                    Ok(7)
                }
            },
        );
        assert_eq!(value, Ok(7));
        assert_eq!(attempts, 2);

        let mut process_attempts = 0_usize;
        let process_race = retry_descriptor_observation(
            Instant::now() + TEST_DEADLINE,
            |_| -> Result<u8, DescriptorObservationAttemptError> {
                process_attempts += 1;
                if process_attempts == 1 {
                    Err(DescriptorObservationAttemptError::TransientProcessChanged)
                } else {
                    Ok(9)
                }
            },
        );
        assert_eq!(process_race, Ok(9));
        assert_eq!(process_attempts, 2);

        const PRIOR_FIXED_ATTEMPT_CAP: usize = 4;
        let mut delayed_stability_attempts = 0_usize;
        let delayed_stability = retry_descriptor_observation(
            Instant::now() + TEST_DEADLINE,
            |_| -> Result<u8, DescriptorObservationAttemptError> {
                delayed_stability_attempts += 1;
                if delayed_stability_attempts <= PRIOR_FIXED_ATTEMPT_CAP {
                    Err(DescriptorObservationAttemptError::TransientProcessChanged)
                } else {
                    Ok(11)
                }
            },
        );
        assert_eq!(delayed_stability, Ok(11));
        assert_eq!(delayed_stability_attempts, PRIOR_FIXED_ATTEMPT_CAP + 1);

        let persistent_race = retry_descriptor_observation(
            Instant::now() + Duration::from_millis(100),
            |_| -> Result<(), DescriptorObservationAttemptError> {
                Err(DescriptorObservationAttemptError::TransientDescriptorChanged)
            },
        );
        assert_eq!(
            persistent_race,
            Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline)
        );

        let mut fail_closed_attempts = 0_usize;
        let forbidden = retry_descriptor_observation(
            Instant::now() + TEST_DEADLINE,
            |_| -> Result<(), DescriptorObservationAttemptError> {
                fail_closed_attempts += 1;
                Err(DescriptorObservationAttemptError::Terminal(
                    calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor,
                ))
            },
        );
        assert_eq!(
            forbidden,
            Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::ForbiddenDescriptor)
        );
        assert_eq!(fail_closed_attempts, 1);

        let mut expired_attempts = 0_usize;
        let expired = retry_descriptor_observation(
            Instant::now(),
            |_| -> Result<(), DescriptorObservationAttemptError> {
                expired_attempts += 1;
                Ok(())
            },
        );
        assert_eq!(
            expired,
            Err(calcifer_unix_child_fd::ProcessGroupDescriptorScanError::Deadline)
        );
        assert_eq!(expired_attempts, 0);
    }

    #[test]
    fn await_ready_accepts_only_the_exact_one_byte_sentinel() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;

        child.await_ready(Instant::now() + TEST_DEADLINE)?;
        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
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
        let mut child = ManagedGroupChild::spawn_fixture(
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

        let _proof =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_rejects_a_delayed_second_byte() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn_fixture(
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

        let _outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_requires_the_writer_to_close_after_the_sentinel() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn_fixture(
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

        let _outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn await_ready_distinguishes_early_exit_from_timeout() -> Result<(), Box<dyn Error>> {
        // Keep the readiness pipe open in a same-group descendant so pipe EOF
        // cannot race the direct child's waitid-visible exit. The guardian must
        // still report the leader's clean early exit and sweep the descendant.
        let command = shell_command("/bin/sleep 1 & exec /bin/sleep 0.2");
        let mut child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, command, true)?;

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

        let outcome = shutdown_fixture_pair(Some(child), None, Duration::ZERO, TEST_DEADLINE)?;
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
        let mut child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), true)?;

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

        let _proof =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        Ok(())
    }

    #[test]
    fn app_shutdown_sends_exactly_one_term_and_accepts_only_exit_zero() -> Result<(), Box<dyn Error>>
    {
        let log = SignalLog::new("app-drained")?;
        let app = ManagedGroupChild::spawn_fixture(
            ChildRole::AppServer,
            app_server_signal_command(&log, "exit-0")?,
            false,
        )?;
        wait_for_signal_log(&log, b"R")?;

        let drained = shutdown_app_server_child(app, Duration::from_millis(100), TEST_DEADLINE)?;

        assert_eq!(log.contents()?, b"RT");
        assert_eq!(drained.outcome().failure(), None);
        assert_eq!(
            drained.outcome().children().app_server(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::Term,
            }
        );
        Ok(())
    }

    #[test]
    fn app_shutdown_rejects_early_exit_without_signaling() -> Result<(), Box<dyn Error>> {
        let mut app = ManagedGroupChild::spawn_fixture(
            ChildRole::AppServer,
            shell_command("/bin/sleep 0.05; exit 0"),
            false,
        )?;
        let deadline = Instant::now() + TEST_DEADLINE;
        while app.poll_liveness(deadline)? != ChildLiveness::Exited {
            sleep_until_next_poll(deadline);
        }

        let retained = shutdown_app_server_child(app, Duration::from_millis(100), TEST_DEADLINE)
            .err()
            .ok_or("an App exit before the initial TERM must retain authority")?;

        assert_eq!(
            retained.error(),
            ProcessError::AppGracefulDrainUnconfirmed {
                role: ChildRole::AppServer,
                stage: AppGracefulDrainFailureStage::ExitedBeforeTerm,
            }
        );
        let retained_app = retained
            .app_server
            .as_ref()
            .ok_or("the invalid App authority was discarded")?;
        assert_eq!(
            retained_app.disposition,
            Some(ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::None,
            })
        );
        std::mem::forget(retained);
        Ok(())
    }

    #[test]
    fn app_shutdown_nonzero_or_signal_is_permanently_fail_closed() -> Result<(), Box<dyn Error>> {
        for (label, behavior) in [("nonzero", "exit-23"), ("signaled", "self-kill")] {
            let log = SignalLog::new(label)?;
            let app = ManagedGroupChild::spawn_fixture(
                ChildRole::AppServer,
                app_server_signal_command(&log, behavior)?,
                false,
            )?;
            wait_for_signal_log(&log, b"R")?;

            let mut retained =
                shutdown_app_server_child(app, Duration::from_millis(100), TEST_DEADLINE)
                    .err()
                    .ok_or("an abnormal App exit must retain authority")?;
            assert_eq!(
                retained.error(),
                ProcessError::AppGracefulDrainUnconfirmed {
                    role: ChildRole::AppServer,
                    stage: AppGracefulDrainFailureStage::InvalidDisposition,
                }
            );
            assert_eq!(log.contents()?, b"RT");

            assert_eq!(
                retained
                    .retry_app_server(Duration::from_millis(20), Duration::from_millis(20))
                    .err(),
                Some(ProcessError::AppGracefulDrainUnconfirmed {
                    role: ChildRole::AppServer,
                    stage: AppGracefulDrainFailureStage::InvalidDisposition,
                })
            );
            assert_eq!(log.contents()?, b"RT");
            std::mem::forget(retained);
        }
        Ok(())
    }

    #[test]
    fn app_shutdown_deadline_and_retry_never_send_a_second_signal() -> Result<(), Box<dyn Error>> {
        let log = SignalLog::new("app-deadline")?;
        let app = ManagedGroupChild::spawn_fixture(
            ChildRole::AppServer,
            app_server_signal_command(&log, "ignore")?,
            false,
        )?;
        wait_for_signal_log(&log, b"R")?;

        let mut retained =
            shutdown_app_server_child(app, Duration::from_millis(20), Duration::from_millis(20))
                .err()
                .ok_or("an undrained App must retain authority")?;
        wait_for_signal_log(&log, b"RT")?;

        assert_eq!(
            retained
                .retry_app_server(Duration::from_millis(20), Duration::from_millis(20))
                .err(),
            Some(ProcessError::WaitTimeout {
                role: ChildRole::AppServer,
            })
        );
        assert_eq!(log.contents()?, b"RT");

        let app = retained
            .app_server
            .as_ref()
            .ok_or("the timed-out App authority was discarded")?;
        rustix::process::kill_process_group(app.pgid, rustix::process::Signal::KILL)?;
        assert_eq!(
            retained
                .retry_app_server(Duration::ZERO, TEST_DEADLINE)
                .err(),
            Some(ProcessError::WaitTimeout {
                role: ChildRole::AppServer,
            })
        );
        assert!(
            retained
                .app_server
                .as_ref()
                .is_some_and(|app| app.disposition.is_some())
        );
        assert_eq!(log.contents()?, b"RT");
        std::mem::forget(retained);
        Ok(())
    }

    #[test]
    fn app_shutdown_signal_failure_is_not_reclassified_as_delivery() -> Result<(), Box<dyn Error>> {
        let mut app =
            ManagedGroupChild::spawn_fixture(ChildRole::AppServer, sleep_command("5"), false)?;
        app.injected_app_shutdown_fault = Some(InjectedAppShutdownFault::Term);

        let mut retained =
            shutdown_app_server_child(app, Duration::from_millis(20), Duration::from_millis(20))
                .err()
                .ok_or("a failed App TERM must retain authority")?;
        assert_eq!(
            retained.error(),
            ProcessError::Signal {
                role: ChildRole::AppServer,
                action: StopAction::Term,
            }
        );
        assert_eq!(
            retained
                .retry_app_server(Duration::from_millis(20), Duration::from_millis(20))
                .err(),
            Some(ProcessError::Signal {
                role: ChildRole::AppServer,
                action: StopAction::Term,
            })
        );

        let app = retained
            .app_server
            .as_ref()
            .ok_or("the signal-failed App authority was discarded")?;
        rustix::process::kill_process_group(app.pgid, rustix::process::Signal::KILL)?;
        let _ = retained.retry_app_server(Duration::ZERO, TEST_DEADLINE);
        assert!(
            retained
                .app_server
                .as_ref()
                .is_some_and(|app| app.disposition.is_some())
        );
        std::mem::forget(retained);
        Ok(())
    }

    #[test]
    fn app_shutdown_stop_and_cont_failures_remain_permanently_unconfirmed()
    -> Result<(), Box<dyn Error>> {
        for (label, fault) in [
            ("stop-failure", InjectedAppShutdownFault::Stop),
            ("cont-failure", InjectedAppShutdownFault::Cont),
        ] {
            let log = SignalLog::new(label)?;
            let mut app = ManagedGroupChild::spawn_fixture(
                ChildRole::AppServer,
                app_server_signal_command(&log, "exit-0")?,
                false,
            )?;
            wait_for_signal_log(&log, b"R")?;
            app.injected_app_shutdown_fault = Some(fault);

            let mut retained = shutdown_app_server_child(
                app,
                Duration::from_millis(20),
                Duration::from_millis(20),
            )
            .err()
            .ok_or("an injected STOP/CONT failure returned App drain authority")?;
            let expected_error = ProcessError::Signal {
                role: ChildRole::AppServer,
                action: StopAction::None,
            };
            assert_eq!(retained.error(), expected_error);
            assert_eq!(log.contents()?, b"R");
            assert_eq!(
                retained
                    .retry_app_server(Duration::from_millis(20), Duration::from_millis(20))
                    .err(),
                Some(expected_error)
            );
            assert_eq!(log.contents()?, b"R");

            let app = retained
                .app_server
                .as_ref()
                .ok_or("the signal-failed App authority was discarded")?;
            assert_eq!(app.app_graceful_drain, AppGracefulDrainState::Invalid);
            match fault {
                InjectedAppShutdownFault::Stop => {
                    rustix::process::kill_process_group(app.pgid, rustix::process::Signal::KILL)?;
                }
                InjectedAppShutdownFault::Cont => {
                    rustix::process::kill_process(app.pid, rustix::process::Signal::CONT)?;
                    wait_for_signal_log(&log, b"RT")?;
                }
                InjectedAppShutdownFault::Term => unreachable!(),
            }
            let _ = retained.retry_app_server(Duration::ZERO, TEST_DEADLINE);
            assert!(
                retained
                    .app_server
                    .as_ref()
                    .is_some_and(|app| app.disposition.is_some())
            );
            let expected_log = if fault == InjectedAppShutdownFault::Cont {
                b"RT".as_slice()
            } else {
                b"R".as_slice()
            };
            assert_eq!(log.contents()?, expected_log);
            std::mem::forget(retained);
        }
        Ok(())
    }

    #[test]
    fn shutdown_escalates_a_term_ignoring_child_to_kill() -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("trap '' TERM; printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;
        child.await_ready(Instant::now() + TEST_DEADLINE)?;

        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(30), TEST_DEADLINE)?;
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
            let mut tui = ManagedGroupChild::spawn_fixture(
                ChildRole::Tui,
                signal_counting_command(&log)?,
                false,
            )?;
            wait_for_signal_log(&log, b"R")?;
            let app = spawn_cooperative_app_fixture()?;

            let forwarded =
                tui.forward_terminal_shutdown_signal(signal, Instant::now() + TEST_DEADLINE)?;
            wait_for_signal_log(&log, expected_log)?;
            let outcome = shutdown_fixture_pair_after_forwarded_tui_signal(
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
                ChildDisposition::Exited {
                    code: 0,
                    stop_action: StopAction::Term,
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
            let mut tui =
                ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
            let forwarded =
                tui.forward_terminal_shutdown_signal(signal, Instant::now() + TEST_DEADLINE)?;
            let deadline = Instant::now() + TEST_DEADLINE;
            while tui.poll_liveness(deadline)? != ChildLiveness::Exited {
                sleep_until_next_poll(deadline);
            }

            let outcome = shutdown_fixture_pair_after_forwarded_tui_signal(
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
    fn tui_output_eof_shutdown_preserves_natural_exit_code() -> Result<(), Box<dyn Error>> {
        let tui = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("/bin/sleep 0.05; exit 23"),
            false,
        )?;

        let outcome = shutdown_fixture_pair_after_tui_output_eof(
            tui,
            None,
            Duration::from_millis(500),
            TEST_DEADLINE,
        )?;

        assert_eq!(outcome.failure(), None);
        assert_eq!(
            outcome.children().tui(),
            ChildDisposition::Exited {
                code: 23,
                stop_action: StopAction::None,
            }
        );
        Ok(())
    }

    #[test]
    fn forwarded_shutdown_continues_stopped_tui_without_minting_resume_authority()
    -> Result<(), Box<dyn Error>> {
        let mut tui = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
        tui.suspend(
            Instant::now() + Duration::from_millis(100),
            Instant::now() + TEST_DEADLINE,
        )?;
        let forwarded = tui.forward_terminal_shutdown_signal(
            TerminalShutdownSignal::Term,
            Instant::now() + TEST_DEADLINE,
        )?;
        tui.continue_after_forwarded_shutdown(&forwarded, Instant::now() + TEST_DEADLINE)?;

        let outcome = shutdown_fixture_pair_after_forwarded_tui_signal(
            tui,
            None,
            forwarded,
            Duration::from_millis(500),
            TEST_DEADLINE,
        )?;
        assert_eq!(outcome.failure(), None);
        assert_eq!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 15,
                core_dumped: false,
                stop_action: StopAction::None,
            }
        );
        Ok(())
    }

    #[test]
    fn tui_output_eof_shutdown_preserves_natural_signal() -> Result<(), Box<dyn Error>> {
        let tui = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("/bin/sleep 0.05; kill -TERM $$"),
            false,
        )?;

        let outcome = shutdown_fixture_pair_after_tui_output_eof(
            tui,
            None,
            Duration::from_millis(500),
            TEST_DEADLINE,
        )?;

        assert_eq!(outcome.failure(), None);
        assert_eq!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 15,
                core_dumped: false,
                stop_action: StopAction::None,
            }
        );
        Ok(())
    }

    #[test]
    fn tui_output_eof_shutdown_contains_a_still_live_child() -> Result<(), Box<dyn Error>> {
        let tui = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;

        let outcome = shutdown_fixture_pair_after_tui_output_eof(
            tui,
            None,
            Duration::from_millis(20),
            TEST_DEADLINE,
        )?;

        assert_eq!(outcome.failure(), None);
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 9,
                stop_action: StopAction::Kill,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn forwarded_tui_shutdown_mode_and_wait_ownership_survive_retry() -> Result<(), Box<dyn Error>>
    {
        let log = SignalLog::new("retry-term")?;
        let mut tui = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            signal_counting_command(&log)?,
            false,
        )?;
        wait_for_signal_log(&log, b"R")?;
        let tui_pid = tui.containment().pid();
        let forwarded = tui.forward_terminal_shutdown_signal(
            TerminalShutdownSignal::Term,
            Instant::now() + TEST_DEADLINE,
        )?;
        wait_for_signal_log(&log, b"RT")?;

        let mut unreaped = shutdown_fixture_pair_after_forwarded_tui_signal(
            tui,
            None,
            forwarded,
            Duration::MAX,
            Duration::ZERO,
        )
        .err()
        .ok_or("overflowing deadline must retain both child handles")?;
        assert_eq!(unreaped.error(), ProcessError::Deadline);
        assert!(format!("{unreaped:?}").contains("tui_owned: true"));
        assert!(format!("{unreaped:?}").contains("app_server_owned: false"));

        let outcome = unreaped.retry_fixture(Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(log.contents()?, b"RT");
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 9,
                stop_action: StopAction::Kill,
                ..
            }
        ));
        assert_eq!(
            outcome.children().app_server(),
            ChildDisposition::NotStarted
        );
        assert_no_wait_authority(tui_pid)?;
        assert_eq!(
            unreaped.retry_fixture(Duration::ZERO, Duration::ZERO),
            Err(ProcessError::RetryAfterResolution)
        );
        Ok(())
    }

    #[test]
    fn forwarded_shutdown_proof_requires_process_local_child_authority()
    -> Result<(), Box<dyn Error>> {
        let first = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
        let second = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;

        // Reproduce the strongest numeric spoof available inside this module:
        // metadata matches the target exactly, but the unforgeable generation
        // remains bound to a different direct Child handle.
        let mismatched = ForwardedTuiSignal {
            signal: TerminalShutdownSignal::Term,
            containment: second.containment(),
            authority: first.authority,
        };
        let outcome = shutdown_fixture_pair_after_forwarded_tui_signal(
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

        let cleanup =
            shutdown_fixture_pair(Some(first), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(cleanup.failure(), None);
        Ok(())
    }

    #[test]
    fn terminal_control_authority_rejects_an_app_server_child() -> Result<(), Box<dyn Error>> {
        let mut app = spawn_cooperative_app_fixture()?;
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

        let outcome =
            shutdown_fixture_pair(None, Some(app), Duration::from_millis(100), TEST_DEADLINE)?;
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
        let child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
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
        let mut child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, command, false)?;
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

        let outcome = shutdown_fixture_pair(Some(child), None, Duration::ZERO, TEST_DEADLINE)?;
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
        let mut child =
            ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
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
        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn suspend_forces_a_tstp_ignoring_tui_group_to_stop() -> Result<(), Box<dyn Error>> {
        let log = SignalLog::new("suspend-fallback")?;
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            signal_counting_command(&log)?,
            false,
        )?;
        wait_for_signal_log(&log, b"R")?;
        let started_at = Instant::now();

        child.suspend(
            started_at + Duration::from_millis(100),
            started_at + TEST_DEADLINE,
        )?;
        assert_eq!(log.contents()?, b"RS");
        assert_eq!(
            child.poll_liveness(Instant::now() + TEST_DEADLINE)?,
            ChildLiveness::Running
        );

        child.resume(Instant::now() + TEST_DEADLINE)?;
        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn repeated_suspend_resume_cycles_do_not_reuse_nonterminal_wait_notifications()
    -> Result<(), Box<dyn Error>> {
        let mut child =
            ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;

        for _ in 0..2 {
            let started_at = Instant::now();
            child.suspend(
                started_at + Duration::from_millis(100),
                started_at + TEST_DEADLINE,
            )?;
            child.resume(Instant::now() + TEST_DEADLINE)?;
        }

        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resume_does_not_require_a_distinct_continued_wait_notification() -> Result<(), Box<dyn Error>>
    {
        let mut child =
            ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
        let started_at = Instant::now();
        child.suspend(
            started_at + Duration::from_millis(100),
            started_at + TEST_DEADLINE,
        )?;

        // Consume the kernel's one advisory CLD_CONTINUED notification before
        // the reviewed resume entrypoint runs. Linux may coalesce that exact
        // notification during real group-stop races, while a successful
        // SIGCONT still performs the required continuation action.
        rustix::process::kill_process_group(child.pgid, rustix::process::Signal::CONT)?;
        let deadline = Instant::now() + TEST_DEADLINE;
        loop {
            match rustix::process::waitid(
                rustix::process::WaitId::Pid(child.pid),
                rustix::process::WaitIdOptions::CONTINUED | rustix::process::WaitIdOptions::NOHANG,
            ) {
                Ok(Some(status)) if status.continued() => break,
                Ok(Some(_)) | Ok(None) if Instant::now() < deadline => {
                    sleep_until_next_poll(deadline);
                }
                Ok(Some(_)) | Ok(None) => {
                    return Err("continued notification was not observable".into());
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }

        child.resume(Instant::now() + Duration::from_millis(100))?;
        let outcome =
            shutdown_fixture_pair(Some(child), None, Duration::from_millis(100), TEST_DEADLINE)?;
        assert_eq!(outcome.failure(), None);
        Ok(())
    }

    #[test]
    fn exact_reap_proof_survives_an_earlier_shutdown_failure() -> Result<(), Box<dyn Error>> {
        let app = spawn_cooperative_app_fixture()?;

        // Keep the App in its typed slot and inject an earlier observational
        // failure directly. A role-mismatched slot is intentionally not a
        // public way to recover App completion authority.
        let completion = shutdown_pair_inner(
            None,
            Some(app),
            Duration::from_millis(100),
            TEST_DEADLINE,
            TuiShutdownMode::StartWithTerm,
            Some(ProcessError::RoleMismatch {
                expected: ChildRole::Tui,
                actual: ChildRole::AppServer,
            }),
        )?;
        assert!(completion.app_gracefully_drained.is_some());
        let outcome = completion.outcome;

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
            outcome.children().app_server(),
            ChildDisposition::Exited {
                code: 0,
                stop_action: StopAction::Term,
            }
        ));
        Ok(())
    }

    #[test]
    fn invalid_shutdown_deadline_returns_the_live_direct_handle_for_retry()
    -> Result<(), Box<dyn Error>> {
        let child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;

        let mut unreaped = shutdown_fixture_pair(Some(child), None, Duration::MAX, Duration::ZERO)
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
    fn tui_shutdown_output_progress_runs_without_replacing_exact_reap_or_error()
    -> Result<(), Box<dyn Error>> {
        let mut child = ManagedGroupChild::spawn_fixture(
            ChildRole::Tui,
            shell_command("trap '' TERM; printf R; exec >/dev/null; exec /bin/sleep 5"),
            true,
        )?;
        child.await_ready(Instant::now() + TEST_DEADLINE)?;
        let pid = child.containment().pid();
        let secret = "synthetic-private-pty-payload@example.invalid";
        let mut calls = 0_u32;
        let mut progress = || {
            std::hint::black_box(secret);
            calls += 1;
            Err(ProcessError::TuiOutputDrain {
                role: ChildRole::Tui,
            })
        };

        let outcome = shutdown_tui_child_with_output_progress(
            child,
            Duration::from_millis(20),
            TEST_DEADLINE,
            &mut progress,
        )?;

        assert!(calls >= 2);
        assert_eq!(
            outcome.failure(),
            Some(ProcessError::TuiOutputDrain {
                role: ChildRole::Tui,
            })
        );
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled {
                signal: 9,
                stop_action: StopAction::Kill,
                ..
            }
        ));
        assert_no_wait_authority(pid)?;
        assert!(!format!("{outcome:?}").contains(secret));
        assert_eq!(
            outcome.failure().map(|error| error.to_string()),
            Some("supervised TUI shutdown output drain failed".to_owned())
        );
        Ok(())
    }

    #[test]
    fn retained_tui_retry_reuses_output_progress_and_exact_wait_authority()
    -> Result<(), Box<dyn Error>> {
        let child = ManagedGroupChild::spawn_fixture(ChildRole::Tui, sleep_command("5"), false)?;
        let pid = child.containment().pid();
        let mut unreaped = shutdown_fixture_pair(Some(child), None, Duration::MAX, Duration::ZERO)
            .err()
            .ok_or("overflowing deadline must retain the exact TUI child")?;
        let calls = std::cell::Cell::new(0_u32);
        let mut progress = || {
            calls.set(calls.get() + 1);
            Ok(())
        };

        let outcome = unreaped.retry_with_tui_output_progress(
            Duration::from_millis(20),
            TEST_DEADLINE,
            &mut progress,
        )?;

        assert!(calls.get() > 0);
        assert_eq!(outcome.failure(), Some(ProcessError::Deadline));
        assert!(matches!(
            outcome.children().tui(),
            ChildDisposition::Signaled { .. }
        ));
        assert_no_wait_authority(pid)?;
        assert_eq!(
            unreaped.retry_with_tui_output_progress(Duration::ZERO, Duration::ZERO, &mut progress,),
            Err(ProcessError::RetryAfterResolution)
        );
        Ok(())
    }

    #[test]
    fn pre_spawn_failure_is_redacted_and_requires_no_wait_authority() -> Result<(), Box<dyn Error>>
    {
        let command = Command::new("/calcifer-private-sentinel/does-not-exist");

        let failure = ManagedGroupChild::spawn_fixture(ChildRole::Tui, command, false)
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
        assert!(!proof.started_unannounced());
        Ok(())
    }
}
