//! Bounded, observe-only transport kernel for remote-TUI readiness gates.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::json::decode_unique_json;

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_THREAD_ID_BYTES: usize = 256;
const MAX_REQUEST_ID_BYTES: usize = 256;
const MAX_METHOD_BYTES: usize = 256;
const MAX_CWD_BYTES: usize = 16 * 1024;
const MAX_MODEL_BYTES: usize = 512;
const MAX_MODEL_PROVIDER_BYTES: usize = 256;
const MAX_POLICY_BYTES: usize = 128;
const MAX_REVIEWER_BYTES: usize = 128;
const MAX_SANDBOX_TYPE_BYTES: usize = 128;
const MAX_WRITABLE_ROOTS: usize = 64;
const MAX_FRAME_BUFFER_BYTES: usize = MAX_MESSAGE_BYTES + 14;
const COPY_BUFFER_BYTES: usize = 8 * 1024;
const EVENT_CHANNEL_CAPACITY: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(2);

const RELAY_RUNNING: u8 = 0;
const RELAY_DISCONNECTED: u8 = 1;
const RELAY_STOPPING: u8 = 2;

const TRANSPORT_ORIGIN_UNSET: u8 = 0;

/// A closed, payload-free origin for a readiness-relay transport failure.
///
/// These values carry no cleanup or lifecycle authority. Their only purpose is
/// to preserve the first exact transport boundary for fixed diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ReadinessTransportOrigin {
    ClientConfigure = 1,
    ClientClone = 2,
    ClientEof = 3,
    ClientRead = 4,
    ClientWrite = 5,
    UpstreamClone = 6,
    UpstreamEof = 7,
    UpstreamRead = 8,
    UpstreamWrite = 9,
    ObservationDelivery = 10,
    ObservationChannelDisconnected = 11,
    LifecycleDisconnected = 12,
    WorkerFinished = 13,
    HealthClientPoll = 14,
    HealthClientPeek = 15,
    HealthClientEof = 16,
    HealthUpstreamPoll = 17,
    HealthUpstreamPeek = 18,
    HealthUpstreamEof = 19,
}

impl ReadinessTransportOrigin {
    #[cfg(test)]
    pub(super) const ALL: [Self; 19] = [
        Self::ClientConfigure,
        Self::ClientClone,
        Self::ClientEof,
        Self::ClientRead,
        Self::ClientWrite,
        Self::UpstreamClone,
        Self::UpstreamEof,
        Self::UpstreamRead,
        Self::UpstreamWrite,
        Self::ObservationDelivery,
        Self::ObservationChannelDisconnected,
        Self::LifecycleDisconnected,
        Self::WorkerFinished,
        Self::HealthClientPoll,
        Self::HealthClientPeek,
        Self::HealthClientEof,
        Self::HealthUpstreamPoll,
        Self::HealthUpstreamPeek,
        Self::HealthUpstreamEof,
    ];

    #[cfg(test)]
    pub(super) const fn fixed_label(self) -> &'static str {
        match self {
            Self::ClientConfigure => "client-configure",
            Self::ClientClone => "client-clone",
            Self::ClientEof => "client-eof",
            Self::ClientRead => "client-read",
            Self::ClientWrite => "client-write",
            Self::UpstreamClone => "upstream-clone",
            Self::UpstreamEof => "upstream-eof",
            Self::UpstreamRead => "upstream-read",
            Self::UpstreamWrite => "upstream-write",
            Self::ObservationDelivery => "observation-delivery",
            Self::ObservationChannelDisconnected => "observation-channel-disconnected",
            Self::LifecycleDisconnected => "lifecycle-disconnected",
            Self::WorkerFinished => "worker-finished",
            Self::HealthClientPoll => "health-client-poll",
            Self::HealthClientPeek => "health-client-peek",
            Self::HealthClientEof => "health-client-eof",
            Self::HealthUpstreamPoll => "health-upstream-poll",
            Self::HealthUpstreamPeek => "health-upstream-peek",
            Self::HealthUpstreamEof => "health-upstream-eof",
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ClientConfigure),
            2 => Some(Self::ClientClone),
            3 => Some(Self::ClientEof),
            4 => Some(Self::ClientRead),
            5 => Some(Self::ClientWrite),
            6 => Some(Self::UpstreamClone),
            7 => Some(Self::UpstreamEof),
            8 => Some(Self::UpstreamRead),
            9 => Some(Self::UpstreamWrite),
            10 => Some(Self::ObservationDelivery),
            11 => Some(Self::ObservationChannelDisconnected),
            12 => Some(Self::LifecycleDisconnected),
            13 => Some(Self::WorkerFinished),
            14 => Some(Self::HealthClientPoll),
            15 => Some(Self::HealthClientPeek),
            16 => Some(Self::HealthClientEof),
            17 => Some(Self::HealthUpstreamPoll),
            18 => Some(Self::HealthUpstreamPeek),
            19 => Some(Self::HealthUpstreamEof),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ReadinessTransportTracker {
    first: AtomicU8,
    selection: Mutex<RelayFailureSelection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayFailureSelection {
    Open,
    Failed(ReadinessProxyError),
    Stopped,
}

#[derive(Clone, Debug)]
struct RelayControl {
    lifecycle: Arc<AtomicU8>,
    transport: Arc<ReadinessTransportTracker>,
}

impl ReadinessTransportTracker {
    const fn new() -> Self {
        Self {
            first: AtomicU8::new(TRANSPORT_ORIGIN_UNSET),
            selection: Mutex::new(RelayFailureSelection::Open),
        }
    }

    fn first(&self) -> Option<ReadinessTransportOrigin> {
        ReadinessTransportOrigin::from_code(self.first.load(Ordering::Acquire))
    }

    fn record(&self, origin: ReadinessTransportOrigin) -> ReadinessTransportOrigin {
        match self.first.compare_exchange(
            TRANSPORT_ORIGIN_UNSET,
            origin as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => origin,
            Err(recorded) => ReadinessTransportOrigin::from_code(recorded).unwrap_or(origin),
        }
    }

    fn error(&self, origin: ReadinessTransportOrigin) -> ReadinessProxyError {
        ReadinessProxyError::Transport(self.record(origin))
    }

    fn authoritative(&self, error: ReadinessProxyError) -> ReadinessProxyError {
        match error {
            ReadinessProxyError::Transport(origin) => self.error(origin),
            error => self
                .first()
                .map(ReadinessProxyError::Transport)
                .unwrap_or(error),
        }
    }

    fn selected_failure(&self) -> Option<ReadinessProxyError> {
        let selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *selection {
            RelayFailureSelection::Failed(selected) => Some(selected),
            RelayFailureSelection::Open | RelayFailureSelection::Stopped => None,
        }
    }

    fn preserve_selected(&self, error: ReadinessProxyError) -> ReadinessProxyError {
        self.selected_failure().unwrap_or(error)
    }

    /// Selects one authoritative run outcome and closes origin publication.
    /// A transport failure that committed first wins; otherwise this semantic
    /// failure wins and later cleanup wakeups cannot mint an origin. An
    /// intentional stop is equally sticky: a worker that observed RUNNING
    /// before the stop cannot reopen the selection with a late failure.
    fn select_failure(&self, error: ReadinessProxyError) -> ProxyRunError {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *selection {
            RelayFailureSelection::Open => {
                let error = self.authoritative(error);
                *selection = RelayFailureSelection::Failed(error);
                ProxyRunError::Failed(error)
            }
            RelayFailureSelection::Failed(selected) => ProxyRunError::Failed(selected),
            RelayFailureSelection::Stopped => ProxyRunError::Stopped,
        }
    }

    fn publish_readiness<F>(&self, lifecycle: &AtomicU8, publish: F) -> Result<(), ProxyRunError>
    where
        F: FnOnce() -> Result<(), ReadinessProxyError>,
    {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING {
            return Err(ProxyRunError::Stopped);
        }
        match *selection {
            RelayFailureSelection::Failed(error) => Err(ProxyRunError::Failed(error)),
            RelayFailureSelection::Stopped => Err(ProxyRunError::Stopped),
            RelayFailureSelection::Open if lifecycle.load(Ordering::Acquire) == RELAY_RUNNING => {
                match publish() {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let error = self.authoritative(error);
                        *selection = RelayFailureSelection::Failed(error);
                        Err(ProxyRunError::Failed(error))
                    }
                }
            }
            RelayFailureSelection::Open => {
                let error = self.authoritative(ReadinessProxyError::Worker);
                *selection = RelayFailureSelection::Failed(error);
                Err(ProxyRunError::Failed(error))
            }
        }
    }

    /// Publishes a failure before changing RUNNING to DISCONNECTED.
    ///
    /// The same gate is held by `stop`, so an intentional shutdown either
    /// happens before this method (and records no origin) or after the exact
    /// origin and disconnected state are both committed.
    fn fail_while_running(
        &self,
        lifecycle: &AtomicU8,
        error: ReadinessProxyError,
    ) -> Option<ReadinessProxyError> {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING {
            return None;
        }
        match *selection {
            RelayFailureSelection::Failed(_) => None,
            RelayFailureSelection::Stopped => None,
            RelayFailureSelection::Open if lifecycle.load(Ordering::Acquire) == RELAY_RUNNING => {
                let error = self.authoritative(error);
                *selection = RelayFailureSelection::Failed(error);
                lifecycle.store(RELAY_DISCONNECTED, Ordering::Release);
                Some(error)
            }
            RelayFailureSelection::Open => None,
        }
    }

    fn disconnect(
        &self,
        lifecycle: &AtomicU8,
        origin: ReadinessTransportOrigin,
    ) -> Option<ReadinessProxyError> {
        self.fail_while_running(lifecycle, ReadinessProxyError::Transport(origin))
    }

    fn classify_disconnected(&self, origin: ReadinessTransportOrigin) -> ReadinessProxyError {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *selection {
            RelayFailureSelection::Failed(error) => error,
            RelayFailureSelection::Open => {
                let error = self.error(origin);
                *selection = RelayFailureSelection::Failed(error);
                error
            }
            RelayFailureSelection::Stopped => ReadinessProxyError::UnexpectedSequence,
        }
    }

    fn stop(&self, lifecycle: &AtomicU8) -> u8 {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *selection == RelayFailureSelection::Open {
            *selection = RelayFailureSelection::Stopped;
        }
        let previous = lifecycle.load(Ordering::Acquire);
        if previous != RELAY_STOPPING {
            lifecycle.store(RELAY_STOPPING, Ordering::Release);
        }
        previous
    }

    fn stop_with_disconnected_origin(
        &self,
        lifecycle: &AtomicU8,
        origin: ReadinessTransportOrigin,
    ) -> (u8, Option<ReadinessProxyError>) {
        let mut selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = lifecycle.load(Ordering::Acquire);
        let error = match *selection {
            RelayFailureSelection::Failed(error) => Some(error),
            RelayFailureSelection::Open if previous == RELAY_DISCONNECTED => {
                let error = self.error(origin);
                *selection = RelayFailureSelection::Failed(error);
                Some(error)
            }
            RelayFailureSelection::Open => {
                *selection = RelayFailureSelection::Stopped;
                None
            }
            RelayFailureSelection::Stopped => None,
        };
        if previous != RELAY_STOPPING {
            lifecycle.store(RELAY_STOPPING, Ordering::Release);
        }
        (previous, error)
    }
}

/// A redacted failure from the isolated readiness proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadinessProxyError {
    InvalidArgument,
    Bind,
    Accept,
    Connect,
    HandshakeTooLarge,
    InvalidHandshake,
    FrameTooLarge,
    InvalidFrame,
    InvalidMessage,
    UnexpectedSequence,
    TargetMismatch,
    Timeout,
    Transport(ReadinessTransportOrigin),
    Worker,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyRunError {
    Stopped,
    Failed(ReadinessProxyError),
}

impl From<ReadinessProxyError> for ProxyRunError {
    fn from(error: ReadinessProxyError) -> Self {
        Self::Failed(error)
    }
}

impl fmt::Display for ReadinessProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "the readiness proxy arguments were invalid",
            Self::Bind => "the readiness proxy could not bind its Unix socket",
            Self::Accept => "the readiness proxy could not accept the TUI connection",
            Self::Connect => "the readiness proxy could not connect to the Codex app-server",
            Self::HandshakeTooLarge => "the readiness WebSocket handshake exceeded its limit",
            Self::InvalidHandshake => "the readiness WebSocket handshake was invalid",
            Self::FrameTooLarge => "a readiness WebSocket message exceeded its limit",
            Self::InvalidFrame => "a readiness WebSocket frame was invalid",
            Self::InvalidMessage => "a readiness JSON-RPC message was invalid",
            Self::UnexpectedSequence => "the readiness JSON-RPC sequence was invalid",
            Self::TargetMismatch => "the readiness response named a different thread",
            Self::Timeout => "the readiness proxy timed out",
            Self::Transport(_) => "the readiness proxy transport failed",
            Self::Worker => "the readiness proxy worker failed",
            Self::Cleanup => "the readiness proxy socket could not be cleaned up",
        })
    }
}

impl std::error::Error for ReadinessProxyError {}

/// A single-client Unix proxy that remains an opaque relay after readiness.
///
/// `wait_until_ready` succeeds only after the upstream WebSocket upgrade and
/// the selected policy's exact target read/resume sequence. A fork lineage also
/// requires the pinned parent metadata round trip to finish. Callers must keep
/// this value alive for the remote TUI's lifetime and call `shutdown` to join
/// both copy pumps and verify socket cleanup.
pub(super) struct ReadinessProxy {
    observer: UnixListener,
    socket_path: PathBuf,
    socket_identity: SocketIdentity,
    readiness: Receiver<Result<EffectiveThreadSettings, ReadinessProxyError>>,
    readiness_result: Option<Result<EffectiveThreadSettings, ReadinessProxyError>>,
    lifecycle: Arc<AtomicU8>,
    transport: Arc<ReadinessTransportTracker>,
    health: Arc<Mutex<Option<RelayHealth>>>,
    worker: Option<JoinHandle<Result<(), ReadinessProxyError>>>,
    joined_result: Option<Result<(), ReadinessProxyError>>,
    cleanup_complete: bool,
    deadline: Instant,
    shutdown_error: Option<ReadinessProxyError>,
}

struct BoundReadinessStartSocket {
    listener: UnixListener,
    path: PathBuf,
    identity: Option<SocketIdentity>,
}

/// Failed exact-relay startup with every socket cleanup authority retained.
///
/// An existing collision produces no bound owner. Once bind succeeds, the
/// listener remains open in this failure and a recorded pathname identity is
/// required before cleanup may unlink anything. An unidentified or replaced
/// pathname is preserved and returned for explicit recovery.
#[must_use = "a readiness start failure can retain an exact bound socket"]
pub(super) struct ReadinessProxyStartFailure {
    error: ReadinessProxyError,
    cleanup_error: Option<ReadinessProxyError>,
    bound: Option<BoundReadinessStartSocket>,
}

impl ReadinessProxyStartFailure {
    fn unbound(error: ReadinessProxyError) -> Box<Self> {
        Box::new(Self {
            error,
            cleanup_error: None,
            bound: None,
        })
    }

    fn bound(error: ReadinessProxyError, bound: BoundReadinessStartSocket) -> Box<Self> {
        Box::new(Self {
            error,
            cleanup_error: None,
            bound: Some(bound),
        })
    }

    pub(super) const fn error(&self) -> ReadinessProxyError {
        self.error
    }

    #[cfg(test)]
    pub(super) const fn cleanup_error(&self) -> Option<ReadinessProxyError> {
        self.cleanup_error
    }

    pub(super) const fn has_bound_socket(&self) -> bool {
        self.bound.is_some()
    }

    pub(super) fn cleanup(mut self: Box<Self>) -> Result<ReadinessProxyStartCleanup, Box<Self>> {
        let Some(bound) = self.bound.as_ref() else {
            return Ok(ReadinessProxyStartCleanup { _private: () });
        };
        let Some(identity) = bound.identity else {
            self.cleanup_error = Some(ReadinessProxyError::Cleanup);
            return Err(self);
        };
        match remove_owned_socket_inner(&bound.path, identity, false) {
            Ok(()) => {
                drop(self.bound.take());
                Ok(ReadinessProxyStartCleanup { _private: () })
            }
            Err(error) => {
                self.cleanup_error = Some(error);
                Err(self)
            }
        }
    }
}

impl fmt::Debug for ReadinessProxyStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessProxyStartFailure")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .field("bound_socket_retained", &self.bound.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ReadinessProxyStartFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ReadinessProxyStartFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadinessProxyStartCleanup {
    _private: (),
}

#[cfg(test)]
thread_local! {
    static FAIL_EXACT_START_AFTER_BIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone)]
struct ReadinessExpectation {
    thread_id: String,
    policy: ReadinessPolicy,
}

#[derive(Clone)]
#[allow(dead_code)] // Exact resume is wired by the next supervised-session slice in issue #33.
enum ReadinessPolicy {
    SyntheticFork {
        source_thread_id: String,
        expected_settings: EffectiveThreadSettings,
    },
    ExactResume {
        expected_cwd: String,
    },
}

pub(super) struct ReadinessProbe<'a> {
    target_thread_id: &'a str,
    source_thread_id: &'a str,
    cwd: &'a Path,
    model: &'a str,
    model_provider: &'a str,
}

impl<'a> ReadinessProbe<'a> {
    pub(super) fn new(
        target_thread_id: &'a str,
        source_thread_id: &'a str,
        cwd: &'a Path,
        model: &'a str,
        model_provider: &'a str,
    ) -> Self {
        Self {
            target_thread_id,
            source_thread_id,
            cwd,
            model,
            model_provider,
        }
    }
}

#[allow(dead_code)] // Exact resume is wired by the next supervised-session slice in issue #33.
pub(super) struct ExactResumeProbe<'a> {
    target_thread_id: &'a str,
    cwd: &'a Path,
}

#[allow(dead_code)] // Exact resume is wired by the next supervised-session slice in issue #33.
impl<'a> ExactResumeProbe<'a> {
    pub(super) const fn new(target_thread_id: &'a str, cwd: &'a Path) -> Self {
        Self {
            target_thread_id,
            cwd,
        }
    }
}

impl ReadinessExpectation {
    fn pinned_probe(
        thread_id: &str,
        source_thread_id: &str,
        cwd: &Path,
        model: &str,
        model_provider: &str,
    ) -> Result<Self, ReadinessProxyError> {
        let cwd = cwd
            .to_str()
            .filter(|cwd| valid_absolute_cwd(cwd))
            .ok_or(ReadinessProxyError::InvalidArgument)?;
        if !valid_thread_id(thread_id)
            || !valid_thread_id(source_thread_id)
            || thread_id == source_thread_id
            || !valid_bounded_text(model, MAX_MODEL_BYTES)
            || !valid_bounded_text(model_provider, MAX_MODEL_PROVIDER_BYTES)
        {
            return Err(ReadinessProxyError::InvalidArgument);
        }
        Ok(Self {
            thread_id: thread_id.to_owned(),
            policy: ReadinessPolicy::SyntheticFork {
                source_thread_id: source_thread_id.to_owned(),
                expected_settings: EffectiveThreadSettings {
                    cwd: cwd.to_owned(),
                    model: model.to_owned(),
                    model_provider: model_provider.to_owned(),
                    approval_policy: EffectiveApprovalPolicy::Never,
                    approvals_reviewer: EffectiveApprovalsReviewer::User,
                    sandbox_type: EffectiveSandboxType::ReadOnly,
                    sandbox_network_access: EffectiveNetworkAccess::Restricted,
                },
            },
        })
    }

    #[allow(dead_code)] // Exact resume is wired by the next supervised-session slice in issue #33.
    fn exact_resume(thread_id: &str, cwd: &Path) -> Result<Self, ReadinessProxyError> {
        let cwd = cwd
            .to_str()
            .filter(|cwd| valid_absolute_cwd(cwd))
            .ok_or(ReadinessProxyError::InvalidArgument)?;
        if !valid_thread_id(thread_id) {
            return Err(ReadinessProxyError::InvalidArgument);
        }
        Ok(Self {
            thread_id: thread_id.to_owned(),
            policy: ReadinessPolicy::ExactResume {
                expected_cwd: cwd.to_owned(),
            },
        })
    }
}

impl ReadinessProxy {
    #[cfg(test)]
    pub(super) fn fail_next_exact_start_after_bind_for_test() {
        FAIL_EXACT_START_AFTER_BIND.with(|fault| fault.set(true));
    }

    pub(super) fn spawn(
        socket_path: &Path,
        upstream_path: &Path,
        probe: ReadinessProbe<'_>,
        timeout: Duration,
    ) -> Result<Self, ReadinessProxyError> {
        if socket_path == upstream_path
            || probe.target_thread_id.is_empty()
            || probe.target_thread_id.len() > MAX_THREAD_ID_BYTES
            || probe.source_thread_id.is_empty()
            || probe.source_thread_id.len() > MAX_THREAD_ID_BYTES
            || probe.source_thread_id == probe.target_thread_id
            || timeout.is_zero()
        {
            return Err(ReadinessProxyError::InvalidArgument);
        }
        let expectation = ReadinessExpectation::pinned_probe(
            probe.target_thread_id,
            probe.source_thread_id,
            probe.cwd,
            probe.model,
            probe.model_provider,
        )?;
        Self::spawn_with_expectation(socket_path, upstream_path, expectation, timeout)
    }

    #[allow(dead_code)] // Exact resume is wired by the next supervised-session slice in issue #33.
    pub(super) fn spawn_exact(
        socket_path: &Path,
        upstream_path: &Path,
        probe: ExactResumeProbe<'_>,
        timeout: Duration,
    ) -> Result<Self, ReadinessProxyError> {
        let expectation = ReadinessExpectation::exact_resume(probe.target_thread_id, probe.cwd)?;
        Self::spawn_with_expectation(socket_path, upstream_path, expectation, timeout)
    }

    /// Starts an exact-resume relay without discarding post-bind cleanup
    /// authority on any failure edge.
    #[cfg(test)]
    pub(super) fn spawn_exact_owned(
        socket_path: &Path,
        upstream_path: &Path,
        probe: ExactResumeProbe<'_>,
        timeout: Duration,
    ) -> Result<Self, Box<ReadinessProxyStartFailure>> {
        let expectation = ReadinessExpectation::exact_resume(probe.target_thread_id, probe.cwd)
            .map_err(ReadinessProxyStartFailure::unbound)?;
        Self::spawn_with_expectation_owned(socket_path, upstream_path, expectation, timeout)
    }

    /// Starts an exact-resume relay against one caller-minted absolute
    /// readiness deadline. The deadline is never translated back into a
    /// relative duration, so the worker cannot outlive its enclosing startup
    /// envelope because of validation or scheduling time between layers.
    pub(super) fn spawn_exact_owned_until(
        socket_path: &Path,
        upstream_path: &Path,
        probe: ExactResumeProbe<'_>,
        deadline: Instant,
    ) -> Result<Self, Box<ReadinessProxyStartFailure>> {
        let expectation = ReadinessExpectation::exact_resume(probe.target_thread_id, probe.cwd)
            .map_err(ReadinessProxyStartFailure::unbound)?;
        Self::spawn_with_expectation_owned_until(socket_path, upstream_path, expectation, deadline)
    }

    #[cfg(test)]
    fn spawn_with_expectation_owned(
        socket_path: &Path,
        upstream_path: &Path,
        expectation: ReadinessExpectation,
        timeout: Duration,
    ) -> Result<Self, Box<ReadinessProxyStartFailure>> {
        if socket_path == upstream_path || timeout.is_zero() {
            return Err(ReadinessProxyStartFailure::unbound(
                ReadinessProxyError::InvalidArgument,
            ));
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ReadinessProxyStartFailure::unbound(ReadinessProxyError::InvalidArgument)
        })?;
        Self::spawn_with_expectation_owned_until(socket_path, upstream_path, expectation, deadline)
    }

    fn spawn_with_expectation_owned_until(
        socket_path: &Path,
        upstream_path: &Path,
        expectation: ReadinessExpectation,
        deadline: Instant,
    ) -> Result<Self, Box<ReadinessProxyStartFailure>> {
        if socket_path == upstream_path {
            return Err(ReadinessProxyStartFailure::unbound(
                ReadinessProxyError::InvalidArgument,
            ));
        }
        if Instant::now() >= deadline {
            return Err(ReadinessProxyStartFailure::unbound(
                ReadinessProxyError::Timeout,
            ));
        }
        verify_private_socket_parent(socket_path).map_err(ReadinessProxyStartFailure::unbound)?;
        let listener = UnixListener::bind(socket_path)
            .map_err(|_| ReadinessProxyStartFailure::unbound(ReadinessProxyError::Bind))?;
        let mut bound = BoundReadinessStartSocket {
            listener,
            path: socket_path.to_owned(),
            identity: None,
        };
        if bound
            .listener
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(Path::to_owned))
            .as_deref()
            != Some(socket_path)
        {
            return Err(ReadinessProxyStartFailure::bound(
                ReadinessProxyError::Bind,
                bound,
            ));
        }
        let identity = match raw_socket_identity(socket_path) {
            Ok(identity) => identity,
            Err(error) => return Err(ReadinessProxyStartFailure::bound(error, bound)),
        };
        bound.identity = Some(identity);
        if fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).is_err() {
            return Err(ReadinessProxyStartFailure::bound(
                ReadinessProxyError::Bind,
                bound,
            ));
        }
        match socket_identity(socket_path) {
            Ok(observed) if observed == identity => {}
            Ok(_) => {
                return Err(ReadinessProxyStartFailure::bound(
                    ReadinessProxyError::Bind,
                    bound,
                ));
            }
            Err(error) => return Err(ReadinessProxyStartFailure::bound(error, bound)),
        }
        if bound.listener.set_nonblocking(true).is_err() {
            return Err(ReadinessProxyStartFailure::bound(
                ReadinessProxyError::Bind,
                bound,
            ));
        }
        #[cfg(test)]
        if FAIL_EXACT_START_AFTER_BIND.with(|fault| fault.replace(false)) {
            return Err(ReadinessProxyStartFailure::bound(
                ReadinessProxyError::Worker,
                bound,
            ));
        }

        let worker_listener = match bound.listener.try_clone() {
            Ok(listener) => listener,
            Err(_) => {
                return Err(ReadinessProxyStartFailure::bound(
                    ReadinessProxyError::Worker,
                    bound,
                ));
            }
        };
        let (readiness_sender, readiness) = mpsc::sync_channel(1);
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let transport = Arc::new(ReadinessTransportTracker::new());
        let worker_control = RelayControl {
            lifecycle: Arc::clone(&lifecycle),
            transport: Arc::clone(&transport),
        };
        let health = Arc::new(Mutex::new(None));
        let worker_health = Arc::clone(&health);
        let worker_socket_path = socket_path.to_owned();
        let worker_upstream_path = upstream_path.to_owned();
        let worker_expectation = expectation;
        let worker = match thread::Builder::new()
            .name("calcifer-codex-readiness-proxy".to_owned())
            .spawn(move || {
                let mut socket_guard = SocketPathGuard::new(worker_socket_path, identity);
                let proxy_result = run_proxy(
                    worker_listener,
                    &worker_upstream_path,
                    &worker_expectation,
                    deadline,
                    &worker_control,
                    &worker_health,
                    &readiness_sender,
                );
                let proxy_result = finalize_proxy_run(proxy_result);
                let _ = socket_guard.cleanup();
                proxy_result
            }) {
            Ok(worker) => worker,
            Err(_) => {
                return Err(ReadinessProxyStartFailure::bound(
                    ReadinessProxyError::Worker,
                    bound,
                ));
            }
        };
        let BoundReadinessStartSocket {
            listener: observer,
            path: _,
            identity: _,
        } = bound;

        Ok(Self {
            observer,
            socket_path: socket_path.to_owned(),
            socket_identity: identity,
            readiness,
            readiness_result: None,
            lifecycle,
            transport,
            health,
            worker: Some(worker),
            joined_result: None,
            cleanup_complete: false,
            deadline,
            shutdown_error: None,
        })
    }

    fn spawn_with_expectation(
        socket_path: &Path,
        upstream_path: &Path,
        expectation: ReadinessExpectation,
        timeout: Duration,
    ) -> Result<Self, ReadinessProxyError> {
        if socket_path == upstream_path || timeout.is_zero() {
            return Err(ReadinessProxyError::InvalidArgument);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ReadinessProxyError::InvalidArgument)?;

        verify_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path).map_err(|_| ReadinessProxyError::Bind)?;
        // AF_UNIX descriptor metadata identifies the kernel socket object, not
        // the filesystem pathname inode (notably on macOS and Linux), so it
        // cannot be compared with `lstat`. Bind the descriptor to the requested
        // address, then protect the pathname with the owner-only parent and a
        // recorded pathname identity used for every cleanup.
        if listener
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(Path::to_owned))
            .as_deref()
            != Some(socket_path)
        {
            drop(listener);
            return Err(ReadinessProxyError::Bind);
        }
        let bound_identity = match raw_socket_identity(socket_path) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                return Err(error);
            }
        };
        if fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).is_err() {
            drop(listener);
            let _ = remove_owned_socket_inner(socket_path, bound_identity, false);
            return Err(ReadinessProxyError::Bind);
        }
        let socket_identity = match socket_identity(socket_path) {
            Ok(identity) if identity == bound_identity => identity,
            Ok(_) => {
                drop(listener);
                let _ = remove_owned_socket_inner(socket_path, bound_identity, false);
                return Err(ReadinessProxyError::Bind);
            }
            Err(error) => {
                drop(listener);
                let _ = remove_owned_socket_inner(socket_path, bound_identity, false);
                return Err(error);
            }
        };
        if listener.set_nonblocking(true).is_err() {
            drop(listener);
            let _ = remove_owned_socket(socket_path, socket_identity);
            return Err(ReadinessProxyError::Bind);
        }

        let worker_listener = match listener.try_clone() {
            Ok(listener) => listener,
            Err(_) => {
                drop(listener);
                let _ = remove_owned_socket(socket_path, socket_identity);
                return Err(ReadinessProxyError::Worker);
            }
        };

        let (readiness_sender, readiness) = mpsc::sync_channel(1);
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let transport = Arc::new(ReadinessTransportTracker::new());
        let worker_control = RelayControl {
            lifecycle: Arc::clone(&lifecycle),
            transport: Arc::clone(&transport),
        };
        let health = Arc::new(Mutex::new(None));
        let worker_health = Arc::clone(&health);
        let worker_socket_path = socket_path.to_owned();
        let worker_upstream_path = upstream_path.to_owned();
        let worker_expectation = expectation;
        let worker = thread::Builder::new()
            .name("calcifer-codex-readiness-proxy".to_owned())
            .spawn(move || {
                let mut socket_guard = SocketPathGuard::new(worker_socket_path, socket_identity);
                let proxy_result = run_proxy(
                    worker_listener,
                    &worker_upstream_path,
                    &worker_expectation,
                    deadline,
                    &worker_control,
                    &worker_health,
                    &readiness_sender,
                );
                let proxy_result = finalize_proxy_run(proxy_result);
                // The joining owner performs the authoritative cleanup proof.
                // This worker-side attempt covers detached/panicking owners but
                // cannot erase a retryable cleanup failure from the owner.
                let _ = socket_guard.cleanup();
                proxy_result
            })
            .map_err(|_| {
                let _ = remove_owned_socket(socket_path, socket_identity);
                ReadinessProxyError::Worker
            })?;

        Ok(Self {
            observer: listener,
            socket_path: socket_path.to_owned(),
            socket_identity,
            readiness,
            readiness_result: None,
            lifecycle,
            transport,
            health,
            worker: Some(worker),
            joined_result: None,
            cleanup_complete: false,
            deadline,
            shutdown_error: None,
        })
    }

    pub(super) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Appends the parent-retained duplicate of the relay listener to a
    /// source-pinned child denyset. It represents the exact kernel socket used
    /// by the worker without exposing the worker thread's raw descriptor.
    pub(super) fn append_forbidden_descriptor<'source>(
        &'source self,
        forbidden: &mut calcifer_unix_child_fd::CrossProcessDescriptorSet<'source>,
    ) -> Result<(), calcifer_unix_child_fd::CrossProcessDescriptorIdentityError> {
        forbidden.capture(self.observer.as_fd())
    }

    pub(super) fn wait_until_ready(&mut self) -> Result<(), ReadinessProxyError> {
        self.wait_until_ready_with_settings().map(|_| ())
    }

    /// Observes exact readiness without blocking the session event loop.
    ///
    /// `Ok(None)` is returned only while the relay is still running and its
    /// fixed startup deadline has not elapsed. Success and failure are cached,
    /// so a later poll cannot reclassify the authoritative first result. A
    /// successful readiness result deliberately remains successful here if the
    /// transport disconnects later; [`Self::ensure_connected`] is the separate
    /// post-readiness liveness proof.
    pub(super) fn poll_ready(
        &mut self,
    ) -> Result<Option<EffectiveThreadSettings>, ReadinessProxyError> {
        if let Some(result) = self.readiness_result.as_ref() {
            return result.clone().map(Some);
        }
        match self.readiness.try_recv() {
            Ok(result) => return self.record_readiness(result).map(Some),
            Err(TryRecvError::Disconnected) => {
                let error = self
                    .transport
                    .preserve_selected(ReadinessProxyError::Worker);
                return self.record_readiness(Err(error)).map(Some);
            }
            Err(TryRecvError::Empty) => {}
        }
        if Instant::now() >= self.deadline {
            return self
                .record_readiness(Err(ReadinessProxyError::Timeout))
                .map(Some);
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            // A copy pump can observe EOF after it has already queued the
            // final semantic event. The supervisor worker must be allowed to
            // consume that event and publish its authoritative readiness
            // verdict before transport disconnect is classified.
            return Ok(None);
        }
        // Close the race between the first empty observation and worker exit.
        // A finished sender can still have left one bounded verdict queued.
        match self.readiness.try_recv() {
            Ok(result) => self.record_readiness(result).map(Some),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                let error = self
                    .transport
                    .preserve_selected(ReadinessProxyError::Worker);
                self.record_readiness(Err(error)).map(Some)
            }
        }
    }

    pub(super) fn wait_until_ready_with_settings(
        &mut self,
    ) -> Result<EffectiveThreadSettings, ReadinessProxyError> {
        if let Some(result) = self.poll_ready()? {
            return Ok(result);
        }
        let wait = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(ReadinessProxyError::Timeout);
        let result = match wait.and_then(|wait| {
            self.readiness
                .recv_timeout(wait)
                .map_err(|error| match error {
                    RecvTimeoutError::Timeout => ReadinessProxyError::Timeout,
                    RecvTimeoutError::Disconnected => self
                        .transport
                        .preserve_selected(ReadinessProxyError::Worker),
                })
        }) {
            Ok(result) => result,
            Err(error) => Err(error),
        };
        self.record_readiness(result)
    }

    fn record_readiness(
        &mut self,
        result: Result<EffectiveThreadSettings, ReadinessProxyError>,
    ) -> Result<EffectiveThreadSettings, ReadinessProxyError> {
        if result.is_err() {
            self.transport.stop(&self.lifecycle);
        }
        self.readiness_result = Some(result.clone());
        result
    }

    pub(super) fn shutdown(
        mut self,
        deadline: Instant,
    ) -> Result<ReadinessProxyShutdownComplete, ReadinessProxyShutdownFailure> {
        self.request_stop();
        match self.wait_and_join(deadline) {
            Ok(()) => Ok(ReadinessProxyShutdownComplete { _private: () }),
            Err(errors) => {
                let retained = self.worker.is_some() || !self.cleanup_complete;
                Err(ReadinessProxyShutdownFailure {
                    proxy: retained.then(|| Box::new(self)),
                    operation_error: errors.operation,
                    cleanup_error: errors.cleanup,
                })
            }
        }
    }

    /// Proves that the relay has not ended between readiness and the caller's
    /// final process-liveness checks. A worker that ended before intentional
    /// shutdown is always a transport failure, even if readiness was emitted.
    pub(super) fn ensure_connected(&mut self) -> Result<(), ReadinessProxyError> {
        if !matches!(self.readiness_result.as_ref(), Some(Ok(_))) {
            return Err(ReadinessProxyError::UnexpectedSequence);
        }
        match self.lifecycle.load(Ordering::Acquire) {
            RELAY_RUNNING => {}
            RELAY_DISCONNECTED => {
                return Err(self
                    .transport
                    .classify_disconnected(ReadinessTransportOrigin::LifecycleDisconnected));
            }
            _ => return Err(ReadinessProxyError::UnexpectedSequence),
        }
        let Some(worker) = self.worker.as_ref() else {
            return Err(self
                .transport
                .disconnect(&self.lifecycle, ReadinessTransportOrigin::WorkerFinished)
                .unwrap_or_else(|| {
                    self.transport
                        .preserve_selected(ReadinessProxyError::UnexpectedSequence)
                }));
        };
        if !worker.is_finished() {
            let health = self.health.lock().map_err(|_| {
                self.transport
                    .preserve_selected(ReadinessProxyError::Worker)
            })?;
            let health = health.as_ref().ok_or_else(|| {
                self.transport
                    .preserve_selected(ReadinessProxyError::Worker)
            })?;
            if health.is_connected(&self.lifecycle, &self.transport)? {
                return Ok(());
            }
            return Err(self
                .transport
                .classify_disconnected(ReadinessTransportOrigin::LifecycleDisconnected));
        }
        // Liveness checks never consume exact join authority. Shutdown owns the
        // join plus the subsequent socket-cleanup proof as one retryable phase.
        Err(self
            .transport
            .disconnect(&self.lifecycle, ReadinessTransportOrigin::WorkerFinished)
            .unwrap_or_else(|| {
                self.transport
                    .preserve_selected(ReadinessProxyError::UnexpectedSequence)
            }))
    }

    fn request_stop(&mut self) {
        if self.readiness_result.as_ref().is_some_and(Result::is_err) {
            self.transport.stop(&self.lifecycle);
            return;
        }
        let (previous, error) = self.transport.stop_with_disconnected_origin(
            &self.lifecycle,
            ReadinessTransportOrigin::LifecycleDisconnected,
        );
        if previous == RELAY_DISCONNECTED {
            if let Some(error) = error {
                self.shutdown_error.get_or_insert(error);
            }
        }
    }

    fn force_stop(&self) {
        let health = match self.health.try_lock() {
            Ok(health) => health,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        if let Some(health) = health.as_ref() {
            let _ = health.client.shutdown(Shutdown::Both);
            let _ = health.upstream.shutdown(Shutdown::Both);
        }
    }

    fn wait_and_join(&mut self, deadline: Instant) -> Result<(), ProxyShutdownErrors> {
        if self.worker.is_some() {
            loop {
                let now = Instant::now();
                if now >= deadline {
                    self.force_stop();
                    return Err(ProxyShutdownErrors::operation(ReadinessProxyError::Timeout));
                }
                let Some(worker) = self.worker.as_ref() else {
                    return Err(ProxyShutdownErrors::operation(ReadinessProxyError::Worker));
                };
                if worker.is_finished() {
                    break;
                }
                thread::sleep(
                    deadline
                        .saturating_duration_since(now)
                        .min(SHUTDOWN_POLL_INTERVAL),
                );
            }
            let joined = match self.worker.take() {
                Some(worker) => match worker.join() {
                    Ok(result) => result,
                    Err(_) => Err(self
                        .transport
                        .preserve_selected(ReadinessProxyError::Worker)),
                },
                None => Err(ReadinessProxyError::Worker),
            };
            self.joined_result = Some(joined);
        }

        let Some(joined_result) = self.joined_result else {
            return Err(ProxyShutdownErrors::operation(ReadinessProxyError::Worker));
        };
        if !self.cleanup_complete && Instant::now() >= deadline {
            return Err(ProxyShutdownErrors::operation(ReadinessProxyError::Timeout));
        }
        let cleanup_error = if self.cleanup_complete {
            None
        } else {
            match remove_owned_socket(&self.socket_path, self.socket_identity) {
                Ok(()) => {
                    self.cleanup_complete = true;
                    None
                }
                Err(error) => Some(error),
            }
        };
        let operation_error = if self.readiness_result.as_ref().is_some_and(Result::is_err) {
            None
        } else {
            self.shutdown_error.or(joined_result.err())
        };
        match (operation_error, cleanup_error) {
            (None, None) => Ok(()),
            (operation, cleanup) => Err(ProxyShutdownErrors { operation, cleanup }),
        }
    }
}

struct ProxyShutdownErrors {
    operation: Option<ReadinessProxyError>,
    cleanup: Option<ReadinessProxyError>,
}

impl ProxyShutdownErrors {
    const fn operation(error: ReadinessProxyError) -> Self {
        Self {
            operation: Some(error),
            cleanup: None,
        }
    }
}

fn finalize_proxy_run(result: Result<(), ProxyRunError>) -> Result<(), ReadinessProxyError> {
    match result {
        Ok(()) | Err(ProxyRunError::Stopped) => Ok(()),
        Err(ProxyRunError::Failed(error)) => Err(error),
    }
}

impl Drop for ReadinessProxy {
    fn drop(&mut self) {
        // Drop may request cancellation and wake blocking copies, but it must
        // never perform an unbounded join or manufacture shutdown proof.
        self.request_stop();
        self.force_stop();
    }
}

#[derive(Debug)]
pub(super) struct ReadinessProxyShutdownComplete {
    _private: (),
}

#[must_use = "a timed-out readiness proxy retains worker join ownership"]
pub(super) struct ReadinessProxyShutdownFailure {
    proxy: Option<Box<ReadinessProxy>>,
    operation_error: Option<ReadinessProxyError>,
    cleanup_error: Option<ReadinessProxyError>,
}

impl ReadinessProxyShutdownFailure {
    pub(super) fn error(&self) -> ReadinessProxyError {
        self.operation_error
            .or(self.cleanup_error)
            .unwrap_or(ReadinessProxyError::Worker)
    }

    pub(super) const fn operation_error(&self) -> Option<ReadinessProxyError> {
        self.operation_error
    }

    pub(super) const fn cleanup_error(&self) -> Option<ReadinessProxyError> {
        self.cleanup_error
    }

    pub(super) fn into_proxy(self) -> Option<ReadinessProxy> {
        self.proxy.map(|proxy| *proxy)
    }
}

impl fmt::Debug for ReadinessProxyShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadinessProxyShutdownFailure")
            .field("operation_error", &self.operation_error)
            .field("cleanup_error", &self.cleanup_error)
            .field("proxy_retained", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ReadinessProxyShutdownFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for ReadinessProxyShutdownFailure {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

struct RelayHealth {
    client: UnixStream,
    upstream: UnixStream,
}

impl RelayHealth {
    fn is_connected(
        &self,
        lifecycle: &AtomicU8,
        transport: &ReadinessTransportTracker,
    ) -> Result<bool, ReadinessProxyError> {
        Ok(
            socket_is_connected(&self.client, HealthEndpoint::Client, lifecycle, transport)?
                && socket_is_connected(
                    &self.upstream,
                    HealthEndpoint::Upstream,
                    lifecycle,
                    transport,
                )?,
        )
    }
}

#[derive(Clone, Copy)]
enum HealthEndpoint {
    Client,
    Upstream,
}

impl HealthEndpoint {
    const fn poll_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::Client => ReadinessTransportOrigin::HealthClientPoll,
            Self::Upstream => ReadinessTransportOrigin::HealthUpstreamPoll,
        }
    }

    const fn peek_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::Client => ReadinessTransportOrigin::HealthClientPeek,
            Self::Upstream => ReadinessTransportOrigin::HealthUpstreamPeek,
        }
    }

    const fn eof_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::Client => ReadinessTransportOrigin::HealthClientEof,
            Self::Upstream => ReadinessTransportOrigin::HealthUpstreamEof,
        }
    }
}

fn socket_is_connected(
    stream: &UnixStream,
    endpoint: HealthEndpoint,
    lifecycle: &AtomicU8,
    transport: &ReadinessTransportTracker,
) -> Result<bool, ReadinessProxyError> {
    let mut poll_fds = [rustix::event::PollFd::new(
        stream,
        rustix::event::PollFlags::IN,
    )];
    loop {
        match rustix::event::poll(&mut poll_fds, Some(&rustix::event::Timespec::default())) {
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => {
                return transport
                    .disconnect(lifecycle, endpoint.poll_origin())
                    .map_or(Ok(false), Err);
            }
        }
    }
    if poll_fds[0].revents().intersects(
        rustix::event::PollFlags::ERR
            | rustix::event::PollFlags::HUP
            | rustix::event::PollFlags::NVAL,
    ) {
        let _ = transport.disconnect(lifecycle, endpoint.eof_origin());
        return Ok(false);
    }

    let mut byte = [0_u8; 1];
    loop {
        match rustix::net::recv(
            stream,
            &mut byte[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        ) {
            Ok((_, 0)) => {
                let _ = transport.disconnect(lifecycle, endpoint.eof_origin());
                return Ok(false);
            }
            Ok((_, _)) | Err(rustix::io::Errno::AGAIN) => return Ok(true),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => {
                return transport
                    .disconnect(lifecycle, endpoint.peek_origin())
                    .map_or(Ok(false), Err);
            }
        }
    }
}

struct SocketPathGuard {
    path: PathBuf,
    identity: SocketIdentity,
    cleaned: bool,
}

impl SocketPathGuard {
    fn new(path: PathBuf, identity: SocketIdentity) -> Self {
        Self {
            path,
            identity,
            cleaned: false,
        }
    }

    fn cleanup(&mut self) -> Result<(), ReadinessProxyError> {
        let result = remove_owned_socket(&self.path, self.identity);
        if result.is_ok() {
            self.cleaned = true;
        }
        result
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = remove_owned_socket(&self.path, self.identity);
        }
    }
}

fn verify_private_socket_parent(path: &Path) -> Result<(), ReadinessProxyError> {
    let parent = path.parent().ok_or(ReadinessProxyError::InvalidArgument)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ReadinessProxyError::Bind)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ReadinessProxyError::Bind);
    }
    Ok(())
}

fn raw_socket_identity(path: &Path) -> Result<SocketIdentity, ReadinessProxyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReadinessProxyError::Bind)?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(ReadinessProxyError::Bind);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid,
    })
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, ReadinessProxyError> {
    let identity = raw_socket_identity(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ReadinessProxyError::Bind)?;
    if metadata.permissions().mode() & 0o777 != 0o600
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
    {
        return Err(ReadinessProxyError::Bind);
    }
    Ok(identity)
}

fn remove_owned_socket(path: &Path, expected: SocketIdentity) -> Result<(), ReadinessProxyError> {
    remove_owned_socket_inner(path, expected, true)
}

fn remove_owned_socket_inner(
    path: &Path,
    expected: SocketIdentity,
    require_private_mode: bool,
) -> Result<(), ReadinessProxyError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ReadinessProxyError::Cleanup),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.uid
        || (require_private_mode && metadata.permissions().mode() & 0o777 != 0o600)
    {
        return Err(ReadinessProxyError::Cleanup);
    }
    fs::remove_file(path).map_err(|_| ReadinessProxyError::Cleanup)
}

struct ReadyNotifier<'a> {
    sender: &'a SyncSender<Result<EffectiveThreadSettings, ReadinessProxyError>>,
    sent: bool,
}

impl<'a> ReadyNotifier<'a> {
    fn new(sender: &'a SyncSender<Result<EffectiveThreadSettings, ReadinessProxyError>>) -> Self {
        Self {
            sender,
            sent: false,
        }
    }

    fn success(&mut self, settings: EffectiveThreadSettings) -> Result<(), ReadinessProxyError> {
        self.sent = true;
        self.sender
            .send(Ok(settings))
            .map_err(|_| ReadinessProxyError::Worker)
    }

    fn failure(&mut self, error: ReadinessProxyError) {
        if !self.sent {
            self.sent = true;
            let _ = self.sender.send(Err(error));
        }
    }
}

fn run_proxy(
    listener: UnixListener,
    upstream_path: &Path,
    expectation: &ReadinessExpectation,
    deadline: Instant,
    control: &RelayControl,
    health: &Arc<Mutex<Option<RelayHealth>>>,
    readiness_sender: &SyncSender<Result<EffectiveThreadSettings, ReadinessProxyError>>,
) -> Result<(), ProxyRunError> {
    let mut notifier = ReadyNotifier::new(readiness_sender);
    let result = run_proxy_inner(
        &listener,
        upstream_path,
        expectation,
        deadline,
        control,
        health,
        &mut notifier,
    );
    let result = result.map_err(|error| select_run_error(&control.transport, error));
    if let Err(ProxyRunError::Failed(error)) = &result {
        notifier.failure(*error);
    }
    result
}

fn select_run_error(transport: &ReadinessTransportTracker, error: ProxyRunError) -> ProxyRunError {
    match error {
        ProxyRunError::Stopped => ProxyRunError::Stopped,
        ProxyRunError::Failed(error) => transport.select_failure(error),
    }
}

fn run_proxy_inner(
    listener: &UnixListener,
    upstream_path: &Path,
    expectation: &ReadinessExpectation,
    deadline: Instant,
    control: &RelayControl,
    health: &Arc<Mutex<Option<RelayHealth>>>,
    notifier: &mut ReadyNotifier<'_>,
) -> Result<(), ProxyRunError> {
    let lifecycle = &control.lifecycle;
    let transport = &control.transport;
    let client = accept_client(listener, deadline, control)?;
    let upstream = connect_upstream(upstream_path, deadline, lifecycle)?;
    let client_reader = client
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::ClientClone))?;
    let client_writer = client
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::ClientClone))?;
    let upstream_reader = upstream
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::UpstreamClone))?;
    let upstream_writer = upstream
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::UpstreamClone))?;
    let health_client = client
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::ClientClone))?;
    let health_upstream = upstream
        .try_clone()
        .map_err(|_| transport_failure(control, ReadinessTransportOrigin::UpstreamClone))?;
    *health.lock().map_err(|_| ReadinessProxyError::Worker)? = Some(RelayHealth {
        client: health_client,
        upstream: health_upstream,
    });

    let inspecting = Arc::new(AtomicBool::new(true));
    // Serialize the inspected forward+observe operations in both directions.
    // In particular, the server response is written to the TUI and its event
    // is queued before the TUI can enqueue the request caused by that response.
    let observation_order = Arc::new(Mutex::new(()));
    let (event_sender, event_receiver) = mpsc::sync_channel(EVENT_CHANNEL_CAPACITY);
    let client_inspecting = Arc::clone(&inspecting);
    let client_sender = event_sender.clone();
    let client_order = Arc::clone(&observation_order);
    let client_control = control.clone();
    let client_pump = thread::Builder::new()
        .name("calcifer-readiness-client-pump".to_owned())
        .spawn(move || {
            pump(
                client_reader,
                upstream_writer,
                Direction::ClientToServer,
                &client_inspecting,
                &client_sender,
                &client_order,
                &client_control,
            );
        });
    let client_pump = match client_pump {
        Ok(pump) => pump,
        Err(_) => {
            return Err(transport.select_failure(ReadinessProxyError::Worker));
        }
    };

    let server_inspecting = Arc::clone(&inspecting);
    let server_order = Arc::clone(&observation_order);
    let server_control = control.clone();
    let server_pump = match thread::Builder::new()
        .name("calcifer-readiness-server-pump".to_owned())
        .spawn(move || {
            pump(
                upstream_reader,
                client_writer,
                Direction::ServerToClient,
                &server_inspecting,
                &event_sender,
                &server_order,
                &server_control,
            );
        }) {
        Ok(pump) => pump,
        Err(_) => {
            let error = transport.select_failure(ReadinessProxyError::Worker);
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = client_pump.join();
            return Err(error);
        }
    };

    let mut state = ReadinessState::new(expectation.clone());
    let mut ready = false;
    let result = loop {
        if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING {
            break Err(ProxyRunError::Stopped);
        }
        if !ready && Instant::now() >= deadline {
            break Err(transport.select_failure(ReadinessProxyError::Timeout));
        }
        let wait = if ready {
            POLL_INTERVAL
        } else {
            deadline
                .saturating_duration_since(Instant::now())
                .min(POLL_INTERVAL)
        };
        match event_receiver.recv_timeout(wait) {
            Ok(PumpEvent::Observed(event)) if !ready => match state.observe(*event) {
                Ok(true) => {
                    let Some(settings) = state.effective_settings().cloned() else {
                        break Err(transport.select_failure(ReadinessProxyError::InvalidMessage));
                    };
                    if let Err(error) = transport.publish_readiness(lifecycle, || {
                        inspecting.store(false, Ordering::Release);
                        notifier.success(settings)
                    }) {
                        break Err(error);
                    }
                    ready = true;
                }
                Ok(false) => {}
                Err(error) => break Err(transport.select_failure(error)),
            },
            Ok(PumpEvent::Observed(_)) => {}
            Ok(PumpEvent::Ended(_)) if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING => {
                break Err(ProxyRunError::Stopped);
            }
            Ok(PumpEvent::Ended(error)) => {
                break Err(transport.select_failure(error));
            }
            Ok(PumpEvent::Failed(_)) if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING => {
                break Err(ProxyRunError::Stopped);
            }
            Ok(PumpEvent::Failed(error)) => {
                break Err(transport.select_failure(error));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected)
                if lifecycle.load(Ordering::Acquire) == RELAY_STOPPING =>
            {
                break Err(ProxyRunError::Stopped);
            }
            Err(RecvTimeoutError::Disconnected) => {
                let error = transport_failure(
                    control,
                    ReadinessTransportOrigin::ObservationChannelDisconnected,
                );
                break Err(select_run_error(transport, error));
            }
        }
    };

    inspecting.store(false, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    drop(event_receiver);
    let client_join = client_pump.join();
    let server_join = server_pump.join();
    if client_join.is_err() || server_join.is_err() {
        return match result {
            Err(ProxyRunError::Failed(error)) => {
                Err(ProxyRunError::Failed(transport.preserve_selected(error)))
            }
            Err(ProxyRunError::Stopped) | Ok(()) => Err(ReadinessProxyError::Worker.into()),
        };
    }
    result
}

fn transport_failure(control: &RelayControl, origin: ReadinessTransportOrigin) -> ProxyRunError {
    match control.transport.disconnect(&control.lifecycle, origin) {
        Some(error) => ProxyRunError::Failed(error),
        None => control
            .transport
            .selected_failure()
            .map(ProxyRunError::Failed)
            .unwrap_or(ProxyRunError::Stopped),
    }
}

fn accept_client(
    listener: &UnixListener,
    deadline: Instant,
    control: &RelayControl,
) -> Result<UnixStream, ProxyRunError> {
    let lifecycle = &control.lifecycle;
    loop {
        if lifecycle.load(Ordering::Acquire) != RELAY_RUNNING {
            return Err(ProxyRunError::Stopped);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|_| {
                    transport_failure(control, ReadinessTransportOrigin::ClientConfigure)
                })?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(ReadinessProxyError::Timeout.into());
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(ReadinessProxyError::Accept.into()),
        }
    }
}

fn connect_upstream(
    path: &Path,
    deadline: Instant,
    lifecycle: &AtomicU8,
) -> Result<UnixStream, ProxyRunError> {
    loop {
        if lifecycle.load(Ordering::Acquire) != RELAY_RUNNING {
            return Err(ProxyRunError::Stopped);
        }
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(ReadinessProxyError::Timeout.into());
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(ReadinessProxyError::Connect.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    const fn reader_eof_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::ClientToServer => ReadinessTransportOrigin::ClientEof,
            Self::ServerToClient => ReadinessTransportOrigin::UpstreamEof,
        }
    }

    const fn reader_error_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::ClientToServer => ReadinessTransportOrigin::ClientRead,
            Self::ServerToClient => ReadinessTransportOrigin::UpstreamRead,
        }
    }

    const fn writer_error_origin(self) -> ReadinessTransportOrigin {
        match self {
            Self::ClientToServer => ReadinessTransportOrigin::UpstreamWrite,
            Self::ServerToClient => ReadinessTransportOrigin::ClientWrite,
        }
    }
}

enum PumpEvent {
    Observed(Box<ObservedEvent>),
    Ended(ReadinessProxyError),
    Failed(ReadinessProxyError),
}

fn pump(
    mut reader: UnixStream,
    mut writer: UnixStream,
    direction: Direction,
    inspecting: &AtomicBool,
    sender: &SyncSender<PumpEvent>,
    observation_order: &Mutex<()>,
    control: &RelayControl,
) {
    let lifecycle = &control.lifecycle;
    let transport = &control.transport;
    let mut inspector = ProtocolInspector::new(direction);
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => {
                let Some(error) = transport.disconnect(lifecycle, direction.reader_eof_origin())
                else {
                    return;
                };
                let _ = sender.send(PumpEvent::Ended(error));
                return;
            }
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let Some(error) = transport.disconnect(lifecycle, direction.reader_error_origin())
                else {
                    return;
                };
                let _ = sender.send(PumpEvent::Failed(error));
                return;
            }
        };
        let bytes = &buffer[..count];
        if !inspecting.load(Ordering::Acquire) {
            if writer.write_all(bytes).is_err() {
                let Some(error) = transport.disconnect(lifecycle, direction.writer_error_origin())
                else {
                    return;
                };
                let _ = sender.send(PumpEvent::Failed(error));
                return;
            }
            continue;
        }

        let events = match inspector.feed(bytes) {
            Ok(events) => events,
            Err(error) => {
                let Some(error) = transport.fail_while_running(lifecycle, error) else {
                    return;
                };
                let _ = sender.send(PumpEvent::Failed(error));
                return;
            }
        };
        let Ok(_ordering_guard) = observation_order.lock() else {
            let Some(error) = transport.fail_while_running(lifecycle, ReadinessProxyError::Worker)
            else {
                return;
            };
            let _ = sender.send(PumpEvent::Failed(error));
            return;
        };
        if writer.write_all(bytes).is_err() {
            let Some(error) = transport.disconnect(lifecycle, direction.writer_error_origin())
            else {
                return;
            };
            let _ = sender.send(PumpEvent::Failed(error));
            return;
        }
        if send_observed(events, sender).is_err() {
            let Some(error) =
                transport.disconnect(lifecycle, ReadinessTransportOrigin::ObservationDelivery)
            else {
                return;
            };
            let _ = sender.send(PumpEvent::Failed(error));
            return;
        }
    }
}

fn send_observed(events: Vec<ObservedEvent>, sender: &SyncSender<PumpEvent>) -> Result<(), ()> {
    for event in events {
        sender
            .send(PumpEvent::Observed(Box::new(event)))
            .map_err(|_| ())?;
    }
    Ok(())
}

struct ProtocolInspector {
    direction: Direction,
    handshake: Vec<u8>,
    handshake_complete: bool,
    frames: FrameDecoder,
}

impl ProtocolInspector {
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            handshake: Vec::new(),
            handshake_complete: false,
            frames: FrameDecoder::new(direction),
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<ObservedEvent>, ReadinessProxyError> {
        let mut events = Vec::new();
        if self.handshake_complete {
            self.frames.feed(bytes, &mut events)?;
            return Ok(events);
        }

        let available = MAX_HANDSHAKE_BYTES.saturating_sub(self.handshake.len());
        let stored = bytes.len().min(available);
        self.handshake.extend_from_slice(&bytes[..stored]);
        let Some(header_end) = find_header_end(&self.handshake) else {
            if stored != bytes.len() || self.handshake.len() == MAX_HANDSHAKE_BYTES {
                return Err(ReadinessProxyError::HandshakeTooLarge);
            }
            return Ok(events);
        };
        if header_end > MAX_HANDSHAKE_BYTES {
            return Err(ReadinessProxyError::HandshakeTooLarge);
        }
        validate_handshake(&self.handshake[..header_end], self.direction)?;
        let remainder = self.handshake.split_off(header_end);
        self.handshake.clear();
        self.handshake_complete = true;
        events.push(ObservedEvent::Handshake(self.direction));
        self.frames.feed(&remainder, &mut events)?;
        self.frames.feed(&bytes[stored..], &mut events)?;
        Ok(events)
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn validate_handshake(bytes: &[u8], direction: Direction) -> Result<(), ReadinessProxyError> {
    let text = str::from_utf8(bytes).map_err(|_| ReadinessProxyError::InvalidHandshake)?;
    let mut lines = text.split("\r\n");
    let first_line = lines.next().ok_or(ReadinessProxyError::InvalidHandshake)?;
    match direction {
        Direction::ClientToServer
            if first_line.starts_with("GET ") && first_line.ends_with(" HTTP/1.1") => {}
        Direction::ServerToClient if first_line.starts_with("HTTP/1.1 101 ") => {}
        _ => return Err(ReadinessProxyError::InvalidHandshake),
    }

    let mut has_upgrade = false;
    let mut has_connection_upgrade = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(ReadinessProxyError::InvalidHandshake)?;
        if name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket") {
            has_upgrade = true;
        }
        if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        {
            has_connection_upgrade = true;
        }
    }
    if has_upgrade && has_connection_upgrade {
        Ok(())
    } else {
        Err(ReadinessProxyError::InvalidHandshake)
    }
}

struct FrameDecoder {
    direction: Direction,
    buffer: Vec<u8>,
    fragmented_text: Option<Vec<u8>>,
}

impl FrameDecoder {
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            buffer: Vec::new(),
            fragmented_text: None,
        }
    }

    fn feed(
        &mut self,
        mut bytes: &[u8],
        events: &mut Vec<ObservedEvent>,
    ) -> Result<(), ReadinessProxyError> {
        loop {
            self.consume_buffered_frames(events)?;
            if bytes.is_empty() {
                return Ok(());
            }
            let available = MAX_FRAME_BUFFER_BYTES
                .checked_sub(self.buffer.len())
                .ok_or(ReadinessProxyError::FrameTooLarge)?;
            if available == 0 {
                return Err(ReadinessProxyError::FrameTooLarge);
            }
            let count = bytes.len().min(available);
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
        }
    }

    fn consume_buffered_frames(
        &mut self,
        events: &mut Vec<ObservedEvent>,
    ) -> Result<(), ReadinessProxyError> {
        loop {
            let Some(frame) = decode_frame_header(&self.buffer, self.direction)? else {
                return Ok(());
            };
            match (frame.opcode, self.fragmented_text.as_ref()) {
                (0x0, Some(fragment))
                    if fragment.len().saturating_add(frame.payload_bytes) > MAX_MESSAGE_BYTES =>
                {
                    return Err(ReadinessProxyError::FrameTooLarge);
                }
                (0x0, None) | (0x1, Some(_)) => {
                    return Err(ReadinessProxyError::InvalidFrame);
                }
                _ => {}
            }
            let frame_end = frame
                .header_bytes
                .checked_add(frame.payload_bytes)
                .ok_or(ReadinessProxyError::FrameTooLarge)?;
            if self.buffer.len() < frame_end {
                return Ok(());
            }
            let mut payload = self.buffer[frame.header_bytes..frame_end].to_vec();
            if let Some(mask) = frame.mask {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= mask[index % mask.len()];
                }
            }
            self.buffer.drain(..frame_end);
            self.consume_frame(frame.fin, frame.opcode, payload, events)?;
        }
    }

    fn consume_frame(
        &mut self,
        fin: bool,
        opcode: u8,
        payload: Vec<u8>,
        events: &mut Vec<ObservedEvent>,
    ) -> Result<(), ReadinessProxyError> {
        match opcode {
            0x0 => {
                let Some(fragment) = self.fragmented_text.as_mut() else {
                    return Err(ReadinessProxyError::InvalidFrame);
                };
                if fragment.len().saturating_add(payload.len()) > MAX_MESSAGE_BYTES {
                    return Err(ReadinessProxyError::FrameTooLarge);
                }
                fragment.extend(payload);
                if fin {
                    let Some(message) = self.fragmented_text.take() else {
                        return Err(ReadinessProxyError::InvalidFrame);
                    };
                    inspect_message(self.direction, &message, events)?;
                }
            }
            0x1 if self.fragmented_text.is_some() => {
                return Err(ReadinessProxyError::InvalidFrame);
            }
            0x1 if fin => {
                inspect_message(self.direction, &payload, events)?;
            }
            0x1 => {
                self.fragmented_text = Some(payload);
            }
            0x8 => {
                return Err(ReadinessProxyError::Transport(
                    self.direction.reader_eof_origin(),
                ));
            }
            0x9 | 0xA => {}
            _ => return Err(ReadinessProxyError::InvalidFrame),
        }
        Ok(())
    }
}

struct DecodedFrameHeader {
    fin: bool,
    opcode: u8,
    header_bytes: usize,
    payload_bytes: usize,
    mask: Option<[u8; 4]>,
}

fn decode_frame_header(
    bytes: &[u8],
    direction: Direction,
) -> Result<Option<DecodedFrameHeader>, ReadinessProxyError> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let fin = bytes[0] & 0x80 != 0;
    if bytes[0] & 0x70 != 0 {
        return Err(ReadinessProxyError::InvalidFrame);
    }
    let opcode = bytes[0] & 0x0f;
    let masked = bytes[1] & 0x80 != 0;
    let should_be_masked = direction == Direction::ClientToServer;
    if masked != should_be_masked {
        return Err(ReadinessProxyError::InvalidFrame);
    }

    let short_length = bytes[1] & 0x7f;
    let (payload_length, mut header_bytes) = match short_length {
        length @ 0..=125 => (u64::from(length), 2),
        126 => {
            if bytes.len() < 4 {
                return Ok(None);
            }
            let length = u64::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if length < 126 {
                return Err(ReadinessProxyError::InvalidFrame);
            }
            (length, 4)
        }
        127 => {
            if bytes.len() < 10 {
                return Ok(None);
            }
            if bytes[2] & 0x80 != 0 {
                return Err(ReadinessProxyError::InvalidFrame);
            }
            let length = u64::from_be_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            if length <= u64::from(u16::MAX) {
                return Err(ReadinessProxyError::InvalidFrame);
            }
            (length, 10)
        }
        _ => return Err(ReadinessProxyError::InvalidFrame),
    };
    let is_control = opcode & 0x08 != 0;
    if (is_control && (!fin || payload_length > 125)) || payload_length > MAX_MESSAGE_BYTES as u64 {
        return Err(if payload_length > MAX_MESSAGE_BYTES as u64 {
            ReadinessProxyError::FrameTooLarge
        } else {
            ReadinessProxyError::InvalidFrame
        });
    }
    let payload_bytes =
        usize::try_from(payload_length).map_err(|_| ReadinessProxyError::FrameTooLarge)?;
    let mask = if masked {
        if bytes.len() < header_bytes + 4 {
            return Ok(None);
        }
        let mask = [
            bytes[header_bytes],
            bytes[header_bytes + 1],
            bytes[header_bytes + 2],
            bytes[header_bytes + 3],
        ];
        header_bytes += 4;
        Some(mask)
    } else {
        None
    };
    Ok(Some(DecodedFrameHeader {
        fin,
        opcode,
        header_bytes,
        payload_bytes,
        mask,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessMethod {
    ThreadRead,
    ThreadResume,
}

#[derive(Debug, Eq, PartialEq)]
enum ObservedEvent {
    Handshake(Direction),
    Request {
        id: Value,
        method: ReadinessMethod,
        thread_id: String,
        include_turns: Option<bool>,
    },
    Response {
        id: Value,
        has_error: bool,
        thread_id: Option<String>,
        forked_from_id: Option<String>,
        settings: Option<EffectiveThreadSettings>,
    },
    ProviderRequest {
        id: Value,
        method: String,
    },
    ProviderNotification {
        method: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveThreadSettings {
    cwd: String,
    model: String,
    model_provider: String,
    approval_policy: EffectiveApprovalPolicy,
    approvals_reviewer: EffectiveApprovalsReviewer,
    sandbox_type: EffectiveSandboxType,
    sandbox_network_access: EffectiveNetworkAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectiveApprovalPolicy {
    Untrusted,
    OnRequest,
    Never,
    Granular {
        sandbox_approval: bool,
        rules: bool,
        skill_approval: bool,
        request_permissions: bool,
        mcp_elicitations: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectiveApprovalsReviewer {
    User,
    AutoReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectiveSandboxType {
    DangerFullAccess,
    ReadOnly,
    ExternalSandbox,
    WorkspaceWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectiveNetworkAccess {
    /// `dangerFullAccess` has no `networkAccess` field on the pinned wire type.
    Unspecified,
    Restricted,
    Enabled,
}

#[allow(dead_code)] // Consumed by the supervised process slice in issue #33.
impl EffectiveThreadSettings {
    pub(crate) fn cwd(&self) -> &str {
        &self.cwd
    }

    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    pub(crate) fn model_provider(&self) -> &str {
        &self.model_provider
    }

    pub(crate) const fn approval_policy(&self) -> EffectiveApprovalPolicy {
        self.approval_policy
    }

    pub(crate) const fn approvals_reviewer(&self) -> EffectiveApprovalsReviewer {
        self.approvals_reviewer
    }

    pub(crate) const fn sandbox_type(&self) -> EffectiveSandboxType {
        self.sandbox_type
    }

    pub(crate) const fn sandbox_network_access(&self) -> EffectiveNetworkAccess {
        self.sandbox_network_access
    }
}

fn inspect_message(
    direction: Direction,
    bytes: &[u8],
    events: &mut Vec<ObservedEvent>,
) -> Result<(), ReadinessProxyError> {
    let message = decode_unique_json(bytes).map_err(|_| ReadinessProxyError::InvalidMessage)?;
    let Some(object) = message.as_object() else {
        return Err(ReadinessProxyError::InvalidMessage);
    };
    match direction {
        Direction::ClientToServer => {
            let Some(method_name) = object.get("method") else {
                if object.get("id").is_some_and(|id| !valid_request_id(id)) {
                    return Err(ReadinessProxyError::InvalidMessage);
                }
                return Ok(());
            };
            let method_name = method_name
                .as_str()
                .filter(|method| valid_bounded_text(method, MAX_METHOD_BYTES))
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            if object.get("id").is_some_and(|id| !valid_request_id(id)) {
                return Err(ReadinessProxyError::InvalidMessage);
            }
            let method = match method_name {
                "thread/read" => ReadinessMethod::ThreadRead,
                "thread/resume" => ReadinessMethod::ThreadResume,
                _ => return Ok(()),
            };
            let id = object
                .get("id")
                .filter(|id| valid_request_id(id))
                .cloned()
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            let params = object
                .get("params")
                .and_then(Value::as_object)
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            let thread_id = params
                .get("threadId")
                .and_then(Value::as_str)
                .filter(|thread_id| valid_thread_id(thread_id))
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            let include_turns = match params.get("includeTurns") {
                Some(value) => Some(value.as_bool().ok_or(ReadinessProxyError::InvalidMessage)?),
                None => None,
            };
            if method == ReadinessMethod::ThreadResume && !resume_uses_thread_id(params) {
                return Err(ReadinessProxyError::InvalidMessage);
            }
            events.push(ObservedEvent::Request {
                id,
                method,
                thread_id: thread_id.to_owned(),
                include_turns,
            });
        }
        Direction::ServerToClient => {
            if let Some(method) = object.get("method") {
                let method = method
                    .as_str()
                    .filter(|method| valid_bounded_text(method, MAX_METHOD_BYTES))
                    .ok_or(ReadinessProxyError::InvalidMessage)?;
                if object.contains_key("result") || object.contains_key("error") {
                    return Err(ReadinessProxyError::InvalidMessage);
                }
                match object.get("id") {
                    Some(id) if valid_request_id(id) => {
                        events.push(ObservedEvent::ProviderRequest {
                            id: id.clone(),
                            method: method.to_owned(),
                        });
                    }
                    Some(_) => return Err(ReadinessProxyError::InvalidMessage),
                    None => events.push(ObservedEvent::ProviderNotification {
                        method: method.to_owned(),
                    }),
                }
                return Ok(());
            }
            let id = object
                .get("id")
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            if !valid_request_id(id) {
                return Err(ReadinessProxyError::InvalidMessage);
            }
            let has_result = object.contains_key("result");
            let has_error = match object.get("error") {
                Some(error) => {
                    validate_jsonrpc_error_body(error)?;
                    true
                }
                None => false,
            };
            if has_result == has_error {
                return Err(ReadinessProxyError::InvalidMessage);
            }
            let (thread_id, forked_from_id) =
                match object.get("result").and_then(|result| result.get("thread")) {
                    Some(thread) => {
                        let thread = thread
                            .as_object()
                            .ok_or(ReadinessProxyError::InvalidMessage)?;
                        let thread_id = thread
                            .get("id")
                            .and_then(Value::as_str)
                            .filter(|thread_id| valid_thread_id(thread_id))
                            .ok_or(ReadinessProxyError::InvalidMessage)?
                            .to_owned();
                        let forked_from_id = match thread.get("forkedFromId") {
                            None | Some(Value::Null) => None,
                            Some(value) => Some(
                                value
                                    .as_str()
                                    .filter(|parent| {
                                        valid_thread_id(parent) && *parent != thread_id.as_str()
                                    })
                                    .ok_or(ReadinessProxyError::InvalidMessage)?
                                    .to_owned(),
                            ),
                        };
                        (Some(thread_id), forked_from_id)
                    }
                    None => (None, None),
                };
            let settings = match object.get("result") {
                Some(result) if thread_id.is_some() => parse_thread_settings(result)?,
                None => None,
                Some(_) => None,
            };
            events.push(ObservedEvent::Response {
                id: id.clone(),
                has_error,
                thread_id,
                forked_from_id,
                settings,
            });
        }
    }
    Ok(())
}

fn resume_uses_thread_id(params: &serde_json::Map<String, Value>) -> bool {
    let history_is_absent = matches!(params.get("history"), None | Some(Value::Null));
    let path_is_absent = matches!(params.get("path"), None | Some(Value::Null))
        || params.get("path").and_then(Value::as_str) == Some("");
    history_is_absent && path_is_absent
}

fn validate_jsonrpc_error_body(error: &Value) -> Result<(), ReadinessProxyError> {
    let error = error
        .as_object()
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    if error.get("code").and_then(Value::as_i64).is_none()
        || error.get("message").and_then(Value::as_str).is_none()
    {
        return Err(ReadinessProxyError::InvalidMessage);
    }
    Ok(())
}

fn parse_thread_settings(
    result: &Value,
) -> Result<Option<EffectiveThreadSettings>, ReadinessProxyError> {
    let Some(result) = result.as_object() else {
        return Ok(None);
    };
    let setting_names = [
        "cwd",
        "model",
        "modelProvider",
        "approvalPolicy",
        "approvalsReviewer",
        "sandbox",
    ];
    if setting_names.iter().all(|name| !result.contains_key(*name)) {
        return Ok(None);
    }
    if setting_names.iter().any(|name| !result.contains_key(*name)) {
        return Err(ReadinessProxyError::InvalidMessage);
    }
    let sandbox = result
        .get("sandbox")
        .and_then(Value::as_object)
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    let cwd = bounded_text(result.get("cwd"), MAX_CWD_BYTES)
        .filter(|cwd| valid_absolute_cwd(cwd))
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    let approval_policy = parse_approval_policy(
        result
            .get("approvalPolicy")
            .ok_or(ReadinessProxyError::InvalidMessage)?,
    )?;
    let approvals_reviewer =
        match bounded_text(result.get("approvalsReviewer"), MAX_REVIEWER_BYTES).as_deref() {
            Some("user") => EffectiveApprovalsReviewer::User,
            Some("auto_review" | "guardian_subagent") => EffectiveApprovalsReviewer::AutoReview,
            _ => return Err(ReadinessProxyError::InvalidMessage),
        };
    let (sandbox_type, sandbox_network_access) = parse_sandbox_settings(sandbox)?;
    Ok(Some(EffectiveThreadSettings {
        cwd,
        model: bounded_text(result.get("model"), MAX_MODEL_BYTES)
            .ok_or(ReadinessProxyError::InvalidMessage)?,
        model_provider: bounded_text(result.get("modelProvider"), MAX_MODEL_PROVIDER_BYTES)
            .ok_or(ReadinessProxyError::InvalidMessage)?,
        approval_policy,
        approvals_reviewer,
        sandbox_type,
        sandbox_network_access,
    }))
}

fn parse_approval_policy(value: &Value) -> Result<EffectiveApprovalPolicy, ReadinessProxyError> {
    if let Some(policy) = value.as_str() {
        if !valid_bounded_text(policy, MAX_POLICY_BYTES) {
            return Err(ReadinessProxyError::InvalidMessage);
        }
        return match policy {
            "untrusted" => Ok(EffectiveApprovalPolicy::Untrusted),
            "on-request" => Ok(EffectiveApprovalPolicy::OnRequest),
            "never" => Ok(EffectiveApprovalPolicy::Never),
            _ => Err(ReadinessProxyError::InvalidMessage),
        };
    }

    let outer = value
        .as_object()
        .filter(|outer| has_exact_keys(outer, &["granular"]))
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    let granular = outer
        .get("granular")
        .and_then(Value::as_object)
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    let allowed = [
        "sandbox_approval",
        "rules",
        "skill_approval",
        "request_permissions",
        "mcp_elicitations",
    ];
    let required = ["sandbox_approval", "rules", "mcp_elicitations"];
    if granular.len() > allowed.len()
        || granular.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !granular.contains_key(*key))
    {
        return Err(ReadinessProxyError::InvalidMessage);
    }
    let required_bool = |name: &str| {
        granular
            .get(name)
            .and_then(Value::as_bool)
            .ok_or(ReadinessProxyError::InvalidMessage)
    };
    let optional_bool = |name: &str| match granular.get(name) {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or(ReadinessProxyError::InvalidMessage),
    };
    Ok(EffectiveApprovalPolicy::Granular {
        sandbox_approval: required_bool("sandbox_approval")?,
        rules: required_bool("rules")?,
        skill_approval: optional_bool("skill_approval")?,
        request_permissions: optional_bool("request_permissions")?,
        mcp_elicitations: required_bool("mcp_elicitations")?,
    })
}

fn parse_sandbox_settings(
    sandbox: &serde_json::Map<String, Value>,
) -> Result<(EffectiveSandboxType, EffectiveNetworkAccess), ReadinessProxyError> {
    let sandbox_type = bounded_text(sandbox.get("type"), MAX_SANDBOX_TYPE_BYTES)
        .ok_or(ReadinessProxyError::InvalidMessage)?;
    match sandbox_type.as_str() {
        "dangerFullAccess" if has_exact_keys(sandbox, &["type"]) => Ok((
            EffectiveSandboxType::DangerFullAccess,
            EffectiveNetworkAccess::Unspecified,
        )),
        "readOnly" if has_exact_keys(sandbox, &["type", "networkAccess"]) => Ok((
            EffectiveSandboxType::ReadOnly,
            bool_network_access(sandbox.get("networkAccess"))?,
        )),
        "externalSandbox" if has_exact_keys(sandbox, &["type", "networkAccess"]) => {
            let network_access =
                match bounded_text(sandbox.get("networkAccess"), MAX_POLICY_BYTES).as_deref() {
                    Some("restricted") => EffectiveNetworkAccess::Restricted,
                    Some("enabled") => EffectiveNetworkAccess::Enabled,
                    _ => return Err(ReadinessProxyError::InvalidMessage),
                };
            Ok((EffectiveSandboxType::ExternalSandbox, network_access))
        }
        "workspaceWrite"
            if has_exact_keys(
                sandbox,
                &[
                    "type",
                    "writableRoots",
                    "networkAccess",
                    "excludeTmpdirEnvVar",
                    "excludeSlashTmp",
                ],
            ) =>
        {
            let writable_roots = sandbox
                .get("writableRoots")
                .and_then(Value::as_array)
                .filter(|roots| roots.len() <= MAX_WRITABLE_ROOTS)
                .ok_or(ReadinessProxyError::InvalidMessage)?;
            if writable_roots
                .iter()
                .any(|root| root.as_str().is_none_or(|root| !valid_absolute_cwd(root)))
                || sandbox
                    .get("excludeTmpdirEnvVar")
                    .and_then(Value::as_bool)
                    .is_none()
                || sandbox
                    .get("excludeSlashTmp")
                    .and_then(Value::as_bool)
                    .is_none()
            {
                return Err(ReadinessProxyError::InvalidMessage);
            }
            Ok((
                EffectiveSandboxType::WorkspaceWrite,
                bool_network_access(sandbox.get("networkAccess"))?,
            ))
        }
        _ => Err(ReadinessProxyError::InvalidMessage),
    }
}

fn has_exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn bool_network_access(
    value: Option<&Value>,
) -> Result<EffectiveNetworkAccess, ReadinessProxyError> {
    match value.and_then(Value::as_bool) {
        Some(false) => Ok(EffectiveNetworkAccess::Restricted),
        Some(true) => Ok(EffectiveNetworkAccess::Enabled),
        None => Err(ReadinessProxyError::InvalidMessage),
    }
}

fn valid_request_id(id: &Value) -> bool {
    id.as_str()
        .is_some_and(|id| valid_bounded_text(id, MAX_REQUEST_ID_BYTES))
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}

fn bounded_text(value: Option<&Value>, max_bytes: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| valid_bounded_text(value, max_bytes))
        .map(str::to_owned)
}

fn valid_bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_absolute_cwd(value: &str) -> bool {
    valid_bounded_text(value, MAX_CWD_BYTES)
        && Path::new(value).is_absolute()
        && Path::new(value).components().all(|component| {
            !matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn valid_thread_id(value: &str) -> bool {
    if !valid_bounded_text(value, MAX_THREAD_ID_BYTES) {
        return false;
    }
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

enum ReadinessPhase {
    AwaitReadRequest,
    AwaitReadResponse(Value),
    AwaitResumeRequest,
    AwaitResumeResponse(Value),
    AwaitPostResumeReadRequest {
        parent_thread_id: String,
        require_error: bool,
    },
    AwaitPostResumeReadResponse {
        id: Value,
        parent_thread_id: String,
        require_error: bool,
    },
    Ready,
}

struct ReadinessState {
    expectation: ReadinessExpectation,
    client_handshake: bool,
    server_handshake: bool,
    phase: ReadinessPhase,
    effective_settings: Option<EffectiveThreadSettings>,
}

impl ReadinessState {
    fn new(expectation: ReadinessExpectation) -> Self {
        Self {
            expectation,
            client_handshake: false,
            server_handshake: false,
            phase: ReadinessPhase::AwaitReadRequest,
            effective_settings: None,
        }
    }

    #[cfg(test)]
    fn new_exact(thread_id: &str, cwd: &Path) -> Result<Self, ReadinessProxyError> {
        ReadinessExpectation::exact_resume(thread_id, cwd).map(Self::new)
    }

    fn effective_settings(&self) -> Option<&EffectiveThreadSettings> {
        self.effective_settings.as_ref()
    }

    fn observe(&mut self, event: ObservedEvent) -> Result<bool, ReadinessProxyError> {
        match event {
            ObservedEvent::Handshake(Direction::ClientToServer) if !self.client_handshake => {
                self.client_handshake = true;
                Ok(false)
            }
            ObservedEvent::Handshake(Direction::ServerToClient)
                if self.client_handshake && !self.server_handshake =>
            {
                self.server_handshake = true;
                Ok(false)
            }
            ObservedEvent::Handshake(_) => Err(ReadinessProxyError::UnexpectedSequence),
            ObservedEvent::Request {
                id,
                method,
                thread_id,
                include_turns,
            } => {
                if !self.server_handshake {
                    return Err(ReadinessProxyError::UnexpectedSequence);
                }
                match (&self.phase, method) {
                    (ReadinessPhase::AwaitReadRequest, ReadinessMethod::ThreadRead) => {
                        if thread_id != self.expectation.thread_id {
                            return Err(ReadinessProxyError::TargetMismatch);
                        }
                        let include_turns_is_valid = match &self.expectation.policy {
                            // Preserve the #28 synthetic compatibility gate's
                            // pre-extraction behavior for its initial read.
                            ReadinessPolicy::SyntheticFork { .. } => true,
                            ReadinessPolicy::ExactResume { .. } => include_turns != Some(true),
                        };
                        if !include_turns_is_valid {
                            return Err(ReadinessProxyError::UnexpectedSequence);
                        }
                        self.phase = ReadinessPhase::AwaitReadResponse(id);
                        Ok(false)
                    }
                    (ReadinessPhase::AwaitResumeRequest, ReadinessMethod::ThreadResume) => {
                        if thread_id != self.expectation.thread_id {
                            return Err(ReadinessProxyError::TargetMismatch);
                        }
                        self.phase = ReadinessPhase::AwaitResumeResponse(id);
                        Ok(false)
                    }
                    (
                        ReadinessPhase::AwaitPostResumeReadRequest {
                            parent_thread_id,
                            require_error,
                        },
                        ReadinessMethod::ThreadRead,
                    ) => {
                        let include_turns_is_valid = match &self.expectation.policy {
                            ReadinessPolicy::SyntheticFork { .. } => include_turns.is_none(),
                            ReadinessPolicy::ExactResume { .. } => include_turns != Some(true),
                        };
                        if thread_id != *parent_thread_id || !include_turns_is_valid {
                            return Err(ReadinessProxyError::TargetMismatch);
                        }
                        self.phase = ReadinessPhase::AwaitPostResumeReadResponse {
                            id,
                            parent_thread_id: parent_thread_id.clone(),
                            require_error: *require_error,
                        };
                        Ok(false)
                    }
                    _ => Err(ReadinessProxyError::UnexpectedSequence),
                }
            }
            ObservedEvent::Response {
                id,
                has_error,
                thread_id,
                forked_from_id,
                settings,
            } => match &self.phase {
                ReadinessPhase::AwaitReadResponse(expected_id) if id == *expected_id => {
                    validate_target_response(
                        has_error,
                        thread_id.as_deref(),
                        &self.expectation.thread_id,
                    )?;
                    self.phase = ReadinessPhase::AwaitResumeRequest;
                    Ok(false)
                }
                ReadinessPhase::AwaitResumeResponse(expected_id) if id == *expected_id => {
                    validate_target_response(
                        has_error,
                        thread_id.as_deref(),
                        &self.expectation.thread_id,
                    )?;
                    let settings = validate_resume_settings(settings, &self.expectation)?;
                    self.effective_settings = Some(settings);
                    let parent = match &self.expectation.policy {
                        ReadinessPolicy::SyntheticFork {
                            source_thread_id, ..
                        } => {
                            if forked_from_id.as_deref() != Some(source_thread_id) {
                                return Err(ReadinessProxyError::TargetMismatch);
                            }
                            Some((source_thread_id.clone(), true))
                        }
                        ReadinessPolicy::ExactResume { .. } => {
                            forked_from_id.map(|parent| (parent, false))
                        }
                    };
                    match parent {
                        Some((parent_thread_id, require_error)) => {
                            self.phase = ReadinessPhase::AwaitPostResumeReadRequest {
                                parent_thread_id,
                                require_error,
                            };
                            Ok(false)
                        }
                        None => {
                            self.phase = ReadinessPhase::Ready;
                            Ok(true)
                        }
                    }
                }
                ReadinessPhase::AwaitPostResumeReadResponse {
                    id: expected_id,
                    parent_thread_id,
                    require_error,
                } if id == *expected_id => {
                    if has_error {
                        if thread_id.is_some() || forked_from_id.is_some() || settings.is_some() {
                            return Err(ReadinessProxyError::InvalidMessage);
                        }
                    } else {
                        if *require_error || settings.is_some() {
                            return Err(ReadinessProxyError::InvalidMessage);
                        }
                        validate_target_response(false, thread_id.as_deref(), parent_thread_id)?;
                    }
                    self.phase = ReadinessPhase::Ready;
                    Ok(true)
                }
                _ => {
                    if response_carries_readiness_evidence(
                        &self.phase,
                        &self.expectation,
                        thread_id.as_deref(),
                        forked_from_id.as_deref(),
                        settings.as_ref(),
                    ) {
                        return Err(ReadinessProxyError::UnexpectedSequence);
                    }
                    Ok(matches!(self.phase, ReadinessPhase::Ready))
                }
            },
            ObservedEvent::ProviderRequest { .. } | ObservedEvent::ProviderNotification { .. }
                if self.server_handshake =>
            {
                // These bytes have already been forwarded to the official TUI.
                // Observation must neither advance readiness nor manufacture a
                // JSON-RPC response on Calcifer's behalf.
                Ok(matches!(self.phase, ReadinessPhase::Ready))
            }
            ObservedEvent::ProviderRequest { .. } | ObservedEvent::ProviderNotification { .. } => {
                Err(ReadinessProxyError::UnexpectedSequence)
            }
        }
    }
}

fn response_carries_readiness_evidence(
    phase: &ReadinessPhase,
    expectation: &ReadinessExpectation,
    thread_id: Option<&str>,
    forked_from_id: Option<&str>,
    settings: Option<&EffectiveThreadSettings>,
) -> bool {
    if matches!(phase, ReadinessPhase::Ready) {
        return false;
    }
    if settings.is_some()
        || forked_from_id.is_some()
        || thread_id == Some(expectation.thread_id.as_str())
    {
        return true;
    }
    match phase {
        ReadinessPhase::AwaitPostResumeReadRequest {
            parent_thread_id, ..
        }
        | ReadinessPhase::AwaitPostResumeReadResponse {
            parent_thread_id, ..
        } => thread_id == Some(parent_thread_id.as_str()),
        _ => false,
    }
}

fn validate_resume_settings(
    actual: Option<EffectiveThreadSettings>,
    expected: &ReadinessExpectation,
) -> Result<EffectiveThreadSettings, ReadinessProxyError> {
    let Some(actual) = actual else {
        return Err(ReadinessProxyError::InvalidMessage);
    };
    let matches = match &expected.policy {
        ReadinessPolicy::SyntheticFork {
            expected_settings, ..
        } => actual == *expected_settings,
        ReadinessPolicy::ExactResume { expected_cwd } => actual.cwd == *expected_cwd,
    };
    if !matches {
        return Err(ReadinessProxyError::TargetMismatch);
    }
    Ok(actual)
}

fn validate_target_response(
    has_error: bool,
    actual_thread_id: Option<&str>,
    expected_thread_id: &str,
) -> Result<(), ReadinessProxyError> {
    if has_error {
        return Err(ReadinessProxyError::InvalidMessage);
    }
    match actual_thread_id {
        Some(actual) if actual == expected_thread_id => Ok(()),
        Some(_) => Err(ReadinessProxyError::TargetMismatch),
        None => Err(ReadinessProxyError::InvalidMessage),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    const TARGET_THREAD_ID: &str = "019f64a7-c5d1-7ed1-aca8-156bc32b650c";
    const SOURCE_THREAD_ID: &str = "019f64a7-c5d1-7ed1-aca8-156bc32b650b";
    const TARGET_CWD: &str = "/synthetic/workspace";
    const TARGET_MODEL: &str = "calcifer-handoff-smoke";
    const TARGET_MODEL_PROVIDER: &str = "calcifer_smoke";

    #[test]
    fn transport_origin_catalog_has_unique_fixed_payload_free_labels() {
        let labels = ReadinessTransportOrigin::ALL
            .into_iter()
            .enumerate()
            .map(|(index, origin)| {
                let label = origin.fixed_label();
                let code = u8::try_from(index + 1).unwrap_or(u8::MAX);
                assert_eq!(origin as u8, code);
                assert_eq!(ReadinessTransportOrigin::from_code(code), Some(origin));
                assert!(!label.is_empty());
                assert!(
                    label
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                );
                assert!(matches!(
                    ReadinessProxyError::Transport(origin),
                    ReadinessProxyError::Transport(projected) if projected == origin
                ));
                assert_eq!(
                    ReadinessProxyError::Transport(origin).to_string(),
                    "the readiness proxy transport failed"
                );
                label
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(labels.len(), ReadinessTransportOrigin::ALL.len());
        assert_eq!(ReadinessTransportOrigin::from_code(0), None);
        assert_eq!(
            ReadinessTransportOrigin::from_code(
                u8::try_from(ReadinessTransportOrigin::ALL.len() + 1).unwrap_or(u8::MAX)
            ),
            None
        );
    }

    #[test]
    fn concurrent_transport_failures_preserve_one_first_origin() -> Result<(), Box<dyn Error>> {
        let tracker = Arc::new(ReadinessTransportTracker::new());
        let barrier = Arc::new(Barrier::new(ReadinessTransportOrigin::ALL.len()));
        let workers = ReadinessTransportOrigin::ALL
            .into_iter()
            .map(|origin| {
                let tracker = Arc::clone(&tracker);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    tracker.record(origin)
                })
            })
            .collect::<Vec<_>>();
        let recorded = workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "transport recorder panicked"))
            .collect::<Result<Vec<_>, _>>()?;
        let first = tracker
            .first()
            .ok_or("concurrent transport failures did not record an origin")?;

        assert!(recorded.into_iter().all(|origin| origin == first));
        for origin in ReadinessTransportOrigin::ALL {
            assert_eq!(tracker.record(origin), first);
        }
        Ok(())
    }

    #[test]
    fn failure_selection_gate_preserves_the_first_transport_semantic_or_stop_winner() {
        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        let transport = ReadinessTransportTracker::new();
        let first = transport
            .disconnect(&lifecycle, ReadinessTransportOrigin::ClientEof)
            .unwrap_or(ReadinessProxyError::UnexpectedSequence);
        assert_eq!(
            first,
            ReadinessProxyError::Transport(ReadinessTransportOrigin::ClientEof)
        );
        assert_eq!(
            transport.select_failure(ReadinessProxyError::InvalidMessage),
            ProxyRunError::Failed(first)
        );

        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        let transport = ReadinessTransportTracker::new();
        let semantic = transport
            .fail_while_running(&lifecycle, ReadinessProxyError::InvalidMessage)
            .unwrap_or(ReadinessProxyError::UnexpectedSequence);
        assert_eq!(semantic, ReadinessProxyError::InvalidMessage);
        assert_eq!(transport.first(), None);
        assert_eq!(lifecycle.load(Ordering::Acquire), RELAY_DISCONNECTED);
        assert_eq!(
            transport.disconnect(&lifecycle, ReadinessTransportOrigin::UpstreamEof),
            None
        );
        assert_eq!(
            transport.select_failure(semantic),
            ProxyRunError::Failed(semantic)
        );
        assert_eq!(transport.first(), None);

        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        let transport = ReadinessTransportTracker::new();
        let timeout = transport.select_failure(ReadinessProxyError::Timeout);
        assert_eq!(timeout, ProxyRunError::Failed(ReadinessProxyError::Timeout));
        assert_eq!(
            transport.disconnect(&lifecycle, ReadinessTransportOrigin::ClientWrite),
            None
        );
        assert_eq!(transport.first(), None);

        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        let transport = ReadinessTransportTracker::new();
        assert_eq!(transport.stop(&lifecycle), RELAY_RUNNING);
        assert_eq!(
            transport.disconnect(&lifecycle, ReadinessTransportOrigin::WorkerFinished),
            None
        );
        assert_eq!(transport.first(), None);
        assert_eq!(lifecycle.load(Ordering::Acquire), RELAY_STOPPING);
    }

    #[test]
    fn stopped_selection_rejects_late_worker_failures_without_recording_an_origin() {
        let failures = [
            ReadinessProxyError::Timeout,
            ReadinessProxyError::InvalidMessage,
            ReadinessProxyError::Transport(ReadinessTransportOrigin::ClientRead),
        ];

        for failure in failures {
            let lifecycle = AtomicU8::new(RELAY_RUNNING);
            let transport = ReadinessTransportTracker::new();
            assert_eq!(transport.stop(&lifecycle), RELAY_RUNNING);

            assert_eq!(transport.select_failure(failure), ProxyRunError::Stopped);
            assert_eq!(
                select_run_error(&transport, ProxyRunError::Failed(failure)),
                ProxyRunError::Stopped
            );
            assert_eq!(transport.first(), None);
            assert_eq!(lifecycle.load(Ordering::Acquire), RELAY_STOPPING);
        }
    }

    #[test]
    fn stop_between_running_read_and_failure_selection_joins_cleanly() -> Result<(), Box<dyn Error>>
    {
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let transport = Arc::new(ReadinessTransportTracker::new());
        let (running_read_sender, running_read_receiver) = mpsc::sync_channel(0);
        let (release_selection_sender, release_selection_receiver) = mpsc::sync_channel(0);
        let worker_lifecycle = Arc::clone(&lifecycle);
        let worker_transport = Arc::clone(&transport);
        let worker = thread::spawn(move || {
            let observed = worker_lifecycle.load(Ordering::Acquire);
            running_read_sender
                .send(observed)
                .map_err(|_| "running-read receiver disappeared")?;
            release_selection_receiver
                .recv()
                .map_err(|_| "selection-release sender disappeared")?;
            let result = worker_transport.select_failure(ReadinessProxyError::Timeout);
            Ok::<_, &'static str>(finalize_proxy_run(Err(result)))
        });

        assert_eq!(running_read_receiver.recv()?, RELAY_RUNNING);
        assert_eq!(transport.stop(&lifecycle), RELAY_RUNNING);
        release_selection_sender.send(())?;

        assert_eq!(
            worker
                .join()
                .map_err(|_| "failure-selection worker panicked")??,
            Ok(())
        );
        assert_eq!(transport.first(), None);
        assert_eq!(lifecycle.load(Ordering::Acquire), RELAY_STOPPING);
        Ok(())
    }

    #[test]
    fn readiness_publication_gate_orders_success_and_transport_failure_without_sleep()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let transport = Arc::new(ReadinessTransportTracker::new());
        let (publication_entered_sender, publication_entered_receiver) = mpsc::sync_channel(0);
        let (release_publication_sender, release_publication_receiver) = mpsc::sync_channel(0);
        let publisher_lifecycle = Arc::clone(&lifecycle);
        let publisher_transport = Arc::clone(&transport);
        let publisher = thread::spawn(move || {
            publisher_transport.publish_readiness(&publisher_lifecycle, || {
                publication_entered_sender
                    .send(())
                    .map_err(|_| ReadinessProxyError::Worker)?;
                release_publication_receiver
                    .recv()
                    .map_err(|_| ReadinessProxyError::Worker)
            })
        });
        publication_entered_receiver.recv()?;

        let failure_lifecycle = Arc::clone(&lifecycle);
        let failure_transport = Arc::clone(&transport);
        let (failure_started_sender, failure_started_receiver) = mpsc::sync_channel(0);
        let failure = thread::spawn(move || {
            failure_started_sender
                .send(())
                .map_err(|_| "failure-start receiver disappeared")?;
            Ok::<_, &'static str>(
                failure_transport
                    .disconnect(&failure_lifecycle, ReadinessTransportOrigin::UpstreamEof),
            )
        });
        failure_started_receiver.recv()?;
        release_publication_sender.send(())?;

        assert!(
            publisher
                .join()
                .map_err(|_| "readiness publisher panicked")?
                .is_ok()
        );
        assert_eq!(
            failure
                .join()
                .map_err(|_| "transport failure worker panicked")??,
            Some(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::UpstreamEof
            ))
        );

        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        let transport = ReadinessTransportTracker::new();
        let expected = transport
            .disconnect(&lifecycle, ReadinessTransportOrigin::ClientEof)
            .unwrap_or(ReadinessProxyError::UnexpectedSequence);
        let mut published = false;
        assert!(matches!(
            transport.publish_readiness(&lifecycle, || {
                published = true;
                Ok(())
            }),
            Err(ProxyRunError::Failed(error)) if error == expected
        ));
        assert!(!published);
        Ok(())
    }

    #[test]
    fn pump_eof_and_write_failures_preserve_exact_endpoint_origins() -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                Direction::ClientToServer,
                ReadinessTransportOrigin::ClientEof,
                ReadinessTransportOrigin::UpstreamWrite,
            ),
            (
                Direction::ServerToClient,
                ReadinessTransportOrigin::UpstreamEof,
                ReadinessTransportOrigin::ClientWrite,
            ),
        ];

        for (direction, eof_origin, write_origin) in cases {
            let (reader, reader_peer) = UnixStream::pair()?;
            let (writer, _writer_peer) = UnixStream::pair()?;
            let (sender, receiver) = mpsc::sync_channel(1);
            let inspecting = AtomicBool::new(false);
            let observation_order = Mutex::new(());
            let control = RelayControl {
                lifecycle: Arc::new(AtomicU8::new(RELAY_RUNNING)),
                transport: Arc::new(ReadinessTransportTracker::new()),
            };
            drop(reader_peer);

            pump(
                reader,
                writer,
                direction,
                &inspecting,
                &sender,
                &observation_order,
                &control,
            );
            assert!(matches!(
                receiver.recv()?,
                PumpEvent::Ended(ReadinessProxyError::Transport(origin)) if origin == eof_origin
            ));
            assert_eq!(control.transport.first(), Some(eof_origin));
            assert_eq!(
                control.lifecycle.load(Ordering::Acquire),
                RELAY_DISCONNECTED
            );

            let (reader, mut reader_peer) = UnixStream::pair()?;
            let (writer, writer_peer) = UnixStream::pair()?;
            let (sender, receiver) = mpsc::sync_channel(1);
            let control = RelayControl {
                lifecycle: Arc::new(AtomicU8::new(RELAY_RUNNING)),
                transport: Arc::new(ReadinessTransportTracker::new()),
            };
            drop(writer_peer);
            reader_peer.write_all(b"force exact writer failure")?;

            pump(
                reader,
                writer,
                direction,
                &inspecting,
                &sender,
                &observation_order,
                &control,
            );
            assert!(matches!(
                receiver.recv()?,
                PumpEvent::Failed(ReadinessProxyError::Transport(origin)) if origin == write_origin
            ));
            assert_eq!(control.transport.first(), Some(write_origin));
            assert_eq!(
                control.lifecycle.load(Ordering::Acquire),
                RELAY_DISCONNECTED
            );
        }
        Ok(())
    }

    #[test]
    fn pump_records_observation_delivery_when_its_receiver_is_gone() -> Result<(), Box<dyn Error>> {
        let (reader, mut reader_peer) = UnixStream::pair()?;
        let (writer, mut writer_peer) = UnixStream::pair()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let inspecting = AtomicBool::new(true);
        let observation_order = Mutex::new(());
        let control = RelayControl {
            lifecycle: Arc::new(AtomicU8::new(RELAY_RUNNING)),
            transport: Arc::new(ReadinessTransportTracker::new()),
        };
        drop(receiver);
        reader_peer.write_all(&websocket_request())?;

        pump(
            reader,
            writer,
            Direction::ClientToServer,
            &inspecting,
            &sender,
            &observation_order,
            &control,
        );
        let mut forwarded = vec![0_u8; websocket_request().len()];
        writer_peer.read_exact(&mut forwarded)?;
        assert_eq!(forwarded, websocket_request());
        assert_eq!(
            control.transport.first(),
            Some(ReadinessTransportOrigin::ObservationDelivery)
        );
        assert_eq!(
            control.lifecycle.load(Ordering::Acquire),
            RELAY_DISCONNECTED
        );
        Ok(())
    }

    #[test]
    fn racing_copy_pump_eofs_publish_the_same_first_origin() -> Result<(), Box<dyn Error>> {
        let (client_reader, client_peer) = UnixStream::pair()?;
        let (client_writer, _client_writer_peer) = UnixStream::pair()?;
        let (upstream_reader, upstream_peer) = UnixStream::pair()?;
        let (upstream_writer, _upstream_writer_peer) = UnixStream::pair()?;
        drop(client_peer);
        drop(upstream_peer);

        let (sender, receiver) = mpsc::sync_channel(2);
        let inspecting = Arc::new(AtomicBool::new(false));
        let observation_order = Arc::new(Mutex::new(()));
        let control = RelayControl {
            lifecycle: Arc::new(AtomicU8::new(RELAY_RUNNING)),
            transport: Arc::new(ReadinessTransportTracker::new()),
        };
        let barrier = Arc::new(Barrier::new(3));
        let pumps = [
            (client_reader, upstream_writer, Direction::ClientToServer),
            (upstream_reader, client_writer, Direction::ServerToClient),
        ]
        .into_iter()
        .map(|(reader, writer, direction)| {
            let sender = sender.clone();
            let inspecting = Arc::clone(&inspecting);
            let observation_order = Arc::clone(&observation_order);
            let control = control.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                pump(
                    reader,
                    writer,
                    direction,
                    &inspecting,
                    &sender,
                    &observation_order,
                    &control,
                );
            })
        })
        .collect::<Vec<_>>();
        drop(sender);
        barrier.wait();

        for pump in pumps {
            pump.join().map_err(|_| "copy pump panicked")?;
        }
        let events = receiver.try_iter().collect::<Vec<_>>();
        let [PumpEvent::Ended(ReadinessProxyError::Transport(origin))] = events.as_slice() else {
            return Err("racing copy pumps did not publish exactly one EOF winner".into());
        };
        let first = control
            .transport
            .first()
            .ok_or("racing copy pumps did not record an origin")?;
        assert!(matches!(
            first,
            ReadinessTransportOrigin::ClientEof | ReadinessTransportOrigin::UpstreamEof
        ));
        assert_eq!(*origin, first);
        Ok(())
    }

    #[test]
    fn intentional_stop_wakeup_never_records_eof_or_write_origins() -> Result<(), Box<dyn Error>> {
        let (reader, reader_peer) = UnixStream::pair()?;
        let (writer, _writer_peer) = UnixStream::pair()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let inspecting = AtomicBool::new(false);
        let observation_order = Mutex::new(());
        let control = RelayControl {
            lifecycle: Arc::new(AtomicU8::new(RELAY_RUNNING)),
            transport: Arc::new(ReadinessTransportTracker::new()),
        };
        control.transport.stop(&control.lifecycle);
        drop(reader_peer);

        pump(
            reader,
            writer,
            Direction::ClientToServer,
            &inspecting,
            &sender,
            &observation_order,
            &control,
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(control.transport.first(), None);
        assert_eq!(control.lifecycle.load(Ordering::Acquire), RELAY_STOPPING);

        let (reader, mut reader_peer) = UnixStream::pair()?;
        let (writer, writer_peer) = UnixStream::pair()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(writer_peer);
        reader_peer.write_all(b"shutdown write wakeup")?;
        pump(
            reader,
            writer,
            Direction::ServerToClient,
            &inspecting,
            &sender,
            &observation_order,
            &control,
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(control.transport.first(), None);
        assert_eq!(control.lifecycle.load(Ordering::Acquire), RELAY_STOPPING);
        Ok(())
    }

    fn expectation() -> ReadinessExpectation {
        ReadinessExpectation {
            thread_id: TARGET_THREAD_ID.to_owned(),
            policy: ReadinessPolicy::SyntheticFork {
                source_thread_id: SOURCE_THREAD_ID.to_owned(),
                expected_settings: observed_settings(),
            },
        }
    }

    fn observed_settings() -> EffectiveThreadSettings {
        EffectiveThreadSettings {
            cwd: TARGET_CWD.to_owned(),
            model: TARGET_MODEL.to_owned(),
            model_provider: TARGET_MODEL_PROVIDER.to_owned(),
            approval_policy: EffectiveApprovalPolicy::Never,
            approvals_reviewer: EffectiveApprovalsReviewer::User,
            sandbox_type: EffectiveSandboxType::ReadOnly,
            sandbox_network_access: EffectiveNetworkAccess::Restricted,
        }
    }

    fn resume_result() -> Value {
        json!({
            "thread": {
                "id": TARGET_THREAD_ID,
                "forkedFromId": SOURCE_THREAD_ID
            },
            "cwd": TARGET_CWD,
            "model": TARGET_MODEL,
            "modelProvider": TARGET_MODEL_PROVIDER,
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": { "type": "readOnly", "networkAccess": false }
        })
    }

    fn exact_resume_result() -> Value {
        let mut result = resume_result();
        result["thread"]["forkedFromId"] = Value::Null;
        result
    }

    fn spawn_test_proxy(
        socket_path: &Path,
        upstream_path: &Path,
        timeout: Duration,
    ) -> Result<ReadinessProxy, ReadinessProxyError> {
        ReadinessProxy::spawn(
            socket_path,
            upstream_path,
            ReadinessProbe::new(
                TARGET_THREAD_ID,
                SOURCE_THREAD_ID,
                Path::new(TARGET_CWD),
                TARGET_MODEL,
                TARGET_MODEL_PROVIDER,
            ),
            timeout,
        )
    }

    fn spawn_exact_test_proxy(
        socket_path: &Path,
        upstream_path: &Path,
        timeout: Duration,
    ) -> Result<ReadinessProxy, ReadinessProxyError> {
        ReadinessProxy::spawn_exact(
            socket_path,
            upstream_path,
            ExactResumeProbe::new(TARGET_THREAD_ID, Path::new(TARGET_CWD)),
            timeout,
        )
    }

    fn shutdown_deadline() -> Result<Instant, ReadinessProxyError> {
        Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or(ReadinessProxyError::InvalidArgument)
    }

    fn state_awaiting_resume_response() -> ReadinessState {
        let mut state = ReadinessState::new(expectation());
        for event in [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
            ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            },
            ObservedEvent::Request {
                id: json!(2),
                method: ReadinessMethod::ThreadResume,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ] {
            assert_eq!(state.observe(event), Ok(false));
        }
        state
    }

    fn exact_state_awaiting_resume_response() -> Result<ReadinessState, ReadinessProxyError> {
        let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        for event in [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
            ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            },
            ObservedEvent::Request {
                id: json!(2),
                method: ReadinessMethod::ThreadResume,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ] {
            if state.observe(event)? {
                return Err(ReadinessProxyError::UnexpectedSequence);
            }
        }
        Ok(state)
    }

    #[test]
    fn exact_resume_readiness_captures_effective_settings_without_a_parent_lookup()
    -> Result<(), ReadinessProxyError> {
        let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        let events = [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: Some(false),
            },
            ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            },
            ObservedEvent::Request {
                id: json!(2),
                method: ReadinessMethod::ThreadResume,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ];

        for event in events {
            assert_eq!(state.observe(event), Ok(false));
        }
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(2),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: Some(observed_settings()),
            }),
            Ok(true)
        );
        assert_eq!(state.effective_settings(), Some(&observed_settings()));
        Ok(())
    }

    #[test]
    fn exact_resume_waits_for_the_pinned_parent_metadata_round_trip()
    -> Result<(), ReadinessProxyError> {
        for parent_succeeds in [true, false] {
            let mut state = exact_state_awaiting_resume_response()?;
            assert_eq!(
                state.observe(ObservedEvent::Response {
                    id: json!(2),
                    has_error: false,
                    thread_id: Some(TARGET_THREAD_ID.to_owned()),
                    forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                    settings: Some(observed_settings()),
                }),
                Ok(false)
            );
            assert_eq!(
                state.observe(ObservedEvent::Request {
                    id: json!(3),
                    method: ReadinessMethod::ThreadRead,
                    thread_id: SOURCE_THREAD_ID.to_owned(),
                    include_turns: None,
                }),
                Ok(false)
            );
            assert_eq!(
                state.observe(ObservedEvent::Response {
                    id: json!(3),
                    has_error: !parent_succeeds,
                    thread_id: parent_succeeds.then(|| SOURCE_THREAD_ID.to_owned()),
                    forked_from_id: None,
                    settings: None,
                }),
                Ok(true)
            );
        }
        Ok(())
    }

    #[test]
    fn exact_resume_rejects_the_wrong_or_non_metadata_parent_lookup()
    -> Result<(), ReadinessProxyError> {
        for (thread_id, include_turns) in [(TARGET_THREAD_ID, None), (SOURCE_THREAD_ID, Some(true))]
        {
            let mut state = exact_state_awaiting_resume_response()?;
            assert_eq!(
                state.observe(ObservedEvent::Response {
                    id: json!(2),
                    has_error: false,
                    thread_id: Some(TARGET_THREAD_ID.to_owned()),
                    forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                    settings: Some(observed_settings()),
                }),
                Ok(false)
            );
            assert_eq!(
                state.observe(ObservedEvent::Request {
                    id: json!(3),
                    method: ReadinessMethod::ThreadRead,
                    thread_id: thread_id.to_owned(),
                    include_turns,
                }),
                Err(ReadinessProxyError::TargetMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn exact_resume_accepts_false_or_omitted_metadata_only_read() -> Result<(), ReadinessProxyError>
    {
        for include_turns in [None, Some(false)] {
            let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
            assert_eq!(
                state.observe(ObservedEvent::Handshake(Direction::ClientToServer)),
                Ok(false)
            );
            assert_eq!(
                state.observe(ObservedEvent::Handshake(Direction::ServerToClient)),
                Ok(false)
            );
            assert_eq!(
                state.observe(ObservedEvent::Request {
                    id: json!(1),
                    method: ReadinessMethod::ThreadRead,
                    thread_id: TARGET_THREAD_ID.to_owned(),
                    include_turns,
                }),
                Ok(false)
            );
        }

        let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ClientToServer)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ServerToClient)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: Some(true),
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );
        Ok(())
    }

    #[test]
    fn synthetic_parent_lookup_requires_omitted_include_turns() {
        let mut state = state_awaiting_resume_response();
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(2),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                settings: Some(observed_settings()),
            }),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Request {
                id: json!(3),
                method: ReadinessMethod::ThreadRead,
                thread_id: SOURCE_THREAD_ID.to_owned(),
                include_turns: Some(false),
            }),
            Err(ReadinessProxyError::TargetMismatch)
        );
    }

    #[test]
    fn readiness_rejects_wrong_id_responses_that_carry_expected_evidence()
    -> Result<(), ReadinessProxyError> {
        let mut target_read = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        for event in [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ] {
            assert_eq!(target_read.observe(event), Ok(false));
        }
        assert_eq!(
            target_read.observe(ObservedEvent::Response {
                id: json!(99),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );

        let mut target_resume = exact_state_awaiting_resume_response()?;
        assert_eq!(
            target_resume.observe(ObservedEvent::Response {
                id: json!(99),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: Some(observed_settings()),
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );

        let mut parent_read = exact_state_awaiting_resume_response()?;
        assert_eq!(
            parent_read.observe(ObservedEvent::Response {
                id: json!(2),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                settings: Some(observed_settings()),
            }),
            Ok(false)
        );
        assert_eq!(
            parent_read.observe(ObservedEvent::Request {
                id: json!(3),
                method: ReadinessMethod::ThreadRead,
                thread_id: SOURCE_THREAD_ID.to_owned(),
                include_turns: None,
            }),
            Ok(false)
        );
        assert_eq!(
            parent_read.observe(ObservedEvent::Response {
                id: json!(99),
                has_error: false,
                thread_id: Some(SOURCE_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );
        Ok(())
    }

    #[test]
    fn readiness_ignores_unrelated_responses_without_readiness_evidence()
    -> Result<(), ReadinessProxyError> {
        let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        for event in [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ] {
            assert_eq!(state.observe(event), Ok(false));
        }
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(99),
                has_error: false,
                thread_id: None,
                forked_from_id: None,
                settings: None,
            }),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            }),
            Ok(false)
        );
        Ok(())
    }

    #[test]
    fn provider_requests_and_notifications_do_not_advance_readiness()
    -> Result<(), ReadinessProxyError> {
        let mut state = ReadinessState::new_exact(TARGET_THREAD_ID, Path::new(TARGET_CWD))?;
        assert_eq!(
            state.observe(ObservedEvent::ProviderNotification {
                method: "account/rateLimits/updated".to_owned(),
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ClientToServer)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ServerToClient)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::ProviderRequest {
                id: json!("approval-1"),
                method: "item/commandExecution/requestApproval".to_owned(),
            }),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::ProviderNotification {
                method: "account/rateLimits/updated".to_owned(),
            }),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: Some(false),
            }),
            Ok(false)
        );
        Ok(())
    }

    #[test]
    fn bounded_event_channel_applies_backpressure_and_preserves_order() -> Result<(), Box<dyn Error>>
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender.send(PumpEvent::Observed(Box::new(
            ObservedEvent::ProviderNotification {
                method: "first".to_owned(),
            },
        )))?;
        assert!(matches!(
            sender.try_send(PumpEvent::Observed(Box::new(
                ObservedEvent::ProviderNotification {
                    method: "second".to_owned(),
                },
            ))),
            Err(mpsc::TrySendError::Full(_))
        ));
        let producer = thread::spawn(move || {
            sender.send(PumpEvent::Observed(Box::new(
                ObservedEvent::ProviderNotification {
                    method: "second".to_owned(),
                },
            )))
        });
        assert!(matches!(
            receiver.recv()?,
            PumpEvent::Observed(event)
                if matches!(*event, ObservedEvent::ProviderNotification { ref method } if method == "first")
        ));
        producer
            .join()
            .map_err(|_| io::Error::other("bounded producer panicked"))??;
        assert!(matches!(
            receiver.recv()?,
            PumpEvent::Observed(event)
                if matches!(*event, ObservedEvent::ProviderNotification { ref method } if method == "second")
        ));
        Ok(())
    }

    #[test]
    fn parses_split_masked_fragmented_requests_with_interleaved_control_frames()
    -> Result<(), Box<dyn Error>> {
        let mut inspector = ProtocolInspector::new(Direction::ClientToServer);
        let handshake = websocket_request();
        let message = serde_json::to_vec(&json!({
            "id": 41,
            "method": "thread/read",
            "params": { "threadId": TARGET_THREAD_ID }
        }))?;
        let split = message.len() / 2;
        let mut wire = handshake.clone();
        wire.extend(masked_frame(false, 0x1, &message[..split]));
        wire.extend(masked_frame(true, 0x9, b"probe"));
        wire.extend(masked_frame(true, 0x0, &message[split..]));

        let mut events = Vec::new();
        for chunk in wire.chunks(3) {
            events.extend(inspector.feed(chunk)?);
        }

        assert_eq!(
            events,
            vec![
                ObservedEvent::Handshake(Direction::ClientToServer),
                ObservedEvent::Request {
                    id: json!(41),
                    method: ReadinessMethod::ThreadRead,
                    thread_id: TARGET_THREAD_ID.to_owned(),
                    include_turns: None,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn parses_split_unmasked_extended_length_responses() -> Result<(), Box<dyn Error>> {
        let mut inspector = ProtocolInspector::new(Direction::ServerToClient);
        let message = serde_json::to_vec(&json!({
            "id": "resume-request",
            "result": {
                "thread": { "id": TARGET_THREAD_ID },
                "padding": "x".repeat(180)
            }
        }))?;
        assert!(message.len() > 125);
        let mut wire = websocket_response();
        wire.extend(unmasked_frame(true, 0x1, &message));

        let mut events = Vec::new();
        for chunk in wire.chunks(7) {
            events.extend(inspector.feed(chunk)?);
        }

        assert_eq!(
            events,
            vec![
                ObservedEvent::Handshake(Direction::ServerToClient),
                ObservedEvent::Response {
                    id: json!("resume-request"),
                    has_error: false,
                    thread_id: Some(TARGET_THREAD_ID.to_owned()),
                    forked_from_id: None,
                    settings: None,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_security_sensitive_json_keys_at_every_depth() {
        let messages = [
            format!(
                r#"{{"id":1,"id":2,"method":"thread/read","params":{{"threadId":"{TARGET_THREAD_ID}"}}}}"#
            ),
            format!(
                r#"{{"id":1,"method":"thread/read","method":"thread/resume","params":{{"threadId":"{TARGET_THREAD_ID}"}}}}"#
            ),
            format!(
                r#"{{"id":1,"method":"thread/read","params":{{"threadId":"{TARGET_THREAD_ID}","threadId":"{SOURCE_THREAD_ID}"}}}}"#
            ),
            format!(
                r#"{{"id":1,"result":{{"thread":{{"id":"{TARGET_THREAD_ID}"}},"cwd":"{TARGET_CWD}","model":"{TARGET_MODEL}","modelProvider":"{TARGET_MODEL_PROVIDER}","approvalPolicy":"never","approvalsReviewer":"user","sandbox":{{"type":"readOnly","type":"dangerFullAccess","networkAccess":false}}}}}}"#
            ),
        ];

        for message in &messages[..3] {
            assert_eq!(
                inspect_message(
                    Direction::ClientToServer,
                    message.as_bytes(),
                    &mut Vec::new()
                ),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }
        assert_eq!(
            inspect_message(
                Direction::ServerToClient,
                messages[3].as_bytes(),
                &mut Vec::new(),
            ),
            Err(ReadinessProxyError::InvalidMessage)
        );
    }

    #[test]
    fn parses_all_pinned_sandbox_shapes_into_bounded_typed_evidence()
    -> Result<(), ReadinessProxyError> {
        let cases = [
            (
                json!({ "type": "dangerFullAccess" }),
                EffectiveSandboxType::DangerFullAccess,
                EffectiveNetworkAccess::Unspecified,
            ),
            (
                json!({ "type": "readOnly", "networkAccess": false }),
                EffectiveSandboxType::ReadOnly,
                EffectiveNetworkAccess::Restricted,
            ),
            (
                json!({ "type": "readOnly", "networkAccess": true }),
                EffectiveSandboxType::ReadOnly,
                EffectiveNetworkAccess::Enabled,
            ),
            (
                json!({ "type": "externalSandbox", "networkAccess": "restricted" }),
                EffectiveSandboxType::ExternalSandbox,
                EffectiveNetworkAccess::Restricted,
            ),
            (
                json!({ "type": "externalSandbox", "networkAccess": "enabled" }),
                EffectiveSandboxType::ExternalSandbox,
                EffectiveNetworkAccess::Enabled,
            ),
            (
                json!({
                    "type": "workspaceWrite",
                    "writableRoots": ["/workspace", "/tmp/build"],
                    "networkAccess": true,
                    "excludeTmpdirEnvVar": false,
                    "excludeSlashTmp": true
                }),
                EffectiveSandboxType::WorkspaceWrite,
                EffectiveNetworkAccess::Enabled,
            ),
        ];

        for (sandbox, expected_type, expected_network) in cases {
            let mut result = resume_result();
            result["sandbox"] = sandbox;
            let settings =
                parse_thread_settings(&result)?.ok_or(ReadinessProxyError::InvalidMessage)?;
            assert_eq!(settings.sandbox_type(), expected_type);
            assert_eq!(settings.sandbox_network_access(), expected_network);
        }
        Ok(())
    }

    #[test]
    fn parses_all_pinned_approval_policy_shapes() -> Result<(), ReadinessProxyError> {
        let cases = [
            (json!("untrusted"), EffectiveApprovalPolicy::Untrusted),
            (json!("on-request"), EffectiveApprovalPolicy::OnRequest),
            (json!("never"), EffectiveApprovalPolicy::Never),
            (
                json!({
                    "granular": {
                        "sandbox_approval": true,
                        "rules": false,
                        "skill_approval": true,
                        "request_permissions": false,
                        "mcp_elicitations": true
                    }
                }),
                EffectiveApprovalPolicy::Granular {
                    sandbox_approval: true,
                    rules: false,
                    skill_approval: true,
                    request_permissions: false,
                    mcp_elicitations: true,
                },
            ),
            (
                json!({
                    "granular": {
                        "sandbox_approval": false,
                        "rules": true,
                        "mcp_elicitations": false
                    }
                }),
                EffectiveApprovalPolicy::Granular {
                    sandbox_approval: false,
                    rules: true,
                    skill_approval: false,
                    request_permissions: false,
                    mcp_elicitations: false,
                },
            ),
        ];
        for (wire, expected) in cases {
            assert_eq!(parse_approval_policy(&wire)?, expected);
        }
        Ok(())
    }

    #[test]
    fn rejects_malformed_granular_approval_policies() {
        let malformed = [
            json!({ "unknown": {} }),
            json!({ "granular": { "sandbox_approval": true, "rules": true } }),
            json!({
                "granular": {
                    "sandbox_approval": "true",
                    "rules": true,
                    "mcp_elicitations": true
                }
            }),
            json!({
                "granular": {
                    "sandbox_approval": true,
                    "rules": true,
                    "mcp_elicitations": true,
                    "unreviewed": false
                }
            }),
        ];
        for wire in malformed {
            assert_eq!(
                parse_approval_policy(&wire),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }
    }

    #[test]
    fn exact_resume_rejects_history_and_non_empty_path_precedence() -> Result<(), Box<dyn Error>> {
        let allowed_params = [
            json!({ "threadId": TARGET_THREAD_ID }),
            json!({ "threadId": TARGET_THREAD_ID, "history": null, "path": null }),
            json!({ "threadId": TARGET_THREAD_ID, "history": null, "path": "" }),
        ];
        for params in allowed_params {
            let message = serde_json::to_vec(&json!({
                "id": 7,
                "method": "thread/resume",
                "params": params
            }))?;
            let mut events = Vec::new();
            inspect_message(Direction::ClientToServer, &message, &mut events)?;
            assert!(matches!(
                events.as_slice(),
                [ObservedEvent::Request {
                    method: ReadinessMethod::ThreadResume,
                    thread_id,
                    ..
                }] if thread_id == TARGET_THREAD_ID
            ));
        }

        let rejected_params = [
            json!({ "threadId": TARGET_THREAD_ID, "history": [] }),
            json!({ "threadId": TARGET_THREAD_ID, "history": [{"type": "message"}] }),
            json!({ "threadId": TARGET_THREAD_ID, "path": "/tmp/other-rollout.jsonl" }),
        ];
        for params in rejected_params {
            let message = serde_json::to_vec(&json!({
                "id": 7,
                "method": "thread/resume",
                "params": params
            }))?;
            assert_eq!(
                inspect_message(Direction::ClientToServer, &message, &mut Vec::new()),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }
        Ok(())
    }

    #[test]
    fn unrelated_bounded_responses_are_classified_without_settings_assumptions()
    -> Result<(), Box<dyn Error>> {
        for result in [
            json!(true),
            json!(null),
            json!([1, 2]),
            json!({ "model": "metadata" }),
        ] {
            let bytes = serde_json::to_vec(&json!({ "id": 99, "result": result }))?;
            let mut events = Vec::new();
            inspect_message(Direction::ServerToClient, &bytes, &mut events)?;
            assert!(matches!(
                events.as_slice(),
                [ObservedEvent::Response {
                    thread_id: None,
                    settings: None,
                    ..
                }]
            ));
        }
        Ok(())
    }

    #[test]
    fn ignored_client_envelopes_still_enforce_method_and_id_bounds() -> Result<(), Box<dyn Error>> {
        let valid = serde_json::to_vec(&json!({
            "id": "bounded",
            "method": "unrelated/notification",
            "params": {}
        }))?;
        inspect_message(Direction::ClientToServer, &valid, &mut Vec::new())?;

        for message in [
            json!({ "id": "x".repeat(MAX_REQUEST_ID_BYTES + 1), "method": "unrelated" }),
            json!({ "id": 1, "method": "x".repeat(MAX_METHOD_BYTES + 1) }),
            json!({ "id": "x".repeat(MAX_REQUEST_ID_BYTES + 1), "result": {} }),
        ] {
            let bytes = serde_json::to_vec(&message)?;
            assert_eq!(
                inspect_message(Direction::ClientToServer, &bytes, &mut Vec::new()),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_unpinned_or_unbounded_effective_settings() {
        let invalid = [
            ("approvalPolicy", json!("always")),
            ("approvalsReviewer", json!("nobody")),
            (
                "sandbox",
                json!({ "type": "readOnly", "networkAccess": "false" }),
            ),
            (
                "sandbox",
                json!({ "type": "dangerFullAccess", "networkAccess": true }),
            ),
            (
                "sandbox",
                json!({
                    "type": "workspaceWrite",
                    "writableRoots": ["relative/path"],
                    "networkAccess": false,
                    "excludeTmpdirEnvVar": false,
                    "excludeSlashTmp": false
                }),
            ),
        ];
        for (field, value) in invalid {
            let mut result = resume_result();
            result[field] = value;
            assert_eq!(
                parse_thread_settings(&result),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }

        let mut oversized = resume_result();
        oversized["model"] = json!("x".repeat(MAX_MODEL_BYTES + 1));
        assert_eq!(
            parse_thread_settings(&oversized),
            Err(ReadinessProxyError::InvalidMessage)
        );
    }

    #[test]
    fn rejects_oversized_handshakes_and_frames_before_allocating_the_payload()
    -> Result<(), Box<dyn Error>> {
        let mut handshake_inspector = ProtocolInspector::new(Direction::ClientToServer);
        let oversized_handshake = vec![b'a'; MAX_HANDSHAKE_BYTES + 1];
        assert_eq!(
            handshake_inspector.feed(&oversized_handshake),
            Err(ReadinessProxyError::HandshakeTooLarge)
        );

        let mut frame_inspector = ProtocolInspector::new(Direction::ServerToClient);
        frame_inspector.feed(&websocket_response())?;
        let oversized_header = frame_header(false, true, 0x1, (MAX_MESSAGE_BYTES + 1) as u64);
        assert_eq!(
            frame_inspector.feed(&oversized_header),
            Err(ReadinessProxyError::FrameTooLarge)
        );
        Ok(())
    }

    #[test]
    fn rejects_fragmented_messages_over_one_mib_from_the_next_frame_header()
    -> Result<(), Box<dyn Error>> {
        let mut inspector = ProtocolInspector::new(Direction::ClientToServer);
        inspector.feed(&websocket_request())?;
        let fragment = vec![b'a'; MAX_MESSAGE_BYTES / 2 + 1];
        inspector.feed(&masked_frame(false, 0x1, &fragment))?;
        let mut continuation_header = frame_header(true, true, 0x0, u64::try_from(fragment.len())?);
        continuation_header.extend([0x12, 0x34, 0x56, 0x78]);

        assert_eq!(
            inspector.feed(&continuation_header),
            Err(ReadinessProxyError::FrameTooLarge)
        );
        Ok(())
    }

    #[test]
    fn rejects_frames_with_the_wrong_mask_direction() -> Result<(), Box<dyn Error>> {
        let mut client = ProtocolInspector::new(Direction::ClientToServer);
        client.feed(&websocket_request())?;
        assert_eq!(
            client.feed(&unmasked_frame(true, 0x1, b"{}")),
            Err(ReadinessProxyError::InvalidFrame)
        );

        let mut server = ProtocolInspector::new(Direction::ServerToClient);
        server.feed(&websocket_response())?;
        assert_eq!(
            server.feed(&masked_frame(true, 0x1, b"{}")),
            Err(ReadinessProxyError::InvalidFrame)
        );
        Ok(())
    }

    #[test]
    fn rejects_an_http_response_that_did_not_upgrade() {
        let mut inspector = ProtocolInspector::new(Direction::ServerToClient);
        assert_eq!(
            inspector.feed(b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
            Err(ReadinessProxyError::InvalidHandshake)
        );
    }

    #[test]
    fn readiness_requires_successful_read_then_resume_for_the_exact_target() {
        let mut state = ReadinessState::new(expectation());
        let events = [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
            ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: None,
                settings: None,
            },
            ObservedEvent::Request {
                id: json!(2),
                method: ReadinessMethod::ThreadResume,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
            ObservedEvent::Response {
                id: json!(2),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                settings: Some(observed_settings()),
            },
            ObservedEvent::Request {
                id: json!(3),
                method: ReadinessMethod::ThreadRead,
                thread_id: SOURCE_THREAD_ID.to_owned(),
                include_turns: None,
            },
            ObservedEvent::Response {
                id: json!(3),
                has_error: true,
                thread_id: None,
                forked_from_id: None,
                settings: None,
            },
        ];

        for (index, event) in events.into_iter().enumerate() {
            assert_eq!(state.observe(event), Ok(index == 7));
        }
    }

    #[test]
    fn readiness_rejects_a_success_response_for_another_thread() {
        let mut state = ReadinessState::new(expectation());
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ClientToServer)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ServerToClient)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            }),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(1),
                has_error: false,
                thread_id: Some("019f64a7-c5d1-7ed1-aca8-156bc32b650d".to_owned()),
                forked_from_id: None,
                settings: None,
            }),
            Err(ReadinessProxyError::TargetMismatch)
        );
    }

    #[test]
    fn readiness_rejects_resume_before_the_read_response() {
        let mut state = ReadinessState::new(expectation());
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ClientToServer)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Handshake(Direction::ServerToClient)),
            Ok(false)
        );
        assert_eq!(
            state.observe(ObservedEvent::Request {
                id: json!(2),
                method: ReadinessMethod::ThreadResume,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            }),
            Err(ReadinessProxyError::UnexpectedSequence)
        );
    }

    #[test]
    fn readiness_rejects_an_error_response_for_the_target_request() {
        let mut state = ReadinessState::new(expectation());
        for event in [
            ObservedEvent::Handshake(Direction::ClientToServer),
            ObservedEvent::Handshake(Direction::ServerToClient),
            ObservedEvent::Request {
                id: json!(1),
                method: ReadinessMethod::ThreadRead,
                thread_id: TARGET_THREAD_ID.to_owned(),
                include_turns: None,
            },
        ] {
            assert_eq!(state.observe(event), Ok(false));
        }
        assert_eq!(
            state.observe(ObservedEvent::Response {
                id: json!(1),
                has_error: true,
                thread_id: None,
                forked_from_id: None,
                settings: None,
            }),
            Err(ReadinessProxyError::InvalidMessage)
        );
    }

    #[test]
    fn readiness_rejects_missing_or_mutated_effective_resume_settings() {
        let mut missing = state_awaiting_resume_response();
        assert_eq!(
            missing.observe(ObservedEvent::Response {
                id: json!(2),
                has_error: false,
                thread_id: Some(TARGET_THREAD_ID.to_owned()),
                forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                settings: None,
            }),
            Err(ReadinessProxyError::InvalidMessage)
        );

        let expected = observed_settings();
        let mutations = [
            EffectiveThreadSettings {
                cwd: "/outside".to_owned(),
                ..expected.clone()
            },
            EffectiveThreadSettings {
                model: "other".to_owned(),
                ..expected.clone()
            },
            EffectiveThreadSettings {
                model_provider: "other".to_owned(),
                ..expected.clone()
            },
            EffectiveThreadSettings {
                approval_policy: EffectiveApprovalPolicy::OnRequest,
                ..expected.clone()
            },
            EffectiveThreadSettings {
                approvals_reviewer: EffectiveApprovalsReviewer::AutoReview,
                ..expected.clone()
            },
            EffectiveThreadSettings {
                sandbox_type: EffectiveSandboxType::WorkspaceWrite,
                ..expected.clone()
            },
            EffectiveThreadSettings {
                sandbox_network_access: EffectiveNetworkAccess::Enabled,
                ..expected
            },
        ];
        for settings in mutations {
            let mut state = state_awaiting_resume_response();
            assert_eq!(
                state.observe(ObservedEvent::Response {
                    id: json!(2),
                    has_error: false,
                    thread_id: Some(TARGET_THREAD_ID.to_owned()),
                    forked_from_id: Some(SOURCE_THREAD_ID.to_owned()),
                    settings: Some(settings),
                }),
                Err(ReadinessProxyError::TargetMismatch)
            );
        }
    }

    #[test]
    fn rejects_ambiguous_response_envelopes() -> Result<(), Box<dyn Error>> {
        let mut inspector = ProtocolInspector::new(Direction::ServerToClient);
        inspector.feed(&websocket_response())?;
        let ambiguous = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "result": { "thread": { "id": TARGET_THREAD_ID } },
                "error": null
            }))?,
        );

        assert_eq!(
            inspector.feed(&ambiguous),
            Err(ReadinessProxyError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_jsonrpc_error_bodies() -> Result<(), Box<dyn Error>> {
        let malformed_errors = [
            json!(null),
            json!("error"),
            json!([]),
            json!({}),
            json!({ "code": -32600 }),
            json!({ "message": "missing code" }),
            json!({ "code": 1.5, "message": "non-integer code" }),
            json!({ "code": 18_446_744_073_709_551_615_u64, "message": "outside int64" }),
            json!({ "code": -32600, "message": 42 }),
        ];

        for error in malformed_errors {
            let mut inspector = ProtocolInspector::new(Direction::ServerToClient);
            inspector.feed(&websocket_response())?;
            let response = unmasked_frame(
                true,
                0x1,
                &serde_json::to_vec(&json!({ "id": 1, "error": error }))?,
            );
            assert_eq!(
                inspector.feed(&response),
                Err(ReadinessProxyError::InvalidMessage)
            );
        }
        Ok(())
    }

    #[test]
    fn transparently_forwards_bytes_and_confirms_remote_resume() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let upstream_listener = UnixListener::bind(&upstream_path)?;

        let request_handshake = websocket_request();
        let response_handshake = websocket_response();
        let read_message = serde_json::to_vec(&json!({
            "id": 11,
            "method": "thread/read",
            "params": { "threadId": TARGET_THREAD_ID }
        }))?;
        let split = read_message.len() / 2;
        let mut read_wire = masked_frame(false, 0x1, &read_message[..split]);
        read_wire.extend(masked_frame(true, 0x9, b"still-here"));
        read_wire.extend(masked_frame(true, 0x0, &read_message[split..]));
        let read_response_wire = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 11,
                "result": { "thread": { "id": TARGET_THREAD_ID } }
            }))?,
        );
        let resume_wire = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "resume",
                "method": "thread/resume",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let resume_response_wire = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "resume",
                "result": resume_result()
            }))?,
        );
        let parent_read_wire = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "parent-title",
                "method": "thread/read",
                "params": { "threadId": SOURCE_THREAD_ID }
            }))?,
        );
        let parent_read_response_wire = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "parent-title",
                "error": { "code": -32600, "message": "parent not present in target home" }
            }))?,
        );

        let expected_request_handshake = request_handshake.clone();
        let expected_read_wire = read_wire.clone();
        let expected_resume_wire = resume_wire.clone();
        let expected_parent_read_wire = parent_read_wire.clone();
        let server_response_handshake = response_handshake.clone();
        let server_read_response = read_response_wire.clone();
        let server_resume_response = resume_response_wire.clone();
        let server_parent_read_response = parent_read_response_wire.clone();
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = upstream_listener.accept()?;
            set_short_timeouts(&stream)?;
            assert_read_exact(&mut stream, &expected_request_handshake)
                .map_err(|error| io::Error::new(error.kind(), "server request handshake"))?;
            write_in_chunks(&mut stream, &server_response_handshake, 5)?;
            assert_read_exact(&mut stream, &expected_read_wire)
                .map_err(|error| io::Error::new(error.kind(), "server thread/read"))?;
            write_in_chunks(&mut stream, &server_read_response, 3)?;
            assert_read_exact(&mut stream, &expected_resume_wire)
                .map_err(|error| io::Error::new(error.kind(), "server thread/resume"))?;
            write_in_chunks(&mut stream, &server_resume_response, 4)?;
            assert_read_exact(&mut stream, &expected_parent_read_wire)
                .map_err(|error| io::Error::new(error.kind(), "server parent thread/read"))?;
            write_in_chunks(&mut stream, &server_parent_read_response, 3)?;
            let mut byte = [0_u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        });

        let mut proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(2))?;
        assert!(
            fs::symlink_metadata(proxy.socket_path())?
                .file_type()
                .is_socket()
        );
        assert_eq!(
            fs::symlink_metadata(temp.path())?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(proxy.socket_path())?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut client = UnixStream::connect(proxy.socket_path())?;
        set_short_timeouts(&client)?;
        write_in_chunks(&mut client, &request_handshake, 2)?;
        assert_read_exact(&mut client, &response_handshake)
            .map_err(|error| io::Error::new(error.kind(), "client response handshake"))?;
        write_in_chunks(&mut client, &read_wire, 3)?;
        assert_read_exact(&mut client, &read_response_wire)
            .map_err(|error| io::Error::new(error.kind(), "client thread/read response"))?;
        write_in_chunks(&mut client, &resume_wire, 4)?;
        assert_read_exact(&mut client, &resume_response_wire)
            .map_err(|error| io::Error::new(error.kind(), "client thread/resume response"))?;
        write_in_chunks(&mut client, &parent_read_wire, 3)?;
        assert_read_exact(&mut client, &parent_read_response_wire)
            .map_err(|error| io::Error::new(error.kind(), "client parent thread/read response"))?;

        assert_eq!(proxy.wait_until_ready(), Ok(()));
        assert_eq!(proxy.ensure_connected(), Ok(()));
        assert_eq!(proxy.transport.first(), None);
        proxy.shutdown(shutdown_deadline()?)?;
        drop(client);
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn exact_proxy_waits_for_forwarded_parent_metadata_before_returning_settings()
    -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let upstream_listener = UnixListener::bind(&upstream_path)?;

        let request_handshake = websocket_request();
        let response_handshake = websocket_response();
        let read_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "method": "thread/read",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let read_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "result": { "thread": { "id": TARGET_THREAD_ID } }
            }))?,
        );
        let resume_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 2,
                "method": "thread/resume",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let resume_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 2,
                "result": resume_result()
            }))?,
        );
        let parent_read_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 3,
                "method": "thread/read",
                "params": { "threadId": SOURCE_THREAD_ID }
            }))?,
        );
        let parent_read_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 3,
                "result": { "thread": { "id": SOURCE_THREAD_ID } }
            }))?,
        );

        let server_request_handshake = request_handshake.clone();
        let server_response_handshake = response_handshake.clone();
        let server_read_request = read_request.clone();
        let server_read_response = read_response.clone();
        let server_resume_request = resume_request.clone();
        let server_resume_response = resume_response.clone();
        let server_parent_read_request = parent_read_request.clone();
        let server_parent_read_response = parent_read_response.clone();
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = upstream_listener.accept()?;
            set_short_timeouts(&stream)?;
            assert_read_exact(&mut stream, &server_request_handshake)?;
            stream.write_all(&server_response_handshake)?;
            assert_read_exact(&mut stream, &server_read_request)?;
            stream.write_all(&server_read_response)?;
            assert_read_exact(&mut stream, &server_resume_request)?;
            stream.write_all(&server_resume_response)?;
            assert_read_exact(&mut stream, &server_parent_read_request)?;
            stream.write_all(&server_parent_read_response)?;
            let mut byte = [0_u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        });

        let mut proxy =
            spawn_exact_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(2))?;
        assert_eq!(proxy.poll_ready(), Ok(None));
        assert_eq!(proxy.lifecycle.load(Ordering::Acquire), RELAY_RUNNING);
        let mut client = UnixStream::connect(proxy.socket_path())?;
        set_short_timeouts(&client)?;
        client.write_all(&request_handshake)?;
        assert_read_exact(&mut client, &response_handshake)?;
        client.write_all(&read_request)?;
        assert_read_exact(&mut client, &read_response)?;
        client.write_all(&resume_request)?;
        assert_read_exact(&mut client, &resume_response)?;
        client.write_all(&parent_read_request)?;
        assert_read_exact(&mut client, &parent_read_response)?;

        let poll_deadline = shutdown_deadline()?;
        let settings = loop {
            match proxy.poll_ready()? {
                Some(settings) => break settings,
                None if Instant::now() < poll_deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                None => {
                    return Err("exact readiness did not arrive before the test deadline".into());
                }
            }
        };
        assert_eq!(settings, observed_settings());
        assert_eq!(proxy.poll_ready(), Ok(Some(observed_settings())));
        assert_eq!(proxy.ensure_connected(), Ok(()));
        assert_eq!(proxy.transport.first(), None);
        proxy.shutdown(shutdown_deadline()?)?;
        drop(client);
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        Ok(())
    }

    #[test]
    fn provider_request_is_forwarded_but_calcifer_emits_no_response() -> Result<(), Box<dyn Error>>
    {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let upstream_listener = UnixListener::bind(&upstream_path)?;

        let request_handshake = websocket_request();
        let response_handshake = websocket_response();
        let provider_request = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "approval-1",
                "method": "item/commandExecution/requestApproval",
                "params": { "command": "must-not-enter-observer-state" }
            }))?,
        );
        let tui_provider_response = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": "approval-1",
                "result": { "decision": "decline" }
            }))?,
        );
        let read_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "method": "thread/read",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let read_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "result": { "thread": { "id": TARGET_THREAD_ID } }
            }))?,
        );
        let resume_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 2,
                "method": "thread/resume",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let resume_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({ "id": 2, "result": exact_resume_result() }))?,
        );

        let server_request_handshake = request_handshake.clone();
        let server_response_handshake = response_handshake.clone();
        let server_provider_request = provider_request.clone();
        let server_tui_provider_response = tui_provider_response.clone();
        let server_read_request = read_request.clone();
        let server_read_response = read_response.clone();
        let server_resume_request = resume_request.clone();
        let server_resume_response = resume_response.clone();
        let (silence_verified_sender, silence_verified_receiver) = mpsc::channel();
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = upstream_listener.accept()?;
            set_short_timeouts(&stream)?;
            assert_read_exact(&mut stream, &server_request_handshake)?;
            stream.write_all(&server_response_handshake)?;
            stream.write_all(&server_provider_request)?;

            stream.set_read_timeout(Some(Duration::from_millis(80)))?;
            let mut byte = [0_u8; 1];
            match stream.read(&mut byte) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Ok(0) => return Err(io::Error::other("relay closed during silence proof")),
                Ok(_) => return Err(io::Error::other("Calcifer answered a provider request")),
                Err(error) => return Err(error),
            }
            silence_verified_sender
                .send(())
                .map_err(|_| io::Error::other("silence receiver disappeared"))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;

            assert_read_exact(&mut stream, &server_tui_provider_response)?;
            assert_read_exact(&mut stream, &server_read_request)?;
            stream.write_all(&server_read_response)?;
            assert_read_exact(&mut stream, &server_resume_request)?;
            stream.write_all(&server_resume_response)?;
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => return Ok(()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        });

        let mut proxy =
            spawn_exact_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(2))?;
        let mut client = UnixStream::connect(proxy.socket_path())?;
        set_short_timeouts(&client)?;
        client.write_all(&request_handshake)?;
        assert_read_exact(&mut client, &response_handshake)?;
        assert_read_exact(&mut client, &provider_request)?;
        silence_verified_receiver.recv_timeout(Duration::from_secs(1))?;
        client.write_all(&tui_provider_response)?;
        client.write_all(&read_request)?;
        assert_read_exact(&mut client, &read_response)?;
        client.write_all(&resume_request)?;
        assert_read_exact(&mut client, &resume_response)?;

        assert_eq!(
            proxy.wait_until_ready_with_settings(),
            Ok(observed_settings())
        );
        assert_eq!(proxy.ensure_connected(), Ok(()));
        assert_eq!(proxy.transport.first(), None);
        proxy.shutdown(shutdown_deadline()?)?;
        drop(client);
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        Ok(())
    }

    #[test]
    fn decodes_a_boundary_frame_before_buffering_a_coalesced_next_frame()
    -> Result<(), Box<dyn Error>> {
        let empty = serde_json::to_vec(&json!({ "id": 1, "result": "" }))?;
        let padding = "x".repeat(MAX_MESSAGE_BYTES - empty.len());
        let first_payload = serde_json::to_vec(&json!({ "id": 1, "result": padding }))?;
        assert_eq!(first_payload.len(), MAX_MESSAGE_BYTES);
        let first_frame = unmasked_frame(true, 0x1, &first_payload);
        let second_payload = serde_json::to_vec(&json!({ "id": 2, "result": null }))?;
        let second_frame = unmasked_frame(true, 0x1, &second_payload);

        let split = first_frame.len() - 2;
        let mut decoder = FrameDecoder::new(Direction::ServerToClient);
        let mut events = Vec::new();
        decoder.feed(&first_frame[..split], &mut events)?;
        assert!(events.is_empty());

        let mut coalesced = first_frame[split..].to_vec();
        coalesced.extend_from_slice(&second_frame);
        decoder.feed(&coalesced, &mut events)?;
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            ObservedEvent::Response {
                id,
                thread_id: None,
                settings: None,
                ..
            } if id == &json!(1)
        ));
        assert!(matches!(
            &events[1],
            ObservedEvent::Response {
                id,
                thread_id: None,
                settings: None,
                ..
            } if id == &json!(2)
        ));
        Ok(())
    }

    #[test]
    fn disconnect_after_readiness_is_not_a_live_attachment() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let upstream_listener = UnixListener::bind(&upstream_path)?;

        let request_handshake = websocket_request();
        let response_handshake = websocket_response();
        let read_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "method": "thread/read",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let read_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 1,
                "result": { "thread": { "id": TARGET_THREAD_ID } }
            }))?,
        );
        let resume_request = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 2,
                "method": "thread/resume",
                "params": { "threadId": TARGET_THREAD_ID }
            }))?,
        );
        let resume_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 2,
                "result": resume_result()
            }))?,
        );
        let parent_read = masked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 3,
                "method": "thread/read",
                "params": { "threadId": SOURCE_THREAD_ID }
            }))?,
        );
        let parent_read_response = unmasked_frame(
            true,
            0x1,
            &serde_json::to_vec(&json!({
                "id": 3,
                "error": { "code": -32600, "message": "parent not present in target home" }
            }))?,
        );

        let server_request_handshake = request_handshake.clone();
        let server_response_handshake = response_handshake.clone();
        let server_read_request = read_request.clone();
        let server_read_response = read_response.clone();
        let server_resume_request = resume_request.clone();
        let server_resume_response = resume_response.clone();
        let server_parent_read = parent_read.clone();
        let server_parent_read_response = parent_read_response.clone();
        let (readiness_observed_sender, readiness_observed_receiver) = mpsc::sync_channel(0);
        let server = thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = upstream_listener.accept()?;
            set_short_timeouts(&stream)?;
            assert_read_exact(&mut stream, &server_request_handshake)?;
            stream.write_all(&server_response_handshake)?;
            assert_read_exact(&mut stream, &server_read_request)?;
            stream.write_all(&server_read_response)?;
            assert_read_exact(&mut stream, &server_resume_request)?;
            stream.write_all(&server_resume_response)?;
            assert_read_exact(&mut stream, &server_parent_read)?;
            stream.write_all(&server_parent_read_response)?;
            readiness_observed_receiver
                .recv()
                .map_err(|_| io::Error::other("readiness observer disappeared"))?;
            stream.shutdown(Shutdown::Both)
        });

        let mut proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(2))?;
        let mut client = UnixStream::connect(proxy.socket_path())?;
        set_short_timeouts(&client)?;
        client.write_all(&request_handshake)?;
        assert_read_exact(&mut client, &response_handshake)?;
        client.write_all(&read_request)?;
        assert_read_exact(&mut client, &read_response)?;
        client.write_all(&resume_request)?;
        assert_read_exact(&mut client, &resume_response)?;
        client.write_all(&parent_read)?;
        assert_read_exact(&mut client, &parent_read_response)?;
        assert_eq!(proxy.wait_until_ready(), Ok(()));
        readiness_observed_sender.send(())?;

        for _ in 0..100 {
            if proxy.lifecycle.load(Ordering::Acquire) == RELAY_DISCONNECTED {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(proxy.lifecycle.load(Ordering::Acquire), RELAY_DISCONNECTED);
        assert_eq!(
            proxy.ensure_connected(),
            Err(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::UpstreamEof
            ))
        );
        let failure = proxy
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("a disconnected proxy unexpectedly shut down cleanly")?;
        assert_eq!(
            failure.error(),
            ReadinessProxyError::Transport(ReadinessTransportOrigin::UpstreamEof)
        );
        assert_eq!(
            failure.operation_error(),
            Some(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::UpstreamEof
            ))
        );
        assert_eq!(failure.cleanup_error(), None);
        server
            .join()
            .map_err(|_| io::Error::other("mock app-server panicked"))??;
        Ok(())
    }

    #[test]
    fn active_health_probe_detects_eof_without_waiting_for_the_copy_pump() -> io::Result<()> {
        let (stream, peer) = UnixStream::pair()?;
        let transport = ReadinessTransportTracker::new();
        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        assert!(
            socket_is_connected(&stream, HealthEndpoint::Client, &lifecycle, &transport)
                .map_err(io::Error::other)?
        );
        assert_eq!(transport.first(), None);
        drop(peer);
        assert!(
            !socket_is_connected(&stream, HealthEndpoint::Client, &lifecycle, &transport)
                .map_err(io::Error::other)?
        );
        assert_eq!(
            transport.first(),
            Some(ReadinessTransportOrigin::HealthClientEof)
        );
        Ok(())
    }

    #[test]
    fn active_health_probe_detects_hangup_behind_buffered_data() -> io::Result<()> {
        let (stream, mut peer) = UnixStream::pair()?;
        let transport = ReadinessTransportTracker::new();
        let lifecycle = AtomicU8::new(RELAY_RUNNING);
        peer.write_all(b"buffered")?;
        peer.shutdown(Shutdown::Both)?;
        assert!(
            !socket_is_connected(&stream, HealthEndpoint::Upstream, &lifecycle, &transport)
                .map_err(io::Error::other)?
        );
        assert_eq!(
            transport.first(),
            Some(ReadinessTransportOrigin::HealthUpstreamEof)
        );
        Ok(())
    }

    #[test]
    fn cleanup_refuses_to_unlink_a_replaced_socket_path() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1))?;
        fs::remove_file(&proxy_path)?;
        fs::write(&proxy_path, b"replacement")?;

        let failure = proxy
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("a replaced proxy socket unexpectedly cleaned up")?;
        assert_eq!(failure.error(), ReadinessProxyError::Cleanup);
        assert_eq!(failure.operation_error(), None);
        assert_eq!(failure.cleanup_error(), Some(ReadinessProxyError::Cleanup));
        assert!(failure.into_proxy().is_some());
        assert_eq!(fs::read(&proxy_path)?, b"replacement");
        Ok(())
    }

    #[test]
    fn expired_exact_owned_deadline_fails_before_binding() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;

        let failure = ReadinessProxy::spawn_exact_owned_until(
            &proxy_path,
            &upstream_path,
            ExactResumeProbe::new(TARGET_THREAD_ID, Path::new(TARGET_CWD)),
            Instant::now() - Duration::from_millis(1),
        )
        .err()
        .ok_or("an expired exact relay deadline unexpectedly started a worker")?;
        assert_eq!(failure.error(), ReadinessProxyError::Timeout);
        assert!(!failure.has_bound_socket());
        assert!(!proxy_path.exists());
        let _cleanup = failure.cleanup()?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn exact_start_failure_retains_bound_socket_and_preserves_a_replacement()
    -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        FAIL_EXACT_START_AFTER_BIND.with(|fault| fault.set(true));

        let failure = ReadinessProxy::spawn_exact_owned(
            &proxy_path,
            &upstream_path,
            ExactResumeProbe::new(TARGET_THREAD_ID, Path::new(TARGET_CWD)),
            Duration::from_secs(1),
        )
        .err()
        .ok_or("the injected post-bind worker fault unexpectedly started a relay")?;
        assert_eq!(failure.error(), ReadinessProxyError::Worker);
        assert!(failure.has_bound_socket());
        assert!(fs::symlink_metadata(&proxy_path)?.file_type().is_socket());

        fs::remove_file(&proxy_path)?;
        fs::write(&proxy_path, b"preserve-start-replacement")?;
        let failure = failure
            .cleanup()
            .err()
            .ok_or("replacement unexpectedly satisfied exact start cleanup")?;
        assert_eq!(failure.cleanup_error(), Some(ReadinessProxyError::Cleanup));
        assert!(failure.has_bound_socket());
        assert_eq!(fs::read(&proxy_path)?, b"preserve-start-replacement");
        fs::remove_file(&proxy_path)?;
        drop(failure);
        Ok(())
    }

    #[test]
    fn exact_start_failure_can_clean_its_recorded_bound_socket() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        FAIL_EXACT_START_AFTER_BIND.with(|fault| fault.set(true));

        let failure = ReadinessProxy::spawn_exact_owned(
            &proxy_path,
            &upstream_path,
            ExactResumeProbe::new(TARGET_THREAD_ID, Path::new(TARGET_CWD)),
            Duration::from_secs(1),
        )
        .err()
        .ok_or("the injected post-bind worker fault unexpectedly started a relay")?;
        let _cleanup = failure.cleanup()?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn bind_rejects_a_parent_directory_accessible_to_other_users() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755))?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;

        assert!(matches!(
            spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1)),
            Err(ReadinessProxyError::Bind)
        ));
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn bind_collisions_preserve_existing_files_symlinks_and_sockets() -> Result<(), Box<dyn Error>>
    {
        for collision in ["file", "symlink", "socket"] {
            let temp = TestDirectory::new()?;
            let upstream_path = temp.path().join("upstream.sock");
            let proxy_path = temp.path().join("proxy.sock");
            let _upstream = UnixListener::bind(&upstream_path)?;
            let mut collision_listener = None;
            match collision {
                "file" => fs::write(&proxy_path, b"preserve-me")?,
                "symlink" => std::os::unix::fs::symlink("missing-target", &proxy_path)?,
                "socket" => collision_listener = Some(UnixListener::bind(&proxy_path)?),
                _ => unreachable!("the collision table is closed"),
            }
            let before = fs::symlink_metadata(&proxy_path)?;

            assert!(matches!(
                spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1)),
                Err(ReadinessProxyError::Bind)
            ));
            let after = fs::symlink_metadata(&proxy_path)?;
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            match collision {
                "file" => assert_eq!(fs::read(&proxy_path)?, b"preserve-me"),
                "symlink" => {
                    assert_eq!(fs::read_link(&proxy_path)?, Path::new("missing-target"))
                }
                "socket" => assert!(after.file_type().is_socket()),
                _ => unreachable!("the collision table is closed"),
            }
            drop(collision_listener);
        }
        Ok(())
    }

    #[test]
    fn bind_rejects_a_symlinked_parent_directory() -> Result<(), Box<dyn Error>> {
        let outer = TestDirectory::new()?;
        let private_parent = outer.path().join("private");
        fs::DirBuilder::new().mode(0o700).create(&private_parent)?;
        let parent_link = outer.path().join("linked");
        std::os::unix::fs::symlink(&private_parent, &parent_link)?;
        let upstream_path = outer.path().join("upstream.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let proxy_path = parent_link.join("proxy.sock");

        assert!(matches!(
            spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1)),
            Err(ReadinessProxyError::Bind)
        ));
        assert!(!private_parent.join("proxy.sock").exists());
        Ok(())
    }

    #[test]
    fn cleanup_refuses_a_socket_whose_security_mode_changed() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1))?;
        fs::set_permissions(&proxy_path, fs::Permissions::from_mode(0o666))?;

        let failure = proxy
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("an insecure proxy socket unexpectedly cleaned up")?;
        assert_eq!(failure.error(), ReadinessProxyError::Cleanup);
        assert_eq!(failure.operation_error(), None);
        assert_eq!(failure.cleanup_error(), Some(ReadinessProxyError::Cleanup));
        assert!(fs::symlink_metadata(&proxy_path)?.file_type().is_socket());
        let retained = failure
            .into_proxy()
            .ok_or("cleanup failure lost proxy socket ownership")?;
        fs::set_permissions(&proxy_path, fs::Permissions::from_mode(0o600))?;
        retained.shutdown(shutdown_deadline()?)?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn timeout_fails_closed_and_removes_the_listener_socket() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let mut proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_millis(100))?;

        assert_eq!(proxy.poll_ready(), Ok(None));
        thread::sleep(Duration::from_millis(120));
        assert_eq!(proxy.poll_ready(), Err(ReadinessProxyError::Timeout));
        assert_eq!(proxy.poll_ready(), Err(ReadinessProxyError::Timeout));
        assert_eq!(proxy.lifecycle.load(Ordering::Acquire), RELAY_STOPPING);
        proxy.shutdown(shutdown_deadline()?)?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn readiness_disconnect_is_sticky_across_nonblocking_polls() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let mut proxy =
            spawn_exact_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1))?;
        let client = UnixStream::connect(proxy.socket_path())?;
        drop(client);

        let poll_deadline = shutdown_deadline()?;
        let error = loop {
            match proxy.poll_ready() {
                Err(error) => break error,
                Ok(None) if Instant::now() < poll_deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => {
                    return Err("disconnect was not observed before the test deadline".into());
                }
                Ok(Some(_)) => return Err("disconnect unexpectedly produced readiness".into()),
            }
        };
        let expected = ReadinessProxyError::Transport(ReadinessTransportOrigin::ClientEof);
        assert_eq!(error, expected);
        assert_eq!(proxy.poll_ready(), Err(expected));
        proxy.shutdown(shutdown_deadline()?)?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn shutdown_timeout_returns_join_ownership_for_a_bounded_retry() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1))?;

        let failure = proxy
            .shutdown(Instant::now())
            .err()
            .ok_or("an expired shutdown deadline unexpectedly joined the proxy")?;
        assert_eq!(failure.error(), ReadinessProxyError::Timeout);
        assert_eq!(
            failure.operation_error(),
            Some(ReadinessProxyError::Timeout)
        );
        assert_eq!(failure.cleanup_error(), None);
        let retained = failure
            .into_proxy()
            .ok_or("shutdown timeout lost proxy join ownership")?;
        retained.shutdown(shutdown_deadline()?)?;
        assert!(!proxy_path.exists());
        Ok(())
    }

    #[test]
    fn forced_shutdown_never_waits_for_a_busy_health_observer() -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_secs(1))?;
        let health = proxy
            .health
            .lock()
            .map_err(|_| "health observer mutex was poisoned")?;

        let started = Instant::now();
        proxy.force_stop();
        assert!(started.elapsed() < Duration::from_millis(50));

        drop(health);
        proxy.shutdown(shutdown_deadline()?)?;
        Ok(())
    }

    #[test]
    fn pre_stop_transport_failure_cannot_be_reclassified_by_a_later_stop()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(AtomicU8::new(RELAY_RUNNING));
        let worker_lifecycle = Arc::clone(&lifecycle);
        let (returned_sender, returned_receiver) = mpsc::sync_channel(0);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            let result = Err(ProxyRunError::Failed(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::ClientRead,
            )));
            returned_sender
                .send(())
                .map_err(|_| "failure-return barrier receiver disappeared")?;
            release_receiver
                .recv()
                .map_err(|_| "failure-finalize barrier sender disappeared")?;
            let finalized = finalize_proxy_run(result);
            Ok::<_, &'static str>((worker_lifecycle.load(Ordering::Acquire), finalized))
        });

        returned_receiver.recv()?;
        lifecycle.store(RELAY_STOPPING, Ordering::Release);
        release_sender.send(())?;
        let (observed_lifecycle, result) = worker
            .join()
            .map_err(|_| "failure-finalize worker panicked")??;
        assert_eq!(observed_lifecycle, RELAY_STOPPING);
        assert_eq!(
            result,
            Err(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::ClientRead
            ))
        );
        Ok(())
    }

    #[test]
    fn finished_worker_liveness_check_preserves_join_and_cleanup_authority()
    -> Result<(), Box<dyn Error>> {
        let temp = TestDirectory::new()?;
        let upstream_path = temp.path().join("upstream.sock");
        let proxy_path = temp.path().join("proxy.sock");
        let _upstream = UnixListener::bind(&upstream_path)?;
        let mut proxy = spawn_test_proxy(&proxy_path, &upstream_path, Duration::from_millis(30))?;
        let deadline = shutdown_deadline()?;
        while !proxy.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            if Instant::now() >= deadline {
                return Err("proxy worker did not finish before the test deadline".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
        proxy.readiness_result = Some(Ok(observed_settings()));
        proxy.lifecycle.store(RELAY_RUNNING, Ordering::Release);
        proxy.transport = Arc::new(ReadinessTransportTracker::new());

        assert_eq!(
            proxy.ensure_connected(),
            Err(ReadinessProxyError::Transport(
                ReadinessTransportOrigin::WorkerFinished
            ))
        );
        assert!(proxy.worker.is_some());
        let failure = proxy
            .shutdown(shutdown_deadline()?)
            .err()
            .ok_or("a timed-out worker unexpectedly produced clean shutdown proof")?;
        assert_eq!(
            failure.error(),
            ReadinessProxyError::Transport(ReadinessTransportOrigin::WorkerFinished)
        );
        assert_eq!(failure.cleanup_error(), None);
        assert!(failure.into_proxy().is_none());
        assert!(!proxy_path.exists());
        Ok(())
    }

    fn websocket_request() -> Vec<u8> {
        b"GET /rpc HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec()
    }

    fn websocket_response() -> Vec<u8> {
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dGVzdA==\r\n\r\n".to_vec()
    }

    fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        frame(fin, true, opcode, payload)
    }

    fn unmasked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        frame(fin, false, opcode, payload)
    }

    fn frame(fin: bool, masked: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut wire = frame_header(masked, fin, opcode, payload.len() as u64);
        if masked {
            let mask = [0x12, 0x34, 0x56, 0x78];
            wire.extend(mask);
            wire.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % mask.len()]),
            );
        } else {
            wire.extend(payload);
        }
        wire
    }

    fn frame_header(masked: bool, fin: bool, opcode: u8, payload_len: u64) -> Vec<u8> {
        let mut header = vec![(u8::from(fin) << 7) | opcode];
        let mask_bit = u8::from(masked) << 7;
        if payload_len <= 125 {
            header.push(mask_bit | payload_len as u8);
        } else if u16::try_from(payload_len).is_ok() {
            header.push(mask_bit | 126);
            header.extend((payload_len as u16).to_be_bytes());
        } else {
            header.push(mask_bit | 127);
            header.extend(payload_len.to_be_bytes());
        }
        header
    }

    fn set_short_timeouts(stream: &UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))
    }

    fn write_in_chunks(stream: &mut UnixStream, bytes: &[u8], size: usize) -> io::Result<()> {
        for chunk in bytes.chunks(size) {
            stream.write_all(chunk)?;
        }
        Ok(())
    }

    fn assert_read_exact(stream: &mut UnixStream, expected: &[u8]) -> io::Result<()> {
        let mut actual = vec![0; expected.len()];
        stream.read_exact(&mut actual)?;
        if actual == expected {
            Ok(())
        } else {
            Err(io::Error::other("proxy changed bytes in transit"))
        }
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> io::Result<Self> {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "calcifer-proxy-test-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
